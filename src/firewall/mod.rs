mod cli;
mod common;
mod iptables;
#[allow(unsafe_code)]
mod libnftables;

use thiserror::Error;
use tracing::{debug, info, trace, warn};

use crate::dns::HostnameIpResolver;
use crate::model::RuntimeSnapshot;

pub use cli::CommandNftRunner;
pub use common::{
    build_apply_script, build_apply_script_with_dns, build_cleanup_script, split_nft_commands,
};
pub use iptables::{CommandIptablesRunner, IptablesFirewall};
pub use libnftables::LibNftablesRunner;

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("failed to run nft command: {0}")]
    CommandExecution(String),
    #[error("nft command failed with code {code}: {stderr}")]
    CommandFailure { code: i32, stderr: String },
    #[error("failed to open nft stdin")]
    MissingStdin,
    #[error("failed to write nft script to stdin: {0}")]
    StdinWrite(String),
    #[error("failed to create libnftables context")]
    LibContextCreate,
    #[error("failed to configure libnftables {buffer}: return code {code}")]
    LibBufferConfig { buffer: &'static str, code: i32 },
    #[error("script contains NUL byte and cannot be passed to libnftables")]
    ScriptContainsNul,
    #[error("libnftables command failed with code {code}: {stderr}")]
    LibCommandFailure { code: i32, stderr: String },
    #[error("libnftables context lock poisoned")]
    LibContextLock,
    #[error("dns resolve failed for host {host}: {message}")]
    DnsResolve { host: String, message: String },
}

pub trait NftRunner {
    fn run_script(&self, script: &str) -> Result<(), FirewallError>;
}

pub struct NftablesFirewall<R> {
    runner: R,
}

impl<R> NftablesFirewall<R>
where
    R: NftRunner,
{
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn apply(&self, snapshot: &RuntimeSnapshot) -> Result<(), FirewallError> {
        self.cleanup()?;
        let script = build_apply_script(snapshot);
        let commands = split_nft_commands(&script);
        info!(
            command_count = commands.len(),
            container_count = snapshot.containers.len(),
            "applying nftables changes"
        );
        for command in &commands {
            debug!(command = %command, "nft apply command");
        }
        trace!(script = %script, "nft apply script detail");
        self.runner.run_script(&script)
    }

    pub fn apply_with_dns(
        &self,
        snapshot: &RuntimeSnapshot,
        resolver: &mut dyn HostnameIpResolver,
    ) -> Result<(), FirewallError> {
        self.cleanup()?;
        let script = build_apply_script_with_dns(snapshot, resolver)?;
        let commands = split_nft_commands(&script);
        info!(
            command_count = commands.len(),
            container_count = snapshot.containers.len(),
            "applying nftables changes with DNS sets"
        );
        for command in &commands {
            debug!(command = %command, "nft apply command");
        }
        trace!(script = %script, "nft apply script detail");
        self.runner.run_script(&script)
    }

    pub fn cleanup(&self) -> Result<(), FirewallError> {
        let script = build_cleanup_script();
        let commands = split_nft_commands(&script);
        info!(command_count = commands.len(), "cleaning up nftables table");
        for command in &commands {
            debug!(command = %command, "nft cleanup command");
        }
        trace!(script = %script, "nft cleanup script detail");
        match self.runner.run_script(&script) {
            Ok(()) => {
                info!("nftables cleanup completed");
                Ok(())
            }
            Err(FirewallError::CommandFailure { stderr, .. })
                if stderr.contains("No such file")
                    || stderr.contains("No such file or directory") =>
            {
                warn!("nftables table not found during cleanup; continuing");
                Ok(())
            }
            Err(FirewallError::LibCommandFailure { stderr, .. })
                if stderr.contains("No such file")
                    || stderr.contains("No such file or directory") =>
            {
                warn!("nftables table not found during cleanup; continuing");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl NftablesFirewall<CommandNftRunner> {
    #[must_use]
    pub const fn with_cli() -> Self {
        Self::new(CommandNftRunner)
    }
}

impl NftablesFirewall<LibNftablesRunner> {
    pub fn with_libnftables() -> Result<Self, FirewallError> {
        let runner = LibNftablesRunner::new()?;
        Ok(Self::new(runner))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use ipnet::IpNet;

    use super::*;
    use crate::model::{
        ContainerPolicy, ContainerSnapshot, EgressRule, EgressTarget, IccMode, NetworkAttachment,
        PortSpec, Protocol,
    };

    #[derive(Clone)]
    enum RunnerFailure {
        CommandFailure { code: i32, stderr: String },
        LibCommandFailure { code: i32, stderr: String },
    }

    #[derive(Clone)]
    struct RecordingRunner {
        scripts: Arc<Mutex<Vec<String>>>,
        fail_with: Option<RunnerFailure>,
    }

    impl RecordingRunner {
        fn new() -> Self {
            Self {
                scripts: Arc::new(Mutex::new(Vec::new())),
                fail_with: None,
            }
        }

        fn with_error(error: RunnerFailure) -> Self {
            Self {
                scripts: Arc::new(Mutex::new(Vec::new())),
                fail_with: Some(error),
            }
        }

        fn scripts(&self) -> Vec<String> {
            let guard = match self.scripts.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock scripts mutex: {error}"),
            };
            guard.clone()
        }
    }

    impl NftRunner for RecordingRunner {
        fn run_script(&self, script: &str) -> Result<(), FirewallError> {
            if let Some(error) = &self.fail_with {
                return Err(match error {
                    RunnerFailure::CommandFailure { code, stderr } => {
                        FirewallError::CommandFailure {
                            code: *code,
                            stderr: stderr.clone(),
                        }
                    }
                    RunnerFailure::LibCommandFailure { code, stderr } => {
                        FirewallError::LibCommandFailure {
                            code: *code,
                            stderr: stderr.clone(),
                        }
                    }
                });
            }

            let mut guard = self
                .scripts
                .lock()
                .map_err(|_| FirewallError::LibContextLock)?;
            guard.push(script.to_string());
            Ok(())
        }
    }

    fn sample_snapshot() -> RuntimeSnapshot {
        let labels = {
            let mut map = BTreeMap::new();
            map.insert("portcullis.enable".to_string(), "true".to_string());
            map
        };

        let attachment_ip: std::net::IpAddr = match "172.18.0.2".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse attachment ip in fixture: {error}"),
        };
        let subnet: IpNet = match "172.18.0.0/16".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse subnet in fixture: {error}"),
        };
        let dst_cidr: IpNet = match "1.1.1.1/32".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse destination cidr in fixture: {error}"),
        };

        RuntimeSnapshot {
            containers: vec![ContainerSnapshot {
                id: "abc".to_string(),
                name: "web".to_string(),
                labels,
                attachments: vec![NetworkAttachment {
                    network_id: "net0".to_string(),
                    network_name: "bridge".to_string(),
                    ip_address: attachment_ip,
                    subnet,
                    aliases: vec!["web".to_string()],
                }],
                policy: Some(ContainerPolicy {
                    enabled: true,
                    icc_mode: IccMode::Deny,
                    egress: vec![EgressRule {
                        target: EgressTarget::IpCidr(dst_cidr),
                        ports: vec![PortSpec {
                            protocol: Protocol::Tcp,
                            port: 443,
                        }],
                    }],
                    icc_allow: Vec::new(),
                }),
            }],
        }
    }

    #[test]
    fn apply_runs_cleanup_then_apply() {
        let runner = RecordingRunner::new();
        let firewall = NftablesFirewall::new(runner.clone());
        let snapshot = sample_snapshot();

        let result = firewall.apply(&snapshot);
        assert!(result.is_ok());

        let scripts = runner.scripts();
        assert_eq!(scripts.len(), 2);
        assert_eq!(scripts[0], "delete table inet portcullis\n");
        assert!(scripts[1].contains("add table inet portcullis"));
    }

    #[test]
    fn cleanup_ignores_missing_table_error_for_cli() {
        let runner = RecordingRunner::with_error(RunnerFailure::CommandFailure {
            code: 1,
            stderr: "No such file or directory".to_string(),
        });
        let firewall = NftablesFirewall::new(runner);

        let result = firewall.cleanup();
        assert!(result.is_ok());
    }

    #[test]
    fn cleanup_ignores_missing_table_error_for_libnftables() {
        let runner = RecordingRunner::with_error(RunnerFailure::LibCommandFailure {
            code: 1,
            stderr: "No such file or directory".to_string(),
        });
        let firewall = NftablesFirewall::new(runner);

        let result = firewall.cleanup();
        assert!(result.is_ok());
    }

    #[test]
    fn cleanup_propagates_other_errors() {
        let runner = RecordingRunner::with_error(RunnerFailure::CommandFailure {
            code: 2,
            stderr: "permission denied".to_string(),
        });
        let firewall = NftablesFirewall::new(runner);

        let result = firewall.cleanup();
        assert!(matches!(
            result,
            Err(FirewallError::CommandFailure { code: 2, .. })
        ));
    }
}
