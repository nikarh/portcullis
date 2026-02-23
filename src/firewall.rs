use std::io::Write as _;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use thiserror::Error;
use tracing::{debug, info, trace, warn};

use crate::model::{EgressTarget, IccMode, Protocol, RuntimeSnapshot};

const TABLE_FAMILY: &str = "inet";
const TABLE_NAME: &str = "portcullis";
const CHAIN_NAME: &str = "egress";

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
}

pub trait NftRunner {
    fn run_script(&self, script: &str) -> Result<(), FirewallError>;
}

pub struct SystemNftRunner;

impl NftRunner for SystemNftRunner {
    fn run_script(&self, script: &str) -> Result<(), FirewallError> {
        trace!(script = %script, "executing nft script");
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| FirewallError::CommandExecution(error.to_string()))?;

        let mut stdin = child.stdin.take().ok_or(FirewallError::MissingStdin)?;
        stdin
            .write_all(script.as_bytes())
            .map_err(|error| FirewallError::StdinWrite(error.to_string()))?;
        drop(stdin);

        let output = child
            .wait_with_output()
            .map_err(|error| FirewallError::CommandExecution(error.to_string()))?;

        if output.status.success() {
            trace!("nft script executed successfully");
            return Ok(());
        }

        let code = output.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        debug!(code, stderr = %stderr, "nft script execution failed");
        Err(FirewallError::CommandFailure { code, stderr })
    }
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
            Err(error) => Err(error),
        }
    }
}

#[must_use]
pub fn build_apply_script(snapshot: &RuntimeSnapshot) -> String {
    let mut lines = vec![
        format!("add table {TABLE_FAMILY} {TABLE_NAME}"),
        format!(
            "add chain {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} {{ type filter hook forward priority 0; policy accept; }}"
        ),
    ];

    let managed_sources = collect_managed_sources(snapshot);

    for container in &snapshot.containers {
        let Some(policy) = &container.policy else {
            continue;
        };

        if !policy.enabled {
            continue;
        }

        for attachment in &container.attachments {
            if policy.icc_mode == IccMode::Deny
                && let Some(rule) = build_icc_deny_rule(attachment.ip_address, &managed_sources)
            {
                lines.push(rule);
            }

            for rule in &policy.egress {
                let EgressTarget::IpCidr(cidr) = &rule.target else {
                    continue;
                };

                for port in &rule.ports {
                    if let Some(allow_rule) = build_allow_rule(attachment.ip_address, cidr, *port) {
                        lines.push(allow_rule);
                    }
                }
            }

            lines.push(build_default_drop_rule(attachment.ip_address));
        }
    }

    lines.push(String::new());
    lines.join("\n")
}

#[must_use]
pub fn build_cleanup_script() -> String {
    format!("delete table {TABLE_FAMILY} {TABLE_NAME}\n")
}

#[must_use]
pub fn split_nft_commands(script: &str) -> Vec<String> {
    script
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[derive(Debug, Default)]
struct ManagedSources {
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

fn collect_managed_sources(snapshot: &RuntimeSnapshot) -> ManagedSources {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    for container in &snapshot.containers {
        let Some(policy) = &container.policy else {
            continue;
        };

        if !policy.enabled {
            continue;
        }

        for attachment in &container.attachments {
            match attachment.ip_address {
                IpAddr::V4(value) => ipv4.push(value.to_string()),
                IpAddr::V6(value) => ipv6.push(value.to_string()),
            }
        }
    }

    ipv4.sort_unstable();
    ipv4.dedup();
    ipv6.sort_unstable();
    ipv6.dedup();

    ManagedSources { ipv4, ipv6 }
}

fn build_icc_deny_rule(source: IpAddr, sources: &ManagedSources) -> Option<String> {
    match source {
        IpAddr::V4(value) => {
            if sources.ipv4.is_empty() {
                return None;
            }
            let list = sources.ipv4.join(", ");
            Some(format!(
                "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {value} ip daddr {{ {list} }} drop"
            ))
        }
        IpAddr::V6(value) => {
            if sources.ipv6.is_empty() {
                return None;
            }
            let list = sources.ipv6.join(", ");
            Some(format!(
                "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {value} ip6 daddr {{ {list} }} drop"
            ))
        }
    }
}

fn build_allow_rule(
    source: IpAddr,
    cidr: &ipnet::IpNet,
    port: crate::model::PortSpec,
) -> Option<String> {
    let protocol = match port.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };

    match (source, cidr) {
        (IpAddr::V4(src), ipnet::IpNet::V4(dst)) => Some(format!(
            "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {src} ip daddr {dst} {protocol} dport {} accept",
            port.port
        )),
        (IpAddr::V6(src), ipnet::IpNet::V6(dst)) => Some(format!(
            "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {src} ip6 daddr {dst} {protocol} dport {} accept",
            port.port
        )),
        _ => None,
    }
}

fn build_default_drop_rule(source: IpAddr) -> String {
    match source {
        IpAddr::V4(value) => {
            format!("add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {value} drop")
        }
        IpAddr::V6(value) => {
            format!("add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {value} drop")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use ipnet::IpNet;

    use super::*;
    use crate::model::{
        ContainerPolicy, ContainerSnapshot, EgressRule, NetworkAttachment, PortSpec, Protocol,
    };

    #[derive(Clone, Debug)]
    enum RunnerFailure {
        CommandFailure { code: i32, stderr: String },
    }

    #[derive(Clone)]
    struct RecordingRunner {
        scripts: Arc<Mutex<Vec<String>>>,
        fail_with: Option<RunnerFailure>,
    }

    #[derive(Clone)]
    struct Recorder {
        scripts: Arc<Mutex<Vec<String>>>,
    }

    impl Recorder {
        fn scripts(&self) -> Vec<String> {
            let guard = match self.scripts.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock scripts mutex: {error}"),
            };
            guard.clone()
        }
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

        fn recorder(&self) -> Recorder {
            Recorder {
                scripts: Arc::clone(&self.scripts),
            }
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
                });
            }

            let mut guard = self.scripts.lock().map_err(|error| {
                FirewallError::CommandExecution(format!("failed to lock scripts mutex: {error}"))
            })?;
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

        let attachment_ip: IpAddr = match "172.18.0.2".parse() {
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
                }],
                policy: Some(ContainerPolicy {
                    enabled: true,
                    icc_mode: IccMode::Deny,
                    egress: vec![
                        EgressRule {
                            target: EgressTarget::IpCidr(dst_cidr),
                            ports: vec![PortSpec {
                                protocol: Protocol::Tcp,
                                port: 443,
                            }],
                        },
                        EgressRule {
                            target: EgressTarget::Hostname("api.example.com".to_string()),
                            ports: vec![PortSpec {
                                protocol: Protocol::Tcp,
                                port: 443,
                            }],
                        },
                    ],
                }),
            }],
        }
    }

    #[test]
    fn build_apply_script_contains_allow_drop_and_icc_rules() {
        let script = build_apply_script(&sample_snapshot());
        assert!(script.contains("add table inet portcullis"));
        assert!(script.contains("add chain inet portcullis egress"));
        assert!(script.contains(
            "add rule inet portcullis egress ip saddr 172.18.0.2 ip daddr { 172.18.0.2 } drop"
        ));
        assert!(script.contains(
            "add rule inet portcullis egress ip saddr 172.18.0.2 ip daddr 1.1.1.1/32 tcp dport 443 accept"
        ));
        assert!(script.contains("add rule inet portcullis egress ip saddr 172.18.0.2 drop"));
        assert!(!script.contains("api.example.com"));
    }

    #[test]
    fn build_cleanup_script_deletes_table() {
        let script = build_cleanup_script();
        assert_eq!(script, "delete table inet portcullis\n");
    }

    #[test]
    fn split_nft_commands_skips_empty_lines() {
        let commands =
            split_nft_commands("add table inet portcullis\n\nadd chain inet portcullis egress\n");
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0], "add table inet portcullis");
        assert_eq!(commands[1], "add chain inet portcullis egress");
    }

    #[test]
    fn apply_runs_cleanup_then_apply() {
        let runner = RecordingRunner::new();
        let recorder = runner.recorder();
        let firewall = NftablesFirewall::new(runner);
        let snapshot = sample_snapshot();

        let result = firewall.apply(&snapshot);
        assert!(result.is_ok());

        let scripts = recorder.scripts();
        assert_eq!(scripts.len(), 2);
        assert_eq!(scripts[0], "delete table inet portcullis\n");
        assert!(scripts[1].contains("add table inet portcullis"));
    }

    #[test]
    fn cleanup_ignores_missing_table_error() {
        let runner = RecordingRunner::with_error(RunnerFailure::CommandFailure {
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
