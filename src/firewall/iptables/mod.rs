mod commands;

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::process::{Command, Output, Stdio};

use ipnet::Ipv4Net;
use tracing::{info, trace};

use crate::dns::{DnsProxyCache, UpstreamResolver};
use crate::model::{
    DnsTarget, EgressTarget, IccAllowRule, IccMode, NetworkId, PortSpec, Protocol, RuntimeState,
};
use commands::{CommandBuffer, IpsetCommand, IptablesCommand, Ipv4Destination};

use super::FirewallError;

const CHAIN_NAME: &str = "PORTCULLIS_EGRESS";
const STAGING_CHAIN_NAME: &str = "PORTCULLIS_EGRESS_NEXT";
const DOCKER_USER_CHAIN: &str = "DOCKER-USER";

pub trait IptablesRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(), FirewallError>;
    fn run_iptables_restore(&self, commands: &[IptablesCommand<'_>]) -> Result<(), FirewallError>;
    fn run_ipset_restore(&self, commands: &[IpsetCommand]) -> Result<(), FirewallError>;
    fn read_iptables_save_filter(&self) -> Result<String, FirewallError>;
}

pub struct CommandIptablesRunner;

fn ensure_success(output: Output) -> Result<Output, FirewallError> {
    if output.status.success() {
        return Ok(output);
    }

    Err(FirewallError::CommandFailure {
        code: output.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

impl IptablesRunner for CommandIptablesRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<(), FirewallError> {
        trace!(program, args = ?args, "executing firewall command");
        let output = Command::new(program).args(args).output()?;
        ensure_success(output)?;

        Ok(())
    }

    fn run_iptables_restore(&self, commands: &[IptablesCommand<'_>]) -> Result<(), FirewallError> {
        if commands.is_empty() {
            return Ok(());
        }
        trace!(
            program = "iptables-restore",
            args = ?["--noflush"],
            command_count = commands.len(),
            commands = ?commands,
            "executing firewall batch command"
        );
        let mut child = Command::new("iptables-restore")
            .arg("--noflush")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut script = String::from("*filter\n");
        for command in commands {
            writeln!(&mut script, "{command}")?;
        }
        script.push_str("COMMIT\n");
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(script.as_bytes())?;
        } else {
            return Err(FirewallError::CommandStdinUnavailable {
                program: "iptables-restore",
            });
        }
        let output = child.wait_with_output()?;
        ensure_success(output)?;

        Ok(())
    }

    fn run_ipset_restore(&self, commands: &[IpsetCommand]) -> Result<(), FirewallError> {
        if commands.is_empty() {
            return Ok(());
        }
        trace!(
            program = "ipset",
            args = ?["restore"],
            command_count = commands.len(),
            commands = ?commands,
            "executing firewall batch command"
        );
        let mut child = Command::new("ipset")
            .arg("restore")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut script = String::new();
        for command in commands {
            writeln!(&mut script, "{command}")?;
        }
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(script.as_bytes())?;
        } else {
            return Err(FirewallError::CommandStdinUnavailable { program: "ipset" });
        }
        let output = child.wait_with_output()?;
        ensure_success(output)?;

        Ok(())
    }

    fn read_iptables_save_filter(&self) -> Result<String, FirewallError> {
        trace!(program = "iptables-save", args = ?["-t", "filter"], "reading firewall filter table");
        let output = Command::new("iptables-save")
            .args(["-t", "filter"])
            .output()?;
        let output = ensure_success(output)?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

pub struct IptablesFirewall<R> {
    runner: R,
    use_ipset: bool,
}

impl<R> IptablesFirewall<R>
where
    R: IptablesRunner,
{
    pub const fn new(runner: R, use_ipset: bool) -> Self {
        Self { runner, use_ipset }
    }

    pub fn apply<Dns: UpstreamResolver>(
        &self,
        state: &RuntimeState,
        resolver: &mut DnsProxyCache<Dns>,
    ) -> Result<(), FirewallError> {
        let commands = build_apply_commands_with_dns(state, resolver, self.use_ipset, CHAIN_NAME)?;

        self.runner.run_ipset_restore(&commands.ipset)?;
        self.runner.run_iptables_restore(&commands.iptables)?;

        Ok(())
    }

    pub fn initialize(&self) -> Result<(), FirewallError> {
        match self.runner.run("iptables", &["-N", CHAIN_NAME]) {
            Ok(()) => {}
            Err(FirewallError::CommandFailure { stderr, .. })
                if stderr.contains("Chain already exists") => {}
            Err(error) => return Err(error),
        }

        match self.runner.run(
            "iptables",
            &["-I", DOCKER_USER_CHAIN, "1", "-j", CHAIN_NAME],
        ) {
            Ok(()) => {}
            Err(FirewallError::CommandFailure { stderr, .. })
                if stderr.contains("exists") || stderr.contains("Bad rule") => {}
            Err(error) => return Err(error),
        }

        Ok(())
    }

    pub fn cleanup(&self) -> Result<(), FirewallError> {
        let filter_rules = self.runner.read_iptables_save_filter()?;
        let cleanup_commands = build_cleanup_restore_commands(&filter_rules);
        self.runner.run_iptables_restore(&cleanup_commands)?;

        info!("iptables cleanup completed");
        Ok(())
    }
}

impl IptablesFirewall<CommandIptablesRunner> {
    #[must_use]
    pub fn with_cli() -> Self {
        let use_ipset = detect_ipset_available();
        if use_ipset {
            info!("ipset detected at startup; enabling ipset-backed hostname rules");
        } else {
            info!("ipset not detected at startup; using direct iptables hostname rules");
        }
        Self::new(CommandIptablesRunner, use_ipset)
    }
}

fn build_apply_commands_with_dns<'a, Dns: UpstreamResolver>(
    state: &RuntimeState,
    resolver: &mut DnsProxyCache<Dns>,
    use_ipset: bool,
    chain_name: &'a str,
) -> Result<CommandBuffer<'a>, FirewallError> {
    let mut commands = CommandBuffer::default();

    commands
        .iptables
        .push(IptablesCommand::FlushChain { chain: chain_name });

    for container in state.containers.values() {
        let policy = &container.policy;

        for attachment in &container.attachments {
            let IpAddr::V4(source_ipv4) = attachment.ip_address else {
                continue;
            };
            let gateway = network_gateway(state, &attachment.network_id);

            append_implicit_dns_allow_commands(
                &mut commands,
                chain_name,
                source_ipv4,
                gateway,
                &policy.dns_targets,
                &container.runtime_dns_servers,
            );

            match policy.icc_mode {
                IccMode::Allow => {
                    append_icc_allow_commands(
                        &mut commands,
                        chain_name,
                        source_ipv4,
                        &attachment.network_id,
                        state,
                    );
                }
                IccMode::Deny => {
                    append_icc_drop_commands(
                        &mut commands,
                        chain_name,
                        source_ipv4,
                        &attachment.network_id,
                        state,
                    );
                }
                IccMode::AllowListed => {
                    append_icc_allow_list_commands(
                        &mut commands,
                        chain_name,
                        source_ipv4,
                        &attachment.network_id,
                        &policy.icc_allow,
                        state,
                    );
                    append_icc_drop_commands(
                        &mut commands,
                        chain_name,
                        source_ipv4,
                        &attachment.network_id,
                        state,
                    );
                }
            }

            for rule in &policy.egress {
                match &rule.target {
                    EgressTarget::IpCidr(cidr) => {
                        let ipnet::IpNet::V4(destination) = cidr else {
                            continue;
                        };
                        append_ip_target_commands(
                            &mut commands,
                            chain_name,
                            source_ipv4,
                            *destination,
                            &rule.ports,
                        );
                    }
                    EgressTarget::Hostname(host) => {
                        append_hostname_target_commands(
                            &mut commands,
                            chain_name,
                            resolver,
                            source_ipv4,
                            host,
                            &rule.ports,
                            use_ipset,
                        )?;
                    }
                }
            }

            append_default_drop_command(&mut commands, chain_name, source_ipv4);
        }
    }

    append_enforced_network_drop_commands(&mut commands, chain_name, &state.network_subnets());

    Ok(commands)
}

fn append_icc_drop_commands<'a>(
    commands: &mut CommandBuffer<'a>,
    chain_name: &'a str,
    source_ipv4: Ipv4Addr,
    source_network_id: &NetworkId,
    state: &RuntimeState,
) {
    let Some(network) = state.networks.get(source_network_id) else {
        return;
    };
    let ipnet::IpNet::V4(destination_subnet) = network.subnet else {
        return;
    };

    commands.iptables.push(IptablesCommand::DropIccSubnet {
        chain: chain_name,
        source: source_ipv4,
        destination: destination_subnet,
    });
}

fn append_icc_allow_commands<'a>(
    commands: &mut CommandBuffer<'a>,
    chain_name: &'a str,
    source_ipv4: Ipv4Addr,
    source_network_id: &NetworkId,
    state: &RuntimeState,
) {
    for container in state.containers.values() {
        for attachment in &container.attachments {
            if attachment.network_id != *source_network_id {
                continue;
            }
            let IpAddr::V4(destination) = attachment.ip_address else {
                continue;
            };
            if destination == source_ipv4 {
                continue;
            }

            commands.iptables.push(IptablesCommand::AcceptIcc {
                chain: chain_name,
                source: source_ipv4,
                destination,
            });
        }
    }
}

fn append_ip_target_commands<'a>(
    commands: &mut CommandBuffer<'a>,
    chain_name: &'a str,
    source_ipv4: Ipv4Addr,
    destination: Ipv4Net,
    ports: &[PortSpec],
) {
    for port in ports {
        commands.iptables.push(IptablesCommand::AcceptIpPort {
            chain: chain_name,
            source: source_ipv4,
            destination: Ipv4Destination::Cidr(destination),
            protocol: port.protocol,
            port: port.port,
        });
    }
}

fn append_hostname_target_commands<'a>(
    commands: &mut CommandBuffer<'a>,
    chain_name: &'a str,
    resolver: &mut DnsProxyCache<impl UpstreamResolver>,
    source_ipv4: Ipv4Addr,
    host: &str,
    ports: &[PortSpec],
    use_ipset: bool,
) -> Result<(), FirewallError> {
    let addresses = resolver
        .resolve(host)
        .map_err(|error| FirewallError::DnsResolve {
            host: host.to_string(),
            message: error.to_string(),
        })?;

    let destination_ipv4: Vec<Ipv4Addr> = addresses
        .iter()
        .filter_map(|address| match address {
            IpAddr::V4(value) => Some(*value),
            IpAddr::V6(_) => None,
        })
        .collect();

    if use_ipset {
        let host_hash = fnv1a_64(host.as_bytes());
        commands.ipset.push(IpsetCommand::Create { host_hash });
        commands.ipset.push(IpsetCommand::Flush { host_hash });

        for destination in &destination_ipv4 {
            commands.ipset.push(IpsetCommand::Add {
                host_hash,
                destination: *destination,
            });
        }

        for port in ports {
            commands.iptables.push(IptablesCommand::AcceptMatchSetPort {
                chain: chain_name,
                source: source_ipv4,
                host_hash,
                protocol: port.protocol,
                port: port.port,
            });
        }
    } else {
        for port in ports {
            for destination in &destination_ipv4 {
                commands.iptables.push(IptablesCommand::AcceptIpPort {
                    chain: chain_name,
                    source: source_ipv4,
                    destination: Ipv4Destination::Address(*destination),
                    protocol: port.protocol,
                    port: port.port,
                });
            }
        }
    }

    Ok(())
}

/// TODO: This seems like a recipe for disaster
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

fn detect_ipset_available() -> bool {
    match Command::new("ipset").arg("--version").output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

fn append_default_drop_command<'a>(
    commands: &mut CommandBuffer<'a>,
    chain_name: &'a str,
    source_ipv4: Ipv4Addr,
) {
    commands.iptables.push(IptablesCommand::DropSourceIp {
        chain: chain_name,
        source: source_ipv4,
    });
}

fn network_gateway(state: &RuntimeState, network_id: &NetworkId) -> Option<IpAddr> {
    state
        .networks
        .get(network_id)
        .and_then(|network| network.gateway)
}

fn append_enforced_network_drop_commands<'a>(
    commands: &mut CommandBuffer<'a>,
    chain_name: &'a str,
    subnets: &[ipnet::IpNet],
) {
    for subnet in subnets {
        let ipnet::IpNet::V4(value) = subnet else {
            continue;
        };
        commands.iptables.push(IptablesCommand::DropSourceSubnet {
            chain: chain_name,
            subnet: *value,
        });
    }
}

fn append_implicit_dns_allow_commands<'a>(
    commands: &mut CommandBuffer<'a>,
    chain_name: &'a str,
    source_ipv4: Ipv4Addr,
    gateway: Option<IpAddr>,
    dns_targets: &[DnsTarget],
    runtime_dns_servers: &HashSet<IpAddr>,
) {
    let mut allow_any = false;
    let mut destinations = BTreeSet::new();
    for target in dns_targets {
        match target {
            DnsTarget::Docker => {
                if let Some(IpAddr::V4(value)) = gateway {
                    destinations.insert(value);
                }
            }
            DnsTarget::Host | DnsTarget::Ip(IpAddr::V6(_)) => {}
            DnsTarget::Runtime => {
                for value in runtime_dns_servers {
                    if let IpAddr::V4(v4) = value {
                        destinations.insert(*v4);
                    }
                }
            }
            DnsTarget::Ip(IpAddr::V4(value)) => {
                destinations.insert(*value);
            }
            DnsTarget::Any => allow_any = true,
        }
    }

    for protocol in [Protocol::Udp, Protocol::Tcp] {
        if allow_any {
            commands.iptables.push(IptablesCommand::AcceptDns {
                chain: chain_name,
                source: source_ipv4,
                destination: None,
                protocol,
            });
        } else {
            for destination_ipv4 in &destinations {
                commands.iptables.push(IptablesCommand::AcceptDns {
                    chain: chain_name,
                    source: source_ipv4,
                    destination: Some(*destination_ipv4),
                    protocol,
                });
            }
        }
        commands.iptables.push(IptablesCommand::DropDns {
            chain: chain_name,
            source: source_ipv4,
            protocol,
        });
    }
}

fn append_icc_allow_list_commands<'a>(
    commands: &mut CommandBuffer<'a>,
    chain_name: &'a str,
    source_ipv4: Ipv4Addr,
    source_network_id: &NetworkId,
    rules: &[IccAllowRule],
    state: &RuntimeState,
) {
    for rule in rules {
        let Some(target_container_id) = state.resolve_container_id(rule.target_container.as_str())
        else {
            continue;
        };
        let Some(target_container) = state.containers.get(target_container_id) else {
            continue;
        };

        for destination in target_container
            .attachments
            .iter()
            .filter_map(|attachment| match attachment.ip_address {
                IpAddr::V4(value) if attachment.network_id == *source_network_id => Some(value),
                _ => None,
            })
            .filter(|destination| *destination != source_ipv4)
        {
            for port in &rule.ports {
                commands.iptables.push(IptablesCommand::AcceptIpPort {
                    chain: chain_name,
                    source: source_ipv4,
                    destination: Ipv4Destination::Address(destination),
                    protocol: port.protocol,
                    port: port.port,
                });
            }
        }
    }
}

fn docker_user_jump_target(line: &str) -> Option<&str> {
    if !line.starts_with("-A DOCKER-USER ") {
        return None;
    }
    let mut parts = line.split_whitespace();
    while let Some(part) = parts.next() {
        if part == "-j" {
            return parts.next();
        }
    }
    None
}

fn build_cleanup_restore_commands(filter_rules: &str) -> Vec<IptablesCommand<'static>> {
    let mut has_egress_chain = false;
    let mut has_staging_chain = false;
    let mut egress_jump_count = 0usize;
    let mut staging_jump_count = 0usize;

    for line in filter_rules.lines() {
        if line.starts_with(':') {
            if line.starts_with(&format!(":{CHAIN_NAME} ")) {
                has_egress_chain = true;
            } else if line.starts_with(&format!(":{STAGING_CHAIN_NAME} ")) {
                has_staging_chain = true;
            }
            continue;
        }
        if let Some(target) = docker_user_jump_target(line) {
            if target == CHAIN_NAME {
                egress_jump_count += 1;
            } else if target == STAGING_CHAIN_NAME {
                staging_jump_count += 1;
            }
        }
    }

    let mut commands = Vec::new();

    for _ in 0..egress_jump_count {
        commands.push(IptablesCommand::DeleteJump {
            chain: DOCKER_USER_CHAIN,
            target: CHAIN_NAME,
        });
    }
    for _ in 0..staging_jump_count {
        commands.push(IptablesCommand::DeleteJump {
            chain: DOCKER_USER_CHAIN,
            target: STAGING_CHAIN_NAME,
        });
    }
    if has_egress_chain {
        commands.push(IptablesCommand::FlushChain { chain: CHAIN_NAME });
        commands.push(IptablesCommand::DeleteChain { chain: CHAIN_NAME });
    }
    if has_staging_chain {
        commands.push(IptablesCommand::FlushChain {
            chain: STAGING_CHAIN_NAME,
        });
        commands.push(IptablesCommand::DeleteChain {
            chain: STAGING_CHAIN_NAME,
        });
    }

    commands
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Duration;

    use ipnet::IpNet;

    use super::*;
    use crate::dns::{DnsError, DnsProxyCache, UpstreamResolver};
    use crate::model::{
        Container, ContainerPolicy, EgressRule, Network, NetworkAttachment, PortSpec,
    };

    struct MockResolver;

    impl UpstreamResolver for MockResolver {
        fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
            if host == "api.example.com" {
                let ip: IpAddr = match "1.1.1.1".parse() {
                    Ok(value) => value,
                    Err(error) => panic!("failed to parse ip fixture: {error}"),
                };
                return Ok(vec![ip]);
            }
            Err(DnsError::LookupFailed {
                host: host.to_string(),
                message: "not found".to_string(),
            })
        }
    }

    fn sample_state() -> RuntimeState {
        let source_ip: IpAddr = match "172.18.0.2".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse source ip: {error}"),
        };
        let subnet: IpNet = match "172.18.0.0/16".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse subnet: {error}"),
        };

        let mut state = RuntimeState::default();
        state.containers.insert(
            "abc".into(),
            Container {
                name: "web".to_string(),
                attachments: vec![NetworkAttachment {
                    network_id: "net0".into(),
                    ip_address: source_ip,
                    aliases: vec!["web".to_string(), "app".to_string()],
                }],
                runtime_dns_servers: HashSet::new(),
                policy: ContainerPolicy {
                    icc_mode: IccMode::Allow,
                    egress: vec![EgressRule {
                        target: EgressTarget::Hostname("api.example.com".to_string()),
                        ports: vec![PortSpec {
                            protocol: Protocol::Tcp,
                            port: 443,
                        }],
                    }],
                    icc_allow: Vec::new(),
                    dns_targets: vec![crate::model::DnsTarget::Docker],
                },
            },
        );
        state.networks.insert(
            "net0".into(),
            Network {
                id: "net0".into(),
                name: "bridge".to_string(),
                subnet,
                gateway: Some("172.18.0.1".parse().expect("gateway fixture should parse")),
            },
        );
        state.refresh_indexes();
        state
    }

    #[test]
    fn build_commands_includes_iptables_for_hostname_without_ipset() {
        let mut resolver = DnsProxyCache::new(MockResolver, Duration::from_secs(300), 128);
        let commands =
            build_apply_commands_with_dns(&sample_state(), &mut resolver, false, CHAIN_NAME);
        assert!(commands.is_ok());
        let value = match commands {
            Ok(items) => items,
            Err(error) => panic!("expected command build to succeed: {error}"),
        };

        assert!(
            value
                .iptables
                .iter()
                .map(std::string::ToString::to_string)
                .any(|line| {
                    line.contains("-d 1.1.1.1/32")
                        && line.contains("--dport 443")
                        && line.contains("ACCEPT")
                })
        );
    }

    #[test]
    fn build_commands_include_icc_allowlisted_alias_target() {
        let mut state = sample_state();
        let peer_ip: IpAddr = match "172.18.0.10".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse peer ip: {error}"),
        };
        let subnet: IpNet = match "172.18.0.0/16".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse subnet: {error}"),
        };
        let second_subnet: IpNet = match "172.19.0.0/16".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse subnet: {error}"),
        };
        state.containers.insert(
            "peer".into(),
            Container {
                name: "/peer".to_string(),
                attachments: vec![
                    NetworkAttachment {
                        network_id: "net0".into(),
                        ip_address: peer_ip,
                        aliases: vec!["db".to_string()],
                    },
                    NetworkAttachment {
                        network_id: "net1".into(),
                        ip_address: "172.19.0.10".parse().expect("peer ip should parse"),
                        aliases: vec!["db".to_string()],
                    },
                ],
                runtime_dns_servers: HashSet::new(),
                policy: crate::model::ContainerPolicy::default(),
            },
        );
        state.networks.insert(
            "net0".into(),
            Network {
                id: "net0".into(),
                name: "bridge".to_string(),
                subnet,
                gateway: Some("172.18.0.1".parse().expect("gateway fixture should parse")),
            },
        );
        state.networks.insert(
            "net1".into(),
            Network {
                id: "net1".into(),
                name: "bridge2".to_string(),
                subnet: second_subnet,
                gateway: Some("172.19.0.1".parse().expect("gateway fixture should parse")),
            },
        );
        state.refresh_indexes();
        state
            .containers
            .get_mut("abc")
            .expect("abc fixture container should exist")
            .policy
            .icc_mode = IccMode::AllowListed;
        state
            .containers
            .get_mut("abc")
            .expect("abc fixture container should exist")
            .policy
            .icc_allow = vec![crate::model::IccAllowRule {
            target_container: "db".into(),
            ports: vec![PortSpec {
                protocol: Protocol::Tcp,
                port: 5432,
            }],
        }];

        let mut resolver = DnsProxyCache::new(MockResolver, Duration::from_secs(300), 128);
        let commands = build_apply_commands_with_dns(&state, &mut resolver, false, CHAIN_NAME)
            .expect("expected command build to succeed");
        assert!(
            commands
                .iptables
                .iter()
                .map(std::string::ToString::to_string)
                .any(|line| {
                    line.contains("-d 172.18.0.10/32") && line.contains("--dport 5432")
                })
        );
        assert!(
            !commands
                .iptables
                .iter()
                .map(std::string::ToString::to_string)
                .any(|line| {
                    line.contains("-d 172.19.")
                        && line.contains("--dport 5432")
                        && line.contains("ACCEPT")
                })
        );
    }

    #[test]
    fn build_commands_adds_icc_allow_for_same_network_container_ips() {
        let mut state = sample_state();
        state.containers.insert(
            "peer".into(),
            Container {
                name: "peer".to_string(),
                attachments: vec![NetworkAttachment {
                    network_id: "net0".into(),
                    ip_address: "172.18.0.10".parse().expect("peer ip should parse"),
                    aliases: vec!["peer".to_string()],
                }],
                runtime_dns_servers: HashSet::new(),
                policy: ContainerPolicy::default(),
            },
        );
        state.refresh_indexes();

        let mut resolver = DnsProxyCache::new(MockResolver, Duration::from_secs(300), 128);
        let commands = build_apply_commands_with_dns(&state, &mut resolver, false, CHAIN_NAME)
            .expect("expected command build to succeed");

        assert!(
            commands
                .iptables
                .iter()
                .map(std::string::ToString::to_string)
                .any(|line| {
                    line == "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -d 172.18.0.10/32 -j ACCEPT"
                })
        );
    }

    #[test]
    fn build_commands_adds_icc_deny_as_subnet_drop() {
        let mut state = sample_state();
        state
            .containers
            .get_mut("abc")
            .expect("abc fixture container should exist")
            .policy
            .icc_mode = IccMode::Deny;

        let mut resolver = DnsProxyCache::new(MockResolver, Duration::from_secs(300), 128);
        let commands = build_apply_commands_with_dns(&state, &mut resolver, false, CHAIN_NAME)
            .expect("expected command build to succeed");

        assert!(
            commands
                .iptables
                .iter()
                .map(std::string::ToString::to_string)
                .any(|line| {
                    line == "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -d 172.18.0.0/16 -j DROP"
                })
        );
    }

    #[test]
    fn build_commands_target_supplied_chain_name() {
        let mut resolver = DnsProxyCache::new(MockResolver, Duration::from_secs(300), 128);
        let commands =
            build_apply_commands_with_dns(&sample_state(), &mut resolver, false, "MYCHAIN")
                .expect("commands");
        assert!(
            commands
                .iptables
                .iter()
                .map(std::string::ToString::to_string)
                .any(|line| line.contains("-A MYCHAIN "))
        );
    }

    struct MockIptablesRunner {
        results: Mutex<VecDeque<Result<(), FirewallError>>>,
        save_filter_output: String,
    }

    impl MockIptablesRunner {
        fn new_with_save(
            results: Vec<Result<(), FirewallError>>,
            save_filter_output: &str,
        ) -> Self {
            Self {
                results: Mutex::new(VecDeque::from(results)),
                save_filter_output: save_filter_output.to_string(),
            }
        }
    }

    impl IptablesRunner for MockIptablesRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> Result<(), FirewallError> {
            let mut guard = self
                .results
                .lock()
                .expect("failed to lock mock iptables runner");
            guard.pop_front().unwrap_or(Ok(()))
        }

        fn run_iptables_restore(
            &self,
            _commands: &[IptablesCommand<'_>],
        ) -> Result<(), FirewallError> {
            let mut guard = self
                .results
                .lock()
                .expect("failed to lock mock iptables runner");
            guard.pop_front().unwrap_or(Ok(()))
        }

        fn run_ipset_restore(&self, commands: &[IpsetCommand]) -> Result<(), FirewallError> {
            if commands.is_empty() {
                return Ok(());
            }
            let mut guard = self
                .results
                .lock()
                .expect("failed to lock mock iptables runner");
            guard.pop_front().unwrap_or(Ok(()))
        }

        fn read_iptables_save_filter(&self) -> Result<String, FirewallError> {
            Ok(self.save_filter_output.clone())
        }
    }

    #[test]
    fn iptables_command_display_formats_line() {
        let line = IptablesCommand::DropSourceIp {
            chain: "PORTCULLIS_EGRESS",
            source: "172.18.0.2".parse().expect("source fixture should parse"),
        }
        .to_string();
        assert_eq!(line, "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -j DROP");
    }

    #[test]
    fn cleanup_runs_via_single_iptables_restore_batch() {
        let runner = MockIptablesRunner::new_with_save(
            vec![Ok(())],
            "\
*filter
:INPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
:PORTCULLIS_EGRESS - [0:0]
-A DOCKER-USER -j PORTCULLIS_EGRESS
COMMIT
",
        );
        let firewall = IptablesFirewall::new(runner, false);
        let result = firewall.cleanup();
        assert!(result.is_ok());
    }

    #[test]
    fn build_cleanup_restore_commands_detects_existing_rules() {
        let commands = build_cleanup_restore_commands(
            "\
*filter
:INPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
:PORTCULLIS_EGRESS - [0:0]
:PORTCULLIS_EGRESS_NEXT - [0:0]
-A DOCKER-USER -j PORTCULLIS_EGRESS
-A DOCKER-USER -j PORTCULLIS_EGRESS_NEXT
COMMIT
",
        );
        let lines: Vec<String> = commands
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(
            lines,
            vec![
                "-D DOCKER-USER -j PORTCULLIS_EGRESS".to_string(),
                "-D DOCKER-USER -j PORTCULLIS_EGRESS_NEXT".to_string(),
                "-F PORTCULLIS_EGRESS".to_string(),
                "-X PORTCULLIS_EGRESS".to_string(),
                "-F PORTCULLIS_EGRESS_NEXT".to_string(),
                "-X PORTCULLIS_EGRESS_NEXT".to_string(),
            ]
        );
    }

    #[test]
    fn build_commands_includes_ipset_for_hostname_with_ipset() {
        let mut resolver = DnsProxyCache::new(MockResolver, Duration::from_secs(300), 128);
        let commands =
            build_apply_commands_with_dns(&sample_state(), &mut resolver, true, CHAIN_NAME)
                .expect("expected command build to succeed");
        assert!(
            commands
                .ipset
                .iter()
                .any(|command| matches!(command, IpsetCommand::Create { .. }))
        );
        assert!(
            commands
                .iptables
                .iter()
                .map(std::string::ToString::to_string)
                .any(|line| line.contains("--match-set pc_h4_"))
        );
    }

    #[test]
    fn build_commands_adds_baseline_drop_for_enforced_network() {
        let state = sample_state();
        let mut resolver = DnsProxyCache::new(MockResolver, Duration::from_secs(300), 128);
        let commands = build_apply_commands_with_dns(&state, &mut resolver, false, CHAIN_NAME)
            .expect("expected command build to succeed");
        assert!(
            commands
                .iptables
                .iter()
                .map(std::string::ToString::to_string)
                .any(|line| line == "-A PORTCULLIS_EGRESS -s 172.18.0.0/16 -j DROP")
        );
    }

    #[test]
    fn build_commands_adds_dns_allows_for_gateway_by_default() {
        let mut resolver = DnsProxyCache::new(MockResolver, Duration::from_secs(300), 128);
        let commands =
            build_apply_commands_with_dns(&sample_state(), &mut resolver, false, CHAIN_NAME)
                .expect("expected command build to succeed");
        assert!(commands
            .iptables
            .iter()
            .map(std::string::ToString::to_string)
            .any(|line| {
                line
                    == "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -d 172.18.0.1/32 -p udp --dport 53 -j ACCEPT"
            }));
        assert!(commands
            .iptables
            .iter()
            .map(std::string::ToString::to_string)
            .any(|line| {
                line
                    == "-A PORTCULLIS_EGRESS -s 172.18.0.2/32 -d 172.18.0.1/32 -p tcp --dport 53 -j ACCEPT"
            }));
    }
}
