use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::net::IpAddr;
use std::process::Command;
use std::process::Stdio;

use tracing::{info, trace};

use crate::dns::HostnameIpResolver;
use crate::model::{DnsTarget, EgressTarget, IccMode, NetworkId, Protocol, RuntimeSnapshot};

use super::FirewallError;

const CHAIN_NAME: &str = "PORTCULLIS_EGRESS";
const STAGING_CHAIN_NAME: &str = "PORTCULLIS_EGRESS_NEXT";
const DOCKER_USER_CHAIN: &str = "DOCKER-USER";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandSpec {
    program: &'static str,
    args: Vec<String>,
}

pub trait IptablesRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<(), FirewallError>;
    fn run_iptables_restore(&self, lines: &[String]) -> Result<(), FirewallError>;
    fn read_iptables_save_filter(&self) -> Result<String, FirewallError>;
}

pub struct CommandIptablesRunner;

impl IptablesRunner for CommandIptablesRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<(), FirewallError> {
        trace!(program, args = ?args, "executing firewall command");
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|error| FirewallError::CommandExecution(error.to_string()))?;

        if output.status.success() {
            return Ok(());
        }

        Err(FirewallError::CommandFailure {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    fn run_iptables_restore(&self, lines: &[String]) -> Result<(), FirewallError> {
        if lines.is_empty() {
            return Ok(());
        }
        trace!(
            program = "iptables-restore",
            args = ?["--noflush"],
            line_count = lines.len(),
            lines = ?lines,
            "executing firewall batch command"
        );
        let mut child = Command::new("iptables-restore")
            .arg("--noflush")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| FirewallError::CommandExecution(error.to_string()))?;
        let mut script = String::from("*filter\n");
        for line in lines {
            script.push_str(line);
            script.push('\n');
        }
        script.push_str("COMMIT\n");
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(script.as_bytes())
                .map_err(|error| FirewallError::CommandExecution(error.to_string()))?;
        } else {
            return Err(FirewallError::CommandExecution(
                "iptables-restore stdin unavailable".to_string(),
            ));
        }
        let output = child
            .wait_with_output()
            .map_err(|error| FirewallError::CommandExecution(error.to_string()))?;
        if output.status.success() {
            return Ok(());
        }
        Err(FirewallError::CommandFailure {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    fn read_iptables_save_filter(&self) -> Result<String, FirewallError> {
        trace!(program = "iptables-save", args = ?["-t", "filter"], "reading firewall filter table");
        let output = Command::new("iptables-save")
            .args(["-t", "filter"])
            .output()
            .map_err(|error| FirewallError::CommandExecution(error.to_string()))?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
        Err(FirewallError::CommandFailure {
            code: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
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

    pub fn apply_with_dns(
        &self,
        snapshot: &RuntimeSnapshot,
        resolver: &mut dyn HostnameIpResolver,
    ) -> Result<(), FirewallError> {
        self.ensure_chain_and_jump()?;

        let commands =
            build_apply_commands_with_dns(snapshot, resolver, self.use_ipset, CHAIN_NAME)?;
        let mut restore_lines = Vec::new();
        restore_lines.push(format!("-F {CHAIN_NAME}"));
        for command in commands {
            if command.program == "iptables" {
                restore_lines.push(iptables_restore_line(&command.args));
            } else {
                self.runner.run(command.program, &command.args)?;
            }
        }
        self.runner.run_iptables_restore(&restore_lines)?;

        Ok(())
    }

    pub fn cleanup(&self) -> Result<(), FirewallError> {
        let filter_rules = self.runner.read_iptables_save_filter()?;
        let cleanup_lines = build_cleanup_restore_lines(&filter_rules);
        self.runner.run_iptables_restore(&cleanup_lines)?;

        info!("iptables cleanup completed");
        Ok(())
    }

    fn ensure_chain_and_jump(&self) -> Result<(), FirewallError> {
        match self
            .runner
            .run("iptables", &["-N".to_string(), CHAIN_NAME.to_string()])
        {
            Ok(()) => {}
            Err(FirewallError::CommandFailure { stderr, .. })
                if stderr.contains("Chain already exists") => {}
            Err(error) => return Err(error),
        }

        match self.runner.run(
            "iptables",
            &[
                "-C".to_string(),
                DOCKER_USER_CHAIN.to_string(),
                "-j".to_string(),
                CHAIN_NAME.to_string(),
            ],
        ) {
            Ok(()) => {}
            Err(FirewallError::CommandFailure { stderr, .. })
                if is_ignorable_cleanup_stderr(&stderr) =>
            {
                self.runner.run(
                    "iptables",
                    &[
                        "-I".to_string(),
                        DOCKER_USER_CHAIN.to_string(),
                        "1".to_string(),
                        "-j".to_string(),
                        CHAIN_NAME.to_string(),
                    ],
                )?;
            }
            Err(error) => return Err(error),
        }

        Ok(())
    }
}

fn is_ignorable_cleanup_stderr(stderr: &str) -> bool {
    stderr.contains("No chain/target/match by that name")
        || stderr.contains("Bad rule")
        || (stderr.contains("Couldn't load target") && stderr.contains("No such file or directory"))
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

fn build_apply_commands_with_dns(
    snapshot: &RuntimeSnapshot,
    resolver: &mut dyn HostnameIpResolver,
    use_ipset: bool,
    chain_name: &str,
) -> Result<Vec<CommandSpec>, FirewallError> {
    let mut commands = Vec::new();

    let managed_ipv4 = collect_managed_ipv4(snapshot);
    let container_targets = collect_container_targets(snapshot);

    for container in &snapshot.containers {
        let policy = &container.policy;

        if !policy.enabled {
            continue;
        }

        for attachment in &container.attachments {
            let IpAddr::V4(source_ipv4) = attachment.ip_address else {
                continue;
            };
            let gateway = network_gateway(snapshot, &attachment.network_id);
            append_implicit_dns_allow_commands(
                &mut commands,
                chain_name,
                source_ipv4,
                gateway,
                &policy.dns_targets,
                &container.runtime_dns_servers,
            );

            if policy.icc_mode == IccMode::Deny {
                append_icc_drop_commands(&mut commands, chain_name, source_ipv4, &managed_ipv4);
            } else if policy.icc_mode == IccMode::AllowListed {
                append_icc_allow_list_commands(
                    &mut commands,
                    chain_name,
                    source_ipv4,
                    &policy.icc_allow,
                    &container_targets,
                );
                append_icc_drop_commands(&mut commands, chain_name, source_ipv4, &managed_ipv4);
            }

            for rule in &policy.egress {
                match &rule.target {
                    EgressTarget::IpCidr(cidr) => {
                        if cidr.addr().is_ipv6() {
                            continue;
                        }

                        append_ip_target_commands(
                            &mut commands,
                            chain_name,
                            source_ipv4,
                            &cidr.to_string(),
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
    append_enforced_network_drop_commands(
        &mut commands,
        chain_name,
        &snapshot.enforced_network_subnets,
    );

    Ok(commands)
}

fn append_icc_drop_commands(
    commands: &mut Vec<CommandSpec>,
    chain_name: &str,
    source_ipv4: std::net::Ipv4Addr,
    managed_ipv4: &[std::net::Ipv4Addr],
) {
    for destination in managed_ipv4 {
        commands.push(CommandSpec {
            program: "iptables",
            args: vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-s".to_string(),
                format!("{source_ipv4}/32"),
                "-d".to_string(),
                format!("{destination}/32"),
                "-j".to_string(),
                "DROP".to_string(),
            ],
        });
    }
}

fn append_ip_target_commands(
    commands: &mut Vec<CommandSpec>,
    chain_name: &str,
    source_ipv4: std::net::Ipv4Addr,
    destination: &str,
    ports: &[crate::model::PortSpec],
) {
    for port in ports {
        commands.push(CommandSpec {
            program: "iptables",
            args: vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-s".to_string(),
                format!("{source_ipv4}/32"),
                "-d".to_string(),
                destination.to_string(),
                "-p".to_string(),
                protocol_name(port.protocol).to_string(),
                "--dport".to_string(),
                port.port.to_string(),
                "-j".to_string(),
                "ACCEPT".to_string(),
            ],
        });
    }
}

fn append_hostname_target_commands(
    commands: &mut Vec<CommandSpec>,
    chain_name: &str,
    resolver: &mut dyn HostnameIpResolver,
    source_ipv4: std::net::Ipv4Addr,
    host: &str,
    ports: &[crate::model::PortSpec],
    use_ipset: bool,
) -> Result<(), FirewallError> {
    let addresses = resolver
        .resolve(host)
        .map_err(|error| FirewallError::DnsResolve {
            host: host.to_string(),
            message: error.to_string(),
        })?;
    let destination_ipv4: Vec<std::net::Ipv4Addr> = addresses
        .iter()
        .filter_map(|address| match address {
            IpAddr::V4(value) => Some(*value),
            IpAddr::V6(_) => None,
        })
        .collect();

    if use_ipset {
        let set_name = set_name_for_host(host);
        commands.push(CommandSpec {
            program: "ipset",
            args: vec![
                "create".to_string(),
                set_name.clone(),
                "hash:ip".to_string(),
                "-exist".to_string(),
            ],
        });
        commands.push(CommandSpec {
            program: "ipset",
            args: vec!["flush".to_string(), set_name.clone()],
        });

        for destination in &destination_ipv4 {
            commands.push(CommandSpec {
                program: "ipset",
                args: vec![
                    "add".to_string(),
                    set_name.clone(),
                    destination.to_string(),
                    "-exist".to_string(),
                ],
            });
        }

        for port in ports {
            commands.push(CommandSpec {
                program: "iptables",
                args: vec![
                    "-A".to_string(),
                    chain_name.to_string(),
                    "-s".to_string(),
                    format!("{source_ipv4}/32"),
                    "-m".to_string(),
                    "set".to_string(),
                    "--match-set".to_string(),
                    set_name.clone(),
                    "dst".to_string(),
                    "-p".to_string(),
                    protocol_name(port.protocol).to_string(),
                    "--dport".to_string(),
                    port.port.to_string(),
                    "-j".to_string(),
                    "ACCEPT".to_string(),
                ],
            });
        }
    } else {
        for port in ports {
            for destination in &destination_ipv4 {
                commands.push(CommandSpec {
                    program: "iptables",
                    args: vec![
                        "-A".to_string(),
                        chain_name.to_string(),
                        "-s".to_string(),
                        format!("{source_ipv4}/32"),
                        "-d".to_string(),
                        format!("{destination}/32"),
                        "-p".to_string(),
                        protocol_name(port.protocol).to_string(),
                        "--dport".to_string(),
                        port.port.to_string(),
                        "-j".to_string(),
                        "ACCEPT".to_string(),
                    ],
                });
            }
        }
    }

    Ok(())
}

fn set_name_for_host(host: &str) -> String {
    let hash = fnv1a_64(host.as_bytes());
    format!("pc_h4_{hash:016x}")
}

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

fn append_default_drop_command(
    commands: &mut Vec<CommandSpec>,
    chain_name: &str,
    source_ipv4: std::net::Ipv4Addr,
) {
    commands.push(CommandSpec {
        program: "iptables",
        args: vec![
            "-A".to_string(),
            chain_name.to_string(),
            "-s".to_string(),
            format!("{source_ipv4}/32"),
            "-j".to_string(),
            "DROP".to_string(),
        ],
    });
}

fn collect_managed_ipv4(snapshot: &RuntimeSnapshot) -> Vec<std::net::Ipv4Addr> {
    let mut values = BTreeSet::new();
    for container in &snapshot.containers {
        let policy = &container.policy;
        if !policy.enabled {
            continue;
        }

        for attachment in &container.attachments {
            if let IpAddr::V4(value) = attachment.ip_address {
                values.insert(value);
            }
        }
    }

    values.into_iter().collect()
}

fn network_gateway(snapshot: &RuntimeSnapshot, network_id: &NetworkId) -> Option<IpAddr> {
    snapshot
        .networks
        .get(network_id)
        .and_then(|network| network.gateway)
}

fn append_enforced_network_drop_commands(
    commands: &mut Vec<CommandSpec>,
    chain_name: &str,
    subnets: &[ipnet::IpNet],
) {
    for subnet in subnets {
        let ipnet::IpNet::V4(value) = subnet else {
            continue;
        };
        commands.push(CommandSpec {
            program: "iptables",
            args: vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-s".to_string(),
                value.to_string(),
                "-j".to_string(),
                "DROP".to_string(),
            ],
        });
    }
}

fn append_implicit_dns_allow_commands(
    commands: &mut Vec<CommandSpec>,
    chain_name: &str,
    source_ipv4: std::net::Ipv4Addr,
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

    for protocol in ["udp", "tcp"] {
        if allow_any {
            commands.push(CommandSpec {
                program: "iptables",
                args: vec![
                    "-A".to_string(),
                    chain_name.to_string(),
                    "-s".to_string(),
                    format!("{source_ipv4}/32"),
                    "-p".to_string(),
                    protocol.to_string(),
                    "--dport".to_string(),
                    "53".to_string(),
                    "-j".to_string(),
                    "ACCEPT".to_string(),
                ],
            });
        } else {
            for destination_ipv4 in &destinations {
                commands.push(CommandSpec {
                    program: "iptables",
                    args: vec![
                        "-A".to_string(),
                        chain_name.to_string(),
                        "-s".to_string(),
                        format!("{source_ipv4}/32"),
                        "-d".to_string(),
                        format!("{destination_ipv4}/32"),
                        "-p".to_string(),
                        protocol.to_string(),
                        "--dport".to_string(),
                        "53".to_string(),
                        "-j".to_string(),
                        "ACCEPT".to_string(),
                    ],
                });
            }
        }
        commands.push(CommandSpec {
            program: "iptables",
            args: vec![
                "-A".to_string(),
                chain_name.to_string(),
                "-s".to_string(),
                format!("{source_ipv4}/32"),
                "-p".to_string(),
                protocol.to_string(),
                "--dport".to_string(),
                "53".to_string(),
                "-j".to_string(),
                "DROP".to_string(),
            ],
        });
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn append_icc_allow_list_commands(
    commands: &mut Vec<CommandSpec>,
    chain_name: &str,
    source_ipv4: std::net::Ipv4Addr,
    rules: &[crate::model::IccAllowRule],
    container_targets: &HashMap<String, Vec<std::net::Ipv4Addr>>,
) {
    for rule in rules {
        let Some(destinations) = container_targets.get(rule.target_container.as_str()) else {
            continue;
        };
        for destination in destinations {
            for port in &rule.ports {
                commands.push(CommandSpec {
                    program: "iptables",
                    args: vec![
                        "-A".to_string(),
                        chain_name.to_string(),
                        "-s".to_string(),
                        format!("{source_ipv4}/32"),
                        "-d".to_string(),
                        format!("{destination}/32"),
                        "-p".to_string(),
                        protocol_name(port.protocol).to_string(),
                        "--dport".to_string(),
                        port.port.to_string(),
                        "-j".to_string(),
                        "ACCEPT".to_string(),
                    ],
                });
            }
        }
    }
}

fn collect_container_targets(
    snapshot: &RuntimeSnapshot,
) -> HashMap<String, Vec<std::net::Ipv4Addr>> {
    let mut by_key: HashMap<String, BTreeSet<std::net::Ipv4Addr>> = HashMap::new();

    for container in &snapshot.containers {
        let mut keys = vec![container.id.to_string(), container.name.clone()];
        if let Some(trimmed) = container.name.strip_prefix('/') {
            keys.push(trimmed.to_string());
        }
        for attachment in &container.attachments {
            for alias in &attachment.aliases {
                keys.push(alias.clone());
            }
        }

        for key in keys {
            let entry = by_key.entry(key).or_default();
            for attachment in &container.attachments {
                if let IpAddr::V4(value) = attachment.ip_address {
                    entry.insert(value);
                }
            }
        }
    }

    by_key
        .into_iter()
        .map(|(key, values)| (key, values.into_iter().collect()))
        .collect()
}

fn iptables_restore_line(args: &[String]) -> String {
    args.join(" ")
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

fn build_cleanup_restore_lines(filter_rules: &str) -> Vec<String> {
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

    let mut lines = Vec::new();
    for _ in 0..egress_jump_count {
        lines.push(format!("-D {DOCKER_USER_CHAIN} -j {CHAIN_NAME}"));
    }
    for _ in 0..staging_jump_count {
        lines.push(format!("-D {DOCKER_USER_CHAIN} -j {STAGING_CHAIN_NAME}"));
    }
    if has_egress_chain {
        lines.push(format!("-F {CHAIN_NAME}"));
        lines.push(format!("-X {CHAIN_NAME}"));
    }
    if has_staging_chain {
        lines.push(format!("-F {STAGING_CHAIN_NAME}"));
        lines.push(format!("-X {STAGING_CHAIN_NAME}"));
    }

    lines
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;
    use std::sync::Mutex;

    use ipnet::IpNet;

    use super::*;
    use crate::dns::{DnsError, HostnameIpResolver};
    use crate::model::{
        ContainerPolicy, ContainerSnapshot, EgressRule, NetworkAttachment, NetworkSnapshot,
        PortSpec,
    };

    struct MockResolver;

    impl HostnameIpResolver for MockResolver {
        fn resolve(&mut self, host: &str) -> Result<Arc<[IpAddr]>, DnsError> {
            if host == "api.example.com" {
                let ip: IpAddr = match "1.1.1.1".parse() {
                    Ok(value) => value,
                    Err(error) => panic!("failed to parse ip fixture: {error}"),
                };
                return Ok(Arc::from(vec![ip].into_boxed_slice()));
            }
            Err(DnsError::LookupFailed {
                host: host.to_string(),
                message: "not found".to_string(),
            })
        }
    }

    fn sample_snapshot() -> RuntimeSnapshot {
        let source_ip: IpAddr = match "172.18.0.2".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse source ip: {error}"),
        };
        let subnet: IpNet = match "172.18.0.0/16".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse subnet: {error}"),
        };

        RuntimeSnapshot {
            containers: vec![ContainerSnapshot {
                id: "abc".into(),
                name: "web".to_string(),
                attachments: vec![NetworkAttachment {
                    network_id: "net0".into(),
                    ip_address: source_ip,
                    aliases: vec!["web".to_string(), "app".to_string()],
                }],
                runtime_dns_servers: HashSet::new(),
                policy: ContainerPolicy {
                    enabled: true,
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
            }],
            networks: HashMap::from([(
                "net0".into(),
                NetworkSnapshot {
                    id: "net0".into(),
                    name: "bridge".to_string(),
                    subnet,
                    gateway: Some("172.18.0.1".parse().expect("gateway fixture should parse")),
                    enforced: false,
                },
            )]),
            enforced_network_subnets: Vec::new(),
        }
    }

    #[test]
    fn build_commands_includes_iptables_for_hostname_without_ipset() {
        let mut resolver = MockResolver;
        let commands =
            build_apply_commands_with_dns(&sample_snapshot(), &mut resolver, false, CHAIN_NAME);
        assert!(commands.is_ok());
        let value = match commands {
            Ok(items) => items,
            Err(error) => panic!("expected command build to succeed: {error}"),
        };

        assert!(value.iter().any(|command| {
            command.program == "iptables"
                && command.args.iter().any(|arg| arg == "-d")
                && command.args.iter().any(|arg| arg == "1.1.1.1/32")
                && command.args.iter().any(|arg| arg == "--dport")
                && command.args.iter().any(|arg| arg == "443")
        }));
    }

    #[test]
    fn build_commands_include_icc_allowlisted_alias_target() {
        let mut snapshot = sample_snapshot();
        let peer_ip: IpAddr = match "172.18.0.10".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse peer ip: {error}"),
        };
        let subnet: IpNet = match "172.18.0.0/16".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse subnet: {error}"),
        };
        snapshot.containers.push(ContainerSnapshot {
            id: "peer".into(),
            name: "/peer".to_string(),
            attachments: vec![NetworkAttachment {
                network_id: "net0".into(),
                ip_address: peer_ip,
                aliases: vec!["db".to_string()],
            }],
            runtime_dns_servers: HashSet::new(),
            policy: crate::model::ContainerPolicy::default(),
        });
        snapshot.networks.insert(
            "net0".into(),
            NetworkSnapshot {
                id: "net0".into(),
                name: "bridge".to_string(),
                subnet,
                gateway: Some("172.18.0.1".parse().expect("gateway fixture should parse")),
                enforced: false,
            },
        );
        snapshot.containers[0].policy.icc_mode = IccMode::AllowListed;
        snapshot.containers[0].policy.icc_allow = vec![crate::model::IccAllowRule {
            target_container: "db".into(),
            ports: vec![PortSpec {
                protocol: Protocol::Tcp,
                port: 5432,
            }],
        }];

        let mut resolver = MockResolver;
        let commands = build_apply_commands_with_dns(&snapshot, &mut resolver, false, CHAIN_NAME)
            .expect("expected command build to succeed");
        assert!(commands.iter().any(|command| {
            command.program == "iptables"
                && command.args.iter().any(|arg| arg == "-d")
                && command.args.iter().any(|arg| arg == "172.18.0.10/32")
                && command.args.iter().any(|arg| arg == "--dport")
                && command.args.iter().any(|arg| arg == "5432")
        }));
    }

    #[test]
    fn build_commands_target_supplied_chain_name() {
        let mut resolver = MockResolver;
        let commands =
            build_apply_commands_with_dns(&sample_snapshot(), &mut resolver, false, "MYCHAIN")
                .expect("commands");
        assert!(commands.iter().any(|command| {
            command.program == "iptables" && command.args.iter().any(|arg| arg == "MYCHAIN")
        }));
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
        fn run(&self, _program: &str, _args: &[String]) -> Result<(), FirewallError> {
            let mut guard = self
                .results
                .lock()
                .expect("failed to lock mock iptables runner");
            guard.pop_front().unwrap_or(Ok(()))
        }

        fn run_iptables_restore(&self, _lines: &[String]) -> Result<(), FirewallError> {
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
    fn iptables_restore_line_joins_arguments() {
        let line = iptables_restore_line(&[
            "-A".to_string(),
            "PORTCULLIS_EGRESS".to_string(),
            "-j".to_string(),
            "DROP".to_string(),
        ]);
        assert_eq!(line, "-A PORTCULLIS_EGRESS -j DROP");
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
    fn build_cleanup_restore_lines_detects_existing_rules() {
        let lines = build_cleanup_restore_lines(
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
        let mut resolver = MockResolver;
        let commands =
            build_apply_commands_with_dns(&sample_snapshot(), &mut resolver, true, CHAIN_NAME)
                .expect("expected command build to succeed");
        assert!(commands.iter().any(|command| {
            command.program == "ipset"
                && command.args.first() == Some(&"create".to_string())
                && command
                    .args
                    .get(1)
                    .is_some_and(|name| name.starts_with("pc_h4_"))
        }));
        assert!(commands.iter().any(|command| {
            command.program == "iptables"
                && command.args.iter().any(|arg| arg == "--match-set")
                && command.args.iter().any(|arg| arg.starts_with("pc_h4_"))
        }));
    }

    #[test]
    fn build_commands_adds_baseline_drop_for_enforced_network() {
        let mut snapshot = sample_snapshot();
        snapshot.enforced_network_subnets.push(
            "172.18.0.0/16"
                .parse()
                .expect("subnet fixture should parse"),
        );
        let mut resolver = MockResolver;
        let commands = build_apply_commands_with_dns(&snapshot, &mut resolver, false, CHAIN_NAME)
            .expect("expected command build to succeed");
        assert!(commands.iter().any(|command| {
            command.program == "iptables"
                && command.args
                    == vec![
                        "-A".to_string(),
                        CHAIN_NAME.to_string(),
                        "-s".to_string(),
                        "172.18.0.0/16".to_string(),
                        "-j".to_string(),
                        "DROP".to_string(),
                    ]
        }));
    }

    #[test]
    fn build_commands_adds_dns_allows_for_gateway_by_default() {
        let mut resolver = MockResolver;
        let commands =
            build_apply_commands_with_dns(&sample_snapshot(), &mut resolver, false, CHAIN_NAME)
                .expect("expected command build to succeed");
        assert!(commands.iter().any(|command| {
            command.program == "iptables"
                && command.args
                    == vec![
                        "-A".to_string(),
                        CHAIN_NAME.to_string(),
                        "-s".to_string(),
                        "172.18.0.2/32".to_string(),
                        "-d".to_string(),
                        "172.18.0.1/32".to_string(),
                        "-p".to_string(),
                        "udp".to_string(),
                        "--dport".to_string(),
                        "53".to_string(),
                        "-j".to_string(),
                        "ACCEPT".to_string(),
                    ]
        }));
        assert!(commands.iter().any(|command| {
            command.program == "iptables"
                && command.args
                    == vec![
                        "-A".to_string(),
                        CHAIN_NAME.to_string(),
                        "-s".to_string(),
                        "172.18.0.2/32".to_string(),
                        "-d".to_string(),
                        "172.18.0.1/32".to_string(),
                        "-p".to_string(),
                        "tcp".to_string(),
                        "--dport".to_string(),
                        "53".to_string(),
                        "-j".to_string(),
                        "ACCEPT".to_string(),
                    ]
        }));
    }
}
