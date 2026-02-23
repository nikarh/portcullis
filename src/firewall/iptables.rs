use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::process::Command;

use tracing::{info, trace};

use crate::dns::HostnameIpResolver;
use crate::model::{EgressTarget, IccMode, Protocol, RuntimeSnapshot};

use super::FirewallError;

const CHAIN_NAME: &str = "PORTCULLIS_EGRESS";
const DOCKER_USER_CHAIN: &str = "DOCKER-USER";

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandSpec {
    program: &'static str,
    args: Vec<String>,
}

pub trait IptablesRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<(), FirewallError>;
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
}

pub struct IptablesFirewall<R> {
    runner: R,
}

impl<R> IptablesFirewall<R>
where
    R: IptablesRunner,
{
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn apply_with_dns(
        &self,
        snapshot: &RuntimeSnapshot,
        resolver: &mut dyn HostnameIpResolver,
    ) -> Result<(), FirewallError> {
        self.cleanup()?;
        let use_ipset = detect_ipset_available();
        if use_ipset {
            info!("ipset detected; using ipset-backed hostname rules");
        } else {
            info!("ipset not detected; using direct iptables hostname rules");
        }
        let commands = build_apply_commands_with_dns(snapshot, resolver, use_ipset)?;

        for command in &commands {
            self.runner.run(command.program, &command.args)?;
        }

        Ok(())
    }

    pub fn cleanup(&self) -> Result<(), FirewallError> {
        let commands = vec![
            CommandSpec {
                program: "iptables",
                args: vec![
                    "-D".to_string(),
                    DOCKER_USER_CHAIN.to_string(),
                    "-j".to_string(),
                    CHAIN_NAME.to_string(),
                ],
            },
            CommandSpec {
                program: "iptables",
                args: vec!["-F".to_string(), CHAIN_NAME.to_string()],
            },
            CommandSpec {
                program: "iptables",
                args: vec!["-X".to_string(), CHAIN_NAME.to_string()],
            },
        ];

        for command in &commands {
            match self.runner.run(command.program, &command.args) {
                Ok(()) => {}
                Err(FirewallError::CommandFailure { stderr, .. })
                    if is_ignorable_cleanup_stderr(&stderr) => {}
                Err(error) => return Err(error),
            }
        }

        info!("iptables cleanup completed");
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
    pub const fn with_cli() -> Self {
        Self::new(CommandIptablesRunner)
    }
}

fn build_apply_commands_with_dns(
    snapshot: &RuntimeSnapshot,
    resolver: &mut dyn HostnameIpResolver,
    use_ipset: bool,
) -> Result<Vec<CommandSpec>, FirewallError> {
    let mut commands = vec![
        CommandSpec {
            program: "iptables",
            args: vec!["-N".to_string(), CHAIN_NAME.to_string()],
        },
        CommandSpec {
            program: "iptables",
            args: vec![
                "-I".to_string(),
                DOCKER_USER_CHAIN.to_string(),
                "1".to_string(),
                "-j".to_string(),
                CHAIN_NAME.to_string(),
            ],
        },
    ];

    let managed_ipv4 = collect_managed_ipv4(snapshot);
    let container_targets = collect_container_targets(snapshot);

    for container in &snapshot.containers {
        let Some(policy) = &container.policy else {
            continue;
        };

        if !policy.enabled {
            continue;
        }

        for attachment in &container.attachments {
            let IpAddr::V4(source_ipv4) = attachment.ip_address else {
                continue;
            };

            if policy.icc_mode == IccMode::Deny {
                append_icc_drop_commands(&mut commands, source_ipv4, &managed_ipv4);
            } else if policy.icc_mode == IccMode::AllowListed {
                append_icc_allow_list_commands(
                    &mut commands,
                    source_ipv4,
                    &policy.icc_allow,
                    &container_targets,
                );
                append_icc_drop_commands(&mut commands, source_ipv4, &managed_ipv4);
            }

            for rule in &policy.egress {
                match &rule.target {
                    EgressTarget::IpCidr(cidr) => {
                        if cidr.addr().is_ipv6() {
                            continue;
                        }

                        append_ip_target_commands(
                            &mut commands,
                            source_ipv4,
                            &cidr.to_string(),
                            &rule.ports,
                        );
                    }
                    EgressTarget::Hostname(host) => {
                        append_hostname_target_commands(
                            &mut commands,
                            resolver,
                            source_ipv4,
                            host,
                            &rule.ports,
                            use_ipset,
                        )?;
                    }
                }
            }

            append_default_drop_command(&mut commands, source_ipv4);
        }
    }

    Ok(commands)
}

fn append_icc_drop_commands(
    commands: &mut Vec<CommandSpec>,
    source_ipv4: std::net::Ipv4Addr,
    managed_ipv4: &[std::net::Ipv4Addr],
) {
    for destination in managed_ipv4 {
        commands.push(CommandSpec {
            program: "iptables",
            args: vec![
                "-A".to_string(),
                CHAIN_NAME.to_string(),
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
    source_ipv4: std::net::Ipv4Addr,
    destination: &str,
    ports: &[crate::model::PortSpec],
) {
    for port in ports {
        commands.push(CommandSpec {
            program: "iptables",
            args: vec![
                "-A".to_string(),
                CHAIN_NAME.to_string(),
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
                    CHAIN_NAME.to_string(),
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
                        CHAIN_NAME.to_string(),
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

fn append_default_drop_command(commands: &mut Vec<CommandSpec>, source_ipv4: std::net::Ipv4Addr) {
    commands.push(CommandSpec {
        program: "iptables",
        args: vec![
            "-A".to_string(),
            CHAIN_NAME.to_string(),
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
        let Some(policy) = &container.policy else {
            continue;
        };
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

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

fn append_icc_allow_list_commands(
    commands: &mut Vec<CommandSpec>,
    source_ipv4: std::net::Ipv4Addr,
    rules: &[crate::model::IccAllowRule],
    container_targets: &HashMap<String, Vec<std::net::Ipv4Addr>>,
) {
    for rule in rules {
        let Some(destinations) = container_targets.get(&rule.target_container) else {
            continue;
        };
        for destination in destinations {
            for port in &rule.ports {
                commands.push(CommandSpec {
                    program: "iptables",
                    args: vec![
                        "-A".to_string(),
                        CHAIN_NAME.to_string(),
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
        let mut keys = vec![container.id.clone(), container.name.clone()];
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex;

    use ipnet::IpNet;

    use super::*;
    use crate::dns::{DnsError, HostnameIpResolver};
    use crate::model::{
        ContainerPolicy, ContainerSnapshot, EgressRule, NetworkAttachment, PortSpec,
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
        let mut labels = BTreeMap::new();
        labels.insert("portcullis.enable".to_string(), "true".to_string());

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
                id: "abc".to_string(),
                name: "web".to_string(),
                labels,
                attachments: vec![NetworkAttachment {
                    network_id: "net0".to_string(),
                    network_name: "bridge".to_string(),
                    ip_address: source_ip,
                    subnet,
                    aliases: vec!["web".to_string(), "app".to_string()],
                }],
                policy: Some(ContainerPolicy {
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
                }),
            }],
        }
    }

    #[test]
    fn build_commands_includes_iptables_for_hostname_without_ipset() {
        let mut resolver = MockResolver;
        let commands = build_apply_commands_with_dns(&sample_snapshot(), &mut resolver, false);
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
            id: "peer".to_string(),
            name: "/peer".to_string(),
            labels: BTreeMap::new(),
            attachments: vec![NetworkAttachment {
                network_id: "net0".to_string(),
                network_name: "bridge".to_string(),
                ip_address: peer_ip,
                subnet,
                aliases: vec!["db".to_string()],
            }],
            policy: None,
        });
        if let Some(policy) = &mut snapshot.containers[0].policy {
            policy.icc_mode = IccMode::AllowListed;
            policy.icc_allow = vec![crate::model::IccAllowRule {
                target_container: "db".to_string(),
                ports: vec![PortSpec {
                    protocol: Protocol::Tcp,
                    port: 5432,
                }],
            }];
        }

        let mut resolver = MockResolver;
        let commands = build_apply_commands_with_dns(&snapshot, &mut resolver, false)
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
    fn build_commands_hook_into_docker_user_chain() {
        let mut resolver = MockResolver;
        let commands = build_apply_commands_with_dns(&sample_snapshot(), &mut resolver, false)
            .expect("commands");
        assert!(commands.iter().any(|command| {
            command.program == "iptables"
                && command.args
                    == vec![
                        "-I".to_string(),
                        DOCKER_USER_CHAIN.to_string(),
                        "1".to_string(),
                        "-j".to_string(),
                        CHAIN_NAME.to_string(),
                    ]
        }));
    }

    struct MockIptablesRunner {
        results: Mutex<VecDeque<Result<(), FirewallError>>>,
    }

    impl MockIptablesRunner {
        fn new(results: Vec<Result<(), FirewallError>>) -> Self {
            Self {
                results: Mutex::new(VecDeque::from(results)),
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
    }

    #[test]
    fn cleanup_ignores_missing_jump_target_error() {
        let runner = MockIptablesRunner::new(vec![
            Err(FirewallError::CommandFailure {
                code: 2,
                stderr: "iptables v1.8.11 (legacy): Couldn't load target `PORTCULLIS_EGRESS':No such file or directory".to_string(),
            }),
            Ok(()),
            Ok(()),
        ]);
        let firewall = IptablesFirewall::new(runner);
        let result = firewall.cleanup();
        assert!(result.is_ok());
    }

    #[test]
    fn build_commands_includes_ipset_for_hostname_with_ipset() {
        let mut resolver = MockResolver;
        let commands = build_apply_commands_with_dns(&sample_snapshot(), &mut resolver, true)
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
}
