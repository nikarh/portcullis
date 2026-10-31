use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::net::IpAddr;
use std::ptr::NonNull;
use std::sync::Mutex;

use super::FirewallError;
use crate::dns::PolicyDnsResolver;
use crate::model::{DnsTarget, EgressTarget, IccMode, NetworkId, Protocol, RuntimeState};
use tracing::{info, trace, warn};

pub const TABLE_FAMILY: &str = "inet";
pub const TABLE_NAME: &str = "portcullis";
pub const CHAIN_NAME: &str = "egress";
const FORWARD_HOOK_PRIORITY: i32 = -1;

pub trait NftRunner {
    fn run_commands(&self, commands: &[String]) -> Result<(), FirewallError>;
}

pub struct NftablesFirewall<R = LibNftablesRunner> {
    runner: R,
}

impl<R> NftablesFirewall<R>
where
    R: NftRunner,
{
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }

    pub fn apply<Dns>(&self, state: &RuntimeState, resolver: &mut Dns) -> Result<(), FirewallError>
    where
        Dns: PolicyDnsResolver,
    {
        let commands = build_refresh_commands_with_dns(state, resolver)?;
        let command_count = commands.len();
        info!(
            command_count,
            container_count = state.containers().len(),
            "applying nftables changes with DNS sets"
        );
        match self.runner.run_commands(&commands) {
            Ok(()) => Ok(()),
            Err(error) if is_missing_table_error(&error) => {
                let init_commands = build_apply_commands_with_dns(state, resolver)?;
                self.runner.run_commands(&init_commands)
            }
            Err(error) => Err(error),
        }
    }

    pub fn cleanup(&self) -> Result<(), FirewallError> {
        let commands = build_cleanup_commands();
        let command_count = commands.len();
        info!(command_count, "cleaning up nftables table");
        match self.runner.run_commands(&commands) {
            Ok(()) => {
                info!("nftables cleanup completed");
                Ok(())
            }
            Err(FirewallError::CommandFailure { stderr, .. })
                if stderr.contains("No such file")
                    || stderr.contains("No such file or directory") =>
            {
                warn!("nftables cleanup ignored: table does not exist");
                Ok(())
            }
            Err(FirewallError::LibCommandFailure { stderr, .. })
                if stderr.contains("No such file")
                    || stderr.contains("No such file or directory") =>
            {
                warn!("nftables cleanup ignored: table does not exist");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl NftablesFirewall<LibNftablesRunner> {
    pub fn with_libnftables() -> Result<Self, FirewallError> {
        let runner = LibNftablesRunner::new()?;
        Ok(Self::new(runner))
    }
}

fn is_missing_table_error(error: &FirewallError) -> bool {
    match error {
        FirewallError::CommandFailure { stderr, .. }
        | FirewallError::LibCommandFailure { stderr, .. } => {
            stderr.contains("No such file") || stderr.contains("No such file or directory")
        }
        _ => false,
    }
}

#[must_use]
#[cfg(test)]
pub fn build_apply_commands(snapshot: &RuntimeState) -> Vec<String> {
    let mut lines = vec![
        format!("add table {TABLE_FAMILY} {TABLE_NAME}"),
        format!(
            "add chain {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} {{ type filter hook forward priority {FORWARD_HOOK_PRIORITY}; policy accept; }}"
        ),
    ];

    let managed_sources = collect_managed_sources(snapshot);
    let container_targets = collect_container_targets(snapshot);

    for container in snapshot.containers().values() {
        let policy = &container.policy;
        for attachment in &container.attachments {
            let gateway = network_gateway(snapshot, &attachment.network_id);
            append_dns_policy_rules(
                &mut lines,
                attachment.ip_address,
                gateway,
                &policy.dns_targets,
                &container.runtime_dns_servers,
            );

            match policy.icc_mode {
                IccMode::Deny => {
                    if let Some(rule) = build_icc_deny_rule(attachment.ip_address, &managed_sources)
                    {
                        lines.push(rule);
                    }
                }
                IccMode::AllowListed => {
                    append_icc_allow_list_rules(
                        &mut lines,
                        attachment.ip_address,
                        &policy.icc_allow,
                        &container_targets,
                    );
                    if let Some(rule) = build_icc_deny_rule(attachment.ip_address, &managed_sources)
                    {
                        lines.push(rule);
                    }
                }
                IccMode::Allow => {}
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

    append_enforced_network_baseline_drop_rules(&mut lines, &snapshot.network_subnets());

    lines
}

#[must_use]
#[cfg(test)]
pub fn build_apply_script(snapshot: &RuntimeState) -> String {
    build_apply_commands(snapshot).join("\n")
}

#[allow(clippy::too_many_lines)]
pub fn build_apply_commands_with_dns(
    snapshot: &RuntimeState,
    resolver: &mut impl PolicyDnsResolver,
) -> Result<Vec<String>, FirewallError> {
    let mut lines = vec![
        format!("add table {TABLE_FAMILY} {TABLE_NAME}"),
        format!(
            "add chain {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} {{ type filter hook forward priority {FORWARD_HOOK_PRIORITY}; policy accept; }}"
        ),
    ];

    let managed_sources = collect_managed_sources(snapshot);
    let container_targets = collect_container_targets(snapshot);

    for container in snapshot.containers().values() {
        let policy = &container.policy;
        for attachment in &container.attachments {
            let gateway = network_gateway(snapshot, &attachment.network_id);
            append_dns_policy_rules(
                &mut lines,
                attachment.ip_address,
                gateway,
                &policy.dns_targets,
                &container.runtime_dns_servers,
            );

            match policy.icc_mode {
                IccMode::Deny => {
                    if let Some(rule) = build_icc_deny_rule(attachment.ip_address, &managed_sources)
                    {
                        lines.push(rule);
                    }
                }
                IccMode::AllowListed => {
                    append_icc_allow_list_rules(
                        &mut lines,
                        attachment.ip_address,
                        &policy.icc_allow,
                        &container_targets,
                    );
                    if let Some(rule) = build_icc_deny_rule(attachment.ip_address, &managed_sources)
                    {
                        lines.push(rule);
                    }
                }
                IccMode::Allow => {}
            }

            for rule in &policy.egress {
                match &rule.target {
                    EgressTarget::IpCidr(cidr) => {
                        for port in &rule.ports {
                            if let Some(allow_rule) =
                                build_allow_rule(attachment.ip_address, cidr, *port)
                            {
                                lines.push(allow_rule);
                            }
                        }
                    }
                    EgressTarget::Hostname(host) => {
                        trace!(%host, "resolving hostname for nftables set population");
                        let resolved =
                            resolver
                                .resolve(host)
                                .map_err(|error| FirewallError::DnsResolve {
                                    host: host.clone(),
                                    message: error.to_string(),
                                })?;
                        trace!(%host, ip_count = resolved.len(), ?resolved, "resolved hostname addresses");
                        let (set4_name, set6_name) = set_names_for_host(host);
                        lines.push(format!(
                            "add set {TABLE_FAMILY} {TABLE_NAME} {set4_name} {{ type ipv4_addr; flags interval; }}"
                        ));
                        lines.push(format!(
                            "add set {TABLE_FAMILY} {TABLE_NAME} {set6_name} {{ type ipv6_addr; flags interval; }}"
                        ));

                        let mut v4 = Vec::new();
                        let mut v6 = Vec::new();
                        for address in resolved.iter().copied() {
                            match address {
                                IpAddr::V4(value) => v4.push(value.to_string()),
                                IpAddr::V6(value) => v6.push(value.to_string()),
                            }
                        }

                        if !v4.is_empty() {
                            lines.push(format!(
                                "add element {TABLE_FAMILY} {TABLE_NAME} {set4_name} {{ {} }}",
                                v4.join(", ")
                            ));
                        }
                        if !v6.is_empty() {
                            lines.push(format!(
                                "add element {TABLE_FAMILY} {TABLE_NAME} {set6_name} {{ {} }}",
                                v6.join(", ")
                            ));
                        }

                        for port in &rule.ports {
                            let protocol = match port.protocol {
                                Protocol::Tcp => "tcp",
                                Protocol::Udp => "udp",
                            };
                            match attachment.ip_address {
                                IpAddr::V4(src) => lines.push(format!(
                                    "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {src} ip daddr @{set4_name} {protocol} dport {} accept",
                                    port.port
                                )),
                                IpAddr::V6(src) => lines.push(format!(
                                    "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {src} ip6 daddr @{set6_name} {protocol} dport {} accept",
                                    port.port
                                )),
                            }
                        }
                    }
                }
            }

            lines.push(build_default_drop_rule(attachment.ip_address));
        }
    }

    append_enforced_network_baseline_drop_rules(&mut lines, &snapshot.network_subnets());

    Ok(lines)
}

#[allow(clippy::too_many_lines)]
pub fn build_refresh_commands_with_dns(
    snapshot: &RuntimeState,
    resolver: &mut impl PolicyDnsResolver,
) -> Result<Vec<String>, FirewallError> {
    let mut commands = build_apply_commands_with_dns(snapshot, resolver)?;
    commands.remove(0);
    commands.insert(0, format!("flush table {TABLE_FAMILY} {TABLE_NAME}"));
    Ok(commands)
}

#[allow(clippy::too_many_lines)]
#[cfg(test)]
pub fn build_apply_script_with_dns(
    snapshot: &RuntimeState,
    resolver: &mut impl PolicyDnsResolver,
) -> Result<String, FirewallError> {
    Ok(build_apply_commands_with_dns(snapshot, resolver)?.join("\n"))
}

#[must_use]
pub fn build_cleanup_commands() -> Vec<String> {
    vec![format!("delete table {TABLE_FAMILY} {TABLE_NAME}")]
}

#[derive(Debug, Default)]
struct ManagedSources {
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

fn collect_managed_sources(snapshot: &RuntimeState) -> ManagedSources {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    for container in snapshot.containers().values() {
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

fn collect_container_targets(snapshot: &RuntimeState) -> HashMap<String, Vec<IpAddr>> {
    let mut by_key: HashMap<String, BTreeSet<IpAddr>> = HashMap::new();

    for (id, container) in snapshot.containers() {
        let mut keys = vec![id.to_string(), container.name.to_string()];
        for attachment in &container.attachments {
            for alias in &attachment.aliases {
                keys.push(alias.clone());
            }
        }

        for key in keys {
            let entry = by_key.entry(key).or_default();
            for attachment in &container.attachments {
                entry.insert(attachment.ip_address);
            }
        }
    }

    by_key
        .into_iter()
        .map(|(key, values)| (key, values.into_iter().collect()))
        .collect()
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

fn append_dns_policy_rules(
    lines: &mut Vec<String>,
    source: IpAddr,
    gateway: Option<IpAddr>,
    dns_targets: &[DnsTarget],
    runtime_dns_servers: &HashSet<IpAddr>,
) {
    let mut allow_any = false;
    let mut destinations = BTreeSet::new();
    for target in dns_targets {
        match target {
            DnsTarget::Docker => {
                if let Some(value) = gateway {
                    destinations.insert(value);
                }
            }
            DnsTarget::Host => {
                // Host DNS target is intentionally ignored: host resolvers are no longer label-driven.
            }
            DnsTarget::Runtime => {
                for value in runtime_dns_servers {
                    destinations.insert(*value);
                }
            }
            DnsTarget::Ip(value) => {
                destinations.insert(*value);
            }
            DnsTarget::Any => {
                allow_any = true;
            }
        }
    }

    match source {
        IpAddr::V4(src) => {
            if allow_any {
                lines.push(format!(
                    "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {src} udp dport 53 accept"
                ));
                lines.push(format!(
                    "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {src} tcp dport 53 accept"
                ));
            } else {
                for destination in &destinations {
                    let IpAddr::V4(dst) = destination else {
                        continue;
                    };
                    lines.push(format!(
                        "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {src} ip daddr {dst} udp dport 53 accept"
                    ));
                    lines.push(format!(
                        "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {src} ip daddr {dst} tcp dport 53 accept"
                    ));
                }
            }
            lines.push(format!(
                "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {src} udp dport 53 drop"
            ));
            lines.push(format!(
                "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {src} tcp dport 53 drop"
            ));
        }
        IpAddr::V6(src) => {
            if allow_any {
                lines.push(format!(
                    "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {src} udp dport 53 accept"
                ));
                lines.push(format!(
                    "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {src} tcp dport 53 accept"
                ));
            } else {
                for destination in &destinations {
                    let IpAddr::V6(dst) = destination else {
                        continue;
                    };
                    lines.push(format!(
                        "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {src} ip6 daddr {dst} udp dport 53 accept"
                    ));
                    lines.push(format!(
                        "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {src} ip6 daddr {dst} tcp dport 53 accept"
                    ));
                }
            }
            lines.push(format!(
                "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {src} udp dport 53 drop"
            ));
            lines.push(format!(
                "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {src} tcp dport 53 drop"
            ));
        }
    }
}

fn append_enforced_network_baseline_drop_rules(lines: &mut Vec<String>, subnets: &[ipnet::IpNet]) {
    for subnet in subnets {
        match subnet {
            ipnet::IpNet::V4(value) => lines.push(format!(
                "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {value} drop"
            )),
            ipnet::IpNet::V6(value) => lines.push(format!(
                "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {value} drop"
            )),
        }
    }
}

fn network_gateway(snapshot: &RuntimeState, network_id: &NetworkId) -> Option<IpAddr> {
    snapshot
        .networks()
        .get(network_id)
        .and_then(|network| network.gateway)
}

fn append_icc_allow_list_rules(
    lines: &mut Vec<String>,
    source: IpAddr,
    icc_allow: &[crate::model::IccAllowRule],
    container_targets: &HashMap<String, Vec<IpAddr>>,
) {
    for rule in icc_allow {
        let Some(destinations) = container_targets.get(rule.target_container.as_str()) else {
            continue;
        };
        for destination in destinations {
            for port in &rule.ports {
                let protocol = match port.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                };
                match (source, destination) {
                    (IpAddr::V4(src), IpAddr::V4(dst)) => lines.push(format!(
                        "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip saddr {src} ip daddr {dst} {protocol} dport {} accept",
                        port.port
                    )),
                    (IpAddr::V6(src), IpAddr::V6(dst)) => lines.push(format!(
                        "add rule {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} ip6 saddr {src} ip6 daddr {dst} {protocol} dport {} accept",
                        port.port
                    )),
                    _ => {}
                }
            }
        }
    }
}

fn set_names_for_host(host: &str) -> (String, String) {
    let hash = fnv1a_64(host.as_bytes());
    (format!("pc_h4_{hash:016x}"), format!("pc_h6_{hash:016x}"))
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod common_tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use crate::dns::{DnsError, DnsProxyCache, UpstreamResolver};
    use crate::model::{
        Container, ContainerId, ContainerPolicy, EgressRule, NetworkAttachment, PortSpec, Protocol,
        RuntimeStateAction,
    };

    use super::*;

    pub(super) struct MockResolver;

    impl UpstreamResolver for MockResolver {
        fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
            if host == "api.example.com" {
                let ip: IpAddr = match "1.1.1.1".parse() {
                    Ok(value) => value,
                    Err(error) => panic!("failed to parse test ip: {error}"),
                };
                return Ok(vec![ip]);
            }

            Err(DnsError::LookupFailed {
                host: host.to_string(),
                message: "host not found".to_string(),
            })
        }
    }

    fn state_with_hostname_rule() -> RuntimeState {
        let source_ip: IpAddr = match "172.18.0.2".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse source ip: {error}"),
        };
        let subnet: ipnet::IpNet = match "172.18.0.0/16".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse subnet: {error}"),
        };

        let mut state = RuntimeState::default();
        state.apply_action(RuntimeStateAction::UpsertNetwork {
            network_id: "net0".into(),
            network_name: "bridge".to_string(),
            subnet,
            gateway: Some("172.18.0.1".parse().expect("gateway fixture should parse")),
        });
        state.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(Container {
                id: "abc".to_string().into(),
                name: "web".to_string().into(),
                attachments: vec![NetworkAttachment {
                    network_id: "net0".into(),
                    ip_address: source_ip,
                    aliases: vec!["web".to_string()],
                }],
                runtime_dns_servers: HashSet::new(),
                policy: ContainerPolicy {
                    icc_mode: crate::model::IccMode::Allow,
                    egress: vec![EgressRule {
                        target: crate::model::EgressTarget::Hostname("api.example.com".to_string()),
                        ports: vec![PortSpec {
                            protocol: Protocol::Tcp,
                            port: 443,
                        }],
                    }],
                    icc_allow: Vec::new(),
                    dns_targets: vec![crate::model::DnsTarget::Docker],
                },
            }),
        });
        state
    }

    fn update_container(state: &mut RuntimeState, id: &str, apply: impl FnOnce(&mut Container)) {
        let id = ContainerId::from(id.to_string());
        let mut container = state
            .containers()
            .get(&id)
            .cloned()
            .expect("container fixture should exist");

        apply(&mut container);
        state.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(container),
        });
    }

    #[test]
    fn build_apply_script_with_dns_adds_sets_and_rules() {
        let mut resolver = DnsProxyCache::new(MockResolver, Duration::from_secs(300), 128);
        let script = build_apply_script_with_dns(&state_with_hostname_rule(), &mut resolver);
        assert!(script.is_ok());
        let value = match script {
            Ok(content) => content,
            Err(error) => panic!("expected script generation to succeed: {error}"),
        };
        assert!(value.contains("add set inet portcullis pc_h4_"));
        assert!(value.contains("add element inet portcullis pc_h4_"));
        assert!(value.contains("ip daddr @pc_h4_"));
    }

    #[test]
    fn build_apply_script_with_dns_reports_resolve_error() {
        let mut resolver = DnsProxyCache::new(MockResolver, Duration::from_secs(300), 128);
        let mut state = state_with_hostname_rule();
        update_container(&mut state, "abc", |container| {
            container.policy.egress[0].target =
                crate::model::EgressTarget::Hostname("bad.example.com".to_string());
        });

        let script = build_apply_script_with_dns(&state, &mut resolver);
        assert!(matches!(script, Err(FirewallError::DnsResolve { .. })));
    }

    #[test]
    fn build_apply_script_with_icc_allowlisted_alias_target() {
        let mut state = state_with_hostname_rule();
        let peer_ip: IpAddr = match "172.18.0.10".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse peer ip: {error}"),
        };
        state.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(Container {
                id: "peer".to_string().into(),
                name: "/peer".to_string().into(),
                attachments: vec![NetworkAttachment {
                    network_id: "net0".into(),
                    ip_address: peer_ip,
                    aliases: vec!["db".to_string()],
                }],
                runtime_dns_servers: HashSet::new(),
                policy: crate::model::ContainerPolicy::default(),
            }),
        });

        update_container(&mut state, "abc", |container| {
            container.policy.icc_mode = crate::model::IccMode::AllowListed;
            container.policy.icc_allow = vec![crate::model::IccAllowRule {
                target_container: "peer".to_string().into(),
                ports: vec![PortSpec {
                    protocol: Protocol::Tcp,
                    port: 5432,
                }],
            }];
        });

        let script = build_apply_script(&state);
        assert!(script.contains("ip daddr 172.18.0.10 tcp dport 5432 accept"));
    }

    #[test]
    fn build_apply_script_uses_pre_docker_forward_priority() {
        let script = build_apply_script(&state_with_hostname_rule());
        assert!(script.contains("hook forward priority -1"));
    }

    #[test]
    fn build_apply_script_adds_baseline_drop_for_enforced_network() {
        let script = build_apply_script(&state_with_hostname_rule());
        assert!(script.contains("ip saddr 172.18.0.0/16 drop"));
    }

    #[test]
    fn build_apply_script_adds_dns_allows_for_network_gateway() {
        let script = build_apply_script(&state_with_hostname_rule());
        assert!(script.contains("ip daddr 172.18.0.1 udp dport 53 accept"));
        assert!(script.contains("ip daddr 172.18.0.1 tcp dport 53 accept"));
    }
}

#[allow(unsafe_code, warnings)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/libnftables_bindings.rs"));
}

trait NftApi {
    type Handle: Copy;

    fn new_context(&self) -> Option<Self::Handle>;
    fn free_context(&self, handle: Self::Handle);
    fn buffer_output(&self, handle: Self::Handle) -> i32;
    fn buffer_error(&self, handle: Self::Handle) -> i32;
    fn run_script(&self, handle: Self::Handle, script: &CStr) -> i32;
    fn error_output(&self, handle: Self::Handle) -> Option<String>;
}

#[derive(Debug, Clone, Copy)]
struct RealNftApi;

#[allow(unsafe_code)]
impl NftApi for RealNftApi {
    type Handle = NonNull<bindings::nft_ctx>;

    fn new_context(&self) -> Option<Self::Handle> {
        // SAFETY: `nft_ctx_new` is an FFI constructor that returns either null or a valid
        // pointer to an allocated context when passed a valid flags value.
        let pointer = unsafe { bindings::nft_ctx_new(bindings::NFT_CTX_DEFAULT) };
        NonNull::new(pointer)
    }

    fn free_context(&self, handle: Self::Handle) {
        // SAFETY: `handle` comes from `nft_ctx_new` and is freed exactly once in `Drop`.
        unsafe { bindings::nft_ctx_free(handle.as_ptr()) };
    }

    fn buffer_output(&self, handle: Self::Handle) -> i32 {
        // SAFETY: `handle` points to a valid live context.
        unsafe { bindings::nft_ctx_buffer_output(handle.as_ptr()) }
    }

    fn buffer_error(&self, handle: Self::Handle) -> i32 {
        // SAFETY: `handle` points to a valid live context.
        unsafe { bindings::nft_ctx_buffer_error(handle.as_ptr()) }
    }

    fn run_script(&self, handle: Self::Handle, script: &CStr) -> i32 {
        // SAFETY: both pointers are valid for the duration of this call.
        unsafe { bindings::nft_run_cmd_from_buffer(handle.as_ptr(), script.as_ptr()) }
    }

    fn error_output(&self, handle: Self::Handle) -> Option<String> {
        // SAFETY: pointer is owned by libnftables for this context and may be null.
        let pointer = unsafe { bindings::nft_ctx_get_error_buffer(handle.as_ptr()) };
        if pointer.is_null() {
            return None;
        }

        // SAFETY: non-null C string pointer returned by libnftables.
        let cstr = unsafe { CStr::from_ptr(pointer) };
        Some(cstr.to_string_lossy().trim().to_string())
    }
}

struct NftContext<A>
where
    A: NftApi,
{
    api: A,
    handle: A::Handle,
}

impl<A> NftContext<A>
where
    A: NftApi,
{
    fn new(api: A) -> Result<Self, FirewallError> {
        let Some(handle) = api.new_context() else {
            return Err(FirewallError::LibContextCreate);
        };

        let output_rc = api.buffer_output(handle);
        if output_rc != 0 {
            api.free_context(handle);
            return Err(FirewallError::LibBufferConfig {
                buffer: "output",
                code: output_rc,
            });
        }

        let error_rc = api.buffer_error(handle);
        if error_rc != 0 {
            api.free_context(handle);
            return Err(FirewallError::LibBufferConfig {
                buffer: "error",
                code: error_rc,
            });
        }

        Ok(Self { api, handle })
    }

    fn run_script(&mut self, script: &str) -> Result<(), FirewallError> {
        let c_script = CString::new(script).map_err(|_| FirewallError::ScriptContainsNul)?;
        let result = self.api.run_script(self.handle, &c_script);
        if result == 0 {
            return Ok(());
        }

        let stderr = self
            .api
            .error_output(self.handle)
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| "unknown libnftables error".to_string());

        Err(FirewallError::LibCommandFailure {
            code: result,
            stderr,
        })
    }
}

impl<A> Drop for NftContext<A>
where
    A: NftApi,
{
    fn drop(&mut self) {
        self.api.free_context(self.handle);
    }
}

pub struct LibNftablesRunner {
    context: Mutex<NftContext<RealNftApi>>,
}

impl LibNftablesRunner {
    pub fn new() -> Result<Self, FirewallError> {
        let context = NftContext::new(RealNftApi)?;
        Ok(Self {
            context: Mutex::new(context),
        })
    }
}

impl NftRunner for LibNftablesRunner {
    fn run_commands(&self, commands: &[String]) -> Result<(), FirewallError> {
        trace!(
            program = "nft",
            commands = ?commands,
            "executing firewall commands"
        );

        let script = format!("{}\n", commands.join("\n"));
        let mut guard = self
            .context
            .lock()
            .map_err(|_| FirewallError::LibContextLock)?;
        guard.run_script(&script)
    }
}

#[cfg(test)]
mod libnftables_tests {
    use std::ffi::CStr;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Debug)]
    struct MockState {
        next_context: Option<usize>,
        output_rc: i32,
        error_rc: i32,
        run_rc: i32,
        error_message: String,
        freed: usize,
        scripts: Vec<String>,
    }

    #[derive(Clone)]
    struct MockApi {
        state: Arc<Mutex<MockState>>,
    }

    impl MockApi {
        fn new(state: MockState) -> Self {
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn state(&self) -> MockState {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.clone()
        }
    }

    impl NftApi for MockApi {
        type Handle = usize;

        fn new_context(&self) -> Option<Self::Handle> {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.next_context
        }

        fn free_context(&self, _handle: Self::Handle) {
            let mut guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.freed += 1;
        }

        fn buffer_output(&self, _handle: Self::Handle) -> i32 {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.output_rc
        }

        fn buffer_error(&self, _handle: Self::Handle) -> i32 {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.error_rc
        }

        fn run_script(&self, _handle: Self::Handle, script: &CStr) -> i32 {
            let mut guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.scripts.push(script.to_string_lossy().to_string());
            guard.run_rc
        }

        fn error_output(&self, _handle: Self::Handle) -> Option<String> {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            Some(guard.error_message.clone())
        }
    }

    fn base_state() -> MockState {
        MockState {
            next_context: Some(1),
            output_rc: 0,
            error_rc: 0,
            run_rc: 0,
            error_message: String::new(),
            freed: 0,
            scripts: Vec::new(),
        }
    }

    #[test]
    fn wrapper_runs_script_successfully() {
        let api = MockApi::new(base_state());
        let mut context = match NftContext::new(api.clone()) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("add table inet portcullis");
        assert!(result.is_ok());

        let state = api.state();
        assert_eq!(state.scripts.len(), 1);
    }

    #[test]
    fn wrapper_reports_script_failure() {
        let mut state = base_state();
        state.run_rc = -1;
        state.error_message = "syntax error".to_string();
        let api = MockApi::new(state);
        let mut context = match NftContext::new(api) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("invalid");
        assert!(matches!(
            result,
            Err(FirewallError::LibCommandFailure { code: -1, .. })
        ));
    }

    #[test]
    fn wrapper_rejects_nul_byte_scripts() {
        let api = MockApi::new(base_state());
        let mut context = match NftContext::new(api) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("bad\0script");
        assert!(matches!(result, Err(FirewallError::ScriptContainsNul)));
    }

    #[test]
    fn wrapper_frees_context_on_drop() {
        let api = MockApi::new(base_state());
        {
            let context = match NftContext::new(api.clone()) {
                Ok(value) => value,
                Err(error) => panic!("expected context creation to succeed: {error}"),
            };
            let _ = context;
        }

        let state = api.state();
        assert_eq!(state.freed, 1);
    }

    #[test]
    fn wrapper_fails_when_context_creation_fails() {
        let mut state = base_state();
        state.next_context = None;
        let api = MockApi::new(state);

        let result = NftContext::new(api);
        assert!(matches!(result, Err(FirewallError::LibContextCreate)));
    }

    #[test]
    fn wrapper_fails_when_output_buffering_fails() {
        let mut state = base_state();
        state.output_rc = -1;
        let api = MockApi::new(state);

        let result = NftContext::new(api);
        assert!(matches!(
            result,
            Err(FirewallError::LibBufferConfig {
                buffer: "output",
                code: -1
            })
        ));
    }
}

#[cfg(test)]
mod firewall_tests {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ipnet::IpNet;

    use super::*;
    use crate::dns::DnsProxyCache;
    use crate::model::{
        Container, ContainerPolicy, EgressRule, EgressTarget, IccMode, NetworkAttachment, PortSpec,
        Protocol, RuntimeStateAction,
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
        fn run_commands(&self, commands: &[String]) -> Result<(), FirewallError> {
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
            guard.push(commands.join("\n"));
            Ok(())
        }
    }

    fn sample_state() -> RuntimeState {
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

        let mut state = RuntimeState::default();
        state.apply_action(RuntimeStateAction::UpsertNetwork {
            network_id: "net0".into(),
            network_name: "bridge".to_string(),
            subnet,
            gateway: Some("172.18.0.1".parse().expect("gateway fixture should parse")),
        });
        state.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(Container {
                id: "abc".to_string().into(),
                name: "web".to_string().into(),
                attachments: vec![NetworkAttachment {
                    network_id: "net0".into(),
                    ip_address: attachment_ip,
                    aliases: vec!["web".to_string()],
                }],
                runtime_dns_servers: HashSet::new(),
                policy: ContainerPolicy {
                    icc_mode: IccMode::Deny,
                    egress: vec![EgressRule {
                        target: EgressTarget::IpCidr(dst_cidr),
                        ports: vec![PortSpec {
                            protocol: Protocol::Tcp,
                            port: 443,
                        }],
                    }],
                    icc_allow: Vec::new(),
                    dns_targets: vec![crate::model::DnsTarget::Docker],
                },
            }),
        });
        state
    }

    #[test]
    fn apply_uses_refresh_commands() {
        let runner = RecordingRunner::new();
        let firewall = NftablesFirewall::new(runner.clone());
        let state = sample_state();
        let mut resolver = DnsProxyCache::new(
            super::common_tests::MockResolver,
            Duration::from_secs(300),
            128,
        );

        let result = firewall.apply(&state, &mut resolver);
        assert!(result.is_ok());

        let scripts = runner.scripts();
        assert_eq!(scripts.len(), 1);
        assert!(scripts[0].contains("flush table inet portcullis"));
        assert!(scripts[0].contains("add chain inet portcullis egress"));
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
