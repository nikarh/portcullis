use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use crate::dns::HostnameIpResolver;
use crate::firewall::FirewallError;
use crate::model::{DnsTarget, EgressTarget, IccMode, NetworkId, Protocol, RuntimeSnapshot};
use tracing::trace;

pub const TABLE_FAMILY: &str = "inet";
pub const TABLE_NAME: &str = "portcullis";
pub const CHAIN_NAME: &str = "egress";
const FORWARD_HOOK_PRIORITY: i32 = -1;

#[must_use]
#[cfg(test)]
pub fn build_apply_commands(snapshot: &RuntimeSnapshot) -> Vec<String> {
    let mut lines = vec![
        format!("add table {TABLE_FAMILY} {TABLE_NAME}"),
        format!(
            "add chain {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} {{ type filter hook forward priority {FORWARD_HOOK_PRIORITY}; policy accept; }}"
        ),
    ];

    let managed_sources = collect_managed_sources(snapshot);
    let container_targets = collect_container_targets(snapshot);

    for container in &snapshot.containers {
        let policy = &container.policy;

        if !policy.enabled {
            continue;
        }

        for attachment in &container.attachments {
            let gateway = network_gateway(snapshot, &attachment.network_id);
            append_dns_policy_rules(
                &mut lines,
                attachment.ip_address,
                gateway,
                &policy.dns_targets,
                &container.runtime_dns_servers,
                &container.parsed_labels.host_dns_servers,
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

    append_enforced_network_baseline_drop_rules(&mut lines, &snapshot.enforced_network_subnets);

    lines
}

#[must_use]
#[cfg(test)]
pub fn build_refresh_commands(snapshot: &RuntimeSnapshot) -> Vec<String> {
    let mut commands = build_apply_commands(snapshot);
    commands.remove(0);
    commands.insert(0, format!("flush table {TABLE_FAMILY} {TABLE_NAME}"));
    commands
}

#[must_use]
#[cfg(test)]
pub fn build_apply_script(snapshot: &RuntimeSnapshot) -> String {
    build_apply_commands(snapshot).join("\n")
}

#[allow(clippy::too_many_lines)]
pub fn build_apply_commands_with_dns(
    snapshot: &RuntimeSnapshot,
    resolver: &mut dyn HostnameIpResolver,
) -> Result<Vec<String>, FirewallError> {
    let mut lines = vec![
        format!("add table {TABLE_FAMILY} {TABLE_NAME}"),
        format!(
            "add chain {TABLE_FAMILY} {TABLE_NAME} {CHAIN_NAME} {{ type filter hook forward priority {FORWARD_HOOK_PRIORITY}; policy accept; }}"
        ),
    ];

    let managed_sources = collect_managed_sources(snapshot);
    let container_targets = collect_container_targets(snapshot);

    for container in &snapshot.containers {
        let policy = &container.policy;

        if !policy.enabled {
            continue;
        }

        for attachment in &container.attachments {
            let gateway = network_gateway(snapshot, &attachment.network_id);
            append_dns_policy_rules(
                &mut lines,
                attachment.ip_address,
                gateway,
                &policy.dns_targets,
                &container.runtime_dns_servers,
                &container.parsed_labels.host_dns_servers,
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

    append_enforced_network_baseline_drop_rules(&mut lines, &snapshot.enforced_network_subnets);

    Ok(lines)
}

#[allow(clippy::too_many_lines)]
pub fn build_refresh_commands_with_dns(
    snapshot: &RuntimeSnapshot,
    resolver: &mut dyn HostnameIpResolver,
) -> Result<Vec<String>, FirewallError> {
    let mut commands = build_apply_commands_with_dns(snapshot, resolver)?;
    commands.remove(0);
    commands.insert(0, format!("flush table {TABLE_FAMILY} {TABLE_NAME}"));
    Ok(commands)
}

#[allow(clippy::too_many_lines)]
#[cfg(test)]
pub fn build_apply_script_with_dns(
    snapshot: &RuntimeSnapshot,
    resolver: &mut dyn HostnameIpResolver,
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

fn collect_managed_sources(snapshot: &RuntimeSnapshot) -> ManagedSources {
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    for container in &snapshot.containers {
        let policy = &container.policy;

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

fn collect_container_targets(snapshot: &RuntimeSnapshot) -> HashMap<String, Vec<IpAddr>> {
    let mut by_key: HashMap<String, BTreeSet<IpAddr>> = HashMap::new();

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
    host_dns_servers: &HashSet<IpAddr>,
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
                for value in host_dns_servers {
                    destinations.insert(*value);
                }
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

fn network_gateway(snapshot: &RuntimeSnapshot, network_id: &NetworkId) -> Option<IpAddr> {
    snapshot
        .networks
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
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use crate::dns::{DnsError, HostnameIpResolver};
    use crate::model::{
        ContainerPolicy, ContainerSnapshot, EgressRule, NetworkAttachment, NetworkSnapshot,
        PortSpec, Protocol,
    };

    use super::*;

    struct MockResolver;

    impl HostnameIpResolver for MockResolver {
        fn resolve(&mut self, host: &str) -> Result<Arc<[IpAddr]>, DnsError> {
            if host == "api.example.com" {
                let ip: IpAddr = match "1.1.1.1".parse() {
                    Ok(value) => value,
                    Err(error) => panic!("failed to parse test ip: {error}"),
                };
                return Ok(Arc::from(vec![ip].into_boxed_slice()));
            }

            Err(DnsError::LookupFailed {
                host: host.to_string(),
                message: "host not found".to_string(),
            })
        }
    }

    fn snapshot_with_hostname_rule() -> RuntimeSnapshot {
        let source_ip: IpAddr = match "172.18.0.2".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse source ip: {error}"),
        };
        let subnet: ipnet::IpNet = match "172.18.0.0/16".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse subnet: {error}"),
        };

        RuntimeSnapshot {
            containers: vec![ContainerSnapshot {
                id: "abc".into(),
                name: "web".to_string(),
                parsed_labels: crate::model::ParsedContainerLabels::default(),
                attachments: vec![NetworkAttachment {
                    network_id: "net0".into(),
                    ip_address: source_ip,
                    aliases: vec!["web".to_string()],
                }],
                runtime_dns_servers: HashSet::new(),
                policy: ContainerPolicy {
                    enabled: true,
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
    fn build_apply_script_with_dns_adds_sets_and_rules() {
        let mut resolver = MockResolver;
        let script = build_apply_script_with_dns(&snapshot_with_hostname_rule(), &mut resolver);
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
        let mut resolver = MockResolver;
        let mut snapshot = snapshot_with_hostname_rule();
        snapshot.containers[0].policy.egress[0].target =
            crate::model::EgressTarget::Hostname("bad.example.com".to_string());

        let script = build_apply_script_with_dns(&snapshot, &mut resolver);
        assert!(matches!(script, Err(FirewallError::DnsResolve { .. })));
    }

    #[test]
    fn build_apply_script_with_icc_allowlisted_alias_target() {
        let mut snapshot = snapshot_with_hostname_rule();
        let peer_ip: IpAddr = match "172.18.0.10".parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse peer ip: {error}"),
        };
        snapshot.containers.push(ContainerSnapshot {
            id: "peer".into(),
            name: "/peer".to_string(),
            parsed_labels: crate::model::ParsedContainerLabels::default(),
            attachments: vec![NetworkAttachment {
                network_id: "net0".into(),
                ip_address: peer_ip,
                aliases: vec!["db".to_string()],
            }],
            runtime_dns_servers: HashSet::new(),
            policy: crate::model::ContainerPolicy::default(),
        });

        snapshot.containers[0].policy.icc_mode = crate::model::IccMode::AllowListed;
        snapshot.containers[0].policy.icc_allow = vec![crate::model::IccAllowRule {
            target_container: "db".into(),
            ports: vec![PortSpec {
                protocol: Protocol::Tcp,
                port: 5432,
            }],
        }];

        let script = build_apply_script(&snapshot);
        assert!(script.contains("ip daddr 172.18.0.10 tcp dport 5432 accept"));
    }

    #[test]
    fn build_apply_script_uses_pre_docker_forward_priority() {
        let script = build_apply_script(&snapshot_with_hostname_rule());
        assert!(script.contains("hook forward priority -1"));
    }

    #[test]
    fn build_apply_script_adds_baseline_drop_for_enforced_network() {
        let mut snapshot = snapshot_with_hostname_rule();
        snapshot.enforced_network_subnets.push(
            "172.18.0.0/16"
                .parse()
                .expect("subnet fixture should parse"),
        );
        let script = build_apply_script(&snapshot);
        assert!(script.contains("ip saddr 172.18.0.0/16 drop"));
    }

    #[test]
    fn build_apply_script_adds_dns_allows_for_network_gateway() {
        let script = build_apply_script(&snapshot_with_hostname_rule());
        assert!(script.contains("ip daddr 172.18.0.1 udp dport 53 accept"));
        assert!(script.contains("ip daddr 172.18.0.1 tcp dport 53 accept"));
    }
}
