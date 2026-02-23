use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use crate::dns::HostnameIpResolver;
use crate::firewall::FirewallError;
use crate::model::{EgressTarget, IccMode, Protocol, RuntimeSnapshot};
use tracing::trace;

pub const TABLE_FAMILY: &str = "inet";
pub const TABLE_NAME: &str = "portcullis";
pub const CHAIN_NAME: &str = "egress";
const FORWARD_HOOK_PRIORITY: i32 = -1;

#[must_use]
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
        let Some(policy) = &container.policy else {
            continue;
        };

        if !policy.enabled {
            continue;
        }

        for attachment in &container.attachments {
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

    lines
}

#[must_use]
pub fn build_refresh_commands(snapshot: &RuntimeSnapshot) -> Vec<String> {
    let mut commands = build_apply_commands(snapshot);
    commands.remove(0);
    commands.insert(0, format!("flush table {TABLE_FAMILY} {TABLE_NAME}"));
    commands
}

#[must_use]
pub fn build_apply_script(snapshot: &RuntimeSnapshot) -> String {
    build_apply_commands(snapshot).join("\n")
}

#[must_use]
pub fn build_refresh_script(snapshot: &RuntimeSnapshot) -> String {
    build_refresh_commands(snapshot).join("\n")
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
        let Some(policy) = &container.policy else {
            continue;
        };

        if !policy.enabled {
            continue;
        }

        for attachment in &container.attachments {
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
pub fn build_apply_script_with_dns(
    snapshot: &RuntimeSnapshot,
    resolver: &mut dyn HostnameIpResolver,
) -> Result<String, FirewallError> {
    Ok(build_apply_commands_with_dns(snapshot, resolver)?.join("\n"))
}

#[allow(clippy::too_many_lines)]
pub fn build_refresh_script_with_dns(
    snapshot: &RuntimeSnapshot,
    resolver: &mut dyn HostnameIpResolver,
) -> Result<String, FirewallError> {
    Ok(build_refresh_commands_with_dns(snapshot, resolver)?.join("\n"))
}

#[must_use]
pub fn build_cleanup_commands() -> Vec<String> {
    vec![format!("delete table {TABLE_FAMILY} {TABLE_NAME}")]
}

#[must_use]
pub fn build_cleanup_script() -> String {
    format!("{}\n", build_cleanup_commands().join("\n"))
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

fn collect_container_targets(snapshot: &RuntimeSnapshot) -> HashMap<String, Vec<IpAddr>> {
    let mut by_key: HashMap<String, BTreeSet<IpAddr>> = HashMap::new();

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

fn append_icc_allow_list_rules(
    lines: &mut Vec<String>,
    source: IpAddr,
    icc_allow: &[crate::model::IccAllowRule],
    container_targets: &HashMap<String, Vec<IpAddr>>,
) {
    for rule in icc_allow {
        let Some(destinations) = container_targets.get(&rule.target_container) else {
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
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use crate::dns::{DnsError, HostnameIpResolver};
    use crate::model::{
        ContainerPolicy, ContainerSnapshot, EgressRule, NetworkAttachment, PortSpec, Protocol,
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
        let mut labels = BTreeMap::new();
        labels.insert("portcullis.enable".to_string(), "true".to_string());

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
                id: "abc".to_string(),
                name: "web".to_string(),
                labels,
                attachments: vec![NetworkAttachment {
                    network_id: "net0".to_string(),
                    network_name: "bridge".to_string(),
                    ip_address: source_ip,
                    subnet,
                    aliases: vec!["web".to_string()],
                }],
                policy: Some(ContainerPolicy {
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
                }),
            }],
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
        if let Some(policy) = &mut snapshot.containers[0].policy {
            policy.egress[0].target =
                crate::model::EgressTarget::Hostname("bad.example.com".to_string());
        }

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
        let subnet: ipnet::IpNet = match "172.18.0.0/16".parse() {
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
            policy.icc_mode = crate::model::IccMode::AllowListed;
            policy.icc_allow = vec![crate::model::IccAllowRule {
                target_container: "db".to_string(),
                ports: vec![PortSpec {
                    protocol: Protocol::Tcp,
                    port: 5432,
                }],
            }];
        }

        let script = build_apply_script(&snapshot);
        assert!(script.contains("ip daddr 172.18.0.10 tcp dport 5432 accept"));
    }

    #[test]
    fn build_apply_script_uses_pre_docker_forward_priority() {
        let script = build_apply_script(&snapshot_with_hostname_rule());
        assert!(script.contains("hook forward priority -1"));
    }
}
