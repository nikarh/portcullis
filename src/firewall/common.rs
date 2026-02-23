use std::net::IpAddr;

use crate::model::{EgressTarget, IccMode, Protocol, RuntimeSnapshot};

pub const TABLE_FAMILY: &str = "inet";
pub const TABLE_NAME: &str = "portcullis";
pub const CHAIN_NAME: &str = "egress";

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
