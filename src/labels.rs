use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use indexmap::IndexMap;
use ipnet::{IpNet, Ipv4Net};
use thiserror::Error;

use crate::events::WarningKind;
use crate::model::{
    ConnectionLimit, ContainerPolicy, DnsTarget, EgressRule, EgressTarget, IccAllowRule, IccMode,
    IccTarget, PortRange, Protocol, Service,
};
use crate::pattern::{NameKind, NamePattern};

const ICC_MODE_LABEL: &str = "portcullis.icc.mode";
const EGRESS_PREFIX: &str = "portcullis.egress.";
const ICC_ALLOW_PREFIX: &str = "portcullis.icc.allow.";
const DNS_PREFIX: &str = "portcullis.dns.";
const DOMAINS_PREFIX: &str = "portcullis.domains.";
const CONNECTION_LIMIT_LABEL: &str = "portcullis.limit.connections";
const NEW_CONNECTIONS_LABEL: &str = "portcullis.limit.new-connections";
const QUARANTINE_LABEL: &str = "portcullis.quarantine";
/// Configuration warnings acknowledged for a container or network, comma-separated.
pub const ACK_LABEL: &str = "portcullis.ack";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LabelParseError {
    #[error("invalid ICC mode value: {0}")]
    InvalidIccMode(String),
    #[error("invalid egress value for {0}: {1}")]
    InvalidEgress(String, String),
    #[error("invalid ICC allow value for {0}: {1}")]
    InvalidIccAllow(String, String),
    #[error("invalid CIDR in {0}: {1}")]
    InvalidCidr(String, String),
    #[error("invalid name in {0}: {1}: {2}")]
    InvalidHostname(String, String, &'static str),
    #[error("invalid container target in {0}: {1}")]
    InvalidContainerTarget(String, String),
    #[error("invalid protocol or ports in {0}: {1}: {2}")]
    InvalidPortSpec(String, String, &'static str),
    #[error("no protocols or ports in {0}: add some, like tcp:443, udp:1024-65535, icmp, or *")]
    MissingPorts(String),
    #[error("invalid dns target in {0}: {1}")]
    InvalidDnsTarget(String, String),
    #[error("invalid {0} value {1:?}: {2}")]
    InvalidValue(&'static str, String, &'static str),
    #[error("unknown warning in {ACK_LABEL}: {0} (expected one of {1})")]
    UnknownAcknowledgement(String, String),
}

/// The warnings a `portcullis.ack` label acknowledges. Unknown names are returned as errors.
pub fn parse_acknowledged(
    labels: &IndexMap<String, String>,
) -> (HashSet<WarningKind>, Vec<LabelParseError>) {
    let mut acknowledged = HashSet::new();
    let mut errors = Vec::new();
    for name in labels
        .get(ACK_LABEL)
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        match WarningKind::acknowledgeable(name) {
            Some(kind) => {
                acknowledged.insert(kind);
            }
            None => errors.push(LabelParseError::UnknownAcknowledgement(
                name.to_string(),
                WarningKind::ACKNOWLEDGEABLE
                    .iter()
                    .map(|(ack, _)| *ack)
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
        }
    }
    (acknowledged, errors)
}

/// Parse a container's policy from its labels.
///
/// Invalid labels are returned as errors and otherwise skipped, so one typo doesn't take
/// the rest of the policy down with it. Skipping a label never grants access: egress, ICC
/// allow and DNS labels only add access, and an invalid ICC mode falls back to `deny`.
pub fn parse_policy(labels: &IndexMap<String, String>) -> (ContainerPolicy, Vec<LabelParseError>) {
    let (acknowledged, mut errors) = parse_acknowledged(labels);
    let icc_mode = match labels.get(ICC_MODE_LABEL) {
        None => IccMode::Allow,
        Some(mode) => parse_icc_mode(mode).unwrap_or_else(|error| {
            errors.push(error);
            IccMode::Deny
        }),
    };

    let mut egress = Vec::new();
    let mut icc_allow = Vec::new();
    let mut dns_targets = Vec::with_capacity(1);
    let mut has_dns_labels = false;
    let mut connection_limit = ConnectionLimit::Default;
    let mut new_connection_rate = None;
    let mut quarantine = true;
    let mut domains: Option<Vec<NamePattern>> = None;

    for (key, value) in labels {
        let result = if key.starts_with(EGRESS_PREFIX) {
            parse_egress_value(key, value).map(|rule| egress.push(rule))
        } else if key.starts_with(ICC_ALLOW_PREFIX) {
            parse_icc_allow_value(key, value).map(|rule| icc_allow.push(rule))
        } else if key.starts_with(DNS_PREFIX) {
            has_dns_labels = true;
            parse_dns_target(key, value).map(|target| dns_targets.push(target))
        } else if key.starts_with(DOMAINS_PREFIX) {
            // Any domains label turns name filtering on, even an invalid one: a typo
            // allows fewer names, never all of them.
            let patterns = domains.get_or_insert_with(Vec::new);
            parse_domains(key, value).map(|parsed| patterns.extend(parsed))
        } else if key == CONNECTION_LIMIT_LABEL {
            parse_connection_limit(value).map(|limit| connection_limit = limit)
        } else if key == NEW_CONNECTIONS_LABEL {
            parse_count(NEW_CONNECTIONS_LABEL, value).map(|rate| new_connection_rate = Some(rate))
        } else if key == QUARANTINE_LABEL {
            match value.as_str() {
                "on" => Ok(()),
                "off" => {
                    quarantine = false;
                    Ok(())
                }
                _ => Err(LabelParseError::InvalidValue(
                    QUARANTINE_LABEL,
                    value.clone(),
                    "expected on or off",
                )),
            }
        } else {
            Ok(())
        };
        if let Err(error) = result {
            errors.push(error);
        }
    }

    // Only fall back to the default when no DNS label was written at all: if every DNS
    // label is invalid, the container gets no DNS rather than the default.
    if !has_dns_labels {
        dns_targets.push(DnsTarget::Docker);
    }

    let policy = ContainerPolicy {
        icc_mode,
        egress,
        icc_allow,
        dns_targets,
        acknowledged,
        connection_limit,
        new_connection_rate,
        quarantine,
        domains,
    };
    (policy, errors)
}

fn parse_dns_target(key: &str, value: &str) -> Result<DnsTarget, LabelParseError> {
    match value {
        "docker" => Ok(DnsTarget::Docker),
        "host" => Ok(DnsTarget::Host),
        "*" => Ok(DnsTarget::Any),
        "none" => Ok(DnsTarget::None),
        _ => {
            if let Some(ip) = value.strip_prefix("ip:")
                && let Ok(parsed) = ip.parse()
            {
                return Ok(DnsTarget::Ip(parsed));
            }
            Err(LabelParseError::InvalidDnsTarget(
                key.to_string(),
                value.to_string(),
            ))
        }
    }
}

/// Comma-separated name patterns (see `pattern`).
fn parse_domains(key: &str, value: &str) -> Result<Vec<NamePattern>, LabelParseError> {
    value
        .split(',')
        .map(str::trim)
        .map(|pattern| {
            NamePattern::parse(pattern, NameKind::Host).map_err(|reason| {
                LabelParseError::InvalidHostname(key.to_string(), pattern.to_string(), reason)
            })
        })
        .collect()
}

/// A positive number.
fn parse_count(label: &'static str, value: &str) -> Result<u32, LabelParseError> {
    value
        .parse::<u32>()
        .ok()
        .filter(|count| *count > 0)
        .ok_or_else(|| {
            LabelParseError::InvalidValue(label, value.to_string(), "expected a positive number")
        })
}

fn parse_connection_limit(value: &str) -> Result<ConnectionLimit, LabelParseError> {
    if value == "none" {
        return Ok(ConnectionLimit::Unlimited);
    }
    parse_count(CONNECTION_LIMIT_LABEL, value)
        .map(ConnectionLimit::At)
        .map_err(|_| {
            LabelParseError::InvalidValue(
                CONNECTION_LIMIT_LABEL,
                value.to_string(),
                "expected a positive number or none",
            )
        })
}

fn parse_icc_mode(value: &str) -> Result<IccMode, LabelParseError> {
    match value {
        "allow" => Ok(IccMode::Allow),
        "deny" => Ok(IccMode::Deny),
        "allow-listed" => Ok(IccMode::AllowListed),
        _ => Err(LabelParseError::InvalidIccMode(value.to_string())),
    }
}

fn parse_egress_value(key: &str, value: &str) -> Result<EgressRule, LabelParseError> {
    let parts = split_value(value);
    let Some((target_part, service_parts)) = parts.split_first() else {
        return Err(LabelParseError::InvalidEgress(
            key.to_string(),
            value.to_string(),
        ));
    };

    let target = parse_target(key, target_part)?;
    let services = parse_services(key, service_parts)?;

    Ok(EgressRule { target, services })
}

/// The comma-separated parts of a value, trimmed, without empty ones.
fn split_value(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
}

fn parse_target(key: &str, part: &str) -> Result<EgressTarget, LabelParseError> {
    let (kind, value) = split_once_colon(key, part)?;

    match kind {
        "ip" => match value {
            "*" => Ok(EgressTarget::AnyAddress),
            "public" => Ok(EgressTarget::PublicAddress),
            _ => {
                // A plain address means just that address.
                let cidr = IpNet::from_str(value)
                    .or_else(|_| IpAddr::from_str(value).map(IpNet::from))
                    .map_err(|_| {
                        LabelParseError::InvalidCidr(key.to_string(), value.to_string())
                    })?;
                Ok(EgressTarget::IpCidr(cidr.trunc()))
            }
        },
        "host" => NamePattern::parse(value, NameKind::Host)
            .map(EgressTarget::Hostname)
            .map_err(|reason| {
                LabelParseError::InvalidHostname(key.to_string(), value.to_string(), reason)
            }),
        _ => Err(LabelParseError::InvalidEgress(
            key.to_string(),
            part.to_string(),
        )),
    }
}

/// What a rule allows to its destination, one entry per part:
/// - `*`: anything;
/// - `<protocol>:<ports>` for protocols with ports (`tcp`, `udp`, `sctp`), where ports are
///   `*`, a port, or a range (`1024-65535`); parts that are only ports or ranges after it
///   are more ports of the same protocol (`tcp:80,443,8000-8100`);
/// - `<protocol>` for those without (`icmp`, `igmp`, `gre`, `esp`, `ah`).
fn parse_services(key: &str, parts: &[&str]) -> Result<Vec<Service>, LabelParseError> {
    if parts.is_empty() {
        return Err(LabelParseError::MissingPorts(key.to_string()));
    }
    let invalid = |part: &str, reason| {
        LabelParseError::InvalidPortSpec(key.to_string(), part.to_string(), reason)
    };
    let mut services = Vec::with_capacity(parts.len());
    // The protocol bare ports belong to.
    let mut current = None;
    for part in parts {
        if *part == "*" {
            services.push(Service::Any);
            current = None;
        } else if let Some((name, ports)) = part.split_once(':') {
            let protocol =
                Protocol::from_name(name).ok_or_else(|| invalid(part, "unknown protocol"))?;
            if !protocol.has_ports() {
                return Err(invalid(part, "this protocol has no ports; name it alone"));
            }
            services.push(Service::Protocol(
                protocol,
                parse_port_range(ports).map_err(|reason| invalid(part, reason))?,
            ));
            current = Some(protocol);
        } else if let Some(protocol) = Protocol::from_name(part) {
            if protocol.has_ports() {
                return Err(invalid(
                    part,
                    "say which ports, like tcp:443, or tcp:* for any",
                ));
            }
            services.push(Service::Protocol(protocol, None));
            current = None;
        } else if part.starts_with(|c: char| c.is_ascii_digit()) {
            let protocol =
                current.ok_or_else(|| invalid(part, "ports need a protocol, like tcp:443"))?;
            let ports = parse_port_range(part).map_err(|reason| invalid(part, reason))?;
            if ports.is_none() {
                return Err(invalid(part, "ports need a protocol, like tcp:*"));
            }
            services.push(Service::Protocol(protocol, ports));
        } else {
            return Err(invalid(part, "unknown protocol"));
        }
    }
    services.sort_unstable();
    services.dedup();
    Ok(services)
}

/// `*` (any port, `None`), a port, or a range of ports.
fn parse_port_range(value: &str) -> Result<Option<PortRange>, &'static str> {
    if value == "*" {
        return Ok(None);
    }
    let port = |text: &str| {
        u16::from_str(text)
            .ok()
            .filter(|port| *port > 0)
            .ok_or("ports are 1 to 65535")
    };
    let range = match value.split_once('-') {
        Some((first, last)) => PortRange {
            first: port(first)?,
            last: port(last)?,
        },
        None => PortRange::single(port(value)?),
    };
    if range.first > range.last {
        return Err("a range goes from the lower port to the higher one");
    }
    Ok(Some(range))
}

fn parse_icc_allow_value(key: &str, value: &str) -> Result<IccAllowRule, LabelParseError> {
    let parts = split_value(value);
    let Some((target_part, service_parts)) = parts.split_first() else {
        return Err(LabelParseError::InvalidIccAllow(
            key.to_string(),
            value.to_string(),
        ));
    };

    let (kind, value) = split_once_colon(key, target_part)?;
    let invalid =
        || LabelParseError::InvalidContainerTarget(key.to_string(), (*target_part).to_string());
    let target = match kind {
        "container" => NamePattern::parse(value, NameKind::Container)
            .map(IccTarget::Container)
            .map_err(|_| invalid())?,
        "multicast" => IccTarget::Multicast(parse_multicast(value).ok_or_else(invalid)?),
        _ => return Err(invalid()),
    };

    let services = parse_services(key, service_parts)?;
    Ok(IccAllowRule { target, services })
}

/// A multicast group, a range of groups, or `*` for all of them (`224.0.0.0/4`).
fn parse_multicast(value: &str) -> Option<Ipv4Net> {
    let all = Ipv4Net::new(Ipv4Addr::new(224, 0, 0, 0), 4).ok()?;
    if value == "*" {
        return Some(all);
    }
    let groups = Ipv4Net::from_str(value)
        .or_else(|_| Ipv4Addr::from_str(value).map(Ipv4Net::from))
        .ok()?
        .trunc();
    all.contains(&groups).then_some(groups)
}

fn split_once_colon<'a>(key: &str, part: &'a str) -> Result<(&'a str, &'a str), LabelParseError> {
    let Some((left, right)) = part.split_once(':') else {
        return Err(LabelParseError::InvalidEgress(
            key.to_string(),
            part.to_string(),
        ));
    };

    Ok((left, right))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The policy, or the first label error.
    fn parse_strict(labels: &IndexMap<String, String>) -> Result<ContainerPolicy, LabelParseError> {
        let (policy, errors) = parse_policy(labels);
        errors.into_iter().next().map_or(Ok(policy), Err)
    }

    #[test]
    fn invalid_labels_are_skipped_and_reported() {
        let (policy, errors) = parse_policy(&labels(&[
            ("portcullis.egress.good", "ip:1.1.1.1/32,tcp:443"),
            ("portcullis.egress.bad", "ip:not-an-ip,tcp:443"),
            ("portcullis.icc.allow.bad", "db,tcp:5432"),
            ("portcullis.icc.allow.good", "container:db,tcp:5432"),
        ]));

        assert_eq!(errors.len(), 2);
        assert_eq!(policy.egress.len(), 1);
        assert_eq!(policy.icc_allow.len(), 1);
        assert_eq!(policy.icc_mode, IccMode::Allow);
        assert_eq!(policy.dns_targets, vec![DnsTarget::Docker]);
    }

    #[test]
    fn egress_ip_accepts_plain_addresses() {
        let policy = parse_strict(&labels(&[
            ("portcullis.egress.v4", "ip:1.1.1.1,tcp:443"),
            ("portcullis.egress.v6", "ip:2001:db8::1,tcp:443"),
        ]))
        .expect("plain addresses should parse");
        let targets: Vec<_> = policy.egress.into_iter().map(|rule| rule.target).collect();
        assert_eq!(
            targets,
            vec![
                EgressTarget::IpCidr("1.1.1.1/32".parse().expect("cidr")),
                EgressTarget::IpCidr("2001:db8::1/128".parse().expect("cidr")),
            ]
        );
    }

    #[test]
    fn invalid_icc_mode_falls_back_to_deny() {
        let (policy, errors) = parse_policy(&labels(&[("portcullis.icc.mode", "allowlisted")]));
        assert_eq!(errors.len(), 1);
        assert_eq!(policy.icc_mode, IccMode::Deny);
    }

    #[test]
    fn invalid_dns_labels_do_not_restore_the_default() {
        let (policy, errors) = parse_policy(&labels(&[("portcullis.dns.0", "bogus")]));
        assert_eq!(errors.len(), 1);
        assert_eq!(policy.dns_targets, [] as [crate::model::DnsTarget; 0]);
    }

    use crate::events::WarningKind;
    use crate::model::{DnsTarget, EgressTarget, IccMode, PortRange, Protocol, Service};
    use crate::pattern::NamePattern;

    #[test]
    fn parses_domains() {
        let (policy, errors) = parse_policy(&labels(&[
            ("portcullis.domains.stripe", "API.stripe.com., *.github.com"),
            ("portcullis.domains.bad", "*.bad**.com"),
        ]));
        assert_eq!(
            policy.domains,
            Some(vec![
                NamePattern::host("api.stripe.com"),
                NamePattern::host("*.github.com")
            ])
        );
        assert_eq!(errors.len(), 1);
        // Without domains labels, names aren't filtered.
        assert_eq!(parse_policy(&IndexMap::new()).0.domains, None);
        // An invalid label alone still turns filtering on.
        let (policy, _) = parse_policy(&labels(&[("portcullis.domains.bad", "not a name")]));
        assert_eq!(policy.domains, Some(Vec::new()));
    }

    #[test]
    fn parses_acknowledged_warnings() {
        let (policy, errors) = parse_policy(&labels(&[(
            "portcullis.ack",
            "docker-socket, unenforced-network,bogus",
        )]));
        assert_eq!(
            policy.acknowledged,
            HashSet::from([WarningKind::DockerSocket, WarningKind::UnenforcedNetwork])
        );
        assert_eq!(errors.len(), 1);
    }

    fn labels(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parse_policy_parses_rules_without_enable_label() {
        let parsed = parse_strict(&labels(&[("portcullis.egress.0", "ip:1.1.1.1/32,tcp:443")]))
            .expect("parser should not fail");
        assert_eq!(parsed.icc_mode, IccMode::Allow);
        assert_eq!(parsed.egress.len(), 1);
    }

    #[test]
    fn parse_policy_parses_ip_and_host_rules() {
        let parsed = parse_strict(&labels(&[
            ("portcullis.icc.mode", "deny"),
            ("portcullis.egress.0", "ip:1.1.1.1/32,tcp:443,udp:53"),
            ("portcullis.egress.1", "host:api.example.com,tcp:443"),
            ("portcullis.icc.allow.0", "container:db,tcp:5432"),
        ]))
        .expect("parser should not fail");

        assert_eq!(parsed.icc_mode, IccMode::Deny);
        assert_eq!(parsed.egress.len(), 2);

        assert_eq!(
            parsed.egress[0].services,
            [
                Service::tcp(443),
                Service::Protocol(Protocol::Udp, Some(PortRange::single(53)))
            ]
        );

        assert_eq!(
            parsed.egress[1].target,
            EgressTarget::Hostname(NamePattern::host("api.example.com"))
        );
        assert_eq!(parsed.icc_allow.len(), 1);
        assert_eq!(
            parsed.icc_allow[0].target,
            IccTarget::Container(NamePattern::container("db"))
        );
        assert_eq!(parsed.icc_allow[0].services, [Service::tcp(5432)]);
        assert_eq!(parsed.dns_targets, vec![DnsTarget::Docker]);
    }

    #[test]
    fn parse_policy_defaults_icc_mode_to_allow() {
        let parsed = parse_strict(&labels(&[("portcullis.egress.0", "ip:10.0.0.0/8,tcp:443")]))
            .expect("parser should not fail");

        assert_eq!(parsed.icc_mode, IccMode::Allow);
        assert_eq!(parsed.icc_allow, [] as [crate::model::IccAllowRule; 0]);
    }

    #[test]
    fn parse_policy_rejects_invalid_icc_mode() {
        let error = parse_strict(&labels(&[("portcullis.icc.mode", "nope")]))
            .expect_err("invalid icc mode should be rejected");

        assert_eq!(error, LabelParseError::InvalidIccMode("nope".to_string()));
    }

    #[test]
    fn parse_policy_rejects_invalid_cidr() {
        let error = parse_strict(&labels(&[("portcullis.egress.0", "ip:not-a-cidr,tcp:443")]))
            .expect_err("invalid cidr should be rejected");

        assert_eq!(
            error,
            LabelParseError::InvalidCidr(
                "portcullis.egress.0".to_string(),
                "not-a-cidr".to_string(),
            )
        );
    }

    #[test]
    fn parse_policy_rejects_missing_ports() {
        let error = parse_strict(&labels(&[("portcullis.egress.0", "ip:1.1.1.1/32")]))
            .expect_err("missing ports should be rejected");

        assert_eq!(
            error,
            LabelParseError::MissingPorts("portcullis.egress.0".to_string())
        );
    }

    #[test]
    fn parse_policy_rejects_invalid_port_definition() {
        let error = parse_strict(&labels(&[(
            "portcullis.egress.0",
            "ip:1.1.1.1/32,quic:443",
        )]))
        .expect_err("invalid port should be rejected");

        assert_eq!(
            error,
            LabelParseError::InvalidPortSpec(
                "portcullis.egress.0".to_string(),
                "quic:443".to_string(),
                "unknown protocol"
            )
        );
    }

    #[test]
    fn parse_policy_rejects_zero_port() {
        let error = parse_strict(&labels(&[("portcullis.egress.0", "ip:1.1.1.1/32,tcp:0")]))
            .expect_err("port zero should be rejected");

        assert_eq!(
            error,
            LabelParseError::InvalidPortSpec(
                "portcullis.egress.0".to_string(),
                "tcp:0".to_string(),
                "ports are 1 to 65535"
            )
        );
    }

    #[test]
    fn parse_policy_parses_icc_allow_rule() {
        let parsed = parse_strict(&labels(&[
            ("portcullis.icc.mode", "allow-listed"),
            ("portcullis.icc.allow.0", "container:redis,tcp:6379"),
        ]))
        .expect("parser should not fail");

        assert_eq!(parsed.icc_mode, IccMode::AllowListed);
        assert_eq!(parsed.icc_allow.len(), 1);
        assert_eq!(
            parsed.icc_allow[0].target,
            IccTarget::Container(NamePattern::container("redis"))
        );
    }

    /// The services of one egress label, or its error.
    fn services(value: &str) -> Result<Vec<Service>, LabelParseError> {
        parse_strict(&labels(&[(
            "portcullis.egress.x",
            &format!("ip:1.1.1.1,{value}"),
        )]))
        .map(|policy| policy.egress[0].services.clone())
    }

    fn ports(protocol: Protocol, first: u16, last: u16) -> Service {
        Service::Protocol(protocol, Some(PortRange { first, last }))
    }

    #[test]
    fn parses_ports_ranges_and_lists() {
        assert_eq!(
            services("tcp:80,443,8000-8100,udp:1024-65535,3478").expect("services"),
            [
                ports(Protocol::Tcp, 80, 80),
                ports(Protocol::Tcp, 443, 443),
                ports(Protocol::Tcp, 8000, 8100),
                ports(Protocol::Udp, 1024, 65535),
                ports(Protocol::Udp, 3478, 3478),
            ]
        );
        assert_eq!(
            services("tcp:*,sctp:1-2").expect("services"),
            [
                Service::Protocol(Protocol::Tcp, None),
                ports(Protocol::Sctp, 1, 2)
            ]
        );
        // Duplicates are listed once.
        assert_eq!(
            services("tcp:443,tcp:443,443").expect("services"),
            [Service::tcp(443)]
        );
    }

    #[test]
    fn parses_protocols_without_ports_and_anything() {
        assert_eq!(
            services("icmp,igmp,gre,esp,ah").expect("services"),
            [
                Service::Protocol(Protocol::Icmp, None),
                Service::Protocol(Protocol::Igmp, None),
                Service::Protocol(Protocol::Gre, None),
                Service::Protocol(Protocol::Esp, None),
                Service::Protocol(Protocol::Ah, None),
            ]
        );
        assert_eq!(services("*").expect("services"), [Service::Any]);
    }

    #[test]
    fn rejects_invalid_ports_and_protocols() {
        for invalid in [
            "tcp",
            "tcp:",
            "tcp:0",
            "tcp:65536",
            "tcp:90-80",
            "tcp:1-",
            "tcp:-1",
            "tcp:a",
            "443",
            "tcp:80,*-1",
            "icmp:8",
            "icmp,80",
            "*,80",
            "quic:443",
            "TCP:443",
            "tcp:1,2,x",
            "tcp:80,0",
        ] {
            assert!(
                matches!(services(invalid), Err(LabelParseError::InvalidPortSpec(..))),
                "{invalid}: {:?}",
                services(invalid)
            );
        }
    }

    #[test]
    fn parses_destinations() {
        let target = |value: &str| {
            parse_strict(&labels(&[(
                "portcullis.egress.x",
                &format!("{value},tcp:443"),
            )]))
            .map(|policy| policy.egress[0].target.clone())
        };
        assert_eq!(target("ip:*"), Ok(EgressTarget::AnyAddress));
        assert_eq!(target("ip:public"), Ok(EgressTarget::PublicAddress));
        assert_eq!(
            target("ip:10.1.2.3/8"),
            Ok(EgressTarget::IpCidr("10.0.0.0/8".parse().expect("cidr")))
        );
        assert_eq!(
            target("host:*.Archive.org."),
            Ok(EgressTarget::Hostname(NamePattern::host("*.archive.org")))
        );
        assert_eq!(
            target("host:**.redd.it"),
            Ok(EgressTarget::Hostname(NamePattern::host("**.redd.it")))
        );
        for invalid in [
            "host:*",
            "host:**",
            "host:a.**.b",
            "host:",
            "ip:private",
            "any",
            "*",
        ] {
            assert!(target(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn parses_multicast_groups() {
        let target = |value: &str| {
            parse_strict(&labels(&[(
                "portcullis.icc.allow.x",
                &format!("{value},udp:5353"),
            )]))
            .map(|policy| policy.icc_allow[0].target.clone())
        };
        let group = |value: &str| Ok(IccTarget::Multicast(value.parse().expect("group")));
        assert_eq!(target("multicast:224.0.0.251"), group("224.0.0.251/32"));
        assert_eq!(target("multicast:239.0.0.0/8"), group("239.0.0.0/8"));
        assert_eq!(target("multicast:*"), group("224.0.0.0/4"));
        for invalid in [
            "multicast:",
            "multicast:10.0.0.1",
            "multicast:0.0.0.0/0",
            "multicast:224.0.0.0/3",
            "multicast:255.255.255.255",
            "multicast:ff02::fb",
            "multicast:mdns",
        ] {
            assert!(target(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn parses_container_patterns() {
        let parsed = parse_strict(&labels(&[
            (
                "portcullis.icc.allow.workers",
                "container:app-worker-*,tcp:8080",
            ),
            ("portcullis.icc.allow.any", "container:*,icmp"),
        ]))
        .expect("parser should not fail");
        assert_eq!(
            parsed.icc_allow[0].target,
            IccTarget::Container(NamePattern::container("app-worker-*"))
        );
        assert_eq!(
            parsed.icc_allow[1].target,
            IccTarget::Container(NamePattern::container("*"))
        );
        assert!(
            parse_strict(&labels(&[(
                "portcullis.icc.allow.x",
                "container:a b,tcp:1"
            )]))
            .is_err()
        );
    }

    #[test]
    fn parse_policy_parses_dns_targets() {
        let parsed = parse_strict(&labels(&[
            ("portcullis.dns.0", "docker"),
            ("portcullis.dns.1", "host"),
            ("portcullis.dns.2", "none"),
            ("portcullis.dns.3", "ip:1.1.1.1"),
            ("portcullis.dns.4", "*"),
        ]))
        .expect("parser should not fail");

        assert_eq!(parsed.dns_targets.len(), 5);
        assert_eq!(parsed.dns_targets[0], DnsTarget::Docker);
        assert_eq!(parsed.dns_targets[1], DnsTarget::Host);
        assert_eq!(parsed.dns_targets[2], DnsTarget::None);
        assert_eq!(
            parsed.dns_targets[3],
            DnsTarget::Ip("1.1.1.1".parse().expect("ip should parse"))
        );
        assert_eq!(parsed.dns_targets[4], DnsTarget::Any);
    }

    #[test]
    fn parse_policy_rejects_invalid_dns_target() {
        let error = parse_strict(&labels(&[("portcullis.dns.0", "bad")]))
            .expect_err("invalid dns target should be rejected");

        assert!(matches!(error, LabelParseError::InvalidDnsTarget(_, _)));
    }

    #[test]
    fn parse_policy_rejects_invalid_icc_allow_target() {
        let error = parse_strict(&labels(&[(
            "portcullis.icc.allow.0",
            "host:redis,tcp:6379",
        )]))
        .expect_err("invalid icc allow target should be rejected");

        assert!(matches!(
            error,
            LabelParseError::InvalidContainerTarget(_, _)
        ));
    }
}
