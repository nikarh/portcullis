use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use indexmap::IndexMap;
use ipnet::IpNet;
use thiserror::Error;

use crate::events::WarningKind;
use crate::model::{
    ConnectionLimit, ContainerPolicy, DnsTarget, EgressRule, EgressTarget, IccAllowRule, IccMode,
    PortSpec, Protocol,
};

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
    #[error("invalid hostname in {0}: {1}")]
    InvalidHostname(String, String),
    #[error("invalid container target in {0}: {1}")]
    InvalidContainerTarget(String, String),
    #[error("invalid port spec in {0}: {1}")]
    InvalidPortSpec(String, String),
    #[error("no ports defined in {0}")]
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
    let mut domains: Option<Vec<String>> = None;

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

/// Comma-separated domain names, each either exact (`api.example.com`) or for any name
/// below one (`*.example.com`). Normalized to lower case without a trailing dot.
fn parse_domains(key: &str, value: &str) -> Result<Vec<String>, LabelParseError> {
    value
        .split(',')
        .map(str::trim)
        .map(|pattern| {
            let normalized = crate::dns::normalize(pattern);
            let name = normalized.strip_prefix("*.").unwrap_or(&normalized);
            let valid = !name.is_empty()
                && name.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                });
            if valid {
                Ok(normalized)
            } else {
                Err(LabelParseError::InvalidHostname(
                    key.to_string(),
                    pattern.to_string(),
                ))
            }
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
    let parts: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();

    let Some((target_part, port_parts)) = parts.split_first() else {
        return Err(LabelParseError::InvalidEgress(
            key.to_string(),
            value.to_string(),
        ));
    };

    let target = parse_target(key, target_part)?;
    let ports = parse_ports(key, port_parts)?;

    Ok(EgressRule { target, ports })
}

fn parse_target(key: &str, part: &str) -> Result<EgressTarget, LabelParseError> {
    let (kind, value) = split_once_colon(key, part)?;

    match kind {
        "ip" => {
            // A plain address means just that address.
            let cidr = IpNet::from_str(value)
                .or_else(|_| IpAddr::from_str(value).map(IpNet::from))
                .map_err(|_| LabelParseError::InvalidCidr(key.to_string(), value.to_string()))?;
            Ok(EgressTarget::IpCidr(cidr))
        }
        "host" => {
            if value.is_empty() {
                return Err(LabelParseError::InvalidHostname(
                    key.to_string(),
                    value.to_string(),
                ));
            }
            Ok(EgressTarget::Hostname(value.to_string()))
        }
        _ => Err(LabelParseError::InvalidEgress(
            key.to_string(),
            part.to_string(),
        )),
    }
}

fn parse_ports(key: &str, parts: &[&str]) -> Result<Vec<PortSpec>, LabelParseError> {
    if parts.is_empty() {
        return Err(LabelParseError::MissingPorts(key.to_string()));
    }

    let mut ports = Vec::with_capacity(parts.len());

    for part in parts {
        let (proto, port_value) = split_once_colon(key, part)?;
        let protocol = match proto {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => {
                return Err(LabelParseError::InvalidPortSpec(
                    key.to_string(),
                    part.to_string(),
                ));
            }
        };

        let port = u16::from_str(port_value)
            .map_err(|_| LabelParseError::InvalidPortSpec(key.to_string(), (*part).to_string()))?;

        if port == 0 {
            return Err(LabelParseError::InvalidPortSpec(
                key.to_string(),
                part.to_string(),
            ));
        }

        ports.push(PortSpec { protocol, port });
    }

    Ok(ports)
}

fn parse_icc_allow_value(key: &str, value: &str) -> Result<IccAllowRule, LabelParseError> {
    let parts: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    let Some((target_part, port_parts)) = parts.split_first() else {
        return Err(LabelParseError::InvalidIccAllow(
            key.to_string(),
            value.to_string(),
        ));
    };

    let (kind, target) = split_once_colon(key, target_part)?;
    if kind != "container" || target.is_empty() {
        return Err(LabelParseError::InvalidContainerTarget(
            key.to_string(),
            (*target_part).to_string(),
        ));
    }

    let ports = parse_ports(key, port_parts)?;
    Ok(IccAllowRule {
        target_container: target.to_string().into(),
        ports,
    })
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
    use crate::model::{DnsTarget, EgressTarget, IccMode, Protocol};

    #[test]
    fn parses_domains() {
        let (policy, errors) = parse_policy(&labels(&[
            ("portcullis.domains.stripe", "API.stripe.com., *.github.com"),
            ("portcullis.domains.bad", "*.bad*.com"),
        ]));
        assert_eq!(
            policy.domains,
            Some(vec![
                "api.stripe.com".to_string(),
                "*.github.com".to_string()
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

        assert_eq!(parsed.egress[0].ports.len(), 2);
        assert_eq!(parsed.egress[0].ports[0].protocol, Protocol::Tcp);
        assert_eq!(parsed.egress[0].ports[0].port, 443);
        assert_eq!(parsed.egress[0].ports[1].protocol, Protocol::Udp);
        assert_eq!(parsed.egress[0].ports[1].port, 53);

        assert_eq!(
            parsed.egress[1].target,
            EgressTarget::Hostname("api.example.com".to_string())
        );
        assert_eq!(parsed.icc_allow.len(), 1);
        assert_eq!(
            parsed.icc_allow[0].target_container,
            "db".to_string().into()
        );
        assert_eq!(parsed.icc_allow[0].ports[0].port, 5432);
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
            "ip:1.1.1.1/32,sctp:443",
        )]))
        .expect_err("invalid port should be rejected");

        assert_eq!(
            error,
            LabelParseError::InvalidPortSpec(
                "portcullis.egress.0".to_string(),
                "sctp:443".to_string()
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
                "tcp:0".to_string()
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
            parsed.icc_allow[0].target_container,
            "redis".to_string().into()
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
