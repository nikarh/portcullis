use std::str::FromStr;

use indexmap::IndexMap;
use ipnet::IpNet;
use thiserror::Error;

use crate::model::{
    ContainerPolicy, DnsTarget, EgressRule, EgressTarget, IccAllowRule, IccMode, PortSpec, Protocol,
};

const ICC_MODE_LABEL: &str = "portcullis.icc.mode";
const EGRESS_PREFIX: &str = "portcullis.egress.";
const ICC_ALLOW_PREFIX: &str = "portcullis.icc.allow.";
const DNS_PREFIX: &str = "portcullis.dns.";

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
}

pub fn parse_policy(labels: &IndexMap<String, String>) -> Result<ContainerPolicy, LabelParseError> {
    let icc_mode = match labels.get(ICC_MODE_LABEL) {
        None => IccMode::Allow,
        Some(mode) => parse_icc_mode(mode)?,
    };

    let mut egress = Vec::new();
    let mut icc_allow = Vec::new();
    let mut dns_targets = Vec::with_capacity(1);

    for (key, value) in labels {
        if key.starts_with(EGRESS_PREFIX) {
            egress.push(parse_egress_value(key, value)?);
        } else if key.starts_with(ICC_ALLOW_PREFIX) {
            icc_allow.push(parse_icc_allow_value(key, value)?);
        } else if key.starts_with(DNS_PREFIX) {
            dns_targets.push(parse_dns_target(key, value)?);
        }
    }

    if dns_targets.is_empty() {
        dns_targets.push(DnsTarget::Docker);
    }

    Ok(ContainerPolicy {
        icc_mode,
        egress,
        icc_allow,
        dns_targets,
    })
}

fn parse_dns_target(key: &str, value: &str) -> Result<DnsTarget, LabelParseError> {
    match value {
        "docker" => Ok(DnsTarget::Docker),
        "host" => Ok(DnsTarget::Host),
        "runtime" => Ok(DnsTarget::Runtime),
        "*" => Ok(DnsTarget::Any),
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
            let cidr = IpNet::from_str(value)
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

    use crate::model::{DnsTarget, EgressTarget, IccMode, Protocol};

    fn labels(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parse_policy_parses_rules_without_enable_label() {
        let parsed = parse_policy(&labels(&[("portcullis.egress.0", "ip:1.1.1.1/32,tcp:443")]))
            .expect("parser should not fail");
        assert_eq!(parsed.icc_mode, IccMode::Allow);
        assert_eq!(parsed.egress.len(), 1);
    }

    #[test]
    fn parse_policy_parses_ip_and_host_rules() {
        let parsed = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
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
        let parsed = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.egress.0", "ip:10.0.0.0/8,tcp:443"),
        ]))
        .expect("parser should not fail");

        assert_eq!(parsed.icc_mode, IccMode::Allow);
        assert!(parsed.icc_allow.is_empty());
    }

    #[test]
    fn parse_policy_rejects_invalid_icc_mode() {
        let error = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.icc.mode", "nope"),
        ]))
        .expect_err("invalid icc mode should be rejected");

        assert_eq!(error, LabelParseError::InvalidIccMode("nope".to_string()));
    }

    #[test]
    fn parse_policy_rejects_invalid_cidr() {
        let error = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.egress.0", "ip:not-a-cidr,tcp:443"),
        ]))
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
        let error = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.egress.0", "ip:1.1.1.1/32"),
        ]))
        .expect_err("missing ports should be rejected");

        assert_eq!(
            error,
            LabelParseError::MissingPorts("portcullis.egress.0".to_string())
        );
    }

    #[test]
    fn parse_policy_rejects_invalid_port_definition() {
        let error = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.egress.0", "ip:1.1.1.1/32,sctp:443"),
        ]))
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
        let error = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.egress.0", "ip:1.1.1.1/32,tcp:0"),
        ]))
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
        let parsed = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
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
        let parsed = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.dns.0", "docker"),
            ("portcullis.dns.1", "host"),
            ("portcullis.dns.2", "runtime"),
            ("portcullis.dns.3", "ip:1.1.1.1"),
            ("portcullis.dns.4", "*"),
        ]))
        .expect("parser should not fail");

        assert_eq!(parsed.dns_targets.len(), 5);
        assert_eq!(parsed.dns_targets[0], DnsTarget::Docker);
        assert_eq!(parsed.dns_targets[1], DnsTarget::Host);
        assert_eq!(parsed.dns_targets[2], DnsTarget::Runtime);
        assert_eq!(
            parsed.dns_targets[3],
            DnsTarget::Ip("1.1.1.1".parse().expect("ip should parse"))
        );
        assert_eq!(parsed.dns_targets[4], DnsTarget::Any);
    }

    #[test]
    fn parse_policy_rejects_invalid_dns_target() {
        let error = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.dns.0", "bad"),
        ]))
        .expect_err("invalid dns target should be rejected");

        assert!(matches!(error, LabelParseError::InvalidDnsTarget(_, _)));
    }

    #[test]
    fn parse_policy_rejects_invalid_icc_allow_target() {
        let error = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.icc.allow.0", "host:redis,tcp:6379"),
        ]))
        .expect_err("invalid icc allow target should be rejected");

        assert!(matches!(
            error,
            LabelParseError::InvalidContainerTarget(_, _)
        ));
    }
}
