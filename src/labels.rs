use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use ipnet::IpNet;
use thiserror::Error;

use crate::model::{ContainerPolicy, EgressRule, EgressTarget, IccMode, PortSpec, Protocol};

const ENABLE_LABEL: &str = "portcullis.enable";
const ICC_MODE_LABEL: &str = "portcullis.icc.mode";
const EGRESS_PREFIX: &str = "portcullis.egress.";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LabelParseError {
    #[error("invalid boolean value for {0}: {1}")]
    InvalidBool(String, String),
    #[error("invalid ICC mode value: {0}")]
    InvalidIccMode(String),
    #[error("invalid egress index in key: {0}")]
    InvalidEgressIndex(String),
    #[error("duplicate egress index in key: {0}")]
    DuplicateEgressIndex(String),
    #[error("invalid egress value for {0}: {1}")]
    InvalidEgress(String, String),
    #[error("invalid CIDR in {0}: {1}")]
    InvalidCidr(String, String),
    #[error("invalid hostname in {0}: {1}")]
    InvalidHostname(String, String),
    #[error("invalid port spec in {0}: {1}")]
    InvalidPortSpec(String, String),
    #[error("no ports defined in {0}")]
    MissingPorts(String),
}

pub fn parse_policy(
    labels: &BTreeMap<String, String>,
) -> Result<Option<ContainerPolicy>, LabelParseError> {
    let enabled = match labels.get(ENABLE_LABEL) {
        None => false,
        Some(value) => parse_bool(ENABLE_LABEL, value)?,
    };

    if !enabled {
        return Ok(None);
    }

    let icc_mode = match labels.get(ICC_MODE_LABEL) {
        None => IccMode::Allow,
        Some(mode) => parse_icc_mode(mode)?,
    };

    let mut egress_indices = BTreeSet::new();
    let mut keyed_values = Vec::new();

    for (key, value) in labels {
        if !key.starts_with(EGRESS_PREFIX) {
            continue;
        }

        let index_part = key.trim_start_matches(EGRESS_PREFIX);
        if index_part.is_empty() {
            return Err(LabelParseError::InvalidEgressIndex(key.clone()));
        }

        if !index_part
            .chars()
            .all(|character| character.is_ascii_digit())
        {
            return Err(LabelParseError::InvalidEgressIndex(key.clone()));
        }

        if !egress_indices.insert(index_part.to_string()) {
            return Err(LabelParseError::DuplicateEgressIndex(key.clone()));
        }

        keyed_values.push((index_part.to_string(), key.clone(), value.clone()));
    }

    keyed_values.sort_by(|left, right| left.0.cmp(&right.0));

    let mut egress = Vec::with_capacity(keyed_values.len());
    for (_, key, value) in keyed_values {
        egress.push(parse_egress_value(&key, &value)?);
    }

    Ok(Some(ContainerPolicy {
        enabled,
        icc_mode,
        egress,
    }))
}

fn parse_bool(key: &str, value: &str) -> Result<bool, LabelParseError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(LabelParseError::InvalidBool(
            key.to_string(),
            value.to_string(),
        )),
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
                    (*part).to_string(),
                ));
            }
        };

        let port = u16::from_str(port_value)
            .map_err(|_| LabelParseError::InvalidPortSpec(key.to_string(), (*part).to_string()))?;

        if port == 0 {
            return Err(LabelParseError::InvalidPortSpec(
                key.to_string(),
                (*part).to_string(),
            ));
        }

        ports.push(PortSpec { protocol, port });
    }

    Ok(ports)
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

    use crate::model::{EgressTarget, IccMode, Protocol};

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for (key, value) in pairs {
            map.insert((*key).to_string(), (*value).to_string());
        }
        map
    }

    #[test]
    fn parse_policy_returns_none_when_not_enabled() {
        let parsed = parse_policy(&labels(&[("portcullis.egress.0", "ip:1.1.1.1/32,tcp:443")]))
            .expect("parser should not fail");
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_policy_parses_ip_and_host_rules() {
        let parsed = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.icc.mode", "deny"),
            ("portcullis.egress.0", "ip:1.1.1.1/32,tcp:443,udp:53"),
            ("portcullis.egress.1", "host:api.example.com,tcp:443"),
        ]))
        .expect("parser should not fail")
        .expect("policy should be enabled");

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
    }

    #[test]
    fn parse_policy_defaults_icc_mode_to_allow() {
        let parsed = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.egress.0", "ip:10.0.0.0/8,tcp:443"),
        ]))
        .expect("parser should not fail")
        .expect("policy should be enabled");

        assert_eq!(parsed.icc_mode, IccMode::Allow);
    }

    #[test]
    fn parse_policy_rejects_invalid_enable_bool() {
        let error = parse_policy(&labels(&[("portcullis.enable", "yes")]))
            .expect_err("invalid bool should be rejected");

        assert_eq!(
            error,
            LabelParseError::InvalidBool("portcullis.enable".to_string(), "yes".to_string())
        );
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
    fn parse_policy_rejects_non_numeric_index() {
        let error = parse_policy(&labels(&[
            ("portcullis.enable", "true"),
            ("portcullis.egress.foo", "ip:1.1.1.1/32,tcp:443"),
        ]))
        .expect_err("non numeric index should be rejected");

        assert_eq!(
            error,
            LabelParseError::InvalidEgressIndex("portcullis.egress.foo".to_string())
        );
    }
}
