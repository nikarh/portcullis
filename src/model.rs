use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContainerId(String);

impl ContainerId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<String> for ContainerId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ContainerId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl Borrow<str> for ContainerId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetworkId(String);

impl NetworkId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<String> for NetworkId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for NetworkId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl Borrow<str> for NetworkId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSpec {
    pub protocol: Protocol,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressTarget {
    IpCidr(IpNet),
    Hostname(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRule {
    pub target: EgressTarget,
    pub ports: Vec<PortSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IccAllowRule {
    pub target_container: ContainerId,
    pub ports: Vec<PortSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IccMode {
    Allow,
    Deny,
    AllowListed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsTarget {
    Docker,
    Host,
    Runtime,
    Ip(IpAddr),
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerPolicy {
    pub enabled: bool,
    pub icc_mode: IccMode,
    pub egress: Vec<EgressRule>,
    pub icc_allow: Vec<IccAllowRule>,
    pub dns_targets: Vec<DnsTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAttachment {
    pub network_id: NetworkId,
    pub network_name: String,
    pub ip_address: IpAddr,
    pub gateway: Option<IpAddr>,
    pub subnet: IpNet,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSnapshot {
    pub id: ContainerId,
    pub name: String,
    pub labels: HashMap<String, String>,
    pub attachments: Vec<NetworkAttachment>,
    pub runtime_dns_servers: HashSet<IpAddr>,
    pub host_dns_servers: HashSet<IpAddr>,
    pub policy: Option<ContainerPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub containers: Vec<ContainerSnapshot>,
    pub enforced_network_subnets: Vec<IpNet>,
}
