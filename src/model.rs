use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

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
    pub target_container: String,
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
    pub network_id: String,
    pub network_name: String,
    pub ip_address: IpAddr,
    pub gateway: Option<IpAddr>,
    pub subnet: IpNet,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSnapshot {
    pub id: String,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub attachments: Vec<NetworkAttachment>,
    pub runtime_dns_servers: Vec<IpAddr>,
    pub host_dns_servers: Vec<IpAddr>,
    pub policy: Option<ContainerPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub containers: Vec<ContainerSnapshot>,
    pub enforced_network_subnets: Vec<IpNet>,
}
