use std::fmt;
use std::net::Ipv4Addr;

use crate::model::Protocol;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct CommandBuffer<'a> {
    pub(crate) ipset: Vec<IpsetCommand>,
    pub(crate) iptables: Vec<IptablesCommand<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IptablesCommand<'a> {
    FlushChain {
        chain: &'a str,
    },
    DeleteChain {
        chain: &'a str,
    },
    DeleteJump {
        chain: &'a str,
        target: &'a str,
    },
    AcceptIpPort {
        chain: &'a str,
        source: Ipv4Addr,
        destination: Ipv4Destination,
        protocol: Protocol,
        port: u16,
    },
    AcceptMatchSetPort {
        chain: &'a str,
        source: Ipv4Addr,
        host_hash: u64,
        protocol: Protocol,
        port: u16,
    },
    AcceptDns {
        chain: &'a str,
        source: Ipv4Addr,
        destination: Option<Ipv4Addr>,
        protocol: Protocol,
    },
    DropDns {
        chain: &'a str,
        source: Ipv4Addr,
        protocol: Protocol,
    },
    DropIcc {
        chain: &'a str,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    },
    DropSourceIp {
        chain: &'a str,
        source: Ipv4Addr,
    },
    DropSourceSubnet {
        chain: &'a str,
        subnet: ipnet::Ipv4Net,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ipv4Destination {
    Address(Ipv4Addr),
    Cidr(ipnet::Ipv4Net),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpsetCommand {
    Create {
        host_hash: u64,
    },
    Flush {
        host_hash: u64,
    },
    Add {
        host_hash: u64,
        destination: Ipv4Addr,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostSetName(u64);

impl fmt::Display for HostSetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pc_h4_{:016x}", self.0)
    }
}

impl fmt::Display for IptablesCommand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FlushChain { chain } => write!(f, "-F {chain}"),
            Self::DeleteChain { chain } => write!(f, "-X {chain}"),
            Self::DeleteJump { chain, target } => write!(f, "-D {chain} -j {target}"),
            Self::AcceptIpPort {
                chain,
                source,
                destination,
                protocol,
                port,
            } => {
                write!(f, "-A {chain} -s {source}/32 -d ")?;
                match destination {
                    Ipv4Destination::Address(value) => write!(f, "{value}/32")?,
                    Ipv4Destination::Cidr(value) => write!(f, "{value}")?,
                }
                write!(
                    f,
                    " -p {} --dport {port} -j ACCEPT",
                    protocol_name(*protocol)
                )
            }
            Self::AcceptMatchSetPort {
                chain,
                source,
                host_hash,
                protocol,
                port,
            } => write!(
                f,
                "-A {chain} -s {source}/32 -m set --match-set {} dst -p {} --dport {port} -j ACCEPT",
                HostSetName(*host_hash),
                protocol_name(*protocol)
            ),
            Self::AcceptDns {
                chain,
                source,
                destination,
                protocol,
            } => {
                write!(f, "-A {chain} -s {source}/32 ")?;
                if let Some(value) = destination {
                    write!(f, "-d {value}/32 ")?;
                }
                write!(f, "-p {} --dport 53 -j ACCEPT", protocol_name(*protocol))
            }
            Self::DropDns {
                chain,
                source,
                protocol,
            } => write!(
                f,
                "-A {chain} -s {source}/32 -p {} --dport 53 -j DROP",
                protocol_name(*protocol)
            ),
            Self::DropIcc {
                chain,
                source,
                destination,
            } => write!(f, "-A {chain} -s {source}/32 -d {destination}/32 -j DROP"),
            Self::DropSourceIp { chain, source } => {
                write!(f, "-A {chain} -s {source}/32 -j DROP")
            }
            Self::DropSourceSubnet { chain, subnet } => {
                write!(f, "-A {chain} -s {subnet} -j DROP")
            }
        }
    }
}

impl fmt::Display for IpsetCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create { host_hash } => {
                write!(f, "create {} hash:ip -exist", HostSetName(*host_hash))
            }
            Self::Flush { host_hash } => write!(f, "flush {}", HostSetName(*host_hash)),
            Self::Add {
                host_hash,
                destination,
            } => {
                write!(f, "add {} {destination} -exist", HostSetName(*host_hash))
            }
        }
    }
}

fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}
