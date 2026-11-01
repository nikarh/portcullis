use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContainerId(Arc<String>);

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
        Self(Arc::new(value))
    }
}

impl Borrow<str> for ContainerId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Deref for ContainerId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContainerName(Arc<String>);

impl ContainerName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<String> for ContainerName {
    fn from(value: String) -> Self {
        Self(Arc::new(value))
    }
}

impl Borrow<str> for ContainerName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Deref for ContainerName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
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

impl Deref for NetworkId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
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
    pub target_container: ContainerName,
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
    /// Whatever Docker's DNS server forwards this container's queries to: its `--dns`
    /// servers, or the host's when it has none.
    Docker,
    /// The host's DNS servers.
    Host,
    Ip(IpAddr),
    Any,
    /// Nothing; only names Docker's DNS answers itself (containers, services) resolve.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerPolicy {
    pub icc_mode: IccMode,
    pub egress: Vec<EgressRule>,
    pub icc_allow: Vec<IccAllowRule>,
    pub dns_targets: Vec<DnsTarget>,
    /// Configuration warnings acknowledged with `portcullis.ack`, not reported.
    pub acknowledged: HashSet<crate::events::WarningKind>,
    /// How many connections the container may have open at a time.
    pub connection_limit: ConnectionLimit,
    /// How many new connections the container may open per second, if limited.
    pub new_connection_rate: Option<u32>,
    /// Whether the container is cut off when it misbehaves (`portcullis.quarantine`).
    pub quarantine: bool,
}

/// `portcullis.limit.connections`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnectionLimit {
    /// `--connection-limit`.
    #[default]
    Default,
    Unlimited,
    At(u32),
}

impl Default for ContainerPolicy {
    fn default() -> Self {
        Self {
            icc_mode: IccMode::Allow,
            egress: Vec::new(),
            icc_allow: Vec::new(),
            dns_targets: vec![DnsTarget::Docker],
            acknowledged: HashSet::new(),
            connection_limit: ConnectionLimit::Default,
            new_connection_rate: None,
            quarantine: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAttachment {
    pub network_id: NetworkId,
    pub ip_address: IpAddr,
    /// The container's MAC address on this network, when Docker reports one.
    pub mac_address: Option<MacAddress>,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub id: NetworkId,
    pub name: String,
    pub subnet: IpNet,
    pub gateway: Option<IpAddr>,
    /// IPv6 is enabled on the network (Portcullis denies it on enforced networks).
    pub ipv6: bool,
    /// Name of the network's bridge interface on the host.
    pub bridge: String,
    /// `portcullis.enable=monitor`: evaluate the policy, but only report what it would deny.
    pub monitor: bool,
}

/// An Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    #[cfg(test)]
    #[must_use]
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(octets: [u8; 6]) -> Self {
        Self(octets)
    }
}

impl FromStr for MacAddress {
    type Err = ();

    /// Parses `aa:bb:cc:dd:ee:ff`.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut octets = [0; 6];
        let mut parts = value.split(':');
        for octet in &mut octets {
            let part = parts.next().ok_or(())?;
            if part.len() != 2 {
                return Err(());
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| ())?;
        }
        if parts.next().is_some() {
            return Err(());
        }
        Ok(Self(octets))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, octet) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(":")?;
            }
            write!(f, "{octet:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub id: ContainerId,
    pub name: ContainerName,
    pub attachments: Vec<NetworkAttachment>,
    pub runtime_dns_servers: HashSet<IpAddr>,
    pub policy: ContainerPolicy,
    /// The container's network namespace, as a file (Docker's `SandboxKey`), while it runs.
    pub sandbox: Option<String>,
}

/// A container's port on a bridge: the host side of its veth pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BridgePort {
    pub name: String,
    pub index: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeState {
    containers: HashMap<ContainerId, Container>,
    networks: HashMap<NetworkId, Network>,
    /// DNS servers set daemon-wide in Docker's `daemon.json`.
    daemon_dns: Vec<IpAddr>,
    /// Bridge port of each container address, where known.
    ports: HashMap<IpAddr, BridgePort>,
    /// Containers cut off from their networks, see `quarantine`.
    quarantined: HashSet<ContainerId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStateAction {
    Initialize {
        containers: HashMap<ContainerId, Container>,
        networks: HashMap<NetworkId, Network>,
    },
    CreateContainer {
        container: Box<Container>,
    },
    RenameContainer {
        container_id: ContainerId,
        name: String,
    },
    RemoveContainer {
        container_id: ContainerId,
    },
    RemoveContainerAttachment {
        container_id: ContainerId,
        network_id: NetworkId,
    },
    UpsertNetwork {
        network: Network,
    },
    RemoveNetwork {
        network_id: NetworkId,
    },
}

impl RuntimeState {
    #[must_use]
    pub fn containers(&self) -> &HashMap<ContainerId, Container> {
        &self.containers
    }

    #[must_use]
    pub fn networks(&self) -> &HashMap<NetworkId, Network> {
        &self.networks
    }

    /// DNS servers Docker's DNS forwards to for containers without their own.
    #[must_use]
    pub fn daemon_dns(&self) -> &[IpAddr] {
        &self.daemon_dns
    }

    pub fn set_daemon_dns(&mut self, servers: Vec<IpAddr>) {
        self.daemon_dns = servers;
    }

    /// The bridge port the container with `address` sends from, where known.
    #[must_use]
    pub fn port(&self, address: IpAddr) -> Option<&BridgePort> {
        self.ports.get(&address)
    }

    pub fn set_ports(&mut self, ports: HashMap<IpAddr, BridgePort>) {
        self.ports = ports;
    }

    /// Cut a container off from its networks. Returns whether it wasn't already.
    pub fn quarantine(&mut self, container: &ContainerId) -> bool {
        self.containers.contains_key(container) && self.quarantined.insert(container.clone())
    }

    /// Let a quarantined container back. Returns whether it was quarantined.
    pub fn release(&mut self, container: &ContainerId) -> bool {
        self.quarantined.remove(container)
    }

    #[must_use]
    pub fn is_quarantined(&self, container: &ContainerId) -> bool {
        self.quarantined.contains(container)
    }

    fn remove_network(&mut self, network_id: &NetworkId) -> bool {
        let mut changed = self.networks.remove(network_id).is_some();
        for container in self.containers.values_mut() {
            let previous_len = container.attachments.len();
            container
                .attachments
                .retain(|attachment| &attachment.network_id != network_id);

            if container.attachments.len() != previous_len {
                changed = true;
            }
        }
        changed
    }

    pub fn apply_action(&mut self, action: RuntimeStateAction) -> bool {
        match action {
            RuntimeStateAction::Initialize {
                containers,
                networks,
            } => {
                self.containers = containers;
                self.networks = networks;
                true
            }
            RuntimeStateAction::CreateContainer { container } => {
                let has_networks = !container.attachments.is_empty();
                self.containers.insert(container.id.clone(), *container);
                has_networks
            }
            RuntimeStateAction::RenameContainer { container_id, name } => {
                let Some(container) = self.containers.get_mut(&container_id) else {
                    return false;
                };
                if container.name.as_str() == name {
                    return false;
                }
                container.name = ContainerName::from(name);
                true
            }
            RuntimeStateAction::RemoveContainer { container_id } => {
                self.quarantined.remove(&container_id);
                if let Some(container) = self.containers.remove(&container_id) {
                    return !container.attachments.is_empty();
                }
                true
            }
            RuntimeStateAction::RemoveContainerAttachment {
                container_id,
                network_id,
            } => {
                if let Some(container) = self.containers.get_mut(&container_id) {
                    let len = container.attachments.len();
                    container.attachments.retain(|a| a.network_id != network_id);
                    return len != container.attachments.len();
                }
                false
            }
            RuntimeStateAction::UpsertNetwork { network } => {
                self.networks.insert(network.id.clone(), network);
                true
            }
            RuntimeStateAction::RemoveNetwork { network_id } => self.remove_network(&network_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_mac_addresses() {
        let mac: MacAddress = "02:42:AC:12:00:0a".parse().expect("mac");
        assert_eq!(mac, MacAddress::new([0x02, 0x42, 0xac, 0x12, 0x00, 0x0a]));
        assert_eq!(mac.to_string(), "02:42:ac:12:00:0a");
        for invalid in [
            "",
            "02:42:ac:12:00",
            "02:42:ac:12:00:0a:00",
            "2:42:ac:12:00:0a",
            "zz:42:ac:12:00:0a",
        ] {
            assert!(invalid.parse::<MacAddress>().is_err(), "{invalid}");
        }
    }
}
