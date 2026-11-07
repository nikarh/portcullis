use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net};

use crate::pattern::NamePattern;

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

/// An IP protocol rules can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
    /// ICMP, or `ICMPv6` for IPv6 sources.
    Icmp,
    Igmp,
    Gre,
    Esp,
    Ah,
}

impl Protocol {
    pub const ALL: [Self; 8] = [
        Self::Tcp,
        Self::Udp,
        Self::Sctp,
        Self::Icmp,
        Self::Igmp,
        Self::Gre,
        Self::Esp,
        Self::Ah,
    ];

    /// Its name in labels, and to nftables.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
            Self::Icmp => "icmp",
            Self::Igmp => "igmp",
            Self::Gre => "gre",
            Self::Esp => "esp",
            Self::Ah => "ah",
        }
    }

    /// Whether its traffic goes to ports.
    #[must_use]
    pub const fn has_ports(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp | Self::Sctp)
    }

    /// Its IP protocol number.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Sctp => 132,
            Self::Icmp => 1,
            Self::Igmp => 2,
            Self::Gre => 47,
            Self::Esp => 50,
            Self::Ah => 51,
        }
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.as_str() == name)
    }

    #[must_use]
    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|protocol| protocol.number() == number)
    }
}

/// Ports `first` to `last`, both included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

impl PortRange {
    #[must_use]
    pub const fn single(port: u16) -> Self {
        Self {
            first: port,
            last: port,
        }
    }
}

/// `80`, or `8000-8100`.
impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

/// What traffic to a destination a rule allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Service {
    /// Any protocol, any port (`*`).
    Any,
    /// One protocol, on some ports, or on any (`None`, also for protocols without ports).
    Protocol(Protocol, Option<PortRange>),
}

impl Service {
    #[cfg(test)]
    #[must_use]
    pub const fn tcp(port: u16) -> Self {
        Self::Protocol(Protocol::Tcp, Some(PortRange::single(port)))
    }
}

/// As in labels: `*`, `tcp:*`, `tcp:443`, `udp:1024-65535`, `icmp`.
impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Protocol(protocol, _) if !protocol.has_ports() => f.write_str(protocol.as_str()),
            Self::Protocol(protocol, None) => write!(f, "{}:*", protocol.as_str()),
            Self::Protocol(protocol, Some(ports)) => write!(f, "{}:{ports}", protocol.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressTarget {
    IpCidr(IpNet),
    /// Any address (`ip:*`), the Docker host's included.
    AnyAddress,
    /// Any public address (`ip:public`): not a private, shared, loopback, link-local,
    /// multicast or otherwise reserved one, nor one of the Docker host's.
    PublicAddress,
    Hostname(NamePattern),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRule {
    pub target: EgressTarget,
    pub services: Vec<Service>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IccAllowRule {
    pub target: IccTarget,
    pub services: Vec<Service>,
}

/// What an ICC allow rule lets a container reach on its networks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IccTarget {
    /// Containers whose name or alias matches (`container:`).
    Container(NamePattern),
    /// Multicast groups (`multicast:`), which reach every container on the network.
    Multicast(Ipv4Net),
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
    /// The domain names the container may look up (`portcullis.domains.*`), if limited.
    pub domains: Option<Vec<NamePattern>>,
    /// How long an address of its `host:` rules stays allowed after it was last seen
    /// (`portcullis.hostname-hold`); `--hostname-hold` if not set.
    pub hostname_hold: Option<Duration>,
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
            domains: None,
            hostname_hold: None,
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

/// What is known of a container's port on a bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortState<T> {
    Known(T),
    /// It has none: the container is stopping, or not attached yet, and can't send.
    Absent,
    /// It couldn't be found: the container's traffic can only be told by address and MAC.
    Unknown,
}

impl<T> PortState<T> {
    #[must_use]
    pub const fn known(&self) -> Option<&T> {
        match self {
            Self::Known(port) => Some(port),
            Self::Absent | Self::Unknown => None,
        }
    }

    #[must_use]
    pub fn map<U>(&self, f: impl FnOnce(&T) -> U) -> PortState<U> {
        match self {
            Self::Known(port) => PortState::Known(f(port)),
            Self::Absent => PortState::Absent,
            Self::Unknown => PortState::Unknown,
        }
    }
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
    /// Container addresses known to have no bridge port: their container can't send.
    portless: HashSet<IpAddr>,
    /// Containers whose network namespace is gone: they are stopping.
    stopping: HashSet<ContainerId>,
    /// Containers cut off from their networks, see `quarantine`, and whether they were
    /// stopped through Docker since.
    quarantined: HashMap<ContainerId, bool>,
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
    /// A container found behind a bridge port before Docker reported it (see
    /// `discovery`): its attachment to that network, its namespace and its DNS servers
    /// replace those known; the rest of a known container stays as Docker reported it.
    /// (Docker's create event, which comes first, has no DNS servers.) Unless the
    /// container was restarted: a new MAC on a network it was known on means its other
    /// attachments, with their MACs, are of its previous run, and are dropped.
    DiscoverContainer {
        container: Box<Container>,
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

    /// The bridge port the container with `address` sends from.
    #[must_use]
    pub fn port(&self, address: IpAddr) -> PortState<&BridgePort> {
        match self.ports.get(&address) {
            Some(port) => PortState::Known(port),
            None if self.portless.contains(&address) => PortState::Absent,
            None => PortState::Unknown,
        }
    }

    /// Containers whose network namespace is gone: they are stopping, and their addresses
    /// may already be another container's.
    pub fn set_stopping(&mut self, stopping: HashSet<ContainerId>) {
        self.stopping = stopping;
    }

    #[must_use]
    pub fn is_stopping(&self, container: &ContainerId) -> bool {
        self.stopping.contains(container)
    }

    pub fn set_ports(&mut self, ports: HashMap<IpAddr, BridgePort>, portless: HashSet<IpAddr>) {
        self.ports = ports;
        self.portless = portless;
    }

    /// Cut a container off from its networks. Returns whether it wasn't already.
    pub fn quarantine(&mut self, container: &ContainerId) -> bool {
        self.containers.contains_key(container)
            && self.quarantined.insert(container.clone(), false).is_none()
    }

    /// A container was stopped or killed through Docker's API: someone with access to
    /// Docker did it, not the container, whose own exit only makes Docker report it dead.
    pub fn stopped(&mut self, container: &ContainerId) {
        if let Some(stopped) = self.quarantined.get_mut(container) {
            *stopped = true;
        }
    }

    /// A container started: a quarantined one is let back if it was stopped through Docker
    /// first. A container that only exited, and was started again by its restart policy,
    /// stays cut off. Returns whether it was let back.
    pub fn started(&mut self, container: &ContainerId) -> bool {
        let stopped = self.quarantined.get(container) == Some(&true);
        if stopped {
            self.quarantined.remove(container);
        }
        stopped
    }

    #[must_use]
    pub fn is_quarantined(&self, container: &ContainerId) -> bool {
        self.quarantined.contains_key(container)
    }

    /// Keep what `previous` knew of quarantined containers that still exist, as this state
    /// replaces it after Docker's state was read again.
    pub fn keep_quarantine(&mut self, previous: &Self) {
        self.quarantined = previous
            .quarantined
            .iter()
            .filter(|(container, _)| self.containers.contains_key(*container))
            .map(|(container, stopped)| (container.clone(), *stopped))
            .collect();
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
            RuntimeStateAction::DiscoverContainer { container } => {
                let Some(known) = self.containers.get_mut(&container.id) else {
                    let has_networks = !container.attachments.is_empty();
                    self.containers.insert(container.id.clone(), *container);
                    return has_networks;
                };
                let before = known.clone();
                let restarted = container.attachments.iter().any(|found| {
                    known.attachments.iter().any(|attachment| {
                        attachment.network_id == found.network_id
                            && matches!(
                                (attachment.mac_address, found.mac_address),
                                (Some(known), Some(found)) if known != found
                            )
                    })
                });
                if restarted {
                    known.attachments.clear();
                }
                for attachment in container.attachments {
                    known
                        .attachments
                        .retain(|existing| existing.network_id != attachment.network_id);
                    known.attachments.push(attachment);
                }
                known.sandbox = container.sandbox;
                known.runtime_dns_servers = container.runtime_dns_servers;
                *known != before
            }
            RuntimeStateAction::RemoveNetwork { network_id } => self.remove_network(&network_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(id: &str, network: &str, address: &str, sandbox: &str) -> Container {
        Container {
            id: id.to_string().into(),
            name: id.to_string().into(),
            attachments: vec![NetworkAttachment {
                network_id: network.into(),
                ip_address: address.parse().expect("address"),
                mac_address: None,
                aliases: Vec::new(),
            }],
            runtime_dns_servers: HashSet::new(),
            policy: ContainerPolicy::default(),
            sandbox: Some(sandbox.to_string()),
        }
    }

    #[test]
    fn discovered_containers_update_one_attachment() {
        let mut state = RuntimeState::default();
        let discovered = |container| RuntimeStateAction::DiscoverContainer {
            container: Box::new(container),
        };
        assert!(state.apply_action(discovered(container("a", "n0", "172.18.0.2", "/old"))));

        let mut known = container("a", "n0", "172.18.0.2", "/old");
        known
            .attachments
            .extend(container("a", "n1", "172.19.0.2", "/old").attachments);
        assert!(state.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(known),
        }));
        // Restarted with a new namespace, and a new address on n1. Its DNS servers are
        // those of its settings, which Docker's create event doesn't have.
        let mut restarted = container("a", "n1", "172.19.0.9", "/new");
        restarted.runtime_dns_servers = HashSet::from(["198.51.100.2".parse().expect("dns")]);
        assert!(state.apply_action(discovered(restarted.clone())));
        let a = state.containers().get("a").expect("a");
        assert_eq!(a.sandbox.as_deref(), Some("/new"));
        assert_eq!(a.runtime_dns_servers, restarted.runtime_dns_servers);
        let addresses: Vec<String> = a
            .attachments
            .iter()
            .map(|attachment| format!("{} {}", attachment.network_id, attachment.ip_address))
            .collect();
        assert_eq!(addresses, ["n0 172.18.0.2", "n1 172.19.0.9"]);
        // Nothing new.
        assert!(!state.apply_action(discovered(restarted)));
    }

    #[test]
    fn a_restarted_container_drops_the_attachments_of_its_previous_run() {
        let mac = |last: u8| Some(MacAddress::from([2, 0, 0, 0, 0, last]));
        let with_mac = |network: &str, address: &str, last: u8| {
            let mut container = container("a", network, address, "/run");
            if let Some(attachment) = container.attachments.first_mut() {
                attachment.mac_address = mac(last);
            }
            container
        };
        let mut state = RuntimeState::default();
        let mut known = with_mac("n0", "172.18.0.2", 1);
        known
            .attachments
            .extend(with_mac("n1", "172.19.0.2", 2).attachments);
        state.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(known),
        });
        let discovered = |container| RuntimeStateAction::DiscoverContainer {
            container: Box::new(container),
        };
        let attachments = |state: &RuntimeState| -> Vec<(String, Option<MacAddress>)> {
            state
                .containers()
                .get("a")
                .map(|a| {
                    a.attachments
                        .iter()
                        .map(|attachment| {
                            (attachment.network_id.to_string(), attachment.mac_address)
                        })
                        .collect()
                })
                .unwrap_or_default()
        };

        // The same MAC on n1: the same run, n0 stays.
        assert!(!state.apply_action(discovered(with_mac("n1", "172.19.0.2", 2))));
        assert_eq!(attachments(&state).len(), 2);
        // A new MAC on n1: restarted. n0's MAC is of the previous run; n0 is found again
        // from its own port, or reported by Docker.
        assert!(state.apply_action(discovered(with_mac("n1", "172.19.0.2", 9))));
        assert_eq!(attachments(&state), [("n1".to_string(), mac(9))]);
    }

    #[test]
    fn quarantine_lasts_until_the_container_is_stopped_through_docker() {
        let mut state = RuntimeState::default();
        state.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(container("a", "n0", "172.18.0.2", "/a")),
        });
        let a: ContainerId = "a".to_string().into();
        assert!(state.quarantine(&a));
        assert!(!state.quarantine(&a), "already");
        // Exited on its own and started again by its restart policy.
        assert!(!state.started(&a));
        assert!(state.is_quarantined(&a));
        // docker restart: killed or stopped, then started.
        state.stopped(&a);
        assert!(state.started(&a));
        assert!(!state.is_quarantined(&a));
        // Stopping a container that isn't quarantined doesn't keep a later quarantine from
        // lasting.
        state.stopped(&a);
        assert!(state.quarantine(&a));
        assert!(!state.started(&a));
        assert!(state.is_quarantined(&a));
    }

    #[test]
    fn quarantine_survives_reading_dockers_state_again() {
        let mut state = RuntimeState::default();
        for (id, address) in [("a", "172.18.0.2"), ("b", "172.18.0.3")] {
            state.apply_action(RuntimeStateAction::CreateContainer {
                container: Box::new(container(id, "n0", address, "/x")),
            });
        }
        let (a, b): (ContainerId, ContainerId) = ("a".to_string().into(), "b".to_string().into());
        assert!(state.quarantine(&a));
        assert!(state.quarantine(&b));
        state.stopped(&b);
        // Read again after Docker restarted: b is gone.
        let mut read = RuntimeState::default();
        read.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(container("a", "n0", "172.18.0.2", "/y")),
        });
        read.keep_quarantine(&state);
        assert!(read.is_quarantined(&a));
        assert!(!read.is_quarantined(&b));
        assert!(!read.started(&a), "not stopped through Docker");
    }

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
