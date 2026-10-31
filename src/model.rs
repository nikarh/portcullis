use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;
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
    Docker,
    Host,
    Runtime,
    Ip(IpAddr),
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerPolicy {
    pub icc_mode: IccMode,
    pub egress: Vec<EgressRule>,
    pub icc_allow: Vec<IccAllowRule>,
    pub dns_targets: Vec<DnsTarget>,
}

impl Default for ContainerPolicy {
    fn default() -> Self {
        Self {
            icc_mode: IccMode::Allow,
            egress: Vec::new(),
            icc_allow: Vec::new(),
            dns_targets: vec![DnsTarget::Docker],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkAttachment {
    pub network_id: NetworkId,
    pub ip_address: IpAddr,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub id: NetworkId,
    pub name: String,
    pub subnet: IpNet,
    pub gateway: Option<IpAddr>,
}

impl Network {
    #[must_use]
    pub fn new(id: NetworkId, name: String, subnet: IpNet, gateway: Option<IpAddr>) -> Self {
        Self {
            id,
            name,
            subnet,
            gateway,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub id: ContainerId,
    pub name: ContainerName,
    pub attachments: Vec<NetworkAttachment>,
    pub runtime_dns_servers: HashSet<IpAddr>,
    pub policy: ContainerPolicy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeState {
    containers: HashMap<ContainerId, Container>,
    networks: HashMap<NetworkId, Network>,

    containers_by_name: HashMap<ContainerName, ContainerId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStateAction {
    Initialize {
        containers: HashMap<ContainerId, Container>,
        networks: HashMap<NetworkId, Network>,
    },
    CreateContainer {
        id: ContainerId,
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
        network_id: NetworkId,
        network_name: String,
        subnet: IpNet,
        gateway: Option<IpAddr>,
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

    #[must_use]
    pub fn container_id(&self, container_name: &str) -> Option<&ContainerId> {
        self.containers_by_name.get(container_name)
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
                self.containers_by_name.clear();

                for (id, container) in &self.containers {
                    self.containers_by_name
                        .insert(container.name.clone(), id.clone());
                }

                true
            }
            RuntimeStateAction::CreateContainer { id, container } => {
                if let Some(previous) = self.containers.get(&id).cloned() {
                    self.containers_by_name.remove(&previous.name);
                }

                let has_networks = !container.attachments.is_empty();

                self.containers_by_name
                    .insert(container.name.clone(), id.clone());
                self.containers.insert(id.clone(), *container);

                has_networks
            }
            RuntimeStateAction::RenameContainer { container_id, name } => {
                let Some(container) = self.containers.get_mut(&container_id) else {
                    return false;
                };
                if container.name.as_str() == name {
                    return false;
                }
                let previous_name =
                    std::mem::replace(&mut container.name, ContainerName::from(name));

                self.containers_by_name.remove(previous_name.as_str());
                self.containers_by_name
                    .insert(container.name.clone(), container_id);
                true
            }
            RuntimeStateAction::RemoveContainer { container_id } => {
                if let Some(container) = self.containers.remove(&container_id) {
                    self.containers_by_name.remove(container.name.as_str());
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
            RuntimeStateAction::UpsertNetwork {
                network_id,
                network_name,
                subnet,
                gateway,
            } => {
                self.networks.insert(
                    network_id.clone(),
                    Network::new(network_id, network_name, subnet, gateway),
                );
                true
            }
            RuntimeStateAction::RemoveNetwork { network_id } => self.remove_network(&network_id),
        }
    }

    #[must_use]
    pub fn network_subnets(&self) -> Vec<IpNet> {
        self.networks
            .values()
            .map(|network| network.subnet)
            .collect()
    }
}
