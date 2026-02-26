use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;

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

impl Deref for ContainerId {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub name: String,
    pub attachments: Vec<NetworkAttachment>,
    pub runtime_dns_servers: HashSet<IpAddr>,
    pub policy: ContainerPolicy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeState {
    pub containers: HashMap<ContainerId, Container>,
    pub networks: HashMap<NetworkId, Network>,
    container_lookup: HashMap<String, ContainerId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStateAction {
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
    fn rebuild_container_lookup(&mut self) {
        self.container_lookup.clear();

        let mut ids: Vec<_> = self.containers.keys().cloned().collect();
        ids.sort_unstable();

        for id in ids {
            let Some(container) = self.containers.get(&id) else {
                continue;
            };

            self.container_lookup
                .insert(id.as_str().to_string(), id.clone());
            self.container_lookup
                .insert(container.name.clone(), id.clone());
            for attachment in &container.attachments {
                for alias in &attachment.aliases {
                    self.container_lookup.insert(alias.clone(), id.clone());
                }
            }
        }
    }

    pub fn refresh_indexes(&mut self) {
        self.rebuild_container_lookup();
    }

    #[must_use]
    pub fn resolve_container_id(&self, key: &str) -> Option<&ContainerId> {
        self.container_lookup.get(key)
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
            RuntimeStateAction::CreateContainer { id, container } => {
                self.containers.insert(id, *container);
                self.rebuild_container_lookup();
                true
            }
            RuntimeStateAction::RenameContainer { container_id, name } => {
                if let Some(container) = self.containers.get_mut(&container_id) {
                    container.name = name;
                    self.rebuild_container_lookup();
                    return true;
                }
                false
            }
            RuntimeStateAction::RemoveContainer { container_id } => {
                let removed = self.containers.remove(&container_id);
                if let Some(container) = removed {
                    self.rebuild_container_lookup();
                    return !container.attachments.is_empty();
                }
                false
            }
            RuntimeStateAction::RemoveContainerAttachment {
                container_id,
                network_id,
            } => {
                if let Some(container) = self.containers.get_mut(&container_id) {
                    let previous_len = container.attachments.len();
                    container
                        .attachments
                        .retain(|attachment| attachment.network_id != network_id);
                    let changed = container.attachments.len() != previous_len;
                    if changed {
                        self.rebuild_container_lookup();
                    }
                    return changed;
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
                    Network {
                        id: network_id,
                        name: network_name,
                        subnet,
                        gateway,
                    },
                );
                true
            }
            RuntimeStateAction::RemoveNetwork { network_id } => {
                let changed = self.remove_network(&network_id);
                if changed {
                    self.rebuild_container_lookup();
                }
                changed
            }
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
