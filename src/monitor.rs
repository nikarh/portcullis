use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use ipnet::IpNet;
use thiserror::Error;
use tracing::{debug, info, trace, warn};

use crate::docker::raw::{
    DockerContainerInspect, DockerContainerSummary, DockerContainerSummaryEndpoint, DockerEndpoint,
    DockerHostConfig, DockerNetworkInspect,
};
use crate::docker::{
    DockerApi, DockerError, DockerEvent, DockerEventAction, DockerEventKind, DockerFirewallBackend,
};
use crate::labels::{LabelParseError, parse_policy};
use crate::model::{Container, ContainerId, NetworkAttachment, NetworkId, RuntimeSnapshot};

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error(transparent)]
    Docker(#[from] DockerError),
    #[error("missing network id in container {container_id} attachment {network_name}")]
    MissingNetworkId {
        container_id: String,
        network_name: String,
    },
    #[error("missing subnet for network id: {0}")]
    MissingNetworkSubnet(String),
    #[error("missing gateway for network id: {0}")]
    MissingNetworkGateway(String),
    #[error("invalid subnet in network id {network_id}: {subnet}")]
    InvalidNetworkSubnet { network_id: String, subnet: String },
    #[error("invalid gateway in network id {network_id}: {gateway}")]
    InvalidNetworkGateway { network_id: String, gateway: String },
    #[error("invalid network label {label} on network {network_id}: {value}")]
    InvalidNetworkLabel {
        network_id: String,
        label: String,
        value: String,
    },
    #[error(transparent)]
    LabelParse(#[from] LabelParseError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Network {
    pub name: String,
    pub subnet: IpNet,
    pub gateway: IpAddr,
}

impl Network {
    fn try_new(network: &DockerNetworkInspect) -> Result<Option<Self>, MonitorError> {
        // Ignore non-bridge networks
        if !network.driver.is_bridge() {
            debug!(
                network_id = %network.id,
                network_name = %network.name,
                driver = ?network.driver,
                "ignoring unsupported docker network driver"
            );
            return Ok(None);
        }

        // Ignore non-portcullis networks
        if !is_portcullis_network_enforced(&network)? {
            debug!(
                network_id = %network.id,
                network_name = %network.name,
                "ignoring non-portcullis network"
            );
            return Ok(None);
        }

        let (subnet, gateway) = network_primary_config(&network)?;

        Ok(Some(Self {
            name: network.name.clone(),
            subnet,
            gateway,
        }))
    }
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeState {
    containers: HashMap<ContainerId, Container>,
    networks: HashMap<NetworkId, Network>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStateAction {
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
        network_id: NetworkId,
        network_name: String,
        subnet: IpNet,
        gateway: IpAddr,
    },
    RemoveNetwork {
        network_id: NetworkId,
    },
}

impl RuntimeState {
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
            RuntimeStateAction::CreateContainer {
                container: snapshot,
            } => {
                let container_id = snapshot.id.clone();
                self.containers.insert(container_id, *snapshot);

                true
            }
            RuntimeStateAction::RenameContainer { container_id, name } => {
                if let Some(container) = self.containers.get_mut(&container_id) {
                    container.name = name;
                    return true;
                }
                false
            }
            RuntimeStateAction::RemoveContainer { container_id } => self
                .containers
                .remove(&container_id)
                .is_some_and(|c| !c.attachments.is_empty()),
            RuntimeStateAction::RemoveContainerAttachment {
                container_id,
                network_id,
            } => {
                if let Some(container) = self.containers.get_mut(&container_id) {
                    let previous_len = container.attachments.len();
                    container
                        .attachments
                        .retain(|attachment| attachment.network_id != network_id);
                    return container.attachments.len() != previous_len;
                }
                false
            }
            RuntimeStateAction::UpsertNetwork {
                network_id,
                network_name,
                subnet,
                gateway,
            } => {
                let next = Network {
                    name: network_name,
                    subnet,
                    gateway,
                };
                self.networks.insert(network_id, next);

                true
            }
            RuntimeStateAction::RemoveNetwork { network_id } => self.remove_network(&network_id),
        }
    }
}

pub struct DockerMonitor<A> {
    api: A,
}

impl<A> DockerMonitor<A>
where
    A: DockerApi,
{
    pub const fn new(api: A) -> Self {
        Self { api }
    }

    pub fn collect_state(&mut self) -> Result<RuntimeState, MonitorError> {
        debug!("collecting docker runtime state");

        let networks = self.api.list_networks()?;
        let containers = self.api.list_containers()?;

        let mut state = RuntimeState::default();
        for network in networks {
            if let Some(data) = Network::try_new(&network)? {
                state.networks.insert(network.id.into(), data);
            }
        }
        for summary in containers {
            let snapshot = Self::build_container_snapshot_from_summary(&state, &summary)?;
            state.containers.insert(snapshot.id.clone(), snapshot);
        }
        Ok(state)
    }

    pub fn resolve_event_action(
        &mut self,
        state: &RuntimeState,
        event: DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        match event.kind {
            DockerEventKind::Container => match event.action {
                DockerEventAction::Destroy => Ok(Some(RuntimeStateAction::RemoveContainer {
                    container_id: event.id.into(),
                })),
                DockerEventAction::Create => Self::create_container_action(event),
                DockerEventAction::Rename => {
                    let Some(name) = event.name else {
                        return Ok(None);
                    };

                    Ok(Some(RuntimeStateAction::RenameContainer {
                        container_id: event.id.into(),
                        name,
                    }))
                }
                _ => Ok(None),
            },
            DockerEventKind::Network => match event.action {
                DockerEventAction::Destroy => Ok(Some(RuntimeStateAction::RemoveNetwork {
                    network_id: event.id.into(),
                })),
                DockerEventAction::Create | DockerEventAction::Update => {
                    self.inspect_network_action(&event.id)
                }
                DockerEventAction::Connect => self.resolve_network_connect_action(state, &event),
                DockerEventAction::Disconnect => {
                    Ok(Self::resolve_network_disconnect_action(state, &event))
                }
                _ => Ok(None),
            },
        }
    }

    fn build_container_snapshot_from_inspect(
        &mut self,
        state: &RuntimeState,
        inspect: DockerContainerInspect,
    ) -> Result<Container, MonitorError> {
        let policy = parse_policy(&inspect.config.labels)?;
        let runtime_dns_servers = runtime_dns_servers(inspect.host_config.as_ref());

        let mut attachments = Vec::new();

        for (network_name, endpoint) in container_inspect_network_endpoints(&inspect) {
            let Some(address) = endpoint.ip_address else {
                continue;
            };
            let network_id: NetworkId = endpoint
                .network_id
                .ok_or_else(|| MonitorError::MissingNetworkId {
                    container_id: inspect.id.clone(),
                    network_name: network_name.to_string(),
                })?
                .into();
            let network_data = if let Some(value) = state.networks.get(&network_id) {
                value.clone()
            } else {
                let value = match self.api.inspect_network(network_id.as_str()) {
                    Ok(network) => Network::try_new(&network)?,
                    Err(error) if is_not_found(&error) => None,
                    Err(error) => return Err(error.into()),
                };
                network_cache.insert(network_id.clone(), value.clone());
                value
            };
            let Some(_network_data) = network_data else {
                warn!(
                    network_id = %network_id,
                    container_id = %inspect.id,
                    "skipping attachment on network without subnet"
                );
                continue;
            };
            attachments.push(NetworkAttachment {
                network_id,
                ip_address: address,
                aliases: endpoint.aliases.unwrap_or_default(),
            });
        }

        Ok(Container {
            id: inspect.id.into(),
            name: inspect.name.trim_start_matches('/').to_string(),
            attachments,
            runtime_dns_servers,
            policy,
        })
    }

    fn inspect_container_action(
        &mut self,
        state: &RuntimeState,
        container_id: &str,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        debug!(%container_id, "resolving container runtime state action");

        match self.api.inspect_container(container_id) {
            Ok(inspect) => {
                let snapshot = self.build_container_snapshot_from_inspect(state, inspect)?;
                Ok(Some(RuntimeStateAction::CreateContainer {
                    container: Box::new(snapshot),
                }))
            }
            Err(error) if is_not_found(&error) => Ok(Some(RuntimeStateAction::RemoveContainer {
                container_id: container_id.into(),
            })),
            Err(error) => Err(error.into()),
        }
    }

    fn create_container_action(
        event: DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        let policy = parse_policy(&event.attributes)?;

        let Some(name) = event.name else {
            return Ok(None);
        };

        Ok(Some(RuntimeStateAction::CreateContainer {
            container: Box::new(Container {
                id: event.id.into(),
                name: name.trim_start_matches('/').to_string(),
                attachments: Vec::new(),
                runtime_dns_servers: HashSet::new(),
                policy,
            }),
        }))
    }

    fn resolve_network_connect_action(
        &mut self,
        state: &RuntimeState,
        event: &DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        let Some(container_id) = event.attributes.get("container") else {
            return Ok(None);
        };

        let requires_refresh = state
            .containers
            .get(container_id.as_str())
            .is_some_and(|snapshot| snapshot.policy.enabled)
            || state
                .networks
                .contains_key(&NetworkId::from(event.id.as_str()));

        if !requires_refresh {
            trace!(
                container_id = %container_id,
                network_id = %event.id,
                "network connect ignored for container without policy on unmanaged network"
            );
            return Ok(None);
        }

        self.inspect_container_action(state, container_id)
    }

    fn resolve_network_disconnect_action(
        state: &RuntimeState,
        event: &DockerEvent,
    ) -> Option<RuntimeStateAction> {
        let container_id = event.attributes.get("container")?;
        let container = state.containers.get(container_id.as_str())?;
        if !container
            .attachments
            .iter()
            .any(|attachment| attachment.network_id == NetworkId::from(event.id.as_str()))
        {
            return None;
        }

        Some(RuntimeStateAction::RemoveContainerAttachment {
            container_id: container_id.as_str().into(),
            network_id: event.id.as_str().into(),
        })
    }

    fn inspect_network_action(
        &mut self,
        network_id: &str,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        debug!(%network_id, "resolving network runtime state action");
        match self.api.inspect_network(network_id) {
            Ok(network) => {
                if let Some(data) = Network::try_new(&network)? {
                    Ok(Some(RuntimeStateAction::UpsertNetwork {
                        network_id: network_id.into(),
                        network_name: network.name.clone(),
                        subnet: data.subnet,
                        gateway: data.gateway,
                    }))
                } else {
                    Ok(Some(RuntimeStateAction::RemoveNetwork {
                        network_id: network_id.into(),
                    }))
                }
            }
            Err(error) if is_not_found(&error) => Ok(Some(RuntimeStateAction::RemoveNetwork {
                network_id: network_id.into(),
            })),
            Err(error) => Err(error.into()),
        }
    }

    fn build_container_snapshot_from_summary(
        state: &RuntimeState,
        summary: &DockerContainerSummary,
    ) -> Result<Container, MonitorError> {
        let policy = parse_policy(&summary.labels)?;
        let runtime_dns_servers = runtime_dns_servers(summary.host_config.as_ref());

        let mut attachments = Vec::new();
        for (_network_name, endpoint) in container_summary_network_endpoints(summary) {
            let Some(address) = endpoint.ip_address else {
                continue;
            };
            let Some(network_id_raw) = endpoint.network_id.clone() else {
                continue;
            };
            let network_id: NetworkId = network_id_raw.into();
            let Some(_network_data) = state.networks.get(&network_id) else {
                continue;
            };
            attachments.push(NetworkAttachment {
                network_id,
                ip_address: address,
                aliases: endpoint.aliases.clone().unwrap_or_default(),
            });
        }

        Ok(Container {
            id: summary.id.clone().into(),
            name: container_summary_name(summary),
            attachments,
            runtime_dns_servers,
            policy,
        })
    }
}

fn is_not_found(error: &DockerError) -> bool {
    matches!(error, DockerError::ApiHttpStatus { status: 404, .. })
}

fn network_primary_config(network: &DockerNetworkInspect) -> Result<(IpNet, IpAddr), MonitorError> {
    let config = network
        .ipam
        .as_ref()
        .and_then(|ipam| ipam.config.as_ref())
        .and_then(|configs| configs.iter().next());

    let subnet = config
        .and_then(|c| c.subnet.as_deref())
        .ok_or_else(|| MonitorError::MissingNetworkSubnet(network.id.clone()))?;
    let subnet = subnet
        .parse::<IpNet>()
        .map_err(|_| MonitorError::InvalidNetworkSubnet {
            network_id: network.id.clone(),
            subnet: subnet.to_string(),
        })?;

    let gateway = config
        .and_then(|c| c.gateway.as_deref())
        .ok_or_else(|| MonitorError::MissingNetworkGateway(network.id.clone()))?;
    let gateway = gateway
        .parse::<IpAddr>()
        .map_err(|_| MonitorError::InvalidNetworkGateway {
            network_id: network.id.clone(),
            gateway: gateway.to_string(),
        })?;

    Ok((subnet, gateway))
}

fn is_portcullis_network_enforced(network: &DockerNetworkInspect) -> Result<bool, MonitorError> {
    const LABEL_KEY: &str = "portcullis.network.enforce";
    let Some(value) = network
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_KEY))
        .cloned()
    else {
        return Ok(false);
    };
    match value.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(MonitorError::InvalidNetworkLabel {
            network_id: network.id.clone(),
            label: LABEL_KEY.to_string(),
            value,
        }),
    }
}

fn runtime_dns_servers(host_config: Option<&DockerHostConfig>) -> HashSet<IpAddr> {
    host_config
        .and_then(|config| config.dns.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|value| value.parse().ok())
        .collect()
}

fn container_inspect_network_endpoints(
    inspect: &DockerContainerInspect,
) -> Vec<(&str, DockerEndpoint)> {
    inspect
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .map(|networks| {
            networks
                .iter()
                .map(|(name, endpoint)| (name.as_str(), endpoint.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn container_summary_network_endpoints(
    summary: &DockerContainerSummary,
) -> Vec<(&str, DockerContainerSummaryEndpoint)> {
    summary
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .map(|networks| {
            networks
                .iter()
                .map(|(name, endpoint)| (name.as_str(), endpoint.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn container_summary_name(summary: &DockerContainerSummary) -> String {
    summary
        .names
        .as_ref()
        .and_then(|values| values.first())
        .cloned()
        .unwrap_or_else(|| summary.id.clone())
        .trim_start_matches('/')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::RefCell;

    use indexmap::IndexMap;
    use serde::Deserialize;

    use crate::docker::raw::{
        DockerContainerConfig, DockerContainerSummaryNetworkSettings, DockerIpam, DockerIpamConfig,
        DockerNetworkDriver, DockerNetworkSettings,
    };

    #[derive(Default)]
    struct MockDockerApi {
        containers_list: Vec<DockerContainerSummary>,
        networks_list: Vec<DockerNetworkInspect>,
        containers: HashMap<String, DockerContainerInspect>,
        networks: HashMap<String, DockerNetworkInspect>,
        inspect_container_requests: RefCell<Vec<String>>,
        inspect_network_requests: RefCell<Vec<String>>,
    }

    impl DockerApi for MockDockerApi {
        fn list_containers(&mut self) -> Result<Vec<DockerContainerSummary>, DockerError> {
            Ok(self.containers_list.clone())
        }

        fn list_networks(&mut self) -> Result<Vec<DockerNetworkInspect>, DockerError> {
            Ok(self.networks_list.clone())
        }

        fn inspect_container(
            &mut self,
            container_id: &str,
        ) -> Result<DockerContainerInspect, DockerError> {
            self.inspect_container_requests
                .borrow_mut()
                .push(container_id.to_string());
            self.containers
                .get(container_id)
                .cloned()
                .ok_or_else(|| DockerError::ApiHttpStatus {
                    status: 404,
                    body: format!("container not found: {container_id}"),
                })
        }

        fn inspect_network(
            &mut self,
            network_id: &str,
        ) -> Result<DockerNetworkInspect, DockerError> {
            self.inspect_network_requests
                .borrow_mut()
                .push(network_id.to_string());
            self.networks
                .get(network_id)
                .cloned()
                .ok_or_else(|| DockerError::ApiHttpStatus {
                    status: 404,
                    body: format!("network not found: {network_id}"),
                })
        }

        fn firewall_backend(&mut self) -> Result<DockerFirewallBackend, DockerError> {
            Ok(DockerFirewallBackend::Nftables)
        }
    }

    fn container_inspect(
        id: &str,
        name: &str,
        labels: &[(&str, &str)],
        network_name: &str,
        network_id: &str,
        address: &str,
    ) -> DockerContainerInspect {
        let label_map = labels
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();

        let mut networks = BTreeMap::new();
        let parsed_address: IpAddr = match address.parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse IP address for test fixture: {error}"),
        };
        networks.insert(
            network_name.to_string(),
            DockerEndpoint {
                network_id: Some(network_id.to_string()),
                ip_address: Some(parsed_address),
                aliases: Some(vec![name.to_string()]),
            },
        );

        DockerContainerInspect {
            id: id.to_string(),
            name: name.to_string(),
            config: DockerContainerConfig { labels: label_map },
            host_config: None,
            network_settings: Some(DockerNetworkSettings {
                networks: Some(networks),
            }),
        }
    }

    fn container_summary(
        id: &str,
        name: &str,
        labels: &[(&str, &str)],
        network_name: &str,
        network_id: &str,
        address: &str,
    ) -> DockerContainerSummary {
        let label_map = labels
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();
        let mut networks = BTreeMap::new();
        let parsed_address: IpAddr = match address.parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse IP address for summary fixture: {error}"),
        };
        networks.insert(
            network_name.to_string(),
            DockerContainerSummaryEndpoint {
                network_id: Some(network_id.to_string()),
                ip_address: Some(parsed_address),
                aliases: Some(vec![name.to_string()]),
            },
        );
        DockerContainerSummary {
            id: id.to_string(),
            names: Some(vec![name.to_string()]),
            labels: label_map,
            host_config: None,
            network_settings: Some(DockerContainerSummaryNetworkSettings {
                networks: Some(networks),
            }),
        }
    }

    fn network_inspect(id: &str, name: &str, subnet: &str) -> DockerNetworkInspect {
        DockerNetworkInspect {
            id: id.to_string(),
            name: name.to_string(),
            driver: DockerNetworkDriver::Bridge,
            ipam: Some(DockerIpam {
                config: Some(vec![DockerIpamConfig {
                    subnet: Some(subnet.to_string()),
                    gateway: None,
                }]),
            }),
            labels: None,
        }
    }

    fn network_without_subnet(id: &str, name: &str) -> DockerNetworkInspect {
        DockerNetworkInspect {
            id: id.to_string(),
            name: name.to_string(),
            driver: DockerNetworkDriver::Bridge,
            ipam: Some(DockerIpam {
                config: Some(vec![DockerIpamConfig {
                    subnet: None,
                    gateway: None,
                }]),
            }),
            labels: None,
        }
    }

    #[test]
    fn docker_monitor_builds_snapshot_with_policy_and_attachments() {
        let mut api = MockDockerApi {
            containers_list: vec![container_summary(
                "abc",
                "/web",
                &[
                    ("portcullis.enable", "true"),
                    ("portcullis.egress.0", "ip:1.1.1.1/32,tcp:443"),
                ],
                "bridge",
                "net0",
                "172.18.0.2",
            )],
            ..MockDockerApi::default()
        };

        api.containers.insert(
            "abc".to_string(),
            container_inspect(
                "abc",
                "web",
                &[
                    ("portcullis.enable", "true"),
                    ("portcullis.egress.0", "ip:1.1.1.1/32,tcp:443"),
                ],
                "bridge",
                "net0",
                "172.18.0.2",
            ),
        );

        api.networks.insert(
            "net0".to_string(),
            network_inspect("net0", "bridge", "172.18.0.0/16"),
        );
        api.networks_list
            .push(network_inspect("net0", "bridge", "172.18.0.0/16"));

        let mut monitor = DockerMonitor::new(api);
        let snapshot = match monitor.snapshot() {
            Ok(value) => value,
            Err(error) => panic!("snapshot should succeed: {error}"),
        };

        assert_eq!(snapshot.containers.len(), 1);
        let container = &snapshot.containers[0];
        assert_eq!(container.id, "abc".into());
        assert_eq!(container.attachments.len(), 1);
        assert!(container.policy.enabled);
        assert!(snapshot.enforced_network_subnets.is_empty());
    }

    #[test]
    fn docker_monitor_skips_endpoints_without_ip() {
        let mut api = MockDockerApi {
            containers_list: vec![DockerContainerSummary {
                id: "abc".into(),
                names: Some(vec!["/web".to_string()]),
                labels: IndexMap::new(),
                host_config: None,
                network_settings: Some(DockerContainerSummaryNetworkSettings {
                    networks: Some(BTreeMap::from([(
                        "bridge".to_string(),
                        DockerContainerSummaryEndpoint {
                            network_id: Some("net0".to_string()),
                            ip_address: None,
                            aliases: Some(vec!["web".to_string()]),
                        },
                    )])),
                }),
            }],
            ..MockDockerApi::default()
        };
        api.networks_list
            .push(network_inspect("net0", "bridge", "172.18.0.0/16"));

        let mut monitor = DockerMonitor::new(api);
        let snapshot = match monitor.snapshot() {
            Ok(value) => value,
            Err(error) => panic!("snapshot should succeed: {error}"),
        };

        assert_eq!(snapshot.containers[0].attachments.len(), 0);
    }

    #[test]
    fn docker_endpoint_deserialization_treats_empty_ip_as_none() {
        let inspect_json = r#"{
          "Id": "abc",
          "Name": "/web",
          "Config": {"Labels": {}},
          "NetworkSettings": {
            "Networks": {
              "bridge": {
                "NetworkID": "net0",
                "IPAddress": "",
                "Aliases": ["web"]
              }
            }
          }
        }"#;

        let inspect: DockerContainerInspect =
            serde_json::from_str(inspect_json).expect("container inspect should deserialize");
        let endpoint = container_inspect_network_endpoints(&inspect)
            .into_iter()
            .next()
            .expect("expected one endpoint")
            .1;
        assert!(endpoint.ip_address.is_none());
    }

    #[test]
    fn docker_monitor_fails_for_invalid_labels() {
        let mut api = MockDockerApi {
            containers_list: vec![container_summary(
                "abc",
                "/web",
                &[
                    ("portcullis.enable", "true"),
                    ("portcullis.egress.0", "ip:bad,tcp:443"),
                ],
                "bridge",
                "net0",
                "172.18.0.2",
            )],
            ..MockDockerApi::default()
        };

        api.containers.insert(
            "abc".to_string(),
            container_inspect(
                "abc",
                "web",
                &[
                    ("portcullis.enable", "true"),
                    ("portcullis.egress.0", "ip:bad,tcp:443"),
                ],
                "bridge",
                "net0",
                "172.18.0.2",
            ),
        );

        api.networks.insert(
            "net0".to_string(),
            network_inspect("net0", "bridge", "172.18.0.0/16"),
        );
        api.networks_list
            .push(network_inspect("net0", "bridge", "172.18.0.0/16"));

        let mut monitor = DockerMonitor::new(api);
        let result = monitor.snapshot();
        assert!(result.is_err());
    }

    #[test]
    fn docker_monitor_collects_enforced_network_subnets_from_network_labels() {
        let mut api = MockDockerApi {
            containers_list: vec![container_summary(
                "abc",
                "/web",
                &[("portcullis.enable", "true")],
                "bridge",
                "net0",
                "172.18.0.2",
            )],
            ..MockDockerApi::default()
        };
        let mut network = network_inspect("net0", "bridge", "172.18.0.0/16");
        network.labels = Some(IndexMap::from([(
            "portcullis.network.enforce".to_string(),
            "true".to_string(),
        )]));
        api.networks.insert("net0".to_string(), network.clone());
        api.networks_list.push(network);

        let mut monitor = DockerMonitor::new(api);
        let snapshot = monitor.snapshot().expect("snapshot should succeed");
        assert_eq!(snapshot.enforced_network_subnets.len(), 1);
        assert_eq!(
            snapshot.enforced_network_subnets[0].to_string(),
            "172.18.0.0/16"
        );
    }

    #[test]
    fn docker_container_event_relevance_filters_noise() {
        let relevant = DockerEvent {
            id: "abc".into(),
            action: DockerEventAction::Create,
            name: Some("web".to_string()),
            kind: DockerEventKind::Container,
            attributes: IndexMap::new(),
        };
        let not_relevant = DockerEvent {
            id: "abc".into(),
            action: DockerEventAction::Resize,
            name: Some("web".to_string()),
            kind: DockerEventKind::Container,
            attributes: IndexMap::new(),
        };
        let relevant_network = DockerEvent {
            id: "net0".to_string(),
            action: DockerEventAction::Disconnect,
            name: Some("pc-managed".to_string()),
            kind: DockerEventKind::Network,
            attributes: IndexMap::new(),
        };

        assert!(relevant.is_relevant_for_policy_refresh());
        assert!(!not_relevant.is_relevant_for_policy_refresh());
        assert!(relevant_network.is_relevant_for_policy_refresh());
    }

    #[test]
    fn create_event_uses_event_attributes_without_container_inspect() {
        let api = MockDockerApi::default();
        let mut monitor = DockerMonitor::new(api);
        let state = RuntimeState::default();
        let event = DockerEvent {
            id: "abc".into(),
            action: DockerEventAction::Create,
            name: Some("web".to_string()),
            kind: DockerEventKind::Container,
            attributes: IndexMap::from([
                ("name".to_string(), "web".to_string()),
                ("image".to_string(), "alpine/curl:latest".to_string()),
                ("portcullis.enable".to_string(), "true".to_string()),
                (
                    "portcullis.egress.1".to_string(),
                    "host:example.com,tcp:443".to_string(),
                ),
            ]),
        };

        let action = monitor
            .resolve_event_action(&state, event)
            .expect("create event should resolve");
        assert!(matches!(
            action,
            Some(RuntimeStateAction::CreateContainer { .. })
        ));
        assert!(monitor.api.inspect_container_requests.borrow().is_empty());
    }

    #[test]
    fn network_connect_uses_single_container_inspect_without_network_inspect() {
        let mut api = MockDockerApi::default();
        api.networks.insert(
            "net0".to_string(),
            network_inspect("net0", "pc-managed", "172.20.0.0/16"),
        );
        api.containers.insert(
            "abc".to_string(),
            container_inspect(
                "abc",
                "web",
                &[("portcullis.enable", "true")],
                "pc-managed",
                "net0",
                "172.20.0.2",
            ),
        );
        let mut monitor = DockerMonitor::new(api);
        let mut state = RuntimeState::default();
        state.apply_action(RuntimeStateAction::UpsertNetwork {
            network_id: "net0".into(),
            network_name: "pc-managed".to_string(),
            subnet: "172.20.0.0/16".parse().expect("valid subnet"),
            gateway: None,
            enforced: true,
        });
        state.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(Container {
                id: "abc".into(),
                name: "web".to_string(),
                attachments: Vec::new(),
                runtime_dns_servers: HashSet::new(),
                policy: parse_policy(
                    &[("portcullis.enable".to_string(), "true".to_string())].into(),
                )
                .expect("policy should parse"),
            }),
        });
        let event = DockerEvent {
            id: "net0".to_string(),
            action: DockerEventAction::Connect,
            name: Some("pc-managed".to_string()),
            kind: DockerEventKind::Network,
            attributes: [("container".to_string(), "abc".to_string())].into(),
        };

        let action = monitor
            .resolve_event_action(&state, event)
            .expect("connect event should resolve");
        assert!(matches!(
            action,
            Some(RuntimeStateAction::CreateContainer { .. })
        ));
        assert_eq!(
            monitor.api.inspect_container_requests.borrow().as_slice(),
            ["abc".to_string()]
        );
        assert!(monitor.api.inspect_network_requests.borrow().is_empty());
    }

    #[test]
    fn network_disconnect_uses_cached_attachment_without_queries() {
        let api = MockDockerApi::default();
        let mut monitor = DockerMonitor::new(api);
        let mut state = RuntimeState::default();
        state.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(Container {
                id: "abc".into(),
                name: "web".to_string(),
                attachments: vec![NetworkAttachment {
                    network_id: "net0".into(),
                    ip_address: "172.20.0.2".parse().expect("valid ip"),
                    aliases: Vec::new(),
                }],
                runtime_dns_servers: HashSet::new(),
                policy: crate::model::ContainerPolicy::default(),
            }),
        });
        let event = DockerEvent {
            id: "net0".to_string(),
            action: DockerEventAction::Disconnect,
            name: Some("pc-managed".to_string()),
            kind: DockerEventKind::Network,
            attributes: [("container".to_string(), "abc".to_string())].into(),
        };

        let action = monitor
            .resolve_event_action(&state, event)
            .expect("disconnect event should resolve");
        assert!(matches!(
            action,
            Some(RuntimeStateAction::RemoveContainerAttachment { .. })
        ));
        assert!(monitor.api.inspect_container_requests.borrow().is_empty());
        assert!(monitor.api.inspect_network_requests.borrow().is_empty());
    }

    #[test]
    fn docker_monitor_collects_enforced_subnets_without_running_containers() {
        let mut api = MockDockerApi::default();
        let mut network = network_inspect("net0", "pc-managed", "172.22.0.0/16");
        network.labels = Some(IndexMap::from([(
            "portcullis.network.enforce".to_string(),
            "true".to_string(),
        )]));
        api.networks_list.push(network.clone());
        api.networks.insert("net0".to_string(), network);

        let mut monitor = DockerMonitor::new(api);
        let snapshot = monitor.snapshot().expect("snapshot should succeed");
        assert!(snapshot.containers.is_empty());
        assert_eq!(snapshot.enforced_network_subnets.len(), 1);
        assert_eq!(
            snapshot.enforced_network_subnets[0].to_string(),
            "172.22.0.0/16"
        );
    }

    #[test]
    fn docker_monitor_ignores_host_network_without_subnet() {
        let mut api = MockDockerApi::default();
        let mut host_network = network_without_subnet("net-no-subnet", "host");
        host_network.driver = DockerNetworkDriver::Host;
        api.networks_list.push(host_network.clone());
        api.networks
            .insert("net-no-subnet".to_string(), host_network);

        let mut monitor = DockerMonitor::new(api);
        let snapshot = monitor.snapshot().expect("snapshot should succeed");
        assert!(snapshot.containers.is_empty());
        assert!(snapshot.enforced_network_subnets.is_empty());
    }

    #[test]
    fn docker_monitor_errors_on_bridge_network_without_subnet() {
        let mut api = MockDockerApi::default();
        api.networks_list
            .push(network_without_subnet("net-no-subnet", "custom-net"));
        api.networks.insert(
            "net-no-subnet".to_string(),
            network_without_subnet("net-no-subnet", "custom-net"),
        );

        let mut monitor = DockerMonitor::new(api);
        let result = monitor.snapshot();
        assert!(matches!(
            result,
            Err(MonitorError::MissingNetworkSubnet(ref id)) if id == "net-no-subnet"
        ));
    }

    #[test]
    fn docker_monitor_ignores_non_bridge_network_even_with_subnet() {
        let mut api = MockDockerApi::default();
        let mut network = network_inspect("net-overlay", "overlay-net", "172.23.0.0/16");
        network.driver = DockerNetworkDriver::Overlay;
        network.labels = Some(IndexMap::from([(
            "portcullis.network.enforce".to_string(),
            "true".to_string(),
        )]));
        api.networks_list.push(network.clone());
        api.networks.insert("net-overlay".to_string(), network);

        let mut monitor = DockerMonitor::new(api);
        let snapshot = monitor.snapshot().expect("snapshot should succeed");
        assert!(snapshot.containers.is_empty());
        assert!(snapshot.enforced_network_subnets.is_empty());
    }

    #[test]
    fn docker_network_driver_deserialization_maps_known_and_other_values() {
        #[derive(Deserialize)]
        struct DriverFixture {
            #[serde(rename = "Driver")]
            driver: DockerNetworkDriver,
        }

        let bridge: DriverFixture =
            serde_json::from_str(r#"{"Driver":"bridge"}"#).expect("bridge should parse");
        let none: DriverFixture =
            serde_json::from_str(r#"{"Driver":"none"}"#).expect("none should parse");
        let custom: DriverFixture =
            serde_json::from_str(r#"{"Driver":"my-plugin"}"#).expect("custom should parse");

        assert_eq!(bridge.driver, DockerNetworkDriver::Bridge);
        assert_eq!(none.driver, DockerNetworkDriver::None);
        assert_eq!(
            custom.driver,
            DockerNetworkDriver::Other("my-plugin".to_string())
        );
    }

    #[test]
    fn inspect_network_action_returns_upsert_network_action() {
        let mut api = MockDockerApi::default();
        api.networks.insert(
            "net0".to_string(),
            network_inspect("net0", "pc-managed", "172.19.0.0/16"),
        );

        let mut monitor = DockerMonitor::new(api);
        let action = monitor
            .inspect_network_action("net0")
            .expect("inspect network should succeed");
        assert!(matches!(
            action,
            Some(RuntimeStateAction::UpsertNetwork { network_id, .. }) if network_id == "net0".into()
        ));
    }

    #[test]
    fn remove_network_prunes_container_attachments() {
        let mut api = MockDockerApi {
            containers_list: vec![container_summary(
                "abc",
                "/web",
                &[("portcullis.enable", "true")],
                "bridge",
                "net0",
                "172.18.0.2",
            )],
            ..MockDockerApi::default()
        };
        api.containers.insert(
            "abc".to_string(),
            container_inspect(
                "abc",
                "web",
                &[("portcullis.enable", "true")],
                "bridge",
                "net0",
                "172.18.0.2",
            ),
        );
        api.networks_list
            .push(network_inspect("net0", "bridge", "172.18.0.0/16"));
        api.networks.insert(
            "net0".to_string(),
            network_inspect("net0", "bridge", "172.18.0.0/16"),
        );

        let mut monitor = DockerMonitor::new(api);
        let mut state = monitor
            .collect_state()
            .expect("collect state should succeed");
        let container_before = state.snapshot().containers[0].attachments.len();
        assert_eq!(container_before, 1);
        assert!(state.remove_network(&"net0".into()));
        let container_after = state.snapshot().containers[0].attachments.len();
        assert_eq!(container_after, 0);
    }

    #[test]
    fn docker_network_primary_subnet_parses_first_subnet() {
        let network = network_inspect("net0", "bridge", "172.18.0.0/16");
        let subnet = match network_primary_subnet(&network) {
            Ok(value) => value,
            Err(error) => panic!("primary_subnet should succeed: {error}"),
        };

        assert_eq!(subnet.to_string(), "172.18.0.0/16");
    }

    fn runtime_snapshot(
        container_id: &str,
        name: &str,
        labels: &[(&str, &str)],
        network_id: &str,
        network_name: &str,
        ip_address: &str,
        subnet: &str,
    ) -> RuntimeSnapshot {
        let label_map = labels
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();

        let parsed_ip = match ip_address.parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse ip fixture: {error}"),
        };
        let parsed_subnet = match subnet.parse() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse subnet fixture: {error}"),
        };

        RuntimeSnapshot {
            containers: vec![Container {
                id: container_id.into(),
                name: name.to_string(),
                attachments: vec![NetworkAttachment {
                    network_id: network_id.into(),
                    ip_address: parsed_ip,
                    aliases: vec![name.to_string()],
                }],
                runtime_dns_servers: HashSet::new(),
                policy: parse_policy(&label_map).unwrap(),
            }],
            networks: HashMap::from([(
                network_id.into(),
                NetworkSnapshot {
                    id: network_id.into(),
                    name: network_name.to_string(),
                    subnet: parsed_subnet,
                    gateway: None,
                    enforced: false,
                },
            )]),
            enforced_network_subnets: Vec::new(),
        }
    }

    #[test]
    fn detect_runtime_changes_reports_additions_for_initial_snapshot() {
        let current = runtime_snapshot(
            "abc",
            "web",
            &[
                ("portcullis.enable", "true"),
                ("portcullis.egress.0", "ip:1.1.1.1/32,tcp:443"),
            ],
            "net0",
            "bridge",
            "172.18.0.2",
            "172.18.0.0/16",
        );

        let changes = detect_runtime_changes(None, &current);
        assert_eq!(changes.len(), 1);
        assert!(matches!(changes[0], RuntimeChange::ContainerAdded { .. }));
    }

    #[test]
    fn detect_runtime_changes_reports_label_and_attachment_changes() {
        let previous = runtime_snapshot(
            "abc",
            "web",
            &[
                ("portcullis.enable", "true"),
                ("portcullis.egress.0", "ip:1.1.1.1/32,tcp:443"),
            ],
            "net0",
            "bridge",
            "172.18.0.2",
            "172.18.0.0/16",
        );
        let current = runtime_snapshot(
            "abc",
            "web",
            &[
                ("portcullis.enable", "true"),
                ("portcullis.egress.0", "ip:2.2.2.2/32,tcp:443"),
            ],
            "net1",
            "backend",
            "172.18.0.3",
            "172.18.0.0/16",
        );

        let changes = detect_runtime_changes(Some(&previous), &current);
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, RuntimeChange::PolicyChanged { .. }))
        );
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, RuntimeChange::AttachmentAdded { .. }))
        );
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, RuntimeChange::AttachmentRemoved { .. }))
        );
    }

    #[test]
    fn runtime_change_tracker_stores_previous_snapshot() {
        let previous = runtime_snapshot(
            "abc",
            "web",
            &[("portcullis.enable", "true")],
            "net0",
            "bridge",
            "172.18.0.2",
            "172.18.0.0/16",
        );
        let current = runtime_snapshot(
            "abc",
            "web",
            &[("portcullis.enable", "false")],
            "net0",
            "bridge",
            "172.18.0.2",
            "172.18.0.0/16",
        );

        let mut tracker = RuntimeChangeTracker::new();
        let first_changes = tracker.detect_and_log(&previous);
        assert_eq!(first_changes.len(), 1);

        let second_changes = tracker.detect_and_log(&current);
        assert!(!second_changes.is_empty());
    }
}
