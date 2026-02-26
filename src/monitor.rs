use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ipnet::IpNet;
use thiserror::Error;
use tracing::{debug, trace, warn};

use crate::docker::raw::{
    DockerContainerInspect, DockerContainerSummary, DockerContainerSummaryEndpoint, DockerEndpoint,
    DockerHostConfig, DockerNetworkInspect,
};
use crate::docker::{DockerApi, DockerError, DockerEvent, DockerEventAction, DockerEventKind};
use crate::labels::{LabelParseError, parse_policy};
use crate::model::{
    Container, ContainerId, Network, NetworkAttachment, NetworkId, RuntimeState, RuntimeStateAction,
};

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

fn network_from_inspect(network: &DockerNetworkInspect) -> Result<Option<Network>, MonitorError> {
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
    if !is_portcullis_network_enforced(network)? {
        debug!(
            network_id = %network.id,
            network_name = %network.name,
            "ignoring non-portcullis network"
        );
        return Ok(None);
    }

    let (subnet, gateway) = network_primary_config(network)?;

    Ok(Some(Network::new(
        network.id.clone().into(),
        network.name.clone(),
        subnet,
        gateway,
    )))
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

    pub fn initialize(&mut self) -> Result<RuntimeState, MonitorError> {
        debug!("collecting docker runtime state");

        let networks = self.api.list_networks()?;
        let containers = self.api.list_containers()?;

        let mut networks_by_id = HashMap::new();
        for network in networks {
            if let Some(data) = network_from_inspect(&network)? {
                networks_by_id.insert(data.id.clone(), data);
            }
        }
        let mut containers_by_id = HashMap::new();
        for summary in containers {
            let container = Self::build_container_from_summary(&networks_by_id, &summary)?;
            containers_by_id.insert(summary.id.into(), container);
        }
        let mut state = RuntimeState::default();
        state.apply_action(RuntimeStateAction::Initialize {
            containers: containers_by_id,
            networks: networks_by_id,
        });
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

    fn build_container_from_inspect(
        state: &RuntimeState,
        inspect: DockerContainerInspect,
    ) -> Result<(ContainerId, Box<Container>), MonitorError> {
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
            if !state.networks().contains_key(&network_id) {
                warn!(
                    network_id = %network_id,
                    container_id = %inspect.id,
                    "skipping attachment on unmanaged network"
                );
                continue;
            }
            attachments.push(NetworkAttachment {
                network_id,
                ip_address: address,
                aliases: endpoint.aliases.unwrap_or_default(),
            });
        }

        Ok((
            inspect.id.into(),
            Box::new(Container {
                name: inspect.name.trim_start_matches('/').to_string(),
                attachments,
                runtime_dns_servers,
                policy,
            }),
        ))
    }

    fn inspect_container_action(
        &mut self,
        state: &RuntimeState,
        container_id: &str,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        debug!(%container_id, "resolving container runtime state action");

        match self.api.inspect_container(container_id) {
            Ok(inspect) => {
                let (id, container) = Self::build_container_from_inspect(state, inspect)?;
                Ok(Some(RuntimeStateAction::CreateContainer { id, container }))
            }
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
            id: event.id.into(),
            container: Box::new(Container {
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
        if !state
            .networks()
            .contains_key(&NetworkId::from(event.id.as_str()))
        {
            trace!(
                network_id = %event.id,
                "network connect ignored for unmanaged network"
            );
            return Ok(None);
        }

        let Some(container_id) = event.attributes.get("container") else {
            return Ok(None);
        };

        self.inspect_container_action(state, container_id)
    }

    fn resolve_network_disconnect_action(
        state: &RuntimeState,
        event: &DockerEvent,
    ) -> Option<RuntimeStateAction> {
        let container_id = event.attributes.get("container")?;
        let container_id = ContainerId::from(container_id.as_str());
        let container = state.containers().get(&container_id)?;
        if !container
            .attachments
            .iter()
            .any(|attachment| attachment.network_id == NetworkId::from(event.id.as_str()))
        {
            return None;
        }

        Some(RuntimeStateAction::RemoveContainerAttachment {
            container_id,
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
                if let Some(data) = network_from_inspect(&network)? {
                    Ok(Some(RuntimeStateAction::UpsertNetwork {
                        network_id: network_id.into(),
                        network_name: data.name,
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

    fn build_container_from_summary(
        managed_networks: &HashMap<NetworkId, Network>,
        summary: &DockerContainerSummary,
    ) -> Result<Container, MonitorError> {
        let policy = parse_policy(&summary.labels)?;
        let runtime_dns_servers = runtime_dns_servers(summary.host_config.as_ref());

        let mut attachments = Vec::new();
        for (_, endpoint) in container_summary_network_endpoints(summary) {
            let Some(ip_address) = endpoint.ip_address else {
                continue;
            };
            let Some(network_id) = endpoint.network_id else {
                continue;
            };
            let network_id = network_id.into();

            // Ignore unregistered network.
            // NOTE: this can lead to problems if there are races in docker events and
            // the network appears after container attachment
            if !managed_networks.contains_key(&network_id) {
                continue;
            }
            let aliases = endpoint.aliases.unwrap_or_default();

            attachments.push(NetworkAttachment {
                network_id,
                ip_address,
                aliases,
            });
        }

        Ok(Container {
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

fn network_primary_config(
    network: &DockerNetworkInspect,
) -> Result<(IpNet, Option<IpAddr>), MonitorError> {
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

    let gateway = config.and_then(|c| c.gateway.as_deref()).map(|value| {
        value
            .parse::<IpAddr>()
            .map_err(|_| MonitorError::InvalidNetworkGateway {
                network_id: network.id.clone(),
                gateway: value.to_string(),
            })
    });
    let gateway = match gateway {
        Some(value) => Some(value?),
        None => None,
    };

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
    use std::cell::RefCell;
    use std::collections::{BTreeMap, HashMap, HashSet};

    use indexmap::IndexMap;

    use super::*;
    use crate::docker::raw::{
        DockerContainerConfig, DockerContainerSummaryNetworkSettings, DockerIpam, DockerIpamConfig,
        DockerNetworkDriver, DockerNetworkSettings,
    };
    use crate::docker::{DockerEvent, DockerFirewallBackend};

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

    fn network_inspect(
        id: &str,
        name: &str,
        subnet: &str,
        gateway: Option<&str>,
        driver: DockerNetworkDriver,
        enforce_label: Option<&str>,
    ) -> DockerNetworkInspect {
        let labels = enforce_label.map(|value| {
            IndexMap::from([("portcullis.network.enforce".to_string(), value.to_string())])
        });

        DockerNetworkInspect {
            id: id.to_string(),
            name: name.to_string(),
            driver,
            ipam: Some(DockerIpam {
                config: Some(vec![DockerIpamConfig {
                    subnet: Some(subnet.to_string()),
                    gateway: gateway.map(std::string::ToString::to_string),
                }]),
            }),
            labels,
        }
    }

    fn container_summary(
        id: &str,
        name: &str,
        labels: &[(&str, &str)],
        networks: &[(&str, &str, &str)],
    ) -> DockerContainerSummary {
        let mut network_map = BTreeMap::new();
        for (network_name, network_id, ip) in networks {
            network_map.insert(
                (*network_name).to_string(),
                DockerContainerSummaryEndpoint {
                    network_id: Some((*network_id).to_string()),
                    ip_address: Some(ip.parse().expect("summary fixture ip should parse")),
                    aliases: Some(vec![name.trim_start_matches('/').to_string()]),
                },
            );
        }

        DockerContainerSummary {
            id: id.to_string(),
            names: Some(vec![name.to_string()]),
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            host_config: None,
            network_settings: Some(DockerContainerSummaryNetworkSettings {
                networks: Some(network_map),
            }),
        }
    }

    fn container_inspect(
        id: &str,
        name: &str,
        labels: &[(&str, &str)],
        networks: &[(&str, &str, &str)],
    ) -> DockerContainerInspect {
        let mut network_map = BTreeMap::new();
        for (network_name, network_id, ip) in networks {
            network_map.insert(
                (*network_name).to_string(),
                DockerEndpoint {
                    network_id: Some((*network_id).to_string()),
                    ip_address: Some(ip.parse().expect("inspect fixture ip should parse")),
                    aliases: Some(vec![name.to_string()]),
                },
            );
        }

        DockerContainerInspect {
            id: id.to_string(),
            name: name.to_string(),
            config: DockerContainerConfig {
                labels: labels
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                    .collect(),
            },
            host_config: None,
            network_settings: Some(DockerNetworkSettings {
                networks: Some(network_map),
            }),
        }
    }

    fn network_connect_event(network_id: &str, container_id: &str) -> DockerEvent {
        DockerEvent {
            id: network_id.to_string(),
            action: DockerEventAction::Connect,
            name: Some("managed-net".to_string()),
            kind: DockerEventKind::Network,
            attributes: IndexMap::from([("container".to_string(), container_id.to_string())]),
        }
    }

    fn add_network(
        state: &mut RuntimeState,
        network_id: &str,
        subnet: &str,
        gateway: Option<&str>,
    ) {
        let subnet = subnet.parse().expect("subnet fixture should parse");
        let gateway = gateway.map(|value| value.parse().expect("gateway fixture should parse"));
        state.apply_action(RuntimeStateAction::UpsertNetwork {
            network_id: network_id.into(),
            network_name: network_id.to_string(),
            subnet,
            gateway,
        });
    }

    fn add_container(state: &mut RuntimeState, id: &str, container: Container) {
        state.apply_action(RuntimeStateAction::CreateContainer {
            id: id.into(),
            container: Box::new(container),
        });
    }

    #[test]
    fn collect_state_keeps_all_containers_and_only_managed_attachments() {
        let mut api = MockDockerApi::default();
        api.networks_list.push(network_inspect(
            "net0",
            "managed",
            "172.20.0.0/16",
            Some("172.20.0.1"),
            DockerNetworkDriver::Bridge,
            Some("true"),
        ));
        api.networks_list.push(network_inspect(
            "net1",
            "unmanaged",
            "172.21.0.0/16",
            Some("172.21.0.1"),
            DockerNetworkDriver::Bridge,
            None,
        ));
        api.containers_list.push(container_summary(
            "abc",
            "/web",
            &[("portcullis.egress.0", "host:api.example.com,tcp:443")],
            &[
                ("managed", "net0", "172.20.0.2"),
                ("unmanaged", "net1", "172.21.0.2"),
            ],
        ));
        api.containers_list.push(container_summary(
            "def",
            "/db",
            &[],
            &[("unmanaged", "net1", "172.21.0.3")],
        ));

        let mut monitor = DockerMonitor::new(api);
        let state = monitor.initialize().expect("collect_state should succeed");

        assert_eq!(state.networks().len(), 1);
        assert!(state.networks().contains_key("net0"));
        assert_eq!(state.containers().len(), 2);
        assert_eq!(
            state
                .containers()
                .get("abc")
                .expect("abc should be present")
                .attachments
                .len(),
            1
        );
        assert!(
            state
                .containers()
                .get("def")
                .expect("def should be present")
                .attachments
                .is_empty()
        );
    }

    #[test]
    fn network_connect_uses_single_container_inspect_without_network_inspect() {
        let mut api = MockDockerApi::default();
        api.containers.insert(
            "abc".to_string(),
            container_inspect(
                "abc",
                "/web",
                &[("portcullis.egress.0", "ip:1.1.1.1/32,tcp:443")],
                &[("managed", "net0", "172.20.0.2")],
            ),
        );

        let mut monitor = DockerMonitor::new(api);
        let mut state = RuntimeState::default();
        add_network(&mut state, "net0", "172.20.0.0/16", Some("172.20.0.1"));

        let action = monitor
            .resolve_event_action(&state, network_connect_event("net0", "abc"))
            .expect("connect action should resolve");

        match action {
            Some(RuntimeStateAction::CreateContainer { id, container }) => {
                assert_eq!(id.as_str(), "abc");
                assert_eq!(container.attachments.len(), 1);
            }
            _ => panic!("expected create container action"),
        }
        assert_eq!(
            monitor.api.inspect_container_requests.borrow().as_slice(),
            ["abc".to_string()]
        );
        assert!(monitor.api.inspect_network_requests.borrow().is_empty());
    }

    #[test]
    fn network_connect_skips_unmanaged_networks_without_queries() {
        let api = MockDockerApi::default();
        let mut monitor = DockerMonitor::new(api);
        let state = RuntimeState::default();

        let action = monitor
            .resolve_event_action(&state, network_connect_event("net-missing", "abc"))
            .expect("connect action should resolve");

        assert!(action.is_none());
        assert!(monitor.api.inspect_container_requests.borrow().is_empty());
        assert!(monitor.api.inspect_network_requests.borrow().is_empty());
    }

    #[test]
    fn network_connect_skips_unknown_container_network_attachments() {
        let mut api = MockDockerApi::default();
        api.containers.insert(
            "abc".to_string(),
            container_inspect("abc", "/web", &[], &[("other", "net-other", "172.30.0.2")]),
        );

        let mut monitor = DockerMonitor::new(api);
        let mut state = RuntimeState::default();
        add_network(&mut state, "net0", "172.20.0.0/16", Some("172.20.0.1"));

        let action = monitor
            .resolve_event_action(&state, network_connect_event("net0", "abc"))
            .expect("connect action should resolve");

        match action {
            Some(RuntimeStateAction::CreateContainer { container, .. }) => {
                assert!(container.attachments.is_empty());
            }
            _ => panic!("expected create container action"),
        }
        assert!(monitor.api.inspect_network_requests.borrow().is_empty());
    }

    #[test]
    fn network_disconnect_uses_cached_attachment_without_queries() {
        let api = MockDockerApi::default();
        let mut monitor = DockerMonitor::new(api);
        let mut state = RuntimeState::default();
        add_container(
            &mut state,
            "abc",
            Container {
                name: "web".to_string(),
                attachments: vec![NetworkAttachment {
                    network_id: "net0".into(),
                    ip_address: "172.20.0.2".parse().expect("valid ip"),
                    aliases: Vec::new(),
                }],
                runtime_dns_servers: HashSet::new(),
                policy: crate::model::ContainerPolicy::default(),
            },
        );

        let event = DockerEvent {
            id: "net0".to_string(),
            action: DockerEventAction::Disconnect,
            name: Some("managed-net".to_string()),
            kind: DockerEventKind::Network,
            attributes: IndexMap::from([("container".to_string(), "abc".to_string())]),
        };

        let action = monitor
            .resolve_event_action(&state, event)
            .expect("disconnect action should resolve");

        assert!(matches!(
            action,
            Some(RuntimeStateAction::RemoveContainerAttachment { .. })
        ));
        assert!(monitor.api.inspect_container_requests.borrow().is_empty());
        assert!(monitor.api.inspect_network_requests.borrow().is_empty());
    }

    #[test]
    fn create_event_uses_event_attributes_without_container_inspect() {
        let api = MockDockerApi::default();
        let mut monitor = DockerMonitor::new(api);
        let state = RuntimeState::default();

        let event = DockerEvent {
            id: "abc".to_string(),
            action: DockerEventAction::Create,
            name: Some("web".to_string()),
            kind: DockerEventKind::Container,
            attributes: IndexMap::from([(
                "portcullis.egress.0".to_string(),
                "host:api.example.com,tcp:443".to_string(),
            )]),
        };

        let action = monitor
            .resolve_event_action(&state, event)
            .expect("create action should resolve");

        assert!(matches!(
            action,
            Some(RuntimeStateAction::CreateContainer { .. })
        ));
        assert!(monitor.api.inspect_container_requests.borrow().is_empty());
    }

    #[test]
    fn network_create_upserts_only_managed_bridge_networks() {
        let mut api = MockDockerApi::default();
        api.networks.insert(
            "net0".to_string(),
            network_inspect(
                "net0",
                "managed",
                "172.20.0.0/16",
                Some("172.20.0.1"),
                DockerNetworkDriver::Bridge,
                Some("true"),
            ),
        );
        api.networks.insert(
            "net1".to_string(),
            network_inspect(
                "net1",
                "unmanaged",
                "172.21.0.0/16",
                Some("172.21.0.1"),
                DockerNetworkDriver::Bridge,
                None,
            ),
        );
        let mut monitor = DockerMonitor::new(api);

        let managed_event = DockerEvent {
            id: "net0".to_string(),
            action: DockerEventAction::Create,
            name: Some("managed".to_string()),
            kind: DockerEventKind::Network,
            attributes: IndexMap::new(),
        };
        let unmanaged_event = DockerEvent {
            id: "net1".to_string(),
            action: DockerEventAction::Create,
            name: Some("unmanaged".to_string()),
            kind: DockerEventKind::Network,
            attributes: IndexMap::new(),
        };

        let managed = monitor
            .resolve_event_action(&RuntimeState::default(), managed_event)
            .expect("managed network action should resolve");
        let unmanaged = monitor
            .resolve_event_action(&RuntimeState::default(), unmanaged_event)
            .expect("unmanaged network action should resolve");

        assert!(matches!(
            managed,
            Some(RuntimeStateAction::UpsertNetwork { network_id, .. }) if network_id == "net0".into()
        ));
        assert!(matches!(
            unmanaged,
            Some(RuntimeStateAction::RemoveNetwork { network_id }) if network_id == "net1".into()
        ));
    }

    #[test]
    fn collect_state_rejects_invalid_network_enforce_label() {
        let mut api = MockDockerApi::default();
        api.networks_list.push(network_inspect(
            "net0",
            "managed",
            "172.20.0.0/16",
            Some("172.20.0.1"),
            DockerNetworkDriver::Bridge,
            Some("yes"),
        ));

        let mut monitor = DockerMonitor::new(api);
        let result = monitor.initialize();

        assert!(matches!(
            result,
            Err(MonitorError::InvalidNetworkLabel { .. })
        ));
    }
}
