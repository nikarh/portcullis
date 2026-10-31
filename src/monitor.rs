use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use indexmap::IndexMap;
use ipnet::IpNet;
use thiserror::Error;
use tracing::{debug, error, trace, warn};

use crate::docker::raw::{
    DockerContainerInspect, DockerContainerSummary, DockerContainerSummaryEndpoint, DockerEndpoint,
    DockerHostConfig, DockerNetworkInspect,
};
use crate::docker::{DockerApi, DockerError, DockerEvent, DockerEventAction, DockerEventKind};
use crate::labels::parse_policy;
use crate::model::{
    Container, ContainerId, ContainerPolicy, Network, NetworkAttachment, NetworkId, RuntimeState,
    RuntimeStateAction,
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
}

/// Policy from a container's labels. Invalid labels are logged and skipped.
fn policy_from_labels(container: &str, labels: &IndexMap<String, String>) -> ContainerPolicy {
    let (policy, errors) = parse_policy(labels);
    for error in errors {
        error!(container = container.trim_start_matches('/'), %error, "ignoring invalid portcullis label");
    }
    policy
}

/// The managed network for `network`, or `None` when Portcullis doesn't manage it. Invalid
/// configuration is logged rather than failing the caller.
fn network_from_inspect(network: &DockerNetworkInspect) -> Option<Network> {
    // Ignore non-bridge networks
    if !network.driver.is_bridge() {
        debug!(
            network_id = %network.id,
            network_name = %network.name,
            driver = ?network.driver,
            "ignoring unsupported docker network driver"
        );
        return None;
    }

    // Ignore non-portcullis networks
    if !is_portcullis_enabled(network) {
        debug!(
            network_id = %network.id,
            network_name = %network.name,
            "ignoring non-portcullis network"
        );
        return None;
    }

    let (subnet, gateway) = match network_primary_config(network) {
        Ok(value) => value,
        Err(error) => {
            error!(network = %network.name, %error, "can't enforce network without a valid subnet");
            return None;
        }
    };

    Some(Network::new(
        network.id.clone().into(),
        network.name.clone(),
        subnet,
        gateway,
    ))
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
            if let Some(data) = network_from_inspect(&network) {
                networks_by_id.insert(data.id.clone(), data);
            }
        }
        let mut containers_by_id = HashMap::new();
        for summary in containers {
            let container = Self::build_container_from_summary(&networks_by_id, summary);
            containers_by_id.insert(container.id.clone(), container);
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
                DockerEventAction::Create => Ok(Self::create_container_action(event)),
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
                DockerEventAction::Connect => self.resolve_network_connect_action(state, event),
                DockerEventAction::Disconnect => {
                    Ok(Self::resolve_network_disconnect_action(state, event))
                }
                _ => Ok(None),
            },
        }
    }

    fn build_container_from_inspect(
        state: &RuntimeState,
        inspect: DockerContainerInspect,
    ) -> Result<Box<Container>, MonitorError> {
        let policy = policy_from_labels(&inspect.name, &inspect.config.labels);
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

        Ok(Box::new(Container {
            id: inspect.id.into(),
            name: inspect.name.trim_start_matches('/').to_string().into(),
            attachments,
            runtime_dns_servers,
            policy,
        }))
    }

    fn inspect_container_action(
        &mut self,
        state: &RuntimeState,
        container_id: &str,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        debug!(%container_id, "resolving container runtime state action");

        match self.api.inspect_container(container_id) {
            Ok(inspect) => {
                let container = Self::build_container_from_inspect(state, inspect)?;
                Ok(Some(RuntimeStateAction::CreateContainer { container }))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn create_container_action(event: DockerEvent) -> Option<RuntimeStateAction> {
        let policy = policy_from_labels(
            event.name.as_deref().unwrap_or(&event.id),
            &event.attributes,
        );

        let name = event.name?;

        Some(RuntimeStateAction::CreateContainer {
            container: Box::new(Container {
                id: event.id.into(),
                name: name.trim_start_matches('/').to_string().into(),
                attachments: Vec::new(),
                runtime_dns_servers: HashSet::new(),
                policy,
            }),
        })
    }

    fn resolve_network_connect_action(
        &mut self,
        state: &RuntimeState,
        event: DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        let network_id = NetworkId::from(event.id);

        if !state.networks().contains_key(&network_id) {
            trace!(
                network_id = %network_id,
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
        mut event: DockerEvent,
    ) -> Option<RuntimeStateAction> {
        let container_id = event.attributes.swap_remove("container")?;
        let container_id = ContainerId::from(container_id);
        let container = state.containers().get(&container_id)?;
        let network_id = NetworkId::from(event.id);

        if !container
            .attachments
            .iter()
            .any(|attachment| attachment.network_id == network_id)
        {
            return None;
        }

        Some(RuntimeStateAction::RemoveContainerAttachment {
            container_id,
            network_id,
        })
    }

    fn inspect_network_action(
        &mut self,
        network_id: &str,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        debug!(%network_id, "resolving network runtime state action");
        match self.api.inspect_network(network_id) {
            Ok(network) => {
                if let Some(data) = network_from_inspect(&network) {
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
        summary: DockerContainerSummary,
    ) -> Container {
        let policy = policy_from_labels(&container_summary_name(&summary), &summary.labels);
        let runtime_dns_servers = runtime_dns_servers(summary.host_config.as_ref());

        let mut attachments = Vec::new();
        for (_, endpoint) in container_summary_network_endpoints(&summary) {
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

        let name = container_summary_name(&summary).into();
        Container {
            id: summary.id.into(),
            name,
            attachments,
            runtime_dns_servers,
            policy,
        }
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

    let gateway = config.and_then(|c| c.gateway.as_deref()).and_then(|value| {
        let gateway = value.parse::<IpAddr>().ok();
        if gateway.is_none() {
            error!(network = %network.name, gateway = value, "ignoring invalid network gateway");
        }
        gateway
    });

    Ok((subnet, gateway))
}

/// Whether the network opted in. An invalid value is logged and treated as enforced, so a
/// typo restricts containers instead of silently leaving them open.
fn is_portcullis_enabled(network: &DockerNetworkInspect) -> bool {
    const LABEL_KEY: &str = "portcullis.enable";
    let Some(value) = network
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_KEY))
        .cloned()
    else {
        return false;
    };
    match value.as_str() {
        "true" => true,
        "false" => false,
        _ => {
            error!(
                network = %network.name,
                label = LABEL_KEY,
                %value,
                "invalid label value, expected true or false; enforcing the network"
            );
            true
        }
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
        let labels = enforce_label
            .map(|value| IndexMap::from([("portcullis.enable".to_string(), value.to_string())]));

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

    fn add_container(state: &mut RuntimeState, container: Container) {
        state.apply_action(RuntimeStateAction::CreateContainer {
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
            Some(RuntimeStateAction::CreateContainer { container }) => {
                assert_eq!(container.id.as_str(), "abc");
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
            Some(RuntimeStateAction::CreateContainer { container }) => {
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
            Container {
                id: "abc".to_string().into(),
                name: "web".to_string().into(),
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
    fn collect_state_enforces_network_with_invalid_enforce_label() {
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
        let state = monitor.initialize().expect("initialize should succeed");
        assert!(state.networks().contains_key("net0"));
    }

    #[test]
    fn collect_state_skips_enforced_network_without_subnet() {
        let mut api = MockDockerApi::default();
        let mut network = network_inspect(
            "net0",
            "managed",
            "172.20.0.0/16",
            Some("not-an-ip"),
            DockerNetworkDriver::Bridge,
            Some("true"),
        );
        network.ipam = None;
        api.networks_list.push(network);
        api.networks_list.push(network_inspect(
            "net1",
            "other",
            "172.21.0.0/16",
            Some("not-an-ip"),
            DockerNetworkDriver::Bridge,
            Some("true"),
        ));

        let mut monitor = DockerMonitor::new(api);
        let state = monitor.initialize().expect("initialize should succeed");
        assert!(!state.networks().contains_key("net0"));
        // an invalid gateway only drops the gateway
        let other = state
            .networks()
            .get("net1")
            .expect("net1 should be managed");
        assert_eq!(other.gateway, None);
    }

    #[test]
    fn collect_state_keeps_containers_with_invalid_labels() {
        let mut api = MockDockerApi::default();
        api.networks_list.push(network_inspect(
            "net0",
            "managed",
            "172.20.0.0/16",
            Some("172.20.0.1"),
            DockerNetworkDriver::Bridge,
            Some("true"),
        ));
        api.containers_list.push(container_summary(
            "abc",
            "/web",
            &[
                ("portcullis.egress.good", "ip:1.1.1.1,tcp:443"),
                ("portcullis.egress.bad", "ip:nope,tcp:443"),
            ],
            &[("managed", "net0", "172.20.0.2")],
        ));
        api.containers_list.push(container_summary(
            "def",
            "/db",
            &[],
            &[("managed", "net0", "172.20.0.3")],
        ));

        let mut monitor = DockerMonitor::new(api);
        let state = monitor.initialize().expect("initialize should succeed");
        assert_eq!(state.containers().len(), 2);
        let web = state.containers().get("abc").expect("web should be kept");
        assert_eq!(web.policy.egress.len(), 1);
    }

    #[test]
    fn create_event_keeps_container_with_invalid_labels() {
        let mut monitor = DockerMonitor::new(MockDockerApi::default());
        let event = DockerEvent {
            id: "abc".to_string(),
            action: DockerEventAction::Create,
            name: Some("web".to_string()),
            kind: DockerEventKind::Container,
            attributes: IndexMap::from([("portcullis.icc.mode".to_string(), "bogus".to_string())]),
        };

        let action = monitor
            .resolve_event_action(&RuntimeState::default(), event)
            .expect("create action should resolve");

        let Some(RuntimeStateAction::CreateContainer { container }) = action else {
            panic!("expected create container action");
        };
        assert_eq!(container.policy.icc_mode, crate::model::IccMode::Deny);
    }
}
