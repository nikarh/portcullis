use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::str::FromStr;

use indexmap::IndexMap;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

use crate::labels::{LabelParseError, parse_host_dns_servers, parse_policy};
use crate::model::{ContainerId, ContainerSnapshot, NetworkAttachment, NetworkId, RuntimeSnapshot};

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("docker socket I/O failed: {0}")]
    SocketIo(String),
    #[error("docker api request failed with status {status}: {body}")]
    ApiHttpStatus { status: u16, body: String },
    #[error("invalid HTTP response from docker api: {0}")]
    InvalidHttpResponse(String),
    #[error("invalid JSON from docker output: {0}")]
    InvalidJson(String),
    #[error("unsupported docker firewall backend: {0}")]
    UnsupportedFirewallBackend(String),
    #[error("missing network id in container {container_id} attachment {network_name}")]
    MissingNetworkId {
        container_id: String,
        network_name: String,
    },
    #[error("missing subnet for network id: {0}")]
    MissingNetworkSubnet(String),
    #[error("invalid subnet in network id {network_id}: {subnet}")]
    InvalidNetworkSubnet { network_id: String, subnet: String },
    #[error("invalid network label {label} on network {network_id}: {value}")]
    InvalidNetworkLabel {
        network_id: String,
        label: String,
        value: String,
    },
    #[error(transparent)]
    LabelParse(#[from] LabelParseError),
}

pub(crate) trait DockerApi {
    fn list_containers(&self) -> Result<Vec<DockerContainerSummary>, MonitorError>;
    fn list_networks(&self) -> Result<Vec<DockerNetworkInspect>, MonitorError>;
    fn inspect_container(&self, container_id: &str)
    -> Result<DockerContainerInspect, MonitorError>;
    fn inspect_network(&self, network_id: &str) -> Result<DockerNetworkInspect, MonitorError>;
    fn firewall_backend(&self) -> Result<DockerFirewallBackend, MonitorError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DockerFirewallBackend {
    Nftables,
    Iptables,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetworkRuntimeData {
    pub subnet: IpNet,
    pub gateway: Option<IpAddr>,
    pub enforced: bool,
}

impl NetworkRuntimeData {
    fn try_new(network: &DockerNetworkInspect) -> Result<Option<Self>, MonitorError> {
        if !network.driver.is_bridge() {
            debug!(
                network_id = %network.id,
                network_name = %network.name,
                driver = ?network.driver,
                "ignoring unsupported docker network driver"
            );
            return Ok(None);
        }

        let subnet = network.primary_subnet()?;
        let gateway = network.primary_gateway()?;
        let enforce_network_policy = network.is_portcullis_network_enforced()?;

        Ok(Some(Self {
            subnet,
            gateway,
            enforced: enforce_network_policy,
        }))
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimeState {
    containers: BTreeMap<ContainerId, ContainerSnapshot>,
    networks: HashMap<NetworkId, NetworkRuntimeData>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeStateAction {
    UpsertContainer {
        snapshot: Box<ContainerSnapshot>,
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
        subnet: IpNet,
        gateway: Option<IpAddr>,
        enforced: bool,
    },
    RemoveNetwork {
        network_id: NetworkId,
    },
}

impl RuntimeState {
    #[must_use]
    pub(crate) fn snapshot(&self) -> RuntimeSnapshot {
        let mut enforced_network_subnets = BTreeSet::new();
        for network in self.networks.values() {
            if network.enforced {
                enforced_network_subnets.insert(network.subnet);
            }
        }
        RuntimeSnapshot {
            containers: self.containers.values().cloned().collect(),
            enforced_network_subnets: enforced_network_subnets.into_iter().collect(),
        }
    }

    fn remove_container(&mut self, container_id: &ContainerId) -> bool {
        self.containers.remove(container_id).is_some()
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

    pub(crate) fn apply_action(&mut self, action: RuntimeStateAction) -> bool {
        match action {
            RuntimeStateAction::UpsertContainer { snapshot } => {
                let snapshot = *snapshot;
                let container_id = snapshot.id.clone();
                let changed = self.containers.get(&container_id) != Some(&snapshot);
                self.containers.insert(container_id, snapshot);
                changed
            }
            RuntimeStateAction::RemoveContainer { container_id } => {
                self.remove_container(&container_id)
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
                    return container.attachments.len() != previous_len;
                }
                false
            }
            RuntimeStateAction::UpsertNetwork {
                network_id,
                subnet,
                gateway,
                enforced,
            } => {
                let next = NetworkRuntimeData {
                    subnet,
                    gateway,
                    enforced,
                };
                let changed = self.networks.get(&network_id).copied() != Some(next);
                self.networks.insert(network_id, next);
                changed
            }
            RuntimeStateAction::RemoveNetwork { network_id } => self.remove_network(&network_id),
        }
    }
}

pub(crate) struct DockerMonitor<A> {
    api: A,
}

impl<A> DockerMonitor<A>
where
    A: DockerApi,
{
    pub(crate) const fn new(api: A) -> Self {
        Self { api }
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> Result<RuntimeSnapshot, MonitorError> {
        let state = self.collect_state()?;
        let snapshot = state.snapshot();
        info!(
            container_count = snapshot.containers.len(),
            "docker runtime snapshot collected"
        );
        trace!(?snapshot, "full docker runtime snapshot");
        Ok(snapshot)
    }

    pub(crate) fn firewall_backend(&self) -> Result<DockerFirewallBackend, MonitorError> {
        self.api.firewall_backend()
    }

    pub(crate) fn collect_state(&self) -> Result<RuntimeState, MonitorError> {
        debug!("collecting docker runtime state");
        let networks = self.api.list_networks()?;
        let containers = self.api.list_containers()?;

        let mut state = RuntimeState::default();
        for network in networks {
            if let Some(data) = NetworkRuntimeData::try_new(&network)? {
                state.networks.insert(network.id.into(), data);
            }
        }
        for summary in containers {
            if let Some(snapshot) =
                Self::try_build_container_snapshot_from_summary(&state, &summary)?
            {
                state.containers.insert(snapshot.id.clone(), snapshot);
                continue;
            }
            let inspect = self.api.inspect_container(&summary.id)?;
            let snapshot = self.build_container_snapshot(&mut state, inspect)?;
            state.containers.insert(snapshot.id.clone(), snapshot);
        }
        Ok(state)
    }

    pub(crate) fn resolve_event_action(
        &self,
        state: &RuntimeState,
        event: &DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        match event.kind {
            DockerEventKind::Container => Self::resolve_container_event_action(state, event),
            DockerEventKind::Network => self.resolve_network_event_action(state, event),
        }
    }

    fn resolve_container_event_action(
        state: &RuntimeState,
        event: &DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        match event.action {
            DockerEventAction::Destroy => Ok(Some(RuntimeStateAction::RemoveContainer {
                container_id: event.id.as_str().into(),
            })),
            DockerEventAction::Create => Self::create_container_action(event),
            DockerEventAction::Rename => Ok(Self::rename_container_action(state, event)),
            DockerEventAction::Update => Self::update_container_action(state, event),
            _ => Ok(None),
        }
    }

    fn resolve_network_event_action(
        &self,
        state: &RuntimeState,
        event: &DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        match event.action {
            DockerEventAction::Destroy => Ok(Some(RuntimeStateAction::RemoveNetwork {
                network_id: event.id.as_str().into(),
            })),
            DockerEventAction::Create | DockerEventAction::Update => {
                self.inspect_network_action(&event.id)
            }
            DockerEventAction::Connect => self.resolve_network_connect_action(state, event),
            DockerEventAction::Disconnect => {
                Ok(Self::resolve_network_disconnect_action(state, event))
            }
            _ => Ok(None),
        }
    }

    fn build_container_snapshot(
        &self,
        state: &mut RuntimeState,
        inspect: DockerContainerInspect,
    ) -> Result<ContainerSnapshot, MonitorError> {
        let labels = inspect.labels();
        let policy = parse_policy(&labels)?;
        let host_dns_servers = parse_host_dns_servers(&labels)?;
        let runtime_dns_servers = inspect.runtime_dns_servers();
        let mut attachments = Vec::new();

        for (network_name, endpoint) in inspect.network_endpoints() {
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
            if !state.networks.contains_key(&network_id) {
                let network_data = match self.api.inspect_network(network_id.as_str()) {
                    Ok(network) => NetworkRuntimeData::try_new(&network)?,
                    Err(error) if is_not_found(&error) => None,
                    Err(error) => return Err(error),
                };
                if let Some(data) = network_data {
                    state.networks.insert(network_id.clone(), data);
                }
            }
            let Some(network_data) = state.networks.get(&network_id).copied() else {
                warn!(
                    network_id = %network_id,
                    container_id = %inspect.id,
                    "skipping attachment on network without subnet"
                );
                continue;
            };
            attachments.push(NetworkAttachment {
                network_id,
                network_name: network_name.to_string(),
                ip_address: address,
                gateway: network_data.gateway,
                subnet: network_data.subnet,
                aliases: endpoint.aliases.unwrap_or_default(),
            });
        }

        Ok(ContainerSnapshot {
            id: inspect.id.into(),
            name: inspect.name,
            labels: labels.into_iter().collect(),
            attachments,
            runtime_dns_servers,
            host_dns_servers,
            policy,
        })
    }

    fn build_container_snapshot_from_inspect(
        &self,
        state: &RuntimeState,
        inspect: DockerContainerInspect,
    ) -> Result<ContainerSnapshot, MonitorError> {
        let labels = inspect.labels();
        let policy = parse_policy(&labels)?;
        let host_dns_servers = parse_host_dns_servers(&labels)?;
        let runtime_dns_servers = inspect.runtime_dns_servers();
        let mut attachments = Vec::new();
        let mut network_cache: HashMap<NetworkId, Option<NetworkRuntimeData>> = state
            .networks
            .iter()
            .map(|(network_id, data)| (network_id.clone(), Some(*data)))
            .collect();

        for (network_name, endpoint) in inspect.network_endpoints() {
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
            let network_data = if let Some(value) = network_cache.get(&network_id) {
                *value
            } else {
                let value = match self.api.inspect_network(network_id.as_str()) {
                    Ok(network) => NetworkRuntimeData::try_new(&network)?,
                    Err(error) if is_not_found(&error) => None,
                    Err(error) => return Err(error),
                };
                network_cache.insert(network_id.clone(), value);
                value
            };
            let Some(network_data) = network_data else {
                warn!(
                    network_id = %network_id,
                    container_id = %inspect.id,
                    "skipping attachment on network without subnet"
                );
                continue;
            };
            attachments.push(NetworkAttachment {
                network_id,
                network_name: network_name.to_string(),
                ip_address: address,
                gateway: network_data.gateway,
                subnet: network_data.subnet,
                aliases: endpoint.aliases.unwrap_or_default(),
            });
        }

        Ok(ContainerSnapshot {
            id: inspect.id.into(),
            name: inspect.name,
            labels: labels.into_iter().collect(),
            attachments,
            runtime_dns_servers,
            host_dns_servers,
            policy,
        })
    }

    fn inspect_container_action(
        &self,
        state: &RuntimeState,
        container_id: &str,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        debug!(%container_id, "resolving container runtime state action");
        match self.api.inspect_container(container_id) {
            Ok(inspect) => {
                let snapshot = self.build_container_snapshot_from_inspect(state, inspect)?;
                Ok(Some(RuntimeStateAction::UpsertContainer {
                    snapshot: Box::new(snapshot),
                }))
            }
            Err(error) if is_not_found(&error) => Ok(Some(RuntimeStateAction::RemoveContainer {
                container_id: container_id.into(),
            })),
            Err(error) => Err(error),
        }
    }

    fn create_container_action(
        event: &DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        let labels = event_portcullis_labels(&event.attributes);
        let policy = parse_policy(&labels)?;
        let host_dns_servers = parse_host_dns_servers(&labels)?;

        let name = event
            .name
            .as_deref()
            .or_else(|| event.attributes.get("name").map(String::as_str))
            .unwrap_or(event.id.as_str())
            .to_string();
        let snapshot = ContainerSnapshot {
            id: event.id.as_str().into(),
            name,
            labels: labels.into_iter().collect(),
            attachments: Vec::new(),
            runtime_dns_servers: HashSet::new(),
            host_dns_servers,
            policy,
        };
        Ok(Some(RuntimeStateAction::UpsertContainer {
            snapshot: Box::new(snapshot),
        }))
    }

    fn rename_container_action(
        state: &RuntimeState,
        event: &DockerEvent,
    ) -> Option<RuntimeStateAction> {
        let existing = state.containers.get(event.id.as_str())?;
        let name = event
            .name
            .as_deref()
            .or_else(|| event.attributes.get("name").map(String::as_str))
            .unwrap_or(existing.name.as_str())
            .to_string();
        if name == existing.name {
            return None;
        }
        let mut snapshot = existing.clone();
        snapshot.name = name;
        Some(RuntimeStateAction::UpsertContainer {
            snapshot: Box::new(snapshot),
        })
    }

    fn update_container_action(
        state: &RuntimeState,
        event: &DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        let Some(existing) = state.containers.get(event.id.as_str()) else {
            return Ok(None);
        };
        let labels = event_portcullis_labels(&event.attributes);
        let policy = parse_policy(&labels)?;
        let host_dns_servers = parse_host_dns_servers(&labels)?;

        if labels.is_empty() {
            return Ok(None);
        }

        let mut snapshot = existing.clone();
        snapshot.labels = labels.into_iter().collect();
        snapshot.policy = policy;
        snapshot.host_dns_servers = host_dns_servers;
        Ok(Some(RuntimeStateAction::UpsertContainer {
            snapshot: Box::new(snapshot),
        }))
    }

    fn resolve_network_connect_action(
        &self,
        state: &RuntimeState,
        event: &DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        let Some(container_id) = event.attributes.get("container") else {
            return Ok(None);
        };

        let requires_refresh = state
            .containers
            .get(container_id.as_str())
            .and_then(|snapshot| snapshot.policy.as_ref())
            .is_some()
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
        &self,
        network_id: &str,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        debug!(%network_id, "resolving network runtime state action");
        match self.api.inspect_network(network_id) {
            Ok(network) => {
                if let Some(data) = NetworkRuntimeData::try_new(&network)? {
                    Ok(Some(RuntimeStateAction::UpsertNetwork {
                        network_id: network_id.into(),
                        subnet: data.subnet,
                        gateway: data.gateway,
                        enforced: data.enforced,
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
            Err(error) => Err(error),
        }
    }

    fn try_build_container_snapshot_from_summary(
        state: &RuntimeState,
        summary: &DockerContainerSummary,
    ) -> Result<Option<ContainerSnapshot>, MonitorError> {
        let labels = summary.labels.clone().unwrap_or_default();
        let policy = parse_policy(&labels)?;
        let host_dns_servers = parse_host_dns_servers(&labels)?;
        let runtime_dns_servers = summary.runtime_dns_servers();

        if policy_uses_runtime_dns(policy.as_ref()) && runtime_dns_servers.is_empty() {
            return Ok(None);
        }

        let mut attachments = Vec::new();
        for (network_name, endpoint) in summary.network_endpoints() {
            let Some(address) = endpoint.ip_address else {
                continue;
            };
            let Some(network_id_raw) = endpoint.network_id.clone() else {
                return Ok(None);
            };
            let network_id: NetworkId = network_id_raw.into();
            let Some(network_data) = state.networks.get(&network_id).copied() else {
                return Ok(None);
            };
            if endpoint.aliases.is_none() {
                return Ok(None);
            }
            attachments.push(NetworkAttachment {
                network_id,
                network_name: network_name.to_string(),
                ip_address: address,
                gateway: network_data.gateway,
                subnet: network_data.subnet,
                aliases: endpoint.aliases.clone().unwrap_or_default(),
            });
        }

        Ok(Some(ContainerSnapshot {
            id: summary.id.clone().into(),
            name: summary.name(),
            labels: labels.into_iter().collect(),
            attachments,
            runtime_dns_servers,
            host_dns_servers,
            policy,
        }))
    }
}

fn policy_uses_runtime_dns(policy: Option<&crate::model::ContainerPolicy>) -> bool {
    policy.is_some_and(|value| {
        value
            .dns_targets
            .iter()
            .any(|target| matches!(target, crate::model::DnsTarget::Runtime))
    })
}

fn event_portcullis_labels(attributes: &HashMap<String, String>) -> IndexMap<String, String> {
    attributes
        .iter()
        .filter(|(key, _)| key.starts_with("portcullis."))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn is_not_found(error: &MonitorError) -> bool {
    matches!(error, MonitorError::ApiHttpStatus { status: 404, .. })
}

pub(crate) struct SocketDockerApi {
    socket_path: String,
}

impl SocketDockerApi {
    #[must_use]
    pub(crate) fn new(socket: String) -> Self {
        let socket_path = if let Some(path) = socket.strip_prefix("unix://") {
            path.to_string()
        } else {
            socket
        };
        Self { socket_path }
    }

    fn request_json<T>(&self, path: &str) -> Result<T, MonitorError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let body = self.request_raw(path)?;
        trace!(
            path,
            body_len = body.len(),
            "docker api json response received"
        );
        serde_json::from_str::<T>(&body)
            .map_err(|error| MonitorError::InvalidJson(error.to_string()))
    }

    fn request_raw(&self, path: &str) -> Result<String, MonitorError> {
        debug!(socket = %self.socket_path, path, "docker api request");
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|error| MonitorError::SocketIo(error.to_string()))?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|error| MonitorError::SocketIo(error.to_string()))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|error| MonitorError::SocketIo(error.to_string()))?;
        let response_text = String::from_utf8(response)
            .map_err(|error| MonitorError::InvalidHttpResponse(error.to_string()))?;
        parse_http_response(&response_text)
    }
}

impl DockerApi for SocketDockerApi {
    fn list_containers(&self) -> Result<Vec<DockerContainerSummary>, MonitorError> {
        let summaries: Vec<DockerContainerSummary> = self.request_json("/containers/json?all=1")?;
        trace!(
            container_count = summaries.len(),
            "parsed docker container summaries"
        );
        Ok(summaries)
    }

    fn list_networks(&self) -> Result<Vec<DockerNetworkInspect>, MonitorError> {
        let networks: Vec<DockerNetworkInspect> = self.request_json("/networks")?;
        trace!(network_count = networks.len(), "parsed docker networks");
        Ok(networks)
    }

    fn inspect_container(
        &self,
        container_id: &str,
    ) -> Result<DockerContainerInspect, MonitorError> {
        self.request_json(&format!("/containers/{container_id}/json"))
    }

    fn inspect_network(&self, network_id: &str) -> Result<DockerNetworkInspect, MonitorError> {
        self.request_json(&format!("/networks/{network_id}"))
    }

    fn firewall_backend(&self) -> Result<DockerFirewallBackend, MonitorError> {
        debug!("detecting docker firewall backend");
        let info: DockerInfo = self.request_json("/info")?;
        let backend = info
            .firewall_backend
            .and_then(DockerFirewallInfo::into_backend)
            .unwrap_or_else(|| "iptables".to_string())
            .to_lowercase();
        match backend.as_str() {
            "nftables" => Ok(DockerFirewallBackend::Nftables),
            "iptables" => Ok(DockerFirewallBackend::Iptables),
            _ => Err(MonitorError::UnsupportedFirewallBackend(backend)),
        }
    }
}

fn parse_http_response(response: &str) -> Result<String, MonitorError> {
    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return Err(MonitorError::InvalidHttpResponse(
            "missing HTTP header separator".to_string(),
        ));
    };
    let mut lines = head.lines();
    let Some(status_line) = lines.next() else {
        return Err(MonitorError::InvalidHttpResponse(
            "missing HTTP status line".to_string(),
        ));
    };
    let mut headers = BTreeMap::new();
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        headers.insert(key.trim().to_lowercase(), value.trim().to_lowercase());
    }

    let mut parts = status_line.split_whitespace();
    let _http_version = parts.next();
    let Some(status_code) = parts.next() else {
        return Err(MonitorError::InvalidHttpResponse(
            "missing HTTP status code".to_string(),
        ));
    };
    let status = status_code.parse::<u16>().map_err(|error| {
        MonitorError::InvalidHttpResponse(format!("invalid HTTP status code: {error}"))
    })?;

    let parsed_body = decode_http_body(body, &headers)?;

    if !(200..=299).contains(&status) {
        return Err(MonitorError::ApiHttpStatus {
            status,
            body: parsed_body.trim().to_string(),
        });
    }

    Ok(parsed_body)
}

fn decode_http_body(
    raw_body: &str,
    headers: &BTreeMap<String, String>,
) -> Result<String, MonitorError> {
    let transfer_encoding = headers
        .get("transfer-encoding")
        .map(String::as_str)
        .unwrap_or_default();
    if transfer_encoding.contains("chunked") {
        return decode_chunked_body(raw_body);
    }

    Ok(raw_body.to_string())
}

fn decode_chunked_body(raw_body: &str) -> Result<String, MonitorError> {
    let bytes = raw_body.as_bytes();
    let mut cursor = 0usize;
    let mut decoded = Vec::new();

    loop {
        let Some(line_end) = find_crlf(bytes, cursor) else {
            return Err(MonitorError::InvalidHttpResponse(
                "chunked response missing chunk size line terminator".to_string(),
            ));
        };

        let size_bytes = bytes.get(cursor..line_end).ok_or_else(|| {
            MonitorError::InvalidHttpResponse(
                "chunked response missing chunk size bytes".to_string(),
            )
        })?;
        let size_line = std::str::from_utf8(size_bytes).map_err(|error| {
            MonitorError::InvalidHttpResponse(format!("invalid chunk size line encoding: {error}"))
        })?;
        let size_hex = size_line.split(';').next().unwrap_or_default().trim();
        let chunk_size = usize::from_str_radix(size_hex, 16).map_err(|error| {
            MonitorError::InvalidHttpResponse(format!("invalid chunk size `{size_hex}`: {error}"))
        })?;
        cursor = line_end + 2;

        if chunk_size == 0 {
            break;
        }

        let chunk_end = cursor
            .checked_add(chunk_size)
            .ok_or_else(|| MonitorError::InvalidHttpResponse("chunk size overflow".to_string()))?;
        let terminator_end = chunk_end.checked_add(2).ok_or_else(|| {
            MonitorError::InvalidHttpResponse("chunk terminator overflow".to_string())
        })?;
        if terminator_end > bytes.len() {
            return Err(MonitorError::InvalidHttpResponse(
                "chunked response truncated before chunk end".to_string(),
            ));
        }

        let chunk = bytes.get(cursor..chunk_end).ok_or_else(|| {
            MonitorError::InvalidHttpResponse("chunked response missing chunk bytes".to_string())
        })?;
        decoded.extend_from_slice(chunk);

        let terminator = bytes.get(chunk_end..terminator_end).ok_or_else(|| {
            MonitorError::InvalidHttpResponse(
                "chunked response missing chunk terminator".to_string(),
            )
        })?;
        if terminator != b"\r\n" {
            return Err(MonitorError::InvalidHttpResponse(
                "chunked response missing chunk terminator".to_string(),
            ));
        }

        cursor = terminator_end;
    }

    String::from_utf8(decoded).map_err(|error| MonitorError::InvalidHttpResponse(error.to_string()))
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    let tail = bytes.get(start..)?;
    tail.windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DockerEventKind {
    Container,
    Network,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DockerEventAction {
    Create,
    Start,
    Rename,
    Update,
    Destroy,
    Connect,
    Disconnect,
    Attach,
    Detach,
    Restart,
    Stop,
    Die,
    Kill,
    Pause,
    Unpause,
    Resize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DockerEvent {
    pub id: String,
    pub action: DockerEventAction,
    pub name: Option<String>,
    pub kind: DockerEventKind,
    pub attributes: HashMap<String, String>,
}

impl DockerEvent {
    #[must_use]
    pub fn is_relevant_for_policy_refresh(&self) -> bool {
        match self.kind {
            DockerEventKind::Container => matches!(
                self.action,
                DockerEventAction::Create
                    | DockerEventAction::Destroy
                    | DockerEventAction::Rename
                    | DockerEventAction::Update
            ),
            DockerEventKind::Network => matches!(
                self.action,
                DockerEventAction::Create
                    | DockerEventAction::Destroy
                    | DockerEventAction::Update
                    | DockerEventAction::Connect
                    | DockerEventAction::Disconnect
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeChange {
    ContainerAdded {
        id: String,
        name: String,
    },
    ContainerRemoved {
        id: String,
        name: String,
    },
    LabelChanged {
        container_id: String,
        key: String,
        previous: Option<String>,
        current: Option<String>,
    },
    AttachmentAdded {
        container_id: String,
        network_id: String,
        ip_address: IpAddr,
        subnet: IpNet,
    },
    AttachmentRemoved {
        container_id: String,
        network_id: String,
        ip_address: IpAddr,
        subnet: IpNet,
    },
    PolicyChanged {
        container_id: String,
    },
}

#[derive(Debug, Default)]
pub(crate) struct RuntimeChangeTracker {
    previous: Option<RuntimeSnapshot>,
}

impl RuntimeChangeTracker {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self { previous: None }
    }

    pub(crate) fn detect_and_log(&mut self, current: &RuntimeSnapshot) -> Vec<RuntimeChange> {
        let changes = detect_runtime_changes(self.previous.as_ref(), current);

        if changes.is_empty() {
            debug!("docker change tracker: no runtime changes detected");
        } else {
            info!(
                change_count = changes.len(),
                "docker runtime changes detected"
            );
        }

        for change in &changes {
            match change {
                RuntimeChange::ContainerAdded { id, name } => {
                    info!(%id, %name, "container added");
                    debug!(?change, "container state change detail");
                }
                RuntimeChange::ContainerRemoved { id, name } => {
                    info!(%id, %name, "container removed");
                    debug!(?change, "container state change detail");
                }
                RuntimeChange::PolicyChanged { container_id } => {
                    info!(container_id = %container_id, "container policy changed");
                    debug!(?change, "container policy change detail");
                }
                RuntimeChange::LabelChanged {
                    container_id, key, ..
                } => {
                    debug!(container_id = %container_id, label_key = %key, ?change, "container label changed");
                }
                RuntimeChange::AttachmentAdded {
                    container_id,
                    network_id,
                    ip_address,
                    subnet,
                } => {
                    info!(container_id = %container_id, network_id = %network_id, %ip_address, %subnet, "container network attachment added");
                    debug!(?change, "network attachment change detail");
                }
                RuntimeChange::AttachmentRemoved {
                    container_id,
                    network_id,
                    ip_address,
                    subnet,
                } => {
                    info!(container_id = %container_id, network_id = %network_id, %ip_address, %subnet, "container network attachment removed");
                    debug!(?change, "network attachment change detail");
                }
            }
        }

        trace!(?changes, "full docker runtime change set");
        self.previous = Some(current.clone());
        changes
    }
}

#[must_use]
fn detect_runtime_changes(
    previous: Option<&RuntimeSnapshot>,
    current: &RuntimeSnapshot,
) -> Vec<RuntimeChange> {
    let mut changes = Vec::new();

    let Some(previous_snapshot) = previous else {
        for container in &current.containers {
            changes.push(RuntimeChange::ContainerAdded {
                id: container.id.to_string(),
                name: container.name.clone(),
            });
        }
        return changes;
    };

    let previous_by_id: HashMap<&str, &ContainerSnapshot> = previous_snapshot
        .containers
        .iter()
        .map(|container| (container.id.as_str(), container))
        .collect();
    let current_by_id: HashMap<&str, &ContainerSnapshot> = current
        .containers
        .iter()
        .map(|container| (container.id.as_str(), container))
        .collect();

    for (container_id, container) in &current_by_id {
        if let Some(previous_container) = previous_by_id.get(container_id) {
            detect_label_changes(&mut changes, previous_container, container);
            detect_attachment_changes(&mut changes, previous_container, container);
            if previous_container.policy != container.policy {
                changes.push(RuntimeChange::PolicyChanged {
                    container_id: (*container_id).to_string(),
                });
            }
        } else {
            changes.push(RuntimeChange::ContainerAdded {
                id: container.id.to_string(),
                name: container.name.clone(),
            });
        }
    }

    for (container_id, container) in &previous_by_id {
        if !current_by_id.contains_key(container_id) {
            changes.push(RuntimeChange::ContainerRemoved {
                id: container.id.to_string(),
                name: container.name.clone(),
            });
        }
    }

    changes
}

fn detect_label_changes(
    changes: &mut Vec<RuntimeChange>,
    previous: &ContainerSnapshot,
    current: &ContainerSnapshot,
) {
    let mut keys = BTreeSet::new();
    keys.extend(previous.labels.keys().cloned());
    keys.extend(current.labels.keys().cloned());

    for key in keys {
        let previous_value = previous.labels.get(&key).cloned();
        let current_value = current.labels.get(&key).cloned();
        if previous_value != current_value {
            changes.push(RuntimeChange::LabelChanged {
                container_id: current.id.to_string(),
                key,
                previous: previous_value,
                current: current_value,
            });
        }
    }
}

fn detect_attachment_changes(
    changes: &mut Vec<RuntimeChange>,
    previous: &ContainerSnapshot,
    current: &ContainerSnapshot,
) {
    let previous_keys: BTreeMap<String, &NetworkAttachment> = previous
        .attachments
        .iter()
        .map(|attachment| (attachment_key(attachment), attachment))
        .collect();
    let current_keys: BTreeMap<String, &NetworkAttachment> = current
        .attachments
        .iter()
        .map(|attachment| (attachment_key(attachment), attachment))
        .collect();

    for (key, attachment) in &current_keys {
        if !previous_keys.contains_key(key) {
            changes.push(RuntimeChange::AttachmentAdded {
                container_id: current.id.to_string(),
                network_id: attachment.network_id.to_string(),
                ip_address: attachment.ip_address,
                subnet: attachment.subnet,
            });
        }
    }

    for (key, attachment) in &previous_keys {
        if !current_keys.contains_key(key) {
            changes.push(RuntimeChange::AttachmentRemoved {
                container_id: previous.id.to_string(),
                network_id: attachment.network_id.to_string(),
                ip_address: attachment.ip_address,
                subnet: attachment.subnet,
            });
        }
    }
}

fn attachment_key(attachment: &NetworkAttachment) -> String {
    format!(
        "{}|{}|{}",
        attachment.network_id, attachment.ip_address, attachment.subnet
    )
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerContainerSummary {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Names")]
    pub names: Option<Vec<String>>,
    #[serde(rename = "Labels")]
    pub labels: Option<IndexMap<String, String>>,
    #[serde(rename = "HostConfig")]
    pub host_config: Option<DockerHostConfig>,
    #[serde(rename = "NetworkSettings")]
    pub network_settings: Option<DockerContainerSummaryNetworkSettings>,
}

impl DockerContainerSummary {
    fn name(&self) -> String {
        self.names
            .as_ref()
            .and_then(|values| values.first())
            .cloned()
            .unwrap_or_else(|| self.id.clone())
    }

    fn runtime_dns_servers(&self) -> HashSet<IpAddr> {
        self.host_config
            .as_ref()
            .and_then(|config| config.dns.as_ref())
            .into_iter()
            .flatten()
            .filter_map(|value| value.parse().ok())
            .collect()
    }

    fn network_endpoints(&self) -> Vec<(&str, DockerContainerSummaryEndpoint)> {
        self.network_settings
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerContainerSummaryNetworkSettings {
    #[serde(rename = "Networks")]
    pub networks: Option<BTreeMap<String, DockerContainerSummaryEndpoint>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerContainerSummaryEndpoint {
    #[serde(rename = "NetworkID")]
    pub network_id: Option<String>,
    #[serde(rename = "IPAddress")]
    #[serde(deserialize_with = "deserialize_optional_ipaddr")]
    pub ip_address: Option<IpAddr>,
    #[serde(rename = "Aliases")]
    pub aliases: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerContainerInspect {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Config")]
    pub config: Option<DockerContainerConfig>,
    #[serde(rename = "HostConfig")]
    pub host_config: Option<DockerHostConfig>,
    #[serde(rename = "NetworkSettings")]
    pub network_settings: Option<DockerNetworkSettings>,
}

impl DockerContainerInspect {
    fn labels(&self) -> IndexMap<String, String> {
        self.config
            .as_ref()
            .and_then(|config| config.labels.clone())
            .unwrap_or_default()
    }

    fn runtime_dns_servers(&self) -> HashSet<IpAddr> {
        self.host_config
            .as_ref()
            .and_then(|config| config.dns.as_ref())
            .into_iter()
            .flatten()
            .filter_map(|value| value.parse().ok())
            .collect()
    }

    fn network_endpoints(&self) -> Vec<(&str, DockerEndpoint)> {
        self.network_settings
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerContainerConfig {
    #[serde(rename = "Labels")]
    pub labels: Option<IndexMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerHostConfig {
    #[serde(rename = "Dns")]
    pub dns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerNetworkSettings {
    #[serde(rename = "Networks")]
    pub networks: Option<BTreeMap<String, DockerEndpoint>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerEndpoint {
    #[serde(rename = "NetworkID")]
    pub network_id: Option<String>,
    #[serde(rename = "IPAddress")]
    #[serde(deserialize_with = "deserialize_optional_ipaddr")]
    pub ip_address: Option<IpAddr>,
    #[serde(rename = "Aliases")]
    pub aliases: Option<Vec<String>>,
}

fn deserialize_optional_ipaddr<'de, D>(deserializer: D) -> Result<Option<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<IpAddr>()
        .map(Some)
        .map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerNetworkInspect {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Driver")]
    pub driver: DockerNetworkDriver,
    #[serde(rename = "IPAM")]
    pub ipam: Option<DockerIpam>,
    #[serde(rename = "Labels")]
    pub labels: Option<IndexMap<String, String>>,
}

impl DockerNetworkInspect {
    fn primary_subnet(&self) -> Result<IpNet, MonitorError> {
        let subnet = self
            .ipam
            .as_ref()
            .and_then(|ipam| ipam.config.as_ref())
            .and_then(|configs| configs.iter().find_map(|config| config.subnet.clone()))
            .ok_or_else(|| MonitorError::MissingNetworkSubnet(self.id.clone()))?;

        IpNet::from_str(&subnet).map_err(|_| MonitorError::InvalidNetworkSubnet {
            network_id: self.id.clone(),
            subnet,
        })
    }

    fn primary_gateway(&self) -> Result<Option<IpAddr>, MonitorError> {
        let gateway = self
            .ipam
            .as_ref()
            .and_then(|ipam| ipam.config.as_ref())
            .and_then(|configs| configs.iter().find_map(|config| config.gateway.clone()));

        let Some(value) = gateway else {
            return Ok(None);
        };

        let value = value
            .parse::<IpAddr>()
            .map_err(|_| MonitorError::InvalidNetworkSubnet {
                network_id: self.id.clone(),
                subnet: value,
            })?;

        Ok(Some(value))
    }

    fn is_portcullis_network_enforced(&self) -> Result<bool, MonitorError> {
        const LABEL_KEY: &str = "portcullis.network.enforce";
        let Some(value) = self
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
                network_id: self.id.clone(),
                label: LABEL_KEY.to_string(),
                value,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerNetworkDriver {
    Bridge,
    Host,
    Ipvlan,
    Macvlan,
    None,
    Overlay,
    Other(String),
}

impl DockerNetworkDriver {
    fn is_bridge(&self) -> bool {
        matches!(self, Self::Bridge)
    }
}

impl From<String> for DockerNetworkDriver {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "bridge" => Self::Bridge,
            "host" => Self::Host,
            "ipvlan" => Self::Ipvlan,
            "macvlan" => Self::Macvlan,
            "none" | "null" => Self::None,
            "overlay" => Self::Overlay,
            _ => Self::Other(value),
        }
    }
}

impl<'de> Deserialize<'de> for DockerNetworkDriver {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from(value))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerIpam {
    #[serde(rename = "Config")]
    pub config: Option<Vec<DockerIpamConfig>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerIpamConfig {
    #[serde(rename = "Subnet")]
    pub subnet: Option<String>,
    #[serde(rename = "Gateway")]
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerInfo {
    #[serde(rename = "FirewallBackend")]
    pub firewall_backend: Option<DockerFirewallInfo>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DockerFirewallInfo {
    Value(String),
    Object {
        #[serde(rename = "Driver")]
        driver: Option<String>,
        #[serde(rename = "Backend")]
        backend: Option<String>,
        #[serde(rename = "Name")]
        name: Option<String>,
    },
}

impl DockerFirewallInfo {
    fn into_backend(self) -> Option<String> {
        match self {
            Self::Value(value) => Some(value),
            Self::Object {
                driver,
                backend,
                name,
            } => driver.or(backend).or(name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

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
        fn list_containers(&self) -> Result<Vec<DockerContainerSummary>, MonitorError> {
            Ok(self.containers_list.clone())
        }

        fn list_networks(&self) -> Result<Vec<DockerNetworkInspect>, MonitorError> {
            Ok(self.networks_list.clone())
        }

        fn inspect_container(
            &self,
            container_id: &str,
        ) -> Result<DockerContainerInspect, MonitorError> {
            self.inspect_container_requests
                .borrow_mut()
                .push(container_id.to_string());
            self.containers
                .get(container_id)
                .cloned()
                .ok_or_else(|| MonitorError::ApiHttpStatus {
                    status: 404,
                    body: format!("container not found: {container_id}"),
                })
        }

        fn inspect_network(&self, network_id: &str) -> Result<DockerNetworkInspect, MonitorError> {
            self.inspect_network_requests
                .borrow_mut()
                .push(network_id.to_string());
            self.networks
                .get(network_id)
                .cloned()
                .ok_or_else(|| MonitorError::ApiHttpStatus {
                    status: 404,
                    body: format!("network not found: {network_id}"),
                })
        }

        fn firewall_backend(&self) -> Result<DockerFirewallBackend, MonitorError> {
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
        let label_map: IndexMap<String, String> = labels
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
            config: Some(DockerContainerConfig {
                labels: Some(label_map),
            }),
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
        let label_map: IndexMap<String, String> = labels
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
            labels: Some(label_map),
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

        let monitor = DockerMonitor::new(api);
        let snapshot = match monitor.snapshot() {
            Ok(value) => value,
            Err(error) => panic!("snapshot should succeed: {error}"),
        };

        assert_eq!(snapshot.containers.len(), 1);
        let container = &snapshot.containers[0];
        assert_eq!(container.id, "abc".into());
        assert_eq!(container.attachments.len(), 1);
        assert!(container.policy.is_some());
        assert!(snapshot.enforced_network_subnets.is_empty());
    }

    #[test]
    fn docker_monitor_skips_endpoints_without_ip() {
        let mut api = MockDockerApi {
            containers_list: vec![DockerContainerSummary {
                id: "abc".into(),
                names: Some(vec!["/web".to_string()]),
                labels: Some(IndexMap::new()),
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

        let monitor = DockerMonitor::new(api);
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
        let endpoint = inspect
            .network_endpoints()
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

        let monitor = DockerMonitor::new(api);
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

        let monitor = DockerMonitor::new(api);
        let snapshot = monitor.snapshot().expect("snapshot should succeed");
        assert_eq!(snapshot.enforced_network_subnets.len(), 1);
        assert_eq!(
            snapshot.enforced_network_subnets[0].to_string(),
            "172.18.0.0/16"
        );
    }

    #[test]
    fn parse_http_response_returns_body_on_success() {
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let body = parse_http_response(response).expect("response should parse");
        assert_eq!(body, "{\"ok\":true}");
    }

    #[test]
    fn parse_http_response_decodes_chunked_body() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Type: application/json\r\n",
            "\r\n",
            "7\r\n",
            "{\"a\":1}\r\n",
            "0\r\n",
            "\r\n"
        );
        let body = parse_http_response(response).expect("chunked response should parse");
        assert_eq!(body, "{\"a\":1}");
    }

    #[test]
    fn parse_http_response_rejects_non_success_status() {
        let response = "HTTP/1.1 404 Not Found\r\n\r\nnot found";
        let result = parse_http_response(response);
        assert!(matches!(
            result,
            Err(MonitorError::ApiHttpStatus { status: 404, .. })
        ));
    }

    #[test]
    fn firewall_backend_info_parsing_supports_string_and_object_shapes() {
        let info_value: DockerInfo = serde_json::from_str(r#"{"FirewallBackend":"nftables"}"#)
            .expect("docker info value shape should parse");
        let info_object: DockerInfo =
            serde_json::from_str(r#"{"FirewallBackend":{"Driver":"iptables"}}"#)
                .expect("docker info object shape should parse");

        let value_backend = info_value
            .firewall_backend
            .and_then(DockerFirewallInfo::into_backend);
        let object_backend = info_object
            .firewall_backend
            .and_then(DockerFirewallInfo::into_backend);

        assert_eq!(value_backend.as_deref(), Some("nftables"));
        assert_eq!(object_backend.as_deref(), Some("iptables"));
    }

    #[test]
    fn parse_http_response_rejects_invalid_chunk_size() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "ZZ\r\n",
            "{}\r\n",
            "0\r\n",
            "\r\n"
        );
        let result = parse_http_response(response);
        assert!(matches!(result, Err(MonitorError::InvalidHttpResponse(_))));
    }

    #[test]
    fn docker_container_event_relevance_filters_noise() {
        let relevant = DockerEvent {
            id: "abc".into(),
            action: DockerEventAction::Create,
            name: Some("web".to_string()),
            kind: DockerEventKind::Container,
            attributes: HashMap::new(),
        };
        let not_relevant = DockerEvent {
            id: "abc".into(),
            action: DockerEventAction::Resize,
            name: Some("web".to_string()),
            kind: DockerEventKind::Container,
            attributes: HashMap::new(),
        };
        let relevant_network = DockerEvent {
            id: "net0".to_string(),
            action: DockerEventAction::Disconnect,
            name: Some("pc-managed".to_string()),
            kind: DockerEventKind::Network,
            attributes: HashMap::new(),
        };

        assert!(relevant.is_relevant_for_policy_refresh());
        assert!(!not_relevant.is_relevant_for_policy_refresh());
        assert!(relevant_network.is_relevant_for_policy_refresh());
    }

    #[test]
    fn create_event_uses_event_attributes_without_container_inspect() {
        let api = MockDockerApi::default();
        let monitor = DockerMonitor::new(api);
        let state = RuntimeState::default();
        let event = DockerEvent {
            id: "abc".into(),
            action: DockerEventAction::Create,
            name: Some("web".to_string()),
            kind: DockerEventKind::Container,
            attributes: HashMap::from([
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
            .resolve_event_action(&state, &event)
            .expect("create event should resolve");
        assert!(matches!(
            action,
            Some(RuntimeStateAction::UpsertContainer { .. })
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
        let monitor = DockerMonitor::new(api);
        let mut state = RuntimeState::default();
        state.apply_action(RuntimeStateAction::UpsertNetwork {
            network_id: "net0".into(),
            subnet: "172.20.0.0/16".parse().expect("valid subnet"),
            gateway: None,
            enforced: true,
        });
        state.apply_action(RuntimeStateAction::UpsertContainer {
            snapshot: Box::new(ContainerSnapshot {
                id: "abc".into(),
                name: "web".to_string(),
                labels: [("portcullis.enable".to_string(), "true".to_string())]
                    .into_iter()
                    .collect(),
                attachments: Vec::new(),
                runtime_dns_servers: HashSet::new(),
                host_dns_servers: HashSet::new(),
                policy: parse_policy(&IndexMap::from([(
                    "portcullis.enable".to_string(),
                    "true".to_string(),
                )]))
                .expect("policy should parse"),
            }),
        });
        let event = DockerEvent {
            id: "net0".to_string(),
            action: DockerEventAction::Connect,
            name: Some("pc-managed".to_string()),
            kind: DockerEventKind::Network,
            attributes: HashMap::from([("container".to_string(), "abc".to_string())]),
        };

        let action = monitor
            .resolve_event_action(&state, &event)
            .expect("connect event should resolve");
        assert!(matches!(
            action,
            Some(RuntimeStateAction::UpsertContainer { .. })
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
        let monitor = DockerMonitor::new(api);
        let mut state = RuntimeState::default();
        state.apply_action(RuntimeStateAction::UpsertContainer {
            snapshot: Box::new(ContainerSnapshot {
                id: "abc".into(),
                name: "web".to_string(),
                labels: HashMap::new(),
                attachments: vec![NetworkAttachment {
                    network_id: "net0".into(),
                    network_name: "pc-managed".to_string(),
                    ip_address: "172.20.0.2".parse().expect("valid ip"),
                    gateway: None,
                    subnet: "172.20.0.0/16".parse().expect("valid subnet"),
                    aliases: Vec::new(),
                }],
                runtime_dns_servers: HashSet::new(),
                host_dns_servers: HashSet::new(),
                policy: None,
            }),
        });
        let event = DockerEvent {
            id: "net0".to_string(),
            action: DockerEventAction::Disconnect,
            name: Some("pc-managed".to_string()),
            kind: DockerEventKind::Network,
            attributes: HashMap::from([("container".to_string(), "abc".to_string())]),
        };

        let action = monitor
            .resolve_event_action(&state, &event)
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

        let monitor = DockerMonitor::new(api);
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

        let monitor = DockerMonitor::new(api);
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

        let monitor = DockerMonitor::new(api);
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

        let monitor = DockerMonitor::new(api);
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

        let monitor = DockerMonitor::new(api);
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

        let monitor = DockerMonitor::new(api);
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
        let subnet = match network.primary_subnet() {
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
        let label_map: IndexMap<String, String> = labels
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
            containers: vec![ContainerSnapshot {
                id: container_id.into(),
                name: name.to_string(),
                labels: label_map
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
                attachments: vec![NetworkAttachment {
                    network_id: network_id.into(),
                    network_name: network_name.to_string(),
                    ip_address: parsed_ip,
                    gateway: None,
                    subnet: parsed_subnet,
                    aliases: vec![name.to_string()],
                }],
                runtime_dns_servers: HashSet::new(),
                host_dns_servers: HashSet::new(),
                policy: match parse_policy(&label_map) {
                    Ok(value) => value,
                    Err(error) => panic!("failed to parse policy fixture: {error}"),
                },
            }],
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
        assert!(changes.iter().any(|change| matches!(
            change,
            RuntimeChange::LabelChanged { key, .. } if key == "portcullis.egress.0"
        )));
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
