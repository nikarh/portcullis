use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::str::FromStr;

use ipnet::IpNet;
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, info, trace};

use crate::labels::{LabelParseError, parse_policy};
use crate::model::{ContainerSnapshot, NetworkAttachment, RuntimeSnapshot};

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
    #[error("docker inspect returned no object for id: {0}")]
    MissingInspectObject(String),
    #[error("missing network id in container {container_id} attachment {network_name}")]
    MissingNetworkId {
        container_id: String,
        network_name: String,
    },
    #[error("missing subnet for network id: {0}")]
    MissingNetworkSubnet(String),
    #[error("invalid subnet in network id {network_id}: {subnet}")]
    InvalidNetworkSubnet { network_id: String, subnet: String },
    #[error(transparent)]
    LabelParse(#[from] LabelParseError),
}

pub trait DockerApi {
    fn list_container_ids(&self) -> Result<Vec<String>, MonitorError>;
    fn inspect_container(&self, container_id: &str)
    -> Result<DockerContainerInspect, MonitorError>;
    fn inspect_network(&self, network_id: &str) -> Result<DockerNetworkInspect, MonitorError>;
    fn firewall_backend(&self) -> Result<DockerFirewallBackend, MonitorError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerFirewallBackend {
    Nftables,
    Iptables,
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

    pub fn snapshot(&self) -> Result<RuntimeSnapshot, MonitorError> {
        debug!("collecting docker runtime snapshot");
        let container_ids = self.api.list_container_ids()?;
        trace!(?container_ids, "listed container ids");
        let mut network_subnets = HashMap::new();
        let mut containers = Vec::with_capacity(container_ids.len());

        for container_id in container_ids {
            trace!(%container_id, "inspecting container");
            let inspect = self.api.inspect_container(&container_id)?;
            let labels = inspect.labels();
            let policy = parse_policy(&labels)?;

            let mut attachments = Vec::new();
            for (network_name, endpoint) in inspect.network_endpoints() {
                let Some(address) = endpoint.ip_address else {
                    continue;
                };

                let network_id =
                    endpoint
                        .network_id
                        .ok_or_else(|| MonitorError::MissingNetworkId {
                            container_id: inspect.id.clone(),
                            network_name: network_name.to_string(),
                        })?;

                let subnet = if let Some(cached) = network_subnets.get(&network_id) {
                    *cached
                } else {
                    trace!(%network_id, "inspecting network for subnet");
                    let network = self.api.inspect_network(&network_id)?;
                    let subnet = network.primary_subnet()?;
                    network_subnets.insert(network_id.clone(), subnet);
                    subnet
                };

                attachments.push(NetworkAttachment {
                    network_id,
                    network_name: network_name.to_string(),
                    ip_address: address,
                    subnet,
                    aliases: endpoint.aliases.unwrap_or_default(),
                });
            }

            containers.push(ContainerSnapshot {
                id: inspect.id,
                name: inspect.name,
                labels,
                attachments,
                policy,
            });
        }

        let snapshot = RuntimeSnapshot { containers };
        info!(
            container_count = snapshot.containers.len(),
            "docker runtime snapshot collected"
        );
        trace!(?snapshot, "full docker runtime snapshot");
        Ok(snapshot)
    }

    pub fn firewall_backend(&self) -> Result<DockerFirewallBackend, MonitorError> {
        self.api.firewall_backend()
    }
}

pub struct SocketDockerApi {
    socket_path: String,
}

impl SocketDockerApi {
    #[must_use]
    pub fn new(socket: String) -> Self {
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
        trace!(path, raw_json = %body, "docker api json response");
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
    fn list_container_ids(&self) -> Result<Vec<String>, MonitorError> {
        #[derive(Debug, Deserialize)]
        struct ContainerSummary {
            #[serde(rename = "Id")]
            id: String,
        }

        let summaries: Vec<ContainerSummary> = self.request_json("/containers/json")?;
        let ids = summaries.into_iter().map(|summary| summary.id).collect();
        trace!(?ids, "parsed docker container ids");
        Ok(ids)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockerContainerEvent {
    pub id: String,
    pub action: String,
    pub name: Option<String>,
}

impl DockerContainerEvent {
    #[must_use]
    pub fn is_relevant_for_policy_refresh(&self) -> bool {
        matches!(
            self.action.as_str(),
            "create"
                | "start"
                | "restart"
                | "stop"
                | "die"
                | "kill"
                | "destroy"
                | "rename"
                | "update"
                | "connect"
                | "disconnect"
                | "pause"
                | "unpause"
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeChange {
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
pub struct RuntimeChangeTracker {
    previous: Option<RuntimeSnapshot>,
}

impl RuntimeChangeTracker {
    #[must_use]
    pub const fn new() -> Self {
        Self { previous: None }
    }

    pub fn detect_and_log(&mut self, current: &RuntimeSnapshot) -> Vec<RuntimeChange> {
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
pub fn detect_runtime_changes(
    previous: Option<&RuntimeSnapshot>,
    current: &RuntimeSnapshot,
) -> Vec<RuntimeChange> {
    let mut changes = Vec::new();

    let Some(previous_snapshot) = previous else {
        for container in &current.containers {
            changes.push(RuntimeChange::ContainerAdded {
                id: container.id.clone(),
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
                id: container.id.clone(),
                name: container.name.clone(),
            });
        }
    }

    for (container_id, container) in &previous_by_id {
        if !current_by_id.contains_key(container_id) {
            changes.push(RuntimeChange::ContainerRemoved {
                id: container.id.clone(),
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
                container_id: current.id.clone(),
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
                container_id: current.id.clone(),
                network_id: attachment.network_id.clone(),
                ip_address: attachment.ip_address,
                subnet: attachment.subnet,
            });
        }
    }

    for (key, attachment) in &previous_keys {
        if !current_keys.contains_key(key) {
            changes.push(RuntimeChange::AttachmentRemoved {
                container_id: previous.id.clone(),
                network_id: attachment.network_id.clone(),
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
pub struct DockerContainerInspect {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Config")]
    pub config: Option<DockerContainerConfig>,
    #[serde(rename = "NetworkSettings")]
    pub network_settings: Option<DockerNetworkSettings>,
}

impl DockerContainerInspect {
    fn labels(&self) -> BTreeMap<String, String> {
        self.config
            .as_ref()
            .and_then(|config| config.labels.clone())
            .unwrap_or_default()
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
    pub labels: Option<BTreeMap<String, String>>,
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
    pub ip_address: Option<IpAddr>,
    #[serde(rename = "Aliases")]
    pub aliases: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerNetworkInspect {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "IPAM")]
    pub ipam: Option<DockerIpam>,
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

    #[derive(Default)]
    struct MockDockerApi {
        ids: Vec<String>,
        containers: HashMap<String, DockerContainerInspect>,
        networks: HashMap<String, DockerNetworkInspect>,
    }

    impl DockerApi for MockDockerApi {
        fn list_container_ids(&self) -> Result<Vec<String>, MonitorError> {
            Ok(self.ids.clone())
        }

        fn inspect_container(
            &self,
            container_id: &str,
        ) -> Result<DockerContainerInspect, MonitorError> {
            self.containers
                .get(container_id)
                .cloned()
                .ok_or_else(|| MonitorError::MissingInspectObject(container_id.to_string()))
        }

        fn inspect_network(&self, network_id: &str) -> Result<DockerNetworkInspect, MonitorError> {
            self.networks
                .get(network_id)
                .cloned()
                .ok_or_else(|| MonitorError::MissingInspectObject(network_id.to_string()))
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
        let mut label_map = BTreeMap::new();
        for (key, value) in labels {
            label_map.insert((*key).to_string(), (*value).to_string());
        }

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
            network_settings: Some(DockerNetworkSettings {
                networks: Some(networks),
            }),
        }
    }

    fn network_inspect(id: &str, name: &str, subnet: &str) -> DockerNetworkInspect {
        DockerNetworkInspect {
            id: id.to_string(),
            name: name.to_string(),
            ipam: Some(DockerIpam {
                config: Some(vec![DockerIpamConfig {
                    subnet: Some(subnet.to_string()),
                }]),
            }),
        }
    }

    #[test]
    fn docker_monitor_builds_snapshot_with_policy_and_attachments() {
        let mut api = MockDockerApi {
            ids: vec!["abc".to_string()],
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

        let monitor = DockerMonitor::new(api);
        let snapshot = match monitor.snapshot() {
            Ok(value) => value,
            Err(error) => panic!("snapshot should succeed: {error}"),
        };

        assert_eq!(snapshot.containers.len(), 1);
        let container = &snapshot.containers[0];
        assert_eq!(container.id, "abc");
        assert_eq!(container.attachments.len(), 1);
        assert!(container.policy.is_some());
    }

    #[test]
    fn docker_monitor_skips_endpoints_without_ip() {
        let mut networks = BTreeMap::new();
        networks.insert(
            "bridge".to_string(),
            DockerEndpoint {
                network_id: Some("net0".to_string()),
                ip_address: None,
                aliases: None,
            },
        );

        let inspect = DockerContainerInspect {
            id: "abc".to_string(),
            name: "web".to_string(),
            config: Some(DockerContainerConfig {
                labels: Some(BTreeMap::new()),
            }),
            network_settings: Some(DockerNetworkSettings {
                networks: Some(networks),
            }),
        };

        let mut api = MockDockerApi {
            ids: vec!["abc".to_string()],
            ..MockDockerApi::default()
        };
        api.containers.insert("abc".to_string(), inspect);

        let monitor = DockerMonitor::new(api);
        let snapshot = match monitor.snapshot() {
            Ok(value) => value,
            Err(error) => panic!("snapshot should succeed: {error}"),
        };

        assert_eq!(snapshot.containers[0].attachments.len(), 0);
    }

    #[test]
    fn docker_monitor_fails_for_invalid_labels() {
        let mut api = MockDockerApi {
            ids: vec!["abc".to_string()],
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

        let monitor = DockerMonitor::new(api);
        let result = monitor.snapshot();
        assert!(result.is_err());
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
        let relevant = DockerContainerEvent {
            id: "abc".to_string(),
            action: "start".to_string(),
            name: Some("web".to_string()),
        };
        let not_relevant = DockerContainerEvent {
            id: "abc".to_string(),
            action: "health_status: healthy".to_string(),
            name: Some("web".to_string()),
        };

        assert!(relevant.is_relevant_for_policy_refresh());
        assert!(!not_relevant.is_relevant_for_policy_refresh());
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
        let mut label_map = BTreeMap::new();
        for (key, value) in labels {
            label_map.insert((*key).to_string(), (*value).to_string());
        }

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
                id: container_id.to_string(),
                name: name.to_string(),
                labels: label_map.clone(),
                attachments: vec![NetworkAttachment {
                    network_id: network_id.to_string(),
                    network_name: network_name.to_string(),
                    ip_address: parsed_ip,
                    subnet: parsed_subnet,
                    aliases: vec![name.to_string()],
                }],
                policy: match parse_policy(&label_map) {
                    Ok(value) => value,
                    Err(error) => panic!("failed to parse policy fixture: {error}"),
                },
            }],
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
