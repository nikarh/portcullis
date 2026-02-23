use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::process::Command;
use std::str::FromStr;

use ipnet::IpNet;
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, info, trace};

use crate::labels::{LabelParseError, parse_policy};
use crate::model::{ContainerSnapshot, NetworkAttachment, RuntimeSnapshot};

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("failed to run command `{program}`: {message}")]
    CommandExecution { program: String, message: String },
    #[error("command `{program}` failed with code {code}: {stderr}")]
    CommandFailure {
        program: String,
        code: i32,
        stderr: String,
    },
    #[error("invalid UTF-8 from command `{program}`")]
    InvalidUtf8 { program: String },
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

pub trait CommandRunner {
    fn run_capture(&self, program: &str, args: &[&str]) -> Result<String, MonitorError>;
}

pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run_capture(&self, program: &str, args: &[&str]) -> Result<String, MonitorError> {
        debug!(%program, ?args, "running command");
        let output = Command::new(program).args(args).output().map_err(|error| {
            MonitorError::CommandExecution {
                program: program.to_string(),
                message: error.to_string(),
            }
        })?;

        if !output.status.success() {
            debug!(
                %program,
                code = output.status.code().unwrap_or(-1),
                stderr = %String::from_utf8_lossy(&output.stderr),
                "command failed"
            );
            return Err(MonitorError::CommandFailure {
                program: program.to_string(),
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }

        let stdout = String::from_utf8(output.stdout).map_err(|_| MonitorError::InvalidUtf8 {
            program: program.to_string(),
        })?;
        trace!(%program, stdout = %stdout, "command output");
        Ok(stdout)
    }
}

pub struct CommandDockerApi<R> {
    runner: R,
}

impl<R> CommandDockerApi<R>
where
    R: CommandRunner,
{
    pub const fn new(runner: R) -> Self {
        Self { runner }
    }

    fn run_json<T>(&self, args: &[&str]) -> Result<Vec<T>, MonitorError>
    where
        T: for<'de> Deserialize<'de>,
    {
        debug!(?args, "running docker json command");
        let stdout = self.runner.run_capture("docker", args)?;
        trace!(?args, raw_json = %stdout, "docker json output");
        serde_json::from_str::<Vec<T>>(&stdout)
            .map_err(|error| MonitorError::InvalidJson(error.to_string()))
    }
}

impl<R> DockerApi for CommandDockerApi<R>
where
    R: CommandRunner,
{
    fn list_container_ids(&self) -> Result<Vec<String>, MonitorError> {
        debug!("listing running docker containers");
        let stdout = self.runner.run_capture("docker", &["ps", "-q"])?;
        let ids = stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        trace!(?ids, "parsed docker container ids");
        Ok(ids)
    }

    fn inspect_container(
        &self,
        container_id: &str,
    ) -> Result<DockerContainerInspect, MonitorError> {
        let objects = self.run_json::<DockerContainerInspect>(&["inspect", container_id])?;
        objects
            .into_iter()
            .next()
            .ok_or_else(|| MonitorError::MissingInspectObject(container_id.to_string()))
    }

    fn inspect_network(&self, network_id: &str) -> Result<DockerNetworkInspect, MonitorError> {
        let objects = self.run_json::<DockerNetworkInspect>(&["network", "inspect", network_id])?;
        objects
            .into_iter()
            .next()
            .ok_or_else(|| MonitorError::MissingInspectObject(network_id.to_string()))
    }

    fn firewall_backend(&self) -> Result<DockerFirewallBackend, MonitorError> {
        debug!("detecting docker firewall backend");
        let stdout = self
            .runner
            .run_capture("docker", &["info", "--format", "{{json .}}"])?;
        trace!(raw_json = %stdout, "docker info output");
        let info: DockerInfo = serde_json::from_str(&stdout)
            .map_err(|error| MonitorError::InvalidJson(error.to_string()))?;
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
    use std::collections::VecDeque;

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

    struct QueueCommandRunner {
        outputs: std::sync::Mutex<VecDeque<Result<String, MonitorError>>>,
    }

    impl QueueCommandRunner {
        fn new(outputs: Vec<Result<String, MonitorError>>) -> Self {
            Self {
                outputs: std::sync::Mutex::new(VecDeque::from(outputs)),
            }
        }
    }

    impl CommandRunner for QueueCommandRunner {
        fn run_capture(&self, _program: &str, _args: &[&str]) -> Result<String, MonitorError> {
            let mut guard = self
                .outputs
                .lock()
                .map_err(|_| MonitorError::CommandExecution {
                    program: "docker".to_string(),
                    message: "failed to lock mock queue".to_string(),
                })?;
            guard
                .pop_front()
                .ok_or_else(|| MonitorError::CommandExecution {
                    program: "docker".to_string(),
                    message: "mock queue exhausted".to_string(),
                })?
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
    fn command_docker_api_lists_ids_from_ps_output() {
        let api =
            CommandDockerApi::new(QueueCommandRunner::new(vec![
                Ok("abc\ndef\n\n".to_string()),
            ]));

        let ids = match api.list_container_ids() {
            Ok(value) => value,
            Err(error) => panic!("list_container_ids should succeed: {error}"),
        };

        assert_eq!(ids, vec!["abc".to_string(), "def".to_string()]);
    }

    #[test]
    fn command_docker_api_parses_inspect_json() {
        let container_json = r#"[
            {
              "Id": "abc",
              "Name": "/web",
              "Config": {
                "Labels": {
                    "portcullis.enable": "true",
                    "portcullis.egress.0": "ip:1.1.1.1/32,tcp:443"
                }
              },
              "NetworkSettings": {
                "Networks": {
                  "bridge": {
                    "NetworkID": "net0",
                    "IPAddress": "172.18.0.2"
                  }
                }
              }
            }
        ]"#;

        let api =
            CommandDockerApi::new(QueueCommandRunner::new(vec![
                Ok(container_json.to_string()),
            ]));

        let inspect = match api.inspect_container("abc") {
            Ok(value) => value,
            Err(error) => panic!("inspect_container should succeed: {error}"),
        };

        assert_eq!(inspect.id, "abc");
        assert_eq!(inspect.name, "/web");
    }

    #[test]
    fn command_docker_api_errors_for_invalid_json() {
        let api = CommandDockerApi::new(QueueCommandRunner::new(vec![Ok("nope".to_string())]));

        let result = api.inspect_container("abc");
        assert!(matches!(result, Err(MonitorError::InvalidJson(_))));
    }

    #[test]
    fn command_docker_api_detects_nftables_backend() {
        let api = CommandDockerApi::new(QueueCommandRunner::new(vec![Ok(
            r#"{"FirewallBackend":"nftables"}"#.to_string(),
        )]));
        let result = api.firewall_backend();
        assert_eq!(result.ok(), Some(DockerFirewallBackend::Nftables));
    }

    #[test]
    fn command_docker_api_defaults_backend_to_iptables() {
        let api = CommandDockerApi::new(QueueCommandRunner::new(vec![Ok("{}".to_string())]));
        let result = api.firewall_backend();
        assert_eq!(result.ok(), Some(DockerFirewallBackend::Iptables));
    }

    #[test]
    fn command_docker_api_detects_object_backend_shape() {
        let api = CommandDockerApi::new(QueueCommandRunner::new(vec![Ok(
            r#"{"FirewallBackend":{"Driver":"nftables"}}"#.to_string(),
        )]));
        let result = api.firewall_backend();
        assert_eq!(result.ok(), Some(DockerFirewallBackend::Nftables));
    }

    #[test]
    fn command_docker_api_rejects_unknown_backend() {
        let api = CommandDockerApi::new(QueueCommandRunner::new(vec![Ok(
            r#"{"FirewallBackend":"unknown"}"#.to_string(),
        )]));
        let result = api.firewall_backend();
        assert!(matches!(
            result,
            Err(MonitorError::UnsupportedFirewallBackend(value)) if value == "unknown"
        ));
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
