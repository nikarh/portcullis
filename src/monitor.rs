use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use ipnet::IpNet;
use thiserror::Error;
use tracing::{debug, error, trace, warn};

use crate::docker::raw::{
    DockerContainerInspect, DockerContainerSummary, DockerContainerSummaryEndpoint, DockerEndpoint,
    DockerHostConfig, DockerNetworkInspect,
};
use crate::docker::{DockerApi, DockerError, DockerEvent, DockerEventAction, DockerEventKind};
use crate::events::{Warning, WarningKind};
use crate::labels::{POLICY_FILE_LABEL, is_policy_label, parse_acknowledged, parse_policy};
use crate::model::{
    Container, ContainerId, ContainerPolicy, MacAddress, Network, NetworkAttachment, NetworkId,
    RuntimeState, RuntimeStateAction,
};
use crate::policy_file;

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error(transparent)]
    Docker(#[from] DockerError),
    #[error("missing network id in container {container_id} attachment {network_name}")]
    MissingNetworkId {
        container_id: String,
        network_name: String,
    },
    #[error("no IPv4 subnet for network id: {0}")]
    MissingNetworkSubnet(String),
}

/// Policy from a container's labels, and from the policy file in `policy_dir` its
/// `portcullis.policy-file` label names. Invalid labels are logged, reported and skipped.
/// A policy file that can't be used denies the container everything.
///
/// Values from the policy file are never logged or reported.
pub fn policy_from_labels(
    container: &str,
    labels: &IndexMap<String, String>,
    policy_dir: &Path,
    warnings: &mut Vec<Warning>,
) -> ContainerPolicy {
    let container = container.trim_start_matches('/');
    let invalid = |warnings: &mut Vec<Warning>, message: String| {
        error!(container, "{message}");
        warnings.push(Warning {
            kind: WarningKind::InvalidLabel,
            container: Some(container.to_string()),
            message,
        });
    };
    let Some(name) = labels.get(POLICY_FILE_LABEL) else {
        let (policy, errors) = parse_policy(labels);
        for error in errors {
            invalid(warnings, format!("ignoring invalid label: {error}"));
        }
        return policy;
    };
    let entries = match policy_file::load(policy_dir, name) {
        Ok(entries) => entries,
        Err(error) => {
            error!(container, %error, "denying everything to a container whose policy file can't be used");
            warnings.push(Warning {
                kind: WarningKind::PolicyFile,
                container: Some(container.to_string()),
                message: format!("denying everything: can't use its policy file: {error}"),
            });
            let mut policy = ContainerPolicy::deny_all();
            policy.acknowledged = parse_acknowledged(labels).0;
            return policy;
        }
    };

    let mut merged = labels.clone();
    let mut from_file = HashSet::new();
    for entry in entries {
        let line = entry.line;
        if !is_policy_label(&entry.key) {
            // Not a label to repeat: it may be a value written in the wrong place.
            invalid(
                warnings,
                format!("ignoring line {line} of policy file {name}: not a container policy label"),
            );
            continue;
        }
        if !from_file.insert(entry.key.clone()) {
            invalid(
                warnings,
                format!(
                    "{} is set more than once in policy file {name}: line {line} is used",
                    entry.key
                ),
            );
        } else if merged.contains_key(&entry.key) {
            invalid(
                warnings,
                format!(
                    "{} is set both as a label and in policy file {name}: the file's value is used",
                    entry.key
                ),
            );
        }
        merged.insert(entry.key, entry.value);
    }

    let (policy, errors) = parse_policy(&merged);
    for error in errors {
        let label = error.label();
        if from_file.contains(label) {
            invalid(
                warnings,
                format!("ignoring invalid {label} in policy file {name}"),
            );
        } else {
            invalid(warnings, format!("ignoring invalid label: {error}"));
        }
    }
    policy
}

fn network_warning(warnings: &mut Vec<Warning>, network: &DockerNetworkInspect, message: &str) {
    error!(network = %network.name, "{message}");
    warnings.push(Warning {
        kind: WarningKind::InvalidNetwork,
        container: None,
        message: format!("network {}: {message}", network.name),
    });
}

/// The managed network for `network`, or `None` when Portcullis doesn't manage it. Invalid
/// configuration is logged rather than failing the caller.
fn network_from_inspect(
    network: &DockerNetworkInspect,
    monitored: &[String],
    warnings: &mut Vec<Warning>,
) -> Option<Network> {
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
    let Some(monitor) = portcullis_mode(network, monitored, warnings) else {
        debug!(
            network_id = %network.id,
            network_name = %network.name,
            "ignoring non-portcullis network"
        );
        return None;
    };

    let (subnet, gateway) = match network_primary_config(network, warnings) {
        Ok(value) => value,
        Err(error) => {
            network_warning(
                warnings,
                network,
                &format!("can't enforce the network without a valid subnet: {error}"),
            );
            return None;
        }
    };

    let labels = network.labels.clone().unwrap_or_default();
    let (acknowledged, errors) = parse_acknowledged(&labels);
    for error in errors {
        network_warning(
            warnings,
            network,
            &format!("ignoring invalid label: {error}"),
        );
    }
    if network.enable_ipv6 && !acknowledged.contains(&WarningKind::Ipv6Network) {
        warn!(network = %network.name, "IPv6 is enabled on an enforced network");
        warnings.push(Warning {
            kind: WarningKind::Ipv6Network,
            container: None,
            message: format!(
                "network {}: IPv6 is enabled, but Portcullis only manages IPv4: all IPv6 traffic of its containers is denied",
                network.name
            ),
        });
    }

    Some(Network {
        id: network.id.clone().into(),
        name: network.name.clone(),
        subnet,
        gateway,
        ipv6: network.enable_ipv6,
        bridge: bridge_name(network),
        monitor,
    })
}

/// The host interface of a bridge network: set with the `com.docker.network.bridge.name`
/// option, or `br-` followed by the first 12 characters of the network id.
fn bridge_name(network: &DockerNetworkInspect) -> String {
    network
        .options
        .as_ref()
        .and_then(|options| options.get("com.docker.network.bridge.name"))
        .filter(|name| !name.is_empty())
        .cloned()
        .unwrap_or_else(|| format!("br-{}", network.id.get(..12).unwrap_or(&network.id)))
}

fn parse_mac(value: Option<&str>) -> Option<MacAddress> {
    value.filter(|value| !value.is_empty())?.parse().ok()
}

/// What Docker's API says about the container or network of an event, as far as handling
/// the event needs it.
///
/// It is fetched by the thread reading Docker's events (see [`fetch`]), not the main loop:
/// Docker answers about a container only once it has finished starting it, which takes
/// seconds for a container on many networks on a slow host, and its `connect` events come
/// before that. Meanwhile the main loop has to find containers behind bridge ports, before
/// the packets it holds for them run out of time (see `discovery`).
#[derive(Debug)]
pub enum Fetched {
    Nothing,
    Container(Result<DockerContainerInspect, DockerError>),
    Network(Result<DockerNetworkInspect, DockerError>),
}

/// Ask Docker what handling `event` needs to know. Containers connecting to networks that
/// aren't `managed` don't matter.
pub fn fetch(
    api: &mut impl DockerApi,
    event: &DockerEvent,
    managed: impl Fn(&str) -> bool,
) -> Fetched {
    match (&event.kind, &event.action) {
        // For the checks of a container that started.
        (DockerEventKind::Container, DockerEventAction::Start) => {
            Fetched::Container(api.inspect_container(&event.id))
        }
        (DockerEventKind::Network, DockerEventAction::Create | DockerEventAction::Update) => {
            Fetched::Network(api.inspect_network(&event.id))
        }
        (DockerEventKind::Network, DockerEventAction::Connect) if managed(&event.id) => event
            .attributes
            .get("container")
            .map_or(Fetched::Nothing, |container| {
                Fetched::Container(api.inspect_container(container))
            }),
        _ => Fetched::Nothing,
    }
}

pub struct DockerMonitor<A> {
    api: A,
    /// Networks managed in monitor mode without a label, see `Config::monitor_networks`.
    monitored: Vec<String>,
    /// Where the files of `portcullis.policy-file` labels are.
    policy_dir: PathBuf,
    /// Configuration problems found since the last `take_warnings`.
    warnings: Vec<Warning>,
}

impl<A> DockerMonitor<A>
where
    A: DockerApi,
{
    pub fn new(api: A) -> Self {
        Self {
            api,
            monitored: Vec::new(),
            policy_dir: PathBuf::from(policy_file::DEFAULT_POLICY_DIR),
            warnings: Vec::new(),
        }
    }

    /// Read the files of `portcullis.policy-file` labels from `directory`.
    #[must_use]
    pub fn with_policy_dir(mut self, directory: PathBuf) -> Self {
        self.policy_dir = directory;
        self
    }

    /// Manage the networks named in `monitored` (`*` for all) in monitor mode, unless
    /// their `portcullis.enable` label says otherwise.
    #[must_use]
    pub fn with_monitored_networks(mut self, monitored: Vec<String>) -> Self {
        self.monitored = monitored;
        self
    }

    /// Configuration problems found since the last call.
    pub fn take_warnings(&mut self) -> Vec<Warning> {
        std::mem::take(&mut self.warnings)
    }

    /// Look for configurations that get around the rules in container `id`, see `checks`.
    pub fn check_container(&mut self, state: &RuntimeState, id: &str) {
        let inspect = self.api.inspect_container(id);
        self.check_inspected(state, id, inspect);
    }

    /// The same, with what Docker said about the container.
    pub fn check_inspected(
        &mut self,
        state: &RuntimeState,
        id: &str,
        inspect: Result<DockerContainerInspect, DockerError>,
    ) {
        match inspect {
            Ok(inspect) => self
                .warnings
                .extend(crate::checks::container_warnings(&inspect, state)),
            Err(error) => debug!(container = %id, %error, "can't inspect container for checks"),
        }
    }

    /// The same for every container.
    pub fn check_containers(&mut self, state: &RuntimeState) {
        let ids: Vec<String> = state.containers().keys().map(ToString::to_string).collect();
        for id in ids {
            self.check_container(state, &id);
        }
    }

    pub fn initialize(&mut self) -> Result<RuntimeState, MonitorError> {
        debug!("collecting docker runtime state");

        let networks = self.api.list_networks()?;
        let containers = self.api.list_containers()?;

        let mut networks_by_id = HashMap::new();
        for network in networks {
            if let Some(data) = network_from_inspect(&network, &self.monitored, &mut self.warnings)
            {
                networks_by_id.insert(data.id.clone(), data);
            }
        }
        let mut containers_by_id = BTreeMap::new();
        for summary in containers {
            let mut container = Self::build_container_from_summary(
                &networks_by_id,
                summary,
                &self.policy_dir,
                &mut self.warnings,
            );
            // The container list doesn't include DNS settings or network aliases (such as
            // Compose's service names, which ICC rules name containers by); managed
            // containers need them.
            if !container.attachments.is_empty() {
                match self.api.inspect_container(&container.id) {
                    Ok(inspect) => {
                        container.runtime_dns_servers =
                            runtime_dns_servers(inspect.host_config.as_ref());
                        let settings = inspect.network_settings;
                        for (_, endpoint) in settings
                            .iter()
                            .filter_map(|settings| settings.networks.as_ref())
                            .flatten()
                        {
                            let Some(attachment) =
                                container.attachments.iter_mut().find(|attachment| {
                                    endpoint.network_id.as_deref()
                                        == Some(attachment.network_id.as_str())
                                })
                            else {
                                continue;
                            };
                            if attachment.aliases.is_empty()
                                && let Some(aliases) = &endpoint.aliases
                            {
                                attachment.aliases.clone_from(aliases);
                            }
                        }
                        container.sandbox = settings
                            .and_then(|settings| settings.sandbox_key)
                            .filter(|key| !key.is_empty());
                    }
                    Err(error) => {
                        debug!(container = %container.name, %error, "failed to inspect container");
                    }
                }
            }
            containers_by_id.insert(container.id.clone(), container);
        }
        let mut state = RuntimeState::default();
        state.apply_action(RuntimeStateAction::Initialize {
            containers: containers_by_id,
            networks: networks_by_id,
        });
        Ok(state)
    }

    #[cfg(test)]
    pub fn resolve_event_action(
        &mut self,
        state: &RuntimeState,
        event: DockerEvent,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        let fetched = fetch(&mut self.api, &event, |network| {
            state.networks().contains_key(network)
        });
        self.resolve_fetched_event_action(state, event, fetched)
    }

    /// `resolve_event_action`, with what Docker said about the event's container or
    /// network already fetched.
    pub fn resolve_fetched_event_action(
        &mut self,
        state: &RuntimeState,
        event: DockerEvent,
        fetched: Fetched,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        match event.kind {
            DockerEventKind::Container => match event.action {
                DockerEventAction::Destroy => Ok(Some(RuntimeStateAction::RemoveContainer {
                    container_id: event.id.into(),
                })),
                // Already found behind a bridge port before Docker's events caught up: the
                // create event has none of the networks it is on by now, and taking them
                // away would take its address, its rules and the connections it made
                // under them, until the events of its start.
                DockerEventAction::Create if state.containers().contains_key(event.id.as_str()) => {
                    Ok(None)
                }
                DockerEventAction::Create => Ok(Self::create_container_action(
                    event,
                    &self.policy_dir,
                    &mut self.warnings,
                )),
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
                    let network = match fetched {
                        Fetched::Network(network) => network,
                        _ => self.api.inspect_network(&event.id),
                    };
                    self.network_action(&event.id, network)
                }
                DockerEventAction::Connect => {
                    self.resolve_network_connect_action(state, event, fetched)
                }
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
        policy_dir: &Path,
        warnings: &mut Vec<Warning>,
    ) -> Result<Box<Container>, MonitorError> {
        let policy =
            policy_from_labels(&inspect.name, &inspect.config.labels, policy_dir, warnings);
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
                mac_address: parse_mac(endpoint.mac_address.as_deref()),
                aliases: endpoint.aliases.unwrap_or_default(),
            });
        }

        let sandbox = inspect
            .network_settings
            .as_ref()
            .and_then(|settings| settings.sandbox_key.clone())
            .filter(|key| !key.is_empty());
        Ok(Box::new(Container {
            id: inspect.id.into(),
            name: inspect.name.trim_start_matches('/').to_string().into(),
            attachments,
            runtime_dns_servers,
            policy,
            sandbox,
        }))
    }

    fn container_action(
        &mut self,
        state: &RuntimeState,
        inspect: Result<DockerContainerInspect, DockerError>,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        match inspect {
            Ok(inspect) => {
                let container = Self::build_container_from_inspect(
                    state,
                    inspect,
                    &self.policy_dir,
                    &mut self.warnings,
                )?;
                Ok(Some(RuntimeStateAction::CreateContainer { container }))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn create_container_action(
        event: DockerEvent,
        policy_dir: &Path,
        warnings: &mut Vec<Warning>,
    ) -> Option<RuntimeStateAction> {
        let policy = policy_from_labels(
            event.name.as_deref().unwrap_or(&event.id),
            &event.attributes,
            policy_dir,
            warnings,
        );

        let name = event.name?;

        Some(RuntimeStateAction::CreateContainer {
            container: Box::new(Container {
                id: event.id.into(),
                name: name.trim_start_matches('/').to_string().into(),
                attachments: Vec::new(),
                runtime_dns_servers: HashSet::new(),
                policy,
                sandbox: None,
            }),
        })
    }

    fn resolve_network_connect_action(
        &mut self,
        state: &RuntimeState,
        event: DockerEvent,
        fetched: Fetched,
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
        debug!(%container_id, "resolving container runtime state action");
        let inspect = match fetched {
            Fetched::Container(inspect) => inspect,
            // The network was managed only from an event the fetch came before.
            _ => self.api.inspect_container(container_id),
        };
        self.container_action(state, inspect)
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

    fn network_action(
        &mut self,
        network_id: &str,
        network: Result<DockerNetworkInspect, DockerError>,
    ) -> Result<Option<RuntimeStateAction>, MonitorError> {
        debug!(%network_id, "resolving network runtime state action");
        match network {
            Ok(network) => {
                if let Some(network) =
                    network_from_inspect(&network, &self.monitored, &mut self.warnings)
                {
                    Ok(Some(RuntimeStateAction::UpsertNetwork { network }))
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
        policy_dir: &Path,
        warnings: &mut Vec<Warning>,
    ) -> Container {
        let policy = policy_from_labels(
            &container_summary_name(&summary),
            &summary.labels,
            policy_dir,
            warnings,
        );
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
            attachments.push(NetworkAttachment {
                network_id,
                ip_address,
                mac_address: parse_mac(endpoint.mac_address.as_deref()),
                aliases: endpoint.aliases.unwrap_or_default(),
            });
        }

        let name = container_summary_name(&summary).into();
        Container {
            id: summary.id.into(),
            name,
            attachments,
            runtime_dns_servers,
            policy,
            sandbox: None,
        }
    }
}

fn is_not_found(error: &DockerError) -> bool {
    matches!(error, DockerError::ApiHttpStatus { status: 404, .. })
}

/// The network's IPv4 subnet and gateway. A bridge network has at most one IPv4 subnet; on
/// dual-stack networks the other configuration is IPv6, which Portcullis doesn't manage.
fn network_primary_config(
    network: &DockerNetworkInspect,
    warnings: &mut Vec<Warning>,
) -> Result<(IpNet, Option<IpAddr>), MonitorError> {
    let configs = network
        .ipam
        .as_ref()
        .and_then(|ipam| ipam.config.as_deref())
        .unwrap_or_default();

    let (subnet, config) = configs
        .iter()
        .find_map(|config| match config.subnet.as_deref()?.parse::<IpNet>() {
            Ok(subnet @ IpNet::V4(_)) => Some((subnet, config)),
            Ok(IpNet::V6(_)) => None,
            Err(_) => {
                network_warning(
                    warnings,
                    network,
                    &format!("ignoring invalid subnet {:?}", config.subnet),
                );
                None
            }
        })
        .ok_or_else(|| MonitorError::MissingNetworkSubnet(network.id.clone()))?;

    let gateway = config.gateway.as_deref().and_then(|value| {
        let gateway = value.parse::<IpAddr>().ok().filter(IpAddr::is_ipv4);
        if gateway.is_none() {
            network_warning(
                warnings,
                network,
                &format!("ignoring invalid gateway {value}"),
            );
        }
        gateway
    });

    Ok((subnet, gateway))
}

/// Whether the network opted in, and in which mode: `Some(false)` for `true` (enforce),
/// `Some(true)` for `monitor`. An invalid value is reported and treated as enforced, so a
/// typo restricts containers instead of silently leaving them open. A network without the
/// label is monitored when `monitored` names it, or is `*`.
fn portcullis_mode(
    network: &DockerNetworkInspect,
    monitored: &[String],
    warnings: &mut Vec<Warning>,
) -> Option<bool> {
    const LABEL_KEY: &str = "portcullis.enable";
    let Some(value) = network
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_KEY))
    else {
        return monitored
            .iter()
            .any(|name| name == "*" || *name == network.name)
            .then_some(true);
    };
    match value.as_str() {
        "true" => Some(false),
        "monitor" => Some(true),
        "false" => None,
        _ => {
            network_warning(
                warnings,
                network,
                &format!(
                    "invalid {LABEL_KEY} value {value:?}, expected true, monitor or false; enforcing the network"
                ),
            );
            Some(false)
        }
    }
}

pub fn runtime_dns_servers(host_config: Option<&DockerHostConfig>) -> HashSet<IpAddr> {
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
    use crate::docker::DockerEvent;
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
            options: None,
            enable_ipv6: false,
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
                    mac_address: None,
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
                    mac_address: None,
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
                sandbox_key: Some("/var/run/docker/netns/abc".to_string()),
            }),
            mounts: Vec::new(),
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
            network: Network {
                id: network_id.into(),
                name: network_id.to_string(),
                subnet,
                gateway,
                ipv6: false,
                bridge: format!("br-{network_id}"),
                monitor: false,
            },
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
        assert_eq!(
            state
                .containers()
                .get("def")
                .expect("def should be present")
                .attachments,
            [] as [crate::model::NetworkAttachment; 0]
        );
    }

    #[test]
    fn collect_state_takes_network_aliases_from_the_inspect() {
        let mut api = MockDockerApi::default();
        api.networks_list.push(network_inspect(
            "net0",
            "managed",
            "172.20.0.0/16",
            Some("172.20.0.1"),
            DockerNetworkDriver::Bridge,
            Some("true"),
        ));
        // Docker's container list has no aliases; its inspect has them.
        let mut summary =
            container_summary("abc", "/web", &[], &[("managed", "net0", "172.20.0.2")]);
        for endpoint in summary
            .network_settings
            .iter_mut()
            .filter_map(|settings| settings.networks.as_mut())
            .flat_map(|networks| networks.values_mut())
        {
            endpoint.aliases = None;
        }
        api.containers_list.push(summary);
        let mut inspect =
            container_inspect("abc", "/web", &[], &[("managed", "net0", "172.20.0.2")]);
        for endpoint in inspect
            .network_settings
            .iter_mut()
            .filter_map(|settings| settings.networks.as_mut())
            .flat_map(|networks| networks.values_mut())
        {
            endpoint.aliases = Some(vec!["frontend".to_string()]);
        }
        api.containers.insert("abc".to_string(), inspect);

        let mut monitor = DockerMonitor::new(api);
        let state = monitor.initialize().expect("collect_state should succeed");

        let web = state
            .containers()
            .get("abc")
            .expect("abc should be present");
        assert_eq!(web.attachments.len(), 1);
        assert_eq!(web.attachments[0].aliases, ["frontend"]);
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
    fn resolves_events_with_what_was_fetched_without_asking_docker_again() {
        let mut fetching = MockDockerApi::default();
        fetching.containers.insert(
            "abc".to_string(),
            container_inspect("abc", "/web", &[], &[("managed", "net0", "172.20.0.2")]),
        );
        let event = network_connect_event("net0", "abc");
        // Only networks Portcullis manages are worth asking about.
        let fetched = fetch(&mut fetching, &event, |network| network == "net0");
        assert!(matches!(fetched, Fetched::Container(Ok(_))));
        assert!(matches!(
            fetch(
                &mut fetching,
                &network_connect_event("other", "abc"),
                |network| { network == "net0" }
            ),
            Fetched::Nothing
        ));
        assert_eq!(fetching.inspect_container_requests.borrow().len(), 1);

        // The main loop's monitor doesn't ask Docker: it would wait for the container to
        // finish starting.
        let mut monitor = DockerMonitor::new(MockDockerApi::default());
        let mut state = RuntimeState::default();
        add_network(&mut state, "net0", "172.20.0.0/16", Some("172.20.0.1"));
        let action = monitor
            .resolve_fetched_event_action(&state, event, fetched)
            .expect("connect action should resolve");
        assert!(matches!(
            action,
            Some(RuntimeStateAction::CreateContainer { container })
                if container.attachments.len() == 1
        ));
        assert!(monitor.api.inspect_container_requests.borrow().is_empty());
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
                assert_eq!(
                    container.attachments,
                    [] as [crate::model::NetworkAttachment; 0]
                );
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
                    mac_address: None,
                    aliases: Vec::new(),
                }],
                runtime_dns_servers: HashSet::new(),
                policy: crate::model::ContainerPolicy::default(),
                sandbox: None,
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
    fn create_event_of_a_container_found_already_keeps_its_networks() {
        let mut monitor = DockerMonitor::new(MockDockerApi::default());
        let mut state = RuntimeState::default();
        state.apply_action(RuntimeStateAction::DiscoverContainer {
            container: Box::new(Container {
                id: "abc".to_string().into(),
                name: "web".to_string().into(),
                attachments: vec![NetworkAttachment {
                    network_id: "n0".into(),
                    ip_address: "172.18.0.2".parse().expect("address"),
                    mac_address: None,
                    aliases: Vec::new(),
                }],
                runtime_dns_servers: HashSet::new(),
                policy: ContainerPolicy::default(),
                sandbox: Some("/run/docker/netns/abc".to_string()),
            }),
        });

        // Docker's create event comes after the container was found behind its port.
        let event = DockerEvent {
            id: "abc".to_string(),
            action: DockerEventAction::Create,
            name: Some("web".to_string()),
            kind: DockerEventKind::Container,
            attributes: IndexMap::new(),
        };
        let action = monitor
            .resolve_event_action(&state, event)
            .expect("create action should resolve");

        assert!(action.is_none());
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
            Some(RuntimeStateAction::UpsertNetwork { network }) if network.id == "net0".into()
        ));
        assert!(matches!(
            unmanaged,
            Some(RuntimeStateAction::RemoveNetwork { network_id }) if network_id == "net1".into()
        ));
    }

    #[test]
    fn collect_state_reads_dns_servers_of_managed_containers() {
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
            &[],
            &[("managed", "net0", "172.20.0.2")],
        ));
        api.containers_list
            .push(container_summary("def", "/other", &[], &[]));
        let mut inspect =
            container_inspect("abc", "/web", &[], &[("managed", "net0", "172.20.0.2")]);
        inspect.host_config = Some(DockerHostConfig {
            dns: Some(vec!["9.9.9.9".to_string()]),
            ..DockerHostConfig::default()
        });
        api.containers.insert("abc".to_string(), inspect);

        let mut monitor = DockerMonitor::new(api);
        let state = monitor.initialize().expect("initialize should succeed");
        let web = state.containers().get("abc").expect("web");
        assert!(
            web.runtime_dns_servers
                .contains(&"9.9.9.9".parse::<IpAddr>().expect("ip"))
        );
        // Only managed containers are inspected.
        assert_eq!(
            monitor.api.inspect_container_requests.borrow().as_slice(),
            ["abc".to_string()]
        );
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
    fn collect_state_uses_the_ipv4_subnet_of_dual_stack_networks() {
        let mut api = MockDockerApi::default();
        let mut network = network_inspect(
            "net0",
            "dual",
            "fd00::/64",
            Some("fd00::1"),
            DockerNetworkDriver::Bridge,
            Some("true"),
        );
        if let Some(configs) = network.ipam.as_mut().and_then(|ipam| ipam.config.as_mut()) {
            configs.push(DockerIpamConfig {
                subnet: Some("172.20.0.0/16".to_string()),
                gateway: Some("172.20.0.1".to_string()),
            });
        }
        api.networks_list.push(network);

        let mut monitor = DockerMonitor::new(api);
        let state = monitor.initialize().expect("initialize should succeed");
        let network = state
            .networks()
            .get("net0")
            .expect("net0 should be managed");
        assert_eq!(
            network.subnet,
            "172.20.0.0/16".parse::<IpNet>().expect("subnet")
        );
        assert_eq!(
            network.gateway,
            Some("172.20.0.1".parse().expect("gateway"))
        );
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
    fn monitors_configured_networks_without_labels() {
        let networks = vec![
            network_inspect(
                "n0",
                "plain",
                "172.20.0.0/16",
                None,
                DockerNetworkDriver::Bridge,
                None,
            ),
            network_inspect(
                "n1",
                "other",
                "172.21.0.0/16",
                None,
                DockerNetworkDriver::Bridge,
                None,
            ),
            network_inspect(
                "n2",
                "enforced",
                "172.22.0.0/16",
                None,
                DockerNetworkDriver::Bridge,
                Some("true"),
            ),
            network_inspect(
                "n3",
                "opted-out",
                "172.23.0.0/16",
                None,
                DockerNetworkDriver::Bridge,
                Some("false"),
            ),
        ];
        let managed = |names: &[&str]| {
            let mut monitor = DockerMonitor::new(MockDockerApi {
                networks_list: networks.clone(),
                ..MockDockerApi::default()
            })
            .with_monitored_networks(names.iter().map(ToString::to_string).collect());
            let state = monitor.initialize().expect("initialize should succeed");
            let mut networks: Vec<(String, bool)> = state
                .networks()
                .values()
                .map(|network| (network.name.clone(), network.monitor))
                .collect();
            networks.sort();
            networks
        };

        assert_eq!(managed(&[]), [("enforced".to_string(), false)]);
        assert_eq!(
            managed(&["plain", "enforced"]),
            [("enforced".to_string(), false), ("plain".to_string(), true)]
        );
        assert_eq!(
            managed(&["*"]),
            [
                ("enforced".to_string(), false),
                ("other".to_string(), true),
                ("plain".to_string(), true),
            ]
        );
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

    mod policy_files {
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;

        use indexmap::IndexMap;

        use super::super::*;
        use crate::model::{DnsTarget, EgressTarget, IccMode};

        const SECRET: &str = "192.0.2.10";

        fn directory(test: &str, files: &[(&str, &str)]) -> PathBuf {
            let path = std::env::temp_dir()
                .join(format!("portcullis-monitor-{test}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("protect directory");
            for (name, text) in files {
                std::fs::write(path.join(name), text).expect("write file");
                std::fs::set_permissions(path.join(name), std::fs::Permissions::from_mode(0o600))
                    .expect("protect file");
            }
            path
        }

        fn labels(pairs: &[(&str, &str)]) -> IndexMap<String, String> {
            pairs
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect()
        }

        fn assert_no_secret(warnings: &[Warning]) {
            for warning in warnings {
                assert!(!warning.message.contains(SECRET), "{}", warning.message);
            }
        }

        #[test]
        fn file_labels_add_to_container_labels() {
            let directory = directory(
                "merge",
                &[(
                    "vpn",
                    "# the VPN endpoint\nportcullis.egress.vpn=ip:192.0.2.10,udp:51820\n",
                )],
            );
            let mut warnings = Vec::new();
            let policy = policy_from_labels(
                "/vpn",
                &labels(&[
                    ("portcullis.policy-file", "vpn"),
                    ("portcullis.egress.web", "host:example.com,tcp:443"),
                    ("portcullis.icc.mode", "deny"),
                ]),
                &directory,
                &mut warnings,
            );
            assert!(warnings.is_empty(), "{warnings:?}");
            assert_eq!(policy.icc_mode, IccMode::Deny);
            assert_eq!(policy.egress.len(), 2);
            assert!(
                policy.egress.iter().any(|rule| rule.target
                    == EgressTarget::IpCidr("192.0.2.10/32".parse().expect("cidr")))
            );
        }

        #[test]
        fn file_values_win_over_labels_and_later_lines_over_earlier() {
            let directory = directory(
                "override",
                &[(
                    "vpn",
                    "portcullis.icc.mode=allow-listed\nportcullis.icc.mode=deny\n",
                )],
            );
            let mut warnings = Vec::new();
            let policy = policy_from_labels(
                "vpn",
                &labels(&[
                    ("portcullis.policy-file", "vpn"),
                    ("portcullis.icc.mode", "allow"),
                ]),
                &directory,
                &mut warnings,
            );
            assert_eq!(policy.icc_mode, IccMode::Deny);
            assert_eq!(warnings.len(), 2, "{warnings:?}");
            assert!(
                warnings
                    .iter()
                    .all(|warning| warning.kind == WarningKind::InvalidLabel)
            );
        }

        #[test]
        fn invalid_file_values_are_reported_without_the_value() {
            let directory = directory(
                "invalid",
                &[(
                    "vpn",
                    "portcullis.egress.vpn=ip:192.0.2.10,udp:x\n192.0.2.10=tcp:443\nportcullis.egress.ok=ip:198.51.100.1,tcp:443\n",
                )],
            );
            let mut warnings = Vec::new();
            let policy = policy_from_labels(
                "vpn",
                &labels(&[("portcullis.policy-file", "vpn")]),
                &directory,
                &mut warnings,
            );
            assert_eq!(policy.egress.len(), 1);
            assert_eq!(warnings.len(), 2, "{warnings:?}");
            assert!(warnings[1].message.contains("portcullis.egress.vpn"));
            assert_no_secret(&warnings);
        }

        #[test]
        fn a_file_that_can_t_be_used_denies_everything() {
            let directory = directory(
                "broken",
                &[("vpn", "portcullis.icc.mode=allow\n192.0.2.10\n")],
            );
            for name in ["missing", "vpn", "../vpn"] {
                let mut warnings = Vec::new();
                let policy = policy_from_labels(
                    "vpn",
                    &labels(&[
                        ("portcullis.policy-file", name),
                        ("portcullis.egress.web", "ip:*,*"),
                        ("portcullis.ack", "privileged"),
                    ]),
                    &directory,
                    &mut warnings,
                );
                assert_eq!(policy.icc_mode, IccMode::Deny, "{name}");
                assert!(policy.egress.is_empty(), "{name}");
                assert!(policy.icc_allow.is_empty(), "{name}");
                assert_eq!(policy.dns_targets, Vec::<DnsTarget>::new(), "{name}");
                assert_eq!(policy.domains, Some(Vec::new()), "{name}");
                assert!(policy.acknowledged.contains(&WarningKind::Privileged));
                assert_eq!(warnings.len(), 1, "{name}: {warnings:?}");
                assert_eq!(warnings[0].kind, WarningKind::PolicyFile);
                assert_no_secret(&warnings);
            }
        }

        #[test]
        fn a_file_can_t_name_another_file() {
            let directory = directory(
                "nested",
                &[
                    ("vpn", "portcullis.policy-file=other\n"),
                    ("other", "portcullis.icc.mode=deny\n"),
                ],
            );
            let mut warnings = Vec::new();
            let policy = policy_from_labels(
                "vpn",
                &labels(&[("portcullis.policy-file", "vpn")]),
                &directory,
                &mut warnings,
            );
            assert_eq!(policy.icc_mode, IccMode::Allow);
            assert_eq!(warnings.len(), 1, "{warnings:?}");
        }
    }
}
