//! Container configurations that get around Portcullis without sending a single packet it
//! could deny: a second network that isn't enforced, someone else's network namespace, the
//! Docker socket, or the privileges to change the container's own network. Each is reported
//! as a warning when the container starts, unless a `portcullis.ack` label on the container
//! acknowledges it.

use std::collections::HashSet;

use crate::docker::raw::{DockerContainerInspect, DockerHostConfig};
use crate::events::{Warning, WarningKind};
use crate::labels::{ACK_LABEL, parse_acknowledged};
use crate::model::{NetworkId, RuntimeState};

/// Configuration warnings about a container, without those it acknowledges.
pub fn container_warnings(inspect: &DockerContainerInspect, state: &RuntimeState) -> Vec<Warning> {
    let name = inspect.name.trim_start_matches('/');
    let labels = &inspect.config.labels;
    let (acknowledged, _) = parse_acknowledged(labels);
    let has_labels = labels
        .keys()
        .any(|key| key.starts_with("portcullis.") && key != ACK_LABEL);
    let host_config = inspect.host_config.clone().unwrap_or_default();
    let networks: Vec<(&str, NetworkId)> = inspect
        .network_settings
        .as_ref()
        .and_then(|settings| settings.networks.as_ref())
        .into_iter()
        .flatten()
        .filter_map(|(name, endpoint)| {
            Some((name.as_str(), NetworkId::from(endpoint.network_id.clone()?)))
        })
        .collect();
    let managed: HashSet<&NetworkId> = networks
        .iter()
        .map(|(_, id)| id)
        .filter(|id| state.networks().contains_key(*id))
        .collect();

    let mut found = Vec::new();
    let mut warn = |kind, message: String| {
        if !acknowledged.contains(&kind) {
            found.push((kind, message));
        }
    };

    if !managed.is_empty() {
        for (network, id) in &networks {
            if !managed.contains(id) {
                warn(
                    WarningKind::UnenforcedNetwork,
                    format!(
                        "is also on network {network}, which isn't enforced: its traffic through that network isn't filtered"
                    ),
                );
            }
        }
    }

    // `container:<id or name>`: the container has no network of its own.
    let shared = host_config
        .network_mode
        .as_deref()
        .and_then(|mode| mode.strip_prefix("container:"))
        .map(|target| {
            let restricted = state
                .containers()
                .values()
                .find(|container| container.id.starts_with(target) || *container.name == *target);
            (
                restricted.map_or_else(|| target.to_string(), |c| c.name.to_string()),
                restricted.is_some_and(|container| !container.attachments.is_empty()),
            )
        });
    if let Some((target, target_restricted)) = &shared {
        if *target_restricted || has_labels {
            warn(
                WarningKind::SharedNetwork,
                format!(
                    "uses the network of {target}: it has {target}'s rules, and its own portcullis labels have no effect"
                ),
            );
        }
    } else if has_labels && managed.is_empty() {
        let message = if host_config.network_mode.as_deref() == Some("host") {
            "uses the host's network: its portcullis labels have no effect"
        } else {
            "isn't on a network with portcullis.enable: its portcullis labels have no effect"
        };
        warn(WarningKind::UnusedLabels, message.to_string());
    }

    let restricted = !managed.is_empty() || shared.is_some_and(|(_, restricted)| restricted);
    if restricted {
        for (kind, message) in ways_out(inspect, host_config) {
            warn(kind, message);
        }
    }

    found
        .into_iter()
        .map(|(kind, message)| Warning {
            kind,
            container: Some(name.to_string()),
            message,
        })
        .collect()
}

/// What lets a restricted container get around the rules from the inside.
fn ways_out(
    inspect: &DockerContainerInspect,
    host_config: DockerHostConfig,
) -> Vec<(WarningKind, String)> {
    let mut found = Vec::new();
    if let Some(mount) = inspect.mounts.iter().find(|mount| {
        mount.source.ends_with("docker.sock") || mount.destination.ends_with("docker.sock")
    }) {
        found.push((
            WarningKind::DockerSocket,
            format!(
                "has the Docker socket ({}): it can start containers that aren't restricted, or change its own",
                mount.destination
            ),
        ));
    }
    let capabilities = host_config.cap_add.unwrap_or_default();
    let has = |capability: &str| {
        capabilities.iter().any(|added| {
            let added = added.to_ascii_uppercase();
            added == "ALL" || added.trim_start_matches("CAP_") == capability
        })
    };
    if host_config.privileged {
        found.push((
            WarningKind::Privileged,
            "is privileged: it can change its network interfaces and get around the rules"
                .to_string(),
        ));
    } else if has("NET_ADMIN") {
        found.push((
            WarningKind::NetAdmin,
            "has NET_ADMIN: it can change its own interfaces and routes; Portcullis still denies what doesn't match its address and MAC".to_string(),
        ));
    }
    found
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::docker::raw::{
        DockerContainerConfig, DockerEndpoint, DockerHostConfig, DockerMount, DockerNetworkSettings,
    };
    use crate::firewall::test_support;

    fn inspect(networks: &[(&str, &str)], labels: &[(&str, &str)]) -> DockerContainerInspect {
        DockerContainerInspect {
            id: "abc".to_string(),
            name: "/app".to_string(),
            config: DockerContainerConfig {
                labels: labels
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                    .collect(),
            },
            host_config: Some(DockerHostConfig::default()),
            network_settings: Some(DockerNetworkSettings {
                networks: Some(
                    networks
                        .iter()
                        .map(|(name, id)| {
                            (
                                (*name).to_string(),
                                DockerEndpoint {
                                    network_id: Some((*id).to_string()),
                                    ip_address: None,
                                    aliases: None,
                                    mac_address: None,
                                },
                            )
                        })
                        .collect::<BTreeMap<_, _>>(),
                ),
                sandbox_key: None,
            }),
            mounts: Vec::new(),
        }
    }

    fn kinds(warnings: &[Warning]) -> Vec<WarningKind> {
        warnings.iter().map(|warning| warning.kind).collect()
    }

    #[test]
    fn reports_a_second_network_that_isnt_enforced() {
        let state = test_support::icc_state();
        let container = inspect(&[("net0", "net0"), ("open", "open")], &[]);
        let warnings = container_warnings(&container, &state);
        assert_eq!(kinds(&warnings), [WarningKind::UnenforcedNetwork]);
        let warning = warnings.first().expect("warning");
        assert!(warning.message.contains("open"));
        assert_eq!(warning.container.as_deref(), Some("app"));
        // Unrestricted containers on networks that aren't enforced are none of its business.
        assert_eq!(
            container_warnings(&inspect(&[("open", "open")], &[]), &state),
            [] as [crate::events::Warning; 0]
        );
    }

    #[test]
    fn reports_labels_without_effect() {
        let state = test_support::icc_state();
        let labels = [("portcullis.egress.web", "ip:1.1.1.1,tcp:443")];
        let mut container = inspect(&[], &labels);
        container.host_config = Some(DockerHostConfig {
            network_mode: Some("host".to_string()),
            ..DockerHostConfig::default()
        });
        let warnings = container_warnings(&container, &state);
        assert_eq!(kinds(&warnings), [WarningKind::UnusedLabels]);
        assert!(
            warnings
                .first()
                .expect("warning")
                .message
                .contains("host's network")
        );
    }

    #[test]
    fn reports_containers_sharing_a_restricted_network() {
        let state = test_support::icc_state();
        let web = state
            .containers()
            .values()
            .find(|container| *container.name == *"web")
            .expect("web")
            .id
            .to_string();
        let mut container = inspect(&[], &[]);
        container.host_config = Some(DockerHostConfig {
            network_mode: Some(format!("container:{web}")),
            privileged: true,
            ..DockerHostConfig::default()
        });
        let warnings = container_warnings(&container, &state);
        assert_eq!(
            kinds(&warnings),
            [WarningKind::SharedNetwork, WarningKind::Privileged]
        );
        assert!(
            warnings
                .first()
                .expect("warning")
                .message
                .contains("network of web")
        );
    }

    #[test]
    fn reports_ways_out_of_restricted_containers_unless_acknowledged() {
        let state = test_support::icc_state();
        let mut container = inspect(&[("net0", "net0")], &[]);
        container.mounts.push(DockerMount {
            source: "/var/run/docker.sock".to_string(),
            destination: "/var/run/docker.sock".to_string(),
        });
        container.host_config = Some(DockerHostConfig {
            cap_add: Some(vec!["CAP_NET_ADMIN".to_string()]),
            ..DockerHostConfig::default()
        });
        assert_eq!(
            kinds(&container_warnings(&container, &state)),
            [WarningKind::DockerSocket, WarningKind::NetAdmin]
        );
        container.config.labels.insert(
            "portcullis.ack".to_string(),
            "docker-socket, net-admin".to_string(),
        );
        assert_eq!(
            container_warnings(&container, &state),
            [] as [crate::events::Warning; 0]
        );
    }
}
