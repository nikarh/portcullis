//! What Portcullis knows about addresses, for attributing events: which container an
//! address or MAC belongs to, which network a bridge serves, and which domain a container
//! reached an address under.
//!
//! Updated by the main loop after every apply, and by DNS inspection; read by the
//! connection log and DNS inspection threads.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::dns::normalize;
use crate::firewall::{Destination, HostSet, Plan, Rule};
use crate::model::MacAddress;

/// Observations kept before expired ones are pruned, at most once per [`PRUNE_EVERY`].
const PRUNE_ABOVE: usize = 16_384;
const PRUNE_EVERY: Duration = Duration::from_secs(1);
/// Observations kept at most: domains on events are best effort, and a container answering
/// itself through a resolver of its own mustn't make them grow without bound.
const MAX_OBSERVATIONS: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInfo {
    pub container: String,
    pub network: String,
    pub mac: Option<MacAddress>,
    /// Interface index of the container's bridge port, where known.
    pub port: Option<u32>,
    /// The container's network is in monitor mode.
    pub monitor: bool,
    /// The container may be quarantined when it misbehaves.
    pub quarantine: bool,
    /// IPv6 is enabled on the container's network.
    pub ipv6_network: bool,
}

#[derive(Debug, Default)]
struct Snapshot {
    sources: HashMap<IpAddr, SourceInfo>,
    by_mac: HashMap<MacAddress, (IpAddr, SourceInfo)>,
    /// Interface index of a bridge port to the container behind it.
    by_port: HashMap<u32, (IpAddr, SourceInfo)>,
    /// Bridge name to network name.
    bridges: HashMap<String, String>,
    /// Hostnames of each source's `host:` rules.
    rule_hosts: HashMap<IpAddr, Vec<String>>,
    host_sets: Vec<HostSet>,
}

#[derive(Debug, Default)]
pub struct Directory {
    snapshot: RwLock<Snapshot>,
    observations: Mutex<Observations>,
}

#[derive(Debug, Default)]
struct Observations {
    /// (container address, destination) to the name the container looked up, until when.
    names: HashMap<(IpAddr, IpAddr), (String, Instant)>,
    pruned: Option<Instant>,
}

impl Directory {
    /// Take over the containers, bridges and hostname sets of the applied plan.
    pub fn update(&self, plan: &Plan) {
        let mut snapshot = Snapshot::default();
        let ipv6_networks: std::collections::HashSet<&str> = plan
            .bridges
            .iter()
            .filter(|bridge| bridge.ipv6)
            .map(|bridge| bridge.network.as_str())
            .collect();
        for source in &plan.sources {
            let info = SourceInfo {
                container: source.container.to_string(),
                network: source.network.clone(),
                mac: source.mac,
                port: source.port.as_ref().map(|port| port.index),
                monitor: source.monitor,
                quarantine: source.quarantine,
                ipv6_network: ipv6_networks.contains(source.network.as_str()),
            };
            if let Some(mac) = source.mac {
                snapshot.by_mac.insert(mac, (source.address, info.clone()));
            }
            if let Some(port) = info.port {
                snapshot
                    .by_port
                    .insert(port, (source.address, info.clone()));
            }
            snapshot.sources.insert(source.address, info);
            let mut hosts: Vec<String> = plan
                .egress_rules(source)
                .iter()
                .filter_map(|rule| match rule {
                    Rule::AcceptPort {
                        destination: Destination::HostSet(index),
                        ..
                    } => plan.host_set(*index).map(|set| set.host.clone()),
                    _ => None,
                })
                .collect();
            hosts.sort_unstable();
            hosts.dedup();
            snapshot.rule_hosts.insert(source.address, hosts);
        }
        snapshot.bridges = plan
            .bridges
            .iter()
            .map(|bridge| (bridge.name.clone(), bridge.network.clone()))
            .collect();
        snapshot.host_sets.clone_from(&plan.host_sets);

        let mut current = self
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        // Addresses get reused: forget what was observed for an address once it belongs to
        // another container, or to none.
        let reassigned: Vec<IpAddr> = current
            .sources
            .iter()
            .filter(|(address, info)| {
                snapshot.sources.get(address).map(|now| &now.container) != Some(&info.container)
            })
            .map(|(address, _)| *address)
            .collect();
        *current = snapshot;
        drop(current);
        if !reassigned.is_empty() {
            self.observations
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .names
                .retain(|(container, _), _| !reassigned.contains(container));
        }
    }

    #[must_use]
    pub fn source(&self, address: IpAddr) -> Option<SourceInfo> {
        self.read().sources.get(&address).cloned()
    }

    /// The container a MAC belongs to, with its address.
    #[must_use]
    pub fn by_mac(&self, mac: MacAddress) -> Option<(IpAddr, SourceInfo)> {
        self.read().by_mac.get(&mac).cloned()
    }

    /// One of a container's addresses, by the container's name.
    #[must_use]
    pub fn container(&self, name: &str) -> Option<SourceInfo> {
        self.read()
            .sources
            .values()
            .find(|info| info.container == name)
            .cloned()
    }

    /// The container behind a bridge port, given the port's interface index, with its
    /// address.
    #[must_use]
    pub fn by_port(&self, index: u32) -> Option<(IpAddr, SourceInfo)> {
        self.read().by_port.get(&index).cloned()
    }

    /// The network served by the bridge a packet came in on, given the interface index of
    /// the bridge or of one of its ports.
    #[must_use]
    pub fn network_of_interface(&self, index: u32) -> Option<String> {
        let name = interface_name(index)?;
        let snapshot = self.read();
        if let Some(network) = snapshot.bridges.get(&name) {
            return Some(network.clone());
        }
        let master = fs::read_link(Path::new("/sys/class/net").join(&name).join("master")).ok()?;
        let bridge = master.file_name()?.to_str()?;
        snapshot.bridges.get(bridge).cloned()
    }

    /// Hostnames of the `host:` rules of the container at `source`.
    #[must_use]
    pub fn rule_hosts(&self, source: IpAddr) -> Vec<String> {
        self.read()
            .rule_hosts
            .get(&source)
            .cloned()
            .unwrap_or_default()
    }

    /// Hostname sets of `container`'s current rules for any of `names`.
    #[must_use]
    pub fn host_sets_for(&self, container: &str, names: &[String]) -> Vec<HostSet> {
        self.read()
            .host_sets
            .iter()
            .filter(|set| set.container.as_str() == container && names.contains(&set.host))
            .cloned()
            .collect()
    }

    /// Record that the container at `container` looked up `name` and got `address`.
    pub fn observe(&self, container: IpAddr, address: IpAddr, name: &str, valid_for: Duration) {
        let now = Instant::now();
        let mut observations = self
            .observations
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if observations.names.len() > PRUNE_ABOVE
            && observations
                .pruned
                .is_none_or(|pruned| now.duration_since(pruned) >= PRUNE_EVERY)
        {
            observations.names.retain(|_, (_, expires)| *expires > now);
            observations.pruned = Some(now);
        }
        let key = (container, address);
        if observations.names.len() >= MAX_OBSERVATIONS && !observations.names.contains_key(&key) {
            return;
        }
        observations
            .names
            .insert(key, (normalize(name), now + valid_for));
    }

    /// The name the container at `container` looked up to get `address`.
    #[must_use]
    pub fn domain(&self, container: IpAddr, address: IpAddr) -> Option<String> {
        let now = Instant::now();
        self.observations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .names
            .get(&(container, address))
            .filter(|(_, expires)| *expires > now)
            .map(|(name, _)| name.clone())
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Snapshot> {
        self.snapshot.read().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The name of the network interface with this index.
fn interface_name(index: u32) -> Option<String> {
    fs::read_dir("/sys/class/net")
        .ok()?
        .flatten()
        .find_map(|entry| {
            let value = fs::read_to_string(entry.path().join("ifindex")).ok()?;
            (value.trim().parse::<u32>().ok()? == index)
                .then(|| entry.file_name().to_string_lossy().into_owned())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::test_support::{self, MockResolver, ip};

    fn directory() -> Directory {
        let plan = Plan::build(
            &test_support::icc_state(),
            &mut MockResolver::default(),
            &[],
            false,
        );
        let directory = Directory::default();
        directory.update(&plan);
        directory
    }

    #[test]
    fn attributes_addresses_and_macs_to_containers() {
        let directory = directory();
        let web = directory.source(ip("172.18.0.2")).expect("web");
        assert_eq!(web.container, "web");
        assert_eq!(web.network, "net0");
        let mac = test_support::mac_of("172.18.0.2").expect("mac");
        let (address, info) = directory.by_mac(mac).expect("by mac");
        assert_eq!(address, ip("172.18.0.2"));
        assert_eq!(info.container, "web");
        assert!(directory.source(ip("172.18.0.99")).is_none());
    }

    #[test]
    fn remembers_looked_up_domains_per_container() {
        let directory = directory();
        let (web, other) = (ip("172.18.0.2"), ip("172.18.0.3"));
        directory.observe(web, ip("1.1.1.1"), "API.test.", Duration::from_secs(60));
        assert_eq!(
            directory.domain(web, ip("1.1.1.1")).as_deref(),
            Some("api.test")
        );
        assert!(directory.domain(other, ip("1.1.1.1")).is_none());
        directory.observe(web, ip("2.2.2.2"), "gone.test", Duration::ZERO);
        assert!(directory.domain(web, ip("2.2.2.2")).is_none());
    }

    #[test]
    fn forgets_observations_of_reassigned_addresses() {
        let directory = directory();
        let web = ip("172.18.0.2");
        directory.observe(web, ip("1.1.1.1"), "api.test", Duration::from_secs(60));
        // Same containers: kept.
        let plan = Plan::build(
            &test_support::icc_state(),
            &mut MockResolver::default(),
            &[],
            false,
        );
        directory.update(&plan);
        assert!(directory.domain(web, ip("1.1.1.1")).is_some());
        // The address is gone: forgotten.
        let plan = Plan::build(
            &test_support::ipv6_state(),
            &mut MockResolver::default(),
            &[],
            false,
        );
        directory.update(&plan);
        assert!(directory.domain(web, ip("1.1.1.1")).is_none());
    }

    #[test]
    fn finds_host_sets_by_name() {
        let plan = Plan::build(
            &test_support::hostname_state(),
            &mut MockResolver::default(),
            &[],
            false,
        );
        let directory = Directory::default();
        directory.update(&plan);
        let sets = directory.host_sets_for("web", &[test_support::HOST.to_string()]);
        assert_eq!(sets.len(), 1);
        assert!(
            directory
                .host_sets_for("web", &["other.test".to_string()])
                .is_empty()
        );
        // Another container's sets.
        assert!(
            directory
                .host_sets_for("db", &[test_support::HOST.to_string()])
                .is_empty()
        );
    }
}
