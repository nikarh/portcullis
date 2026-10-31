//! Backend-agnostic firewall plan.
//!
//! The planner turns [`RuntimeState`] into one ordered rule list per managed source address,
//! the hostname address sets those rules reference, and the enforced network subnets. Both
//! firewall backends only render this plan, so policy semantics live in one place and a
//! future backend (such as eBPF) only needs a renderer.
//!
//! Evaluation model, for traffic from a container:
//! 1. packets of established or related connections pass;
//! 2. a packet whose source is a managed address is checked against that source's rules,
//!    first match wins: ICC rules for traffic to containers on the same network (bridged),
//!    egress rules for everything else (routed), which end with an implicit deny;
//! 3. any other packet entering from an enforced network's bridge is denied: unknown or
//!    spoofed source addresses, and managed addresses sent with another container's MAC;
//! 4. everything else passes.
//!
//! "Pass" and "accept" only mean that this policy doesn't drop the packet; Docker's own
//! rules still apply afterwards.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::ops::Range;
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net};
use tracing::{error, trace};

use crate::dns::{HostResolver, normalize};
use crate::model::{
    Container, ContainerName, DnsTarget, EgressTarget, IccAllowRule, IccMode, MacAddress,
    NetworkAttachment, Protocol, RuntimeState,
};

pub const DNS_PORT: u16 = 53;
const DNS_PROTOCOLS: [Protocol; 2] = [Protocol::Udp, Protocol::Tcp];
/// IPv4 destinations that reach every container on a bridge besides the subnet itself:
/// the limited broadcast address and multicast.
const ICC_BROADCAST_V4: [IpNet; 2] = [
    IpNet::V4(Ipv4Net::new_assert(std::net::Ipv4Addr::BROADCAST, 32)),
    IpNet::V4(Ipv4Net::new_assert(
        std::net::Ipv4Addr::new(224, 0, 0, 0),
        4,
    )),
];

/// Destination of an [`Rule::AcceptPort`] rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    Net(IpNet),
    Addr(IpAddr),
    /// Index into [`Plan::host_sets`].
    HostSet(usize),
}

/// A rule of one source. Every address in a rule has the same family as the source; the
/// planner never emits mixed-family rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Allow DNS to `destination`, or to any destination when `None`.
    AcceptDns {
        destination: Option<IpAddr>,
        protocol: Protocol,
    },
    /// Deny any other DNS.
    DenyDns { protocol: Protocol },
    /// Allow all traffic to a subnet (ICC allow).
    AcceptNet(IpNet),
    /// Allow all traffic to an address of the host itself, such as the network gateway.
    AcceptHost(IpAddr),
    /// Deny all traffic to a subnet (ICC deny).
    DenyNet(IpNet),
    /// Allow traffic to `destination` on a single port.
    AcceptPort {
        destination: Destination,
        protocol: Protocol,
        port: u16,
    },
}

/// A managed source address and its rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub address: IpAddr,
    pub container: ContainerName,
    /// Name of the network the address belongs to.
    pub network: String,
    /// Monitor mode: denials are reported, not enforced.
    pub monitor: bool,
    /// The container's MAC address on the network the address belongs to. Packets from the
    /// address are only accepted with this MAC, so containers can't borrow others' addresses.
    pub mac: Option<MacAddress>,
    /// Range into [`Plan::rules`] of rules for traffic leaving the network.
    egress: Range<usize>,
    /// Range into [`Plan::rules`] of rules for traffic to containers on the same network.
    icc: Range<usize>,
}

/// Stable identifier of a hostname set, derived from the hostname.
///
/// Stable across applies so that a set keeps referring to the same hostname while rules
/// referencing it are being replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostSetId(u64);

impl HostSetId {
    /// 64-bit FNV-1a of the hostname. Hostnames are deduplicated before hashing, so a
    /// collision would require two distinct hostnames used in the same policy to share a
    /// 64-bit hash, which is negligible for any realistic number of hostnames.
    #[must_use]
    pub fn for_host(host: &str) -> Self {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in host.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
        Self(hash)
    }

    /// Name of the set with the given prefix, e.g. `pc_h4_<hash>`.
    #[must_use]
    pub const fn name(self, prefix: &'static str) -> SetName {
        SetName { prefix, id: self }
    }
}

/// Set name rendered without allocating.
#[derive(Debug, Clone, Copy)]
pub struct SetName {
    prefix: &'static str,
    id: HostSetId,
}

impl fmt::Display for SetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:016x}", self.prefix, self.id.0)
    }
}

pub const SET_PREFIX_V4: &str = "pc_h4_";
pub const SET_PREFIX_V6: &str = "pc_h6_";

/// Known addresses of one hostname, shared by every rule that targets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSet {
    pub id: HostSetId,
    /// The hostname, normalized.
    pub host: String,
    /// Addresses and how long each stays allowed.
    pub addresses: Vec<(IpAddr, Duration)>,
    /// Whether any IPv4 rule references this set.
    pub used_v4: bool,
    /// Whether any IPv6 rule references this set.
    pub used_v6: bool,
}

impl HostSet {
    pub fn v4(&self) -> impl Iterator<Item = (IpAddr, Duration)> + '_ {
        self.addresses
            .iter()
            .copied()
            .filter(|(address, _)| address.is_ipv4())
    }

    pub fn v6(&self) -> impl Iterator<Item = (IpAddr, Duration)> + '_ {
        self.addresses
            .iter()
            .copied()
            .filter(|(address, _)| address.is_ipv6())
    }
}

/// The bridge interface of a managed network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedBridge {
    pub name: String,
    pub network: String,
    pub subnet: IpNet,
    /// Monitor mode: denials are reported, not enforced.
    pub monitor: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Managed source addresses, each listed once.
    pub sources: Vec<Source>,
    /// Rules of all sources, see [`Plan::rules`].
    rules: Vec<Rule>,
    /// Hostname sets, one per distinct hostname.
    pub host_sets: Vec<HostSet>,
    /// Bridges of managed networks. Traffic entering from them with a source that isn't a
    /// managed address (and MAC) is denied.
    pub bridges: Vec<ManagedBridge>,
    /// Hostnames that could not be resolved; their sets are empty.
    pub unresolved_hosts: Vec<String>,
}

impl Plan {
    /// Build the plan for `state`, resolving every distinct hostname exactly once.
    /// `host_resolvers` are the host's DNS servers, see [`crate::host_dns`]. With
    /// `monitor_all`, every network is in monitor mode.
    pub fn build<R>(
        state: &RuntimeState,
        resolver: &mut R,
        host_resolvers: &[IpAddr],
        monitor_all: bool,
    ) -> Self
    where
        R: HostResolver,
    {
        let mut planner = Planner {
            state,
            resolver,
            host_resolvers,
            monitor_all,
            plan: Self::default(),
            seen_sources: HashSet::new(),
            host_index: HashMap::new(),
            icc_targets: None,
            scratch: Vec::new(),
        };

        for container in state.containers().values() {
            for attachment in &container.attachments {
                planner.plan_attachment(container, attachment);
            }
        }

        planner
            .plan
            .bridges
            .extend(state.networks().values().map(|network| ManagedBridge {
                name: network.bridge.clone(),
                network: network.name.clone(),
                subnet: network.subnet,
                monitor: monitor_all || network.monitor,
            }));
        planner
            .plan
            .bridges
            .sort_unstable_by(|a, b| a.name.cmp(&b.name));

        planner.plan
    }

    /// Rules for traffic of `source` leaving its network (routed traffic), in evaluation
    /// order. They end with an implicit deny.
    #[must_use]
    pub fn egress_rules(&self, source: &Source) -> &[Rule] {
        self.rules.get(source.egress.clone()).unwrap_or_default()
    }

    /// Rules for traffic of `source` to containers on the same network (bridged traffic),
    /// in evaluation order. Traffic no rule matches is allowed; empty means unrestricted.
    #[must_use]
    pub fn icc_rules(&self, source: &Source) -> &[Rule] {
        self.rules.get(source.icc.clone()).unwrap_or_default()
    }

    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub fn host_set(&self, index: usize) -> Option<&HostSet> {
        self.host_sets.get(index)
    }
}

struct Planner<'s, 'r, R> {
    state: &'s RuntimeState,
    resolver: &'r mut R,
    monitor_all: bool,
    host_resolvers: &'s [IpAddr],
    plan: Plan,
    seen_sources: HashSet<IpAddr>,
    /// Hostname -> index into `plan.host_sets`.
    host_index: HashMap<&'s str, usize>,
    /// Built lazily, only when an allow-listed container exists.
    icc_targets: Option<IccTargets<'s>>,
    /// Reused buffer for DNS destinations.
    scratch: Vec<IpAddr>,
}

impl<'s, R> Planner<'s, '_, R>
where
    R: HostResolver,
{
    fn plan_attachment(&mut self, container: &'s Container, attachment: &'s NetworkAttachment) {
        let source = attachment.ip_address;
        // An address can only belong to one container at a time. Should stale state ever
        // contain it twice, the first owner wins, as it would in a linear rule list.
        if !self.seen_sources.insert(source) {
            return;
        }

        let policy = &container.policy;
        let network = self
            .state
            .networks()
            .get(&attachment.network_id)
            .filter(|network| same_family(source, network.subnet.addr()));
        let subnet = network.map(|network| network.subnet);

        let egress_start = self.plan.rules.len();
        // Traffic within the network is up to the ICC rules. It only reaches the routed
        // path at all when br_netfilter is loaded; don't let the egress deny catch it there.
        if let Some(subnet) = subnet {
            self.plan.rules.push(Rule::AcceptNet(subnet));
        }
        self.plan_dns(source, &policy.dns_targets, container);

        for rule in &policy.egress {
            let destination = match &rule.target {
                EgressTarget::IpCidr(net) if same_family(source, net.addr()) => {
                    Destination::Net(*net)
                }
                EgressTarget::IpCidr(_) => continue,
                EgressTarget::Hostname(host) => {
                    let index = self.host_set(host);
                    if let Some(set) = self.plan.host_sets.get_mut(index) {
                        if source.is_ipv4() {
                            set.used_v4 = true;
                        } else {
                            set.used_v6 = true;
                        }
                    }
                    Destination::HostSet(index)
                }
            };
            self.plan
                .rules
                .extend(rule.ports.iter().map(|port| Rule::AcceptPort {
                    destination,
                    protocol: port.protocol,
                    port: port.port,
                }));
        }

        let egress = egress_start..self.plan.rules.len();

        let icc_start = self.plan.rules.len();
        if let Some(network) = network {
            // The gateway is the host itself, not another container.
            if let Some(gateway) = network
                .gateway
                .filter(|gateway| same_family(source, *gateway))
            {
                self.plan.rules.push(Rule::AcceptHost(gateway));
            }
            match policy.icc_mode {
                IccMode::Allow => self.plan.rules.push(Rule::AcceptNet(network.subnet)),
                IccMode::Deny => self.deny_icc(network.subnet),
                IccMode::AllowListed => {
                    self.plan_icc_allow_list(source, attachment, &policy.icc_allow);
                    self.deny_icc(network.subnet);
                }
            }
        }
        let icc = icc_start..self.plan.rules.len();

        self.plan.sources.push(Source {
            address: source,
            container: container.name.clone(),
            network: network
                .map(|network| network.name.clone())
                .unwrap_or_default(),
            monitor: self.monitor_all || network.is_some_and(|network| network.monitor),
            mac: attachment.mac_address,
            egress,
            icc,
        });
    }

    /// DNS rules. They only cover DNS leaving the container's network; Docker's DNS server
    /// itself runs inside the container's network namespace and is never filtered.
    fn plan_dns(&mut self, source: IpAddr, targets: &[DnsTarget], container: &Container) {
        let mut allow_any = false;
        self.scratch.clear();
        for target in targets {
            match target {
                // Docker's DNS server forwards from the container's address to the
                // container's `--dns` servers, else to the daemon-wide ones, else to the
                // host's.
                DnsTarget::Docker => {
                    if container.runtime_dns_servers.is_empty() {
                        let daemon_dns = self.state.daemon_dns();
                        self.scratch.extend_from_slice(if daemon_dns.is_empty() {
                            self.host_resolvers
                        } else {
                            daemon_dns
                        });
                    } else {
                        self.scratch
                            .extend(container.runtime_dns_servers.iter().copied());
                    }
                }
                DnsTarget::Host => self.scratch.extend_from_slice(self.host_resolvers),
                DnsTarget::Ip(address) => self.scratch.push(*address),
                DnsTarget::Any => allow_any = true,
                DnsTarget::None => {}
            }
        }

        if allow_any {
            self.plan
                .rules
                .extend(DNS_PROTOCOLS.map(|protocol| Rule::AcceptDns {
                    destination: None,
                    protocol,
                }));
        } else {
            self.scratch
                .retain(|destination| same_family(source, *destination));
            self.scratch.sort_unstable();
            self.scratch.dedup();
            for destination in &self.scratch {
                self.plan
                    .rules
                    .extend(DNS_PROTOCOLS.map(|protocol| Rule::AcceptDns {
                        destination: Some(*destination),
                        protocol,
                    }));
            }
        }

        self.plan
            .rules
            .extend(DNS_PROTOCOLS.map(|protocol| Rule::DenyDns { protocol }));
    }

    /// Deny traffic to other containers of the network: to its subnet, and to broadcast and
    /// multicast addresses, which reach every container on the bridge.
    fn deny_icc(&mut self, subnet: IpNet) {
        self.plan.rules.push(Rule::DenyNet(subnet));
        if subnet.addr().is_ipv4() {
            self.plan
                .rules
                .extend(ICC_BROADCAST_V4.iter().map(|net| Rule::DenyNet(*net)));
        }
    }

    fn plan_icc_allow_list(
        &mut self,
        source: IpAddr,
        attachment: &NetworkAttachment,
        allow_list: &[IccAllowRule],
    ) {
        let state = self.state;
        let targets = self
            .icc_targets
            .get_or_insert_with(|| IccTargets::build(state));

        for rule in allow_list {
            let destinations = targets
                .lookup(
                    attachment.network_id.as_str(),
                    rule.target_container.as_str(),
                )
                .iter()
                .map(|target| target.address)
                .filter(|destination| *destination != source && same_family(source, *destination));

            for destination in destinations {
                self.plan
                    .rules
                    .extend(rule.ports.iter().map(|port| Rule::AcceptPort {
                        destination: Destination::Addr(destination),
                        protocol: port.protocol,
                        port: port.port,
                    }));
            }
        }
    }

    /// Index of the set for `host`. A hostname that can't be resolved gets an empty set,
    /// so its rules allow nothing while the rest of the policy still applies.
    fn host_set(&mut self, host: &'s str) -> usize {
        if let Some(index) = self.host_index.get(host) {
            return *index;
        }

        let normalized = normalize(host);
        let addresses = match self.resolver.addresses(&normalized) {
            Ok(addresses) => addresses,
            Err(error) => {
                error!(%host, %error, "failed to resolve hostname; its rules allow nothing until it resolves");
                Vec::new()
            }
        };
        if addresses.is_empty() {
            self.plan.unresolved_hosts.push(normalized.clone());
        }
        trace!(%host, ip_count = addresses.len(), ?addresses, "known hostname addresses");

        let index = self.plan.host_sets.len();
        self.plan.host_sets.push(HostSet {
            id: HostSetId::for_host(&normalized),
            host: normalized,
            addresses,
            used_v4: false,
            used_v6: false,
        });
        self.host_index.insert(host, index);
        index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct IccTarget<'s> {
    network_id: &'s str,
    key: &'s str,
    address: IpAddr,
}

/// Network-scoped lookup of ICC allow-list targets.
///
/// A target matches by container name or network alias, restricted to the source
/// attachment's network, the way Docker's embedded DNS resolves names. Container IDs are
/// deliberately not matched: they change on every recreate, so they can't be used in labels.
/// A single sorted vector of borrowed keys: one allocation, binary search lookups.
struct IccTargets<'s> {
    entries: Vec<IccTarget<'s>>,
}

impl<'s> IccTargets<'s> {
    fn build(state: &'s RuntimeState) -> Self {
        let mut entries = Vec::new();
        for container in state.containers().values() {
            for attachment in &container.attachments {
                let network_id = attachment.network_id.as_str();
                let address = attachment.ip_address;
                let keys = std::iter::once(container.name.as_str())
                    .chain(attachment.aliases.iter().map(String::as_str));
                entries.extend(keys.map(|key| IccTarget {
                    network_id,
                    key,
                    address,
                }));
            }
        }
        entries.sort_unstable();
        entries.dedup();
        Self { entries }
    }

    fn lookup(&self, network_id: &str, key: &str) -> &[IccTarget<'s>] {
        let start = self
            .entries
            .partition_point(|entry| (entry.network_id, entry.key) < (network_id, key));
        let rest = self.entries.get(start..).unwrap_or_default();
        let len = rest.partition_point(|entry| entry.network_id == network_id && entry.key == key);
        rest.get(..len).unwrap_or_default()
    }
}

const fn same_family(a: IpAddr, b: IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::test_support::{self, MockResolver, ip, net};

    fn build(state: &RuntimeState) -> (Plan, MockResolver) {
        let mut resolver = MockResolver::default();
        let plan = Plan::build(state, &mut resolver, &test_support::host_resolvers(), false);
        (plan, resolver)
    }

    fn source<'p>(plan: &'p Plan, address: &str) -> &'p Source {
        let address = ip(address);
        plan.sources
            .iter()
            .find(|candidate| candidate.address == address)
            .expect("source should be planned")
    }

    fn rules_of(plan: &Plan, address: &str) -> Vec<Rule> {
        plan.egress_rules(source(plan, address)).to_vec()
    }

    fn icc_of(plan: &Plan, address: &str) -> Vec<Rule> {
        plan.icc_rules(source(plan, address)).to_vec()
    }

    #[test]
    fn plans_rules_in_evaluation_order() {
        let (plan, _) = build(&test_support::hostname_state());
        let resolver = ip("9.9.9.9");

        assert_eq!(
            rules_of(&plan, "172.18.0.2"),
            vec![
                Rule::AcceptNet(net("172.18.0.0/16")),
                Rule::AcceptDns {
                    destination: Some(resolver),
                    protocol: Protocol::Udp
                },
                Rule::AcceptDns {
                    destination: Some(resolver),
                    protocol: Protocol::Tcp
                },
                Rule::DenyDns {
                    protocol: Protocol::Udp
                },
                Rule::DenyDns {
                    protocol: Protocol::Tcp
                },
                Rule::AcceptPort {
                    destination: Destination::HostSet(0),
                    protocol: Protocol::Tcp,
                    port: 443
                },
                Rule::AcceptPort {
                    destination: Destination::Net(net("8.8.8.0/24")),
                    protocol: Protocol::Tcp,
                    port: 853
                },
            ]
        );
        assert_eq!(
            icc_of(&plan, "172.18.0.2"),
            vec![
                Rule::AcceptHost(ip("172.18.0.1")),
                Rule::DenyNet(net("172.18.0.0/16")),
                Rule::DenyNet(net("255.255.255.255/32")),
                Rule::DenyNet(net("224.0.0.0/4")),
            ]
        );
        assert_eq!(
            plan.bridges
                .iter()
                .map(|bridge| bridge.name.as_str())
                .collect::<Vec<_>>(),
            vec!["br-net0"]
        );
    }

    fn dns_destinations(state: &RuntimeState, host_resolvers: &[IpAddr]) -> Vec<IpAddr> {
        let plan = Plan::build(state, &mut MockResolver::default(), host_resolvers, false);
        let mut destinations: Vec<_> = rules_of(&plan, "172.18.0.2")
            .into_iter()
            .filter_map(|rule| match rule {
                Rule::AcceptDns {
                    destination: Some(destination),
                    protocol: Protocol::Udp,
                } => Some(destination),
                _ => None,
            })
            .collect();
        destinations.sort_unstable();
        destinations
    }

    fn with_dns(dns_targets: Vec<DnsTarget>, runtime_dns: &[&str]) -> RuntimeState {
        let mut state = test_support::hostname_state();
        let mut web = state.containers().get("abc").cloned().expect("web fixture");
        web.policy.dns_targets = dns_targets;
        web.runtime_dns_servers = runtime_dns.iter().map(|value| ip(value)).collect();
        state.apply_action(crate::model::RuntimeStateAction::CreateContainer {
            container: Box::new(web),
        });
        state
    }

    #[test]
    fn docker_dns_allows_host_resolvers() {
        let state = with_dns(vec![DnsTarget::Docker], &[]);
        assert_eq!(
            dns_destinations(&state, &[ip("9.9.9.9")]),
            vec![ip("9.9.9.9")]
        );
    }

    #[test]
    fn docker_dns_follows_container_dns_servers_instead_of_the_hosts() {
        let state = with_dns(vec![DnsTarget::Docker], &["1.1.1.1"]);
        assert_eq!(
            dns_destinations(&state, &[ip("9.9.9.9")]),
            vec![ip("1.1.1.1")]
        );
    }

    #[test]
    fn none_dns_allows_nothing() {
        let state = with_dns(vec![DnsTarget::None], &["1.1.1.1"]);
        assert!(dns_destinations(&state, &[ip("9.9.9.9")]).is_empty());
    }

    #[test]
    fn docker_dns_follows_daemon_dns_servers() {
        let mut state = with_dns(vec![DnsTarget::Docker], &[]);
        state.set_daemon_dns(vec![ip("10.0.0.53")]);
        assert_eq!(
            dns_destinations(&state, &[ip("9.9.9.9")]),
            vec![ip("10.0.0.53")]
        );
        // The container's own servers still win.
        let mut state = with_dns(vec![DnsTarget::Docker], &["1.1.1.1"]);
        state.set_daemon_dns(vec![ip("10.0.0.53")]);
        assert_eq!(
            dns_destinations(&state, &[ip("9.9.9.9")]),
            vec![ip("1.1.1.1")]
        );
    }

    #[test]
    fn host_dns_allows_host_resolvers_only() {
        let state = with_dns(vec![DnsTarget::Host], &["1.1.1.1"]);
        assert_eq!(
            dns_destinations(&state, &[ip("9.9.9.9")]),
            vec![ip("9.9.9.9")]
        );
    }

    #[test]
    fn plans_each_source_once() {
        let mut state = test_support::hostname_state();
        test_support::add_container(
            &mut state,
            "stale",
            "stale",
            &[("net0", "172.18.0.2", &[])],
            test_support::policy(IccMode::Allow, Vec::new()),
        );
        let (plan, _) = build(&state);
        assert_eq!(plan.sources.len(), 1);
    }

    #[test]
    fn resolves_and_creates_each_hostname_set_once() {
        let (plan, resolver) = build(&test_support::shared_hostname_state());
        assert_eq!(resolver.calls, 1);
        assert_eq!(plan.host_sets.len(), 1);
        assert_eq!(plan.sources.len(), 2);
        for source in &plan.sources {
            assert!(plan.egress_rules(source).contains(&Rule::AcceptPort {
                destination: Destination::HostSet(0),
                protocol: Protocol::Tcp,
                port: 443,
            }));
        }
    }

    #[test]
    fn marks_host_set_families_by_referencing_source() {
        let (plan, _) = build(&test_support::hostname_state());
        let set = plan.host_set(0).expect("host set");
        assert!(set.used_v4);
        assert!(!set.used_v6);

        let (plan, _) = build(&test_support::ipv6_state());
        let set = plan.host_set(0).expect("host set");
        assert!(!set.used_v4);
        assert!(set.used_v6);
    }

    #[test]
    fn icc_allow_accepts_its_network() {
        let (plan, _) = build(&test_support::icc_state());
        assert_eq!(
            icc_of(&plan, "172.18.0.3"),
            vec![
                Rule::AcceptHost(ip("172.18.0.1")),
                Rule::AcceptNet(net("172.18.0.0/16"))
            ]
        );
    }

    #[test]
    fn icc_allow_list_resolves_alias_on_source_network_only() {
        let (plan, _) = build(&test_support::icc_state());
        let accepted: Vec<_> = icc_of(&plan, "172.18.0.2")
            .into_iter()
            .filter_map(|rule| match rule {
                Rule::AcceptPort {
                    destination: Destination::Addr(destination),
                    port,
                    ..
                } => Some((destination, port)),
                _ => None,
            })
            .collect();
        assert_eq!(accepted, vec![(ip("172.18.0.10"), 5432)]);
    }

    #[test]
    fn icc_allow_list_matches_container_name_but_not_id() {
        for (key, matches) in [("project-db-1", true), ("peer", false)] {
            let mut state = test_support::icc_state();
            let mut web = state.containers().get("abc").cloned().expect("web fixture");
            if let Some(rule) = web.policy.icc_allow.first_mut() {
                rule.target_container = key.to_string().into();
            }
            state.apply_action(crate::model::RuntimeStateAction::CreateContainer {
                container: Box::new(web),
            });

            let (plan, _) = build(&state);
            assert_eq!(
                icc_of(&plan, "172.18.0.2").contains(&Rule::AcceptPort {
                    destination: Destination::Addr(ip("172.18.0.10")),
                    protocol: Protocol::Tcp,
                    port: 5432,
                }),
                matches,
                "target {key}"
            );
        }
    }

    #[test]
    fn never_mixes_address_families() {
        let (plan, _) = build(&test_support::ipv6_state());
        let rules = rules_of(&plan, "fd00::2");
        assert!(!rules.iter().any(|rule| matches!(
            rule,
            Rule::AcceptDns {
                destination: Some(IpAddr::V4(_)),
                ..
            }
        )));
        assert!(rules.contains(&Rule::AcceptPort {
            destination: Destination::Net(net("2001:db8::/32")),
            protocol: Protocol::Tcp,
            port: 443,
        }));
    }

    #[test]
    fn unresolvable_hostname_allows_nothing_but_keeps_the_rest() {
        let (plan, _) = build(&test_support::unresolvable_state());
        assert_eq!(plan.unresolved_hosts, vec![test_support::UNRESOLVABLE_HOST]);
        let set = plan.host_set(0).expect("host set");
        assert!(set.addresses.is_empty());
        assert!(set.used_v4);
        let rules = rules_of(&plan, "172.18.0.2");
        assert!(rules.contains(&Rule::AcceptPort {
            destination: Destination::HostSet(0),
            protocol: Protocol::Tcp,
            port: 443,
        }));
        assert!(rules.contains(&Rule::AcceptPort {
            destination: Destination::Net(net("8.8.8.0/24")),
            protocol: Protocol::Tcp,
            port: 853,
        }));
        assert_eq!(
            plan.bridges
                .iter()
                .map(|bridge| bridge.name.as_str())
                .collect::<Vec<_>>(),
            vec!["br-net0"]
        );
    }
}
