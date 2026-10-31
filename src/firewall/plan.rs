//! Backend-agnostic firewall plan.
//!
//! The planner turns [`RuntimeState`] into one ordered rule list per managed source address,
//! the hostname address sets those rules reference, and the enforced network subnets. Both
//! the iptables and the nftables backends only render this plan, so policy semantics live in
//! exactly one place and cannot drift apart.
//!
//! Evaluation model shared by both backends, for traffic forwarded from a container:
//! 1. packets of established or related connections pass;
//! 2. a packet whose source is a managed address is dispatched to that source's rules,
//!    evaluated in order, first match wins, ending with an implicit drop;
//! 3. any other packet from an enforced subnet is dropped;
//! 4. everything else passes.
//!
//! "Pass" and "accept" only mean that this policy doesn't drop the packet; Docker's own
//! rules still apply afterwards.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::ops::Range;
use std::sync::Arc;

use ipnet::IpNet;
use tracing::{error, trace};

use crate::dns::PolicyDnsResolver;
use crate::model::{
    Container, DnsTarget, EgressTarget, IccAllowRule, IccMode, NetworkAttachment, Protocol,
    RuntimeState,
};

pub const DNS_PORT: u16 = 53;
const DNS_PROTOCOLS: [Protocol; 2] = [Protocol::Udp, Protocol::Tcp];

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
    /// Drop any other DNS.
    DropDns { protocol: Protocol },
    /// Allow all traffic to a subnet (ICC allow).
    AcceptNet(IpNet),
    /// Drop all traffic to a subnet (ICC deny).
    DropNet(IpNet),
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
    /// Range into [`Plan::rules`].
    rules: Range<usize>,
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

/// Resolved addresses of one hostname, shared by every rule that targets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSet {
    pub id: HostSetId,
    pub addresses: Arc<[IpAddr]>,
    /// Whether any IPv4 rule references this set.
    pub used_v4: bool,
    /// Whether any IPv6 rule references this set.
    pub used_v6: bool,
}

impl HostSet {
    pub fn v4(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.addresses.iter().copied().filter(IpAddr::is_ipv4)
    }

    pub fn v6(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.addresses.iter().copied().filter(IpAddr::is_ipv6)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Managed source addresses, each listed once.
    pub sources: Vec<Source>,
    /// Rules of all sources, see [`Plan::rules`].
    rules: Vec<Rule>,
    /// Hostname sets, one per distinct hostname.
    pub host_sets: Vec<HostSet>,
    /// Subnets of enforced networks; unmanaged sources in them are dropped.
    pub enforced_subnets: Vec<IpNet>,
}

impl Plan {
    /// Build the plan for `state`, resolving every distinct hostname exactly once.
    /// `host_resolvers` are the host's DNS servers, see [`crate::host_dns`].
    pub fn build<R>(state: &RuntimeState, resolver: &mut R, host_resolvers: &[IpAddr]) -> Self
    where
        R: PolicyDnsResolver,
    {
        let mut planner = Planner {
            state,
            resolver,
            host_resolvers,
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
            .enforced_subnets
            .extend(state.networks().values().map(|network| network.subnet));

        planner.plan
    }

    /// Rules of `source`, in evaluation order. A source's rules end with an implicit drop.
    #[must_use]
    pub fn rules(&self, source: &Source) -> &[Rule] {
        self.rules.get(source.rules.clone()).unwrap_or_default()
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
    R: PolicyDnsResolver,
{
    fn plan_attachment(&mut self, container: &'s Container, attachment: &'s NetworkAttachment) {
        let source = attachment.ip_address;
        // An address can only belong to one container at a time. Should stale state ever
        // contain it twice, the first owner wins, as it would in a linear rule list.
        if !self.seen_sources.insert(source) {
            return;
        }

        let start = self.plan.rules.len();
        let policy = &container.policy;
        let network = self.state.networks().get(&attachment.network_id);

        self.plan_dns(
            source,
            network.and_then(|network| network.gateway),
            &policy.dns_targets,
            container,
        );

        if let Some(network) = network.filter(|network| same_family(source, network.subnet.addr()))
        {
            let subnet = network.subnet;
            match policy.icc_mode {
                IccMode::Allow => self.plan.rules.push(Rule::AcceptNet(subnet)),
                IccMode::Deny => self.plan.rules.push(Rule::DropNet(subnet)),
                IccMode::AllowListed => {
                    self.plan_icc_allow_list(source, attachment, &policy.icc_allow);
                    self.plan.rules.push(Rule::DropNet(subnet));
                }
            }
        }

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

        self.plan.sources.push(Source {
            address: source,
            rules: start..self.plan.rules.len(),
        });
    }

    fn plan_dns(
        &mut self,
        source: IpAddr,
        gateway: Option<IpAddr>,
        targets: &[DnsTarget],
        container: &Container,
    ) {
        let mut allow_any = false;
        self.scratch.clear();
        for target in targets {
            match target {
                // Docker's DNS server forwards from the container's address to the
                // container's `--dns` servers, or to the host's when it has none.
                DnsTarget::Docker => {
                    self.scratch.extend(gateway);
                    if container.runtime_dns_servers.is_empty() {
                        self.scratch.extend_from_slice(self.host_resolvers);
                    } else {
                        self.scratch
                            .extend(container.runtime_dns_servers.iter().copied());
                    }
                }
                DnsTarget::Host => self.scratch.extend_from_slice(self.host_resolvers),
                DnsTarget::Runtime => self
                    .scratch
                    .extend(container.runtime_dns_servers.iter().copied()),
                DnsTarget::Ip(address) => self.scratch.push(*address),
                DnsTarget::Any => allow_any = true,
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
            .extend(DNS_PROTOCOLS.map(|protocol| Rule::DropDns { protocol }));
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

        let addresses = match self.resolver.resolve(host) {
            Ok(addresses) => addresses,
            Err(error) => {
                error!(%host, %error, "failed to resolve hostname; its rules allow nothing until it resolves");
                Arc::from([])
            }
        };
        trace!(%host, ip_count = addresses.len(), ?addresses, "resolved hostname addresses");

        let index = self.plan.host_sets.len();
        self.plan.host_sets.push(HostSet {
            id: HostSetId::for_host(host),
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
        let plan = Plan::build(state, &mut resolver, &[]);
        (plan, resolver)
    }

    fn rules_of(plan: &Plan, source: &str) -> Vec<Rule> {
        let source = ip(source);
        let source = plan
            .sources
            .iter()
            .find(|candidate| candidate.address == source)
            .expect("source should be planned");
        plan.rules(source).to_vec()
    }

    #[test]
    fn plans_rules_in_evaluation_order() {
        let (plan, _) = build(&test_support::hostname_state());
        let gateway = ip("172.18.0.1");

        assert_eq!(
            rules_of(&plan, "172.18.0.2"),
            vec![
                Rule::AcceptDns {
                    destination: Some(gateway),
                    protocol: Protocol::Udp
                },
                Rule::AcceptDns {
                    destination: Some(gateway),
                    protocol: Protocol::Tcp
                },
                Rule::DropDns {
                    protocol: Protocol::Udp
                },
                Rule::DropDns {
                    protocol: Protocol::Tcp
                },
                Rule::DropNet(net("172.18.0.0/16")),
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
        assert_eq!(plan.enforced_subnets, vec![net("172.18.0.0/16")]);
    }

    fn dns_destinations(state: &RuntimeState, host_resolvers: &[IpAddr]) -> Vec<IpAddr> {
        let plan = Plan::build(state, &mut MockResolver::default(), host_resolvers);
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
    fn docker_dns_allows_gateway_and_host_resolvers() {
        let state = with_dns(vec![DnsTarget::Docker], &[]);
        assert_eq!(
            dns_destinations(&state, &[ip("9.9.9.9")]),
            vec![ip("9.9.9.9"), ip("172.18.0.1")]
        );
    }

    #[test]
    fn docker_dns_follows_container_dns_servers_instead_of_the_hosts() {
        let state = with_dns(vec![DnsTarget::Docker], &["1.1.1.1"]);
        assert_eq!(
            dns_destinations(&state, &[ip("9.9.9.9")]),
            vec![ip("1.1.1.1"), ip("172.18.0.1")]
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
            assert!(plan.rules(source).contains(&Rule::AcceptPort {
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
    fn icc_allow_accepts_own_subnet() {
        let (plan, _) = build(&test_support::icc_state());
        assert!(rules_of(&plan, "172.18.0.3").contains(&Rule::AcceptNet(net("172.18.0.0/16"))));
    }

    #[test]
    fn icc_allow_list_resolves_alias_on_source_network_only() {
        let (plan, _) = build(&test_support::icc_state());
        let accepted: Vec<_> = rules_of(&plan, "172.18.0.2")
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
                rules_of(&plan, "172.18.0.2").contains(&Rule::AcceptPort {
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
        assert_eq!(plan.enforced_subnets, vec![net("172.18.0.0/16")]);
    }
}
