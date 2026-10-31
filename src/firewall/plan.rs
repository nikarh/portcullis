//! Backend-agnostic firewall plan.
//!
//! The planner turns [`RuntimeState`] into an ordered list of typed [`Rule`]s plus the
//! hostname address sets they reference. Both the iptables and the nftables backends only
//! render this plan, so policy semantics live in exactly one place and cannot drift apart.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use tracing::trace;

use super::FirewallError;
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

/// A single firewall rule. Rules are evaluated in order, first match wins.
///
/// Every address in a rule has the same family as its `source`; the planner never emits
/// mixed-family rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Allow DNS from `source` to `destination`, or to any destination when `None`.
    AcceptDns {
        source: IpAddr,
        destination: Option<IpAddr>,
        protocol: Protocol,
    },
    /// Drop any other DNS from `source`.
    DropDns { source: IpAddr, protocol: Protocol },
    /// Allow all traffic from `source` to `destination` (ICC allow).
    AcceptNet { source: IpAddr, destination: IpNet },
    /// Drop all traffic from `source` to `destination` (ICC deny).
    DropNet { source: IpAddr, destination: IpNet },
    /// Allow traffic from `source` to `destination` on a single port.
    AcceptPort {
        source: IpAddr,
        destination: Destination,
        protocol: Protocol,
        port: u16,
    },
    /// Default deny for a policy-managed source address.
    DropSource { source: IpAddr },
    /// Baseline deny for an enforced network subnet.
    DropSourceNet { subnet: IpNet },
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
    pub rules: Vec<Rule>,
    /// Hostname sets, one per distinct hostname.
    pub host_sets: Vec<HostSet>,
}

impl Plan {
    /// Build the plan for `state`, resolving every distinct hostname exactly once.
    pub fn build<R>(state: &RuntimeState, resolver: &mut R) -> Result<Self, FirewallError>
    where
        R: PolicyDnsResolver,
    {
        let mut planner = Planner {
            state,
            resolver,
            plan: Self::default(),
            host_index: HashMap::new(),
            icc_targets: None,
            scratch: Vec::new(),
        };

        for container in state.containers().values() {
            for attachment in &container.attachments {
                planner.plan_attachment(container, attachment)?;
            }
        }

        planner.plan.rules.extend(
            state
                .networks()
                .values()
                .map(|network| Rule::DropSourceNet {
                    subnet: network.subnet,
                }),
        );

        Ok(planner.plan)
    }

    #[must_use]
    pub fn host_set(&self, index: usize) -> Option<&HostSet> {
        self.host_sets.get(index)
    }
}

struct Planner<'s, 'r, R> {
    state: &'s RuntimeState,
    resolver: &'r mut R,
    plan: Plan,
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
    fn plan_attachment(
        &mut self,
        container: &'s Container,
        attachment: &'s NetworkAttachment,
    ) -> Result<(), FirewallError> {
        let source = attachment.ip_address;
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
                IccMode::Allow => self.plan.rules.push(Rule::AcceptNet {
                    source,
                    destination: subnet,
                }),
                IccMode::Deny => self.plan.rules.push(Rule::DropNet {
                    source,
                    destination: subnet,
                }),
                IccMode::AllowListed => {
                    self.plan_icc_allow_list(source, attachment, &policy.icc_allow);
                    self.plan.rules.push(Rule::DropNet {
                        source,
                        destination: subnet,
                    });
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
                    let index = self.host_set(host)?;
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
                    source,
                    destination,
                    protocol: port.protocol,
                    port: port.port,
                }));
        }

        self.plan.rules.push(Rule::DropSource { source });
        Ok(())
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
                DnsTarget::Docker => self.scratch.extend(gateway),
                // Host resolvers are not label-driven anymore.
                DnsTarget::Host => {}
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
                    source,
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
                        source,
                        destination: Some(*destination),
                        protocol,
                    }));
            }
        }

        self.plan
            .rules
            .extend(DNS_PROTOCOLS.map(|protocol| Rule::DropDns { source, protocol }));
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
                        source,
                        destination: Destination::Addr(destination),
                        protocol: port.protocol,
                        port: port.port,
                    }));
            }
        }
    }

    fn host_set(&mut self, host: &'s str) -> Result<usize, FirewallError> {
        if let Some(index) = self.host_index.get(host) {
            return Ok(*index);
        }

        let addresses = self
            .resolver
            .resolve(host)
            .map_err(|error| FirewallError::DnsResolve {
                host: host.to_string(),
                message: error.to_string(),
            })?;
        trace!(%host, ip_count = addresses.len(), ?addresses, "resolved hostname addresses");

        let index = self.plan.host_sets.len();
        self.plan.host_sets.push(HostSet {
            id: HostSetId::for_host(host),
            addresses,
            used_v4: false,
            used_v6: false,
        });
        self.host_index.insert(host, index);
        Ok(index)
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
/// A target matches the same way Docker's embedded DNS resolves it from the source
/// container: by container ID, container name or network alias, restricted to the source
/// attachment's network. A single sorted vector of borrowed keys: one allocation, binary
/// search lookups.
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
                let keys = [container.id.as_str(), container.name.as_str()]
                    .into_iter()
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
        let plan = Plan::build(state, &mut resolver).expect("plan should build");
        (plan, resolver)
    }

    fn rules_from(plan: &Plan, source: &str) -> Vec<Rule> {
        let source = ip(source);
        plan.rules
            .iter()
            .copied()
            .filter(|rule| match *rule {
                Rule::AcceptDns { source: s, .. }
                | Rule::DropDns { source: s, .. }
                | Rule::AcceptNet { source: s, .. }
                | Rule::DropNet { source: s, .. }
                | Rule::AcceptPort { source: s, .. }
                | Rule::DropSource { source: s } => s == source,
                Rule::DropSourceNet { .. } => false,
            })
            .collect()
    }

    #[test]
    fn plans_rules_in_evaluation_order() {
        let (plan, _) = build(&test_support::hostname_state());
        let source = ip("172.18.0.2");
        let gateway = ip("172.18.0.1");

        assert_eq!(
            rules_from(&plan, "172.18.0.2"),
            vec![
                Rule::AcceptDns {
                    source,
                    destination: Some(gateway),
                    protocol: Protocol::Udp
                },
                Rule::AcceptDns {
                    source,
                    destination: Some(gateway),
                    protocol: Protocol::Tcp
                },
                Rule::DropDns {
                    source,
                    protocol: Protocol::Udp
                },
                Rule::DropDns {
                    source,
                    protocol: Protocol::Tcp
                },
                Rule::DropNet {
                    source,
                    destination: net("172.18.0.0/16")
                },
                Rule::AcceptPort {
                    source,
                    destination: Destination::HostSet(0),
                    protocol: Protocol::Tcp,
                    port: 443
                },
                Rule::AcceptPort {
                    source,
                    destination: Destination::Net(net("8.8.8.0/24")),
                    protocol: Protocol::Tcp,
                    port: 853
                },
                Rule::DropSource { source },
            ]
        );
        assert_eq!(
            plan.rules.last(),
            Some(&Rule::DropSourceNet {
                subnet: net("172.18.0.0/16")
            })
        );
    }

    #[test]
    fn resolves_and_creates_each_hostname_set_once() {
        let (plan, resolver) = build(&test_support::shared_hostname_state());
        assert_eq!(resolver.calls, 1);
        assert_eq!(plan.host_sets.len(), 1);
        assert_eq!(
            plan.rules
                .iter()
                .filter(|rule| matches!(
                    rule,
                    Rule::AcceptPort {
                        destination: Destination::HostSet(0),
                        ..
                    }
                ))
                .count(),
            2
        );
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
        assert!(rules_from(&plan, "172.18.0.3").contains(&Rule::AcceptNet {
            source: ip("172.18.0.3"),
            destination: net("172.18.0.0/16"),
        }));
    }

    #[test]
    fn icc_allow_list_resolves_alias_on_source_network_only() {
        let (plan, _) = build(&test_support::icc_state());
        let accepted: Vec<_> = rules_from(&plan, "172.18.0.2")
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
    fn icc_allow_list_matches_container_id_and_name() {
        for key in ["peer", "project-db-1"] {
            let mut state = test_support::icc_state();
            let mut web = state.containers().get("abc").cloned().expect("web fixture");
            if let Some(rule) = web.policy.icc_allow.first_mut() {
                rule.target_container = key.to_string().into();
            }
            state.apply_action(crate::model::RuntimeStateAction::CreateContainer {
                container: Box::new(web),
            });

            let (plan, _) = build(&state);
            assert!(
                plan.rules.contains(&Rule::AcceptPort {
                    source: ip("172.18.0.2"),
                    destination: Destination::Addr(ip("172.18.0.10")),
                    protocol: Protocol::Tcp,
                    port: 5432,
                }),
                "target {key} should resolve"
            );
        }
    }

    #[test]
    fn never_mixes_address_families() {
        let (plan, _) = build(&test_support::ipv6_state());
        assert!(!plan.rules.iter().any(|rule| matches!(
            rule,
            Rule::AcceptDns {
                source: IpAddr::V6(_),
                destination: Some(IpAddr::V4(_)),
                ..
            }
        )));
        assert!(plan.rules.contains(&Rule::AcceptPort {
            source: ip("fd00::2"),
            destination: Destination::Net(net("2001:db8::/32")),
            protocol: Protocol::Tcp,
            port: 443,
        }));
    }

    #[test]
    fn reports_resolve_errors() {
        let mut state = test_support::hostname_state();
        let mut web = state.containers().get("abc").cloned().expect("web fixture");
        web.policy.egress = vec![crate::model::EgressRule {
            target: EgressTarget::Hostname("unknown.example.com".to_string()),
            ports: vec![test_support::tcp(443)],
        }];
        state.apply_action(crate::model::RuntimeStateAction::CreateContainer {
            container: Box::new(web),
        });

        let result = Plan::build(&state, &mut MockResolver::default());
        assert!(matches!(result, Err(FirewallError::DnsResolve { .. })));
    }
}
