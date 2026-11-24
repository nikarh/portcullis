//! What the kernel holds after rule updates, compared across ways of putting them in place,
//! rule for rule and byte for byte:
//!
//! - updates over netlink, as Portcullis puts them in place;
//! - the same updates written out as nft scripts, which nft puts in place;
//! - each update's rules from scratch, as nft puts them in place;
//! - each update's rules from scratch, over netlink.
//!
//! For many generated plans and changes to them: every kind of rule, every option, IPv4 and
//! IPv6, monitor mode, containers coming and going, changing their labels, ports and
//! addresses, hostname sets whose addresses change, and restarts that keep the rules or put
//! the saved ones back.
//!
//! Each runs in a network namespace of its own, so these tests need root (and `nft`): run
//! them in the e2e VM with `cargo test -- --ignored kernel` (see `e2e/kernel.sh`).

use std::collections::HashSet;
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;
use std::process::{Command as Process, Stdio};
use std::time::Duration;

use ipnet::IpNet;

use super::elements::TimeoutSet;
use super::netlink::{
    self, Encoder, NFPROTO_BRIDGE, NFPROTO_INET, NFT_MSG_GETCHAIN, NFT_MSG_GETRULE, NFT_MSG_GETSET,
    NFT_MSG_GETSETELEM, NFT_MSG_GETTABLE, NFTA_CHAIN_NAME, NFTA_CHAIN_TABLE, NFTA_LIST_ELEM,
    NFTA_RULE_CHAIN, NFTA_RULE_EXPRESSIONS, NFTA_RULE_TABLE, NFTA_SET_ELEM_LIST_ELEMENTS,
    NFTA_SET_ELEM_LIST_SET, NFTA_SET_ELEM_LIST_TABLE, NFTA_SET_NAME, NFTA_SET_TABLE,
    NFTA_TABLE_NAME, NftSocket,
};
use super::nftables::{
    DenyAction, Found, LogAllowed, NetlinkRunner, NftRunner, NftablesFirewall, Options,
    fresh_batch_with_slots,
};
use super::ruleset::{Batch, TABLE_NAME};
use super::{FirewallError, Plan};
use crate::dns::HostResolver;
use crate::model::{
    BridgePort, ConnectionLimit, Container, ContainerPolicy, DnsTarget, EgressRule, EgressTarget,
    IccAllowRule, IccMode, IccTarget, MacAddress, Network, NetworkAttachment, PortRange, Protocol,
    RuntimeState, RuntimeStateAction, Service,
};
use crate::pattern::NamePattern;

/// Run `run` in a network namespace of its own, on a thread of its own.
fn in_namespace<T: Send + 'static>(run: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(move || {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
            .expect("a network namespace (root only)");
        run()
    })
    .join()
    .expect("the namespace's thread")
}

/// Puts batches in place through `nft -f`, as scripts.
struct NftCli(NetlinkRunner);

fn nft(script: &str) -> Result<(), FirewallError> {
    let mut child = Process::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(FirewallError::Netlink)?;
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(script.as_bytes())
        .map_err(FirewallError::Netlink)?;
    let output = child.wait_with_output().map_err(FirewallError::Netlink)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(FirewallError::Refused {
            command: script.to_string(),
            error: std::io::Error::other("nft failed"),
            reason: Some(String::from_utf8_lossy(&output.stderr).into_owned()),
        })
    }
}

impl NftRunner for NftCli {
    fn run(&self, batch: &Batch) -> Result<(), FirewallError> {
        nft(&batch.to_string())
    }

    fn run_encoded(&self, batch: &mut [u8]) -> Result<(), FirewallError> {
        self.0.run_encoded(batch)
    }

    fn installed(&self) -> Result<Option<Found>, FirewallError> {
        self.0.installed()
    }

    fn set_timeouts(
        &self,
        sets: &[TimeoutSet<'_>],
        addresses: &[(IpAddr, Duration)],
    ) -> Result<(), FirewallError> {
        self.0.set_timeouts(sets, addresses)
    }
}

/// Attributes as `kind=hex`, but those that tell objects apart rather than describe them
/// (handles, positions, when elements expire).
fn attributes(attributes: &[u8], skip: &[u16]) -> String {
    let mut out = String::new();
    for (kind, value) in crate::nfnetlink::attributes(attributes) {
        if skip.contains(&kind) {
            continue;
        }
        let _ = write!(out, " {kind}=");
        for byte in value {
            let _ = write!(out, "{byte:02x}");
        }
    }
    out
}

/// Everything the managed tables hold, one line per object, rule and element, in an order
/// that doesn't depend on how they got there.
#[allow(clippy::too_many_lines)]
fn snapshot() -> Vec<String> {
    const TABLE_HANDLE: u16 = 4;
    const CHAIN_HANDLE: u16 = 2;
    const RULE_HANDLE: u16 = 3;
    const RULE_POSITION: u16 = 6;
    const SET_HANDLE: u16 = 16;
    const ELEMENT_EXPIRATION: u16 = 5;
    let mut socket = NftSocket::open().expect("socket");
    let mut lines = Vec::new();
    for (family, name) in [(NFPROTO_INET, "inet"), (NFPROTO_BRIDGE, "bridge")] {
        let ours = |kind| {
            move |out: &mut netlink::Writer<'_>| {
                if kind != 0 {
                    out.string(kind, TABLE_NAME);
                }
            }
        };
        let mut tables = Vec::new();
        socket
            .dump(NFT_MSG_GETTABLE, family, ours(0), |table| {
                if netlink::string_attribute(table, NFTA_TABLE_NAME) == Some(TABLE_NAME) {
                    tables.push(format!(
                        "table {name}{}",
                        attributes(table, &[TABLE_HANDLE])
                    ));
                }
            })
            .expect("tables");
        if tables.is_empty() {
            continue;
        }
        lines.extend(tables);
        let mut chains = Vec::new();
        socket
            .dump(NFT_MSG_GETCHAIN, family, ours(0), |chain| {
                if netlink::string_attribute(chain, NFTA_CHAIN_TABLE) == Some(TABLE_NAME) {
                    let chain_name = netlink::string_attribute(chain, NFTA_CHAIN_NAME)
                        .unwrap_or_default()
                        .to_string();
                    chains.push((chain_name, attributes(chain, &[CHAIN_HANDLE])));
                }
            })
            .expect("chains");
        chains.sort();
        for (chain, described) in chains {
            lines.push(format!("chain {name} {chain}{described}"));
            let filter = |out: &mut netlink::Writer<'_>| {
                out.string(NFTA_RULE_TABLE, TABLE_NAME);
                out.string(NFTA_RULE_CHAIN, &chain);
            };
            socket
                .dump(NFT_MSG_GETRULE, family, filter, |rule| {
                    let expressions = crate::nfnetlink::attributes(rule)
                        .find(|(kind, _)| *kind == NFTA_RULE_EXPRESSIONS)
                        .map(|(_, value)| value)
                        .unwrap_or_default();
                    lines.push(format!(
                        "  rule {}\n    {}",
                        attributes(rule, &[RULE_HANDLE, RULE_POSITION]),
                        netlink::tests::describe(expressions).join("\n    ")
                    ));
                })
                .expect("rules");
        }
        let mut sets = Vec::new();
        socket
            .dump(NFT_MSG_GETSET, family, ours(NFTA_SET_TABLE), |set| {
                let set_name = netlink::string_attribute(set, NFTA_SET_NAME)
                    .unwrap_or_default()
                    .to_string();
                sets.push((set_name, attributes(set, &[SET_HANDLE])));
            })
            .expect("sets");
        sets.sort();
        for (set, described) in sets {
            lines.push(format!("set {name} {set}{described}"));
            let filter = |out: &mut netlink::Writer<'_>| {
                out.string(NFTA_SET_ELEM_LIST_TABLE, TABLE_NAME);
                out.string(NFTA_SET_ELEM_LIST_SET, &set);
            };
            let mut elements = Vec::new();
            socket
                .dump(NFT_MSG_GETSETELEM, family, filter, |message| {
                    for (kind, list) in crate::nfnetlink::attributes(message) {
                        if kind != NFTA_SET_ELEM_LIST_ELEMENTS {
                            continue;
                        }
                        for (kind, element) in crate::nfnetlink::attributes(list) {
                            if kind == NFTA_LIST_ELEM {
                                elements.push(format!(
                                    "  element{}",
                                    attributes(element, &[ELEMENT_EXPIRATION])
                                ));
                            }
                        }
                    }
                })
                .expect("elements");
            elements.sort();
            lines.extend(elements);
        }
    }
    lines
}

/// Where `ours` and `theirs` differ, for a test failure.
fn difference(ours: &[String], theirs: &[String]) -> Option<String> {
    if ours == theirs {
        return None;
    }
    let mut out = String::new();
    let first = ours
        .iter()
        .zip(theirs)
        .position(|(a, b)| a != b)
        .unwrap_or(ours.len().min(theirs.len()));
    let _ = writeln!(out, "first difference at line {first}:");
    for (label, lines) in [("<", ours), (">", theirs)] {
        for line in lines.iter().skip(first.saturating_sub(2)).take(6) {
            let _ = writeln!(out, "{label} {line}");
        }
    }
    let ours_set: HashSet<_> = ours.iter().collect();
    let theirs_set: HashSet<_> = theirs.iter().collect();
    for line in ours
        .iter()
        .filter(|line| !theirs_set.contains(line))
        .take(10)
    {
        let _ = writeln!(out, "only <: {line}");
    }
    for line in theirs
        .iter()
        .filter(|line| !ours_set.contains(line))
        .take(10)
    {
        let _ = writeln!(out, "only >: {line}");
    }
    Some(out)
}

/// A small deterministic random number generator (xorshift).
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % bound.max(1) as u64).unwrap_or(0)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Resolves hostnames to addresses that change with `variant`.
#[derive(Clone, Copy)]
struct Resolver {
    variant: u8,
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("address")
}

fn net(text: &str) -> IpNet {
    text.parse().expect("network")
}

impl HostResolver for Resolver {
    fn default_hold(&self) -> Duration {
        Duration::from_secs(3600)
    }

    fn addresses(
        &mut self,
        _container: &str,
        host: &str,
        hold: Duration,
    ) -> Vec<(IpAddr, Duration)> {
        let addresses: &[&str] = match (host, self.variant % 3) {
            ("api.example.com", 0) => &["1.1.1.1", "2606:4700::1111"],
            ("api.example.com", 1) => &["1.1.1.1", "1.0.0.1"],
            ("api.example.com", _) => &["2606:4700::1001"],
            ("db.example.net", 0 | 1) => &["192.0.2.10"],
            _ => &[],
        };
        addresses
            .iter()
            .map(|address| (ip(address), hold))
            .collect()
    }

    fn looked_up_before(&self, _host: &str) -> bool {
        true
    }
}

/// A network of a generated state.
#[derive(Clone)]
struct NetworkSpec {
    number: u8,
    monitor: bool,
    ipv6: bool,
}

impl NetworkSpec {
    fn id(&self) -> String {
        format!("net{}", self.number)
    }

    fn address(&self, host: u8) -> IpAddr {
        if self.ipv6 {
            ip(&format!("fd00:{}::{host:x}", self.number))
        } else {
            ip(&format!(
                "172.{}.{}.{host}",
                20 + self.number / 8,
                self.number % 8 * 32
            ))
        }
    }

    fn network(&self) -> Network {
        let (subnet, gateway) = if self.ipv6 {
            (
                net(&format!("fd00:{}::/64", self.number)),
                ip(&format!("fd00:{}::1", self.number)),
            )
        } else {
            (
                net(&format!(
                    "172.{}.{}.0/19",
                    20 + self.number / 8,
                    self.number % 8 * 32
                )),
                self.address(1),
            )
        };
        Network {
            id: self.id().into(),
            name: self.id(),
            subnet,
            gateway: Some(gateway),
            ipv6: self.ipv6,
            bridge: format!("br-{}", self.id()),
            monitor: self.monitor,
        }
    }
}

/// The bridge port state of a generated container.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Port {
    Known,
    Unknown,
    Absent,
}

/// A container of a generated state.
#[derive(Clone)]
struct ContainerSpec {
    number: u16,
    /// Networks (by number) and host part of the address.
    attachments: Vec<(u8, u8)>,
    policy: ContainerPolicy,
    port: Port,
    mac: bool,
    quarantined: bool,
}

impl ContainerSpec {
    fn name(&self) -> String {
        format!("app-{}", self.number)
    }
}

/// A generated state, changed step by step.
#[derive(Clone)]
struct World {
    networks: Vec<NetworkSpec>,
    containers: Vec<ContainerSpec>,
    resolver: Resolver,
    next_container: u16,
    next_host: u8,
}

fn tcp(first: u16, last: u16) -> Service {
    Service::Protocol(Protocol::Tcp, Some(PortRange { first, last }))
}

#[allow(clippy::too_many_lines)]
fn policy(random: &mut Random, names: &[String]) -> ContainerPolicy {
    let egress_pool = [
        EgressRule {
            target: EgressTarget::Hostname(NamePattern::host("api.example.com")),
            services: vec![tcp(443, 443)],
        },
        EgressRule {
            target: EgressTarget::Hostname(NamePattern::host("db.example.net")),
            services: vec![tcp(5432, 5432), Service::Protocol(Protocol::Udp, None)],
        },
        EgressRule {
            target: EgressTarget::Hostname(NamePattern::host("unresolvable.example.com")),
            services: vec![Service::Any],
        },
        EgressRule {
            target: EgressTarget::Hostname(NamePattern::host("*.example.org")),
            services: vec![Service::Protocol(Protocol::Tcp, None)],
        },
        EgressRule {
            target: EgressTarget::IpCidr(net("8.8.8.0/24")),
            services: vec![tcp(853, 853)],
        },
        EgressRule {
            target: EgressTarget::IpCidr(net("10.1.2.3/32")),
            services: vec![Service::Protocol(Protocol::Sctp, None)],
        },
        EgressRule {
            target: EgressTarget::IpCidr(net("192.0.2.0/25")),
            services: vec![Service::Protocol(Protocol::Esp, None), tcp(1, 1024)],
        },
        EgressRule {
            target: EgressTarget::IpCidr(net("2001:db8::/32")),
            services: vec![tcp(443, 443)],
        },
        EgressRule {
            target: EgressTarget::IpCidr(net("2001:db8:1::5/128")),
            services: vec![Service::Any],
        },
        EgressRule {
            target: EgressTarget::PublicAddress,
            services: vec![
                tcp(1024, 65535),
                Service::Protocol(
                    Protocol::Udp,
                    Some(PortRange {
                        first: 3478,
                        last: 3479,
                    }),
                ),
            ],
        },
        EgressRule {
            target: EgressTarget::AnyAddress,
            services: vec![Service::Protocol(Protocol::Icmp, None)],
        },
        EgressRule {
            target: EgressTarget::AnyAddress,
            services: vec![Service::Any],
        },
    ];
    let mut egress = Vec::new();
    for rule in &egress_pool {
        if random.chance(25) {
            egress.push(rule.clone());
        }
    }
    let mut icc_allow = Vec::new();
    if !names.is_empty() && random.chance(50) {
        icc_allow.push(IccAllowRule {
            target: IccTarget::Container(NamePattern::container(random.pick(names))),
            services: vec![*random.pick(&[tcp(5432, 5432), Service::Any, tcp(8000, 8100)])],
        });
    }
    if random.chance(20) {
        icc_allow.push(IccAllowRule {
            target: IccTarget::Container(NamePattern::container("app-*")),
            services: vec![Service::Protocol(Protocol::Udp, None)],
        });
    }
    if random.chance(15) {
        icc_allow.push(IccAllowRule {
            target: IccTarget::Multicast("239.1.2.3/32".parse().expect("group")),
            services: vec![Service::Protocol(
                Protocol::Udp,
                Some(PortRange {
                    first: 5000,
                    last: 5000,
                }),
            )],
        });
    }
    let dns: &[&[DnsTarget]] = &[
        &[DnsTarget::Docker],
        &[DnsTarget::Host],
        &[DnsTarget::Ip(ip("9.9.9.9"))],
        &[DnsTarget::Any],
        &[DnsTarget::None],
        &[DnsTarget::Docker, DnsTarget::Ip(ip("2620:fe::fe"))],
    ];
    ContainerPolicy {
        icc_mode: *random.pick(&[IccMode::Allow, IccMode::Deny, IccMode::AllowListed]),
        egress,
        icc_allow,
        dns_targets: random.pick(dns).to_vec(),
        connection_limit: *random.pick(&[
            ConnectionLimit::Default,
            ConnectionLimit::Unlimited,
            ConnectionLimit::At(100),
        ]),
        new_connection_rate: *random.pick(&[None, None, Some(20), Some(5)]),
        quarantine: random.chance(70),
        domains: random
            .chance(20)
            .then(|| vec![NamePattern::host("api.example.com")]),
        ..ContainerPolicy::default()
    }
}

impl World {
    fn new(random: &mut Random, networks: u8, containers: usize) -> Self {
        let mut world = Self {
            networks: (0..networks)
                .map(|number| NetworkSpec {
                    number,
                    monitor: random.chance(30),
                    ipv6: number > 0 && random.chance(20),
                })
                .collect(),
            containers: Vec::new(),
            resolver: Resolver { variant: 0 },
            next_container: 0,
            next_host: 2,
        };
        for _ in 0..containers {
            world.add_container(random);
        }
        world
    }

    fn names(&self) -> Vec<String> {
        self.containers.iter().map(ContainerSpec::name).collect()
    }

    fn add_container(&mut self, random: &mut Random) {
        if self.networks.is_empty() {
            return;
        }
        let names = self.names();
        let first = random.pick(&self.networks).number;
        let mut attachments = vec![(first, self.next_host)];
        if self.networks.len() > 1 && random.chance(25) {
            let second = random.pick(&self.networks).number;
            if second != first {
                attachments.push((second, self.next_host));
            }
        }
        self.next_host = self.next_host.wrapping_add(1).max(2);
        self.containers.push(ContainerSpec {
            number: self.next_container,
            attachments,
            policy: policy(random, &names),
            port: *random.pick(&[
                Port::Known,
                Port::Known,
                Port::Known,
                Port::Unknown,
                Port::Absent,
            ]),
            mac: random.chance(90),
            quarantined: random.chance(10),
        });
        self.next_container += 1;
    }

    /// A random change, as Docker or a container's labels make them.
    fn change(&mut self, random: &mut Random) {
        match random.below(10) {
            0 | 1 => self.add_container(random),
            2 if !self.containers.is_empty() => {
                let index = random.below(self.containers.len());
                self.containers.remove(index);
            }
            3 if !self.containers.is_empty() => {
                let names = self.names();
                let index = random.below(self.containers.len());
                self.containers[index].policy = policy(random, &names);
            }
            4 if !self.containers.is_empty() => {
                let index = random.below(self.containers.len());
                let container = &mut self.containers[index];
                container.port = *random.pick(&[Port::Known, Port::Unknown, Port::Absent]);
                container.quarantined = random.chance(30);
            }
            5 if !self.networks.is_empty() => {
                let index = random.below(self.networks.len());
                self.networks[index].monitor = !self.networks[index].monitor;
            }
            6 if !self.containers.is_empty() => {
                // Its address goes to a new container.
                let index = random.below(self.containers.len());
                let attachments = self.containers.remove(index).attachments;
                self.add_container(random);
                if let Some(container) = self.containers.last_mut() {
                    container.attachments = attachments;
                }
            }
            7 => self.resolver.variant = self.resolver.variant.wrapping_add(1),
            8 if self.networks.len() > 1 => {
                let index = random.below(self.networks.len());
                let number = self.networks.remove(index).number;
                for container in &mut self.containers {
                    container
                        .attachments
                        .retain(|(network, _)| *network != number);
                }
                self.containers
                    .retain(|container| !container.attachments.is_empty());
            }
            _ => {
                let number = self
                    .networks
                    .iter()
                    .map(|network| network.number)
                    .max()
                    .map_or(0, |max| max + 1);
                self.networks.push(NetworkSpec {
                    number,
                    monitor: random.chance(30),
                    ipv6: random.chance(20),
                });
            }
        }
    }

    fn state(&self) -> RuntimeState {
        let mut state = RuntimeState::default();
        for network in &self.networks {
            state.apply_action(RuntimeStateAction::UpsertNetwork {
                network: network.network(),
            });
        }
        let mut ports = std::collections::HashMap::new();
        let mut portless = HashSet::new();
        for container in &self.containers {
            let attachments = container
                .attachments
                .iter()
                .filter_map(|(number, host)| {
                    let network = self
                        .networks
                        .iter()
                        .find(|network| network.number == *number)?;
                    let address = network.address(*host);
                    let mac = match address {
                        IpAddr::V4(v4) if container.mac => {
                            let [a, b, c, d] = v4.octets();
                            Some(MacAddress::from([0x02, 0x42, a, b, c, d]))
                        }
                        _ => None,
                    };
                    Some(NetworkAttachment {
                        network_id: network.id().into(),
                        ip_address: address,
                        mac_address: mac,
                        aliases: vec![format!("alias-{}", container.number % 3)],
                    })
                })
                .collect::<Vec<_>>();
            for attachment in &attachments {
                match container.port {
                    Port::Known => {
                        ports.insert(
                            attachment.ip_address,
                            BridgePort {
                                name: format!(
                                    "veth{}x{}",
                                    container.number,
                                    u8::from(attachment.ip_address.is_ipv6())
                                ),
                                index: u32::from(container.number) + 10,
                            },
                        );
                    }
                    Port::Absent => {
                        portless.insert(attachment.ip_address);
                    }
                    Port::Unknown => {}
                }
            }
            let id = format!("c{}", container.number);
            state.apply_action(RuntimeStateAction::CreateContainer {
                container: Box::new(Container {
                    id: id.clone().into(),
                    name: container.name().into(),
                    attachments,
                    runtime_dns_servers: HashSet::new(),
                    policy: container.policy.clone(),
                    sandbox: None,
                }),
            });
            if container.quarantined {
                state.quarantine(&id.into());
            }
        }
        state.set_ports(ports, portless);
        state
    }
}

/// How a scenario's firewall restarts before a step.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Restart {
    None,
    /// A new run finds the rules in place and keeps them.
    Kept,
    /// The tables are gone (a reboot), and a new run puts the saved rules back.
    Saved,
}

/// A generated scenario: options, and the states of each step with how it starts.
struct Scenario {
    options: Options,
    monitor_all: bool,
    steps: Vec<(World, Restart)>,
}

fn option_sets() -> Vec<Options> {
    vec![
        Options::default(),
        Options {
            deny: DenyAction::Reject,
            log_group: 7,
            log_allowed: LogAllowed::Always,
            dns_queue: Some(3),
            source_queue: Some(4),
            monitor_source_queue: Some(5),
            connection_limit: Some(1000),
            dns_query_queue: Some(6),
        },
        Options {
            deny: DenyAction::Drop,
            log_group: 2,
            log_allowed: LogAllowed::Never,
            dns_queue: Some(3),
            source_queue: None,
            monitor_source_queue: Some(5),
            connection_limit: None,
            dns_query_queue: None,
        },
        Options {
            deny: DenyAction::Drop,
            log_allowed: LogAllowed::Always,
            source_queue: Some(4),
            ..Options::default()
        },
    ]
}

fn scenarios(seed: u64, count: usize, containers: usize, steps: usize) -> Vec<Scenario> {
    let mut random = Random(seed);
    let options = option_sets();
    (0..count)
        .map(|index| {
            let networks = 1 + u8::try_from(random.next() % 3).unwrap_or(0);
            let mut world = World::new(&mut random, networks, containers);
            let mut all = vec![(world.clone(), Restart::None)];
            for step in 1..steps {
                for _ in 0..=random.below(3) {
                    world.change(&mut random);
                }
                let restart = match (step, random.below(8)) {
                    (_, 0) => Restart::Kept,
                    (_, 1) => Restart::Saved,
                    _ => Restart::None,
                };
                if restart == Restart::Kept {
                    // Kept hostname sets keep what they hold: their addresses mustn't
                    // change at the same step for them to match a fresh start.
                    world.resolver = all.last().map_or(world.resolver, |(last, _)| last.resolver);
                }
                all.push((world.clone(), restart));
            }
            Scenario {
                options: options[index % options.len()],
                monitor_all: random.chance(15),
                steps: all,
            }
        })
        .collect()
}

/// Apply the steps of `scenario` as Portcullis does, with the runner `new` makes; a
/// snapshot of the tables after each.
/// The slot of each source after each step, which numbers its chains.
type Slots = Vec<std::collections::BTreeMap<IpAddr, usize>>;

fn incremental<R: NftRunner>(
    scenario: &Scenario,
    saved: &std::path::Path,
    new: impl Fn() -> R,
) -> (Vec<Vec<String>>, Slots) {
    let firewall = || NftablesFirewall::new(new(), scenario.options).saving_to(saved.to_path_buf());
    let mut current = firewall();
    let mut snapshots = Vec::new();
    let mut slots = Vec::new();
    for (index, (world, restart)) in scenario.steps.iter().enumerate() {
        match restart {
            Restart::None => {}
            Restart::Kept => {
                current = firewall();
                current.restore().expect("restore kept rules");
            }
            Restart::Saved => {
                current.cleanup().expect("cleanup");
                current = firewall();
                current.restore().expect("restore saved rules");
            }
        }
        let plan = current
            .apply(
                &world.state(),
                &mut world.resolver.clone(),
                &[ip("9.9.9.9")],
                scenario.monitor_all,
            )
            .unwrap_or_else(|error| panic!("step {index}: {error}"));
        current.save(&plan).expect("save");
        snapshots.push(snapshot());
        slots.push(current.slots());
    }
    (snapshots, slots)
}

/// Each step's rules from scratch, as nft (`script`) or netlink puts them in place, with
/// sources' chains numbered as the updates numbered them (an update keeps a source's
/// number, starting from scratch numbers them in order).
fn fresh(scenario: &Scenario, slots: &Slots, script: bool) -> Vec<Vec<String>> {
    let mut socket = NftSocket::open().expect("socket");
    let mut buffer = Vec::new();
    scenario
        .steps
        .iter()
        .enumerate()
        .zip(slots)
        .map(|((index, (world, _)), slots)| {
            let plan = Plan::build(
                &world.state(),
                &mut world.resolver.clone(),
                &[ip("9.9.9.9")],
                scenario.monitor_all,
            );
            let batch = fresh_batch_with_slots(&plan, scenario.options, slots);
            if script {
                nft(&batch.to_string()).unwrap_or_else(|error| panic!("step {index}: {error}"));
            } else {
                Encoder::new(&mut buffer).batch(&batch);
                socket
                    .send_batch(&mut buffer)
                    .unwrap_or_else(|refusal| panic!("step {index}: {refusal:?}"));
            }
            snapshot()
        })
        .collect()
}

/// What the scenarios must have put in place, so that every kind of rule and set was
/// compared.
const COVERED: &[&str] = &[
    "set sources_by_port",
    "set sources_by_mac",
    "set sources_by_address",
    "set arp_by_port",
    "set arp_by_mac",
    "set arp_by_address",
    "set egress6",
    "set name_limited",
    "set ports_conns100 ",
    "set ports_new5_monitor",
    "set pc_h6_",
    "connlimit count 100 flags 1",
    "limit rate 20/second burst 20 type packets flags 0x1",
    "limit rate 10/second burst 5 type packets flags 0x0",
    "reject type 1 code 0",
    "reject type 2 code 3",
    "queue num 3 bypass",
    "queue num 4",
    "queue num 6",
    "fib daddr type",
    "ct load dst_ip6",
    "ct load src_ip6",
    "range eq reg 1",
    "range neq reg 1",
    "payload load 16b @ network header + 28",
    "meta load iiftype",
    "meta set mark",
    "jump -> arp_check_monitor",
    "goto -> limit_rate",
    "chain bridge icc",
    "lookup reg 1 set enforced_ports",
    "lookup reg 1 set monitored_ports",
    "lookup reg 1 set quarantined",
];

fn compare(scenarios: Vec<Scenario>, covered: &[&str]) {
    // One directory per comparison: the tests run at once, and each removes its own.
    static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let mut seen = vec![false; covered.len()];
    let run = RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("portcullis-kernel-{}-{run}", std::process::id()));
    let mut failures = Vec::new();
    let mut steps = 0;
    for (number, scenario) in scenarios.into_iter().enumerate() {
        let scenario = std::sync::Arc::new(scenario);
        let incremental_run = |script: bool| {
            let scenario = scenario.clone();
            let saved = root.join(format!("{number}-{script}/rules.batch"));
            std::thread::spawn(move || {
                in_namespace(move || {
                    if script {
                        incremental(&scenario, &saved, || {
                            NftCli(NetlinkRunner::new().expect("runner"))
                        })
                    } else {
                        incremental(&scenario, &saved, || NetlinkRunner::new().expect("runner"))
                    }
                })
            })
        };
        let (netlink, slots) = incremental_run(false).join().expect("netlink");
        let script = incremental_run(true);
        let slots = std::sync::Arc::new(slots);
        let fresh_run = |script: bool| {
            let scenario = scenario.clone();
            let slots = slots.clone();
            std::thread::spawn(move || in_namespace(move || fresh(&scenario, &slots, script)))
        };
        let (nft_fresh, netlink_fresh) = (fresh_run(true), fresh_run(false));
        let (script, _) = script.join().expect("nft");
        let nft_fresh = nft_fresh.join().expect("nft from scratch");
        let netlink_fresh = netlink_fresh.join().expect("netlink from scratch");
        for snapshot in &netlink {
            for line in snapshot {
                for (needle, seen) in covered.iter().zip(&mut seen) {
                    *seen |= line.contains(needle);
                }
            }
        }
        for step in 0..netlink.len() {
            steps += 1;
            for (label, theirs) in [
                ("nft running the same updates", &script[step]),
                (
                    "nft putting the rules in place from scratch",
                    &nft_fresh[step],
                ),
                (
                    "netlink putting the rules in place from scratch",
                    &netlink_fresh[step],
                ),
            ] {
                if let Some(difference) = difference(&netlink[step], theirs) {
                    failures.push(format!(
                        "scenario {number}, step {step}: updates over netlink (<) differ from {label} (>):\n{difference}"
                    ));
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        failures.is_empty(),
        "{} comparisons of {steps} steps differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
    let missed: Vec<_> = covered
        .iter()
        .zip(&seen)
        .filter_map(|(needle, seen)| (!seen).then_some(needle))
        .collect();
    assert!(missed.is_empty(), "nothing compared had {missed:?}");
    tracing::info!(steps, "the kernel holds the same rules, sets and elements");
}

#[test]
#[ignore = "needs root and nft: run in the e2e VM (e2e/kernel.sh)"]
fn kernel_holds_the_same_rules_after_netlink_and_nft() {
    compare(scenarios(0x5eed_0001, 48, 6, 8), COVERED);
}

#[test]
#[ignore = "needs root and nft: run in the e2e VM (e2e/kernel.sh)"]
fn kernel_holds_the_same_rules_with_many_containers() {
    compare(scenarios(0x5eed_0002, 4, 120, 5), &[]);
}
