use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fmt::{self, Write as _};
use std::net::IpAddr;
use std::ptr::NonNull;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tracing::{info, trace};

use super::FirewallError;
use super::plan::{
    DNS_PORT, Destination, HostSet, Plan, Rule, SET_PREFIX_V4, SET_PREFIX_V6, Source,
};
use crate::dns::HostResolver;
use crate::model::{ContainerName, RuntimeState};

/// Name of both managed tables.
const TABLE_NAME: &str = "portcullis";
/// Priority of all base chains: before Docker's filter chains.
const HOOK_PRIORITY: i32 = -1;

/// The managed tables: `inet` sees traffic routed out of a container's network (forward
/// hook) and traffic to the host itself (input hook), `bridge` sees traffic between containers on the same network, which a bridge
/// switches without passing the IP hooks unless `br_netfilter` is loaded (prerouting hook:
/// the bridge family only supports `reject` there).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Table {
    Inet,
    Bridge,
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inet => write!(f, "inet {TABLE_NAME}"),
            Self::Bridge => write!(f, "bridge {TABLE_NAME}"),
        }
    }
}

/// A chain, displayed as `<family> <table> <chain>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chain {
    /// The base chain of a table.
    Base(Table),
    /// Base chain of the inet table for traffic addressed to the host itself.
    Input,
    /// Egress rules of the n-th source, in the inet table.
    Egress(usize),
    /// ICC rules of the n-th source, in the bridge table.
    Icc(usize),
}

impl Table {
    const fn hook(self) -> &'static str {
        match self {
            Self::Inet => "forward",
            Self::Bridge => "prerouting",
        }
    }
}

impl Chain {
    const fn table(self) -> Table {
        match self {
            Self::Base(table) => table,
            Self::Input | Self::Egress(_) => Table::Inet,
            Self::Icc(_) => Table::Bridge,
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.table(), ChainName(*self))
    }
}

/// The chain name alone, as used in jump targets.
struct ChainName(Chain);

impl fmt::Display for ChainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Chain::Base(table) => f.write_str(table.hook()),
            Chain::Input => f.write_str("input"),
            Chain::Egress(index) => write!(f, "egress{index}"),
            Chain::Icc(index) => write!(f, "icc{index}"),
        }
    }
}

pub trait NftRunner {
    /// Run an nft script as a single atomic transaction.
    fn run_script(&self, script: String) -> Result<(), FirewallError>;
}

/// What happens to traffic a policy doesn't allow.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DenyAction {
    /// Answer with an ICMP "administratively prohibited" error, so clients fail at once.
    #[default]
    Reject,
    /// Discard silently; clients wait for their own timeout.
    Drop,
}

impl fmt::Display for DenyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Reject => "reject with icmpx admin-prohibited",
            Self::Drop => "drop",
        })
    }
}

/// How rules decide and report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub deny: DenyAction,
    /// NFLOG group decisions are logged to.
    pub log_group: u16,
    /// Which allowed new connections are logged; denied ones always are.
    pub log_allowed: LogAllowed,
    /// NFQUEUE number DNS answers to managed containers are held in for inspection.
    pub dns_queue: Option<u16>,
    /// NFQUEUE number packets from not yet known sources on enforced networks are held in
    /// until the next rule update, instead of being denied. See `source_hold`.
    pub source_queue: Option<u16>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            deny: DenyAction::Reject,
            log_group: 1,
            log_allowed: LogAllowed::Monitor,
            dns_queue: None,
            source_queue: None,
        }
    }
}

/// Packet mark of held packets whose source stayed unknown: they are denied when they come
/// back.
pub const HOLD_EXPIRED_MARK: u32 = 0x7063_0001;

/// Which allowed connections are reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogAllowed {
    Always,
    /// Only on networks in monitor mode, to show everything a policy will need.
    #[default]
    Monitor,
    Never,
}

impl LogAllowed {
    /// Whether allowed traffic of a source in (or not in) monitor mode is reported.
    #[must_use]
    pub const fn logs(self, monitor: bool) -> bool {
        match self {
            Self::Always => true,
            Self::Monitor => monitor,
            Self::Never => false,
        }
    }
}

/// Log prefix of a decision: `pc:<a|d|w>:<reason>`, see `connection_log`.
pub const LOG_PREFIX: &str = "pc";

/// Bytes of each logged packet copied to userspace: enough for IP and TCP/UDP headers.
const LOG_SNAPLEN: u16 = 128;
/// Bytes copied of denied DNS queries, so their name can be reported.
const LOG_SNAPLEN_DNS: u16 = 512;

pub struct NftablesFirewall<R = LibNftablesRunner> {
    runner: R,
    options: Options,
    /// What the last successful update installed; `None` before the first one and after a
    /// cleanup, when the tables may hold leftovers of another run.
    installed: Mutex<Option<Installed>>,
}

/// Chains and sets an update created besides the fixed base chains and log sets, as
/// `<family> <table> <name>`. The next update deletes the ones it doesn't need anymore.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Installed {
    chains: BTreeSet<String>,
    sets: BTreeSet<String>,
    /// The container of each managed address.
    sources: BTreeMap<IpAddr, ContainerName>,
}

impl<R> NftablesFirewall<R>
where
    R: NftRunner,
{
    pub const fn new(runner: R, options: Options) -> Self {
        Self {
            runner,
            options,
            installed: Mutex::new(None),
        }
    }

    /// Apply rules for `state`. Returns the plan that was applied.
    pub fn apply<Hosts>(
        &self,
        state: &RuntimeState,
        hosts: &mut Hosts,
        host_resolvers: &[IpAddr],
        monitor_all: bool,
    ) -> Result<Plan, FirewallError>
    where
        Hosts: HostResolver,
    {
        let plan = Plan::build(state, hosts, host_resolvers, monitor_all);
        info!(
            source_count = plan.sources.len(),
            rule_count = plan.rule_count(),
            host_set_count = plan.host_sets.len(),
            container_count = state.containers().len(),
            "applying nftables changes"
        );

        let mut installed = self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut script = String::with_capacity(plan.rule_count() * 96);
        let now_installed =
            render_apply_script(&plan, self.options, installed.as_ref(), &mut script)?;
        self.runner.run_script(script)?;
        *installed = Some(now_installed);
        Ok(plan)
    }

    /// Allow more addresses for a hostname set of the current rules.
    pub fn add_host_addresses(
        &self,
        set: &HostSet,
        addresses: &[(IpAddr, Duration)],
    ) -> Result<(), FirewallError> {
        let mut script = String::new();
        for (prefix, used, is_family) in [
            (
                SET_PREFIX_V4,
                set.used_v4,
                IpAddr::is_ipv4 as fn(&IpAddr) -> bool,
            ),
            (SET_PREFIX_V6, set.used_v6, IpAddr::is_ipv6),
        ] {
            if !used {
                continue;
            }
            render_elements(
                &mut script,
                format_args!("add element {} {}", Table::Inet, set.id.name(prefix)),
                addresses
                    .iter()
                    .filter(|(address, _)| is_family(address))
                    .map(|(address, timeout)| Timed(*address, *timeout)),
                "",
            )?;
        }
        if script.is_empty() {
            return Ok(());
        }
        self.runner.run_script(script)
    }

    pub fn cleanup(&self) -> Result<(), FirewallError> {
        let mut script = String::new();
        render_table_reset(&mut script)?;
        self.runner.run_script(script)?;
        *self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        info!("nftables cleanup completed");
        Ok(())
    }
}

impl NftablesFirewall<LibNftablesRunner> {
    pub fn with_libnftables(options: Options) -> Result<Self, FirewallError> {
        let runner = LibNftablesRunner::new()?;
        Ok(Self::new(runner, options))
    }
}

/// Remove the managed tables. The `add` makes the `delete` succeed whether or not a table
/// exists, so neither cleanup nor apply depend on prior state or on matching error strings.
fn render_table_reset(out: &mut String) -> fmt::Result {
    for table in [Table::Inet, Table::Bridge] {
        writeln!(out, "add table {table}")?;
        writeln!(out, "delete table {table}")?;
    }
    Ok(())
}

/// What a rule does with matching traffic, and how it reports it.
#[derive(Debug, Clone, Copy)]
struct Outcome {
    options: Options,
    allow: bool,
    /// Monitor mode: a deny becomes a logged accept.
    monitor: bool,
    /// What to report, if anything; denials are always reported.
    reason: Option<&'static str>,
    snaplen: u16,
    /// The traffic is IPv6 (for the de-duplication key).
    ipv6: bool,
}

impl Outcome {
    const fn allow(options: Options, monitor: bool, reason: Option<&'static str>) -> Self {
        Self {
            options,
            allow: true,
            monitor,
            reason,
            snaplen: LOG_SNAPLEN,
            ipv6: false,
        }
    }

    const fn deny(options: Options, monitor: bool, reason: &'static str) -> Self {
        Self {
            options,
            allow: false,
            monitor,
            reason: Some(reason),
            snaplen: LOG_SNAPLEN,
            ipv6: false,
        }
    }

    const fn snaplen(mut self, snaplen: u16) -> Self {
        self.snaplen = snaplen;
        self
    }

    const fn for_address(mut self, address: IpAddr) -> Self {
        self.ipv6 = address.is_ipv6();
        self
    }

    /// The log prefix, if this outcome is reported.
    fn log_prefix(&self) -> Option<(char, &'static str)> {
        let (verdict, log) = match (self.allow, self.monitor) {
            (true, monitor) => ('a', self.options.log_allowed.logs(monitor)),
            (false, false) => ('d', true),
            (false, true) => ('w', true),
        };
        self.reason.filter(|_| log).map(|reason| (verdict, reason))
    }
}

/// The verdict alone.
impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.allow || self.monitor {
            f.write_str("accept")
        } else {
            write!(f, "{}", self.options.deny)
        }
    }
}

/// Recently reported flows: (source, destination, protocol, port), one set per address
/// family and table. A flow is reported once per timeout, however many packets it sends.
const LOGGED_SET_V4: &str = "logged4";
const LOGGED_SET_V6: &str = "logged6";
const LOGGED_TIMEOUT: &str = "60s";
const LOGGED_SIZE: u32 = 65_536;

/// Create the sets of reported flows; with `flush`, forget the flows reported so far.
fn render_logged_sets(out: &mut String, table: Table, flush: bool) -> fmt::Result {
    let families: &[(&str, &str)] = match table {
        Table::Inet => &[(LOGGED_SET_V4, "ipv4_addr"), (LOGGED_SET_V6, "ipv6_addr")],
        Table::Bridge => &[(LOGGED_SET_V4, "ipv4_addr")],
    };
    for (name, address) in families {
        writeln!(
            out,
            "add set {table} {name} {{ type {address} . {address} . inet_proto . inet_service; flags dynamic,timeout; timeout {LOGGED_TIMEOUT}; size {LOGGED_SIZE}; }}"
        )?;
        if flush {
            writeln!(out, "flush set {table} {name}")?;
        }
    }
    Ok(())
}

/// Render a decision: `head` (`add rule <chain> <match>`) followed by the outcome. A
/// reported outcome gets a rule before it that logs the packet, but only the first of its
/// flow within the de-duplication timeout; the verdict rule applies to every packet.
fn decide(out: &mut String, head: fmt::Arguments<'_>, outcome: Outcome) -> fmt::Result {
    if let Some((verdict, reason)) = outcome.log_prefix() {
        let (set, ip) = if outcome.ipv6 {
            (LOGGED_SET_V6, "ip6")
        } else {
            (LOGGED_SET_V4, "ip")
        };
        let key = format_args!("{ip} saddr . {ip} daddr . meta l4proto . th dport");
        writeln!(
            out,
            "{head} {key} != @{set} add @{set} {{ {key} }} log prefix \"{LOG_PREFIX}:{verdict}:{reason}\" group {} snaplen {}",
            outcome.options.log_group, outcome.snaplen
        )?;
    }
    writeln!(out, "{head} {outcome}")
}

/// `{ e1, e2, ... }`, or `None` without elements.
fn set_literal<T: fmt::Display>(elements: impl Iterator<Item = T>) -> Option<String> {
    let mut literal = String::new();
    for (index, element) in elements.enumerate() {
        literal.push_str(if index == 0 { "{ " } else { ", " });
        let _ = write!(literal, "{element}");
    }
    if literal.is_empty() {
        return None;
    }
    literal.push_str(" }");
    Some(literal)
}

/// Render the script of a rule update.
///
/// Each table has a base chain that lets established traffic through and dispatches each
/// managed source address through a verdict map to its own chain. A packet costs one hash
/// lookup plus the rules of its own source, regardless of how many containers are managed.
///
/// The tables, base chains and log sets are created once and kept: an update flushes and
/// refills chains and sets, and deletes those of the previous update it doesn't need, in
/// one atomic transaction. Deleting a base chain would unregister its hook, and the kernel
/// drops every packet held in a queue from that hook: DNS answers being inspected, and
/// packets of new containers waiting for their rules. Only the first update, without
/// `previous`, starts from empty tables, removing whatever a previous run left behind.
fn render_apply_script(
    plan: &Plan,
    options: Options,
    previous: Option<&Installed>,
    out: &mut String,
) -> Result<Installed, fmt::Error> {
    let empty = Installed::default();
    let previous = if let Some(previous) = previous {
        previous
    } else {
        render_table_reset(out)?;
        &empty
    };
    // Flows are remembered by address: when an address goes to another container, or to
    // none, its flows must be reported again.
    let sources: BTreeMap<IpAddr, ContainerName> = plan
        .sources
        .iter()
        .map(|source| (source.address, source.container.clone()))
        .collect();
    let reassigned = previous
        .sources
        .iter()
        .any(|(address, container)| sources.get(address) != Some(container));
    for table in [Table::Inet, Table::Bridge] {
        writeln!(out, "add table {table}")?;
        render_base_chain(out, Chain::Base(table), table.hook())?;
        if table == Table::Inet {
            render_base_chain(out, Chain::Input, "input")?;
            writeln!(out, "flush chain {}", Chain::Input)?;
        }
        render_logged_sets(out, table, reassigned)?;
        writeln!(out, "flush chain {}", Chain::Base(table))?;
    }

    let mut installed = render_objects(out, plan, options, previous)?;
    installed.sources = sources;
    let ipv4_sources = || {
        plan.sources
            .iter()
            .enumerate()
            .filter(|(_, source)| source.address.is_ipv4())
    };

    // Routed traffic.
    let base = Chain::Base(Table::Inet);
    if let Some(queue) = options.dns_queue {
        // Hold DNS answers to managed containers until the addresses they contain are
        // allowed. `bypass` lets them through when Portcullis isn't listening.
        render_elements(
            out,
            format_args!("add rule {base} oifname"),
            plan.bridges.iter().map(|bridge| Quoted(&bridge.name)),
            format_args!(
                " meta l4proto {{ tcp, udp }} th sport {DNS_PORT} ct direction reply queue num {queue} bypass"
            ),
        )?;
    }
    // Traffic to the host itself (services on the host, and other containers' published
    // ports through Docker's userland proxy) leaves the container's network as much as
    // routed traffic does, and follows the same rules.
    for base in [base, Chain::Input] {
        render_egress_dispatch(out, plan, options, base)?;
    }
    for (index, source) in plan.sources.iter().enumerate() {
        let chain = Chain::Egress(index);
        for rule in plan.egress_rules(source) {
            render_rule(plan, source, chain, rule, options, out)?;
        }
        decide(
            out,
            format_args!("add rule {chain}"),
            Outcome::deny(options, source.monitor, "egress").for_address(source.address),
        )?;
    }

    // Everything entering a managed network's bridge from a container: source checks and
    // traffic between containers on the same network.
    writeln!(
        out,
        "add rule {} ct state established,related accept",
        Chain::Base(Table::Bridge)
    )?;
    if !plan.bridges.is_empty() {
        render_bridge_dispatch(out, plan, options)?;
    }
    for (index, source) in ipv4_sources() {
        if icc_chain_needed(plan, source, options) {
            let chain = Chain::Icc(index);
            for rule in plan.icc_rules(source) {
                render_rule(plan, source, chain, rule, options, out)?;
            }
        }
    }
    Ok(installed)
}

/// Send traffic from containers through their egress chains, from `base`.
fn render_egress_dispatch(
    out: &mut String,
    plan: &Plan,
    options: Options,
    base: Chain,
) -> fmt::Result {
    writeln!(out, "add rule {base} ct state established,related accept")?;
    for (family, is_family) in FAMILIES {
        let entries = plan
            .sources
            .iter()
            .enumerate()
            .filter(|(_, source)| is_family(&source.address))
            .map(|(index, source)| Dispatch(source.address, Verdict::Goto(Chain::Egress(index))));
        render_elements(
            out,
            format_args!("add rule {base} {family} saddr vmap"),
            entries,
            "",
        )?;
    }
    // Unknown or spoofed sources of enforced networks; the bridge table already reported
    // them.
    render_elements(
        out,
        format_args!("add rule {base} iifname"),
        plan.bridges
            .iter()
            .filter(|bridge| !bridge.monitor)
            .map(|bridge| Quoted(&bridge.name)),
        format_args!(" {}", options.deny),
    )
}

/// Create or flush the chains and sets of `plan`, and remove those of `previous` it doesn't
/// need. Returns what is installed afterwards.
fn render_objects(
    out: &mut String,
    plan: &Plan,
    options: Options,
    previous: &Installed,
) -> Result<Installed, fmt::Error> {
    let mut installed = Installed::default();
    // Containers are only managed by their IPv4 address on the bridge; see the IPv6
    // limitation.
    let ipv4_sources = || {
        plan.sources
            .iter()
            .enumerate()
            .filter(|(_, source)| source.address.is_ipv4())
    };
    let chains = plan
        .sources
        .iter()
        .enumerate()
        .map(|(index, _)| Chain::Egress(index))
        .chain(
            ipv4_sources()
                .filter(|(_, source)| icc_chain_needed(plan, source, options))
                .map(|(index, _)| Chain::Icc(index)),
        );
    for chain in chains {
        writeln!(out, "add chain {chain}")?;
        writeln!(out, "flush chain {chain}")?;
        installed.chains.insert(chain.to_string());
    }
    for set in &plan.host_sets {
        if set.used_v4 {
            installed
                .sets
                .insert(render_set(out, set, SET_PREFIX_V4, "ipv4_addr", set.v4())?);
        }
        if set.used_v6 {
            installed
                .sets
                .insert(render_set(out, set, SET_PREFIX_V6, "ipv6_addr", set.v6())?);
        }
    }
    // Nothing references them anymore: the chains that did were flushed above.
    for chain in previous.chains.difference(&installed.chains) {
        writeln!(out, "flush chain {chain}")?;
        writeln!(out, "delete chain {chain}")?;
    }
    for set in previous.sets.difference(&installed.sets) {
        writeln!(out, "delete set {set}")?;
    }

    Ok(installed)
}

/// Whether `source` needs its own ICC chain: anything beyond "allow everything" without
/// reporting it.
fn icc_chain_needed(plan: &Plan, source: &Source, options: Options) -> bool {
    options.log_allowed.logs(source.monitor)
        || plan
            .icc_rules(source)
            .iter()
            .any(|rule| !matches!(rule, Rule::AcceptHost(_) | Rule::AcceptNet(_)))
}

/// nftables keyword of an address family, and whether an address belongs to it.
type Family = (&'static str, fn(&IpAddr) -> bool);

const FAMILIES: [Family; 2] = [("ip", IpAddr::is_ipv4), ("ip6", IpAddr::is_ipv6)];

fn render_base_chain(out: &mut String, chain: Chain, hook: &str) -> fmt::Result {
    writeln!(
        out,
        "add chain {chain} {{ type filter hook {hook} priority {HOOK_PRIORITY}; policy accept; }}"
    )
}

/// Bridge base chain: only frames entering a managed network's bridge are checked. An
/// IPv4 frame passes only when its source address belongs to a managed container and comes
/// with that container's MAC; it then continues to the container's ICC rules, if any.
/// Everything else IPv4 is denied, which stops containers from using addresses that aren't
/// theirs; with a source queue, it is held first, in case it comes from a container whose
/// rules aren't applied yet (see `source_hold`). ARP and IPv6 pass; other frames, such as
/// VLAN-tagged ones, are denied on enforced bridges.
fn render_bridge_dispatch(out: &mut String, plan: &Plan, options: Options) -> fmt::Result {
    let base = Chain::Base(Table::Bridge);
    render_elements(
        out,
        format_args!("add rule {base} meta ibrname !="),
        plan.bridges.iter().map(|bridge| Quoted(&bridge.name)),
        " accept",
    )?;
    // A VLAN-tagged frame (even with VLAN ID 0, which receivers treat as untagged) would
    // carry IPv4 past every check below, so enforced bridges only pass ARP and IPv6 besides
    // IPv4. Other frames aren't IP, can't be reported by address, and are denied silently.
    writeln!(out, "add rule {base} ether type {{ arp, ip6 }} accept")?;
    render_elements(
        out,
        format_args!("add rule {base} meta ibrname"),
        plan.bridges
            .iter()
            .filter(|bridge| !bridge.monitor)
            .map(|bridge| Quoted(&bridge.name)),
        format_args!(" ether type != ip {}", options.deny),
    )?;
    writeln!(out, "add rule {base} ether type != ip accept")?;

    let verdict = |index: usize, source: &Source| {
        if icc_chain_needed(plan, source, options) {
            Verdict::Goto(Chain::Icc(index))
        } else {
            Verdict::Accept
        }
    };
    let ipv4 = || {
        plan.sources
            .iter()
            .enumerate()
            .filter(|(_, source)| source.address.is_ipv4())
    };
    render_elements(
        out,
        format_args!("add rule {base} ip saddr . ether saddr vmap"),
        ipv4().filter_map(|(index, source)| {
            let mac = source.mac?;
            Some(Dispatch(
                format_args!("{} . {mac}", source.address).to_string(),
                verdict(index, source),
            ))
        }),
        "",
    )?;
    // Docker always reports a MAC for bridge endpoints; without one, only the address is
    // checked.
    render_elements(
        out,
        format_args!("add rule {base} ip saddr vmap"),
        ipv4()
            .filter(|(_, source)| source.mac.is_none())
            .map(|(index, source)| Dispatch(source.address, verdict(index, source))),
        "",
    )?;
    let bridges = |monitor: bool| {
        set_literal(
            plan.bridges
                .iter()
                .filter(move |bridge| bridge.monitor == monitor)
                .map(|bridge| Quoted(&bridge.name)),
        )
    };
    if let Some(monitored) = bridges(true) {
        decide(
            out,
            format_args!("add rule {base} meta ibrname {monitored} ether type ip"),
            Outcome::deny(options, true, "source"),
        )?;
    }
    let Some(enforced) = bridges(false) else {
        return Ok(());
    };
    let deny = Outcome::deny(options, false, "source");
    let Some(queue) = options.source_queue else {
        return decide(
            out,
            format_args!("add rule {base} meta ibrname {enforced} ether type ip"),
            deny,
        );
    };
    // Held before, and the source stayed unknown.
    decide(
        out,
        format_args!(
            "add rule {base} meta ibrname {enforced} ether type ip meta mark {HOLD_EXPIRED_MARK:#x}"
        ),
        deny,
    )?;
    // A source no container has (yet): most likely a container that just started, or that
    // got the address of a removed one, and that Portcullis hasn't applied rules for. Hold
    // the packet until the next update; spoofed sources stay unknown and are denied above
    // once the hold expires.
    writeln!(
        out,
        "add rule {base} meta ibrname {enforced} ether type ip queue num {queue}"
    )
}

/// Write `{head} { e1, e2, ... }{tail}` and a newline; writes nothing without elements.
fn render_elements<T: fmt::Display>(
    out: &mut String,
    head: fmt::Arguments<'_>,
    elements: impl Iterator<Item = T>,
    tail: impl fmt::Display,
) -> fmt::Result {
    let mut elements = elements.peekable();
    if elements.peek().is_none() {
        return Ok(());
    }
    write!(out, "{head} {{ ")?;
    for (index, element) in elements.enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        write!(out, "{element}")?;
    }
    writeln!(out, " }}{tail}")?;
    Ok(())
}

/// Sets have per-element timeouts: addresses expire when nothing renews them. Returns the
/// set's qualified name.
fn render_set(
    out: &mut String,
    set: &HostSet,
    prefix: &'static str,
    type_name: &str,
    addresses: impl Iterator<Item = (IpAddr, Duration)>,
) -> Result<String, fmt::Error> {
    let name = format!("{} {}", Table::Inet, set.id.name(prefix));
    writeln!(out, "add set {name} {{ type {type_name}; flags timeout; }}")?;
    writeln!(out, "flush set {name}")?;
    render_elements(
        out,
        format_args!("add element {name}"),
        addresses.map(|(address, timeout)| Timed(address, timeout)),
        "",
    )?;
    Ok(name)
}

/// A set element with a timeout, at least one second.
struct Timed(IpAddr, Duration);

impl fmt::Display for Timed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.1.as_secs() + u64::from(self.1.subsec_nanos() > 0);
        write!(f, "{} timeout {}s", self.0, seconds.max(1))
    }
}

/// Verdict map entry: `<key> : <verdict>`.
struct Dispatch<K>(K, Verdict);

impl<K: fmt::Display> fmt::Display for Dispatch<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} : ", self.0)?;
        match self.1 {
            Verdict::Accept => f.write_str("accept"),
            Verdict::Goto(chain) => write!(f, "goto {}", ChainName(chain)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Verdict {
    Accept,
    Goto(Chain),
}

/// A string in double quotes, as nft expects interface names.
struct Quoted<'a>(&'a str);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0)
    }
}

const fn family(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    }
}

fn render_rule(
    plan: &Plan,
    source: &Source,
    chain: Chain,
    rule: &Rule,
    options: Options,
    out: &mut String,
) -> fmt::Result {
    let f = family(source.address);
    let icc = matches!(chain, Chain::Icc(_));
    let reason = if icc { "icc" } else { "egress" };
    let allow = Outcome::allow(options, source.monitor, Some(reason)).for_address(source.address);
    let deny = |reason| Outcome::deny(options, source.monitor, reason).for_address(source.address);
    match *rule {
        // DNS traffic itself is reported from the DNS answers Portcullis inspects.
        Rule::AcceptDns {
            destination,
            protocol,
        } => {
            write!(out, "add rule {chain} ")?;
            if let Some(destination) = destination {
                write!(out, "{f} daddr {destination} ")?;
            }
            writeln!(out, "{} dport {DNS_PORT} accept", protocol.as_str())
        }
        Rule::DenyDns { protocol } => decide(
            out,
            format_args!("add rule {chain} {} dport {DNS_PORT}", protocol.as_str()),
            deny("dns").snaplen(LOG_SNAPLEN_DNS),
        ),
        Rule::AcceptPeers { subnet, gateway } => {
            write!(out, "add rule {chain} {f} daddr {subnet} ")?;
            if let Some(gateway) = gateway {
                write!(out, "{f} daddr != {gateway} ")?;
            }
            writeln!(out, "accept")
        }
        Rule::AcceptNet(destination) => decide(
            out,
            format_args!("add rule {chain} {f} daddr {destination}"),
            allow,
        ),
        Rule::AcceptHost(destination) => {
            writeln!(out, "add rule {chain} {f} daddr {destination} accept")
        }
        Rule::DenyNet(destination) => decide(
            out,
            format_args!("add rule {chain} {f} daddr {destination}"),
            deny(reason),
        ),
        Rule::AcceptPort {
            destination,
            protocol,
            port,
        } => {
            let protocol = protocol.as_str();
            match destination {
                Destination::Net(destination) => decide(
                    out,
                    format_args!(
                        "add rule {chain} {f} daddr {destination} {protocol} dport {port}"
                    ),
                    allow,
                ),
                Destination::Addr(destination) => decide(
                    out,
                    format_args!(
                        "add rule {chain} {f} daddr {destination} {protocol} dport {port}"
                    ),
                    allow,
                ),
                Destination::HostSet(index) => {
                    let Some(set) = plan.host_set(index) else {
                        return Ok(());
                    };
                    let prefix = if source.address.is_ipv4() {
                        SET_PREFIX_V4
                    } else {
                        SET_PREFIX_V6
                    };
                    decide(
                        out,
                        format_args!(
                            "add rule {chain} {f} daddr @{} {protocol} dport {port}",
                            set.id.name(prefix)
                        ),
                        allow,
                    )
                }
            }
        }
    }
}

#[allow(unsafe_code, warnings)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/libnftables_bindings.rs"));
}

trait NftApi {
    type Handle: Copy;

    fn new_context(&self) -> Option<Self::Handle>;
    fn free_context(&self, handle: Self::Handle);
    fn buffer_output(&self, handle: Self::Handle) -> i32;
    fn buffer_error(&self, handle: Self::Handle) -> i32;
    fn run_script(&self, handle: Self::Handle, script: &CStr) -> i32;
    fn error_output(&self, handle: Self::Handle) -> Option<String>;
}

#[derive(Debug, Clone, Copy)]
struct RealNftApi;

#[allow(unsafe_code)]
impl NftApi for RealNftApi {
    type Handle = NonNull<bindings::nft_ctx>;

    fn new_context(&self) -> Option<Self::Handle> {
        // SAFETY: `nft_ctx_new` is an FFI constructor that returns either null or a valid
        // pointer to an allocated context when passed a valid flags value.
        let pointer = unsafe { bindings::nft_ctx_new(bindings::NFT_CTX_DEFAULT) };
        NonNull::new(pointer)
    }

    fn free_context(&self, handle: Self::Handle) {
        // SAFETY: `handle` comes from `nft_ctx_new` and is freed exactly once in `Drop`.
        unsafe { bindings::nft_ctx_free(handle.as_ptr()) };
    }

    fn buffer_output(&self, handle: Self::Handle) -> i32 {
        // SAFETY: `handle` points to a valid live context.
        unsafe { bindings::nft_ctx_buffer_output(handle.as_ptr()) }
    }

    fn buffer_error(&self, handle: Self::Handle) -> i32 {
        // SAFETY: `handle` points to a valid live context.
        unsafe { bindings::nft_ctx_buffer_error(handle.as_ptr()) }
    }

    fn run_script(&self, handle: Self::Handle, script: &CStr) -> i32 {
        // SAFETY: both pointers are valid for the duration of this call.
        unsafe { bindings::nft_run_cmd_from_buffer(handle.as_ptr(), script.as_ptr()) }
    }

    fn error_output(&self, handle: Self::Handle) -> Option<String> {
        // SAFETY: pointer is owned by libnftables for this context and may be null.
        let pointer = unsafe { bindings::nft_ctx_get_error_buffer(handle.as_ptr()) };
        if pointer.is_null() {
            return None;
        }

        // SAFETY: non-null C string pointer returned by libnftables.
        let cstr = unsafe { CStr::from_ptr(pointer) };
        Some(cstr.to_string_lossy().trim().to_string())
    }
}

struct NftContext<A>
where
    A: NftApi,
{
    api: A,
    handle: A::Handle,
}

impl<A> NftContext<A>
where
    A: NftApi,
{
    fn new(api: A) -> Result<Self, FirewallError> {
        let Some(handle) = api.new_context() else {
            return Err(FirewallError::LibContextCreate);
        };

        let output_rc = api.buffer_output(handle);
        if output_rc != 0 {
            api.free_context(handle);
            return Err(FirewallError::LibBufferConfig {
                buffer: "output",
                code: output_rc,
            });
        }

        let error_rc = api.buffer_error(handle);
        if error_rc != 0 {
            api.free_context(handle);
            return Err(FirewallError::LibBufferConfig {
                buffer: "error",
                code: error_rc,
            });
        }

        Ok(Self { api, handle })
    }

    /// Run `script`. Taking ownership of a `String` lets the NUL terminator be appended
    /// without copying the script.
    fn run_script(&mut self, script: impl Into<Vec<u8>>) -> Result<(), FirewallError> {
        let c_script = CString::new(script).map_err(|_| FirewallError::ScriptContainsNul)?;
        let result = self.api.run_script(self.handle, &c_script);
        if result == 0 {
            return Ok(());
        }

        let stderr = self
            .api
            .error_output(self.handle)
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| "unknown libnftables error".to_string());

        Err(FirewallError::LibCommandFailure {
            code: result,
            stderr,
        })
    }
}

impl<A> Drop for NftContext<A>
where
    A: NftApi,
{
    fn drop(&mut self) {
        self.api.free_context(self.handle);
    }
}

// SAFETY: a libnftables context isn't tied to the thread that created it, and
// `LibNftablesRunner` only touches it while holding its mutex, so it's never used from two
// threads at once.
#[allow(unsafe_code)]
unsafe impl Send for NftContext<RealNftApi> {}

pub struct LibNftablesRunner {
    context: Mutex<NftContext<RealNftApi>>,
}

impl LibNftablesRunner {
    pub fn new() -> Result<Self, FirewallError> {
        let context = NftContext::new(RealNftApi)?;
        Ok(Self {
            context: Mutex::new(context),
        })
    }
}

impl NftRunner for LibNftablesRunner {
    fn run_script(&self, script: String) -> Result<(), FirewallError> {
        trace!(program = "nft", script, "executing firewall script");
        let mut guard = self
            .context
            .lock()
            .map_err(|_| FirewallError::LibContextLock)?;
        guard.run_script(script)
    }
}

#[cfg(test)]
mod libnftables_tests {
    use std::ffi::CStr;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Debug)]
    struct MockState {
        next_context: Option<usize>,
        output_rc: i32,
        error_rc: i32,
        run_rc: i32,
        error_message: String,
        freed: usize,
        scripts: Vec<String>,
    }

    #[derive(Clone)]
    struct MockApi {
        state: Arc<Mutex<MockState>>,
    }

    impl MockApi {
        fn new(state: MockState) -> Self {
            Self {
                state: Arc::new(Mutex::new(state)),
            }
        }

        fn state(&self) -> MockState {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.clone()
        }
    }

    impl NftApi for MockApi {
        type Handle = usize;

        fn new_context(&self) -> Option<Self::Handle> {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.next_context
        }

        fn free_context(&self, _handle: Self::Handle) {
            let mut guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.freed += 1;
        }

        fn buffer_output(&self, _handle: Self::Handle) -> i32 {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.output_rc
        }

        fn buffer_error(&self, _handle: Self::Handle) -> i32 {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.error_rc
        }

        fn run_script(&self, _handle: Self::Handle, script: &CStr) -> i32 {
            let mut guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            guard.scripts.push(script.to_string_lossy().to_string());
            guard.run_rc
        }

        fn error_output(&self, _handle: Self::Handle) -> Option<String> {
            let guard = match self.state.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock mock state: {error}"),
            };
            Some(guard.error_message.clone())
        }
    }

    fn base_state() -> MockState {
        MockState {
            next_context: Some(1),
            output_rc: 0,
            error_rc: 0,
            run_rc: 0,
            error_message: String::new(),
            freed: 0,
            scripts: Vec::new(),
        }
    }

    #[test]
    fn wrapper_runs_script_successfully() {
        let api = MockApi::new(base_state());
        let mut context = match NftContext::new(api.clone()) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("add table inet portcullis");
        assert!(result.is_ok());

        let state = api.state();
        assert_eq!(state.scripts.len(), 1);
    }

    #[test]
    fn wrapper_reports_script_failure() {
        let mut state = base_state();
        state.run_rc = -1;
        state.error_message = "syntax error".to_string();
        let api = MockApi::new(state);
        let mut context = match NftContext::new(api) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("invalid");
        assert!(matches!(
            result,
            Err(FirewallError::LibCommandFailure { code: -1, .. })
        ));
    }

    #[test]
    fn wrapper_rejects_nul_byte_scripts() {
        let api = MockApi::new(base_state());
        let mut context = match NftContext::new(api) {
            Ok(value) => value,
            Err(error) => panic!("expected context creation to succeed: {error}"),
        };

        let result = context.run_script("bad\0script");
        assert!(matches!(result, Err(FirewallError::ScriptContainsNul)));
    }

    #[test]
    fn wrapper_frees_context_on_drop() {
        let api = MockApi::new(base_state());
        {
            let context = match NftContext::new(api.clone()) {
                Ok(value) => value,
                Err(error) => panic!("expected context creation to succeed: {error}"),
            };
            let _ = context;
        }

        let state = api.state();
        assert_eq!(state.freed, 1);
    }

    #[test]
    fn wrapper_fails_when_context_creation_fails() {
        let mut state = base_state();
        state.next_context = None;
        let api = MockApi::new(state);

        let result = NftContext::new(api);
        assert!(matches!(result, Err(FirewallError::LibContextCreate)));
    }

    #[test]
    fn wrapper_fails_when_output_buffering_fails() {
        let mut state = base_state();
        state.output_rc = -1;
        let api = MockApi::new(state);

        let result = NftContext::new(api);
        assert!(matches!(
            result,
            Err(FirewallError::LibBufferConfig {
                buffer: "output",
                code: -1
            })
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::test_support::{self, MockResolver};

    const OPTIONS: Options = Options {
        deny: DenyAction::Drop,
        log_group: 7,
        log_allowed: LogAllowed::Never,
        dns_queue: None,
        source_queue: None,
    };

    fn render_with(state: &RuntimeState, options: Options, monitor_all: bool) -> String {
        let plan = Plan::build(
            state,
            &mut MockResolver::default(),
            &test_support::host_resolvers(),
            monitor_all,
        );
        let mut script = String::new();
        render_apply_script(&plan, options, Some(&Installed::default()), &mut script)
            .expect("script should render");
        script
    }

    fn render(state: &RuntimeState) -> String {
        render_with(state, OPTIONS, false)
    }

    /// The de-duplicated log statement of a reported IPv4 decision.
    fn log_rule(verdict: char, reason: &str) -> String {
        let snaplen = if reason == "dns" { 512 } else { 128 };
        let key = "ip saddr . ip daddr . meta l4proto . th dport";
        format!(
            "{key} != @logged4 add @logged4 {{ {key} }} log prefix \"pc:{verdict}:{reason}\" group 7 snaplen {snaplen}"
        )
    }

    /// The two rules of a reported decision: the log rule, then the verdict rule.
    fn decided(head: &str, verdict: char, reason: &str, action: &str) -> String {
        format!("{head} {}\n{head} {action}", log_rule(verdict, reason))
    }

    fn has_line(script: &str, expected: &str) -> bool {
        script.lines().any(|line| line == expected)
    }

    /// Every expected entry is a line, or consecutive lines, of the script.
    fn assert_lines(script: &str, expected: &[String]) {
        for lines in expected {
            let found = if lines.contains('\n') {
                script.contains(&format!("{lines}\n"))
            } else {
                has_line(script, lines)
            };
            assert!(found, "missing:\n{lines}\nin:\n{script}");
        }
    }

    #[test]
    fn renders_layout() {
        let script = render(&test_support::hostname_state());
        let expected_head = "\
add table inet portcullis
add chain inet portcullis forward { type filter hook forward priority -1; policy accept; }
add chain inet portcullis input { type filter hook input priority -1; policy accept; }
flush chain inet portcullis input
add set inet portcullis logged4 { type ipv4_addr . ipv4_addr . inet_proto . inet_service; flags dynamic,timeout; timeout 60s; size 65536; }
add set inet portcullis logged6 { type ipv6_addr . ipv6_addr . inet_proto . inet_service; flags dynamic,timeout; timeout 60s; size 65536; }
flush chain inet portcullis forward
add table bridge portcullis
add chain bridge portcullis prerouting { type filter hook prerouting priority -1; policy accept; }
add set bridge portcullis logged4 { type ipv4_addr . ipv4_addr . inet_proto . inet_service; flags dynamic,timeout; timeout 60s; size 65536; }
flush chain bridge portcullis prerouting
add chain inet portcullis egress0
flush chain inet portcullis egress0
add chain bridge portcullis icc0
flush chain bridge portcullis icc0
";
        assert!(
            script.starts_with(expected_head),
            "unexpected head:\n{script}"
        );
        assert_lines(
            &script,
            &[
                "add rule inet portcullis forward ip saddr vmap { 172.18.0.2 : goto egress0 }".into(),
                // Traffic to the host follows the same rules.
                "add rule inet portcullis input ct state established,related accept".into(),
                "add rule inet portcullis input ip saddr vmap { 172.18.0.2 : goto egress0 }".into(),
                "add rule inet portcullis input iifname { \"br-net0\" } drop".into(),
                // The gateway is the host: traffic to it follows the egress rules.
                "add rule inet portcullis egress0 ip daddr 172.18.0.0/16 ip daddr != 172.18.0.1 accept".into(),
                // Reported by the bridge table already.
                "add rule inet portcullis forward iifname { \"br-net0\" } drop".into(),
                decided("add rule inet portcullis egress0", 'd', "egress", "drop"),
                "add rule bridge portcullis prerouting ct state established,related accept".into(),
                "add rule bridge portcullis prerouting meta ibrname != { \"br-net0\" } accept".into(),
                "add rule bridge portcullis prerouting ether type { arp, ip6 } accept".into(),
                "add rule bridge portcullis prerouting meta ibrname { \"br-net0\" } ether type != ip drop".into(),
                "add rule bridge portcullis prerouting ether type != ip accept".into(),
                "add rule bridge portcullis prerouting ip saddr . ether saddr vmap { 172.18.0.2 . 02:42:ac:12:00:02 : goto icc0 }".into(),
                decided("add rule bridge portcullis prerouting meta ibrname { \"br-net0\" } ether type ip", 'd', "source", "drop"),
                "add rule bridge portcullis icc0 ip daddr 172.18.0.1 accept".into(),
                decided("add rule bridge portcullis icc0 ip daddr 172.18.0.0/16", 'd', "icc", "drop"),
                // Broadcast and multicast reach every container on the bridge.
                decided("add rule bridge portcullis icc0 ip daddr 255.255.255.255/32", 'd', "icc", "drop"),
                decided("add rule bridge portcullis icc0 ip daddr 224.0.0.0/4", 'd', "icc", "drop"),
            ],
        );
        // nothing for families without sources
        assert!(!script.contains("ip6 saddr"));
    }

    #[test]
    fn holds_unknown_sources_of_enforced_networks() {
        let options = Options {
            source_queue: Some(9),
            ..OPTIONS
        };
        let script = render_with(&test_support::hostname_state(), options, false);
        let head =
            "add rule bridge portcullis prerouting meta ibrname { \"br-net0\" } ether type ip";
        let expected = [
            "add rule bridge portcullis prerouting ip saddr . ether saddr vmap { 172.18.0.2 . 02:42:ac:12:00:02 : goto icc0 }".to_string(),
            decided(&format!("{head} meta mark 0x70630001"), 'd', "source", "drop"),
            format!("{head} queue num 9"),
        ]
        .join("\n");
        assert!(script.contains(&format!("{expected}\n")), "{script}");
        // No bypass: without Portcullis, such packets aren't let through.
        assert!(!script.contains("bypass"), "{script}");

        // Monitor mode lets them through, reported.
        let monitored = render_with(&test_support::hostname_state(), options, true);
        assert!(!monitored.contains("queue num 9"), "{monitored}");
    }

    /// The chains a script creates or keeps, without the base chains.
    fn chains(script: &str) -> BTreeSet<&str> {
        script
            .lines()
            .filter_map(|line| line.strip_prefix("add chain "))
            .filter(|chain| !chain.contains('{'))
            .collect()
    }

    #[test]
    fn updates_rules_without_recreating_tables() {
        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        let mut resolver = MockResolver::default();
        for state in [
            test_support::icc_state(),
            test_support::hostname_state(),
            test_support::icc_state(),
        ] {
            firewall
                .apply(&state, &mut resolver, &[], false)
                .expect("apply");
        }
        let scripts = firewall.runner.scripts.lock().expect("lock");
        let [first, second, third] = scripts.as_slice() else {
            panic!("expected three scripts");
        };
        // The first update clears what another run may have left.
        assert!(first.starts_with("add table inet portcullis\ndelete table inet portcullis\n"));
        for script in [second, third] {
            // Deleting a table or base chain would drop every packet held in its queues.
            assert!(!script.contains("delete table"), "{script}");
            assert!(!script.contains("delete chain inet portcullis forward"));
            assert!(!script.contains("delete chain inet portcullis input"));
            assert!(!script.contains("delete chain bridge portcullis prerouting"));
        }

        // What the previous update created and this one doesn't need is removed; the rest
        // is flushed and refilled.
        let removed: Vec<_> = chains(first).difference(&chains(second)).copied().collect();
        assert!(!removed.is_empty());
        for chain in removed {
            assert!(
                second.contains(&format!("flush chain {chain}\ndelete chain {chain}\n")),
                "{chain} not removed:\n{second}"
            );
        }
        for chain in chains(second) {
            assert!(
                !second.contains(&format!("delete chain {chain}\n")),
                "{second}"
            );
        }
        assert!(!second.contains("delete set"), "{second}");

        // Same for host sets.
        let set = second
            .lines()
            .filter_map(|line| line.strip_prefix("add set "))
            .filter_map(|rest| rest.split(" {").next())
            .find(|name| name.contains("pc_h4_"))
            .expect("host set");
        assert!(third.contains(&format!("delete set {set}\n")), "{third}");
    }

    #[test]
    fn forgets_reported_flows_of_reassigned_addresses() {
        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        let mut resolver = MockResolver::default();
        let mut apply = |state: &RuntimeState| {
            firewall
                .apply(state, &mut resolver, &[], false)
                .expect("apply");
        };
        let state = test_support::icc_state();
        apply(&state);
        apply(&state);
        // web's address goes to another container.
        let mut reassigned = test_support::icc_state();
        reassigned.apply_action(crate::model::RuntimeStateAction::RemoveContainer {
            container_id: "abc".to_string().into(),
        });
        test_support::add_container(
            &mut reassigned,
            "new",
            "web-2",
            &[("net0", "172.18.0.2", &[])],
            crate::model::ContainerPolicy::default(),
        );
        apply(&reassigned);
        // A container is added: nothing to forget.
        let mut added = reassigned.clone();
        test_support::add_container(
            &mut added,
            "more",
            "more",
            &[("net0", "172.18.0.20", &[])],
            crate::model::ContainerPolicy::default(),
        );
        apply(&added);

        let scripts = firewall.runner.scripts.lock().expect("lock");
        let flushes = |script: &String| {
            ["inet", "bridge"]
                .map(|table| script.contains(&format!("flush set {table} portcullis logged4\n")))
        };
        let flushed: Vec<_> = scripts.iter().skip(1).map(flushes).collect();
        assert_eq!(
            flushed,
            [[false, false], [true, true], [false, false]],
            "{scripts:#?}"
        );
    }

    #[test]
    fn renders_reject_as_deny_action() {
        let options = Options {
            deny: DenyAction::Reject,
            ..OPTIONS
        };
        let script = render_with(&test_support::hostname_state(), options, false);
        let reject = "reject with icmpx admin-prohibited";
        assert!(!script.contains(" drop"));
        assert_lines(
            &script,
            &[
                format!("add rule inet portcullis forward iifname {{ \"br-net0\" }} {reject}"),
                decided(
                    "add rule inet portcullis egress0 udp dport 53",
                    'd',
                    "dns",
                    reject,
                ),
                decided("add rule inet portcullis egress0", 'd', "egress", reject),
                decided(
                    "add rule bridge portcullis prerouting meta ibrname { \"br-net0\" } ether type ip",
                    'd',
                    "source",
                    reject,
                ),
            ],
        );
    }

    #[test]
    fn monitor_mode_reports_instead_of_denying() {
        let script = render_with(&test_support::hostname_state(), OPTIONS, true);
        assert!(!script.contains(" drop\n"), "{script}");
        assert!(!script.contains("iifname"), "{script}");
        assert_lines(
            &script,
            &[
                decided("add rule inet portcullis egress0", 'w', "egress", "accept"),
                decided(
                    "add rule inet portcullis egress0 udp dport 53",
                    'w',
                    "dns",
                    "accept",
                ),
                decided(
                    "add rule bridge portcullis icc0 ip daddr 172.18.0.0/16",
                    'w',
                    "icc",
                    "accept",
                ),
                decided(
                    "add rule bridge portcullis prerouting meta ibrname { \"br-net0\" } ether type ip",
                    'w',
                    "source",
                    "accept",
                ),
            ],
        );
    }

    #[test]
    fn logs_allowed_connections_when_asked() {
        let quiet = render(&test_support::icc_state());
        assert!(!quiet.contains("pc:a:"));
        // Allow-mode containers need no ICC chain when nothing is reported.
        assert!(quiet.contains("172.18.0.3 . 02:42:ac:12:00:03 : accept"));

        let options = Options {
            log_allowed: LogAllowed::Always,
            ..OPTIONS
        };
        let script = render_with(&test_support::icc_state(), options, false);
        assert!(script.contains(&format!(
            "ip daddr 172.18.0.10 tcp dport 5432 {}",
            log_rule('a', "icc")
        )));
        assert!(script.contains(&format!("ip daddr 172.18.0.0/16 {}", log_rule('a', "icc"))));
        assert!(!script.contains("172.18.0.3 . 02:42:ac:12:00:03 : accept"));

        // By default, only in monitor mode.
        let options = Options {
            log_allowed: LogAllowed::Monitor,
            ..OPTIONS
        };
        let enforced = render_with(&test_support::hostname_state(), options, false);
        assert!(!enforced.contains("pc:a:"));
        let monitored = render_with(&test_support::hostname_state(), options, true);
        assert!(monitored.contains(&format!("tcp dport 443 {}", log_rule('a', "egress"))));
    }

    #[test]
    fn holds_dns_answers_for_inspection() {
        let options = Options {
            dns_queue: Some(9),
            ..OPTIONS
        };
        let script = render_with(&test_support::hostname_state(), options, false);
        let queue = "add rule inet portcullis forward oifname { \"br-net0\" } meta l4proto { tcp, udp } th sport 53 ct direction reply queue num 9 bypass";
        let established = "add rule inet portcullis forward ct state established,related accept";
        let position = |line: &str| script.lines().position(|candidate| candidate == line);
        assert!(
            position(queue).expect("queue rule") < position(established).expect("established rule")
        );
    }

    #[test]
    fn renders_hostname_sets_with_timeouts_once_per_host() {
        let script = render(&test_support::shared_hostname_state());
        assert_eq!(script.matches("add set inet portcullis pc_h4_").count(), 1);
        assert!(script.contains("{ type ipv4_addr; flags timeout; }"));
        assert!(script.contains(" { 1.1.1.1 timeout 3600s }\n"));
        assert_eq!(script.matches("ip daddr @pc_h4_").count(), 2);
        // no IPv6 source references the host, so no IPv6 set is created
        assert!(!script.contains("pc_h6_"));
    }

    #[test]
    fn renders_ipv6_rules_and_sets() {
        let script = render(&test_support::ipv6_state());
        assert!(script.contains("add set inet portcullis pc_h6_"));
        assert!(script.contains(" { 2606:4700::1111 timeout 3600s }\n"));
        assert!(!script.contains("pc_h4_"));
        assert!(has_line(
            &script,
            "add rule inet portcullis forward ip6 saddr vmap { fd00::2 : goto egress0 }"
        ));
        assert!(has_line(
            &script,
            "add rule inet portcullis egress0 ip6 daddr 2001:db8::/32 tcp dport 443 accept"
        ));
        // IPv6 sources only get egress rules.
        assert!(!script.contains("bridge portcullis icc"));
    }

    #[test]
    fn renders_icc_modes() {
        let script = render(&test_support::icc_state());
        // web (172.18.0.2) goes to its chain; the others are unrestricted.
        let chain = script
            .split("172.18.0.2 . 02:42:ac:12:00:02 : goto ")
            .nth(1)
            .and_then(|rest| rest.split([',', ' ']).next())
            .expect("web's ICC chain");
        assert_lines(
            &script,
            &[
                format!(
                    "add rule bridge portcullis {chain} ip daddr 172.18.0.10 tcp dport 5432 accept"
                ),
                decided(
                    &format!("add rule bridge portcullis {chain} ip daddr 172.18.0.0/16"),
                    'd',
                    "icc",
                    "drop",
                ),
            ],
        );
        assert_eq!(script.matches(": goto icc").count(), 1);
        assert!(!script.contains("ip daddr 172.19.0.10 tcp dport 5432"));
    }

    #[test]
    fn renders_unresolvable_hostname_as_empty_set() {
        let script = render(&test_support::unresolvable_state());
        assert!(script.contains("add set inet portcullis pc_h4_"));
        assert!(!script.contains("add element"));
        assert!(script.contains("ip daddr @pc_h4_"));
        assert!(script.contains("ip daddr 8.8.8.0/24 tcp dport 853 accept"));
    }

    #[derive(Default)]
    struct RecordingRunner {
        scripts: Mutex<Vec<String>>,
    }

    impl NftRunner for RecordingRunner {
        fn run_script(&self, script: String) -> Result<(), FirewallError> {
            self.scripts.lock().expect("lock").push(script);
            Ok(())
        }
    }

    #[test]
    fn apply_runs_single_script() {
        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        let plan = firewall
            .apply(
                &test_support::unresolvable_state(),
                &mut MockResolver::default(),
                &[],
                false,
            )
            .expect("apply should succeed");
        assert_eq!(plan.unresolved_hosts, vec![test_support::UNRESOLVABLE_HOST]);
        assert_eq!(firewall.runner.scripts.lock().expect("lock").len(), 1);
    }

    #[test]
    fn adds_addresses_to_host_sets() {
        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        let plan = Plan::build(
            &test_support::hostname_state(),
            &mut MockResolver::default(),
            &[],
            false,
        );
        let set = plan.host_set(0).expect("host set");
        firewall
            .add_host_addresses(
                set,
                &[
                    (
                        test_support::ip("198.51.100.3"),
                        Duration::from_millis(1500),
                    ),
                    (test_support::ip("2001:db8::1"), Duration::from_secs(60)),
                ],
            )
            .expect("add");
        let scripts = firewall.runner.scripts.lock().expect("lock");
        let name = set.id.name(SET_PREFIX_V4);
        assert_eq!(
            scripts.as_slice(),
            [format!(
                "add element inet portcullis {name} {{ 198.51.100.3 timeout 2s }}\n"
            )]
        );
    }

    #[test]
    fn cleanup_deletes_tables_even_if_missing() {
        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        firewall.cleanup().expect("cleanup should succeed");
        let scripts = firewall.runner.scripts.lock().expect("lock");
        assert_eq!(
            scripts.as_slice(),
            [
                "add table inet portcullis\ndelete table inet portcullis\nadd table bridge portcullis\ndelete table bridge portcullis\n"
            ]
        );
    }
}
