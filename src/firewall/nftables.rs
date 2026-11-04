use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::fmt::{self, Write as _};
use std::fs;
use std::io::{self, Write as _};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tracing::{info, trace, warn};

use super::FirewallError;
use super::plan::{
    DNS_PORT, Destination, HostSet, ICC_BROADCAST_V4, Plan, Rule, SET_PREFIX_V4, SET_PREFIX_V6,
    Source,
};
use crate::dns::{HostResolver, MAX_ADDRESSES_PER_HOST};
use crate::model::{ConnectionLimit, ContainerName, MacAddress, RuntimeState};

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
    /// Base chain of the bridge table for frames a bridge delivers to the host itself.
    BridgeInput,
    /// Base chain of the bridge table for frames a bridge passes from one container to
    /// another.
    BridgeForward,
    /// Reports and denies connections over a container's limit: open connections, or new
    /// connections per second (`rate`), in monitor mode or not.
    Limited { rate: bool, monitor: bool },
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
            Self::BridgeInput | Self::BridgeForward | Self::Limited { .. } | Self::Icc(_) => {
                Table::Bridge
            }
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
            Chain::Input | Chain::BridgeInput => f.write_str("input"),
            Chain::BridgeForward => f.write_str("forward"),
            Chain::Limited { rate, monitor } => write!(
                f,
                "limit_{}{}",
                if rate { "rate" } else { "open" },
                if monitor { "_monitor" } else { "" }
            ),
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
    /// The same for networks in monitor mode. This queue fails open: while nothing reads
    /// it, packets pass.
    pub monitor_source_queue: Option<u16>,
    /// Open connections a container may have at a time, unless its labels say otherwise.
    pub connection_limit: Option<u32>,
    /// NFQUEUE number DNS queries of containers with `portcullis.domains` labels are held
    /// in until Portcullis has checked the name. See `dns_filter`.
    pub dns_query_queue: Option<u16>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            deny: DenyAction::Reject,
            log_group: 1,
            log_allowed: LogAllowed::Monitor,
            dns_queue: None,
            source_queue: None,
            monitor_source_queue: None,
            connection_limit: Some(DEFAULT_CONNECTION_LIMIT),
            dns_query_queue: None,
        }
    }
}

/// Open connections a container may have at a time by default: far more than most services
/// need, and a fraction of the host's connection tracking table, which every container
/// shares.
pub const DEFAULT_CONNECTION_LIMIT: u32 = 16_384;

/// Packet marks of DNS queries Portcullis checked: the name is allowed, or it isn't.
pub const DNS_ALLOWED_MARK: u32 = 0x7063_0003;
pub const DNS_DENIED_MARK: u32 = 0x7063_0002;

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
    /// Where the rules of every update are saved, to be restored at the next start.
    saved: Option<PathBuf>,
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
            saved: None,
        }
    }

    /// Save the rules of every update to `path`, as a script that installs them from
    /// scratch, so the next start can put them in place before anything else (see
    /// [`Self::restore`]).
    #[must_use]
    pub fn saving_to(mut self, path: PathBuf) -> Self {
        self.saved = Some(path);
        self
    }

    /// Put the rules a previous run saved in place, replacing whatever is there. Returns
    /// whether there were any.
    pub fn restore(&self) -> Result<bool, FirewallError> {
        let Some(path) = &self.saved else {
            return Ok(false);
        };
        let script = match fs::read_to_string(path) {
            Ok(script) => script,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(FirewallError::Saved(error)),
        };
        self.runner.run_script(script)?;
        // The next update starts from empty tables again.
        *self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        Ok(true)
    }

    /// Forget the saved rules, so the next start doesn't restore them.
    pub fn forget_saved(&self) -> Result<(), FirewallError> {
        match self.saved.as_deref().map(fs::remove_file) {
            Some(Err(error)) if error.kind() != io::ErrorKind::NotFound => {
                Err(FirewallError::Saved(error))
            }
            _ => Ok(()),
        }
    }

    /// Write the rules of `plan`, from scratch, where the next start finds them. Written
    /// to a temporary file first and renamed, so a crash never leaves half a script.
    fn save(&self, plan: &Plan) -> Result<(), FirewallError> {
        let Some(path) = &self.saved else {
            return Ok(());
        };
        let mut script = String::with_capacity(plan.rule_count() * 96);
        render_apply_script(plan, self.options, None, &mut script)?;
        let temporary = path.with_extension("tmp");
        let write = || -> io::Result<()> {
            if let Some(directory) = path.parent() {
                fs::create_dir_all(directory)?;
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(script.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, path)
        };
        write().map_err(FirewallError::Saved)
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
        drop(installed);
        if let Err(error) = self.save(&plan) {
            warn!(%error, "can't save the rules; the next start begins without them");
        }
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
    /// What reports are de-duplicated by.
    key: LogKey,
    /// Denied traffic is dropped whatever the deny action: it can't be rejected (frames
    /// that aren't IP), or a rejection would go to an address the sender only claims.
    drop: bool,
}

/// What reports of a decision are de-duplicated by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogKey {
    /// The flow of an IPv4 packet: addresses, protocol and destination port.
    Ipv4,
    /// The same for IPv6.
    Ipv6,
    /// The flow of an IPv4 connection as the container opened it, before DNAT.
    OriginalV4,
    /// The same for IPv6.
    OriginalV6,
    /// A frame that may not even be IP: the bridge port, source MAC and ether type.
    Frame,
    /// ARP: the bridge port, and the MAC and address it announces.
    Arp,
}

impl Outcome {
    const fn allow(options: Options, monitor: bool, reason: Option<&'static str>) -> Self {
        Self {
            options,
            allow: true,
            monitor,
            reason,
            snaplen: LOG_SNAPLEN,
            key: LogKey::Ipv4,
            drop: false,
        }
    }

    const fn deny(options: Options, monitor: bool, reason: &'static str) -> Self {
        Self {
            options,
            allow: false,
            monitor,
            reason: Some(reason),
            snaplen: LOG_SNAPLEN,
            key: LogKey::Ipv4,
            drop: false,
        }
    }

    const fn snaplen(mut self, snaplen: u16) -> Self {
        self.snaplen = snaplen;
        self
    }

    const fn for_address(mut self, address: IpAddr) -> Self {
        self.key = if address.is_ipv6() {
            LogKey::Ipv6
        } else {
            LogKey::Ipv4
        };
        self
    }

    const fn for_frame(mut self) -> Self {
        self.key = LogKey::Frame;
        self.drop = true;
        self
    }

    /// De-duplicate by the connection's destination before DNAT, which the inet table's
    /// rules match.
    const fn original(mut self) -> Self {
        self.key = match self.key {
            LogKey::Ipv4 => LogKey::OriginalV4,
            LogKey::Ipv6 => LogKey::OriginalV6,
            other => other,
        };
        self
    }

    const fn for_arp(mut self) -> Self {
        self.key = LogKey::Arp;
        self.drop = true;
        self
    }

    const fn dropped(mut self) -> Self {
        self.drop = true;
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
        } else if self.drop {
            f.write_str("drop")
        } else {
            write!(f, "{}", self.options.deny)
        }
    }
}

/// Recently reported flows: (source, destination, protocol, port), one set per address
/// family and table. A flow is reported once per timeout, however many packets it sends.
const LOGGED_SET_V4: &str = "logged4";
const LOGGED_SET_V6: &str = "logged6";
/// Recently reported frames: (bridge port, source MAC, ether type), in the bridge table.
const LOGGED_SET_FRAMES: &str = "frames";
/// Recently reported ARP: (bridge port, announced MAC, announced address).
const LOGGED_SET_ARP: &str = "announced";
const LOGGED_TIMEOUT: &str = "60s";
const LOGGED_SIZE: u32 = 65_536;

/// Create the sets of reported flows; with `flush`, forget the flows reported so far.
fn render_logged_sets(out: &mut String, table: Table, flush: bool) -> fmt::Result {
    const FLOW_V4: &str = "ipv4_addr . ipv4_addr . inet_proto . inet_service";
    const FLOW_V6: &str = "ipv6_addr . ipv6_addr . inet_proto . inet_service";
    const FRAME: &str = "ifname . ether_addr . ether_type";
    const ARP: &str = "ifname . ether_addr . ipv4_addr";
    let sets: &[(&str, &str)] = match table {
        Table::Inet => &[(LOGGED_SET_V4, FLOW_V4), (LOGGED_SET_V6, FLOW_V6)],
        Table::Bridge => &[
            (LOGGED_SET_V4, FLOW_V4),
            (LOGGED_SET_FRAMES, FRAME),
            (LOGGED_SET_ARP, ARP),
        ],
    };
    for (name, key) in sets {
        writeln!(
            out,
            "add set {table} {name} {{ type {key}; flags dynamic,timeout; timeout {LOGGED_TIMEOUT}; size {LOGGED_SIZE}; }}"
        )?;
        if flush {
            writeln!(out, "flush set {table} {name}")?;
        }
    }
    Ok(())
}

/// Render a decision: `head` (`add rule <chain> <match>`) followed by the outcome. A
/// reported outcome gets rules before it that log the packet, but only the first of its
/// flow within the de-duplication timeout; the verdict rule applies to every packet.
fn decide(out: &mut String, head: fmt::Arguments<'_>, outcome: Outcome) -> fmt::Result {
    if let Some((verdict, reason)) = outcome.log_prefix() {
        let (set, key) = match outcome.key {
            LogKey::Ipv4 => (
                LOGGED_SET_V4,
                "ip saddr . ip daddr . meta l4proto . th dport",
            ),
            LogKey::Ipv6 => (
                LOGGED_SET_V6,
                "ip6 saddr . ip6 daddr . meta l4proto . th dport",
            ),
            LogKey::OriginalV4 => (
                LOGGED_SET_V4,
                "ip saddr . ct original ip daddr . meta l4proto . ct original proto-dst",
            ),
            LogKey::OriginalV6 => (
                LOGGED_SET_V6,
                "ip6 saddr . ct original ip6 daddr . meta l4proto . ct original proto-dst",
            ),
            LogKey::Frame => (LOGGED_SET_FRAMES, "iifname . ether saddr . ether type"),
            LogKey::Arp => (LOGGED_SET_ARP, "iifname . arp saddr ether . arp saddr ip"),
        };
        let log = format_args!(
            "log prefix \"{LOG_PREFIX}:{verdict}:{reason}\" group {} snaplen {}",
            outcome.options.log_group, outcome.snaplen
        );
        writeln!(out, "{head} {key} != @{set} add @{set} {{ {key} }} {log}")?;
        // Adding to a full set fails, and so would the log statement after it: anyone able
        // to fill the set with flows of their own would make every denial after it go
        // unreported. A flow the rule above didn't add is still logged, at a limited rate
        // per rule, so one source can't drown out the others either.
        writeln!(
            out,
            "{head} {key} != @{set} limit rate {LOG_FULL_RATE} {log}"
        )?;
    }
    writeln!(out, "{head} {outcome}")
}

/// How often a rule reports flows once its de-duplication set is full.
const LOG_FULL_RATE: &str = "10/second";

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
/// Each table has a base chain that dispatches each managed source address through a
/// verdict map to its own chain: the bridge table after checking where a frame came from,
/// the inet table after letting established traffic through. A packet costs one hash
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
        let input = match table {
            Table::Inet => Chain::Input,
            Table::Bridge => Chain::BridgeInput,
        };
        render_base_chain(out, input, "input")?;
        writeln!(out, "flush chain {input}")?;
        if table == Table::Bridge {
            render_base_chain(out, Chain::BridgeForward, "forward")?;
            writeln!(out, "flush chain {}", Chain::BridgeForward)?;
            render_quarantined_set(out, plan)?;
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
        render_related(out, chain, source.address)?;
        for rule in plan.egress_rules(source) {
            render_rule(plan, source, chain, rule, options, out)?;
        }
        decide(
            out,
            format_args!("add rule {chain}"),
            Outcome::deny(options, source.monitor, "egress")
                .for_address(source.address)
                .original(),
        )?;
    }

    // Everything entering a managed network's bridge from a container: source checks and
    // traffic between containers on the same network. Established traffic only passes
    // once its source checks out, in the ICC chains: a container could otherwise send with
    // another container's address into that container's connections.
    if !plan.bridges.is_empty() {
        render_bridge_dispatch(out, plan, options)?;
        render_link_local(out, plan, options)?;
        render_bridged_destinations(out, plan, options)?;
    }
    for (index, source) in ipv4_sources() {
        if icc_chain_needed(plan, source, options) {
            let chain = Chain::Icc(index);
            writeln!(out, "add rule {chain} ct state established accept")?;
            render_related(out, chain, source.address)?;
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
    render_link_local_ip(out, plan, options, base)?;
    render_dns_names(out, plan, options, base)?;
    // The bridge table checked where established traffic comes from. Related traffic (ICMP
    // errors about a connection) is checked in the source's chain, see `render_related`.
    writeln!(out, "add rule {base} ct state established accept")?;
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

/// Accept related traffic (ICMP errors about a connection) from `address` only when it is
/// one end of that connection. The kernel relates an ICMP error to a connection by the
/// packet quoted inside it, whoever sends it: anyone could otherwise send ICMP errors, with
/// data of their choice, to wherever any container has a connection. Other related traffic
/// continues through the chain's rules.
fn render_related(out: &mut String, chain: Chain, address: IpAddr) -> fmt::Result {
    let f = family(address);
    for direction in ["original", "reply"] {
        writeln!(
            out,
            "add rule {chain} ct state related ct {direction} {f} saddr {address} accept"
        )?;
    }
    Ok(())
}

/// DNS queries of containers whose names are limited are held until Portcullis has read the
/// name, before established traffic is let through (a query over TCP comes after the
/// handshake). A checked query comes back marked: an allowed one continues through the rules
/// as any other, a denied one is rejected, so the lookup fails at once. The queue has no
/// bypass: while Portcullis isn't reading it, such lookups fail.
fn render_dns_names(out: &mut String, plan: &Plan, options: Options, base: Chain) -> fmt::Result {
    let Some(queue) = options.dns_query_queue else {
        return Ok(());
    };
    render_elements(
        out,
        format_args!("add rule {base} ip saddr"),
        plan.sources
            .iter()
            .filter(|source| source.address.is_ipv4() && source.domains.is_some())
            .map(|source| source.address),
        format_args!(
            " meta l4proto {{ tcp, udp }} th dport {DNS_PORT} ct direction original meta mark != {DNS_ALLOWED_MARK:#x} meta mark != {DNS_DENIED_MARK:#x} queue num {queue}"
        ),
    )?;
    writeln!(
        out,
        "add rule {base} meta mark {DNS_DENIED_MARK:#x} meta l4proto tcp reject with tcp reset"
    )?;
    writeln!(
        out,
        "add rule {base} meta mark {DNS_DENIED_MARK:#x} reject with icmpx admin-prohibited"
    )?;
    writeln!(
        out,
        "add rule {base} meta mark {DNS_ALLOWED_MARK:#x} meta mark set 0x0"
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
    let limited = (!plan.bridges.is_empty())
        .then_some([false, true])
        .into_iter()
        .flatten()
        .flat_map(|rate| [false, true].map(|monitor| Chain::Limited { rate, monitor }));
    for chain in chains.chain(limited) {
        writeln!(out, "add chain {chain}")?;
        writeln!(out, "flush chain {chain}")?;
        installed.chains.insert(chain.to_string());
    }
    for limit in limits(plan, options).into_keys() {
        let name = format!("{} {}", Table::Bridge, limit.set_name());
        let flags = if limit.rate {
            "dynamic,timeout; timeout 60s"
        } else {
            "dynamic"
        };
        writeln!(
            out,
            "add set {name} {{ type ifname; flags {flags}; size 65536; }}"
        )?;
        installed.sets.insert(name);
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

/// Bridge base chain: only frames entering a managed network's bridge are checked. A frame
/// passes only when it comes from a managed container's own port on the bridge, with that
/// container's MAC and, for IPv4 and ARP, its address; IPv4 then continues to the
/// container's ICC rules, if any. That stops containers from sending as another container,
/// and from taking over another container's MAC in the bridge's forwarding table or its
/// address in the neighbours' ARP caches.
///
/// Everything else is denied: on enforced bridges, IPv4 and ARP from a port that belongs to
/// no managed container yet are held first, in case they come from a container whose rules
/// aren't applied yet (see `source_hold`). Other kinds of frames, such as IPv6 or
/// VLAN-tagged ones, are never accepted on enforced bridges: the receiving container's
/// kernel could unwrap a VLAN tag (even VLAN ID 0) past every check here, and Portcullis
/// doesn't manage IPv6.
fn render_bridge_dispatch(out: &mut String, plan: &Plan, options: Options) -> fmt::Result {
    let base = Chain::Base(Table::Bridge);
    render_elements(
        out,
        format_args!("add rule {base} meta ibrname !="),
        plan.bridges.iter().map(|bridge| Quoted(&bridge.name)),
        " accept",
    )?;
    render_limits(out, plan, options)?;
    render_known_sources(out, plan, options, base)?;
    let bridges = |monitor: bool| {
        set_literal(
            plan.bridges
                .iter()
                .filter(move |bridge| bridge.monitor == monitor)
                .map(|bridge| Quoted(&bridge.name)),
        )
    };
    for monitor in [true, false] {
        let Some(selected) = bridges(monitor) else {
            continue;
        };
        let queue = if monitor {
            options.monitor_source_queue
        } else {
            options.source_queue
        };
        render_unknown_sources(out, plan, options, monitor, &selected, queue)?;
    }
    Ok(())
}

/// Frames entering `bridges` (all enforced, or all in monitor mode) that no rule above
/// accepted: their source isn't a managed container's own address, MAC and port.
fn render_unknown_sources(
    out: &mut String,
    plan: &Plan,
    options: Options,
    monitor: bool,
    bridges: &str,
    queue: Option<u16>,
) -> fmt::Result {
    let base = Chain::Base(Table::Bridge);
    // From a managed container's port, but not with its own address and MAC: denied at once.
    let networks: BTreeSet<&str> = plan
        .bridges
        .iter()
        .filter(|bridge| bridge.monitor == monitor)
        .map(|bridge| bridge.network.as_str())
        .collect();
    if let Some(ports) = set_literal(
        plan.sources
            .iter()
            .filter(|source| networks.contains(source.network.as_str()))
            .filter_map(|source| source.port.as_ref())
            .map(|port| Quoted(&port.name)),
    ) {
        render_denied_frames(
            out,
            options,
            monitor,
            &format!("meta ibrname {bridges} iifname {ports}"),
        )?;
    }
    if let Some(queue) = queue {
        // Held before, and the source stayed unknown.
        render_denied_frames(
            out,
            options,
            monitor,
            &format!("meta ibrname {bridges} meta mark {HOLD_EXPIRED_MARK:#x}"),
        )?;
        // A port no managed container has (yet): most likely a container that just started,
        // or that got the address of a removed one, and that Portcullis hasn't applied rules
        // for. Hold the packet until Portcullis knows the container; if the source stays
        // unknown, it is denied (or in monitor mode reported) above once the hold expires.
        // In monitor mode the queue fails open.
        writeln!(
            out,
            "add rule {base} meta ibrname {bridges} ether type {{ ip, arp }} queue num {queue}{}",
            if monitor { " bypass" } else { "" }
        )?;
    }
    render_denied_frames(out, options, monitor, &format!("meta ibrname {bridges}"))
}

/// The set of quarantined containers' bridge ports, refilled on every update.
const QUARANTINED_SET: &str = "quarantined";

fn render_quarantined_set(out: &mut String, plan: &Plan) -> fmt::Result {
    let name = format!("{} {QUARANTINED_SET}", Table::Bridge);
    writeln!(out, "add set {name} {{ type ifname; }}")?;
    writeln!(out, "flush set {name}")?;
    render_elements(
        out,
        format_args!("add element {name}"),
        plan.sources
            .iter()
            .filter(|source| source.quarantined && !source.monitor)
            .filter_map(|source| source.port.as_ref())
            .map(|port| port.name.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(Quoted),
        "",
    )
}

/// A limit shared by some containers: open connections or new connections per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Limit {
    rate: bool,
    value: u32,
    monitor: bool,
}

impl Limit {
    /// The set counting each port's connections, or new connections, under this limit.
    fn set_name(self) -> String {
        format!("{}{}", if self.rate { "new" } else { "conns" }, self.value)
    }
}

/// Containers by the limits they are under, by their bridge ports. Containers whose port
/// isn't known aren't limited.
fn limits(plan: &Plan, options: Options) -> BTreeMap<Limit, BTreeSet<&str>> {
    let mut limits: BTreeMap<Limit, BTreeSet<&str>> = BTreeMap::new();
    for source in &plan.sources {
        let Some(port) = &source.port else {
            continue;
        };
        let open = match source.connection_limit {
            ConnectionLimit::Default => options.connection_limit,
            ConnectionLimit::Unlimited => None,
            ConnectionLimit::At(value) => Some(value),
        };
        let found = [(false, open), (true, source.new_connection_rate)];
        for (rate, value) in found {
            if let Some(value) = value {
                let limit = Limit {
                    rate,
                    value,
                    monitor: source.monitor,
                };
                limits.entry(limit).or_default().insert(&port.name);
            }
        }
    }
    limits
}

/// Quarantined containers get nowhere. Containers over a limit get no new connections:
/// a container opening connections without end would otherwise fill the host's connection
/// tracking table, which every container shares, and new connections of all of them would
/// fail. Both are matched by bridge port, which a container can't borrow, before its
/// address is checked.
fn render_limits(out: &mut String, plan: &Plan, options: Options) -> fmt::Result {
    let base = Chain::Base(Table::Bridge);
    writeln!(out, "add rule {base} iifname @{QUARANTINED_SET} drop")?;
    writeln!(
        out,
        "add rule {} iifname @{QUARANTINED_SET} drop",
        Chain::BridgeInput
    )?;
    for (limit, ports) in limits(plan, options) {
        let Some(ports) = set_literal(ports.iter().map(|port| Quoted(port))) else {
            continue;
        };
        let check = if limit.rate {
            format!("limit rate over {0}/second burst {0} packets", limit.value)
        } else {
            format!("ct count over {}", limit.value)
        };
        writeln!(
            out,
            "add rule {base} iifname {ports} ct state new add @{} {{ iifname {check} }} goto {}",
            limit.set_name(),
            ChainName(Chain::Limited {
                rate: limit.rate,
                monitor: limit.monitor
            })
        )?;
    }
    for rate in [false, true] {
        for monitor in [false, true] {
            let chain = Chain::Limited { rate, monitor };
            let reason = if rate { "limit:rate" } else { "limit:open" };
            decide(
                out,
                format_args!("add rule {chain}"),
                Outcome::deny(options, monitor, reason).dropped(),
            )?;
        }
    }
    Ok(())
}

/// Frames to the link-local group addresses (01:80:c2:00:00:00 to 0f, used by protocols
/// such as STP and LLDP) skip the bridge's prerouting hook: the bridge hands them to the
/// host directly, on the container's port instead of the bridge. With IP inside, they reach
/// the host's IP stack without any of the bridge's checks, from any address the container
/// likes. No container has a reason to send them; they are denied where the bridge hands
/// them over. LLDP (and STP, where enabled) skips even that hook, see
/// `render_link_local_ip`.
fn render_link_local(out: &mut String, plan: &Plan, options: Options) -> fmt::Result {
    for monitor in [false, true] {
        let Some(bridges) = set_literal(
            plan.bridges
                .iter()
                .filter(|bridge| bridge.monitor == monitor)
                .map(|bridge| Quoted(&bridge.name)),
        ) else {
            continue;
        };
        decide(
            out,
            format_args!(
                "add rule {} meta ibrname {bridges} {LINK_LOCAL_GROUP}",
                Chain::BridgeInput
            ),
            Outcome::deny(options, monitor, "frame").for_frame(),
        )?;
    }
    Ok(())
}

/// A bridge passes a frame to whichever port has its destination MAC, whatever its IP
/// destination. The ICC rules only see IP destinations: a frame to another container's MAC,
/// addressed to that container's address on another network, would pass them, and the
/// container would accept it. IPv4 passed from one container to another must therefore be
/// addressed to the network itself, or be broadcast or multicast (which the ICC rules
/// check). The bridge's forward hook can only drop.
fn render_bridged_destinations(out: &mut String, plan: &Plan, options: Options) -> fmt::Result {
    for bridge in plan
        .bridges
        .iter()
        .filter(|bridge| bridge.subnet.addr().is_ipv4())
    {
        let Some(destinations) =
            set_literal(std::iter::once(&bridge.subnet).chain(&ICC_BROADCAST_V4))
        else {
            continue;
        };
        decide(
            out,
            format_args!(
                "add rule {} meta ibrname {} ip daddr != {destinations}",
                Chain::BridgeForward,
                Quoted(&bridge.name),
            ),
            Outcome::deny(options, bridge.monitor, "icc").dropped(),
        )?;
    }
    Ok(())
}

/// The link-local group addresses: 01:80:c2:00:00:00 to 01:80:c2:00:00:0f.
const LINK_LOCAL_GROUP: &str = "ether daddr & ff:ff:ff:ff:ff:f0 == 01:80:c2:00:00:00";

/// IP in frames to link-local group addresses that the bridge passed to the host without any
/// bridge hook (LLDP, and STP where enabled). Nothing legitimate sends IP that way, from
/// anywhere, so it is denied on every interface. Reported as denied while any network is
/// enforced, as would-be-denied while all are monitored.
fn render_link_local_ip(
    out: &mut String,
    plan: &Plan,
    options: Options,
    base: Chain,
) -> fmt::Result {
    if plan.bridges.is_empty() {
        return Ok(());
    }
    let monitor = plan.bridges.iter().all(|bridge| bridge.monitor);
    for (family, key) in [("ipv4", LogKey::Ipv4), ("ipv6", LogKey::Ipv6)] {
        let mut outcome = Outcome::deny(options, monitor, "frame").dropped();
        outcome.key = key;
        decide(
            out,
            format_args!("add rule {base} meta nfproto {family} {LINK_LOCAL_GROUP}"),
            outcome,
        )?;
    }
    Ok(())
}

/// Deny (or in monitor mode, report) frames of the bridge base chain matching `selector`:
/// IPv4 and ARP as using a source that isn't the sender's, anything else as a frame
/// enforced networks don't carry.
fn render_denied_frames(
    out: &mut String,
    options: Options,
    monitor: bool,
    selector: &str,
) -> fmt::Result {
    let base = Chain::Base(Table::Bridge);
    let source = Outcome::deny(options, monitor, "source").dropped();
    decide(
        out,
        format_args!("add rule {base} {selector} ether type ip"),
        source,
    )?;
    decide(
        out,
        format_args!("add rule {base} {selector} ether type arp"),
        source.for_arp(),
    )?;
    decide(
        out,
        format_args!("add rule {base} {selector}"),
        Outcome::deny(options, monitor, "frame").for_frame(),
    )
}

/// How a managed container's frames are recognised: by port, MAC and address where its port
/// is known; by MAC and address where not; by address alone without a MAC (Docker always
/// reports one for bridge endpoints).
enum SourceKey<'a> {
    Port(&'a str, MacAddress, IpAddr),
    Mac(MacAddress, IpAddr),
    Address(IpAddr),
}

impl<'a> SourceKey<'a> {
    fn of(source: &'a Source) -> Self {
        match (source.mac, &source.port) {
            (Some(mac), Some(port)) => Self::Port(&port.name, mac, source.address),
            (Some(mac), None) => Self::Mac(mac, source.address),
            (None, _) => Self::Address(source.address),
        }
    }
}

/// Send frames from managed containers' own port, MAC and address to their ICC rules, and
/// accept their ARP.
fn render_known_sources(
    out: &mut String,
    plan: &Plan,
    options: Options,
    base: Chain,
) -> fmt::Result {
    let verdict = |index: usize, source: &Source| {
        if icc_chain_needed(plan, source, options) {
            Verdict::Goto(Chain::Icc(index))
        } else {
            Verdict::Accept
        }
    };
    let keys = || {
        plan.sources
            .iter()
            .enumerate()
            .filter(|(_, source)| source.address.is_ipv4())
            .map(|(index, source)| (index, source, SourceKey::of(source)))
    };
    // A raw socket is enough to send with another container's address and MAC, but not
    // from its port.
    render_elements(
        out,
        format_args!("add rule {base} iifname . ip saddr . ether saddr vmap"),
        keys().filter_map(|(index, source, key)| match key {
            SourceKey::Port(port, mac, address) => Some(Dispatch(
                format!("{} . {address} . {mac}", Quoted(port)),
                verdict(index, source),
            )),
            _ => None,
        }),
        "",
    )?;
    render_elements(
        out,
        format_args!("add rule {base} ip saddr . ether saddr vmap"),
        keys().filter_map(|(index, source, key)| match key {
            SourceKey::Mac(mac, address) => Some(Dispatch(
                format!("{address} . {mac}"),
                verdict(index, source),
            )),
            _ => None,
        }),
        "",
    )?;
    render_elements(
        out,
        format_args!("add rule {base} ip saddr vmap"),
        keys().filter_map(|(index, source, key)| match key {
            SourceKey::Address(address) => Some(Dispatch(address, verdict(index, source))),
            _ => None,
        }),
        "",
    )?;
    // ARP may only announce the container's own address and MAC, or no address at all
    // (0.0.0.0, a probe for whether an address is in use).
    let unspecified = IpAddr::from([0, 0, 0, 0]);
    render_elements(
        out,
        format_args!("add rule {base} iifname . ether saddr . arp saddr ether . arp saddr ip"),
        keys()
            .flat_map(|(_, _, key)| match key {
                SourceKey::Port(port, mac, address) => [address, unspecified]
                    .map(|address| Some(format!("{} . {mac} . {mac} . {address}", Quoted(port)))),
                _ => [None, None],
            })
            .flatten(),
        " accept",
    )?;
    render_elements(
        out,
        format_args!("add rule {base} ether saddr . arp saddr ether . arp saddr ip"),
        keys()
            .flat_map(|(_, _, key)| match key {
                SourceKey::Mac(mac, address) => {
                    [address, unspecified].map(|address| Some(format!("{mac} . {mac} . {address}")))
                }
                _ => [None, None],
            })
            .flatten(),
        " accept",
    )?;
    render_elements(
        out,
        format_args!("add rule {base} arp saddr ip"),
        keys().filter_map(|(_, _, key)| match key {
            SourceKey::Address(address) => Some(address),
            _ => None,
        }),
        " accept",
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
    // Bounded in the kernel too: addresses are added from DNS answers between updates.
    writeln!(
        out,
        "add set {name} {{ type {type_name}; flags timeout; size {HOST_SET_SIZE}; }}"
    )?;
    writeln!(out, "flush set {name}")?;
    render_elements(
        out,
        format_args!("add element {name}"),
        addresses.map(|(address, timeout)| Timed(address, timeout)),
        "",
    )?;
    Ok(name)
}

/// Room in a hostname set: the addresses a container may learn for a hostname, and those
/// Portcullis resolves itself.
const HOST_SET_SIZE: usize = MAX_ADDRESSES_PER_HOST * 2;

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

/// How a rule matches destinations. The bridge table sees packets as sent. The inet table
/// sees them after Docker's DNAT has rewritten published ports of the host to the
/// container behind them, so it matches the destination the container asked for, as
/// connection tracking remembers it: a published port reached through the host is the
/// host's address and port, not another container on the same network.
struct Match {
    family: &'static str,
    original: bool,
}

impl Match {
    const fn new(address: IpAddr, chain: Chain) -> Self {
        Self {
            family: family(address),
            original: !matches!(chain, Chain::Icc(_)),
        }
    }

    fn daddr(&self) -> String {
        if self.original {
            format!("ct original {} daddr", self.family)
        } else {
            format!("{} daddr", self.family)
        }
    }

    fn dport(&self, protocol: &str, port: u16) -> String {
        if self.original {
            format!("meta l4proto {protocol} ct original proto-dst {port}")
        } else {
            format!("{protocol} dport {port}")
        }
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
    let to = Match::new(source.address, chain);
    let daddr = to.daddr();
    let icc = matches!(chain, Chain::Icc(_));
    let reason = if icc { "icc" } else { "egress" };
    let outcome = |outcome: Outcome| {
        let outcome = outcome.for_address(source.address);
        if icc { outcome } else { outcome.original() }
    };
    let allow = outcome(Outcome::allow(options, source.monitor, Some(reason)));
    let deny = |reason| outcome(Outcome::deny(options, source.monitor, reason));
    match *rule {
        // DNS traffic itself is reported from the DNS answers Portcullis inspects.
        Rule::AcceptDns {
            destination,
            protocol,
        } => {
            write!(out, "add rule {chain} ")?;
            if let Some(destination) = destination {
                write!(out, "{daddr} {destination} ")?;
            }
            writeln!(out, "{} accept", to.dport(protocol.as_str(), DNS_PORT))
        }
        Rule::DenyDns { protocol } => decide(
            out,
            format_args!("add rule {chain} {}", to.dport(protocol.as_str(), DNS_PORT)),
            deny("dns").snaplen(LOG_SNAPLEN_DNS),
        ),
        Rule::AcceptPeers { subnet, gateway } => {
            write!(out, "add rule {chain} {daddr} {subnet} ")?;
            if let Some(gateway) = gateway {
                write!(out, "{daddr} != {gateway} ")?;
            }
            writeln!(out, "accept")
        }
        Rule::AcceptNet(destination) => decide(
            out,
            format_args!("add rule {chain} {daddr} {destination}"),
            allow,
        ),
        Rule::AcceptHost(destination) => {
            writeln!(out, "add rule {chain} {daddr} {destination} accept")
        }
        Rule::DenyNet(destination) => decide(
            out,
            format_args!("add rule {chain} {daddr} {destination}"),
            deny(reason),
        ),
        Rule::AcceptPort {
            destination,
            protocol,
            port,
        } => {
            let port = to.dport(protocol.as_str(), port);
            let destination = match destination {
                Destination::Net(destination) => destination.to_string(),
                Destination::Addr(destination) => destination.to_string(),
                Destination::HostSet(index) => {
                    let Some(set) = plan.host_set(index) else {
                        return Ok(());
                    };
                    let prefix = if source.address.is_ipv4() {
                        SET_PREFIX_V4
                    } else {
                        SET_PREFIX_V6
                    };
                    format!("@{}", set.id.name(prefix))
                }
            };
            decide(
                out,
                format_args!("add rule {chain} {daddr} {destination} {port}"),
                allow,
            )
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
        monitor_source_queue: None,
        connection_limit: None,
        dns_query_queue: None,
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

    /// The de-duplicated log statement of a reported IPv4 decision, of the bridge table.
    fn log_rule(verdict: char, reason: &str) -> String {
        log_rule_keyed(
            verdict,
            reason,
            "ip saddr . ip daddr . meta l4proto . th dport",
        )
    }

    /// The same for an egress chain, which matches destinations before DNAT.
    fn egress_log_rule(verdict: char, reason: &str) -> String {
        log_rule_keyed(
            verdict,
            reason,
            "ip saddr . ct original ip daddr . meta l4proto . ct original proto-dst",
        )
    }

    fn log_rule_keyed(verdict: char, reason: &str, key: &str) -> String {
        let snaplen = if reason == "dns" { 512 } else { 128 };
        format!(
            "{key} != @logged4 add @logged4 {{ {key} }} log prefix \"pc:{verdict}:{reason}\" group 7 snaplen {snaplen}"
        )
    }

    /// The de-duplicated log statement of a reported frame decision.
    fn arp_log_rule(verdict: char) -> String {
        let key = "iifname . arp saddr ether . arp saddr ip";
        format!(
            "{key} != @announced add @announced {{ {key} }} log prefix \"pc:{verdict}:source\" group 7 snaplen 128"
        )
    }

    fn frame_log_rule(verdict: char, reason: &str) -> String {
        let key = "iifname . ether saddr . ether type";
        format!(
            "{key} != @frames add @frames {{ {key} }} log prefix \"pc:{verdict}:{reason}\" group 7 snaplen 128"
        )
    }

    /// The rules reporting and deciding a frame of `head`, for `reason`.
    fn framed(head: &str, verdict: char, reason: &str, action: &str) -> String {
        reported(head, &frame_log_rule(verdict, reason), action)
    }

    /// The rules denying, or reporting, the frames of a selector in the bridge base chain.
    /// They drop whatever the deny action: a rejection would go to the address the sender
    /// claims, or can't be sent for frames that aren't IP.
    fn denied_frames(selector: &str, verdict: char) -> String {
        let head = format!("add rule bridge portcullis prerouting {selector}");
        let action = if verdict == 'w' { "accept" } else { "drop" };
        [
            decided(&format!("{head} ether type ip"), verdict, "source", action),
            reported(
                &format!("{head} ether type arp"),
                &arp_log_rule(verdict),
                action,
            ),
            framed(&head, verdict, "frame", action),
        ]
        .join("\n")
    }

    /// The rules of a reported decision: the log rule, the log rule for when its
    /// de-duplication set is full, then the verdict rule.
    fn decided(head: &str, verdict: char, reason: &str, action: &str) -> String {
        let log = if head.contains(" egress") {
            egress_log_rule(verdict, reason)
        } else {
            log_rule(verdict, reason)
        };
        reported(head, &log, action)
    }

    fn reported(head: &str, log: &str, action: &str) -> String {
        let (key, rest) = log.split_once(" add @").expect("dedup rule");
        let statement = rest.split_once("} ").expect("log statement").1;
        format!("{head} {log}\n{head} {key} limit rate 10/second {statement}\n{head} {action}")
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
add chain bridge portcullis input { type filter hook input priority -1; policy accept; }
flush chain bridge portcullis input
add chain bridge portcullis forward { type filter hook forward priority -1; policy accept; }
flush chain bridge portcullis forward
add set bridge portcullis quarantined { type ifname; }
flush set bridge portcullis quarantined
add set bridge portcullis logged4 { type ipv4_addr . ipv4_addr . inet_proto . inet_service; flags dynamic,timeout; timeout 60s; size 65536; }
add set bridge portcullis frames { type ifname . ether_addr . ether_type; flags dynamic,timeout; timeout 60s; size 65536; }
add set bridge portcullis announced { type ifname . ether_addr . ipv4_addr; flags dynamic,timeout; timeout 60s; size 65536; }
flush chain bridge portcullis prerouting
add chain inet portcullis egress0
flush chain inet portcullis egress0
add chain bridge portcullis icc0
flush chain bridge portcullis icc0
add chain bridge portcullis limit_open
flush chain bridge portcullis limit_open
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
                "add rule inet portcullis input ct state established accept".into(),
                // ICMP errors only from an end of the connection they are about.
                "add rule inet portcullis egress0 ct state related ct original ip saddr 172.18.0.2 accept".into(),
                "add rule inet portcullis egress0 ct state related ct reply ip saddr 172.18.0.2 accept".into(),
                "add rule inet portcullis input ip saddr vmap { 172.18.0.2 : goto egress0 }".into(),
                "add rule inet portcullis input iifname { \"br-net0\" } drop".into(),
                // The gateway is the host: traffic to it follows the egress rules.
                "add rule inet portcullis egress0 ct original ip daddr 172.18.0.0/16 ct original ip daddr != 172.18.0.1 accept".into(),
                // Reported by the bridge table already.
                "add rule inet portcullis forward iifname { \"br-net0\" } drop".into(),
                decided("add rule inet portcullis egress0", 'd', "egress", "drop"),
                "add rule bridge portcullis prerouting meta ibrname != { \"br-net0\" } accept".into(),
                "add rule bridge portcullis prerouting ip saddr . ether saddr vmap { 172.18.0.2 . 02:42:ac:12:00:02 : goto icc0 }".into(),
                // ARP may only announce the container's own address and MAC.
                "add rule bridge portcullis prerouting ether saddr . arp saddr ether . arp saddr ip { 02:42:ac:12:00:02 . 02:42:ac:12:00:02 . 172.18.0.2, 02:42:ac:12:00:02 . 02:42:ac:12:00:02 . 0.0.0.0 } accept".into(),
                // Everything else is denied: IPv4 and ARP as a source that isn't the
                // sender's, other frames (IPv6, VLAN tags) as frames.
                denied_frames("meta ibrname { \"br-net0\" }", 'd'),
                // Established traffic passes once its source checked out.
                "add rule bridge portcullis icc0 ct state established accept\nadd rule bridge portcullis icc0 ct state related ct original ip saddr 172.18.0.2 accept\nadd rule bridge portcullis icc0 ct state related ct reply ip saddr 172.18.0.2 accept\nadd rule bridge portcullis icc0 ip daddr 172.18.0.1 accept".into(),
                decided("add rule bridge portcullis icc0 ip daddr 172.18.0.0/16", 'd', "icc", "drop"),
                // Broadcast and multicast reach every container on the bridge.
                decided("add rule bridge portcullis icc0 ip daddr 255.255.255.255/32", 'd', "icc", "drop"),
                decided("add rule bridge portcullis icc0 ip daddr 224.0.0.0/4", 'd', "icc", "drop"),
            ],
        );
        // nothing for families without sources
        assert!(!script.contains("ip6 saddr vmap"));
    }

    #[test]
    fn holds_unknown_sources_of_enforced_networks() {
        let options = Options {
            source_queue: Some(9),
            ..OPTIONS
        };
        let script = render_with(&test_support::hostname_state(), options, false);
        let expected = [
            denied_frames("meta ibrname { \"br-net0\" } meta mark 0x70630001", 'd'),
            "add rule bridge portcullis prerouting meta ibrname { \"br-net0\" } ether type { ip, arp } queue num 9".to_string(),
            denied_frames("meta ibrname { \"br-net0\" }", 'd'),
        ]
        .join("\n");
        assert!(script.contains(&format!("{expected}\n")), "{script}");
        // No bypass: without Portcullis, such packets aren't let through.
        assert!(!script.contains("bypass"), "{script}");

        // Monitor mode lets them through, reported.
        let monitored = render_with(&test_support::hostname_state(), options, true);
        assert!(!monitored.contains("queue num 9"), "{monitored}");
    }

    #[test]
    fn holds_unknown_sources_of_monitored_networks_failing_open() {
        let options = Options {
            source_queue: Some(9),
            monitor_source_queue: Some(10),
            ..OPTIONS
        };
        let script = render_with(&test_support::hostname_state(), options, true);
        let expected = [
            denied_frames("meta ibrname { \"br-net0\" } meta mark 0x70630001", 'w'),
            "add rule bridge portcullis prerouting meta ibrname { \"br-net0\" } ether type { ip, arp } queue num 10 bypass".to_string(),
            denied_frames("meta ibrname { \"br-net0\" }", 'w'),
        ]
        .join("\n");
        assert!(script.contains(&format!("{expected}\n")), "{script}");
        assert!(!script.contains("queue num 9"), "{script}");
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
            assert!(!script.contains("delete chain bridge portcullis input"));
            assert!(!script.contains("delete chain bridge portcullis forward"));
        }

        // What the previous update created and this one doesn't need is removed; the rest
        // is flushed and refilled.
        let removed: Vec<_> = chains(first).difference(&chains(second)).copied().collect();
        assert_ne!(removed, [] as [&str; 0]);
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
    fn binds_sources_to_their_bridge_port() {
        let mut state = test_support::icc_state();
        state.set_ports(
            [(
                test_support::ip("172.18.0.2"),
                crate::model::BridgePort {
                    name: "veth0a1b2c3".to_string(),
                    index: 9,
                },
            )]
            .into(),
        );
        let script = render(&state);
        let line = |prefix: &str| {
            script
                .lines()
                .find(|line| line.starts_with(prefix))
                .unwrap_or_default()
                .to_string()
        };
        // web's address and MAC only count from its own port...
        assert!(
            line("add rule bridge portcullis prerouting iifname . ip saddr . ether saddr vmap")
                .contains("\"veth0a1b2c3\" . 172.18.0.2 . 02:42:ac:12:00:02 : goto icc"),
            "{script}"
        );
        // ...and not without it; containers whose port isn't known are checked by address
        // and MAC.
        let by_mac = line("add rule bridge portcullis prerouting ip saddr . ether saddr vmap");
        assert!(!by_mac.contains("172.18.0.2 "), "{script}");
        assert!(
            by_mac.contains("172.18.0.3 . 02:42:ac:12:00:03"),
            "{script}"
        );
        // ARP may only announce web's own address and MAC, from its port.
        assert!(has_line(
            &script,
            "add rule bridge portcullis prerouting iifname . ether saddr . arp saddr ether . arp saddr ip { \"veth0a1b2c3\" . 02:42:ac:12:00:02 . 02:42:ac:12:00:02 . 172.18.0.2, \"veth0a1b2c3\" . 02:42:ac:12:00:02 . 02:42:ac:12:00:02 . 0.0.0.0 } accept"
        ));
        // Anything else from web's port is denied at once, not held.
        let options = Options {
            source_queue: Some(9),
            ..OPTIONS
        };
        let script = render_with(&state, options, false);
        let known_port = denied_frames(
            "meta ibrname { \"br-net0\", \"br-net1\" } iifname { \"veth0a1b2c3\" }",
            'd',
        );
        let held = "add rule bridge portcullis prerouting meta ibrname { \"br-net0\", \"br-net1\" } ether type { ip, arp } queue num 9";
        let position = |text: &str| script.find(text).unwrap_or(usize::MAX);
        assert!(position(&known_port) < position(held), "{script}");
    }

    #[test]
    fn limits_and_quarantines_containers_by_port() {
        let mut state = RuntimeState::default();
        test_support::add_network(&mut state, "net0", "172.18.0.0/16", "172.18.0.1");
        let limited = crate::model::ContainerPolicy {
            connection_limit: ConnectionLimit::At(10),
            new_connection_rate: Some(5),
            ..crate::model::ContainerPolicy::default()
        };
        test_support::add_container(
            &mut state,
            "a",
            "busy",
            &[("net0", "172.18.0.2", &[])],
            limited,
        );
        test_support::add_container(
            &mut state,
            "b",
            "rogue",
            &[("net0", "172.18.0.3", &[])],
            crate::model::ContainerPolicy::default(),
        );
        let port = |name: &str, index| crate::model::BridgePort {
            name: name.to_string(),
            index,
        };
        state.set_ports(
            [
                (test_support::ip("172.18.0.2"), port("veth2", 2)),
                (test_support::ip("172.18.0.3"), port("veth3", 3)),
            ]
            .into(),
        );
        assert!(state.quarantine(&"b".to_string().into()));
        let options = Options {
            connection_limit: Some(1000),
            ..OPTIONS
        };
        let script = render_with(&state, options, false);
        assert_lines(
            &script,
            &[
                // Quarantined ports get nowhere, before anything else is checked.
                "add element bridge portcullis quarantined { \"veth3\" }".into(),
                "add rule bridge portcullis prerouting meta ibrname != { \"br-net0\" } accept\nadd rule bridge portcullis prerouting iifname @quarantined drop".into(),
                "add rule bridge portcullis input iifname @quarantined drop".into(),
                // Open connections: the label's limit, or the default.
                "add rule bridge portcullis prerouting iifname { \"veth2\" } ct state new add @conns10 { iifname ct count over 10 } goto limit_open".into(),
                "add rule bridge portcullis prerouting iifname { \"veth3\" } ct state new add @conns1000 { iifname ct count over 1000 } goto limit_open".into(),
                // New connections per second, only where a label asks for it.
                "add rule bridge portcullis prerouting iifname { \"veth2\" } ct state new add @new5 { iifname limit rate over 5/second burst 5 packets } goto limit_rate".into(),
                "add set bridge portcullis conns10 { type ifname; flags dynamic; size 65536; }".into(),
                "add set bridge portcullis new5 { type ifname; flags dynamic,timeout; timeout 60s; size 65536; }".into(),
                decided("add rule bridge portcullis limit_open", 'd', "limit:open", "drop"),
                decided("add rule bridge portcullis limit_rate", 'd', "limit:rate", "drop"),
            ],
        );
    }

    #[test]
    fn holds_dns_queries_of_containers_with_limited_names() {
        let mut state = RuntimeState::default();
        test_support::add_network(&mut state, "net0", "172.18.0.0/16", "172.18.0.1");
        let limited = crate::model::ContainerPolicy {
            domains: Some(vec!["api.test".to_string()]),
            ..crate::model::ContainerPolicy::default()
        };
        test_support::add_container(
            &mut state,
            "a",
            "named",
            &[("net0", "172.18.0.2", &[])],
            limited,
        );
        test_support::add_container(
            &mut state,
            "b",
            "free",
            &[("net0", "172.18.0.3", &[])],
            crate::model::ContainerPolicy::default(),
        );
        let options = Options {
            dns_query_queue: Some(9),
            ..OPTIONS
        };
        let script = render_with(&state, options, false);
        for base in ["forward", "input"] {
            let head = format!("add rule inet portcullis {base}");
            let expected = [
                format!("{head} ip saddr {{ 172.18.0.2 }} meta l4proto {{ tcp, udp }} th dport 53 ct direction original meta mark != 0x70630003 meta mark != 0x70630002 queue num 9"),
                format!("{head} meta mark 0x70630002 meta l4proto tcp reject with tcp reset"),
                format!("{head} meta mark 0x70630002 reject with icmpx admin-prohibited"),
                format!("{head} meta mark 0x70630003 meta mark set 0x0"),
                format!("{head} ct state established accept"),
            ]
            .join("\n");
            assert!(script.contains(&expected), "{script}");
        }
    }

    #[test]
    fn renders_reject_as_deny_action() {
        let options = Options {
            deny: DenyAction::Reject,
            ..OPTIONS
        };
        let script = render_with(&test_support::hostname_state(), options, false);
        let reject = "reject with icmpx admin-prohibited";
        // Only traffic denied for what it is, not where it goes, is dropped.
        for line in script.lines().filter(|line| line.ends_with(" drop")) {
            assert!(
                line.starts_with("add rule bridge portcullis prerouting ")
                    || line.starts_with("add rule bridge portcullis forward ")
                    || line.starts_with("add rule bridge portcullis limit_")
                    || line.contains("@quarantined")
                    || line.contains(LINK_LOCAL_GROUP),
                "{line}"
            );
        }
        assert_lines(
            &script,
            &[
                format!("add rule inet portcullis forward iifname {{ \"br-net0\" }} {reject}"),
                decided(
                    "add rule inet portcullis egress0 meta l4proto udp ct original proto-dst 53",
                    'd',
                    "dns",
                    reject,
                ),
                decided("add rule inet portcullis egress0", 'd', "egress", reject),
                denied_frames("meta ibrname { \"br-net0\" }", 'd'),
            ],
        );
    }

    #[test]
    fn monitor_mode_reports_instead_of_denying() {
        let script = render_with(&test_support::hostname_state(), OPTIONS, true);
        // Only quarantined and limited containers' traffic is dropped, which monitor mode
        // never does to anyone.
        assert!(
            script
                .lines()
                .filter(|line| line.ends_with(" drop"))
                .all(|line| line.contains("@quarantined")
                    || line.contains(" limit_open ")
                    || line.contains(" limit_rate ")),
            "{script}"
        );
        assert!(!script.contains("iifname {"), "{script}");
        assert_lines(
            &script,
            &[
                decided("add rule inet portcullis egress0", 'w', "egress", "accept"),
                decided(
                    "add rule inet portcullis egress0 meta l4proto udp ct original proto-dst 53",
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
                denied_frames("meta ibrname { \"br-net0\" }", 'w'),
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
        assert!(monitored.contains(&format!(
            "ct original proto-dst 443 {}",
            egress_log_rule('a', "egress")
        )));
    }

    #[test]
    fn holds_dns_answers_for_inspection() {
        let options = Options {
            dns_queue: Some(9),
            ..OPTIONS
        };
        let script = render_with(&test_support::hostname_state(), options, false);
        let queue = "add rule inet portcullis forward oifname { \"br-net0\" } meta l4proto { tcp, udp } th sport 53 ct direction reply queue num 9 bypass";
        let established = "add rule inet portcullis forward ct state established accept";
        let position = |line: &str| script.lines().position(|candidate| candidate == line);
        assert!(
            position(queue).expect("queue rule") < position(established).expect("established rule")
        );
    }

    #[test]
    fn renders_hostname_sets_with_timeouts_once_per_container_and_host() {
        let script = render(&test_support::shared_hostname_state());
        assert_eq!(script.matches("add set inet portcullis pc_h4_").count(), 2);
        assert!(script.contains("{ type ipv4_addr; flags timeout; size 8192; }"));
        assert!(script.contains(" { 1.1.1.1 timeout 3600s }\n"));
        assert_eq!(script.matches("ct original ip daddr @pc_h4_").count(), 2);
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
            "add rule inet portcullis egress0 ct original ip6 daddr 2001:db8::/32 meta l4proto tcp ct original proto-dst 443 accept"
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
        assert!(script.contains("ct original ip daddr @pc_h4_"));
        assert!(script.contains(
            "ct original ip daddr 8.8.8.0/24 meta l4proto tcp ct original proto-dst 853 accept"
        ));
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
    fn saves_rules_to_restore_them_at_the_next_start() {
        let path =
            std::env::temp_dir().join(format!("portcullis-saved-{}/rules.nft", std::process::id()));
        let _ = fs::remove_file(&path);
        let firewall =
            NftablesFirewall::new(RecordingRunner::default(), OPTIONS).saving_to(path.clone());
        assert!(!firewall.restore().expect("restore"), "nothing saved yet");
        let mut resolver = MockResolver::default();
        for state in [test_support::icc_state(), test_support::hostname_state()] {
            firewall
                .apply(&state, &mut resolver, &[], false)
                .expect("apply");
        }
        // The saved script installs the last update's rules from scratch, unlike the
        // update itself.
        let saved = fs::read_to_string(&path).expect("saved");
        assert!(saved.starts_with("add table inet portcullis\ndelete table inet portcullis\n"));
        // ...with nothing of the update before it.
        assert!(saved.contains("ct original ip daddr @pc_h4_"));
        assert!(!saved.contains("delete chain"), "{saved}");

        // Restoring runs it, and the next update starts from empty tables again.
        assert!(firewall.restore().expect("restore"));
        firewall
            .apply(&test_support::icc_state(), &mut resolver, &[], false)
            .expect("apply");
        let scripts = firewall.runner.scripts.lock().expect("lock");
        assert_eq!(scripts.get(2), Some(&saved));
        assert!(
            scripts
                .get(3)
                .is_some_and(|script| script.contains("delete table"))
        );
        drop(scripts);

        firewall.forget_saved().expect("forget");
        assert!(!path.exists());
        firewall.forget_saved().expect("forgetting twice");
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
