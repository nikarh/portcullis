use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write as _};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use tracing::{debug, info, trace, warn};

use super::FirewallError;
use super::elements::{TimeoutSet, encode_timeouts};
use super::netlink::{self, Encoder, NftSocket};
use super::plan::{
    DNS_PORT, Destination, HostSet, HostSetId, ICC_BROADCAST_V4, PRIVATE_V4, PRIVATE_V6, Plan,
    Rule, SET_PREFIX_V4, SET_PREFIX_V6, Source,
};
use super::ruleset::{
    Batch, Chain, Command, CtState, Element, Expr, Key, KeyType, Object, Part, SetDecl, SetFlags,
    Stateful, TABLE_NAME, Table, Value, Verdict,
};
use crate::dns::{HostResolver, MAX_ADDRESSES_PER_HOST};
use crate::model::{
    ConnectionLimit, ContainerName, MacAddress, PortState, Protocol, RuntimeState, Service,
};

pub trait NftRunner {
    /// Put the commands of `batch` in place, as a single atomic transaction.
    fn run(&self, batch: &Batch) -> Result<(), FirewallError>;
    /// Put a batch saved as encoded (see [`NftablesFirewall::save`]) in place, as a single
    /// atomic transaction.
    fn run_encoded(&self, batch: &mut [u8]) -> Result<(), FirewallError>;
    /// The chains and sets of the managed tables, or `None` unless both exist.
    fn installed(&self) -> Result<Option<Found>, FirewallError>;
    /// Set how much longer each address stays in the hostname sets of the inet table that
    /// hold its family, in one transaction (see [`render_timeouts`]).
    fn set_timeouts(
        &self,
        sets: &[TimeoutSet<'_>],
        addresses: &[(IpAddr, Duration)],
    ) -> Result<(), FirewallError>;
}

/// The chains (and whether each is a base chain) and sets of the managed tables.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    pub chains: Vec<(Object, bool)>,
    pub sets: Vec<Object>,
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

impl DenyAction {
    const fn expr(self) -> Expr {
        match self {
            Self::Reject => Expr::Reject { tcp_reset: false },
            Self::Drop => Expr::Verdict(Verdict::Drop),
        }
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

pub struct NftablesFirewall<R = NetlinkRunner> {
    runner: R,
    options: Options,
    /// What the last successful update installed; `None` before the first one and after a
    /// cleanup, when the tables may hold leftovers of another run.
    installed: Mutex<Option<Installed>>,
    /// Where the rules of every update are saved, to be restored at the next start.
    saved: Option<PathBuf>,
}

/// Chains and sets an update created besides the fixed base chains and log sets. The next
/// update deletes the ones it doesn't need anymore.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Installed {
    chains: BTreeSet<Object>,
    sets: BTreeSet<Object>,
    /// The container of each managed address.
    sources: BTreeMap<IpAddr, ContainerName>,
    /// The slot of each managed address, which numbers its chains.
    slots: Slots,
    /// What the chains and sets hold, as far as an update needs to know to only write what
    /// changed. Taken out by the next update: after a failed one, everything is written
    /// again.
    written: Written,
    /// Found in place at the start, rather than installed by this run.
    found: bool,
    /// Left in place by a previous run that stopped, rather than put back from the saved
    /// rules: the addresses in its hostname sets are as current as that run left them.
    kept: bool,
    /// Hostname sets whose addresses to renew once the update is in place.
    renewals: Vec<Renewal>,
    /// The plan of the last update, once it is in place.
    applied: Option<Plan>,
}

/// What [`NftablesFirewall::apply_with`] did.
#[derive(Debug)]
pub struct Update {
    pub plan: Plan,
    /// Whether anything was put in place: not when the rules were those of the plan already.
    pub changed: bool,
}

/// The addresses Portcullis knows for a hostname set it kept from a previous run, to renew
/// in it: the update only adds those the set doesn't hold.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Renewal {
    set: String,
    ipv6: bool,
    addresses: Vec<(IpAddr, Duration)>,
}

impl Installed {
    /// What an update needs to know of `found`: the chains and sets it may delete, all
    /// but the base chains and the sets every update creates anyway.
    fn of(found: Found) -> Self {
        let fixed = |set: &Object| {
            NamedSet::ALL
                .iter()
                .any(|named| named.table() == set.table && named.name() == set.name)
                || [
                    QUARANTINED_SET,
                    LOGGED_SET_V4,
                    LOGGED_SET_V6,
                    LOGGED_SET_FRAMES,
                    LOGGED_SET_ARP,
                ]
                .contains(&set.name.as_str())
        };
        Self {
            chains: found
                .chains
                .into_iter()
                .filter_map(|(chain, base)| (!base).then_some(chain))
                .collect(),
            sets: found.sets.into_iter().filter(|set| !fixed(set)).collect(),
            found: true,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Written {
    /// What each source's chain was written from. A chain written from the same isn't
    /// written again.
    rules: HashMap<Chain, ChainInputs>,
    /// The elements of each named set, so that only elements that changed are added and
    /// deleted. `None` when the sets may hold others: found in place at the start, or
    /// after an update failed.
    elements: Option<HashMap<NamedSet, Vec<Element>>>,
    /// The addresses each hostname set was filled with, by set.
    host_addresses: HashMap<String, String>,
}

/// What [`NftablesFirewall::restore`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restored {
    /// Rules a previous run left in place, kept.
    Kept,
    /// The rules a previous run saved, put in place.
    Saved,
    /// No rules of a previous run.
    Nothing,
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

    /// Get the rules of a previous run in place. Rules a previous run left in place (it
    /// stopped, keeping them) are kept, and the first update changes what it needs of them,
    /// as any other update would: deleting and creating the tables again would misjudge
    /// packets that pass meanwhile, denying established connections. Otherwise the rules a
    /// previous run saved are put in place, if any (after a reboot).
    pub fn restore(&self) -> Result<Restored, FirewallError> {
        if let Some(found) = self.find_installed()? {
            *self
                .installed
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(Installed {
                kept: true,
                ..found
            });
            return Ok(Restored::Kept);
        }
        let Some(path) = &self.saved else {
            return Ok(Restored::Nothing);
        };
        let mut saved = match fs::read(path) {
            Ok(saved) => saved,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Restored::Nothing),
            Err(error) => return Err(FirewallError::Saved(error)),
        };
        let current = saved.starts_with(SAVED_HEADER);
        let Some(batch) = saved.get_mut(SAVED_HEADER.len()..).filter(|_| current) else {
            warn!(
                path = %path.display(),
                "the saved rules aren't in a format this version reads; the first update \
                 puts the rules in place"
            );
            return Ok(Restored::Nothing);
        };
        self.runner.run_encoded(batch)?;
        // What the batch installed is known by name only from the kernel.
        *self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = self.find_installed()?;
        Ok(Restored::Saved)
    }

    /// The chains and sets of both tables, when both exist.
    fn find_installed(&self) -> Result<Option<Installed>, FirewallError> {
        Ok(self.runner.installed()?.map(Installed::of))
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

    /// Save the rules of `plan`, just applied, for `restore` at the next start, as the
    /// netlink batch that installs them from scratch. Written to a temporary file first and
    /// renamed, so a crash never leaves half a batch. Not part of `apply`: writing them can
    /// take a while, and what the new rules report should be attributed
    /// (`Directory::update`) as soon as they are in place.
    pub fn save(&self, plan: &Plan) -> Result<(), FirewallError> {
        let Some(path) = &self.saved else {
            return Ok(());
        };
        let saved = encode_saved(&fresh_batch(plan, self.options));
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
            file.write_all(&saved)?;
            file.sync_all()?;
            fs::rename(&temporary, path)
        };
        write().map_err(FirewallError::Saved)
    }

    /// Apply rules for `state`. Returns the plan that was applied.
    #[cfg(test)]
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
        self.apply_with(state, hosts, host_resolvers, monitor_all, |_| {})
            .map(|update| update.plan)
    }

    /// `apply`, calling `before` with the plan just before its rules are put in place.
    ///
    /// When the rules in place are those of the plan already (the last update put them in
    /// place, see [`Plan::same_rules`]), nothing is put in place and `before` isn't called:
    /// changes of the state that don't change the rules, such as Docker's report of a
    /// container found before it, cost no update.
    pub fn apply_with<Hosts>(
        &self,
        state: &RuntimeState,
        hosts: &mut Hosts,
        host_resolvers: &[IpAddr],
        monitor_all: bool,
        before: impl FnOnce(&Plan),
    ) -> Result<Update, FirewallError>
    where
        Hosts: HostResolver,
    {
        let started = Instant::now();
        let plan = Plan::build(state, hosts, host_resolvers, monitor_all);
        let planned = started.elapsed();
        let mut installed = self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(current) = installed.as_mut() {
            // Taken out: should this update fail, the next one isn't skipped.
            if current
                .applied
                .take()
                .is_some_and(|applied| applied.same_rules(&plan))
            {
                current.applied = Some(plan.clone());
                debug!(
                    container_count = state.containers().len(),
                    "the rules in place are the same; nothing to change"
                );
                return Ok(Update {
                    plan,
                    changed: false,
                });
            }
        }
        info!(
            source_count = plan.sources.len(),
            rule_count = plan.rule_count(),
            host_set_count = plan.host_sets.len(),
            container_count = state.containers().len(),
            "applying nftables changes"
        );

        let mut batch = Batch::default();
        // Takes the rules of the installed chains out of `installed`: should the update fail,
        // the next one writes every chain again.
        let now_installed =
            render_apply_script(&plan, self.options, installed.as_mut(), &mut batch);
        before(&plan);
        let mut now_installed = match self.runner.run(&batch) {
            Ok(()) => now_installed,
            // Tables another version left may not fit these rules (a set of another type):
            // start from empty ones.
            Err(error) if installed.as_ref().is_some_and(|installed| installed.found) => {
                warn!(%error, "can't update the rules found in place; replacing them");
                let mut batch = Batch::default();
                let now_installed = render_apply_script(&plan, self.options, None, &mut batch);
                self.runner.run(&batch)?;
                now_installed
            }
            Err(error) => return Err(error),
        };
        for renewal in std::mem::take(&mut now_installed.renewals) {
            let set = TimeoutSet {
                name: &renewal.set,
                ipv6: renewal.ipv6,
            };
            if let Err(error) = self.runner.set_timeouts(&[set], &renewal.addresses) {
                warn!(%error, set = renewal.set, "can't renew the addresses of a hostname set");
            }
        }
        now_installed.applied = Some(plan.clone());
        *installed = Some(now_installed);
        drop(installed);
        debug!(plan = ?planned, total = ?started.elapsed(), "nftables update timings");
        Ok(Update {
            plan,
            changed: true,
        })
    }

    /// Set how much longer each of `addresses` stays allowed in a hostname set of the
    /// current rules, whether it is in the set already or not; zero removes it.
    pub fn update_host_addresses(
        &self,
        set: &HostSet,
        addresses: &[(IpAddr, Duration)],
    ) -> Result<(), FirewallError> {
        let (v4, v6) = (set.id.name(SET_PREFIX_V4), set.id.name(SET_PREFIX_V6));
        let both = [
            TimeoutSet {
                name: &v4,
                ipv6: false,
            },
            TimeoutSet {
                name: &v6,
                ipv6: true,
            },
        ];
        let used = match (set.used_v4, set.used_v6) {
            (true, true) => &both[..],
            (true, false) => &both[..1],
            (false, true) => &both[1..],
            (false, false) => return Ok(()),
        };
        if addresses.is_empty() {
            return Ok(());
        }
        self.runner.set_timeouts(used, addresses)
    }

    pub fn cleanup(&self) -> Result<(), FirewallError> {
        let mut batch = Batch::default();
        render_table_reset(&mut batch);
        self.runner.run(&batch)?;
        *self
            .installed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        info!("nftables cleanup completed");
        Ok(())
    }
}

impl NftablesFirewall<NetlinkRunner> {
    pub fn with_netlink(options: Options) -> Result<Self, FirewallError> {
        let runner = NetlinkRunner::new()?;
        Ok(Self::new(runner, options))
    }
}

/// What a saved batch starts with: its format, which a later version may change.
const SAVED_HEADER: &[u8] = b"portcullis nf_tables batch 1
";

/// The saved form of `batch`: the header, then the encoded batch.
fn encode_saved(batch: &Batch) -> Vec<u8> {
    let mut encoded = Vec::new();
    Encoder::new(&mut encoded).batch(batch);
    let mut saved = Vec::with_capacity(SAVED_HEADER.len() + encoded.len());
    saved.extend_from_slice(SAVED_HEADER);
    saved.extend_from_slice(&encoded);
    saved
}

/// The commands that put the rules of `plan` in place from scratch.
pub(super) fn fresh_batch(plan: &Plan, options: Options) -> Batch {
    let mut batch = Batch::default();
    render_apply_script(plan, options, None, &mut batch);
    batch
}

/// Remove the managed tables, whether or not they exist, so neither cleanup nor apply
/// depend on prior state or on matching error strings.
fn render_table_reset(out: &mut Batch) {
    for table in Table::ALL {
        out.push(Command::ResetTable(table));
    }
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

    /// The verdict alone.
    const fn verdict(&self) -> Expr {
        if self.allow || self.monitor {
            Expr::Verdict(Verdict::Accept)
        } else if self.drop {
            Expr::Verdict(Verdict::Drop)
        } else {
            self.options.deny.expr()
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
const LOGGED_TIMEOUT: Duration = Duration::from_secs(60);
const LOGGED_SIZE: u32 = 65_536;

/// Create the sets of reported flows; with `flush`, forget the flows reported so far.
fn render_logged_sets(out: &mut Batch, table: Table, flush: bool) {
    const FLOW_V4: &[KeyType] = &[
        KeyType::Ipv4,
        KeyType::Ipv4,
        KeyType::InetProto,
        KeyType::InetService,
    ];
    const FLOW_V6: &[KeyType] = &[
        KeyType::Ipv6,
        KeyType::Ipv6,
        KeyType::InetProto,
        KeyType::InetService,
    ];
    const FRAME: &[KeyType] = &[KeyType::Ifname, KeyType::Ether, KeyType::EtherType];
    const ARP: &[KeyType] = &[KeyType::Ifname, KeyType::Ether, KeyType::Ipv4];
    let sets: &[(&'static str, &'static [KeyType])] = match table {
        Table::Inet => &[(LOGGED_SET_V4, FLOW_V4), (LOGGED_SET_V6, FLOW_V6)],
        Table::Bridge => &[
            (LOGGED_SET_V4, FLOW_V4),
            (LOGGED_SET_FRAMES, FRAME),
            (LOGGED_SET_ARP, ARP),
        ],
    };
    for &(name, key) in sets {
        let decl = SetDecl {
            flags: SetFlags {
                dynamic: true,
                timeout: true,
            },
            timeout: Some(LOGGED_TIMEOUT),
            size: Some(LOGGED_SIZE),
            ..SetDecl::set(table, name, key)
        };
        out.push(Command::AddSet(decl.clone()));
        if flush {
            out.push(Command::FlushSet(decl));
        }
    }
}

/// Render a decision: `head` (matches of a rule of `chain`) followed by the outcome. A
/// reported outcome gets rules before it that log the packet, but only the first of its
/// flow within the de-duplication timeout; the verdict rule applies to every packet.
fn decide(out: &mut Batch, chain: Chain, head: Vec<Expr>, outcome: Outcome) {
    const IPV4: &[Key] = &[Key::IpSaddr, Key::IpDaddr, Key::L4proto, Key::ThDport];
    const IPV6: &[Key] = &[Key::Ip6Saddr, Key::Ip6Daddr, Key::L4proto, Key::ThDport];
    const ORIGINAL_V4: &[Key] = &[
        Key::IpSaddr,
        Key::CtDaddr { ipv6: false },
        Key::L4proto,
        Key::CtProtoDst,
    ];
    const ORIGINAL_V6: &[Key] = &[
        Key::Ip6Saddr,
        Key::CtDaddr { ipv6: true },
        Key::L4proto,
        Key::CtProtoDst,
    ];
    const FRAME: &[Key] = &[Key::Iifname, Key::EtherSaddr, Key::EtherType];
    const ARP: &[Key] = &[Key::Iifname, Key::ArpSaddrEther, Key::ArpSaddrIp];
    if let Some((verdict, reason)) = outcome.log_prefix() {
        let (set, key) = match outcome.key {
            LogKey::Ipv4 => (LOGGED_SET_V4, IPV4),
            LogKey::Ipv6 => (LOGGED_SET_V6, IPV6),
            LogKey::OriginalV4 => (LOGGED_SET_V4, ORIGINAL_V4),
            LogKey::OriginalV6 => (LOGGED_SET_V6, ORIGINAL_V6),
            LogKey::Frame => (LOGGED_SET_FRAMES, FRAME),
            LogKey::Arp => (LOGGED_SET_ARP, ARP),
        };
        let log = Expr::Log {
            prefix: Cow::Owned(format!("{LOG_PREFIX}:{verdict}:{reason}")),
            group: outcome.options.log_group,
            snaplen: outcome.snaplen,
        };
        let not_logged = Expr::Lookup {
            key,
            set: Cow::Borrowed(set),
            negate: true,
        };
        let mut first = head.clone();
        first.extend([
            not_logged.clone(),
            Expr::AddToSet {
                key,
                set: Cow::Borrowed(set),
                stateful: None,
            },
            log.clone(),
        ]);
        out.rule(chain, first);
        // Adding to a full set fails, and so would the log statement after it: anyone able
        // to fill the set with flows of their own would make every denial after it go
        // unreported. A flow the rule above didn't add is still logged, at a limited rate
        // per rule, so one source can't drown out the others either.
        let mut second = head.clone();
        second.extend([
            not_logged,
            Expr::Limit {
                rate: LOG_FULL_RATE,
                burst: None,
                over: false,
            },
            log,
        ]);
        out.rule(chain, second);
    }
    let mut verdict = head;
    verdict.push(outcome.verdict());
    out.rule(chain, verdict);
}

/// How often (per second) a rule reports flows once its de-duplication set is full.
const LOG_FULL_RATE: u32 = 10;

const ACCEPT: Expr = Expr::Verdict(Verdict::Accept);

/// Render the commands of a rule update.
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
    previous: Option<&mut Installed>,
    out: &mut Batch,
) -> Installed {
    render_update(plan, options, previous, Slots::default(), out)
}

/// [`render_apply_script`], with the slots sources keep from scratch (without `previous`).
fn render_update(
    plan: &Plan,
    options: Options,
    previous: Option<&mut Installed>,
    slots: Slots,
    out: &mut Batch,
) -> Installed {
    let empty = Installed {
        slots,
        ..Installed::default()
    };
    let (previous, mut written) = if let Some(previous) = previous {
        let written = std::mem::take(&mut previous.written);
        (&*previous, written)
    } else {
        render_table_reset(out);
        (&empty, Written::default())
    };
    let mut elements = Elements::default();
    let slots = Slots::assign(plan, &previous.slots);
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
    render_declarations(out, plan, reassigned);

    let mut installed = render_objects(
        out,
        plan,
        options,
        previous,
        &slots,
        &mut written.host_addresses,
    );
    installed.sources = sources;

    render_source_chains(
        out,
        plan,
        options,
        &slots,
        &mut written.rules,
        &mut installed,
    );

    // Routed traffic.
    let base = Chain::Base(Table::Inet);
    let bridges = |mode: Option<bool>| {
        plan.bridges
            .iter()
            .filter(move |bridge| mode.is_none_or(|monitor| bridge.monitor == monitor))
            .map(|bridge| Element::of(&[Part::Ifname(&bridge.name)]))
    };
    elements.fill(NamedSet::InetBridges, bridges(None));
    elements.fill(NamedSet::InetEnforcedBridges, bridges(Some(false)));
    elements.fill(NamedSet::BridgeBridges, bridges(None));
    elements.fill(NamedSet::MonitoredBridges, bridges(Some(true)));
    elements.fill(NamedSet::EnforcedBridges, bridges(Some(false)));
    if let Some(queue) = options.dns_queue
        && !plan.bridges.is_empty()
    {
        // Hold DNS answers to managed containers until the addresses they contain are
        // allowed. `bypass` lets them through when Portcullis isn't listening.
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            out.rule(
                base,
                vec![
                    Expr::lookup(&[Key::Oifname], NamedSet::InetBridges.name()),
                    Expr::cmp(Key::L4proto, Value::Protocol(protocol, false)),
                    Expr::cmp(Key::ThSport, Value::Range(DNS_PORT, DNS_PORT)),
                    Expr::cmp(Key::CtDirection, Value::Reply),
                    Expr::Queue {
                        num: queue,
                        bypass: true,
                    },
                ],
            );
        }
    }
    // Traffic to the host itself (services on the host, and other containers' published
    // ports through Docker's userland proxy) leaves the container's network as much as
    // routed traffic does, and follows the same rules.
    for base in [base, Chain::Input] {
        render_egress_dispatch(out, plan, options, base, &slots, &mut elements);
    }

    // Everything entering a managed network's bridge from a container: source checks and
    // traffic between containers on the same network. Established traffic only passes
    // once its source checks out, in the ICC chains: a container could otherwise send with
    // another container's address into that container's connections.
    if !plan.bridges.is_empty() {
        render_bridge_dispatch(out, plan, options, &slots, &mut elements);
        render_link_local(out, plan, options);
        render_bridged_destinations(out, plan, options);
    }
    elements.render(out, written.elements.as_ref());
    installed.written.elements = Some(elements.0);
    // Nothing references them anymore: their map elements are gone, and the chains whose
    // rules used the sets were written again.
    for chain in previous.chains.difference(&installed.chains) {
        out.push(Command::DeleteChain(chain.clone()));
    }
    for set in previous.sets.difference(&installed.sets) {
        out.push(Command::DeleteSet(set.clone()));
    }
    installed.slots = slots;
    installed
}

/// Create the tables, base chains and fixed sets, and empty the base chains.
fn render_declarations(out: &mut Batch, plan: &Plan, reassigned: bool) {
    for table in Table::ALL {
        out.push(Command::AddTable(table));
        out.push(Command::AddChain(Chain::Base(table)));
        let input = match table {
            Table::Inet => Chain::Input,
            Table::Bridge => Chain::BridgeInput,
        };
        out.push(Command::AddChain(input));
        out.push(Command::FlushChain(input));
        if table == Table::Bridge {
            out.push(Command::AddChain(Chain::BridgeForward));
            out.push(Command::FlushChain(Chain::BridgeForward));
            render_quarantined_set(out, plan);
        }
        render_logged_sets(out, table, reassigned);
        out.push(Command::FlushChain(Chain::Base(table)));
        // Changed at the end, see `Elements::render`.
        for set in NamedSet::ALL.iter().filter(|set| set.table() == table) {
            out.push(Command::AddSet(set.declaration()));
        }
    }
}

/// The chains of each source, before the maps that lead to them are filled. Only those
/// whose rules changed are written: whether they did is told from what the rules are
/// written from ([`ChainInputs`]), without writing them.
fn render_source_chains(
    out: &mut Batch,
    plan: &Plan,
    options: Options,
    slots: &Slots,
    previous: &mut HashMap<Chain, ChainInputs>,
    installed: &mut Installed,
) {
    for source in &plan.sources {
        let chain = Chain::Egress(slots.of(source));
        let rules = plan.egress_rules(source);
        let written = Written::chain(plan, source, chain, rules, previous, installed);
        if !written {
            begin_chain(out, chain);
            render_related(out, chain, source.address);
            for rule in rules {
                render_rule(plan, source, chain, rule, options, out);
            }
            decide(
                out,
                chain,
                Vec::new(),
                Outcome::deny(options, source.monitor, "egress")
                    .for_address(source.address)
                    .original(),
            );
        }
        if source.address.is_ipv4() && icc_chain_needed(plan, source, options) {
            let chain = Chain::Icc(slots.of(source));
            let rules = plan.icc_rules(source);
            if !Written::chain(plan, source, chain, rules, previous, installed) {
                begin_chain(out, chain);
                out.rule(
                    chain,
                    vec![
                        Expr::cmp(Key::CtState, Value::CtState(CtState::Established)),
                        ACCEPT,
                    ],
                );
                render_related(out, chain, source.address);
                for rule in rules {
                    render_rule(plan, source, chain, rule, options, out);
                }
            }
        }
    }
}

/// Create `chain` if it isn't there, and empty it.
fn begin_chain(out: &mut Batch, chain: Chain) {
    out.push(Command::AddChain(chain));
    out.push(Command::FlushChain(chain));
}

/// What the rules of a source's chain are written from, besides the chain itself and the
/// options, which stay the same: the source's address and mode, and its rules, with
/// hostname sets by their IDs (the plan's indexes of them change from one update to the
/// next).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChainInputs {
    address: IpAddr,
    monitor: bool,
    rules: Vec<(Rule, Option<HostSetId>)>,
}

impl ChainInputs {
    fn of(plan: &Plan, source: &Source, rules: &[Rule]) -> Self {
        Self {
            address: source.address,
            monitor: source.monitor,
            rules: rules.iter().map(|rule| rule_input(plan, *rule)).collect(),
        }
    }

    /// Whether the chain of `source` with `rules` is written from these.
    fn are(&self, plan: &Plan, source: &Source, rules: &[Rule]) -> bool {
        self.address == source.address
            && self.monitor == source.monitor
            && self.rules.len() == rules.len()
            && self
                .rules
                .iter()
                .zip(rules)
                .all(|(input, rule)| *input == rule_input(plan, *rule))
    }
}

/// A rule as its chain is written from it: a hostname set by its ID, or `None` when the
/// set isn't there (and the rule isn't written).
fn rule_input(plan: &Plan, rule: Rule) -> (Rule, Option<HostSetId>) {
    match rule {
        Rule::Accept {
            destination: Destination::HostSet(index),
            service,
        } => (
            Rule::Accept {
                destination: Destination::HostSet(0),
                service,
            },
            plan.host_set(index).map(|set| set.id),
        ),
        rule => (rule, None),
    }
}

impl Written {
    /// Whether `chain` of `source` with `rules` was written from the same inputs before
    /// (`previous`, which they are taken out of), and needn't be written again. Either way
    /// `installed` then has its inputs.
    fn chain(
        plan: &Plan,
        source: &Source,
        chain: Chain,
        rules: &[Rule],
        previous: &mut HashMap<Chain, ChainInputs>,
        installed: &mut Installed,
    ) -> bool {
        let (inputs, written) = match previous.remove(&chain) {
            Some(inputs) if inputs.are(plan, source, rules) => (inputs, true),
            _ => (ChainInputs::of(plan, source, rules), false),
        };
        installed.written.rules.insert(chain, inputs);
        written
    }
}

/// The elements of the named sets in an update, by set.
#[derive(Default)]
struct Elements(HashMap<NamedSet, Vec<Element>>);

impl Elements {
    /// Set the elements of `set`.
    fn fill(&mut self, set: NamedSet, elements: impl Iterator<Item = Element>) {
        self.0.entry(set).or_default().extend(elements);
    }

    /// Change the sets from the elements an update wrote before (`previous`, none when they
    /// aren't known) to these: add what's new; a set that lost elements, or a verdict map
    /// with an element whose verdict changed, is emptied and filled again instead.
    fn render(&self, out: &mut Batch, previous: Option<&HashMap<NamedSet, Vec<Element>>>) {
        let mut old_sorted = Vec::new();
        let mut new_sorted = Vec::new();
        for set in NamedSet::ALL {
            let new = self.0.get(&set).map_or(&[][..], Vec::as_slice);
            let old = previous.map(|previous| previous.get(&set).map_or(&[][..], Vec::as_slice));
            if old == Some(new) {
                continue;
            }
            old_sorted.clear();
            old_sorted.extend_from_slice(old.unwrap_or_default());
            old_sorted.sort_unstable();
            new_sorted.clear();
            new_sorted.extend_from_slice(new);
            new_sorted.sort_unstable();
            let refill = old.is_none()
                || old_sorted
                    .iter()
                    .any(|element| new_sorted.binary_search(element).is_err());
            let decl = set.declaration();
            if refill {
                out.push(Command::FlushSet(decl.clone()));
                render_added(out, decl, new.to_vec());
            } else {
                let added = new
                    .iter()
                    .filter(|element| old_sorted.binary_search(element).is_err())
                    .copied()
                    .collect();
                render_added(out, decl, added);
            }
        }
    }
}

/// Which slot each source's chains are numbered by. A source keeps its slot from one
/// update to the next, so that its chains keep their names, and only those whose rules
/// changed are written again; a new source takes the lowest free slot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Slots(BTreeMap<IpAddr, usize>);

impl Slots {
    fn assign(plan: &Plan, previous: &Self) -> Self {
        let mut slots = BTreeMap::new();
        let mut taken = BTreeSet::new();
        for source in &plan.sources {
            if let Some(&slot) = previous.0.get(&source.address)
                && taken.insert(slot)
            {
                slots.insert(source.address, slot);
            }
        }
        let mut free = (0..).filter(|slot| !taken.contains(slot));
        for source in &plan.sources {
            if !slots.contains_key(&source.address)
                && let Some(slot) = free.next()
            {
                slots.insert(source.address, slot);
            }
        }
        Self(slots)
    }

    /// The slot of a source of the plan the slots were assigned for.
    fn of(&self, source: &Source) -> usize {
        self.0.get(&source.address).copied().unwrap_or_default()
    }
}

/// Send traffic from containers through their egress chains, from `base`.
fn render_egress_dispatch(
    out: &mut Batch,
    plan: &Plan,
    options: Options,
    base: Chain,
    slots: &Slots,
    elements: &mut Elements,
) {
    render_link_local_ip(out, plan, options, base);
    render_dns_names(out, plan, options, base, elements);
    // The bridge table checked where established traffic comes from. Related traffic (ICMP
    // errors about a connection) is checked in the source's chain, see `render_related`.
    out.rule(
        base,
        vec![
            Expr::cmp(Key::CtState, Value::CtState(CtState::Established)),
            ACCEPT,
        ],
    );
    for (key, is_family, map) in [
        (
            &[Key::IpSaddr][..],
            IpAddr::is_ipv4 as fn(&IpAddr) -> bool,
            NamedSet::Egress4,
        ),
        (&[Key::Ip6Saddr][..], IpAddr::is_ipv6, NamedSet::Egress6),
    ] {
        let mut entries = plan
            .sources
            .iter()
            .filter(|source| is_family(&source.address))
            .map(|source| {
                Element::of(&[Part::Address(source.address)])
                    .with_verdict(Verdict::Goto(Chain::Egress(slots.of(source))))
            })
            .peekable();
        if entries.peek().is_none() {
            continue;
        }
        // Filled once, from the forward chain; the input chain uses the same map.
        if base == Chain::Base(Table::Inet) {
            elements.fill(map, entries);
        }
        // Only from a managed bridge: a container's address arriving from anywhere else
        // isn't the container, and its traffic mustn't count against the container (or
        // get it quarantined).
        out.rule(
            base,
            vec![
                Expr::lookup(&[Key::Iifname], NamedSet::InetBridges.name()),
                Expr::Vmap {
                    key,
                    map: map.name().into(),
                },
            ],
        );
    }
    // Unknown or spoofed sources of enforced networks; the bridge table already reported
    // them.
    if plan.bridges.iter().any(|bridge| !bridge.monitor) {
        out.rule(
            base,
            vec![
                Expr::lookup(&[Key::Iifname], NamedSet::InetEnforcedBridges.name()),
                options.deny.expr(),
            ],
        );
    }
}

/// Accept related traffic (ICMP errors about a connection) from `address` only when it is
/// one end of that connection. The kernel relates an ICMP error to a connection by the
/// packet quoted inside it, whoever sends it: anyone could otherwise send ICMP errors, with
/// data of their choice, to wherever any container has a connection. Other related traffic
/// continues through the chain's rules.
fn render_related(out: &mut Batch, chain: Chain, address: IpAddr) {
    for reply in [false, true] {
        out.rule(
            chain,
            vec![
                Expr::cmp(Key::CtState, Value::CtState(CtState::Related)),
                Expr::cmp(
                    Key::CtSaddr {
                        reply,
                        ipv6: address.is_ipv6(),
                    },
                    Value::Address(address),
                ),
                ACCEPT,
            ],
        );
    }
}

/// DNS queries of containers whose names are limited are held until Portcullis has read the
/// name, before established traffic is let through (a query over TCP comes after the
/// handshake). A checked query comes back marked: an allowed one continues through the rules
/// as any other, a denied one is rejected, so the lookup fails at once. The queue has no
/// bypass: while Portcullis isn't reading it, such lookups fail.
fn render_dns_names(
    out: &mut Batch,
    plan: &Plan,
    options: Options,
    base: Chain,
    elements: &mut Elements,
) {
    let Some(queue) = options.dns_query_queue else {
        return;
    };
    let mut limited = plan
        .sources
        .iter()
        .filter(|source| source.address.is_ipv4() && source.domains.is_some())
        .map(|source| Element::of(&[Part::Address(source.address)]))
        .peekable();
    if limited.peek().is_some() {
        if base == Chain::Base(Table::Inet) {
            elements.fill(NamedSet::NameLimited, limited);
        }
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            out.rule(
                base,
                vec![
                    Expr::lookup(&[Key::IpSaddr], NamedSet::NameLimited.name()),
                    Expr::cmp(Key::L4proto, Value::Protocol(protocol, false)),
                    Expr::cmp(Key::ThDport, Value::Range(DNS_PORT, DNS_PORT)),
                    Expr::cmp(Key::CtDirection, Value::Original),
                    Expr::not(Key::Mark, Value::Mark(DNS_ALLOWED_MARK)),
                    Expr::not(Key::Mark, Value::Mark(DNS_DENIED_MARK)),
                    Expr::Queue {
                        num: queue,
                        bypass: false,
                    },
                ],
            );
        }
    }
    out.rule(
        base,
        vec![
            Expr::cmp(Key::Mark, Value::Mark(DNS_DENIED_MARK)),
            Expr::cmp(Key::L4proto, Value::Protocol(Protocol::Tcp, false)),
            Expr::Reject { tcp_reset: true },
        ],
    );
    out.rule(
        base,
        vec![
            Expr::cmp(Key::Mark, Value::Mark(DNS_DENIED_MARK)),
            Expr::Reject { tcp_reset: false },
        ],
    );
    out.rule(
        base,
        vec![
            Expr::cmp(Key::Mark, Value::Mark(DNS_ALLOWED_MARK)),
            Expr::SetMark(0),
        ],
    );
}

/// Create or flush the chains and sets of `plan`, and remove those of `previous` it doesn't
/// need. Returns what is installed afterwards.
fn render_objects(
    out: &mut Batch,
    plan: &Plan,
    options: Options,
    previous: &Installed,
    slots: &Slots,
    previous_host_addresses: &mut HashMap<String, String>,
) -> Installed {
    let mut installed = Installed::default();
    // Written by `render_chain`, if their rules changed. Containers are only managed by
    // their IPv4 address on the bridge; see the IPv6 limitation.
    for source in &plan.sources {
        let slot = slots.of(source);
        installed.chains.insert(Chain::Egress(slot).object());
        if source.address.is_ipv4() && icc_chain_needed(plan, source, options) {
            installed.chains.insert(Chain::Icc(slot).object());
        }
    }
    let limited = (!plan.bridges.is_empty())
        .then_some([false, true])
        .into_iter()
        .flatten()
        .flat_map(|rate| [false, true].map(|monitor| Chain::Limited { rate, monitor }));
    let arp_checks = (!plan.bridges.is_empty())
        .then_some([false, true])
        .into_iter()
        .flatten()
        .map(|monitor| Chain::ArpCheck { monitor });
    for chain in limited.chain(arp_checks) {
        out.push(Command::AddChain(chain));
        out.push(Command::FlushChain(chain));
        installed.chains.insert(chain.object());
    }
    for limit in limits(plan, options).into_keys() {
        let decl = limit.set();
        installed.sets.insert(Object {
            table: decl.table,
            name: decl.name.to_string(),
        });
        out.push(Command::AddSet(decl));
    }
    for (limit, ports) in limits(plan, options) {
        // Kept in `installed`.
        let decl = limit.ports();
        installed.sets.insert(Object {
            table: decl.table,
            name: decl.name.to_string(),
        });
        out.push(Command::AddSet(decl.clone()));
        out.push(Command::FlushSet(decl.clone()));
        render_added(
            out,
            decl,
            ports
                .into_iter()
                .map(|port| Element::of(&[Part::Ifname(port)]))
                .collect(),
        );
    }
    let mut listed = String::new();
    for set in &plan.host_sets {
        let mut host_set = HostSetUpdate {
            previous,
            previous_addresses: previous_host_addresses,
            installed: &mut installed,
            listed: &mut listed,
        };
        if set.used_v4 {
            host_set.render(out, set, SET_PREFIX_V4, || set.v4());
        }
        if set.used_v6 {
            host_set.render(out, set, SET_PREFIX_V6, || set.v6());
        }
    }
    installed
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
fn render_bridge_dispatch(
    out: &mut Batch,
    plan: &Plan,
    options: Options,
    slots: &Slots,
    elements: &mut Elements,
) {
    let base = Chain::Base(Table::Bridge);
    out.rule(
        base,
        vec![
            Expr::Lookup {
                key: &[Key::Ibrname],
                set: NamedSet::BridgeBridges.name().into(),
                negate: true,
            },
            ACCEPT,
        ],
    );
    render_limits(out, plan, options);
    render_arp_check(out, plan, options);
    render_known_sources(out, plan, options, base, slots, elements);
    for monitor in [true, false] {
        if !plan.bridges.iter().any(|bridge| bridge.monitor == monitor) {
            continue;
        }
        let queue = if monitor {
            options.monitor_source_queue
        } else {
            options.source_queue
        };
        render_unknown_sources(out, plan, options, monitor, queue, elements);
    }
}

/// ARP of a container is accepted by who it says it is (see `render_known_sources`); what
/// it carries besides must be nothing more than ARP itself. A request or reply for Ethernet
/// and IPv4 is 28 bytes, padded with zeros to 46 by some senders: anything else, such as
/// data after the ARP body, would reach containers ARP goes to whatever their ICC rules
/// say. Denied as a frame enforced networks don't carry. Checked in a chain of its own,
/// which other frames skip with one rule.
fn render_arp_check(out: &mut Batch, plan: &Plan, options: Options) {
    let malformed = || {
        [
            vec![Expr::not(Key::ArpHtype, Value::Number(1))],
            vec![Expr::not(Key::ArpPtype, Value::EtherIp)],
            vec![Expr::not(Key::ArpHlen, Value::Number(6))],
            vec![Expr::not(Key::ArpPlen, Value::Number(4))],
            vec![Expr::not(Key::ArpOperation, Value::Range(1, 2))],
            vec![
                Expr::not(Key::Length, Value::Number(28)),
                Expr::not(Key::Length, Value::Number(46)),
            ],
            // The padding, 18 bytes after the body, in two parts: a comparison takes at
            // most 16.
            vec![
                Expr::cmp(Key::Length, Value::Number(46)),
                Expr::not(
                    Key::Raw {
                        offset: 224,
                        bits: 128,
                    },
                    Value::Number(0),
                ),
            ],
            vec![
                Expr::cmp(Key::Length, Value::Number(46)),
                Expr::not(
                    Key::Raw {
                        offset: 352,
                        bits: 16,
                    },
                    Value::Number(0),
                ),
            ],
        ]
    };
    let base = Chain::Base(Table::Bridge);
    for (monitor, bridges) in [
        (false, NamedSet::EnforcedBridges),
        (true, NamedSet::MonitoredBridges),
    ] {
        if !plan.bridges.iter().any(|bridge| bridge.monitor == monitor) {
            continue;
        }
        let chain = Chain::ArpCheck { monitor };
        out.rule(
            base,
            vec![
                Expr::lookup(&[Key::Ibrname], bridges.name()),
                Expr::cmp(Key::EtherType, Value::EtherArp),
                Expr::Verdict(Verdict::Jump(chain)),
            ],
        );
        for malformed in malformed() {
            decide(
                out,
                chain,
                malformed,
                Outcome::deny(options, monitor, "frame").for_frame(),
            );
        }
    }
}

/// Frames entering `bridges` (all enforced, or all in monitor mode) that no rule above
/// accepted: their source isn't a managed container's own address, MAC and port.
fn render_unknown_sources(
    out: &mut Batch,
    plan: &Plan,
    options: Options,
    monitor: bool,
    queue: Option<u16>,
    elements: &mut Elements,
) {
    let base = Chain::Base(Table::Bridge);
    let (bridges, ports) = if monitor {
        (NamedSet::MonitoredBridges, NamedSet::MonitoredPorts)
    } else {
        (NamedSet::EnforcedBridges, NamedSet::EnforcedPorts)
    };
    let on_bridges = || Expr::lookup(&[Key::Ibrname], bridges.name());
    if queue.is_some() {
        // Held before, and the source stayed unknown: Portcullis didn't know the sender in
        // time, whatever port it came from by now, so it isn't taken for spoofing.
        render_denied_frames(
            out,
            options,
            monitor,
            &[
                on_bridges(),
                Expr::cmp(Key::Mark, Value::Mark(HOLD_EXPIRED_MARK)),
            ],
            "source:held",
        );
    }
    // From a managed container's port, but not with its own address and MAC: denied at once.
    let networks: BTreeSet<&str> = plan
        .bridges
        .iter()
        .filter(|bridge| bridge.monitor == monitor)
        .map(|bridge| bridge.network.as_str())
        .collect();
    let mut known = plan
        .sources
        .iter()
        .filter(|source| networks.contains(source.network.as_str()))
        .filter_map(|source| source.port.known())
        .map(|port| Element::of(&[Part::Ifname(&port.name)]))
        .peekable();
    if known.peek().is_some() {
        elements.fill(ports, known);
        render_denied_frames(
            out,
            options,
            monitor,
            &[on_bridges(), Expr::lookup(&[Key::Iifname], ports.name())],
            "source",
        );
    }
    if let Some(queue) = queue {
        // A port no managed container has (yet): most likely a container that just started,
        // or that got the address of a removed one, and that Portcullis hasn't applied rules
        // for. Hold the packet until Portcullis knows the container; if the source stays
        // unknown, it is denied (or in monitor mode reported) above once the hold expires.
        // In monitor mode the queue fails open.
        for ether_type in [Value::EtherIp, Value::EtherArp] {
            out.rule(
                base,
                vec![
                    on_bridges(),
                    Expr::cmp(Key::EtherType, ether_type),
                    Expr::Queue {
                        num: queue,
                        bypass: monitor,
                    },
                ],
            );
        }
    }
    render_denied_frames(out, options, monitor, &[on_bridges()], "source");
}

/// The set of quarantined containers' bridge ports, refilled on every update.
const QUARANTINED_SET: &str = "quarantined";

fn render_quarantined_set(out: &mut Batch, plan: &Plan) {
    let decl = SetDecl::set(Table::Bridge, QUARANTINED_SET, &[KeyType::Ifname]);
    out.push(Command::AddSet(decl.clone()));
    out.push(Command::FlushSet(decl.clone()));
    render_added(
        out,
        decl,
        plan.sources
            .iter()
            .filter(|source| source.quarantined && !source.monitor)
            .filter_map(|source| source.port.known())
            .map(|port| port.name.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|port| Element::of(&[Part::Ifname(port)]))
            .collect(),
    );
}

/// A limit shared by some containers: open connections or new connections per second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Limit {
    rate: bool,
    value: u32,
    monitor: bool,
}

/// Room in the sets that count connections, by port.
const LIMIT_SET_SIZE: u32 = 65_536;
/// How long a port's count of new connections lasts.
const RATE_TIMEOUT: Duration = Duration::from_secs(60);

impl Limit {
    /// The name of the set counting each port's connections, or new connections, under this
    /// limit.
    fn set_name(self) -> String {
        let kind = if self.rate { "new" } else { "conns" };
        format!("{kind}{}", self.value)
    }

    /// The set counting each port's connections, or new connections, under this limit.
    fn set(self) -> SetDecl {
        SetDecl {
            name: self.set_name().into(),
            flags: SetFlags {
                dynamic: true,
                timeout: self.rate,
            },
            timeout: self.rate.then_some(RATE_TIMEOUT),
            size: Some(LIMIT_SET_SIZE),
            ..SetDecl::set(Table::Bridge, "", &[KeyType::Ifname])
        }
    }

    /// The set of the ports under this limit.
    fn ports(self) -> SetDecl {
        let monitor = if self.monitor { "_monitor" } else { "" };
        SetDecl {
            name: format!("ports_{}{monitor}", self.set_name()).into(),
            ..SetDecl::set(Table::Bridge, "", &[KeyType::Ifname])
        }
    }
}

/// Containers by the limits they are under, by their bridge ports. Containers whose port
/// isn't known aren't limited.
fn limits(plan: &Plan, options: Options) -> BTreeMap<Limit, BTreeSet<&str>> {
    let mut limits: BTreeMap<Limit, BTreeSet<&str>> = BTreeMap::new();
    for source in &plan.sources {
        let Some(port) = source.port.known() else {
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
fn render_limits(out: &mut Batch, plan: &Plan, options: Options) {
    let base = Chain::Base(Table::Bridge);
    for chain in [base, Chain::BridgeInput] {
        out.rule(
            chain,
            vec![
                Expr::lookup(&[Key::Iifname], QUARANTINED_SET),
                Expr::Verdict(Verdict::Drop),
            ],
        );
    }
    for limit in limits(plan, options).into_keys() {
        let stateful = if limit.rate {
            Stateful::RateOver(limit.value)
        } else {
            Stateful::CtCountOver(limit.value)
        };
        out.rule(
            base,
            vec![
                Expr::lookup(&[Key::Iifname], limit.ports().name),
                Expr::cmp(Key::CtState, Value::CtState(CtState::New)),
                Expr::AddToSet {
                    key: &[Key::Iifname],
                    set: limit.set_name().into(),
                    stateful: Some(stateful),
                },
                Expr::Verdict(Verdict::Goto(Chain::Limited {
                    rate: limit.rate,
                    monitor: limit.monitor,
                })),
            ],
        );
    }
    for rate in [false, true] {
        for monitor in [false, true] {
            let chain = Chain::Limited { rate, monitor };
            let reason = if rate { "limit:rate" } else { "limit:open" };
            decide(
                out,
                chain,
                Vec::new(),
                Outcome::deny(options, monitor, reason).dropped(),
            );
        }
    }
}

/// Frames to the link-local group addresses (01:80:c2:00:00:00 to 0f, used by protocols
/// such as STP and LLDP) skip the bridge's prerouting hook: the bridge hands them to the
/// host directly, on the container's port instead of the bridge. With IP inside, they reach
/// the host's IP stack without any of the bridge's checks, from any address the container
/// likes. No container has a reason to send them; they are denied where the bridge hands
/// them over. LLDP (and STP, where enabled) skips even that hook, see
/// `render_link_local_ip`.
fn render_link_local(out: &mut Batch, plan: &Plan, options: Options) {
    for (monitor, bridges) in [
        (false, NamedSet::EnforcedBridges),
        (true, NamedSet::MonitoredBridges),
    ] {
        if !plan.bridges.iter().any(|bridge| bridge.monitor == monitor) {
            continue;
        }
        decide(
            out,
            Chain::BridgeInput,
            vec![
                Expr::lookup(&[Key::Ibrname], bridges.name()),
                link_local_group(),
            ],
            Outcome::deny(options, monitor, "frame").for_frame(),
        );
    }
}

/// A bridge passes a frame to whichever port has its destination MAC, whatever its IP
/// destination. The ICC rules only see IP destinations: a frame to another container's MAC,
/// addressed to that container's address on another network, would pass them, and the
/// container would accept it. IPv4 passed from one container to another must therefore be
/// addressed to the network itself, or be broadcast or multicast (which the ICC rules
/// check). The bridge's forward hook can only drop.
fn render_bridged_destinations(out: &mut Batch, plan: &Plan, options: Options) {
    let chain = Chain::BridgeForward;
    for bridge in plan
        .bridges
        .iter()
        .filter(|bridge| bridge.subnet.addr().is_ipv4())
    {
        let name = || Expr::cmp(Key::Ibrname, Value::Ifname(bridge.name.clone().into()));
        for destination in std::iter::once(&bridge.subnet).chain(&ICC_BROADCAST_V4) {
            out.rule(
                chain,
                vec![
                    name(),
                    Expr::cmp(Key::IpDaddr, Value::Network(*destination)),
                    ACCEPT,
                ],
            );
        }
        decide(
            out,
            chain,
            vec![name(), Expr::cmp(Key::EtherType, Value::EtherIp)],
            Outcome::deny(options, bridge.monitor, "icc").dropped(),
        );
    }
}

/// The link-local group addresses: 01:80:c2:00:00:00 to 01:80:c2:00:00:0f.
fn link_local_group() -> Expr {
    Expr::Masked {
        key: Key::EtherDaddr,
        mask: Value::Mac(MacAddress::from([0xff, 0xff, 0xff, 0xff, 0xff, 0xf0])),
        value: Value::Mac(MacAddress::from([0x01, 0x80, 0xc2, 0, 0, 0])),
    }
}

/// IP in frames to link-local group addresses that the bridge passed to the host without any
/// bridge hook (LLDP, and STP where enabled). Nothing legitimate sends IP that way, from
/// anywhere, so it is denied on every interface. Reported as denied while any network is
/// enforced, as would-be-denied while all are monitored.
fn render_link_local_ip(out: &mut Batch, plan: &Plan, options: Options, base: Chain) {
    if plan.bridges.is_empty() {
        return;
    }
    let monitor = plan.bridges.iter().all(|bridge| bridge.monitor);
    for (ipv6, key) in [(false, LogKey::Ipv4), (true, LogKey::Ipv6)] {
        let mut outcome = Outcome::deny(options, monitor, "frame").dropped();
        outcome.key = key;
        decide(
            out,
            base,
            vec![
                Expr::cmp(Key::Nfproto, Value::NfProto(ipv6)),
                link_local_group(),
            ],
            outcome,
        );
    }
}

/// Deny (or in monitor mode, report) frames of the bridge base chain matching `selector`:
/// IPv4 and ARP as using a source that isn't the sender's (reported with `reason`), anything
/// else as a frame enforced networks don't carry.
fn render_denied_frames(
    out: &mut Batch,
    options: Options,
    monitor: bool,
    selector: &[Expr],
    reason: &'static str,
) {
    let base = Chain::Base(Table::Bridge);
    let source = Outcome::deny(options, monitor, reason).dropped();
    let with = |ether_type| {
        let mut head = selector.to_vec();
        head.push(Expr::cmp(Key::EtherType, ether_type));
        head
    };
    decide(out, base, with(Value::EtherIp), source);
    decide(out, base, with(Value::EtherArp), source.for_arp());
    decide(
        out,
        base,
        selector.to_vec(),
        Outcome::deny(options, monitor, "frame").for_frame(),
    );
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
    /// None for a container with no port, which can't send: whatever comes with its
    /// address or MAC is someone else's, from another port, and is denied as such.
    fn of(source: &'a Source) -> Option<Self> {
        match (source.mac, &source.port) {
            (Some(mac), PortState::Known(port)) => {
                Some(Self::Port(&port.name, mac, source.address))
            }
            (_, PortState::Absent) => None,
            (Some(mac), _) => Some(Self::Mac(mac, source.address)),
            (None, _) => Some(Self::Address(source.address)),
        }
    }
}

/// Send frames from managed containers' own port, MAC and address to their ICC rules, and
/// accept their ARP.
fn render_known_sources(
    out: &mut Batch,
    plan: &Plan,
    options: Options,
    base: Chain,
    slots: &Slots,
    elements: &mut Elements,
) {
    let verdict = |source: &Source| {
        if icc_chain_needed(plan, source, options) {
            Verdict::Goto(Chain::Icc(slots.of(source)))
        } else {
            Verdict::Accept
        }
    };
    let keys = || {
        plan.sources
            .iter()
            .filter(|source| source.address.is_ipv4())
            .filter_map(|source| Some((source, SourceKey::of(source)?)))
    };
    // A raw socket is enough to send with another container's address and MAC, but not
    // from its port.
    render_dispatch(
        out,
        elements,
        base,
        &[Key::Iifname, Key::IpSaddr, Key::EtherSaddr],
        NamedSet::SourcesByPort,
        keys().filter_map(|(source, key)| match key {
            SourceKey::Port(port, mac, address) => Some(
                Element::of(&[Part::Ifname(port), Part::Address(address), Part::Mac(mac)])
                    .with_verdict(verdict(source)),
            ),
            _ => None,
        }),
    );
    render_dispatch(
        out,
        elements,
        base,
        &[Key::IpSaddr, Key::EtherSaddr],
        NamedSet::SourcesByMac,
        keys().filter_map(|(source, key)| match key {
            SourceKey::Mac(mac, address) => Some(
                Element::of(&[Part::Address(address), Part::Mac(mac)])
                    .with_verdict(verdict(source)),
            ),
            _ => None,
        }),
    );
    render_dispatch(
        out,
        elements,
        base,
        &[Key::IpSaddr],
        NamedSet::SourcesByAddress,
        keys().filter_map(|(source, key)| match key {
            SourceKey::Address(address) => {
                Some(Element::of(&[Part::Address(address)]).with_verdict(verdict(source)))
            }
            _ => None,
        }),
    );
    render_known_arp(out, plan, base, elements);
}

/// Accept ARP of managed containers announcing themselves.
fn render_known_arp(out: &mut Batch, plan: &Plan, base: Chain, elements: &mut Elements) {
    let keys = || {
        plan.sources
            .iter()
            .filter(|source| source.address.is_ipv4())
            .filter_map(SourceKey::of)
    };
    // ARP may only announce the container's own address and MAC, or no address at all
    // (0.0.0.0, a probe for whether an address is in use).
    let unspecified = IpAddr::from([0, 0, 0, 0]);
    render_dispatch(
        out,
        elements,
        base,
        &[
            Key::Iifname,
            Key::EtherSaddr,
            Key::ArpSaddrEther,
            Key::ArpSaddrIp,
        ],
        NamedSet::ArpByPort,
        keys()
            .flat_map(|key| match key {
                SourceKey::Port(port, mac, address) => [address, unspecified].map(|address| {
                    Some(Element::of(&[
                        Part::Ifname(port),
                        Part::Mac(mac),
                        Part::Mac(mac),
                        Part::Address(address),
                    ]))
                }),
                _ => [None, None],
            })
            .flatten(),
    );
    render_dispatch(
        out,
        elements,
        base,
        &[Key::EtherSaddr, Key::ArpSaddrEther, Key::ArpSaddrIp],
        NamedSet::ArpByMac,
        keys()
            .flat_map(|key| match key {
                SourceKey::Mac(mac, address) => [address, unspecified].map(|address| {
                    Some(Element::of(&[
                        Part::Mac(mac),
                        Part::Mac(mac),
                        Part::Address(address),
                    ]))
                }),
                _ => [None, None],
            })
            .flatten(),
    );
    render_dispatch(
        out,
        elements,
        base,
        &[Key::ArpSaddrIp],
        NamedSet::ArpByAddress,
        keys().filter_map(|key| match key {
            SourceKey::Address(address) => Some(Element::of(&[Part::Address(address)])),
            _ => None,
        }),
    );
}

/// Fill `set` with `elements` and match `key` against it in `chain`: through it, for a
/// verdict map, or accepting what it holds. Nothing is matched without elements.
fn render_dispatch(
    out: &mut Batch,
    elements_of: &mut Elements,
    chain: Chain,
    key: &'static [Key],
    set: NamedSet,
    elements: impl Iterator<Item = Element>,
) {
    let mut elements = elements.peekable();
    if elements.peek().is_none() {
        return;
    }
    elements_of.fill(set, elements);
    if set.is_map() {
        out.rule(
            chain,
            vec![Expr::Vmap {
                key,
                map: set.name().into(),
            }],
        );
    } else {
        out.rule(chain, vec![Expr::lookup(key, set.name()), ACCEPT]);
    }
}

/// The sets and verdict maps rules match against, besides those of hostnames, limits and
/// reports. Rules never carry anonymous sets (`{ a, b }`): an update replaces such a set
/// along with its rule, and while the kernel commits the update, lookups in it can miss.
/// That briefly lets packets through checks, or denies established connections as from an
/// unknown source. A named set lives on: an update deletes the elements it doesn't hold
/// anymore and adds the new ones, which lookups of the others don't notice. Sets of ranges
/// (`flags interval`) can miss as well, so rules match ranges one prefix at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum NamedSet {
    /// Bridges of managed networks, for the inet table.
    InetBridges,
    /// Bridges of enforced networks, for the inet table.
    InetEnforcedBridges,
    /// Egress chains of IPv4 sources.
    Egress4,
    /// Egress chains of IPv6 sources.
    Egress6,
    /// Sources whose DNS lookups are limited to some names.
    NameLimited,
    /// Bridges of managed networks.
    BridgeBridges,
    MonitoredBridges,
    EnforcedBridges,
    /// Ports of managed containers on monitored networks.
    MonitoredPorts,
    /// Ports of managed containers on enforced networks.
    EnforcedPorts,
    /// ICC chains of sources, by port, address and MAC.
    SourcesByPort,
    /// The same, by address and MAC, for sources whose port isn't known.
    SourcesByMac,
    /// The same, by address, for sources without a MAC.
    SourcesByAddress,
    /// ARP sources may send, by port.
    ArpByPort,
    ArpByMac,
    ArpByAddress,
}

impl NamedSet {
    const ALL: [Self; 16] = [
        Self::InetBridges,
        Self::InetEnforcedBridges,
        Self::Egress4,
        Self::Egress6,
        Self::NameLimited,
        Self::BridgeBridges,
        Self::MonitoredBridges,
        Self::EnforcedBridges,
        Self::MonitoredPorts,
        Self::EnforcedPorts,
        Self::SourcesByPort,
        Self::SourcesByMac,
        Self::SourcesByAddress,
        Self::ArpByPort,
        Self::ArpByMac,
        Self::ArpByAddress,
    ];

    const fn table(self) -> Table {
        match self {
            Self::InetBridges
            | Self::InetEnforcedBridges
            | Self::Egress4
            | Self::Egress6
            | Self::NameLimited => Table::Inet,
            _ => Table::Bridge,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::InetBridges | Self::BridgeBridges => "bridges",
            Self::InetEnforcedBridges | Self::EnforcedBridges => "enforced_bridges",
            Self::MonitoredBridges => "monitored_bridges",
            Self::Egress4 => "egress4",
            Self::Egress6 => "egress6",
            Self::NameLimited => "name_limited",
            Self::MonitoredPorts => "monitored_ports",
            Self::EnforcedPorts => "enforced_ports",
            Self::SourcesByPort => "sources_by_port",
            Self::SourcesByMac => "sources_by_mac",
            Self::SourcesByAddress => "sources_by_address",
            Self::ArpByPort => "arp_by_port",
            Self::ArpByMac => "arp_by_mac",
            Self::ArpByAddress => "arp_by_address",
        }
    }

    /// The type of its elements, or keys.
    const fn key_type(self) -> &'static [KeyType] {
        match self {
            Self::InetBridges
            | Self::InetEnforcedBridges
            | Self::BridgeBridges
            | Self::MonitoredBridges
            | Self::EnforcedBridges
            | Self::MonitoredPorts
            | Self::EnforcedPorts => &[KeyType::Ifname],
            Self::Egress4 | Self::NameLimited | Self::SourcesByAddress | Self::ArpByAddress => {
                &[KeyType::Ipv4]
            }
            Self::Egress6 => &[KeyType::Ipv6],
            Self::SourcesByPort => &[KeyType::Ifname, KeyType::Ipv4, KeyType::Ether],
            Self::SourcesByMac => &[KeyType::Ipv4, KeyType::Ether],
            Self::ArpByPort => &[
                KeyType::Ifname,
                KeyType::Ether,
                KeyType::Ether,
                KeyType::Ipv4,
            ],
            Self::ArpByMac => &[KeyType::Ether, KeyType::Ether, KeyType::Ipv4],
        }
    }

    const fn is_map(self) -> bool {
        matches!(
            self,
            Self::Egress4
                | Self::Egress6
                | Self::SourcesByPort
                | Self::SourcesByMac
                | Self::SourcesByAddress
        )
    }

    fn declaration(self) -> SetDecl {
        let mut decl = SetDecl::set(self.table(), self.name(), self.key_type());
        decl.map = self.is_map();
        decl
    }
}

/// Add elements to a set, if there are any.
fn render_added(out: &mut Batch, decl: SetDecl, elements: Vec<Element>) {
    if !elements.is_empty() {
        out.push(Command::AddElements(decl, elements));
    }
}

/// Writes the hostname sets of an update.
struct HostSetUpdate<'a> {
    previous: &'a Installed,
    /// Taken out of `previous`, as they're moved to `installed`.
    previous_addresses: &'a mut HashMap<String, String>,
    installed: &'a mut Installed,
    /// Reused buffer for a set's addresses.
    listed: &'a mut String,
}

impl HostSetUpdate<'_> {
    /// Sets have per-element timeouts: addresses expire when nothing renews them.
    ///
    /// An update empties the set and fills it with what Portcullis knows, except the first
    /// one after a restart, in rules the previous run left in place: Portcullis doesn't
    /// remember the addresses that run learned from DNS answers, but the set does, with the
    /// time each has left. Those are kept, to run out as they would have; the update renews
    /// the rest.
    ///
    /// A set that holds the same addresses as at the last update is left alone: DNS
    /// answers and Portcullis's own lookups renew its addresses in place meanwhile (see
    /// [`NftablesFirewall::update_host_addresses`]), so it holds them with the time they
    /// have left already.
    fn render<I>(
        &mut self,
        out: &mut Batch,
        set: &HostSet,
        prefix: &'static str,
        addresses: impl Fn() -> I,
    ) where
        I: Iterator<Item = (IpAddr, Duration)>,
    {
        let name = set.id.name(prefix).to_string();
        let object = Object {
            table: Table::Inet,
            name: name.clone(),
        };
        self.listed.clear();
        for (address, _) in addresses() {
            let _ = write!(self.listed, "{address} ");
        }
        let listed = match self.previous_addresses.remove(&name) {
            Some(written) if written == *self.listed && self.previous.sets.contains(&object) => {
                written
            }
            _ => {
                // Bounded in the kernel too: addresses are added from DNS answers between
                // updates.
                let decl = SetDecl {
                    name: Cow::Owned(name.clone()),
                    flags: SetFlags {
                        dynamic: false,
                        timeout: true,
                    },
                    size: Some(HOST_SET_SIZE),
                    ..SetDecl::set(
                        Table::Inet,
                        "",
                        if prefix == SET_PREFIX_V6 {
                            &[KeyType::Ipv6]
                        } else {
                            &[KeyType::Ipv4]
                        },
                    )
                };
                out.push(Command::AddSet(decl.clone()));
                let timed = || {
                    addresses()
                        .map(|(address, timeout)| {
                            Element::of(&[Part::Address(address)]).with_timeout(timeout)
                        })
                        .collect()
                };
                if self.previous.kept && self.previous.sets.contains(&object) {
                    // Adding doesn't renew the addresses the set holds already: that's done
                    // once the update is in place.
                    render_added(out, decl, timed());
                    self.installed.renewals.push(Renewal {
                        set: name.clone(),
                        ipv6: prefix == SET_PREFIX_V6,
                        addresses: addresses().collect(),
                    });
                } else {
                    out.push(Command::FlushSet(decl.clone()));
                    render_added(out, decl, timed());
                }
                self.listed.clone()
            }
        };
        self.installed.written.host_addresses.insert(name, listed);
        self.installed.sets.insert(object);
    }
}

/// Set how much longer each address stays in the set `name`, whether it is there already or
/// not; zero removes it.
///
/// Adding an element that exists doesn't renew its timeout (kernels before 6.10 never do,
/// later ones only when the timeout differs), so an address seen again would still expire
/// when it was first due. Each address is added, deleted and added again in one
/// transaction instead: the add before the delete makes sure there is something to delete,
/// and packets only ever see the set before or after, never without an address it keeps.
///
/// The firewall sends this as a netlink batch (see [`super::elements`]), not as a script;
/// tests record it as the script that does the same.
#[cfg(test)]
fn render_timeouts<I>(out: &mut Batch, name: &str, ipv6: bool, addresses: impl Fn() -> I)
where
    I: Iterator<Item = (IpAddr, Duration)>,
{
    let decl = SetDecl::set(
        Table::Inet,
        "",
        if ipv6 {
            &[KeyType::Ipv6]
        } else {
            &[KeyType::Ipv4]
        },
    );
    let decl = SetDecl {
        name: Cow::Owned(name.to_string()),
        ..decl
    };
    let timed = || {
        addresses()
            .map(|(address, timeout)| Element::of(&[Part::Address(address)]).with_timeout(timeout))
    };
    let added: Vec<_> = timed().collect();
    if added.is_empty() {
        return;
    }
    out.push(Command::AddElements(decl.clone(), added.clone()));
    out.push(Command::DeleteElements(decl.clone(), added));
    render_added(
        out,
        decl,
        timed()
            .filter(|element| element.timeout.is_some_and(|timeout| !timeout.is_zero()))
            .collect(),
    );
}

/// Room in a hostname set: the addresses a container may learn for a hostname, and those
/// Portcullis resolves itself.
#[allow(clippy::cast_possible_truncation)]
const HOST_SET_SIZE: u32 = MAX_ADDRESSES_PER_HOST as u32 * 2;

/// IPv4 and IPv6 ranges that aren't public, as prefixes.
static PRIVATE: LazyLock<[Vec<IpNet>; 2]> = LazyLock::new(|| {
    let parse = |ranges: &[&str]| {
        ranges
            .iter()
            .filter_map(|range| range.parse().ok())
            .collect()
    };
    [parse(&PRIVATE_V4), parse(&PRIVATE_V6)]
});

/// How a rule matches destinations. The bridge table sees packets as sent. The inet table
/// sees them after Docker's DNAT has rewritten published ports of the host to the
/// container behind them, so it matches the destination the container asked for, as
/// connection tracking remembers it: a published port reached through the host is the
/// host's address and port, not another container on the same network.
struct Match {
    ipv6: bool,
    original: bool,
}

impl Match {
    const fn new(address: IpAddr, chain: Chain) -> Self {
        Self {
            ipv6: address.is_ipv6(),
            original: !matches!(chain, Chain::Icc(_)),
        }
    }

    /// The destination address, as a one-part key.
    const fn daddr(&self) -> &'static [Key] {
        match (self.original, self.ipv6) {
            (true, ipv6) => {
                if ipv6 {
                    &[Key::CtDaddr { ipv6: true }]
                } else {
                    &[Key::CtDaddr { ipv6: false }]
                }
            }
            (false, false) => &[Key::IpDaddr],
            (false, true) => &[Key::Ip6Daddr],
        }
    }

    fn to(&self, value: Value) -> Expr {
        let [key] = self.daddr() else {
            unreachable!("a destination is one key")
        };
        Expr::cmp(*key, value)
    }

    fn not_to(&self, value: Value) -> Expr {
        let [key] = self.daddr() else {
            unreachable!("a destination is one key")
        };
        Expr::not(*key, value)
    }

    fn dport(&self, protocol: Protocol, port: u16, out: &mut Vec<Expr>) {
        if self.original {
            out.push(Expr::cmp(Key::L4proto, Value::Protocol(protocol, false)));
            out.push(Expr::cmp(Key::CtProtoDst, Value::Range(port, port)));
        } else {
            out.push(Expr::cmp(Key::Dport(protocol), Value::Range(port, port)));
        }
    }

    /// What matches `service`; nothing for any traffic.
    fn service(&self, service: Service, out: &mut Vec<Expr>) {
        let Service::Protocol(protocol, ports) = service else {
            return;
        };
        match ports {
            Some(ports) if self.original => {
                out.push(Expr::cmp(
                    Key::L4proto,
                    Value::Protocol(protocol, self.ipv6),
                ));
                out.push(Expr::cmp(
                    Key::CtProtoDst,
                    Value::Range(ports.first, ports.last),
                ));
            }
            Some(ports) => out.push(Expr::cmp(
                Key::Dport(protocol),
                Value::Range(ports.first, ports.last),
            )),
            None => out.push(Expr::cmp(
                Key::L4proto,
                Value::Protocol(protocol, self.ipv6),
            )),
        }
    }
}

fn render_rule(
    plan: &Plan,
    source: &Source,
    chain: Chain,
    rule: &Rule,
    options: Options,
    out: &mut Batch,
) {
    let to = Match::new(source.address, chain);
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
            let mut exprs = Vec::with_capacity(4);
            if let Some(destination) = destination {
                exprs.push(to.to(Value::Address(destination)));
            }
            to.dport(protocol, DNS_PORT, &mut exprs);
            exprs.push(ACCEPT);
            out.rule(chain, exprs);
        }
        Rule::DenyDns { protocol } => {
            let mut exprs = Vec::with_capacity(2);
            to.dport(protocol, DNS_PORT, &mut exprs);
            decide(out, chain, exprs, deny("dns").snaplen(LOG_SNAPLEN_DNS));
        }
        // Only what leaves through a bridge: the chain also checks traffic to the host
        // (from the input hook, without an output interface), which can have a destination
        // in the subnet too, its broadcast address.
        Rule::AcceptPeers { subnet, gateway } => {
            let mut exprs = vec![to.to(Value::Network(subnet))];
            if let Some(gateway) = gateway {
                exprs.push(to.not_to(Value::Address(gateway)));
            }
            exprs.push(Expr::lookup(&[Key::Oifname], NamedSet::InetBridges.name()));
            exprs.push(ACCEPT);
            out.rule(chain, exprs);
            // Broadcast and multicast are never routed: leaving through a bridge, they are
            // bridged, and the ICC rules decided on them.
            if subnet.addr().is_ipv4() {
                for destination in &ICC_BROADCAST_V4 {
                    out.rule(
                        chain,
                        vec![
                            to.to(Value::Network(*destination)),
                            Expr::lookup(&[Key::Oifname], NamedSet::InetBridges.name()),
                            ACCEPT,
                        ],
                    );
                }
            }
        }
        Rule::AcceptNet(destination) => {
            decide(out, chain, vec![to.to(Value::Network(destination))], allow);
        }
        Rule::AcceptHost(destination) => {
            out.rule(chain, vec![to.to(Value::Address(destination)), ACCEPT]);
        }
        Rule::DenyNet(destination) => decide(
            out,
            chain,
            vec![to.to(Value::Network(destination))],
            deny(reason),
        ),
        Rule::Accept {
            destination,
            service,
        } => {
            let mut exprs = Vec::new();
            match destination {
                Destination::Net(destination) => exprs.push(to.to(Value::Network(destination))),
                Destination::Addr(destination) => exprs.push(to.to(Value::Address(destination))),
                Destination::HostSet(index) => {
                    let Some(set) = plan.host_set(index) else {
                        return;
                    };
                    let prefix = if to.ipv6 {
                        SET_PREFIX_V6
                    } else {
                        SET_PREFIX_V4
                    };
                    exprs.push(Expr::lookup(to.daddr(), set.id.name(prefix).to_string()));
                }
                Destination::Any => {}
                Destination::Public => {
                    let [v4, v6] = &*PRIVATE;
                    let private = if to.ipv6 { v6 } else { v4 };
                    // One prefix at a time, not a set of ranges, see `NamedSet`.
                    for range in private {
                        exprs.push(to.not_to(Value::Network(*range)));
                    }
                    // The host's own addresses are local wherever they are: traffic to them
                    // goes to the input hook, or, to a published port, gets DNAT.
                    exprs.push(Expr::not(Key::FibDaddrType, Value::Local));
                    exprs.push(Expr::Masked {
                        key: Key::CtStatus,
                        mask: Value::Dnat,
                        value: Value::Number(0),
                    });
                }
            }
            to.service(service, &mut exprs);
            decide(out, chain, exprs, allow);
        }
    }
}

/// Puts rule updates in place over nfnetlink (see [`super::netlink`]).
pub struct NetlinkRunner {
    /// Opened at the first update, and again after one failed: answers of a batch that
    /// failed half way may still be queued.
    updates: Mutex<Option<NftSocket>>,
    /// The encoded batch, reused from one update to the next.
    buffer: Mutex<Vec<u8>>,
    /// For renewals of hostname sets, which come from DNS answers held meanwhile: they don't
    /// wait for an update.
    elements: Mutex<Option<(NftSocket, Vec<u8>, String)>>,
}

impl NetlinkRunner {
    pub fn new() -> Result<Self, FirewallError> {
        Ok(Self {
            updates: Mutex::new(Some(NftSocket::open().map_err(FirewallError::Netlink)?)),
            buffer: Mutex::new(Vec::new()),
            elements: Mutex::new(None),
        })
    }

    /// Send an encoded batch on the update socket; `describe` names the command of a
    /// message the kernel refused.
    fn send(
        &self,
        batch: &mut [u8],
        describe: impl Fn(Option<usize>) -> String,
    ) -> Result<(), FirewallError> {
        let mut guard = self.updates.lock().unwrap_or_else(PoisonError::into_inner);
        let socket = match &mut *guard {
            Some(socket) => socket,
            empty => empty.insert(NftSocket::open().map_err(FirewallError::Netlink)?),
        };
        socket.send_batch(batch).map_err(|refusal| {
            *guard = None;
            FirewallError::Refused {
                command: describe(refusal.message),
                error: refusal.error,
                reason: refusal.reason,
            }
        })
    }

    /// Dump the objects of `kind` of the managed table of `table`'s family.
    fn dump(&self, kind: u16, table: Table, each: impl FnMut(&[u8])) -> Result<(), FirewallError> {
        let mut guard = self.updates.lock().unwrap_or_else(PoisonError::into_inner);
        let socket = match &mut *guard {
            Some(socket) => socket,
            empty => empty.insert(NftSocket::open().map_err(FirewallError::Netlink)?),
        };
        let filter = |out: &mut netlink::Writer<'_>| {
            if kind == netlink::NFT_MSG_GETSET {
                out.string(netlink::NFTA_SET_TABLE, TABLE_NAME);
            }
        };
        socket
            .dump(kind, netlink::family(table), filter, each)
            .map_err(FirewallError::Netlink)
    }
}

/// The text of a command, short enough for a log line.
fn short(command: &Command) -> String {
    const LONGEST: usize = 300;
    let mut text = command.to_string();
    if text.len() > LONGEST {
        let mut end = LONGEST;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
    }
    text
}

impl NftRunner for NetlinkRunner {
    fn run(&self, batch: &Batch) -> Result<(), FirewallError> {
        if tracing::enabled!(tracing::Level::TRACE) {
            trace!(script = %batch, "putting rules in place");
        }
        let mut buffer = self.buffer.lock().unwrap_or_else(PoisonError::into_inner);
        let origins = Encoder::new(&mut buffer).batch(batch);
        self.send(&mut buffer, |message| {
            message
                .and_then(|message| origins.get(message))
                .and_then(|origin| batch.commands.get(*origin))
                .map_or_else(|| "the batch".to_string(), short)
        })
    }

    fn run_encoded(&self, batch: &mut [u8]) -> Result<(), FirewallError> {
        self.send(batch, |message| {
            message.map_or_else(
                || "the saved batch".to_string(),
                |message| format!("message {message} of the saved batch"),
            )
        })
    }

    fn installed(&self) -> Result<Option<Found>, FirewallError> {
        let mut found = Found::default();
        for table in Table::ALL {
            let mut exists = false;
            self.dump(netlink::NFT_MSG_GETTABLE, table, |attributes| {
                exists |= netlink::string_attribute(attributes, netlink::NFTA_TABLE_NAME)
                    == Some(TABLE_NAME);
            })?;
            if !exists {
                return Ok(None);
            }
            self.dump(netlink::NFT_MSG_GETCHAIN, table, |attributes| {
                if netlink::string_attribute(attributes, netlink::NFTA_CHAIN_TABLE)
                    != Some(TABLE_NAME)
                {
                    return;
                }
                if let Some(name) = netlink::string_attribute(attributes, netlink::NFTA_CHAIN_NAME)
                {
                    let base = netlink::has_attribute(attributes, netlink::NFTA_CHAIN_HOOK);
                    found.chains.push((
                        Object {
                            table,
                            name: name.to_string(),
                        },
                        base,
                    ));
                }
            })?;
            self.dump(netlink::NFT_MSG_GETSET, table, |attributes| {
                if let Some(name) = netlink::string_attribute(attributes, netlink::NFTA_SET_NAME) {
                    found.sets.push(Object {
                        table,
                        name: name.to_string(),
                    });
                }
            })?;
        }
        Ok(Some(found))
    }

    fn set_timeouts(
        &self,
        sets: &[TimeoutSet<'_>],
        addresses: &[(IpAddr, Duration)],
    ) -> Result<(), FirewallError> {
        let mut guard = self.elements.lock().unwrap_or_else(PoisonError::into_inner);
        let (socket, buffer, name) = match &mut *guard {
            Some(open) => open,
            empty => empty.insert((
                NftSocket::open().map_err(FirewallError::Netlink)?,
                Vec::new(),
                String::new(),
            )),
        };
        encode_timeouts(buffer, name, TABLE_NAME, sets, addresses);
        let result = socket.send_batch(buffer);
        if result.is_err() {
            // Answers of a batch that failed half way may still be queued.
            *guard = None;
        }
        result.map_err(|refusal| FirewallError::Netlink(refusal.error))
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
        let mut batch = Batch::default();
        render_apply_script(&plan, options, Some(&mut Installed::default()), &mut batch);
        batch.to_string()
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
    fn arp_log_rule(verdict: char, reason: &str) -> String {
        let key = "iifname . arp saddr ether . arp saddr ip";
        format!(
            "{key} != @announced add @announced {{ {key} }} log prefix \"pc:{verdict}:{reason}\" group 7 snaplen 128"
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
        denied_frames_as(selector, verdict, "source")
    }

    /// `denied_frames`, with IPv4 and ARP reported with `reason`.
    fn denied_frames_as(selector: &str, verdict: char, reason: &str) -> String {
        let head = format!("add rule bridge portcullis prerouting {selector}");
        let action = if verdict == 'w' { "accept" } else { "drop" };
        [
            decided(&format!("{head} ether type ip"), verdict, reason, action),
            reported(
                &format!("{head} ether type arp"),
                &arp_log_rule(verdict, reason),
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
add set inet portcullis bridges { type ifname; }
add set inet portcullis enforced_bridges { type ifname; }
add map inet portcullis egress4 { type ipv4_addr : verdict; }
add map inet portcullis egress6 { type ipv6_addr : verdict; }
add set inet portcullis name_limited { type ipv4_addr; }
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
add set bridge portcullis bridges { type ifname; }
add set bridge portcullis monitored_bridges { type ifname; }
add set bridge portcullis enforced_bridges { type ifname; }
add set bridge portcullis monitored_ports { type ifname; }
add set bridge portcullis enforced_ports { type ifname; }
add map bridge portcullis sources_by_port { type ifname . ipv4_addr . ether_addr : verdict; }
add map bridge portcullis sources_by_mac { type ipv4_addr . ether_addr : verdict; }
add map bridge portcullis sources_by_address { type ipv4_addr : verdict; }
add set bridge portcullis arp_by_port { type ifname . ether_addr . ether_addr . ipv4_addr; }
add set bridge portcullis arp_by_mac { type ether_addr . ether_addr . ipv4_addr; }
add set bridge portcullis arp_by_address { type ipv4_addr; }
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
                "add map inet portcullis egress4 { type ipv4_addr : verdict; elements = { 172.18.0.2 : goto egress0 }; }".into(), "add rule inet portcullis forward iifname @bridges ip saddr vmap @egress4".into(),
                // Traffic to the host follows the same rules.
                "add rule inet portcullis input ct state established accept".into(),
                // ICMP errors only from an end of the connection they are about.
                "add rule inet portcullis egress0 ct state related ct original ip saddr 172.18.0.2 accept".into(),
                "add rule inet portcullis egress0 ct state related ct reply ip saddr 172.18.0.2 accept".into(),
                "add rule inet portcullis input iifname @bridges ip saddr vmap @egress4".into(),
                "add rule inet portcullis input iifname @enforced_bridges drop".into(),
                "add set inet portcullis enforced_bridges { type ifname; elements = { \"br-net0\" }; }".into(),
                // The gateway is the host: traffic to it follows the egress rules. So does
                // anything else the host receives, such as broadcast to the subnet: only
                // what leaves through a bridge is for other containers.
                "add rule inet portcullis egress0 ct original ip daddr 172.18.0.0/16 ct original ip daddr != 172.18.0.1 oifname @bridges accept".into(),
                // Broadcast and multicast leaving through a bridge are bridged (with
                // br_netfilter): the ICC rules decided on them.
                "add rule inet portcullis egress0 ct original ip daddr 255.255.255.255/32 oifname @bridges accept\nadd rule inet portcullis egress0 ct original ip daddr 224.0.0.0/4 oifname @bridges accept".into(),
                // Reported by the bridge table already.
                "add rule inet portcullis forward iifname @enforced_bridges drop".into(),
                decided("add rule inet portcullis egress0", 'd', "egress", "drop"),
                "add set bridge portcullis bridges { type ifname; elements = { \"br-net0\" }; }".into(),
                "add rule bridge portcullis prerouting meta ibrname != @bridges accept".into(),
                "add map bridge portcullis sources_by_mac { type ipv4_addr . ether_addr : verdict; elements = { 172.18.0.2 . 02:42:ac:12:00:02 : goto icc0 }; }".into(), "add rule bridge portcullis prerouting ip saddr . ether saddr vmap @sources_by_mac".into(),
                // ARP may only announce the container's own address and MAC.
                "add set bridge portcullis arp_by_mac { type ether_addr . ether_addr . ipv4_addr; elements = { 02:42:ac:12:00:02 . 02:42:ac:12:00:02 . 172.18.0.2, 02:42:ac:12:00:02 . 02:42:ac:12:00:02 . 0.0.0.0 }; }".into(), "add rule bridge portcullis prerouting ether saddr . arp saddr ether . arp saddr ip @arp_by_mac accept".into(),
                // Everything else is denied: IPv4 and ARP as a source that isn't the
                // sender's, other frames (IPv6, VLAN tags) as frames.
                denied_frames("meta ibrname @enforced_bridges", 'd'),
                // Traffic from one container to another must be addressed to their
                // network, one prefix at a time.
                "add rule bridge portcullis forward meta ibrname \"br-net0\" ip daddr 172.18.0.0/16 accept\nadd rule bridge portcullis forward meta ibrname \"br-net0\" ip daddr 255.255.255.255/32 accept\nadd rule bridge portcullis forward meta ibrname \"br-net0\" ip daddr 224.0.0.0/4 accept".into(),
                decided("add rule bridge portcullis forward meta ibrname \"br-net0\" ether type ip", 'd', "icc", "drop"),
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
        // No anonymous sets, nor sets of ranges: lookups in them can miss while an update
        // is committed.
        for line in script.lines().filter(|line| line.starts_with("add rule")) {
            assert!(!line.contains(" { ") || line.contains(" add @"), "{line}");
        }
        assert!(!script.contains("interval"), "{script}");
    }

    #[test]
    fn holds_unknown_sources_of_enforced_networks() {
        let options = Options {
            source_queue: Some(9),
            ..OPTIONS
        };
        let script = render_with(&test_support::hostname_state(), options, false);
        let expected = [
            denied_frames_as("meta ibrname @enforced_bridges meta mark 0x70630001", 'd', "source:held"),
            "add rule bridge portcullis prerouting meta ibrname @enforced_bridges ether type ip queue num 9".to_string(),
            "add rule bridge portcullis prerouting meta ibrname @enforced_bridges ether type arp queue num 9".to_string(),
            denied_frames("meta ibrname @enforced_bridges", 'd'),
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
    fn denies_arp_that_carries_more_than_arp() {
        let script = render(&test_support::hostname_state());
        // Checked before ARP is accepted by its sender.
        let jump = "add rule bridge portcullis prerouting meta ibrname @enforced_bridges ether type arp jump arp_check";
        let accepted = script.find("@arp_by_").expect("ARP accepted by sender");
        assert!(
            script.find(jump).is_some_and(|at| at < accepted),
            "{script}"
        );
        assert!(
            script.contains("add chain bridge portcullis arp_check\n"),
            "{script}"
        );
        for malformed in [
            "arp htype != 1",
            "arp ptype != ip",
            "arp hlen != 6",
            "arp plen != 4",
            "arp operation != 1-2",
            "meta length != 28 meta length != 46",
            "meta length 46 @nh,224,128 != 0",
            "meta length 46 @nh,352,16 != 0",
        ] {
            let head = format!("add rule bridge portcullis arp_check {malformed}");
            assert!(
                script.contains(&framed(&head, 'd', "frame", "drop")),
                "{malformed}: {script}"
            );
        }
        // Reported only, on networks in monitor mode.
        let monitored = render_with(&test_support::hostname_state(), OPTIONS, true);
        assert!(
            monitored
                .contains("meta ibrname @monitored_bridges ether type arp jump arp_check_monitor"),
            "{monitored}"
        );
        assert!(
            monitored.contains(&framed(
                "add rule bridge portcullis arp_check_monitor arp htype != 1",
                'w',
                "frame",
                "accept"
            )),
            "{monitored}"
        );
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
            denied_frames_as("meta ibrname @monitored_bridges meta mark 0x70630001", 'w', "source:held"),
            "add rule bridge portcullis prerouting meta ibrname @monitored_bridges ether type ip queue num 10 bypass".to_string(),
            "add rule bridge portcullis prerouting meta ibrname @monitored_bridges ether type arp queue num 10 bypass".to_string(),
            denied_frames("meta ibrname @monitored_bridges", 'w'),
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

    /// A removed container's elements go, the map emptied and filled again without them,
    /// then its chains (slot `a`); the other container's (slot `b`) stay.
    fn assert_removed(removed: &str, a: usize, b: usize) {
        let deleted = "flush map inet portcullis egress4\n";
        let chain = format!(
            "flush chain inet portcullis egress{a}\ndelete chain inet portcullis egress{a}\n"
        );
        let (Some(deleted), Some(chain)) = (removed.find(deleted), removed.find(&chain)) else {
            panic!("{removed}");
        };
        assert!(deleted < chain, "{removed}");
        let refilled = removed
            .lines()
            .find(|line| {
                line.starts_with(
                    "add map inet portcullis egress4 { type ipv4_addr : verdict; elements = ",
                )
            })
            .expect("refilled map");
        assert!(
            refilled.contains(&format!("172.18.0.3 : goto egress{b}")),
            "{removed}"
        );
        assert!(!refilled.contains("172.18.0.2"), "{removed}");
    }

    #[test]
    fn writes_only_the_chains_whose_rules_changed() {
        use crate::model::{IccMode, RuntimeStateAction};

        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        let mut resolver = MockResolver::default();
        let mut state = RuntimeState::default();
        test_support::add_network(&mut state, "net", "172.18.0.0/16", "172.18.0.1");
        let add = |state: &mut RuntimeState, name: &str, address: &str| {
            test_support::add_container(
                state,
                name,
                name,
                &[("net", address, &[])],
                test_support::policy(IccMode::Deny, vec![test_support::host_egress()]),
            );
        };
        add(&mut state, "a", "172.18.0.2");
        add(&mut state, "b", "172.18.0.3");
        let mut apply = |state: &RuntimeState| {
            firewall
                .apply(state, &mut resolver, &[], false)
                .expect("apply");
        };
        apply(&state);
        add(&mut state, "c", "172.18.0.4");
        apply(&state);
        state.apply_action(RuntimeStateAction::RemoveContainer {
            container_id: "a".to_string().into(),
        });
        apply(&state);
        // The same state again puts nothing in place.
        apply(&state);
        // A network without containers: the update changes none of the containers' rules.
        test_support::add_network(&mut state, "other", "172.30.0.0/16", "172.30.0.1");
        apply(&state);
        add(&mut state, "d", "172.18.0.5");
        apply(&state);

        let scripts = firewall.runner.scripts.lock().expect("lock");
        let [first, added, removed, unchanged, reused] = scripts.as_slice() else {
            panic!("expected five scripts");
        };
        let written = |script: &str, chain: &str| {
            script.contains(&format!("add chain {chain}\nflush chain {chain}\n"))
        };
        // The slot of each of the first two containers, which come in no particular order.
        let (a, b) = if first.contains("172.18.0.2 : goto egress0") {
            (0, 1)
        } else {
            (1, 0)
        };
        // A new container gets chains of its own, and elements in the maps leading to
        // them; the others keep theirs, untouched.
        assert!(written(added, "inet portcullis egress2"), "{added}");
        assert!(written(added, "bridge portcullis icc2"), "{added}");
        assert!(
            has_line(
                added,
                "add map inet portcullis egress4 { type ipv4_addr : verdict; elements = { 172.18.0.4 : goto egress2 }; }"
            ),
            "{added}"
        );
        for chain in ["egress0", "egress1", "icc0", "icc1"] {
            assert!(!added.contains(&format!("portcullis {chain}\n")), "{added}");
            assert!(!added.contains(&format!("goto {chain}")), "{added}");
        }
        assert!(!added.contains("flush map"), "{added}");
        assert_removed(removed, a, b);
        assert!(!removed.contains("delete element"), "{removed}");
        assert!(
            !removed.contains(&format!("flush chain inet portcullis egress{b}")),
            "{removed}"
        );
        // Nothing of the containers changed: nothing of theirs is written.
        assert!(
            !unchanged.contains("chain inet portcullis egress"),
            "{unchanged}"
        );
        assert!(
            !unchanged.contains("chain bridge portcullis icc"),
            "{unchanged}"
        );
        for set in [
            "inet portcullis egress4",
            "bridge portcullis sources_by_mac",
        ] {
            let touched = |line: &str| line.contains(set) && !line.ends_with("verdict; }");
            assert!(!unchanged.lines().any(touched), "{unchanged}");
        }
        // The next container takes the free slot.
        assert!(
            written(reused, &format!("inet portcullis egress{a}")),
            "{reused}"
        );
        assert!(
            has_line(
                reused,
                &format!(
                    "add map inet portcullis egress4 {{ type ipv4_addr : verdict; elements = {{ 172.18.0.5 : goto egress{a} }}; }}"
                )
            ),
            "{reused}"
        );
    }

    #[test]
    fn writes_a_chain_again_when_what_it_is_written_from_changes() {
        use crate::model::{IccMode, RuntimeStateAction};

        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        let mut resolver = MockResolver::default();
        let mut state = RuntimeState::default();
        test_support::add_network(&mut state, "net", "172.18.0.0/16", "172.18.0.1");
        test_support::add_container(
            &mut state,
            "a",
            "a",
            &[("net", "172.18.0.2", &[])],
            test_support::policy(IccMode::Deny, vec![test_support::host_egress()]),
        );
        let mut apply = |state: &RuntimeState| {
            firewall
                .apply(state, &mut resolver, &[], false)
                .expect("apply");
        };
        apply(&state);
        // Its hostname set is named after the container: renamed, the rule uses another.
        state.apply_action(RuntimeStateAction::RenameContainer {
            container_id: "a".to_string().into(),
            name: "renamed".to_string(),
        });
        apply(&state);
        // Other rules.
        test_support::add_container(
            &mut state,
            "a",
            "renamed",
            &[("net", "172.18.0.2", &[])],
            test_support::policy(IccMode::Deny, vec![]),
        );
        apply(&state);

        let scripts = firewall.runner.scripts.lock().expect("lock");
        let [first, renamed, changed] = scripts.as_slice() else {
            panic!("expected three scripts");
        };
        let chain = "inet portcullis egress0";
        let written =
            |script: &str| script.contains(&format!("add chain {chain}\nflush chain {chain}\n"));
        let rules = |script: &str| {
            script
                .lines()
                .filter(|line| line.starts_with(&format!("add rule {chain} ")))
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        assert!(written(first), "{first}");
        assert!(written(renamed), "{renamed}");
        assert!(written(changed), "{changed}");
        assert_ne!(rules(first), rules(renamed));
        assert!(rules(changed).len() < rules(renamed).len(), "{changed}");
    }

    #[test]
    fn writes_hostname_sets_only_when_their_addresses_change() {
        /// Resolves every name to the addresses it holds.
        struct Answers(Vec<IpAddr>);
        impl HostResolver for Answers {
            fn default_hold(&self) -> Duration {
                test_support::HOLD
            }
            fn addresses(
                &mut self,
                _container: &str,
                _host: &str,
                hold: Duration,
            ) -> Vec<(IpAddr, Duration)> {
                self.0.iter().map(|address| (*address, hold)).collect()
            }
            fn looked_up_before(&self, _host: &str) -> bool {
                true
            }
        }

        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        let state = test_support::hostname_state();
        // Another container, for an update that changes something but the set.
        let mut more = state.clone();
        test_support::add_container(
            &mut more,
            "more",
            "more",
            &[("net0", "172.18.0.9", &[])],
            crate::model::ContainerPolicy::default(),
        );
        let mut answers = Answers(vec![test_support::ip("1.1.1.1")]);
        let name = Plan::build(&state, &mut answers, &[], false)
            .host_set(0)
            .expect("host set")
            .id
            .name(SET_PREFIX_V4)
            .to_string();
        for (state, addresses) in [
            (&state, &["1.1.1.1"][..]),
            (&more, &["1.1.1.1"]),
            (&more, &["1.1.1.1", "1.0.0.1"]),
        ] {
            answers.0 = addresses.iter().map(|a| test_support::ip(a)).collect();
            firewall
                .apply(state, &mut answers, &[], false)
                .expect("apply");
        }
        let scripts = firewall.runner.scripts.lock().expect("lock");
        let [first, same, changed] = scripts.as_slice() else {
            panic!("expected three scripts");
        };
        let set = format!("inet portcullis {name}");
        assert!(
            first.contains(&format!(
                "flush set {set}\nadd set {set} {{ type ipv4_addr; flags timeout; size 8192; elements = {{ 1.1.1.1 timeout 3600s }}; }}\n"
            )),
            "{first}"
        );
        // DNS answers and Portcullis's own lookups renew the addresses in the set.
        assert!(!same.contains(&set), "{same}");
        assert!(
            changed.contains(&format!(
                "flush set {set}\nadd set {set} {{ type ipv4_addr; flags timeout; size 8192; elements = {{ 1.1.1.1 timeout 3600s, 1.0.0.1 timeout 3600s }}; }}\n"
            )),
            "{changed}"
        );
    }

    #[test]
    fn puts_nothing_in_place_when_the_rules_stay_the_same() {
        use crate::model::{Container, RuntimeStateAction};

        /// Resolves every name to 1.1.1.1, for as long as `left` says.
        struct Answers {
            left: Duration,
        }
        impl HostResolver for Answers {
            fn default_hold(&self) -> Duration {
                test_support::HOLD
            }
            fn addresses(
                &mut self,
                _container: &str,
                _host: &str,
                _hold: Duration,
            ) -> Vec<(IpAddr, Duration)> {
                vec![(test_support::ip("1.1.1.1"), self.left)]
            }
            fn looked_up_before(&self, _host: &str) -> bool {
                true
            }
        }

        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        let mut answers = Answers {
            left: test_support::HOLD,
        };
        let apply = |state: &RuntimeState, answers: &mut Answers| {
            let mut before = false;
            let update = firewall
                .apply_with(state, answers, &[], false, |_| before = true)
                .expect("apply");
            assert_eq!(before, update.changed);
            update.changed
        };
        let state = test_support::hostname_state();
        assert!(apply(&state, &mut answers));
        // Again: Docker's report of a container found before it, with the same rules.
        let mut reported = state.clone();
        let web = reported.containers().get("abc").cloned().expect("web");
        reported.apply_action(RuntimeStateAction::CreateContainer {
            container: Box::new(Container {
                sandbox: Some("/var/run/docker/netns/0123456789ab".to_string()),
                ..web
            }),
        });
        assert!(!apply(&reported, &mut answers));
        // The hostname's address has less time left: lookups and DNS answers renew it in
        // the set, which the update leaves alone.
        answers.left = Duration::from_secs(60);
        assert!(!apply(&reported, &mut answers));
        // Anything else is put in place: another container...
        let mut more = reported.clone();
        test_support::add_container(
            &mut more,
            "more",
            "more",
            &[("net0", "172.18.0.9", &[])],
            crate::model::ContainerPolicy::default(),
        );
        assert!(apply(&more, &mut answers));
        // ...or its going.
        assert!(apply(&reported, &mut answers));
        assert!(!apply(&reported, &mut answers));
        assert_eq!(firewall.runner.scripts.lock().expect("lock").len(), 3);
    }

    #[test]
    fn writes_every_chain_again_after_a_failed_update() {
        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        let mut resolver = MockResolver::default();
        let state = test_support::icc_state();
        firewall
            .apply(&state, &mut resolver, &[], false)
            .expect("apply");
        *firewall.runner.failing.lock().expect("lock") = Some("add table".to_string());
        firewall
            .apply(&test_support::hostname_state(), &mut resolver, &[], false)
            .expect_err("failed apply");
        *firewall.runner.failing.lock().expect("lock") = None;
        // The rules in place are those of `state` or not, depending on how far the failed
        // update got: they are put in place again.
        firewall
            .apply(&state, &mut resolver, &[], false)
            .expect("apply");
        assert_eq!(firewall.runner.scripts.lock().expect("lock").len(), 2);
        let scripts = firewall.runner.scripts.lock().expect("lock");
        let last = scripts.last().expect("script");
        // The sets too: what they hold isn't known.
        assert!(
            has_line(last, "flush map inet portcullis egress4"),
            "{last}"
        );
        assert!(
            last.contains(
                "add chain inet portcullis egress0\nflush chain inet portcullis egress0\n"
            ),
            "{last}"
        );
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
        assert_eq!(flushed, [[true, true], [false, false]], "{scripts:#?}");
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
            std::collections::HashSet::new(),
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
            line("add map bridge portcullis sources_by_port { type ifname . ipv4_addr . ether_addr : verdict; elements =")
                .contains("\"veth0a1b2c3\" . 172.18.0.2 . 02:42:ac:12:00:02 : goto icc"),
            "{script}"
        );
        assert!(has_line(
            &script,
            "add rule bridge portcullis prerouting iifname . ip saddr . ether saddr vmap @sources_by_port"
        ));
        // ...and not without it; containers whose port isn't known are checked by address
        // and MAC.
        let by_mac = line(
            "add map bridge portcullis sources_by_mac { type ipv4_addr . ether_addr : verdict; elements =",
        );
        assert!(!by_mac.contains("172.18.0.2 "), "{script}");
        assert!(
            by_mac.contains("172.18.0.3 . 02:42:ac:12:00:03"),
            "{script}"
        );
        // ARP may only announce web's own address and MAC, from its port.
        assert_lines(
            &script,
            &["add set bridge portcullis arp_by_port { type ifname . ether_addr . ether_addr . ipv4_addr; elements = { \"veth0a1b2c3\" . 02:42:ac:12:00:02 . 02:42:ac:12:00:02 . 172.18.0.2, \"veth0a1b2c3\" . 02:42:ac:12:00:02 . 02:42:ac:12:00:02 . 0.0.0.0 }; }".into(), "add rule bridge portcullis prerouting iifname . ether saddr . arp saddr ether . arp saddr ip @arp_by_port accept".into()],
        );
        // Anything else from web's port is denied at once, not held.
        let options = Options {
            source_queue: Some(9),
            ..OPTIONS
        };
        let script = render_with(&state, options, false);
        assert_lines(
            &script,
            &["add set bridge portcullis enforced_ports { type ifname; elements = { \"veth0a1b2c3\" }; }".into()],
        );
        let known_port = denied_frames(
            "meta ibrname @enforced_bridges iifname @enforced_ports",
            'd',
        );
        let held = "add rule bridge portcullis prerouting meta ibrname @enforced_bridges ether type ip queue num 9";
        let position = |text: &str| script.find(text).unwrap_or(usize::MAX);
        assert!(position(&known_port) < position(held), "{script}");
        // Unless it was held before, and its hold ran out before Portcullis knew the port:
        // that isn't taken for spoofing.
        let expired = denied_frames_as(
            "meta ibrname @enforced_bridges meta mark 0x70630001",
            'd',
            "source:held",
        );
        assert!(position(&expired) < position(&known_port), "{script}");
    }

    #[test]
    fn doesnt_recognise_containers_without_a_port() {
        // web is stopping: its port and namespace are gone. Anything with its address and
        // MAC comes from someone else's port, and is denied as from an unknown source.
        let mut state = test_support::icc_state();
        state.set_ports(
            std::collections::HashMap::new(),
            std::collections::HashSet::from([test_support::ip("172.18.0.2")]),
        );
        let script = render(&state);
        for line in script
            .lines()
            .filter(|line| line.starts_with("add element bridge portcullis"))
        {
            assert!(!line.contains("172.18.0.2 "), "{line}");
        }
        // Others are still recognised by address and MAC, where their port isn't known.
        assert!(
            script.contains("172.18.0.3 . 02:42:ac:12:00:03 : accept"),
            "{script}"
        );
        // Its rules stay, for traffic the bridge table already let through.
        assert!(script.contains("172.18.0.2 : goto egress"), "{script}");
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
            std::collections::HashSet::new(),
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
                "add set bridge portcullis quarantined { type ifname; elements = { \"veth3\" }; }".into(),
                "add rule bridge portcullis prerouting meta ibrname != @bridges accept\nadd rule bridge portcullis prerouting iifname @quarantined drop".into(),
                "add rule bridge portcullis input iifname @quarantined drop".into(),
                // Open connections: the label's limit, or the default.
                "add set bridge portcullis ports_conns10 { type ifname; elements = { \"veth2\" }; }".into(),
                "add rule bridge portcullis prerouting iifname @ports_conns10 ct state new add @conns10 { iifname ct count over 10 } goto limit_open".into(),
                "add set bridge portcullis ports_conns1000 { type ifname; elements = { \"veth3\" }; }".into(),
                "add rule bridge portcullis prerouting iifname @ports_conns1000 ct state new add @conns1000 { iifname ct count over 1000 } goto limit_open".into(),
                // New connections per second, only where a label asks for it.
                "add set bridge portcullis ports_new5 { type ifname; elements = { \"veth2\" }; }".into(),
                "add rule bridge portcullis prerouting iifname @ports_new5 ct state new add @new5 { iifname limit rate over 5/second burst 5 packets } goto limit_rate".into(),
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
            domains: Some(vec![crate::pattern::NamePattern::host("api.test")]),
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
                format!("{head} ip saddr @name_limited meta l4proto tcp th dport 53 ct direction original meta mark != 0x70630003 meta mark != 0x70630002 queue num 9"),
                format!("{head} ip saddr @name_limited meta l4proto udp th dport 53 ct direction original meta mark != 0x70630003 meta mark != 0x70630002 queue num 9"),
                format!("{head} meta mark 0x70630002 meta l4proto tcp reject with tcp reset"),
                format!("{head} meta mark 0x70630002 reject with icmpx admin-prohibited"),
                format!("{head} meta mark 0x70630003 meta mark set 0x0"),
                format!("{head} ct state established accept"),
            ]
            .join("\n");
            assert!(script.contains(&expected), "{script}");
        }
        assert!(has_line(
            &script,
            "add set inet portcullis name_limited { type ipv4_addr; elements = { 172.18.0.2 }; }"
        ));
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
                    || line.starts_with("add rule bridge portcullis arp_check ")
                    || line.contains("@quarantined")
                    || line.contains(&link_local_group().to_string()),
                "{line}"
            );
        }
        assert_lines(
            &script,
            &[
                format!("add rule inet portcullis forward iifname @enforced_bridges {reject}"),
                decided(
                    "add rule inet portcullis egress0 meta l4proto udp ct original proto-dst 53",
                    'd',
                    "dns",
                    reject,
                ),
                decided("add rule inet portcullis egress0", 'd', "egress", reject),
                denied_frames("meta ibrname @enforced_bridges", 'd'),
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
        assert!(!script.contains("iifname @enforced_bridges"), "{script}");
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
                denied_frames("meta ibrname @monitored_bridges", 'w'),
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
        let queue = "add rule inet portcullis forward oifname @bridges meta l4proto udp th sport 53 ct direction reply queue num 9 bypass";
        let established = "add rule inet portcullis forward ct state established accept";
        let position = |line: &str| script.lines().position(|candidate| candidate == line);
        assert!(
            position(queue).expect("queue rule") < position(established).expect("established rule")
        );
    }

    #[test]
    fn renders_hostname_sets_with_timeouts_once_per_container_and_host() {
        let script = render(&test_support::shared_hostname_state());
        let declarations = script
            .lines()
            .filter(|line| line.starts_with("add set inet portcullis pc_h4_"));
        assert_eq!(
            declarations
                .filter(|line| line.ends_with("size 8192; }"))
                .count(),
            2
        );
        assert!(script.contains("{ type ipv4_addr; flags timeout; size 8192; }"));
        assert!(script.contains("; elements = { 1.1.1.1 timeout 3600s }; }\n"));
        assert_eq!(script.matches("ct original ip daddr @pc_h4_").count(), 2);
        // no IPv6 source references the host, so no IPv6 set is created
        assert!(!script.contains("pc_h6_"));
    }

    #[test]
    fn renders_ipv6_rules_and_sets() {
        let script = render(&test_support::ipv6_state());
        assert!(script.contains("add set inet portcullis pc_h6_"));
        assert!(script.contains("; elements = { 2606:4700::1111 timeout 3600s }; }\n"));
        assert!(!script.contains("pc_h4_"));
        assert!(has_line(
            &script,
            "add rule inet portcullis forward iifname @bridges ip6 saddr vmap @egress6"
        ));
        assert!(has_line(
            &script,
            "add map inet portcullis egress6 { type ipv6_addr : verdict; elements = { fd00::2 : goto egress0 }; }"
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
    fn renders_destinations_and_services_of_every_kind() {
        let script = render(&test_support::services_state());
        let public = PRIVATE_V4
            .iter()
            .map(|range| format!("ct original ip daddr != {range}"))
            .collect::<Vec<_>>()
            .join(" ");
        let egress = script
            .split("172.18.0.2 : goto ")
            .nth(1)
            .and_then(|rest| rest.split([',', ' ']).next())
            .expect("web's egress chain");
        let set = script
            .split("ct original ip daddr @")
            .nth(1)
            .and_then(|rest| rest.split(' ').next())
            .expect("host set");
        assert_lines(
            &script,
            &[
                // Public: none of the ranges that aren't, and nothing local, before or after
                // DNAT.
                format!(
                    "add rule inet portcullis {egress} {public} fib daddr type != local ct status & dnat == 0 meta l4proto tcp ct original proto-dst 1024-65535 accept"
                ),
                format!(
                    "add rule inet portcullis {egress} {public} fib daddr type != local ct status & dnat == 0 meta l4proto udp ct original proto-dst 3478-3479 accept"
                ),
                format!("add rule inet portcullis {egress} meta l4proto icmp accept"),
                format!(
                    "add rule inet portcullis {egress} ct original ip daddr @{set} meta l4proto tcp accept"
                ),
            ],
        );
        let chain = script
            .split("172.18.0.2 . 02:42:ac:12:00:02 : goto ")
            .nth(1)
            .and_then(|rest| rest.split([',', ' ']).next())
            .expect("web's ICC chain");
        assert_lines(
            &script,
            &[
                format!("add rule bridge portcullis {chain} ip daddr 172.18.0.11 accept"),
                format!("add rule bridge portcullis {chain} ip daddr 172.18.0.12 accept"),
            ],
        );
        assert!(!script.contains("ip daddr 172.18.0.20 accept"), "{script}");
        // DNS is still decided by the DNS rules, before any of these.
        let position = |text: String| script.find(&text).expect("rule");
        assert!(
            position(format!(
                "{egress} meta l4proto udp ct original proto-dst 53 drop"
            )) < position(format!("{egress} meta l4proto icmp accept"))
        );
    }

    #[test]
    fn renders_services_for_traffic_between_containers() {
        use crate::model::{PortRange, Protocol};
        let to = Match::new(test_support::ip("172.18.0.2"), Chain::Icc(0));
        let ports = PortRange {
            first: 1,
            last: 200,
        };
        let service = |to: &Match, service| {
            let mut exprs = Vec::new();
            to.service(service, &mut exprs);
            exprs.iter().fold(String::new(), |mut text, expr| {
                let _ = write!(text, " {expr}");
                text
            })
        };
        assert_eq!(
            service(&to, Service::Protocol(Protocol::Tcp, Some(ports))),
            " tcp dport 1-200"
        );
        assert_eq!(
            service(&to, Service::Protocol(Protocol::Sctp, None)),
            " meta l4proto sctp"
        );
        assert_eq!(service(&to, Service::Any), "");
        let routed = Match::new(test_support::ip("fd00::2"), Chain::Egress(0));
        assert_eq!(
            service(&routed, Service::Protocol(Protocol::Icmp, None)),
            " meta l4proto ipv6-icmp"
        );
    }

    #[test]
    fn renders_unresolvable_hostname_as_empty_set() {
        let script = render(&test_support::unresolvable_state());
        assert!(script.contains("add set inet portcullis pc_h4_"));
        assert!(!script.contains("add element inet portcullis pc_h4_"));
        assert!(script.contains("ct original ip daddr @pc_h4_"));
        assert!(script.contains(
            "ct original ip daddr 8.8.8.0/24 meta l4proto tcp ct original proto-dst 853 accept"
        ));
    }

    #[derive(Default)]
    struct RecordingRunner {
        scripts: Mutex<Vec<String>>,
        /// Saved batches put in place.
        encoded: Mutex<Vec<Vec<u8>>>,
        /// What the tables hold, if they exist.
        found: Mutex<Option<Found>>,
        /// Batches fail while they contain this.
        failing: Mutex<Option<String>>,
        /// What the next batch makes appear, as if it created the tables.
        creates: Mutex<Option<Found>>,
    }

    impl RecordingRunner {
        /// Pretend both tables exist, as a previous run left them.
        fn with_tables(found: Found) -> Self {
            let runner = Self::default();
            *runner.found.lock().expect("lock") = Some(found);
            runner
        }

        fn created(&self) {
            if let Some(created) = self.creates.lock().expect("lock").take() {
                *self.found.lock().expect("lock") = Some(created);
            }
        }
    }

    impl NftRunner for RecordingRunner {
        fn run(&self, batch: &Batch) -> Result<(), FirewallError> {
            let script = batch.to_string();
            let failing = self.failing.lock().expect("lock");
            if failing
                .as_ref()
                .is_some_and(|text| script.contains(text.as_str()))
            {
                return Err(FirewallError::Refused {
                    command: script,
                    error: io::Error::from_raw_os_error(16),
                    reason: None,
                });
            }
            self.scripts.lock().expect("lock").push(script);
            self.created();
            Ok(())
        }

        fn run_encoded(&self, batch: &mut [u8]) -> Result<(), FirewallError> {
            self.encoded.lock().expect("lock").push(batch.to_vec());
            self.created();
            Ok(())
        }

        fn installed(&self) -> Result<Option<Found>, FirewallError> {
            Ok(self.found.lock().expect("lock").clone())
        }

        /// Recorded as the script that does the same.
        fn set_timeouts(
            &self,
            sets: &[TimeoutSet<'_>],
            addresses: &[(IpAddr, Duration)],
        ) -> Result<(), FirewallError> {
            let mut batch = Batch::default();
            for set in sets {
                render_timeouts(&mut batch, &set.name.to_string(), set.ipv6, || {
                    addresses
                        .iter()
                        .copied()
                        .filter(|(address, _)| address.is_ipv6() == set.ipv6)
                });
            }
            if !batch.is_empty() {
                self.run(&batch)?;
            }
            Ok(())
        }
    }

    fn object(table: Table, name: &str) -> Object {
        Object {
            table,
            name: name.to_string(),
        }
    }

    /// The tables a previous run left: base chains, chains of sources, sets every update
    /// creates, and sets of hostnames and limits.
    fn previous_run() -> Found {
        Found {
            chains: vec![
                (object(Table::Inet, "forward"), true),
                (object(Table::Inet, "egress0"), false),
                (object(Table::Inet, "egress7"), false),
                (object(Table::Bridge, "prerouting"), true),
                (object(Table::Bridge, "icc3"), false),
                (object(Table::Bridge, "limit_open"), false),
            ],
            sets: vec![
                object(Table::Inet, "logged4"),
                object(Table::Inet, "egress4"),
                object(Table::Inet, "pc_h4_00000000000000aa"),
                object(Table::Bridge, "quarantined"),
                object(Table::Bridge, "conns16384"),
            ],
        }
    }

    #[test]
    fn keeps_the_rules_a_previous_run_left_in_place() {
        let firewall = NftablesFirewall::new(RecordingRunner::with_tables(previous_run()), OPTIONS);
        assert_eq!(firewall.restore().expect("restore"), Restored::Kept);
        firewall
            .apply(
                &test_support::hostname_state(),
                &mut MockResolver::default(),
                &[],
                false,
            )
            .expect("apply");
        let scripts = firewall.runner.scripts.lock().expect("lock");
        let [script] = scripts.as_slice() else {
            panic!("expected one script: {scripts:#?}");
        };
        // Updated in place, as by any update.
        assert!(!script.contains("delete table"), "{script}");
        // Chains and sets it doesn't need anymore are removed; base chains and the sets
        // every update creates are kept.
        assert_lines(
            script,
            &[
                "flush chain inet portcullis egress7\ndelete chain inet portcullis egress7".into(),
                "flush chain bridge portcullis icc3\ndelete chain bridge portcullis icc3".into(),
                "delete set inet portcullis pc_h4_00000000000000aa".into(),
                "delete set bridge portcullis conns16384".into(),
            ],
        );
        for kept in [
            "chain inet portcullis forward",
            "chain bridge portcullis prerouting",
            "chain inet portcullis egress0",
            "chain bridge portcullis limit_open",
            "set inet portcullis logged4",
            "map inet portcullis egress4",
            "set bridge portcullis quarantined",
        ] {
            assert!(
                !script.contains(&format!("delete {kept}\n")),
                "{kept}:\n{script}"
            );
        }
    }

    #[test]
    fn replaces_rules_found_in_place_that_updates_cant_change() {
        let runner = RecordingRunner::with_tables(previous_run());
        *runner.failing.lock().expect("lock") = Some("delete chain inet portcullis egress7".into());
        let firewall = NftablesFirewall::new(runner, OPTIONS);
        firewall.restore().expect("restore");
        let state = test_support::hostname_state();
        let mut resolver = MockResolver::default();
        firewall
            .apply(&state, &mut resolver, &[], false)
            .expect("apply");
        let scripts = firewall.runner.scripts.lock().expect("lock").clone();
        assert_eq!(scripts.len(), 1);
        assert!(
            scripts[0].starts_with("add table inet portcullis\ndelete table inet portcullis\n")
        );
        // Only the first update does: rules this run installed stay updated in place.
        *firewall.runner.failing.lock().expect("lock") = Some("add rule".into());
        let changed = test_support::shared_hostname_state();
        assert!(firewall.apply(&changed, &mut resolver, &[], false).is_err());
        assert_eq!(firewall.runner.scripts.lock().expect("lock").len(), 1);
    }

    #[test]
    fn lists_installed_chains_and_sets() {
        let installed = Installed::of(previous_run());
        assert_eq!(
            installed.chains,
            BTreeSet::from([
                object(Table::Inet, "egress0"),
                object(Table::Inet, "egress7"),
                object(Table::Bridge, "icc3"),
                object(Table::Bridge, "limit_open"),
            ])
        );
        assert_eq!(
            installed.sets,
            BTreeSet::from([
                object(Table::Inet, "pc_h4_00000000000000aa"),
                object(Table::Bridge, "conns16384"),
            ])
        );
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
    fn sets_how_long_addresses_stay_in_host_sets() {
        let firewall = NftablesFirewall::new(RecordingRunner::default(), OPTIONS);
        let plan = Plan::build(
            &test_support::hostname_state(),
            &mut MockResolver::default(),
            &[],
            false,
        );
        let set = plan.host_set(0).expect("host set");
        firewall
            .update_host_addresses(
                set,
                &[
                    (
                        test_support::ip("198.51.100.3"),
                        Duration::from_millis(1500),
                    ),
                    (test_support::ip("198.51.100.4"), Duration::ZERO),
                    (test_support::ip("2001:db8::1"), Duration::from_secs(60)),
                ],
            )
            .expect("update");
        let scripts = firewall.runner.scripts.lock().expect("lock");
        let name = set.id.name(SET_PREFIX_V4);
        // Added, deleted and added again: an add alone doesn't renew the timeout of an
        // address that is in the set already. Zero removes an address, there or not.
        assert_eq!(
            scripts.as_slice(),
            [format!(
                "add set inet portcullis {name} {{ type ipv4_addr; elements = {{ 198.51.100.3 timeout 2s, 198.51.100.4 timeout 1s }}; }}\n\
                 delete element inet portcullis {name} {{ 198.51.100.3, 198.51.100.4 }}\n\
                 add set inet portcullis {name} {{ type ipv4_addr; elements = {{ 198.51.100.3 timeout 2s }}; }}\n"
            )]
        );
    }

    #[test]
    fn keeps_host_addresses_a_previous_run_left_in_place_at_the_first_update() {
        let state = test_support::hostname_state();
        let plan = Plan::build(&state, &mut MockResolver::default(), &[], false);
        let name = plan.host_set(0).expect("host set").id.name(SET_PREFIX_V4);
        let tables = || Found {
            chains: vec![
                (object(Table::Bridge, "prerouting"), true),
                (object(Table::Bridge, "icc3"), false),
                (object(Table::Bridge, "limit_open"), false),
            ],
            sets: vec![
                object(Table::Inet, &name.to_string()),
                object(Table::Bridge, "quarantined"),
                object(Table::Bridge, "conns16384"),
            ],
        };
        let renewed = format!(
            "add set inet portcullis {name} {{ type ipv4_addr; elements = {{ 1.1.1.1 timeout 3600s }}; }}\n\
             delete element inet portcullis {name} {{ 1.1.1.1 }}\n\
             add set inet portcullis {name} {{ type ipv4_addr; elements = {{ 1.1.1.1 timeout 3600s }}; }}\n"
        );
        let added = format!(
            "add set inet portcullis {name} {{ type ipv4_addr; flags timeout; size 8192; elements = {{ 1.1.1.1 timeout 3600s }}; }}\n"
        );
        let flushed = format!("flush set inet portcullis {name}\n{added}");

        // Left in place by a run that stopped: what the set has stays, the update renews
        // what Portcullis knows.
        let firewall = NftablesFirewall::new(RecordingRunner::with_tables(tables()), OPTIONS);
        assert_eq!(firewall.restore().expect("restore"), Restored::Kept);
        // Then a network without containers: an update that changes nothing of the set.
        let mut more = state.clone();
        test_support::add_network(&mut more, "other", "172.30.0.0/16", "172.30.0.1");
        for state in [&state, &more] {
            firewall
                .apply(state, &mut MockResolver::default(), &[], false)
                .expect("apply");
        }
        let scripts = firewall.runner.scripts.lock().expect("lock");
        // Added where missing, then renewed once the update is in place.
        assert!(scripts[0].contains(&added), "{}", scripts[0]);
        assert!(!scripts[0].contains(&format!("flush set inet portcullis {name}")));
        assert_eq!(scripts[1], renewed);
        // A later update with the same addresses leaves the set alone: what the previous run
        // learned still runs out as it would have.
        assert_eq!(scripts.len(), 3);
        assert!(
            !scripts[2].contains(&format!("inet portcullis {name}")),
            "{}",
            scripts[2]
        );
        drop(scripts);

        // Put back from the saved rules after a reboot: those addresses may be days old.
        let path = std::env::temp_dir().join(format!(
            "portcullis-saved-hosts-{}/rules.batch",
            std::process::id()
        ));
        fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        fs::write(&path, encode_saved(&Batch::default())).expect("save");
        let restored =
            NftablesFirewall::new(RecordingRunner::default(), OPTIONS).saving_to(path.clone());
        *restored.runner.creates.lock().expect("lock") = Some(tables());
        assert_eq!(restored.restore().expect("restore"), Restored::Saved);
        restored
            .apply(&state, &mut MockResolver::default(), &[], false)
            .expect("apply");
        let scripts = restored.runner.scripts.lock().expect("lock");
        assert!(scripts[0].contains(&flushed), "{}", scripts[0]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn saves_rules_to_restore_them_at_the_next_start() {
        let path = std::env::temp_dir().join(format!(
            "portcullis-saved-{}/rules.batch",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let firewall =
            NftablesFirewall::new(RecordingRunner::default(), OPTIONS).saving_to(path.clone());
        assert_eq!(
            firewall.restore().expect("restore"),
            Restored::Nothing,
            "nothing saved yet"
        );
        let mut resolver = MockResolver::default();
        let mut last = None;
        for state in [test_support::icc_state(), test_support::hostname_state()] {
            let plan = firewall
                .apply(&state, &mut resolver, &[], false)
                .expect("apply");
            firewall.save(&plan).expect("save");
            last = Some(plan);
        }
        // The saved batch installs the last update's rules from scratch, unlike the update
        // itself.
        let fresh = fresh_batch(&last.expect("plan"), OPTIONS);
        let script = fresh.to_string();
        assert!(script.starts_with("add table inet portcullis\ndelete table inet portcullis\n"));
        // ...with nothing of the update before it.
        assert!(script.contains("ct original ip daddr @pc_h4_"));
        assert!(!script.contains("delete chain"), "{script}");
        let saved = fs::read(&path).expect("saved");
        assert_eq!(saved, encode_saved(&fresh));

        // Without tables in place (after a reboot), restoring puts it in place, and the next
        // update changes what it installed in place.
        *firewall.runner.creates.lock().expect("lock") = Some(previous_run());
        assert_eq!(firewall.restore().expect("restore"), Restored::Saved);
        assert_eq!(
            firewall.runner.encoded.lock().expect("lock").as_slice(),
            [saved[SAVED_HEADER.len()..].to_vec()]
        );
        firewall
            .apply(&test_support::icc_state(), &mut resolver, &[], false)
            .expect("apply");
        let scripts = firewall.runner.scripts.lock().expect("lock");
        assert!(
            scripts
                .get(2)
                .is_some_and(|script| !script.contains("delete table"))
        );
        drop(scripts);

        // Rules an earlier version saved as an nft script aren't run.
        fs::write(&path, "add table inet portcullis\n").expect("save");
        let earlier =
            NftablesFirewall::new(RecordingRunner::default(), OPTIONS).saving_to(path.clone());
        assert_eq!(earlier.restore().expect("restore"), Restored::Nothing);
        assert!(earlier.runner.encoded.lock().expect("lock").is_empty());

        // With tables in place, they are kept, and the saved script isn't run.
        let kept = NftablesFirewall::new(RecordingRunner::with_tables(previous_run()), OPTIONS)
            .saving_to(path.clone());
        assert_eq!(kept.restore().expect("restore"), Restored::Kept);
        assert!(kept.runner.scripts.lock().expect("lock").is_empty());
        assert!(kept.runner.encoded.lock().expect("lock").is_empty());

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
