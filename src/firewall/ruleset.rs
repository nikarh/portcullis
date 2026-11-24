//! The commands of a rule update, as Portcullis puts them in place: tables, chains, sets
//! and their elements, and rules made of typed expressions and statements.
//!
//! An update is built as a [`Batch`] of [`Command`]s. The kernel gets it as one `nf_tables`
//! transaction (see [`super::netlink`]); written out (`Display`), it is the nft script that
//! does the same, which tests and logs read.

use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use ipnet::IpNet;

use crate::model::{MacAddress, Protocol};

/// Name of both managed tables.
pub const TABLE_NAME: &str = "portcullis";
/// Priority of all base chains: before Docker's filter chains.
pub const HOOK_PRIORITY: i32 = -1;

/// The managed tables: `inet` sees traffic routed out of a container's network (forward
/// hook) and traffic to the host itself (input hook), `bridge` sees traffic between
/// containers on the same network, which a bridge switches without passing the IP hooks
/// unless `br_netfilter` is loaded (prerouting hook: the bridge family only supports
/// `reject` there).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Table {
    Inet,
    Bridge,
}

impl Table {
    pub const ALL: [Self; 2] = [Self::Inet, Self::Bridge];

    /// The hook of its main base chain.
    pub const fn hook(self) -> &'static str {
        match self {
            Self::Inet => "forward",
            Self::Bridge => "prerouting",
        }
    }

    pub const fn family(self) -> &'static str {
        match self {
            Self::Inet => "inet",
            Self::Bridge => "bridge",
        }
    }
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {TABLE_NAME}", self.family())
    }
}

/// A chain, displayed as `<family> <table> <chain>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Chain {
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
    /// Denies (or in monitor mode, reports) ARP that isn't a plain request or reply.
    ArpCheck { monitor: bool },
    /// Egress rules of the source in the n-th slot, in the inet table.
    Egress(usize),
    /// ICC rules of the source in the n-th slot, in the bridge table.
    Icc(usize),
}

impl Chain {
    pub const fn table(self) -> Table {
        match self {
            Self::Base(table) => table,
            Self::Input | Self::Egress(_) => Table::Inet,
            Self::BridgeInput
            | Self::BridgeForward
            | Self::Limited { .. }
            | Self::ArpCheck { .. }
            | Self::Icc(_) => Table::Bridge,
        }
    }

    /// The hook of a base chain; `None` for the others.
    pub const fn hook(self) -> Option<&'static str> {
        match self {
            Self::Base(table) => Some(table.hook()),
            Self::Input | Self::BridgeInput => Some("input"),
            Self::BridgeForward => Some("forward"),
            _ => None,
        }
    }

    /// The chain as a named object of its table.
    pub fn object(self) -> Object {
        Object {
            table: self.table(),
            name: ChainName(self).to_string(),
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.table(), ChainName(*self))
    }
}

/// The chain name alone, as used in jump targets.
#[derive(Clone, Copy)]
pub struct ChainName(pub Chain);

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
            Chain::ArpCheck { monitor } => {
                write!(f, "arp_check{}", if monitor { "_monitor" } else { "" })
            }
            Chain::Egress(index) => write!(f, "egress{index}"),
            Chain::Icc(index) => write!(f, "icc{index}"),
        }
    }
}

/// A chain or set of a table by name, displayed as `<family> <table> <name>`: one that may
/// have been found in place, left by another run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Object {
    pub table: Table,
    pub name: String,
}

impl fmt::Display for Object {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.table, self.name)
    }
}

/// A set name: fixed, or made up for a host or a limit.
pub type Name = Cow<'static, str>;

/// The type of a set's key, or of one part of a concatenated key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    Ifname,
    Ipv4,
    Ipv6,
    Ether,
    EtherType,
    InetProto,
    InetService,
}

impl KeyType {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ifname => "ifname",
            Self::Ipv4 => "ipv4_addr",
            Self::Ipv6 => "ipv6_addr",
            Self::Ether => "ether_addr",
            Self::EtherType => "ether_type",
            Self::InetProto => "inet_proto",
            Self::InetService => "inet_service",
        }
    }

    /// Bytes of a value, before padding to the register size in concatenations.
    pub const fn len(self) -> usize {
        match self {
            Self::Ifname | Self::Ipv6 => 16,
            Self::Ipv4 => 4,
            Self::Ether => 6,
            Self::EtherType | Self::InetService => 2,
            Self::InetProto => 1,
        }
    }
}

/// `flags` of a set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SetFlags {
    /// Rules add elements (`add @set { ... }`).
    pub dynamic: bool,
    /// Elements expire.
    pub timeout: bool,
}

/// What a set or verdict map is, as declared.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SetDecl {
    pub table: Table,
    pub name: Name,
    pub key: &'static [KeyType],
    /// A verdict map rather than a set.
    pub map: bool,
    pub flags: SetFlags,
    /// How long elements stay by default.
    pub timeout: Option<Duration>,
    /// How many elements it may hold.
    pub size: Option<u32>,
}

impl SetDecl {
    pub const fn set(table: Table, name: &'static str, key: &'static [KeyType]) -> Self {
        Self {
            table,
            name: Cow::Borrowed(name),
            key,
            map: false,
            flags: SetFlags {
                dynamic: false,
                timeout: false,
            },
            timeout: None,
            size: None,
        }
    }

    const fn kind(&self) -> &'static str {
        if self.map { "map" } else { "set" }
    }

    /// `add <kind> <table> <name> { type <type>; <flags...>`, without the closing brace.
    fn head(&self) -> impl fmt::Display + '_ {
        fmt::from_fn(move |f| {
            write!(
                f,
                "add {} {} {} {{ type ",
                self.kind(),
                self.table,
                self.name
            )?;
            for (index, part) in self.key.iter().enumerate() {
                if index > 0 {
                    f.write_str(" . ")?;
                }
                f.write_str(part.name())?;
            }
            if self.map {
                f.write_str(" : verdict")?;
            }
            let flags = match (self.flags.dynamic, self.flags.timeout) {
                (true, true) => Some("dynamic,timeout"),
                (true, false) => Some("dynamic"),
                (false, true) => Some("timeout"),
                (false, false) => None,
            };
            if let Some(flags) = flags {
                write!(f, "; flags {flags}")?;
            }
            if let Some(timeout) = self.timeout {
                write!(f, "; timeout {}s", timeout.as_secs())?;
            }
            if let Some(size) = self.size {
                write!(f, "; size {size}")?;
            }
            Ok(())
        })
    }
}

/// The longest key of any set: two IPv6 addresses, a protocol and a port.
const MAX_KEY: usize = 40;

/// A set element: its key as the kernel holds it, the verdict of a map element, and how long
/// it stays in a set with timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Element {
    key: [u8; MAX_KEY],
    len: u8,
    pub verdict: Option<Verdict>,
    pub timeout: Option<Duration>,
}

impl Element {
    /// The key, with each part of a concatenation padded to 4 bytes.
    pub fn key(&self) -> &[u8] {
        self.key.get(..usize::from(self.len)).unwrap_or_default()
    }

    #[must_use]
    pub const fn with_verdict(mut self, verdict: Verdict) -> Self {
        self.verdict = Some(verdict);
        self
    }

    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// An element with a key of the parts `parts`.
    pub fn of(parts: &[Part<'_>]) -> Self {
        let mut element = Self {
            key: [0; MAX_KEY],
            len: 0,
            verdict: None,
            timeout: None,
        };
        let concatenated = parts.len() > 1;
        let mut at = 0;
        for part in parts {
            let start = at;
            let mut put = |bytes: &[u8]| {
                if let Some(slot) = element.key.get_mut(at..at + bytes.len()) {
                    slot.copy_from_slice(bytes);
                }
                at += bytes.len();
            };
            match part {
                Part::Ifname(name) => {
                    let mut bytes = [0; 16];
                    let name = name.as_bytes();
                    let length = name.len().min(15);
                    for (slot, byte) in bytes.iter_mut().zip(name.iter().take(length)) {
                        *slot = *byte;
                    }
                    put(&bytes);
                }
                Part::Address(IpAddr::V4(address)) => put(&address.octets()),
                Part::Address(IpAddr::V6(address)) => put(&address.octets()),
                Part::Mac(mac) => put(&mac.octets()),
            }
            if concatenated {
                at = start + (at - start).next_multiple_of(4);
            }
        }
        element.len = u8::try_from(at.min(MAX_KEY)).unwrap_or_default();
        element
    }

    /// Written out as in an nft script, for a set of `decl`.
    pub fn display<'a>(&'a self, decl: &'a SetDecl) -> impl fmt::Display + 'a {
        fmt::from_fn(move |f| {
            let mut rest = self.key();
            let concatenated = decl.key.len() > 1;
            for (index, part) in decl.key.iter().enumerate() {
                if index > 0 {
                    f.write_str(" . ")?;
                }
                let length = part.len();
                let taken = if concatenated {
                    length.next_multiple_of(4)
                } else {
                    length
                };
                let value = rest.get(..length).unwrap_or_default();
                rest = rest.get(taken..).unwrap_or_default();
                match part {
                    KeyType::Ifname => {
                        let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                        let name = String::from_utf8_lossy(value.get(..end).unwrap_or_default());
                        write!(f, "{}", Quoted(&name))?;
                    }
                    KeyType::Ipv4 => {
                        let octets: [u8; 4] = value.try_into().unwrap_or_default();
                        write!(f, "{}", Ipv4Addr::from(octets))?;
                    }
                    KeyType::Ipv6 => {
                        let octets: [u8; 16] = value.try_into().unwrap_or_default();
                        write!(f, "{}", Ipv6Addr::from(octets))?;
                    }
                    KeyType::Ether => {
                        let octets: [u8; 6] = value.try_into().unwrap_or_default();
                        write!(f, "{}", MacAddress::from(octets))?;
                    }
                    KeyType::EtherType | KeyType::InetProto | KeyType::InetService => {
                        let mut number = 0_u32;
                        for byte in value {
                            number = number << 8 | u32::from(*byte);
                        }
                        write!(f, "{number}")?;
                    }
                }
            }
            match self.verdict {
                Some(Verdict::Accept) => f.write_str(" : accept")?,
                Some(Verdict::Drop) => f.write_str(" : drop")?,
                Some(Verdict::Goto(chain)) => write!(f, " : goto {}", ChainName(chain))?,
                Some(Verdict::Jump(chain)) => write!(f, " : jump {}", ChainName(chain))?,
                None => {}
            }
            if let Some(timeout) = self.timeout {
                write!(f, " timeout {}s", timeout_seconds(timeout))?;
            }
            Ok(())
        })
    }
}

/// A part of an element's key.
#[derive(Debug, Clone, Copy)]
pub enum Part<'a> {
    Ifname(&'a str),
    Address(IpAddr),
    Mac(MacAddress),
}

/// A timeout as scripts write it: whole seconds, rounded up, at least one.
pub fn timeout_seconds(timeout: Duration) -> u64 {
    let seconds = timeout.as_secs() + u64::from(timeout.subsec_nanos() > 0);
    seconds.max(1)
}

/// A string in double quotes, as nft expects interface names.
pub struct Quoted<'a>(pub &'a str);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0)
    }
}

/// What a rule, or a map element, does with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verdict {
    Accept,
    Drop,
    Goto(Chain),
    Jump(Chain),
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept => f.write_str("accept"),
            Self::Drop => f.write_str("drop"),
            Self::Goto(chain) => write!(f, "goto {}", ChainName(*chain)),
            Self::Jump(chain) => write!(f, "jump {}", ChainName(*chain)),
        }
    }
}

/// What a rule matches on: packet headers, metadata, connection tracking or routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    Iifname,
    Oifname,
    /// The bridge a frame entered.
    Ibrname,
    L4proto,
    Nfproto,
    Length,
    Mark,
    EtherSaddr,
    EtherDaddr,
    EtherType,
    ArpHtype,
    ArpPtype,
    ArpHlen,
    ArpPlen,
    ArpOperation,
    /// The MAC an ARP packet announces.
    ArpSaddrEther,
    /// The address an ARP packet announces.
    ArpSaddrIp,
    IpSaddr,
    IpDaddr,
    Ip6Saddr,
    Ip6Daddr,
    /// The source port of any transport protocol.
    ThSport,
    /// The destination port of any transport protocol.
    ThDport,
    /// The destination port of a protocol with ports.
    Dport(Protocol),
    /// `bits` bits of the network header from bit `offset` on.
    Raw {
        offset: u16,
        bits: u16,
    },
    CtState,
    CtStatus,
    CtDirection,
    /// The source address of a connection in its original direction, or its reply.
    CtSaddr {
        reply: bool,
        ipv6: bool,
    },
    /// The destination address of a connection in its original direction.
    CtDaddr {
        ipv6: bool,
    },
    /// The destination port of a connection in its original direction.
    CtProtoDst,
    /// The routing type of the destination address.
    FibDaddrType,
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let family = |ipv6: bool| if ipv6 { "ip6" } else { "ip" };
        match self {
            Self::Iifname => f.write_str("iifname"),
            Self::Oifname => f.write_str("oifname"),
            Self::Ibrname => f.write_str("meta ibrname"),
            Self::L4proto => f.write_str("meta l4proto"),
            Self::Nfproto => f.write_str("meta nfproto"),
            Self::Length => f.write_str("meta length"),
            Self::Mark => f.write_str("meta mark"),
            Self::EtherSaddr => f.write_str("ether saddr"),
            Self::EtherDaddr => f.write_str("ether daddr"),
            Self::EtherType => f.write_str("ether type"),
            Self::ArpHtype => f.write_str("arp htype"),
            Self::ArpPtype => f.write_str("arp ptype"),
            Self::ArpHlen => f.write_str("arp hlen"),
            Self::ArpPlen => f.write_str("arp plen"),
            Self::ArpOperation => f.write_str("arp operation"),
            Self::ArpSaddrEther => f.write_str("arp saddr ether"),
            Self::ArpSaddrIp => f.write_str("arp saddr ip"),
            Self::IpSaddr => f.write_str("ip saddr"),
            Self::IpDaddr => f.write_str("ip daddr"),
            Self::Ip6Saddr => f.write_str("ip6 saddr"),
            Self::Ip6Daddr => f.write_str("ip6 daddr"),
            Self::ThSport => f.write_str("th sport"),
            Self::ThDport => f.write_str("th dport"),
            Self::Dport(protocol) => write!(f, "{} dport", protocol.as_str()),
            Self::Raw { offset, bits } => write!(f, "@nh,{offset},{bits}"),
            Self::CtState => f.write_str("ct state"),
            Self::CtStatus => f.write_str("ct status"),
            Self::CtDirection => f.write_str("ct direction"),
            Self::CtSaddr { reply, ipv6 } => write!(
                f,
                "ct {} {} saddr",
                if *reply { "reply" } else { "original" },
                family(*ipv6)
            ),
            Self::CtDaddr { ipv6 } => write!(f, "ct original {} daddr", family(*ipv6)),
            Self::CtProtoDst => f.write_str("ct original proto-dst"),
            Self::FibDaddrType => f.write_str("fib daddr type"),
        }
    }
}

/// What a key is compared with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Value {
    /// A number, written in decimal.
    Number(u32),
    /// A packet mark, written in hex.
    Mark(u32),
    /// `first` to `last`, both included; a single number when they're the same.
    Range(u16, u16),
    Address(IpAddr),
    /// A prefix; written with its length, even a full one.
    Network(IpNet),
    Ifname(Name),
    Mac(MacAddress),
    /// An IP protocol; ICMP is `ipv6-icmp` with `ipv6`.
    Protocol(Protocol, bool),
    /// IPv4 (`ip`) as an Ethernet or ARP protocol type.
    EtherIp,
    /// ARP as an Ethernet type.
    EtherArp,
    /// `ipv4` or `ipv6` as the family of a packet.
    NfProto(bool),
    CtState(CtState),
    /// A connection's original direction.
    Original,
    /// A connection's reply direction.
    Reply,
    /// The connection got destination NAT.
    Dnat,
    /// An address of the host itself.
    Local,
}

/// Connection tracking states rules check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CtState {
    New,
    Established,
    Related,
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(number) => write!(f, "{number}"),
            Self::Mark(mark) => write!(f, "{mark:#x}"),
            Self::Range(first, last) if first == last => write!(f, "{first}"),
            Self::Range(first, last) => write!(f, "{first}-{last}"),
            Self::Address(address) => write!(f, "{address}"),
            Self::Network(network) => write!(f, "{network}"),
            Self::Ifname(name) => write!(f, "{}", Quoted(name)),
            Self::Mac(mac) => write!(f, "{mac}"),
            Self::Protocol(Protocol::Icmp, true) => f.write_str("ipv6-icmp"),
            Self::Protocol(protocol, _) => f.write_str(protocol.as_str()),
            Self::EtherIp => f.write_str("ip"),
            Self::EtherArp => f.write_str("arp"),
            Self::NfProto(false) => f.write_str("ipv4"),
            Self::NfProto(true) => f.write_str("ipv6"),
            Self::CtState(CtState::New) => f.write_str("new"),
            Self::CtState(CtState::Established) => f.write_str("established"),
            Self::CtState(CtState::Related) => f.write_str("related"),
            Self::Original => f.write_str("original"),
            Self::Reply => f.write_str("reply"),
            Self::Dnat => f.write_str("dnat"),
            Self::Local => f.write_str("local"),
        }
    }
}

/// What a dynamic set's element of a packet counts before the packet passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stateful {
    /// More than this many connections are open.
    CtCountOver(u32),
    /// More than this many new packets per second, with a burst of as many.
    RateOver(u32),
}

/// A part of a rule: a match, or a statement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expr {
    /// `<key> <value>`, or `<key> != <value>`.
    Cmp {
        key: Key,
        equal: bool,
        value: Value,
    },
    /// `<key> & <mask> == <value>`.
    Masked {
        key: Key,
        mask: Value,
        value: Value,
    },
    /// The key, or concatenation of keys, is in the set (or with `negate`, isn't).
    Lookup {
        key: &'static [Key],
        set: Name,
        negate: bool,
    },
    /// The verdict a map has for the key.
    Vmap {
        key: &'static [Key],
        map: Name,
    },
    /// Add the key to a dynamic set, and match while its element counts no more than it may.
    AddToSet {
        key: &'static [Key],
        set: Name,
        stateful: Option<Stateful>,
    },
    /// Match at most `rate` packets per second (or with `over`, only those beyond), with an
    /// initial burst of `burst`.
    Limit {
        rate: u32,
        burst: Option<u32>,
        over: bool,
    },
    Log {
        prefix: Name,
        group: u16,
        snaplen: u16,
    },
    Verdict(Verdict),
    /// Answer with ICMP "administratively prohibited" (or for TCP, a reset).
    Reject {
        tcp_reset: bool,
    },
    Queue {
        num: u16,
        bypass: bool,
    },
    SetMark(u32),
}

impl Expr {
    pub const fn cmp(key: Key, value: Value) -> Self {
        Self::Cmp {
            key,
            equal: true,
            value,
        }
    }

    pub const fn not(key: Key, value: Value) -> Self {
        Self::Cmp {
            key,
            equal: false,
            value,
        }
    }

    pub fn lookup(key: &'static [Key], set: impl Into<Name>) -> Self {
        Self::Lookup {
            key,
            set: set.into(),
            negate: false,
        }
    }
}

/// Keys joined with ` . `.
struct Concat(&'static [Key]);

impl fmt::Display for Concat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, key) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(" . ")?;
            }
            write!(f, "{key}")?;
        }
        Ok(())
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cmp {
                key,
                equal: true,
                value,
            } => write!(f, "{key} {value}"),
            Self::Cmp {
                key,
                equal: false,
                value,
            } => write!(f, "{key} != {value}"),
            Self::Masked { key, mask, value } => write!(f, "{key} & {mask} == {value}"),
            Self::Lookup { key, set, negate } => write!(
                f,
                "{} {}@{set}",
                Concat(key),
                if *negate { "!= " } else { "" }
            ),
            Self::Vmap { key, map } => write!(f, "{} vmap @{map}", Concat(key)),
            Self::AddToSet { key, set, stateful } => {
                write!(f, "add @{set} {{ {}", Concat(key))?;
                match stateful {
                    Some(Stateful::CtCountOver(count)) => write!(f, " ct count over {count}")?,
                    Some(Stateful::RateOver(rate)) => {
                        write!(f, " limit rate over {rate}/second burst {rate} packets")?;
                    }
                    None => {}
                }
                f.write_str(" }")
            }
            Self::Limit { rate, burst, over } => {
                write!(
                    f,
                    "limit rate {}{rate}/second",
                    if *over { "over " } else { "" }
                )?;
                if let Some(burst) = burst {
                    write!(f, " burst {burst} packets")?;
                }
                Ok(())
            }
            Self::Log {
                prefix,
                group,
                snaplen,
            } => write!(f, "log prefix \"{prefix}\" group {group} snaplen {snaplen}"),
            Self::Verdict(verdict) => write!(f, "{verdict}"),
            Self::Reject { tcp_reset: false } => f.write_str("reject with icmpx admin-prohibited"),
            Self::Reject { tcp_reset: true } => f.write_str("reject with tcp reset"),
            Self::Queue { num, bypass } => {
                write!(f, "queue num {num}{}", if *bypass { " bypass" } else { "" })
            }
            Self::SetMark(mark) => write!(f, "meta mark set {mark:#x}"),
        }
    }
}

/// One command of an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    AddTable(Table),
    /// Delete a table; added first, so that it exists to delete.
    ResetTable(Table),
    /// Create a chain (a base chain with its hook) if it isn't there.
    AddChain(Chain),
    FlushChain(Chain),
    /// Empty and delete a chain.
    DeleteChain(Object),
    /// Create a set if it isn't there.
    AddSet(SetDecl),
    /// Add elements to a set that is there.
    AddElements(SetDecl, Vec<Element>),
    #[cfg_attr(not(test), allow(dead_code))]
    DeleteElements(SetDecl, Vec<Element>),
    FlushSet(SetDecl),
    DeleteSet(Object),
    AddRule(Chain, Vec<Expr>),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddTable(table) => write!(f, "add table {table}"),
            Self::ResetTable(table) => write!(f, "add table {table}\ndelete table {table}"),
            Self::AddChain(chain) => match chain.hook() {
                Some(hook) => write!(
                    f,
                    "add chain {chain} {{ type filter hook {hook} priority {HOOK_PRIORITY}; policy accept; }}"
                ),
                None => write!(f, "add chain {chain}"),
            },
            Self::FlushChain(chain) => write!(f, "flush chain {chain}"),
            Self::DeleteChain(chain) => write!(f, "flush chain {chain}\ndelete chain {chain}"),
            Self::AddSet(decl) => write!(f, "{}; }}", decl.head()),
            Self::AddElements(decl, elements) => {
                write!(f, "{}; elements = {{ ", decl.head())?;
                for (index, element) in elements.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}", element.display(decl))?;
                }
                f.write_str(" }; }")
            }
            Self::DeleteElements(decl, elements) => {
                write!(f, "delete element {} {} {{ ", decl.table, decl.name)?;
                for (index, element) in elements.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    // Deleted by key alone.
                    let key = Element {
                        verdict: None,
                        timeout: None,
                        ..*element
                    };
                    write!(f, "{}", key.display(decl))?;
                }
                f.write_str(" }")
            }
            Self::FlushSet(decl) => {
                write!(f, "flush {} {} {}", decl.kind(), decl.table, decl.name)
            }
            Self::DeleteSet(set) => write!(f, "delete set {set}"),
            Self::AddRule(chain, exprs) => {
                write!(f, "add rule {chain}")?;
                for expr in exprs {
                    write!(f, " {expr}")?;
                }
                Ok(())
            }
        }
    }
}

/// Takes the commands of a batch as they come, instead of keeping them.
pub type Sink = Box<dyn FnMut(Command)>;

/// The commands of an update, in order, applied as one transaction.
#[derive(Default)]
pub struct Batch {
    pub commands: Vec<Command>,
    /// Where commands go instead of `commands`, if anywhere.
    sink: Option<Sink>,
}

impl fmt::Debug for Batch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Batch")
            .field("commands", &self.commands)
            .field("sink", &self.sink.is_some())
            .finish()
    }
}

impl Batch {
    /// A batch whose commands go to `sink` as they come: one that is written out without
    /// keeping all of it.
    pub fn streaming(sink: Sink) -> Self {
        Self {
            commands: Vec::new(),
            sink: Some(sink),
        }
    }

    /// A batch of `commands`.
    #[cfg(test)]
    pub fn of(commands: Vec<Command>) -> Self {
        Self {
            commands,
            sink: None,
        }
    }

    pub fn push(&mut self, command: Command) {
        match &mut self.sink {
            Some(sink) => sink(command),
            None => self.commands.push(command),
        }
    }

    pub fn rule(&mut self, chain: Chain, exprs: Vec<Expr>) {
        self.push(Command::AddRule(chain, exprs));
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }
}

/// The script that does the same, one command per line.
impl fmt::Display for Batch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for command in &self.commands {
            writeln!(f, "{command}")?;
        }
        Ok(())
    }
}
