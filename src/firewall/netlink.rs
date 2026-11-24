//! Rule updates over nfnetlink: the commands of a [`Batch`] encoded as `nf_tables`
//! messages, sent as one batch, which the kernel applies as one transaction, as nft does
//! for a script.
//!
//! Rules are encoded as nft encodes them: the same expressions, registers, byte order and
//! dependencies (`ip saddr` in the inet table first checks that the packet is IPv4, `tcp
//! dport` that it is TCP), and sets get the same key types and user data, so that `nft
//! list ruleset` shows them as if nft had added them. The e2e tests compare what the kernel
//! holds after both, rule for rule (see `kernel_tests`).

use std::io;
use std::net::IpAddr;

use ipnet::IpNet;
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use nix::sys::socket::{setsockopt, sockopt};

use super::ruleset::{
    Batch, ChainName, Command, CtState, Element, Expr, HOOK_PRIORITY, Key, KeyType, SetDecl,
    Stateful, TABLE_NAME, Table, Value, Verdict,
};
use crate::model::Protocol;
use crate::nfnetlink::{NLM_F_REQUEST, NLMSG_ERROR, align4};

pub const NLM_F_ACK: u16 = 0x4;
const NLM_F_ACK_TLVS: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLMSG_DONE: u16 = 3;
const NLA_F_NESTED: u16 = 0x8000;
const NLMSGERR_ATTR_MSG: u16 = 1;

pub const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
pub const NFNL_MSG_BATCH_END: u16 = 0x11;
pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
const AF_UNSPEC: u8 = 0;

// Message types.
pub const NFT_MSG_NEWTABLE: u16 = 0;
pub const NFT_MSG_GETTABLE: u16 = 1;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_GETCHAIN: u16 = 4;
const NFT_MSG_DELCHAIN: u16 = 5;
const NFT_MSG_NEWRULE: u16 = 6;
#[cfg(test)]
pub const NFT_MSG_GETRULE: u16 = 7;
const NFT_MSG_DELRULE: u16 = 8;
const NFT_MSG_NEWSET: u16 = 9;
pub const NFT_MSG_GETSET: u16 = 10;
const NFT_MSG_DELSET: u16 = 11;
pub const NFT_MSG_NEWSETELEM: u16 = 12;
pub const NFT_MSG_GETSETELEM: u16 = 13;
pub const NFT_MSG_DELSETELEM: u16 = 14;

// Families.
pub const NFPROTO_INET: u8 = 1;
pub const NFPROTO_BRIDGE: u8 = 7;

// Attributes.
pub const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
pub const NFTA_CHAIN_TABLE: u16 = 1;
pub const NFTA_CHAIN_NAME: u16 = 3;
pub const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
pub const NFTA_RULE_TABLE: u16 = 1;
pub const NFTA_RULE_CHAIN: u16 = 2;
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;
pub const NFTA_SET_TABLE: u16 = 1;
pub const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;
const NFTA_SET_KEY_TYPE: u16 = 4;
const NFTA_SET_KEY_LEN: u16 = 5;
const NFTA_SET_DATA_TYPE: u16 = 6;
const NFTA_SET_DESC: u16 = 9;
const NFTA_SET_ID: u16 = 10;
const NFTA_SET_TIMEOUT: u16 = 11;
const NFTA_SET_USERDATA: u16 = 13;
const NFTA_SET_DESC_SIZE: u16 = 1;
pub const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
pub const NFTA_SET_ELEM_LIST_SET: u16 = 2;
pub const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
pub const NFTA_LIST_ELEM: u16 = 1;
pub const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_DATA: u16 = 2;
pub const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
pub const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_VERDICT_CHAIN: u16 = 2;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

const NFT_SET_MAP: u32 = 0x8;
const NFT_SET_TIMEOUT: u32 = 0x10;
const NFT_SET_EVAL: u32 = 0x20;
const NFT_DATA_VERDICT: u32 = 0xffff_ff00;

const NF_DROP: i32 = 0;
const NF_ACCEPT: i32 = 1;
const NFT_JUMP: i32 = -3;
const NFT_GOTO: i32 = -4;

/// Registers: the verdict, and the first general purpose one.
const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;
const NFT_REG32_00: u32 = 8;

/// Writes netlink messages and attributes into a buffer.
pub struct Writer<'a>(pub &'a mut Vec<u8>);

impl Writer<'_> {
    /// Start a message, returning where it starts; [`Self::finish`] writes its length.
    /// Batch markers carry the nftables subsystem in the resource id.
    pub fn begin(&mut self, kind: u16, flags: u16, sequence: u32, family: u8) -> usize {
        let out = &mut *self.0;
        let start = out.len();
        out.extend_from_slice(&0_u32.to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
        out.extend_from_slice(&sequence.to_ne_bytes());
        out.extend_from_slice(&0_u32.to_ne_bytes());
        out.extend_from_slice(&[family, 0]);
        let resource = if matches!(kind, NFNL_MSG_BATCH_BEGIN | NFNL_MSG_BATCH_END) {
            NFNL_SUBSYS_NFTABLES
        } else {
            0
        };
        out.extend_from_slice(&resource.to_be_bytes());
        start
    }

    /// Start an `nf_tables` message.
    pub fn message(&mut self, kind: u16, flags: u16, family: u8) -> usize {
        self.begin((NFNL_SUBSYS_NFTABLES << 8) | kind, flags, 0, family)
    }

    pub fn finish(&mut self, start: usize) {
        let length = u32::try_from(self.0.len() - start).unwrap_or(u32::MAX);
        if let Some(field) = self.0.get_mut(start..start + 4) {
            field.copy_from_slice(&length.to_ne_bytes());
        }
    }

    pub fn attribute(&mut self, kind: u16, value: &[u8]) {
        let out = &mut *self.0;
        let length = 4 + value.len();
        out.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value);
        out.resize(out.len() + align4(length) - length, 0);
    }

    pub fn u32(&mut self, kind: u16, value: u32) {
        self.attribute(kind, &value.to_be_bytes());
    }

    fn u16(&mut self, kind: u16, value: u16) {
        self.attribute(kind, &value.to_be_bytes());
    }

    fn u64(&mut self, kind: u16, value: u64) {
        self.attribute(kind, &value.to_be_bytes());
    }

    pub fn string(&mut self, kind: u16, value: &str) {
        let out = &mut *self.0;
        let length = 4 + value.len() + 1;
        out.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value.as_bytes());
        out.push(0);
        out.resize(out.len() + align4(length) - length, 0);
    }

    /// A string written with `Display`, without allocating.
    fn display(&mut self, kind: u16, value: impl std::fmt::Display) {
        use std::io::Write as _;
        let start = self.0.len();
        self.0.extend_from_slice(&[0; 4]);
        let _ = write!(self.0, "{value}");
        self.0.push(0);
        let length = self.0.len() - start;
        let mut header = [0; 4];
        for (slot, byte) in header.iter_mut().zip(
            u16::try_from(length)
                .unwrap_or(u16::MAX)
                .to_ne_bytes()
                .into_iter()
                .chain(kind.to_ne_bytes()),
        ) {
            *slot = byte;
        }
        if let Some(field) = self.0.get_mut(start..start + 4) {
            field.copy_from_slice(&header);
        }
        self.0.resize(start + align4(length), 0);
    }

    pub fn nest(&mut self, kind: u16) -> usize {
        let start = self.0.len();
        self.0.extend_from_slice(&0_u16.to_ne_bytes());
        self.0
            .extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
        start
    }

    pub fn end(&mut self, start: usize) {
        let length = u16::try_from(self.0.len() - start).unwrap_or(u16::MAX);
        if let Some(field) = self.0.get_mut(start..start + 2) {
            field.copy_from_slice(&length.to_ne_bytes());
        }
    }

    /// `NFTA_DATA_VALUE` in a nest of `kind`.
    fn data(&mut self, kind: u16, value: &[u8]) {
        let nest = self.nest(kind);
        self.attribute(NFTA_DATA_VALUE, value);
        self.end(nest);
    }

    fn verdict(&mut self, kind: u16, verdict: Verdict) {
        let data = self.nest(kind);
        let nest = self.nest(NFTA_DATA_VERDICT);
        let (code, chain) = match verdict {
            Verdict::Accept => (NF_ACCEPT, None),
            Verdict::Drop => (NF_DROP, None),
            Verdict::Jump(chain) => (NFT_JUMP, Some(chain)),
            Verdict::Goto(chain) => (NFT_GOTO, Some(chain)),
        };
        self.attribute(NFTA_VERDICT_CODE, &code.to_be_bytes());
        if let Some(chain) = chain {
            self.display(NFTA_VERDICT_CHAIN, ChainName(chain));
        }
        self.end(nest);
        self.end(data);
    }
}

pub const fn family(table: Table) -> u8 {
    match table {
        Table::Inet => NFPROTO_INET,
        Table::Bridge => NFPROTO_BRIDGE,
    }
}

/// The hook number of a base chain's hook, the same in both families.
fn hook_number(hook: &str) -> u32 {
    match hook {
        "prerouting" => 0,
        "input" => 1,
        "output" => 3,
        _ => 2,
    }
}

/// How many bytes of elements go in one message: an attribute's length is 16 bits.
const ELEMENTS_PER_MESSAGE: usize = 32 * 1024;

/// Encodes the commands of a batch into `nf_tables` messages between batch markers.
pub struct Encoder<'a> {
    out: Writer<'a>,
    /// Which command each message encodes, by index.
    pub origins: Vec<usize>,
    /// Numbers sets created in this batch.
    set_id: u32,
}

impl<'a> Encoder<'a> {
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        out.clear();
        let mut out = Writer(out);
        let begin = out.begin(NFNL_MSG_BATCH_BEGIN, 0, 0, AF_UNSPEC);
        out.finish(begin);
        Self {
            out,
            origins: Vec::new(),
            set_id: 0,
        }
    }

    /// Go on encoding a batch in `out`, the commands of which `new` and earlier encoders
    /// wrote, and whose sets are numbered up to `set_id`; see [`Self::set_id`]. Without
    /// the end marker: a batch written in parts ends with [`end_marker`].
    pub fn resume(out: &'a mut Vec<u8>, set_id: u32) -> Self {
        Self {
            out: Writer(out),
            origins: Vec::new(),
            set_id,
        }
    }

    /// The number of the last set created.
    pub const fn set_id(&self) -> u32 {
        self.set_id
    }

    /// Encode all commands of `batch`.
    pub fn batch(mut self, batch: &Batch) -> Vec<usize> {
        for (index, command) in batch.commands.iter().enumerate() {
            self.command(index, command);
        }
        self.end()
    }

    /// Close the batch; returns which command each message encodes.
    pub fn end(mut self) -> Vec<usize> {
        let end = self.out.begin(NFNL_MSG_BATCH_END, 0, 0, AF_UNSPEC);
        self.out.finish(end);
        self.origins
    }

    fn start(&mut self, origin: usize, kind: u16, flags: u16, table: Table) -> usize {
        self.origins.push(origin);
        self.out.message(kind, flags, family(table))
    }

    pub fn command(&mut self, origin: usize, command: &Command) {
        match command {
            Command::AddTable(table) => {
                let message = self.start(origin, NFT_MSG_NEWTABLE, NLM_F_CREATE, *table);
                self.out.string(NFTA_TABLE_NAME, TABLE_NAME);
                self.out.u32(NFTA_TABLE_FLAGS, 0);
                self.out.finish(message);
            }
            Command::ResetTable(table) => {
                self.command(origin, &Command::AddTable(*table));
                let message = self.start(origin, NFT_MSG_DELTABLE, 0, *table);
                self.out.string(NFTA_TABLE_NAME, TABLE_NAME);
                self.out.finish(message);
            }
            Command::AddChain(chain) => {
                let message = self.start(origin, NFT_MSG_NEWCHAIN, NLM_F_CREATE, chain.table());
                self.out.string(NFTA_CHAIN_TABLE, TABLE_NAME);
                self.out.display(NFTA_CHAIN_NAME, ChainName(*chain));
                if let Some(hook) = chain.hook() {
                    let nest = self.out.nest(NFTA_CHAIN_HOOK);
                    self.out.u32(NFTA_HOOK_HOOKNUM, hook_number(hook));
                    self.out
                        .attribute(NFTA_HOOK_PRIORITY, &HOOK_PRIORITY.to_be_bytes());
                    self.out.end(nest);
                    self.out
                        .attribute(NFTA_CHAIN_POLICY, &NF_ACCEPT.to_be_bytes());
                    self.out.string(NFTA_CHAIN_TYPE, "filter");
                }
                self.out.finish(message);
            }
            Command::FlushChain(chain) => {
                let message = self.start(origin, NFT_MSG_DELRULE, 0, chain.table());
                self.out.string(NFTA_RULE_TABLE, TABLE_NAME);
                self.out.display(NFTA_RULE_CHAIN, ChainName(*chain));
                self.out.finish(message);
            }
            Command::DeleteChain(chain) => {
                let message = self.start(origin, NFT_MSG_DELRULE, 0, chain.table);
                self.out.string(NFTA_RULE_TABLE, TABLE_NAME);
                self.out.string(NFTA_RULE_CHAIN, &chain.name);
                self.out.finish(message);
                let message = self.start(origin, NFT_MSG_DELCHAIN, 0, chain.table);
                self.out.string(NFTA_CHAIN_TABLE, TABLE_NAME);
                self.out.string(NFTA_CHAIN_NAME, &chain.name);
                self.out.finish(message);
            }
            Command::AddSet(decl) => self.add_set(origin, decl),
            Command::AddElements(decl, elements) => {
                self.elements(origin, NFT_MSG_NEWSETELEM, NLM_F_CREATE, decl, elements);
            }
            Command::DeleteElements(decl, elements) => {
                self.elements(origin, NFT_MSG_DELSETELEM, 0, decl, elements);
            }
            Command::FlushSet(decl) => {
                let message = self.start(origin, NFT_MSG_DELSETELEM, 0, decl.table);
                self.out.string(NFTA_SET_ELEM_LIST_TABLE, TABLE_NAME);
                self.out.string(NFTA_SET_ELEM_LIST_SET, &decl.name);
                self.out.finish(message);
            }
            Command::DeleteSet(set) => {
                let message = self.start(origin, NFT_MSG_DELSET, 0, set.table);
                self.out.string(NFTA_SET_TABLE, TABLE_NAME);
                self.out.string(NFTA_SET_NAME, &set.name);
                self.out.finish(message);
            }
            Command::AddRule(chain, exprs) => {
                let message = self.start(
                    origin,
                    NFT_MSG_NEWRULE,
                    NLM_F_CREATE | NLM_F_APPEND,
                    chain.table(),
                );
                self.out.string(NFTA_RULE_TABLE, TABLE_NAME);
                self.out.display(NFTA_RULE_CHAIN, ChainName(*chain));
                let nest = self.out.nest(NFTA_RULE_EXPRESSIONS);
                Rule::new(&mut self.out, chain.table()).exprs(exprs);
                self.out.end(nest);
                self.out.finish(message);
            }
        }
    }

    fn add_set(&mut self, origin: usize, decl: &SetDecl) {
        let message = self.start(origin, NFT_MSG_NEWSET, NLM_F_CREATE, decl.table);
        self.out.string(NFTA_SET_TABLE, TABLE_NAME);
        self.out.string(NFTA_SET_NAME, &decl.name);
        let flags = if decl.map { NFT_SET_MAP } else { 0 }
            | if decl.flags.timeout {
                NFT_SET_TIMEOUT
            } else {
                0
            }
            | if decl.flags.dynamic { NFT_SET_EVAL } else { 0 };
        if flags != 0 {
            self.out.u32(NFTA_SET_FLAGS, flags);
        }
        self.out.u32(NFTA_SET_KEY_TYPE, key_type(decl.key));
        self.out.u32(
            NFTA_SET_KEY_LEN,
            u32::try_from(key_len(decl.key)).unwrap_or(0),
        );
        if decl.map {
            self.out.u32(NFTA_SET_DATA_TYPE, NFT_DATA_VERDICT);
        }
        if let Some(timeout) = decl.timeout {
            self.out.u64(
                NFTA_SET_TIMEOUT,
                u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
            );
        }
        if let Some(size) = decl.size {
            let nest = self.out.nest(NFTA_SET_DESC);
            self.out.u32(NFTA_SET_DESC_SIZE, size);
            self.out.end(nest);
        }
        self.set_id = self.set_id.wrapping_add(1);
        self.out.u32(NFTA_SET_ID, self.set_id);
        self.out.attribute(NFTA_SET_USERDATA, &set_userdata(decl));
        self.out.finish(message);
    }

    fn elements(
        &mut self,
        origin: usize,
        kind: u16,
        flags: u16,
        decl: &SetDecl,
        elements: &[Element],
    ) {
        let mut elements = elements.iter().peekable();
        while elements.peek().is_some() {
            let message = self.start(origin, kind, flags, decl.table);
            self.out.string(NFTA_SET_ELEM_LIST_TABLE, TABLE_NAME);
            self.out.string(NFTA_SET_ELEM_LIST_SET, &decl.name);
            let list = self.out.nest(NFTA_SET_ELEM_LIST_ELEMENTS);
            while let Some(element) =
                elements.next_if(|_| self.out.0.len() - list < ELEMENTS_PER_MESSAGE)
            {
                let nest = self.out.nest(NFTA_LIST_ELEM);
                self.out.data(NFTA_SET_ELEM_KEY, element.key());
                if kind == NFT_MSG_NEWSETELEM {
                    if let Some(verdict) = element.verdict {
                        self.out.verdict(NFTA_SET_ELEM_DATA, verdict);
                    }
                    if let Some(timeout) = element.timeout {
                        self.out.u64(
                            NFTA_SET_ELEM_TIMEOUT,
                            super::ruleset::timeout_seconds(timeout) * 1000,
                        );
                    }
                }
                self.out.end(nest);
            }
            self.out.end(list);
            self.out.finish(message);
        }
    }
}

/// The beginning (or with `end`, the end) of a batch.
pub fn batch_marker(out: &mut Vec<u8>, end: bool) {
    let mut out = Writer(out);
    let kind = if end {
        NFNL_MSG_BATCH_END
    } else {
        NFNL_MSG_BATCH_BEGIN
    };
    let marker = out.begin(kind, 0, 0, AF_UNSPEC);
    out.finish(marker);
}

/// The type of a key, as nft numbers its data types; a concatenation's combines those of its
/// parts, 6 bits each.
fn key_type(key: &[KeyType]) -> u32 {
    key.iter().fold(0, |id, part| {
        id << 6
            | match part {
                KeyType::Ipv4 => 7,
                KeyType::Ipv6 => 8,
                KeyType::Ether => 9,
                KeyType::EtherType => 10,
                KeyType::InetProto => 12,
                KeyType::InetService => 13,
                KeyType::Ifname => 41,
            }
    })
}

/// Bytes of a key: a concatenation's parts are each padded to 4 bytes.
fn key_len(key: &[KeyType]) -> usize {
    if let [single] = key {
        single.len()
    } else {
        key.iter().map(|part| part.len().next_multiple_of(4)).sum()
    }
}

/// What nft keeps with a set, for its listing: the byte order of the key (and of a map's
/// data), and how to show them.
fn set_userdata(decl: &SetDecl) -> Vec<u8> {
    const KEY_BYTEORDER: u8 = 0;
    const DATA_BYTEORDER: u8 = 1;
    const KEY_TYPEOF: u8 = 3;
    const DATA_TYPEOF: u8 = 4;
    const DATA_INTERVAL: u8 = 6;
    const SINGLE: &[u8] = &[0, 4, 4, 0, 0, 0, 1, 0];
    const CONCATENATED: &[u8] = &[0, 4, 13, 0, 0, 0, 1, 10, 0, 0, 0, 4, 4, 0, 0, 0, 1, 0];
    let mut out = Vec::with_capacity(48);
    let mut put = |kind: u8, value: &[u8]| {
        out.push(kind);
        out.push(u8::try_from(value.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(value);
    };
    let byte_order: u32 = match decl.key {
        [KeyType::Ifname] => 1,
        [_] => 2,
        _ => 0,
    };
    put(KEY_BYTEORDER, &byte_order.to_ne_bytes());
    if decl.map {
        put(DATA_BYTEORDER, &0_u32.to_ne_bytes());
    }
    put(
        KEY_TYPEOF,
        if decl.key.len() > 1 {
            CONCATENATED
        } else {
            SINGLE
        },
    );
    if decl.map {
        put(DATA_TYPEOF, SINGLE);
        put(DATA_INTERVAL, &0_u32.to_ne_bytes());
    }
    out
}

/// What a rule has established about the packet so far, so that dependencies aren't
/// matched twice.
#[derive(Default)]
struct Context {
    /// The network protocol: IPv4, IPv6 or ARP, by its Ethernet type.
    network: Option<u16>,
    /// The transport protocol.
    transport: Option<u8>,
    /// The input interface is Ethernet.
    ethernet: bool,
}

const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IPV6: u16 = 0x86dd;

/// Where a key comes from.
enum Source {
    Meta(u32),
    Payload { base: u32, offset: u32 },
    Ct { key: u32, direction: Option<u8> },
    Fib,
}

/// How a key is loaded, and its length in bytes.
fn source(key: Key) -> (Source, usize) {
    const LINK: u32 = 0;
    const NETWORK: u32 = 1;
    const TRANSPORT: u32 = 2;
    let payload = |base, offset| Source::Payload { base, offset };
    let ct = |key, direction| Source::Ct { key, direction };
    match key {
        Key::Length => (Source::Meta(0), 4),
        Key::Mark => (Source::Meta(3), 4),
        Key::Iifname => (Source::Meta(6), 16),
        Key::Oifname => (Source::Meta(7), 16),
        Key::Nfproto => (Source::Meta(15), 1),
        Key::L4proto => (Source::Meta(16), 1),
        Key::Ibrname => (Source::Meta(17), 16),
        Key::EtherDaddr => (payload(LINK, 0), 6),
        Key::EtherSaddr => (payload(LINK, 6), 6),
        Key::EtherType => (payload(LINK, 12), 2),
        Key::ArpHtype => (payload(NETWORK, 0), 2),
        Key::ArpPtype => (payload(NETWORK, 2), 2),
        Key::ArpHlen => (payload(NETWORK, 4), 1),
        Key::ArpPlen => (payload(NETWORK, 5), 1),
        Key::ArpOperation => (payload(NETWORK, 6), 2),
        Key::ArpSaddrEther => (payload(NETWORK, 8), 6),
        Key::ArpSaddrIp => (payload(NETWORK, 14), 4),
        Key::IpSaddr => (payload(NETWORK, 12), 4),
        Key::IpDaddr => (payload(NETWORK, 16), 4),
        Key::Ip6Saddr => (payload(NETWORK, 8), 16),
        Key::Ip6Daddr => (payload(NETWORK, 24), 16),
        Key::ThSport => (payload(TRANSPORT, 0), 2),
        Key::ThDport | Key::Dport(_) => (payload(TRANSPORT, 2), 2),
        Key::Raw { offset, bits } => (
            payload(NETWORK, u32::from(offset / 8)),
            usize::from(bits / 8),
        ),
        Key::CtState => (ct(0, None), 4),
        Key::CtDirection => (ct(1, None), 1),
        Key::CtStatus => (ct(2, None), 4),
        Key::CtMark => (ct(3, None), 4),
        Key::CtProtoDst => (ct(12, Some(0)), 2),
        Key::CtSaddr { reply, ipv6 } => (
            ct(if ipv6 { 21 } else { 19 }, Some(u8::from(reply))),
            if ipv6 { 16 } else { 4 },
        ),
        Key::CtDaddr { ipv6 } => (
            ct(if ipv6 { 22 } else { 20 }, Some(0)),
            if ipv6 { 16 } else { 4 },
        ),
        Key::FibDaddrType => (Source::Fib, 4),
    }
}

/// The network protocol a key needs the packet to have, by Ethernet type.
const fn network(key: Key) -> Option<u16> {
    match key {
        Key::IpSaddr | Key::IpDaddr => Some(ETH_P_IP),
        Key::Ip6Saddr | Key::Ip6Daddr => Some(ETH_P_IPV6),
        Key::ArpHtype
        | Key::ArpPtype
        | Key::ArpHlen
        | Key::ArpPlen
        | Key::ArpOperation
        | Key::ArpSaddrEther
        | Key::ArpSaddrIp => Some(ETH_P_ARP),
        _ => None,
    }
}

/// A value of at most 16 bytes, as rules compare it.
#[derive(Clone, Copy)]
struct Data {
    bytes: [u8; 16],
    len: usize,
}

impl Data {
    fn of(value: &[u8]) -> Self {
        let mut bytes = [0; 16];
        let len = value.len().min(16);
        for (slot, byte) in bytes.iter_mut().zip(value) {
            *slot = *byte;
        }
        Self { bytes, len }
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }

    /// A number of `len` bytes: in network byte order for header fields, or in the host's for
    /// metadata the kernel keeps as such.
    fn number(value: u64, len: usize, host: bool) -> Self {
        let len = len.min(16);
        let mut bytes = [0; 16];
        if host {
            for (slot, byte) in bytes.iter_mut().zip(value.to_le_bytes()).take(len) {
                *slot = byte;
            }
        } else {
            // The low bytes, at the end.
            for (index, byte) in value.to_le_bytes().into_iter().enumerate().take(len) {
                if let Some(slot) = bytes.get_mut(len - 1 - index) {
                    *slot = byte;
                }
            }
        }
        Self { bytes, len }
    }
}

/// Whether a key holds a number in the host's byte order.
const fn host_order(key: Key) -> bool {
    matches!(
        key,
        Key::Length | Key::Mark | Key::CtState | Key::CtStatus | Key::CtMark | Key::FibDaddrType
    ) && cfg!(target_endian = "little")
}

fn address(address: IpAddr) -> Data {
    match address {
        IpAddr::V4(address) => Data::of(&address.octets()),
        IpAddr::V6(address) => Data::of(&address.octets()),
    }
}

const CMP_EQ: u32 = 0;
const CMP_NEQ: u32 = 1;

/// Encodes the expressions of one rule.
struct Rule<'w, 'a> {
    out: &'w mut Writer<'a>,
    table: Table,
    context: Context,
}

impl<'w, 'a> Rule<'w, 'a> {
    fn new(out: &'w mut Writer<'a>, table: Table) -> Self {
        Self {
            out,
            table,
            context: Context::default(),
        }
    }

    fn exprs(&mut self, exprs: &[Expr]) {
        for expr in exprs {
            self.expr(expr);
        }
    }

    /// Start an expression; returns the nests to end with [`Self::close`].
    fn open(&mut self, name: &str) -> (usize, usize) {
        let element = self.out.nest(NFTA_LIST_ELEM);
        self.out.string(NFTA_EXPR_NAME, name);
        let data = self.out.nest(NFTA_EXPR_DATA);
        (element, data)
    }

    fn close(&mut self, (element, data): (usize, usize)) {
        self.out.end(data);
        self.out.end(element);
    }

    fn meta(&mut self, key: u32, register: u32) {
        let expr = self.open("meta");
        self.out.u32(2, key);
        self.out.u32(1, register);
        self.close(expr);
    }

    fn payload(&mut self, base: u32, offset: u32, len: usize, register: u32) {
        let expr = self.open("payload");
        self.out.u32(1, register);
        self.out.u32(2, base);
        self.out.u32(3, offset);
        self.out.u32(4, u32::try_from(len).unwrap_or(0));
        self.close(expr);
    }

    fn cmp(&mut self, op: u32, data: &[u8]) {
        let expr = self.open("cmp");
        self.out.u32(1, NFT_REG_1);
        self.out.u32(2, op);
        self.out.data(3, data);
        self.close(expr);
    }

    fn bitwise(&mut self, mask: &[u8]) {
        let zeros = [0; 16];
        self.bitwise_xor(mask, zeros.get(..mask.len()).unwrap_or(&zeros));
    }

    /// `reg 1 = (reg 1 & mask) ^ xor`.
    fn bitwise_xor(&mut self, mask: &[u8], xor: &[u8]) {
        let expr = self.open("bitwise");
        self.out.u32(1, NFT_REG_1);
        self.out.u32(2, NFT_REG_1);
        self.out.u32(3, u32::try_from(mask.len()).unwrap_or(0));
        self.out.data(4, mask);
        self.out.data(5, xor);
        self.close(expr);
    }

    /// Load `key` into `register`, `len` bytes of it where a payload can be shortened.
    fn load(&mut self, key: Key, register: u32, len: Option<usize>) {
        let (source, full) = source(key);
        match source {
            Source::Meta(meta) => self.meta(meta, register),
            Source::Payload { base, offset } => {
                self.payload(base, offset, len.unwrap_or(full), register);
            }
            Source::Ct { key, direction } => {
                let expr = self.open("ct");
                self.out.u32(1, register);
                self.out.u32(2, key);
                if let Some(direction) = direction {
                    self.out.attribute(3, &[direction]);
                }
                self.close(expr);
            }
            Source::Fib => {
                const ADDRESS_TYPE: u32 = 3;
                const DESTINATION: u32 = 2;
                let expr = self.open("fib");
                self.out.u32(1, register);
                self.out.u32(2, ADDRESS_TYPE);
                self.out.u32(3, DESTINATION);
                self.close(expr);
            }
        }
    }

    /// Match what `keys` need of the packet before them, unless the rule did already.
    fn dependencies(&mut self, keys: &[Key]) {
        for &key in keys {
            if let Some(protocol) = network(key)
                && self.context.network != Some(protocol)
            {
                match (self.table, protocol) {
                    (Table::Inet, ETH_P_IPV6) => {
                        self.meta(15, NFT_REG_1);
                        self.cmp(CMP_EQ, &[10]);
                    }
                    (Table::Inet, _) => {
                        self.meta(15, NFT_REG_1);
                        self.cmp(CMP_EQ, &[2]);
                    }
                    (Table::Bridge, ETH_P_ARP) => {
                        self.payload(0, 12, 2, NFT_REG_1);
                        self.cmp(CMP_EQ, &protocol.to_be_bytes());
                    }
                    (Table::Bridge, _) => {
                        self.meta(1, NFT_REG_1);
                        self.cmp(CMP_EQ, &protocol.to_be_bytes());
                    }
                }
                self.context.network = Some(protocol);
            }
            if let Key::Dport(protocol) = key
                && self.context.transport != Some(protocol.number())
            {
                self.meta(16, NFT_REG_1);
                self.cmp(CMP_EQ, &[protocol.number()]);
                self.context.transport = Some(protocol.number());
            }
            if matches!(key, Key::EtherSaddr | Key::EtherDaddr | Key::EtherType)
                && self.table == Table::Inet
                && !self.context.ethernet
            {
                const ARPHRD_ETHER: u16 = 1;
                self.meta(8, NFT_REG_1);
                self.cmp(CMP_EQ, &ARPHRD_ETHER.to_ne_bytes());
                self.context.ethernet = true;
            }
        }
    }

    /// Load a key, or a concatenation of keys, from the first register on, as nft does:
    /// each part in the next free 32-bit register.
    fn load_concat(&mut self, keys: &[Key]) {
        self.dependencies(keys);
        let mut word = 0_u32;
        for &key in keys {
            let register = if word.is_multiple_of(4) {
                NFT_REG_1 + word / 4
            } else {
                NFT_REG32_00 + word
            };
            self.load(key, register, None);
            word += u32::try_from(source(key).1.div_ceil(4)).unwrap_or(0);
        }
    }

    fn expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Cmp { key, equal, value } => self.compare(*key, *equal, value),
            Expr::Masked {
                key,
                mask,
                equal,
                value,
            } => {
                self.dependencies(&[*key]);
                self.load(*key, NFT_REG_1, None);
                self.bitwise(value_data(*key, mask).as_slice());
                let op = if *equal { CMP_EQ } else { CMP_NEQ };
                self.cmp(op, value_data(*key, value).as_slice());
            }
            Expr::SetCtMark { keep, set } => {
                // As nft has it: bits that are set are kept out of the mask.
                self.load(Key::CtMark, NFT_REG_1, None);
                let host = host_order(Key::CtMark);
                self.bitwise_xor(
                    Data::number(u64::from(keep & !set), 4, host).as_slice(),
                    Data::number(u64::from(*set), 4, host).as_slice(),
                );
                let expr = self.open("ct");
                self.out.u32(2, 3);
                self.out.u32(4, NFT_REG_1);
                self.close(expr);
            }
            Expr::Lookup { key, set, negate } => {
                self.load_concat(key);
                let expr = self.open("lookup");
                self.out.string(1, set);
                self.out.u32(2, NFT_REG_1);
                self.out.u32(5, u32::from(*negate));
                self.close(expr);
            }
            Expr::Vmap { key, map } => {
                self.load_concat(key);
                let expr = self.open("lookup");
                self.out.string(1, map);
                self.out.u32(2, NFT_REG_1);
                self.out.u32(3, NFT_REG_VERDICT);
                self.out.u32(5, 0);
                self.close(expr);
            }
            Expr::AddToSet { key, set, stateful } => self.add_to_set(key, set, *stateful),
            Expr::Limit { rate, burst, over } => {
                let expr = self.open("limit");
                self.limit(*rate, burst.unwrap_or(5), *over);
                self.close(expr);
            }
            Expr::Log {
                prefix,
                group,
                snaplen,
            } => {
                let expr = self.open("log");
                self.out.u16(1, *group);
                self.out.string(2, prefix);
                self.out.u32(3, u32::from(*snaplen));
                self.close(expr);
            }
            Expr::Verdict(verdict) => {
                let expr = self.open("immediate");
                self.out.u32(1, NFT_REG_VERDICT);
                self.out.verdict(2, *verdict);
                self.close(expr);
            }
            Expr::Reject { tcp_reset } => {
                let expr = self.open("reject");
                if *tcp_reset {
                    self.out.u32(1, 1);
                } else {
                    // ICMPX: unreachable, administratively prohibited.
                    self.out.u32(1, 2);
                    self.out.attribute(2, &[3]);
                }
                self.close(expr);
            }
            Expr::Queue { num, bypass } => {
                let expr = self.open("queue");
                self.out.u16(1, *num);
                self.out.u16(2, 1);
                self.out.u16(3, u16::from(*bypass));
                self.close(expr);
            }
            Expr::SetMark(mark) => {
                let expr = self.open("immediate");
                self.out.u32(1, NFT_REG_1);
                let data = Data::number(u64::from(*mark), 4, host_order(Key::Mark));
                self.out.data(2, data.as_slice());
                self.close(expr);
                let expr = self.open("meta");
                self.out.u32(2, 3);
                self.out.u32(3, NFT_REG_1);
                self.close(expr);
            }
        }
    }

    /// Add the key to a dynamic set, with what its element counts.
    fn add_to_set(&mut self, key: &[Key], set: &str, stateful: Option<Stateful>) {
        self.load_concat(key);
        let expr = self.open("dynset");
        self.out.string(1, set);
        // Add.
        self.out.u32(3, 0);
        self.out.u32(4, NFT_REG_1);
        if let Some(stateful) = stateful {
            let nest = self.out.nest(7);
            self.out.string(
                NFTA_EXPR_NAME,
                match stateful {
                    Stateful::CtCountOver(_) => "connlimit",
                    Stateful::RateOver(_) => "limit",
                },
            );
            let data = self.out.nest(NFTA_EXPR_DATA);
            match stateful {
                Stateful::CtCountOver(count) => {
                    self.out.u32(1, count);
                    // Over.
                    self.out.u32(2, 1);
                }
                Stateful::RateOver(rate) => self.limit(rate, rate, true),
            }
            self.out.end(data);
            self.out.end(nest);
        }
        self.close(expr);
    }

    fn limit(&mut self, rate: u32, burst: u32, over: bool) {
        self.out.u64(1, u64::from(rate));
        // Per second.
        self.out.u64(2, 1);
        self.out.u32(3, burst);
        // Packets.
        self.out.u32(4, 0);
        self.out.u32(5, u32::from(over));
    }

    fn compare(&mut self, key: Key, equal: bool, value: &Value) {
        let op = if equal { CMP_EQ } else { CMP_NEQ };
        self.dependencies(&[key]);
        match value {
            Value::CtState(_) => {
                // A bit of the state: set, or with `!=` not.
                self.load(key, NFT_REG_1, None);
                self.bitwise(value_data(key, value).as_slice());
                self.cmp(if equal { CMP_NEQ } else { CMP_EQ }, &[0; 4]);
            }
            Value::Range(first, last) if first != last => {
                self.load(key, NFT_REG_1, None);
                let expr = self.open("range");
                self.out.u32(1, NFT_REG_1);
                self.out.u32(2, op);
                self.out.data(3, &first.to_be_bytes());
                self.out.data(4, &last.to_be_bytes());
                self.close(expr);
            }
            Value::Network(network) if network.prefix_len() < network.max_prefix_len() => {
                self.prefix(key, op, network);
            }
            _ => {
                self.load(key, NFT_REG_1, None);
                self.cmp(op, value_data(key, value).as_slice());
            }
        }
        if equal {
            match (key, value) {
                (Key::Nfproto, Value::NfProto(ipv6)) => {
                    self.context.network = Some(if *ipv6 { ETH_P_IPV6 } else { ETH_P_IP });
                }
                (Key::EtherType, Value::EtherIp) => self.context.network = Some(ETH_P_IP),
                (Key::EtherType, Value::EtherArp) => self.context.network = Some(ETH_P_ARP),
                (Key::L4proto, Value::Protocol(protocol, ipv6)) => {
                    self.context.transport = Some(protocol_number(*protocol, *ipv6));
                }
                _ => {}
            }
        }
    }

    /// A prefix: a whole number of bytes is compared alone (and only those loaded from the
    /// packet); others are masked first.
    fn prefix(&mut self, key: Key, op: u32, network: &IpNet) {
        let bits = usize::from(network.prefix_len());
        let full = address(network.network());
        if bits % 8 == 0 {
            let bytes = bits / 8;
            let shortened = matches!(source(key).0, Source::Payload { .. }).then_some(bytes);
            self.load(key, NFT_REG_1, shortened);
            self.cmp(op, full.as_slice().get(..bytes).unwrap_or_default());
        } else {
            self.load(key, NFT_REG_1, None);
            self.bitwise(address(network.netmask()).as_slice());
            self.cmp(op, full.as_slice());
        }
    }
}

const fn protocol_number(protocol: Protocol, ipv6: bool) -> u8 {
    match protocol {
        Protocol::Icmp if ipv6 => 58,
        protocol => protocol.number(),
    }
}

/// The bytes `value` is for `key`.
fn value_data(key: Key, value: &Value) -> Data {
    let len = source(key).1;
    let number = |value: u64| Data::number(value, len, host_order(key));
    match value {
        Value::Number(number_) => number(u64::from(*number_)),
        Value::Mark(mark) => number(u64::from(*mark)),
        Value::Range(first, _) => number(u64::from(*first)),
        Value::Address(value) => address(*value),
        Value::Network(network) => address(network.network()),
        Value::Ifname(name) => {
            let mut bytes = [0; 16];
            for (slot, byte) in bytes.iter_mut().zip(name.as_bytes().iter().take(15)) {
                *slot = *byte;
            }
            Data::of(&bytes)
        }
        Value::Mac(mac) => Data::of(&mac.octets()),
        Value::Protocol(protocol, ipv6) => Data::of(&[protocol_number(*protocol, *ipv6)]),
        Value::EtherIp => Data::of(&ETH_P_IP.to_be_bytes()),
        Value::EtherArp => Data::of(&ETH_P_ARP.to_be_bytes()),
        Value::NfProto(ipv6) => Data::of(&[if *ipv6 { 10 } else { 2 }]),
        Value::CtState(state) => number(match state {
            CtState::Established => 2,
            CtState::Related => 4,
            CtState::New => 8,
        }),
        Value::Original => Data::of(&[0]),
        Value::Reply => Data::of(&[1]),
        // IPS_DST_NAT.
        Value::Dnat => number(0x20),
        // RTN_LOCAL.
        Value::Local => number(2),
    }
}

/// Why the kernel refused a batch: the first message it failed, and what it said.
#[derive(Debug)]
pub struct Refusal {
    /// The message, numbered from 0 after the batch begins; `None` for the batch itself.
    pub message: Option<usize>,
    pub error: io::Error,
    /// The kernel's explanation (extended acknowledgement), if any.
    pub reason: Option<String>,
}

/// A netlink socket for `nf_tables` batches and listings, with buffers reused from one to the
/// next.
pub struct NftSocket {
    socket: Socket,
    sequence: u32,
    response: Vec<u8>,
    send_buffer: usize,
}

/// Room for answers: dumps come in parts of at most 32 KiB.
const RESPONSE_BUFFER: usize = 1 << 16;

impl NftSocket {
    pub fn open() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        // Errors name what was wrong, and don't repeat the message they are about.
        let _ = socket.set_ext_ack(true);
        let _ = socket.set_cap_ack(true);
        Ok(Self {
            socket,
            sequence: 0,
            response: Vec::with_capacity(RESPONSE_BUFFER),
            send_buffer: 0,
        })
    }

    /// Send the batch in `batch` (as [`Encoder`] wrote it) and wait for the kernel's answer.
    /// The kernel applies all of its messages, or none.
    pub fn send_batch(&mut self, batch: &mut [u8]) -> Result<(), Refusal> {
        let refusal = |error: io::Error| Refusal {
            message: None,
            error,
            reason: None,
        };
        // Number the messages, and ask for an acknowledgement of the last one before the
        // end marker: errors of the others come before it.
        let begin = self.sequence.wrapping_add(1);
        let mut sequence = begin;
        let mut offsets = Vec::new();
        let mut at = 0;
        while let Some(header) = batch.get_mut(at..at + 16) {
            let length = header
                .get(..4)
                .and_then(|length| length.try_into().ok())
                .map_or(0, u32::from_ne_bytes) as usize;
            if length < 16 {
                return Err(refusal(io::Error::from(io::ErrorKind::InvalidData)));
            }
            if let Some(field) = header.get_mut(8..12) {
                field.copy_from_slice(&sequence.to_ne_bytes());
            }
            offsets.push(at);
            sequence = sequence.wrapping_add(1);
            at += align4(length);
        }
        self.sequence = sequence;
        // The batch markers, and nothing between them.
        if offsets.len() <= 2 {
            return Ok(());
        }
        let last = begin.wrapping_add(u32::try_from(offsets.len() - 2).unwrap_or(0));
        if let Some(&offset) = offsets.get(offsets.len() - 2)
            && let Some(flags) = batch.get_mut(offset + 6..offset + 8)
        {
            let value = u16::from_ne_bytes(flags.try_into().unwrap_or_default()) | NLM_F_ACK;
            flags.copy_from_slice(&value.to_ne_bytes());
        }
        self.reserve(batch.len());
        self.socket.send(batch, 0).map_err(refusal)?;
        let mut failure: Option<Refusal> = None;
        loop {
            self.response.clear();
            self.socket.recv(&mut self.response, 0).map_err(refusal)?;
            for message in parse(&self.response) {
                if message.kind != NLMSG_ERROR {
                    continue;
                }
                let offset = message.sequence.wrapping_sub(begin);
                if offset > last.wrapping_sub(begin) {
                    continue;
                }
                let (code, reason) = error(message.flags, message.body);
                if code != 0 && failure.is_none() {
                    failure = Some(Refusal {
                        message: (offset > 0).then(|| offset as usize - 1),
                        error: io::Error::from_raw_os_error(-code),
                        reason,
                    });
                }
                // The batch itself failed, or the last message's answer: nothing follows.
                if offset == 0 && code != 0 || message.sequence == last {
                    return failure.map_or(Ok(()), Err);
                }
            }
        }
    }

    /// Make the send buffer hold `length` bytes: a batch is one message, and the kernel
    /// refuses messages larger than the buffer.
    fn reserve(&mut self, length: usize) {
        if length <= self.send_buffer {
            return;
        }
        let size = length.next_power_of_two().max(1 << 18);
        if setsockopt(&self.socket, sockopt::SndBufForce, &size).is_err() {
            let _ = setsockopt(&self.socket, sockopt::SndBuf, &size);
        }
        self.send_buffer = size;
    }

    /// Dump the objects of `kind` (`NFT_MSG_GET...`) of `family`, calling `each` with the
    /// attributes of each. `attributes` narrow it down, such as to a set's elements. Starts
    /// over when the ruleset changed while it was dumped.
    pub fn dump(
        &mut self,
        kind: u16,
        family: u8,
        attributes: impl Fn(&mut Writer<'_>),
        mut each: impl FnMut(&[u8]),
    ) -> io::Result<()> {
        /// How a part of a dump ended.
        enum Next {
            Read,
            Done,
            Failed(i32),
        }
        let mut request = Vec::with_capacity(64);
        let mut found: Vec<Vec<u8>> = Vec::new();
        for _ in 0..10 {
            self.sequence = self.sequence.wrapping_add(1);
            request.clear();
            let mut out = Writer(&mut request);
            let message = out.begin(
                (NFNL_SUBSYS_NFTABLES << 8) | kind,
                NLM_F_DUMP | NLM_F_ACK,
                self.sequence,
                family,
            );
            attributes(&mut out);
            out.finish(message);
            self.socket.send(&request, 0)?;
            found.clear();
            let mut interrupted = false;
            loop {
                self.response.clear();
                self.socket.recv(&mut self.response, 0)?;
                let mut next = Next::Read;
                for message in parse(&self.response) {
                    if message.sequence != self.sequence {
                        continue;
                    }
                    interrupted |= message.flags & NLM_F_DUMP_INTR != 0;
                    match message.kind {
                        NLMSG_DONE => next = Next::Done,
                        NLMSG_ERROR => {
                            let (code, _) = error(message.flags, message.body);
                            next = if code == 0 {
                                Next::Done
                            } else {
                                Next::Failed(code)
                            };
                        }
                        _ if interrupted => {}
                        _ => found.push(message.body.get(4..).unwrap_or_default().to_vec()),
                    }
                }
                match next {
                    Next::Read => {}
                    Next::Done if interrupted => break,
                    Next::Done => {
                        for object in &found {
                            each(object);
                        }
                        return Ok(());
                    }
                    Next::Failed(code) => return Err(io::Error::from_raw_os_error(-code)),
                }
            }
        }
        Err(io::Error::from(io::ErrorKind::Interrupted))
    }
}

/// The value of a string attribute, without its terminating NUL.
pub fn string_attribute(attributes: &[u8], kind: u16) -> Option<&str> {
    crate::nfnetlink::attributes(attributes)
        .find(|(found, _)| *found == kind)
        .and_then(|(_, value)| std::str::from_utf8(value.strip_suffix(&[0]).unwrap_or(value)).ok())
}

pub fn has_attribute(attributes: &[u8], kind: u16) -> bool {
    crate::nfnetlink::attributes(attributes).any(|(found, _)| found == kind)
}

struct Message<'a> {
    kind: u16,
    flags: u16,
    sequence: u32,
    body: &'a [u8],
}

fn parse(mut buffer: &[u8]) -> impl Iterator<Item = Message<'_>> {
    std::iter::from_fn(move || {
        let header = buffer.get(..16)?;
        let length = u32::from_ne_bytes(header.get(..4)?.try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(header.get(4..6)?.try_into().ok()?);
        let flags = u16::from_ne_bytes(header.get(6..8)?.try_into().ok()?);
        let sequence = u32::from_ne_bytes(header.get(8..12)?.try_into().ok()?);
        let body = buffer.get(16..length)?;
        buffer = buffer.get(align4(length)..).unwrap_or_default();
        Some(Message {
            kind,
            flags,
            sequence,
            body,
        })
    })
}

/// The error code of an `NLMSG_ERROR` message (0 for an acknowledgement), and the kernel's
/// explanation, if any.
fn error(flags: u16, body: &[u8]) -> (i32, Option<String>) {
    let code = body
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(-71, i32::from_ne_bytes);
    let mut reason = None;
    if flags & NLM_F_ACK_TLVS != 0 {
        // After the code, the header of the message it is about (without its payload, see
        // `NETLINK_CAP_ACK`).
        let attributes = body.get(4 + 16..).unwrap_or_default();
        for (kind, value) in crate::nfnetlink::attributes(attributes) {
            if kind == NLMSGERR_ATTR_MSG {
                let text = value.strip_suffix(&[0]).unwrap_or(value);
                reason = Some(String::from_utf8_lossy(text).into_owned());
            }
        }
    }
    (code, reason)
}

#[cfg(test)]
pub mod tests;
