//! Checks the names connections through `host:` rules ask for.
//!
//! A `host:` rule allows the addresses its hostname resolves to. Many sites share an
//! address (a CDN, shared hosting, a reverse proxy), and the server picks the site by the
//! name the client sends: the TLS server name (SNI), or the HTTP Host. So a connection
//! through a `host:` rule that names a server is only allowed when the name is one of the
//! container's `host:` names (for that port) whose addresses include the destination.
//! Connections that don't name a server (TLS without a server name, other protocols, UDP
//! other than QUIC) are allowed by address, unless names are checked strictly.
//!
//! The rules hand the first packet of such a connection, and every packet after it, both
//! ways, to this queue (see `render_name_check`), until the check is over:
//!
//! - TCP: the handshake passes. The client's first bytes are held until they show what the
//!   connection is: a TLS `ClientHello` or an HTTP/1 request (after a Postgres request for
//!   TLS, if any), however many segments it spans, or something else. Nothing of it
//!   reaches the server before its name is checked.
//! - TLS: once allowed, the connection stays checked until the server has acknowledged the
//!   whole `ClientHello`: until then the client could resend those bytes changed, and a
//!   server that never got the first copy (one sent to expire on the way, or with a bad
//!   checksum) would take the second. Resent bytes must be the same as those checked. Then
//!   the connection leaves the queue, and its packets pass in the kernel like any other.
//! - Plain HTTP names a server in every request, so the client's packets with data keep
//!   coming here for as long as the connection is tracked: every request head is checked,
//!   and bodies are followed by their length or chunks to find the next one.
//! - QUIC: the client's Initial packets are decrypted (see `quic`) until they hold the
//!   whole `ClientHello`; then the flow leaves the queue.
//! - Anything else leaves the queue after its first data, allowed by address.
//!
//! On networks in monitor mode nothing is held or denied: the check runs on copies and only
//! reports what it would deny.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use tracing::{debug, warn};

use crate::conntrack::{self, Tuple};
use crate::directory::{Directory, NameRule, SourceInfo};
use crate::events::{Connection, DomainSource, Event, EventBus, Reason, Verdict};
use crate::firewall::{
    LogAllowed, NAME_ALLOWED_MARK, NAME_DENIED_MARK, NAME_WATCH_MARK, NameChecks, SetLookup,
    TABLE_NAME,
};
use crate::model::Strictness;
use crate::names::{self, HttpState, Opening, Step};
use crate::nfnetlink::{
    Ipv4Packet, NfqueueSocket, Overruns, PROTOCOL_TCP, PROTOCOL_UDP, QueueOverflow, QueueVerdict,
    QueuedPacket, is_overrun,
};
use crate::quic::{self, Crypto, Datagram, Hello};

/// How long the segments of a `ClientHello` or request head are held, waiting for the rest.
pub const HOLD_TIMEOUT: Duration = Duration::from_secs(3);
/// How long a connection may go without a packet before Portcullis asks connection
/// tracking whether it is still there, and forgets it if it isn't. A connection is never
/// forgotten while it is tracked: a plain HTTP connection may idle between requests for as
/// long as its server keeps it open.
pub const IDLE_CHECK: Duration = Duration::from_mins(1);
/// Connections checked at a time, per queue. Beyond that, new ones are denied: what they
/// ask for couldn't be followed.
pub const MAX_CONNECTIONS: usize = 65_536;
/// Datagrams of a QUIC flow taken before its `ClientHello` is whole, at most.
const MAX_DATAGRAMS: usize = 8;
/// Segments held, and bytes buffered, per connection at most.
const MAX_HELD: usize = 64;
const MAX_BUFFERED: usize = names::MAX_CLIENT_HELLO + 1024;
/// Bytes of request heads and chunk framing kept per connection, to compare what the
/// client resends with.
const MAX_PINNED: usize = 1 << 18;
/// Requests for encryption before TLS (see `names::Opening::Preamble`) at most.
const MAX_PREAMBLES: usize = 2;
/// The same decision about the same connection target is reported once per interval.
const REPORT_INTERVAL: Duration = Duration::from_mins(1);
/// How often connections are looked at for held packets that waited too long.
const EXPIRE_EVERY: Duration = Duration::from_millis(250);

const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Answers whether a hostname set of the inet table holds an address.
pub trait Sets {
    fn contains(&mut self, set: &str, address: IpAddr) -> bool;
}

/// Answers whether connection tracking still tracks a connection.
pub trait Tracking {
    fn exists(&mut self, connection: &Tuple) -> bool;
}

impl Tracking for conntrack::Lookup {
    fn exists(&mut self, connection: &Tuple) -> bool {
        // When it can't tell, the connection is kept: it is forgotten later.
        Self::exists(self, connection).unwrap_or(true)
    }
}

/// How name checks run.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    pub checks: NameChecks,
    /// `--name-checks`: for rules of containers that don't say.
    pub strictness: Strictness,
    pub log_allowed: LogAllowed,
    /// See [`IDLE_CHECK`].
    pub idle_check: Duration,
}

impl Sets for SetLookup {
    fn contains(&mut self, set: &str, address: IpAddr) -> bool {
        match Self::contains(self, set, address) {
            Ok(contains) => contains,
            Err(error) => {
                warn!(%error, set, "can't look an address up in a hostname set; taking it as missing");
                false
            }
        }
    }
}

/// Start checking the connections held in both queues. If reading one fails for good, its
/// thread says why on `failed` and ends.
pub fn spawn(
    settings: Settings,
    directory: &Arc<Directory>,
    bus: &EventBus,
    failed: &Sender<String>,
) -> io::Result<()> {
    for (queue, overflow, monitor) in [
        (settings.checks.enforce, QueueOverflow::Drop, false),
        (settings.checks.monitor, QueueOverflow::Accept, true),
    ] {
        let mut socket = NfqueueSocket::bind(queue, overflow)?.with_connections(overflow)?;
        socket.set_receive_timeout(EXPIRE_EVERY)?;
        let mut checker = Checker::new(
            monitor,
            &settings,
            Arc::clone(directory),
            SetLookup::open(TABLE_NAME)?,
            conntrack::Lookup::open()?,
        );
        let (bus, failed) = (bus.clone(), failed.clone());
        thread::spawn(move || {
            let mut overruns = Overruns::default();
            let mut expired = Instant::now();
            loop {
                let packets = match socket.receive() {
                    Ok(packets) => packets,
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                // With a timeout, a stop and continue (SIGSTOP, SIGCONT)
                                // isn't restarted.
                                | io::ErrorKind::Interrupted
                        ) =>
                    {
                        Vec::new()
                    }
                    Err(error) if is_overrun(&error) => {
                        if overruns.report() {
                            warn!(
                                "connections whose names are checked came faster than they could be read; the kernel dropped some of their packets"
                            );
                        }
                        Vec::new()
                    }
                    Err(error) => {
                        let _ = failed.send(format!(
                            "reading connections whose names are checked failed: {error}"
                        ));
                        return;
                    }
                };
                let now = Instant::now();
                let mut out = Output::default();
                for packet in &packets {
                    checker.packet(packet, now, &mut out);
                }
                if now.duration_since(expired) >= EXPIRE_EVERY {
                    checker.expire(now, &mut out);
                    expired = now;
                }
                for (id, verdict) in out.verdicts {
                    if let Err(error) = socket.verdict(id, verdict) {
                        warn!(%error, "failed to release a packet of a connection whose name is checked");
                    }
                }
                for event in out.events {
                    bus.publish(&Event::Connection(event));
                }
            }
        });
    }
    Ok(())
}

/// What handling packets decided: verdicts, and events to report.
#[derive(Debug, Default)]
pub struct Output {
    pub verdicts: Vec<(u32, QueueVerdict)>,
    pub events: Vec<Connection>,
}

const ALLOWED: QueueVerdict = QueueVerdict::Repeat {
    mark: Some(NAME_ALLOWED_MARK),
};
const WATCH: QueueVerdict = QueueVerdict::Repeat {
    mark: Some(NAME_WATCH_MARK),
};
const DENIED: QueueVerdict = QueueVerdict::Repeat {
    mark: Some(NAME_DENIED_MARK),
};

/// The connections of one queue.
pub struct Checker<S, T> {
    /// The queue's networks are in monitor mode.
    monitor: bool,
    log_allowed: LogAllowed,
    strictness: Strictness,
    idle_check: Duration,
    directory: Arc<Directory>,
    sets: S,
    tracking: T,
    connections: HashMap<Tuple, Checked>,
    /// When each decision was last reported.
    reported: HashMap<ReportKey, Instant>,
    /// Packets that came without their tracked connection, reported once.
    untracked: bool,
    /// Connections whose check ended allowed, and when. Packets of theirs the kernel queued
    /// before it knew pass.
    finished: HashMap<Tuple, Instant>,
}

/// How long packets of a connection that was allowed may still come.
const FINISHED: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReportKey {
    source: IpAddr,
    destination: (IpAddr, u16),
    protocol: u8,
    name: Option<String>,
    verdict: Verdict,
    detail: Option<Cow<'static, str>>,
}

/// A connection being checked.
struct Checked {
    source: SourceInfo,
    phase: Phase,
    stream: Stream,
    /// Held packets, by ID, with the stream offset their data ends at.
    held: Vec<(u32, u64)>,
    held_since: Option<Instant>,
    last_seen: Instant,
    /// Names found allowed for the destination already.
    allowed: Vec<String>,
    preambles: usize,
    /// The CRYPTO data of a QUIC flow's Initial packets so far, and how many datagrams.
    quic: Option<(Crypto, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// Before the client's first message.
    Opening,
    /// TLS, allowed: until the server acknowledges the `ClientHello`, up to `end`.
    Acknowledging { end: u64 },
    /// Plain HTTP: every request is checked.
    Http(HttpState),
}

/// The client's side of a TCP connection, by offset from its first byte.
#[derive(Debug, Default)]
struct Stream {
    /// The client's first sequence number, of the SYN.
    initial: Option<u32>,
    /// Bytes up to here have arrived in order.
    next: u64,
    /// Bytes up to here are allowed; `next - judged` bytes are in `buffer`.
    judged: u64,
    buffer: Vec<u8>,
    /// Segments that arrived ahead of `next`, by offset.
    ahead: BTreeMap<u64, Vec<u8>>,
    /// What the checks read (`ClientHello`, request heads, chunk framing), by offset, to
    /// compare resent bytes with. Bodies aren't kept: what they say doesn't matter.
    pinned: VecDeque<(u64, Vec<u8>)>,
    pinned_bytes: usize,
    /// Pinned bytes below this offset were let go of.
    floor: u64,
}

impl Stream {
    /// The stream offset of sequence number `sequence`, the one nearest `near`.
    fn offset(&self, sequence: u32) -> Option<u64> {
        let first = self.initial?.wrapping_add(1);
        let relative = u64::from(sequence.wrapping_sub(first));
        let near = self.next;
        let base = near & !0xffff_ffff;
        [
            base.checked_sub(1 << 32),
            Some(base),
            base.checked_add(1 << 32),
        ]
        .into_iter()
        .flatten()
        .map(|base| base + relative)
        .min_by_key(|offset| offset.abs_diff(near))
    }

    /// Take in the segments that arrived early and follow on now; false when one overlaps
    /// what came before and differs.
    fn follow_on(&mut self) -> bool {
        while let Some(entry) = self.ahead.first_entry() {
            let start = *entry.key();
            if start > self.next {
                break;
            }
            let segment = entry.remove();
            let skip = usize::try_from(self.next - start).unwrap_or(usize::MAX);
            if let Some((overlap, rest)) = segment.split_at_checked(skip) {
                if !self.same(start, overlap) {
                    return false;
                }
                self.buffer.extend_from_slice(rest);
                self.next += rest.len() as u64;
            }
        }
        true
    }

    fn pin(&mut self, offset: u64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.pinned.push_back((offset, bytes.to_vec()));
        self.pinned_bytes += bytes.len();
        while self.pinned_bytes > MAX_PINNED {
            let Some((start, bytes)) = self.pinned.pop_front() else {
                break;
            };
            self.pinned_bytes -= bytes.len();
            self.floor = start + bytes.len() as u64;
        }
    }

    /// Whether data at `offset`, below `next`, is what arrived there before, as far as
    /// that is known: pinned bytes, and those not judged yet.
    fn same(&self, offset: u64, data: &[u8]) -> bool {
        let end = offset + data.len() as u64;
        if offset < self.floor {
            return false;
        }
        let compare = |start: u64, known: &[u8]| {
            let from = offset.max(start);
            let to = end.min(start + known.len() as u64);
            let slice = |bytes: &[u8], at: u64| -> Option<Vec<u8>> {
                let at = usize::try_from(at).ok()?;
                let length = usize::try_from(to - from).ok()?;
                bytes.get(at..)?.get(..length).map(<[u8]>::to_vec)
            };
            from >= to || {
                let ours = slice(data, from - offset);
                ours.is_some() && ours == slice(known, from - start)
            }
        };
        self.pinned
            .iter()
            .all(|(start, known)| compare(*start, known))
            && compare(self.judged, &self.buffer)
    }
}

/// Why a connection is denied, and the name it asked for, if any.
struct Denial {
    name: Option<String>,
    detail: Cow<'static, str>,
}

impl Denial {
    fn new(detail: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: None,
            detail: detail.into(),
        }
    }
}

/// What judging the stream led to.
enum Judged {
    /// Nothing new decided.
    Nothing,
    /// A first name was allowed: TLS, or the first request of plain HTTP.
    Allowed {
        name: String,
    },
    /// A request that turns the connection into a tunnel was allowed, for `name`.
    Tunnel {
        name: String,
    },
    /// The connection doesn't name a server, as `detail` says.
    Nameless(&'static str),
    Denied(Denial),
}

impl<S: Sets, T: Tracking> Checker<S, T> {
    pub fn new(
        monitor: bool,
        settings: &Settings,
        directory: Arc<Directory>,
        sets: S,
        tracking: T,
    ) -> Self {
        Self {
            monitor,
            log_allowed: settings.log_allowed,
            strictness: settings.strictness,
            idle_check: settings.idle_check,
            directory,
            sets,
            tracking,
            connections: HashMap::new(),
            reported: HashMap::new(),
            untracked: false,
            finished: HashMap::new(),
        }
    }

    /// Decide on a packet, or hold it.
    pub fn packet(&mut self, packet: &QueuedPacket, now: Instant, out: &mut Output) {
        let (Some(tracked), Some(ip)) = (packet.connection, Ipv4Packet::parse(&packet.payload))
        else {
            if !self.untracked {
                self.untracked = true;
                warn!(
                    "a packet of a connection whose name is checked came without its tracked connection; such packets are denied"
                );
            }
            out.verdicts.push((packet.id, self.deny_verdict()));
            return;
        };
        let key = tracked.original;
        match key.protocol {
            PROTOCOL_TCP => self.tcp(packet.id, key, tracked.reply, &ip, now, out),
            PROTOCOL_UDP if !tracked.reply => self.udp(packet.id, key, ip.data, now, out),
            _ if self.finished.contains_key(&key) => {
                out.verdicts.push((packet.id, QueueVerdict::Accept));
            }
            _ => out.verdicts.push((packet.id, self.deny_verdict())),
        }
    }

    /// Start checking a connection, if there is room; or deny its packet `id`.
    fn start(
        &mut self,
        id: u32,
        key: Tuple,
        initial: Option<u32>,
        now: Instant,
        out: &mut Output,
    ) -> bool {
        let source = self.directory.attributed(key.source.0);
        let Some(source) = source.filter(|_| self.connections.len() < MAX_CONNECTIONS) else {
            let detail = if self.connections.len() >= MAX_CONNECTIONS {
                "too many connections being checked at once"
            } else {
                "from an address that isn't a known container's"
            };
            self.decided(key, None, Some(Denial::new(detail)), out);
            out.verdicts.push((id, self.deny_verdict()));
            return false;
        };
        self.connections.insert(
            key,
            Checked {
                source,
                phase: Phase::Opening,
                stream: Stream {
                    initial,
                    ..Stream::default()
                },
                held: Vec::new(),
                held_since: None,
                last_seen: now,
                allowed: Vec::new(),
                preambles: 0,
                quic: None,
            },
        );
        true
    }

    /// A datagram of a UDP flow: QUIC's first ones are read until they hold the whole
    /// `ClientHello`; others name no server.
    fn udp(&mut self, id: u32, key: Tuple, data: &[u8], now: Instant, out: &mut Output) {
        if self.finished.contains_key(&key) {
            out.verdicts.push((id, QueueVerdict::Accept));
            return;
        }
        if !self.connections.contains_key(&key) && !self.start(id, key, None, now, out) {
            return;
        }
        let Some(checked) = self.connections.get_mut(&key) else {
            return;
        };
        checked.last_seen = now;
        checked.held.push((id, u64::MAX));
        checked.held_since.get_or_insert(now);
        let started = checked.quic.is_some();
        let frames = match quic::datagram(data) {
            Datagram::Crypto { frames, .. } => frames,
            // More of a flow whose ClientHello is still incomplete waits with it.
            Datagram::NotQuic | Datagram::Unreadable(_) if started => {
                return self.udp_held(key, now, out);
            }
            Datagram::NotQuic => {
                return self.nameless(key, "UDP that isn't QUIC: no name to check", now, out);
            }
            Datagram::Unreadable(reason) => return self.nameless(key, reason, now, out),
        };
        let (crypto, datagrams) = checked.quic.get_or_insert_with(Default::default);
        *datagrams += 1;
        if let Err(reason) = crypto.add(frames) {
            return self.deny(key, Denial::new(reason), out);
        }
        match crypto.hello() {
            Hello::NeedMore => self.udp_held(key, now, out),
            Hello::Refused(reason) => self.deny(key, Denial::new(reason), out),
            Hello::Complete { name: None, .. } => self.nameless(
                key,
                "a QUIC ClientHello without a server name (SNI)",
                now,
                out,
            ),
            Hello::Complete {
                name: Some(name),
                ech,
            } => match self.check(key, Some(&name), ech) {
                Ok(()) => {
                    self.release_all(key, ALLOWED, out);
                    self.decided(key, Some(name), None, out);
                    self.finish(key, now);
                }
                Err(mut denial) => {
                    denial.name = Some(name);
                    self.deny(key, denial, out);
                }
            },
        }
    }

    /// Datagrams of a QUIC flow wait for the rest of the `ClientHello` (in monitor mode,
    /// they pass meanwhile), but not for long.
    fn udp_held(&mut self, key: Tuple, now: Instant, out: &mut Output) {
        let monitor = self.monitor;
        let Some(checked) = self.connections.get_mut(&key) else {
            return;
        };
        let datagrams = checked.quic.as_ref().map_or(0, |(_, count)| *count);
        if datagrams > MAX_DATAGRAMS || checked.held.len() > MAX_DATAGRAMS {
            return self.deny(
                key,
                Denial::new("a QUIC ClientHello that doesn't arrive whole"),
                out,
            );
        }
        if monitor {
            let held = std::mem::take(&mut checked.held);
            checked.held_since = None;
            out.verdicts
                .extend(held.into_iter().map(|(id, _)| (id, QueueVerdict::Accept)));
        }
        let _ = now;
    }

    /// The connection names no server, as `detail` says: allowed by address, unless the
    /// rules that allow its address check names strictly.
    fn nameless(&mut self, key: Tuple, detail: &'static str, now: Instant, out: &mut Output) {
        if self.by_address(key) {
            self.release_all(key, ALLOWED, out);
            self.decided(key, None, None, out);
            self.finish(key, now);
        } else {
            self.deny(
                key,
                Denial::new(format!("{detail}; names are checked strictly")),
                out,
            );
        }
    }

    /// Whether a rule of the connection's port that doesn't check names strictly has its
    /// destination.
    fn by_address(&mut self, key: Tuple) -> bool {
        let Some(checked) = self.connections.get(&key) else {
            return false;
        };
        let (protocol, (destination, port)) = (key.protocol, key.destination);
        let sets: Vec<String> = checked
            .source
            .names
            .iter()
            .filter(|rule| {
                rule.service.allows(protocol, port)
                    && rule.strictness.unwrap_or(self.strictness) == Strictness::Lenient
            })
            .map(|rule| rule.set.clone())
            .collect();
        sets.iter().any(|set| self.sets.contains(set, destination))
    }

    /// Release every held packet of the connection, the last with `last`.
    fn release_all(&mut self, key: Tuple, last: QueueVerdict, out: &mut Output) {
        let Some(checked) = self.connections.get_mut(&key) else {
            return;
        };
        let held = std::mem::take(&mut checked.held);
        checked.held_since = None;
        let count = held.len();
        for (index, (id, _)) in held.into_iter().enumerate() {
            let verdict = if index + 1 == count {
                last
            } else {
                QueueVerdict::Accept
            };
            out.verdicts.push((id, verdict));
        }
    }

    /// What a denied packet gets: denied, or in monitor mode, let through for good.
    const fn deny_verdict(&self) -> QueueVerdict {
        if self.monitor { ALLOWED } else { DENIED }
    }

    fn tcp(
        &mut self,
        id: u32,
        key: Tuple,
        reply: bool,
        ip: &Ipv4Packet<'_>,
        now: Instant,
        out: &mut Output,
    ) {
        let flags = ip.tcp_flags.unwrap_or_default();
        let Some((sequence, acknowledged)) = ip.tcp_sequence else {
            out.verdicts.push((id, self.deny_verdict()));
            return;
        };
        if !reply && flags & (TCP_SYN | TCP_ACK) == TCP_SYN {
            self.syn(id, key, sequence, ip.data, now, out);
            return;
        }
        if self.finished.contains_key(&key) {
            out.verdicts.push((id, QueueVerdict::Accept));
            return;
        }
        let Some(checked) = self.connections.get_mut(&key) else {
            // A connection whose start wasn't seen, or that was forgotten: its first bytes
            // can't be told apart from the rest.
            if !reply && !ip.data.is_empty() {
                self.decided(
                    key,
                    None,
                    Some(Denial::new(
                        "Portcullis didn't see the connection start, or forgot it",
                    )),
                    out,
                );
            }
            out.verdicts.push((id, self.deny_verdict()));
            return;
        };
        checked.last_seen = now;
        if flags & TCP_RST != 0 {
            let held = std::mem::take(&mut checked.held);
            self.connections.remove(&key);
            out.verdicts
                .extend(held.into_iter().map(|(id, _)| (id, QueueVerdict::Accept)));
            out.verdicts.push((id, QueueVerdict::Accept));
            return;
        }
        if reply {
            let verdict = match checked.phase {
                Phase::Acknowledging { end }
                    if flags & TCP_ACK != 0
                        && checked
                            .stream
                            .offset(acknowledged)
                            .is_some_and(|offset| offset >= end) =>
                {
                    self.finish(key, now);
                    ALLOWED
                }
                _ => QueueVerdict::Accept,
            };
            out.verdicts.push((id, verdict));
            return;
        }
        if ip.data.is_empty() {
            out.verdicts.push((id, QueueVerdict::Accept));
            return;
        }
        let Some(offset) = checked.stream.offset(sequence) else {
            out.verdicts.push((id, self.deny_verdict()));
            return;
        };
        self.data(id, key, offset, ip.data, now, out);
    }

    fn syn(
        &mut self,
        id: u32,
        key: Tuple,
        sequence: u32,
        data: &[u8],
        now: Instant,
        out: &mut Output,
    ) {
        self.finished.remove(&key);
        if let Some(checked) = self.connections.get_mut(&key) {
            // Sent again.
            checked.last_seen = now;
            if checked.stream.initial == Some(sequence) && data.is_empty() {
                out.verdicts.push((id, QueueVerdict::Accept));
                return;
            }
        }
        if !self.start(id, key, Some(sequence), now, out) {
            return;
        }
        if data.is_empty() {
            out.verdicts.push((id, QueueVerdict::Accept));
            return;
        }
        // Data in the SYN (TCP Fast Open) can't be held for the rest: nothing more comes
        // before the handshake. It has to hold the whole ClientHello or request head.
        self.data(id, key, 0, data, now, out);
        if let Some(checked) = self.connections.get(&key)
            && checked.held.iter().any(|(held, _)| *held == id)
        {
            self.deny(key, Denial::new("data in a SYN (TCP Fast Open) that doesn't hold a whole ClientHello or request"), out);
        }
    }

    /// Data the client sent at `offset` of its stream.
    fn data(
        &mut self,
        id: u32,
        key: Tuple,
        offset: u64,
        data: &[u8],
        now: Instant,
        out: &mut Output,
    ) {
        let monitor = self.monitor;
        let Some(checked) = self.connections.get_mut(&key) else {
            return;
        };
        let end = offset + data.len() as u64;
        // After the ClientHello, TLS is only compared with it, never read.
        if let Phase::Acknowledging { .. } = checked.phase {
            if checked.stream.same(offset, data) {
                out.verdicts.push((id, QueueVerdict::Accept));
            } else {
                self.deny_packet(key, id, "the client resent its ClientHello changed", out);
            }
            return;
        }
        let stream = &mut checked.stream;
        // What arrived before must be the same again.
        let old = usize::try_from(stream.next.saturating_sub(offset))
            .unwrap_or(usize::MAX)
            .min(data.len());
        let (before, after) = data.split_at(old);
        if old > 0 && !stream.same(offset, before) {
            self.deny_packet(key, id, "the client resent data changed", out);
            return;
        }
        if offset > stream.next {
            stream.ahead.insert(offset, data.to_vec());
        } else if end > stream.next {
            stream.buffer.extend_from_slice(after);
            stream.next = end;
        }
        // Segments that arrived early may follow on now.
        if !stream.follow_on() {
            self.deny_packet(
                key,
                id,
                "the client sent overlapping data that differs",
                out,
            );
            return;
        }
        let buffered: usize =
            stream.buffer.len() + stream.ahead.values().map(Vec::len).sum::<usize>();
        if end > stream.judged {
            checked.held.push((id, end));
        } else {
            out.verdicts.push((id, QueueVerdict::Accept));
        }
        if checked.held.len() > MAX_HELD || buffered > MAX_BUFFERED {
            self.deny(
                key,
                Denial::new("more data than a ClientHello or request head before its name"),
                out,
            );
            return;
        }
        let opening = matches!(checked.phase, Phase::Opening);
        let judged = self.judge(key);
        let Some(checked) = self.connections.get_mut(&key) else {
            return;
        };
        match judged {
            Judged::Denied(denial) => {
                self.deny(key, denial, out);
            }
            Judged::Nameless(detail) => self.nameless(key, detail, now, out),
            Judged::Tunnel { name } => {
                if self.by_address(key) {
                    self.release_all(key, ALLOWED, out);
                    self.decided(key, Some(name), None, out);
                    self.finish(key, now);
                } else {
                    self.deny(
                        key,
                        Denial {
                            name: Some(name),
                            detail: "an HTTP upgrade or CONNECT: what follows names no server; names are checked strictly".into(),
                        },
                        out,
                    );
                }
            }
            Judged::Allowed { name } => {
                let tls = matches!(checked.phase, Phase::Acknowledging { .. });
                // Plain HTTP stays watched. TLS stays checked until the server has the
                // ClientHello, except in monitor mode, where nothing is protected.
                let last = match (tls, monitor) {
                    (false, _) if opening => Some(WATCH),
                    (true, true) => Some(ALLOWED),
                    _ => None,
                };
                self.release(key, now, out, last);
                self.decided(key, Some(name), None, out);
                if tls && monitor {
                    self.finish(key, now);
                }
            }
            Judged::Nothing => self.release(key, now, out, None),
        }
    }

    /// Read as far as the stream allows, checking each name on the way.
    fn judge(&mut self, key: Tuple) -> Judged {
        /// What to do with the front of the buffer.
        enum Next {
            Stop,
            Deny(&'static str),
            Nameless(&'static str),
            /// Take this many bytes; pin them when they are framing.
            Take(usize, bool),
            Http,
            Tls(names::ClientHello),
            Request(names::RequestHead),
        }
        let mut first = None;
        loop {
            let Some(checked) = self.connections.get_mut(&key) else {
                return Judged::Nothing;
            };
            if checked.stream.buffer.is_empty() {
                break;
            }
            let buffer = &checked.stream.buffer;
            let next = match &mut checked.phase {
                Phase::Opening => match names::opening(buffer) {
                    Opening::NeedMore => Next::Stop,
                    Opening::Nameless(reason) => Next::Nameless(reason),
                    Opening::Refused(reason) => Next::Deny(reason),
                    Opening::Preamble(length) => {
                        checked.preambles += 1;
                        if checked.preambles > MAX_PREAMBLES {
                            Next::Deny("too many requests for encryption before TLS")
                        } else {
                            Next::Take(length, true)
                        }
                    }
                    Opening::Tls(hello) => Next::Tls(hello),
                    Opening::Http(_) => Next::Http,
                },
                Phase::Acknowledging { .. } => Next::Stop,
                Phase::Http(state) => {
                    let framing = !matches!(state, HttpState::Body(_) | HttpState::ChunkData(_));
                    match state.advance(buffer) {
                        Step::NeedMore => Next::Stop,
                        Step::Refused(reason) => Next::Deny(reason),
                        Step::Skip(length) => Next::Take(length, framing),
                        Step::Request(head) => Next::Request(head),
                    }
                }
            };
            match next {
                Next::Stop => break,
                Next::Deny(reason) => return Judged::Denied(Denial::new(reason)),
                Next::Nameless(reason) => return Judged::Nameless(reason),
                Next::Take(length, pin) => consume(&mut checked.stream, length, pin),
                Next::Http => checked.phase = Phase::Http(HttpState::Head),
                Next::Tls(names::ClientHello { name: None, .. }) => {
                    return Judged::Nameless("a ClientHello without a server name (SNI)");
                }
                Next::Tls(hello) => {
                    let start = checked.stream.judged;
                    let end = start + hello.end as u64;
                    if let Err(mut denial) = self.check(key, hello.name.as_deref(), hello.ech) {
                        denial.name = hello.name;
                        return Judged::Denied(denial);
                    }
                    let Some(checked) = self.connections.get_mut(&key) else {
                        return Judged::Nothing;
                    };
                    let stream = &mut checked.stream;
                    let pinned = stream.buffer.get(..hello.end).unwrap_or_default().to_vec();
                    stream.pin(start, &pinned);
                    stream.buffer.clear();
                    // Everything after the ClientHello is encrypted, and allowed.
                    stream.judged = u64::MAX;
                    checked.phase = Phase::Acknowledging { end };
                    return Judged::Allowed {
                        name: hello.name.unwrap_or_default(),
                    };
                }
                Next::Request(head) => {
                    if let Err(mut denial) = self.check(key, Some(&head.name), false) {
                        denial.name = Some(head.name);
                        return Judged::Denied(denial);
                    }
                    let Some(checked) = self.connections.get_mut(&key) else {
                        return Judged::Nothing;
                    };
                    consume(&mut checked.stream, head.end, true);
                    if head.tunnel {
                        return Judged::Tunnel { name: head.name };
                    }
                    first.get_or_insert(head.name);
                }
            }
        }
        match first {
            Some(name) => Judged::Allowed { name },
            None => Judged::Nothing,
        }
    }

    /// Whether the connection may ask for `name`: a `host:` rule of its container for its
    /// port matches the name, and the name's addresses include the destination.
    fn check(&mut self, key: Tuple, name: Option<&str>, ech: bool) -> Result<(), Denial> {
        let Some(checked) = self.connections.get_mut(&key) else {
            return Err(Denial::new("forgotten"));
        };
        let Some(name) = name else {
            return Err(Denial::new("a ClientHello without a server name (SNI)"));
        };
        if checked.allowed.iter().any(|allowed| allowed == name) {
            return Ok(());
        }
        let (protocol, (destination, port)) = (key.protocol, key.destination);
        let rules: Vec<&NameRule> = checked
            .source
            .names
            .iter()
            .filter(|rule| rule.service.allows(protocol, port) && rule.pattern.matches(name))
            .collect();
        if rules.is_empty() {
            return Err(Denial::new(if ech {
                "an encrypted ClientHello (ECH), whose visible server name isn't one of the container's host: names"
            } else {
                "not one of the container's host: names for this port"
            }));
        }
        let sets: Vec<String> = rules.iter().map(|rule| rule.set.clone()).collect();
        if sets.iter().any(|set| self.sets.contains(set, destination)) {
            if let Some(checked) = self.connections.get_mut(&key) {
                checked.allowed.push(name.to_string());
            }
            Ok(())
        } else {
            Err(Denial::new(
                "one of the container's host: names, but its addresses don't include this one",
            ))
        }
    }

    /// Release the held packets whose data is all allowed; the last one released gets
    /// `last` instead of passing on.
    fn release(&mut self, key: Tuple, now: Instant, out: &mut Output, last: Option<QueueVerdict>) {
        let monitor = self.monitor;
        let Some(checked) = self.connections.get_mut(&key) else {
            return;
        };
        let judged = checked.stream.judged;
        let (released, held): (Vec<_>, Vec<_>) = checked
            .held
            .drain(..)
            .partition(|(_, end)| monitor || *end <= judged);
        checked.held = held;
        checked.held_since = if checked.held.is_empty() {
            None
        } else {
            checked.held_since.or(Some(now))
        };
        // The packet that completed the name is always among them.
        let count = released.len();
        for (index, (id, _)) in released.into_iter().enumerate() {
            let verdict = match last {
                Some(verdict) if index + 1 == count => verdict,
                _ => QueueVerdict::Accept,
            };
            out.verdicts.push((id, verdict));
        }
    }

    /// Deny the connection: its held packets, and with them the connection itself.
    fn deny(&mut self, key: Tuple, denial: Denial, out: &mut Output) {
        let verdict = self.deny_verdict();
        if let Some(checked) = self.connections.remove(&key) {
            // In monitor mode, the connection goes on unchecked.
            out.verdicts
                .extend(checked.held.iter().map(|(id, _)| (*id, verdict)));
            self.report(key, &checked.source, denial.name, Some(denial.detail), out);
        }
    }

    /// Deny the connection because of packet `id`, which isn't held.
    fn deny_packet(&mut self, key: Tuple, id: u32, detail: &'static str, out: &mut Output) {
        out.verdicts.push((id, self.deny_verdict()));
        self.deny(key, Denial::new(detail), out);
    }

    /// Report a decision about a connection that is gone from `connections` or never was.
    fn decided(
        &mut self,
        key: Tuple,
        name: Option<String>,
        denial: Option<Denial>,
        out: &mut Output,
    ) {
        let source = self
            .connections
            .get(&key)
            .map(|checked| checked.source.clone())
            .or_else(|| self.directory.attributed(key.source.0));
        let (name, detail) = match denial {
            Some(denial) => (denial.name.or(name), Some(denial.detail)),
            None => (name, None),
        };
        match source {
            Some(source) => self.report(key, &source, name, detail, out),
            None => self.report_unknown(key, name, detail, out),
        }
    }

    fn report_unknown(
        &mut self,
        key: Tuple,
        name: Option<String>,
        detail: Option<Cow<'static, str>>,
        out: &mut Output,
    ) {
        let source = SourceInfo {
            container: String::new(),
            network: String::new(),
            mac: None,
            port: crate::model::PortState::Unknown,
            monitor: self.monitor,
            quarantine: false,
            ipv6_network: false,
            domains: None,
            names: Arc::from([]),
        };
        self.report(key, &source, name, detail, out);
    }

    fn report(
        &mut self,
        key: Tuple,
        source: &SourceInfo,
        name: Option<String>,
        detail: Option<Cow<'static, str>>,
        out: &mut Output,
    ) {
        let verdict = match (detail.is_some(), self.monitor) {
            (false, _) => Verdict::Allowed,
            (true, false) => Verdict::Denied,
            (true, true) => Verdict::WouldDeny,
        };
        if verdict == Verdict::Allowed && !self.log_allowed.logs(self.monitor) {
            return;
        }
        let now = Instant::now();
        self.reported
            .retain(|_, at| now.duration_since(*at) < REPORT_INTERVAL);
        let report = ReportKey {
            source: key.source.0,
            destination: key.destination,
            protocol: key.protocol,
            name: name.clone(),
            verdict,
            detail: detail.clone(),
        };
        if self.reported.insert(report, now).is_some() {
            return;
        }
        let (source_address, destination) = (key.source.0, key.destination.0);
        let domain = self.directory.domain(source_address, destination);
        let known = !source.container.is_empty();
        out.events.push(Connection {
            verdict,
            reason: Reason::Egress,
            container: known.then(|| source.container.clone()),
            network: known.then(|| source.network.clone()),
            protocol: if key.protocol == PROTOCOL_TCP {
                "tcp".into()
            } else {
                "udp".into()
            },
            source: Some(source_address),
            source_port: Some(key.source.1),
            destination: Some(destination),
            destination_port: Some(key.destination.1),
            destination_container: None,
            domain_source: domain.as_ref().map(|_| DomainSource::Dns),
            domain,
            query: None,
            name,
            detail,
            mid_stream: false,
            forged: false,
        });
    }

    /// The check of a connection ended allowed.
    fn finish(&mut self, key: Tuple, now: Instant) {
        self.connections.remove(&key);
        self.finished.insert(key, now);
    }

    /// Decide on connections whose held packets waited too long for the rest, and forget
    /// those that idled and aren't tracked anymore.
    pub fn expire(&mut self, now: Instant, out: &mut Output) {
        self.finished
            .retain(|_, at| now.duration_since(*at) < FINISHED);
        let late: Vec<Tuple> = self
            .connections
            .iter()
            .filter(|(_, checked)| {
                checked
                    .held_since
                    .is_some_and(|since| now.duration_since(since) >= HOLD_TIMEOUT)
            })
            .map(|(key, _)| *key)
            .collect();
        for key in late {
            debug!(
                ?key,
                "a connection's first bytes didn't arrive whole in time"
            );
            // Whatever doesn't arrive whole could still turn out to name a server: TLS,
            // HTTP (a request line comes in pieces), a Postgres request for TLS, QUIC.
            self.deny(
                key,
                Denial::new("its first bytes didn't arrive whole within 3 seconds"),
                out,
            );
        }
        let idle: Vec<Tuple> = self
            .connections
            .iter()
            .filter(|(_, checked)| {
                checked.held.is_empty() && now.duration_since(checked.last_seen) >= self.idle_check
            })
            .map(|(key, _)| *key)
            .collect();
        for key in idle {
            if self.tracking.exists(&key) {
                if let Some(checked) = self.connections.get_mut(&key) {
                    checked.last_seen = now;
                }
            } else {
                self.connections.remove(&key);
            }
        }
    }
}

/// Take `length` judged bytes off the front of the stream's buffer; `pin` keeps them to
/// compare resent data with.
fn consume(stream: &mut Stream, length: usize, pin: bool) {
    let length = length.min(stream.buffer.len());
    if pin {
        let bytes: Vec<u8> = stream.buffer.get(..length).unwrap_or_default().to_vec();
        let start = stream.judged;
        stream.pin(start, &bytes);
    }
    stream.buffer.drain(..length);
    stream.judged += length as u64;
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::firewall::test_support::{self, MockResolver, ip};
    use crate::firewall::{HostSetId, Plan, SET_PREFIX_V4};
    use crate::model::{EgressRule, EgressTarget, IccMode, Protocol, Service};
    use crate::names::tests::client_hello_for;
    use crate::nfnetlink::Tracked;
    use crate::nfnetlink::tests::{ipv4, udp};
    use crate::pattern::NamePattern;

    const CLIENT: [u8; 4] = [172, 18, 0, 2];
    /// The address of api.example.com, shared with other sites.
    const SHARED: [u8; 4] = [1, 1, 1, 1];
    /// The address of www.example.org.
    const ORG: [u8; 4] = [93, 184, 216, 34];
    const ISN: u32 = 0xffff_fff0;
    const SERVER_ISN: u32 = 7000;

    /// Hostname sets by name.
    #[derive(Default)]
    struct FakeSets(HashSet<(String, IpAddr)>);

    impl Sets for FakeSets {
        fn contains(&mut self, set: &str, address: IpAddr) -> bool {
            self.0.contains(&(set.to_string(), address))
        }
    }

    fn set(host: &str) -> String {
        HostSetId::for_host("web", host)
            .name(SET_PREFIX_V4)
            .to_string()
    }

    /// Connections connection tracking forgot.
    #[derive(Default)]
    struct FakeTracking(HashSet<Tuple>);

    impl Tracking for FakeTracking {
        fn exists(&mut self, connection: &Tuple) -> bool {
            !self.0.contains(connection)
        }
    }

    /// The address of strict.example.net, whose rule checks names strictly.
    const STRICT: [u8; 4] = [5, 6, 7, 8];

    type TestChecker = Checker<FakeSets, FakeTracking>;

    fn checker(monitor: bool, log_allowed: LogAllowed) -> TestChecker {
        checker_with(monitor, log_allowed, Strictness::Lenient)
    }

    fn checker_with(monitor: bool, log_allowed: LogAllowed, strictness: Strictness) -> TestChecker {
        let mut state = crate::model::RuntimeState::default();
        test_support::add_network(&mut state, "net0", "172.18.0.0/16", "172.18.0.1");
        let rule = |target, services| EgressRule { target, services };
        test_support::add_container(
            &mut state,
            "w",
            "web",
            &[("net0", "172.18.0.2", &[])],
            test_support::policy(
                IccMode::Deny,
                vec![
                    rule(
                        EgressTarget::Hostname(NamePattern::host(test_support::HOST)),
                        vec![
                            Service::tcp(443),
                            Service::tcp(80),
                            Service::Protocol(Protocol::Udp, None),
                        ],
                    ),
                    rule(
                        EgressTarget::Hostname(NamePattern::host("*.example.org")),
                        vec![Service::tcp(443)],
                    ),
                    rule(
                        EgressTarget::StrictHostname(NamePattern::host("strict.example.net")),
                        vec![Service::tcp(443), Service::Protocol(Protocol::Udp, None)],
                    ),
                ],
            ),
        );
        let plan = Plan::build(&state, &mut MockResolver::default(), &[], false);
        let directory = Directory::default();
        directory.update(&plan);
        let mut sets = FakeSets::default();
        sets.0
            .insert((set(test_support::HOST), IpAddr::from(SHARED)));
        sets.0.insert((set("*.example.org"), IpAddr::from(ORG)));
        sets.0
            .insert((set("strict.example.net"), IpAddr::from(STRICT)));
        let settings = Settings {
            checks: NameChecks {
                enforce: 1,
                monitor: 2,
                marks: crate::firewall::CtMarkBits::default(),
            },
            strictness,
            log_allowed,
            idle_check: IDLE_CHECK,
        };
        Checker::new(
            monitor,
            &settings,
            Arc::new(directory),
            sets,
            FakeTracking::default(),
        )
    }

    fn tuple(destination: [u8; 4], port: u16, protocol: u8) -> Tuple {
        Tuple {
            protocol,
            source: (IpAddr::from(CLIENT), 40000),
            destination: (IpAddr::from(destination), port),
        }
    }

    fn segment(flags: u8, sequence: u32, acknowledged: u32, data: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend(40000_u16.to_be_bytes());
        header.extend(443_u16.to_be_bytes());
        header.extend(sequence.to_be_bytes());
        header.extend(acknowledged.to_be_bytes());
        header.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        header.extend(data);
        header
    }

    /// Drives one connection through a checker.
    struct Connection {
        checker: TestChecker,
        key: Tuple,
        id: u32,
        now: Instant,
    }

    impl Connection {
        fn new(checker: TestChecker, destination: [u8; 4], port: u16) -> Self {
            Self {
                checker,
                key: tuple(destination, port, PROTOCOL_TCP),
                id: 0,
                now: Instant::now(),
            }
        }

        fn send(
            &mut self,
            reply: bool,
            flags: u8,
            sequence: u32,
            acknowledged: u32,
            data: &[u8],
        ) -> (u32, Output) {
            self.id += 1;
            let (source, destination) = if reply {
                (self.key.destination.0, self.key.source.0)
            } else {
                (self.key.source.0, self.key.destination.0)
            };
            let octets = |address: IpAddr| match address {
                IpAddr::V4(address) => address.octets(),
                IpAddr::V6(_) => unreachable!(),
            };
            let packet = QueuedPacket {
                id: self.id,
                physindev: None,
                hwaddr: None,
                payload: ipv4(
                    octets(source),
                    octets(destination),
                    self.key.protocol,
                    &segment(flags, sequence, acknowledged, data),
                ),
                connection: Some(Tracked {
                    original: self.key,
                    reply,
                    mark: 0,
                }),
            };
            let mut out = Output::default();
            self.checker.packet(&packet, self.now, &mut out);
            (self.id, out)
        }

        /// The handshake, which passes.
        fn open(&mut self) {
            let (id, out) = self.send(false, TCP_SYN, ISN, 0, &[]);
            assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
            let (id, out) = self.send(
                true,
                TCP_SYN | TCP_ACK,
                SERVER_ISN,
                ISN.wrapping_add(1),
                &[],
            );
            assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
            let (id, out) = self.send(false, TCP_ACK, ISN.wrapping_add(1), SERVER_ISN + 1, &[]);
            assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        }

        /// The client's data at `offset` of its stream.
        fn client(&mut self, offset: u32, data: &[u8]) -> (u32, Output) {
            self.send(
                false,
                TCP_ACK,
                ISN.wrapping_add(1).wrapping_add(offset),
                SERVER_ISN + 1,
                data,
            )
        }

        /// The server acknowledges the client's stream up to `offset`.
        fn acknowledge(&mut self, offset: u32) -> (u32, Output) {
            self.send(
                true,
                TCP_ACK,
                SERVER_ISN + 1,
                ISN.wrapping_add(1).wrapping_add(offset),
                &[],
            )
        }
    }

    fn length(data: &[u8]) -> u32 {
        u32::try_from(data.len()).expect("short")
    }

    fn denied(out: &Output) -> &Connection_ {
        out.events.first().expect("an event")
    }

    type Connection_ = crate::events::Connection;

    #[test]
    fn allows_the_name_of_a_rule_once_the_server_has_the_client_hello() {
        let mut connection = Connection::new(checker(false, LogAllowed::Always), SHARED, 443);
        connection.open();
        let hello = client_hello_for(test_support::HOST);
        let (first, out) = connection.client(0, &hello[..50]);
        assert_eq!(out.verdicts, [], "held until the ClientHello is whole");
        let (second, out) = connection.client(50, &hello[50..]);
        assert_eq!(
            out.verdicts,
            [
                (first, QueueVerdict::Accept),
                (second, QueueVerdict::Accept)
            ]
        );
        let event = denied(&out);
        assert_eq!(event.verdict, Verdict::Allowed);
        assert_eq!(event.name.as_deref(), Some(test_support::HOST));
        assert_eq!(event.container.as_deref(), Some("web"));
        assert_eq!(event.destination, Some(IpAddr::from(SHARED)));
        // Resent the same, and more after it: fine.
        let (id, out) = connection.client(0, &hello);
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        let (id, out) = connection.client(length(&hello), b"\x17\x03\x03\x00\x01x");
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        // Until the server has all of it, the connection stays checked.
        let (id, out) = connection.acknowledge(50);
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        let (id, out) = connection.acknowledge(length(&hello));
        assert_eq!(out.verdicts, [(id, ALLOWED)]);
        assert!(connection.checker.connections.is_empty());
        // Packets the kernel queued before it knew pass.
        let (id, out) = connection.send(true, TCP_ACK, SERVER_ISN + 1, ISN.wrapping_add(1), b"x");
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
    }

    #[test]
    fn denies_other_sites_on_the_same_address() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        connection.open();
        let hello = client_hello_for("files.example.net");
        let (first, out) = connection.client(0, &hello[..10]);
        assert_eq!(out.verdicts, []);
        let (second, out) = connection.client(10, &hello[10..]);
        assert_eq!(out.verdicts, [(first, DENIED), (second, DENIED)]);
        let event = denied(&out);
        assert_eq!(event.verdict, Verdict::Denied);
        assert_eq!(event.reason, Reason::Egress);
        assert_eq!(event.name.as_deref(), Some("files.example.net"));
        assert_eq!(
            event.detail.as_deref(),
            Some("not one of the container's host: names for this port")
        );
        assert!(connection.checker.connections.is_empty());
    }

    #[test]
    fn denies_a_name_of_a_rule_at_an_address_that_isnt_its() {
        // www.example.org matches a rule, but its addresses don't include this one.
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        connection.open();
        let (id, out) = connection.client(0, &client_hello_for("www.example.org"));
        assert_eq!(out.verdicts, [(id, DENIED)]);
        assert!(
            denied(&out)
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("addresses don't include")
        );
        // At its own address it is allowed, by the pattern.
        let mut connection = Connection::new(checker(false, LogAllowed::Never), ORG, 443);
        connection.open();
        let (id, out) = connection.client(0, &client_hello_for("www.example.org"));
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        // Not on a port the rule doesn't have.
        let mut connection = Connection::new(checker(false, LogAllowed::Never), ORG, 8443);
        connection.open();
        let (id, out) = connection.client(0, &client_hello_for("www.example.org"));
        assert_eq!(out.verdicts, [(id, DENIED)]);
    }

    #[test]
    fn allows_client_hellos_without_a_name_by_address_unless_strict() {
        let mut hello = vec![22, 3, 1, 0, 45, 1, 0, 0, 41, 3, 3];
        hello.extend([0; 32]);
        hello.extend([0, 0, 2, 0x13, 0x01, 1, 0]);
        let mut connection = Connection::new(checker(false, LogAllowed::Always), SHARED, 443);
        connection.open();
        let (id, out) = connection.client(0, &hello);
        assert_eq!(out.verdicts, [(id, ALLOWED)]);
        assert_eq!(denied(&out).verdict, Verdict::Allowed);
        assert!(connection.checker.connections.is_empty());
        // Not with a strict rule's address, nor with the strict default.
        let mut connection = Connection::new(checker(false, LogAllowed::Never), STRICT, 443);
        connection.open();
        let (id, out) = connection.client(0, &hello);
        assert_eq!(out.verdicts, [(id, DENIED)]);
        assert_eq!(
            denied(&out).detail.as_deref(),
            Some("a ClientHello without a server name (SNI); names are checked strictly")
        );
        let mut connection = Connection::new(
            checker_with(false, LogAllowed::Never, Strictness::Strict),
            SHARED,
            443,
        );
        connection.open();
        let (id, out) = connection.client(0, &hello);
        assert_eq!(out.verdicts, [(id, DENIED)]);
    }

    #[test]
    fn allows_a_real_client_hello_over_two_segments() {
        let hello = include_bytes!("testdata/client-hello-api.example.com.bin");
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        connection.open();
        let (first, out) = connection.client(0, &hello[..1448]);
        assert_eq!(out.verdicts, []);
        let (second, out) = connection.client(1448, &hello[1448..]);
        assert_eq!(
            out.verdicts,
            [
                (first, QueueVerdict::Accept),
                (second, QueueVerdict::Accept)
            ]
        );
    }

    #[test]
    fn allows_what_isnt_tls_or_http_by_address_unless_strict() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        connection.open();
        // A server that speaks first is let through: only the client names a server.
        let (id, out) = connection.send(
            true,
            TCP_ACK,
            SERVER_ISN + 1,
            ISN.wrapping_add(1),
            b"SSH-2.0-server\r\n",
        );
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        let (id, out) = connection.client(0, b"SSH-2.0-client\r\n");
        assert_eq!(out.verdicts, [(id, ALLOWED)]);
        assert!(connection.checker.connections.is_empty());
        let mut connection = Connection::new(checker(false, LogAllowed::Never), STRICT, 443);
        connection.open();
        let (id, out) = connection.client(0, b"SSH-2.0-client\r\n");
        assert_eq!(out.verdicts, [(id, DENIED)]);
        assert_eq!(denied(&out).name, None);
        // Something that may still turn out to be a request waits, and is denied when it
        // doesn't: the rest could name another server.
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        connection.open();
        let (id, out) = connection.client(0, b"PING");
        assert_eq!(out.verdicts, []);
        let mut out = Output::default();
        connection
            .checker
            .expire(connection.now + HOLD_TIMEOUT, &mut out);
        assert_eq!(out.verdicts, [(id, DENIED)]);
    }

    #[test]
    fn puts_segments_that_come_early_in_order() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        connection.open();
        let hello = client_hello_for(test_support::HOST);
        let (late, out) = connection.client(50, &hello[50..]);
        assert_eq!(out.verdicts, []);
        let (early, out) = connection.client(0, &hello[..60]);
        assert_eq!(
            out.verdicts,
            [(late, QueueVerdict::Accept), (early, QueueVerdict::Accept)]
        );
    }

    #[test]
    fn denies_overlapping_segments_that_differ() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        connection.open();
        let hello = client_hello_for(test_support::HOST);
        let mut other = hello.clone();
        other[60] ^= 1;
        let (late, out) = connection.client(50, &other[50..]);
        assert_eq!(out.verdicts, []);
        let (early, out) = connection.client(0, &hello[..70]);
        assert!(out.verdicts.iter().all(|(_, verdict)| *verdict == DENIED));
        assert_eq!(out.verdicts.len(), 2, "{late} {early}");
    }

    #[test]
    fn denies_a_client_hello_resent_changed() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        connection.open();
        let hello = client_hello_for(test_support::HOST);
        let (id, out) = connection.client(0, &hello);
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        // As if the first copy never reached the server, the client sends another name in
        // the same place.
        let other = client_hello_for("evil.example.com");
        let (id, out) = connection.client(0, &other);
        assert_eq!(out.verdicts, [(id, DENIED)]);
        assert!(connection.checker.connections.is_empty());
    }

    #[test]
    fn denies_a_client_hello_that_doesnt_complete_in_time() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        connection.open();
        let hello = client_hello_for(test_support::HOST);
        let (id, out) = connection.client(0, &hello[..20]);
        assert_eq!(out.verdicts, []);
        let mut out = Output::default();
        connection
            .checker
            .expire(connection.now + Duration::from_secs(2), &mut out);
        assert_eq!(out.verdicts, []);
        connection
            .checker
            .expire(connection.now + HOLD_TIMEOUT, &mut out);
        assert_eq!(out.verdicts, [(id, DENIED)]);
        assert!(
            denied(&out)
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("within 3 seconds")
        );
    }

    #[test]
    fn denies_connections_it_didnt_see_start() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        let (id, out) = connection.client(0, &client_hello_for(test_support::HOST));
        assert_eq!(out.verdicts, [(id, DENIED)]);
    }

    #[test]
    fn keeps_connections_while_they_are_tracked() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 80);
        connection.open();
        let first = b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let (id, out) = connection.client(0, first);
        assert_eq!(out.verdicts, [(id, WATCH)]);
        // Idle for longer than any timeout: still tracked, still there.
        let mut out = Output::default();
        let later = connection.now + IDLE_CHECK * 100;
        connection.checker.expire(later, &mut out);
        connection.now = later;
        let second = b"GET /b HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let (id, out) = connection.client(length(first), second);
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        // Forgotten once connection tracking has forgotten it.
        connection.checker.tracking.0.insert(connection.key);
        let mut out = Output::default();
        connection
            .checker
            .expire(connection.now + IDLE_CHECK, &mut out);
        assert!(connection.checker.connections.is_empty());
    }

    #[test]
    fn checks_the_client_hello_after_a_postgres_request_for_tls() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        connection.open();
        let request = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
        let (id, out) = connection.client(0, &request);
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        let (id, out) = connection.send(
            true,
            TCP_ACK | 0x08,
            SERVER_ISN + 1,
            ISN.wrapping_add(9),
            b"S",
        );
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        let hello = client_hello_for("other.example.com");
        let (id, out) = connection.client(8, &hello);
        assert_eq!(out.verdicts, [(id, DENIED)]);
    }

    #[test]
    fn checks_every_http_request() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 80);
        connection.open();
        let first = b"POST /a HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 30\r\n\r\n";
        let (id, out) = connection.client(0, &first[..20]);
        assert_eq!(out.verdicts, []);
        let (last, out) = connection.client(20, &first[20..]);
        // Allowed, and its client's data stays watched.
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept), (last, WATCH)]);
        let mut offset = length(first);
        // A body that looks like a request is a body.
        let body = b"GET / HTTP/1.1\r\nHost: evil\r\n\r\n";
        let (id, out) = connection.client(offset, body);
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        offset += length(body);
        let second = b"GET /b HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
        let (id, out) = connection.client(offset, second);
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        offset += length(second);
        let third = b"GET /c HTTP/1.1\r\nHost: files.example.net\r\n\r\n";
        let (id, out) = connection.client(offset, third);
        assert_eq!(out.verdicts, [(id, DENIED)]);
        assert_eq!(denied(&out).name.as_deref(), Some("files.example.net"));
    }

    #[test]
    fn lets_an_allowed_tunnel_go_unless_strict() {
        let upgrade = b"GET /ws HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\n\r\n";
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 80);
        connection.open();
        let (id, out) = connection.client(0, upgrade);
        assert_eq!(out.verdicts, [(id, ALLOWED)]);
        let mut connection = Connection::new(
            checker_with(false, LogAllowed::Never, Strictness::Strict),
            SHARED,
            80,
        );
        connection.open();
        let (id, out) = connection.client(0, upgrade);
        assert_eq!(out.verdicts, [(id, DENIED)]);
        // To another site, not at all.
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 80);
        connection.open();
        let (id, out) = connection.client(
            0,
            b"CONNECT files.example.net:443 HTTP/1.1\r\nHost: files.example.net:443\r\n\r\n",
        );
        assert_eq!(out.verdicts, [(id, DENIED)]);
    }

    #[test]
    fn denies_pipelined_requests_for_other_sites() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 80);
        connection.open();
        let (id, out) = connection.client(
            0,
            b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\nGET / HTTP/1.1\r\nHost: files.example.net\r\n\r\n",
        );
        assert_eq!(out.verdicts, [(id, DENIED)]);
    }

    const QUIC_API: [&[u8]; 2] = [
        include_bytes!("testdata/quic-v1-api.example.com-0.bin"),
        include_bytes!("testdata/quic-v1-api.example.com-1.bin"),
    ];
    const QUIC_SPLIT: [&[u8]; 3] = [
        include_bytes!("testdata/quic-v1-split.example.org-0.bin"),
        include_bytes!("testdata/quic-v1-split.example.org-1.bin"),
        include_bytes!("testdata/quic-v1-split.example.org-2.bin"),
    ];

    /// The verdicts on `datagrams` of one flow to `destination`, and the events.
    fn quic(checker: &mut TestChecker, destination: [u8; 4], datagrams: &[&[u8]]) -> Output {
        let mut all = Output::default();
        for (index, data) in datagrams.iter().enumerate() {
            let id = u32::try_from(index).expect("few") + 1;
            let mut out = Output::default();
            checker.packet(
                &datagram_numbered(id, destination, data),
                Instant::now(),
                &mut out,
            );
            all.verdicts.extend(out.verdicts);
            all.events.extend(out.events);
        }
        all
    }

    #[test]
    fn checks_the_server_name_of_quic() {
        let mut checker = checker(false, LogAllowed::Always);
        let out = quic(&mut checker, SHARED, &QUIC_API);
        assert_eq!(out.verdicts.last(), Some(&(2, ALLOWED)));
        assert_eq!(denied(&out).name.as_deref(), Some(test_support::HOST));
        // Another site on the same address, its ClientHello over three packets: each waits
        // for the rest, and all are denied.
        let mut checker = self::checker(false, LogAllowed::Never);
        let out = quic(&mut checker, SHARED, &QUIC_SPLIT);
        assert_eq!(out.verdicts, [(1, DENIED), (2, DENIED), (3, DENIED)]);
        assert_eq!(denied(&out).name.as_deref(), Some("split.example.org"));
        // In monitor mode nothing waits.
        let mut checker = self::checker(true, LogAllowed::Never);
        let out = quic(&mut checker, SHARED, &QUIC_SPLIT);
        assert_eq!(
            out.verdicts,
            [
                (1, QueueVerdict::Accept),
                (2, QueueVerdict::Accept),
                (3, ALLOWED)
            ]
        );
        assert_eq!(denied(&out).verdict, Verdict::WouldDeny);
        // A flow whose ClientHello doesn't come whole is denied.
        let mut checker = self::checker(false, LogAllowed::Never);
        let out = quic(&mut checker, SHARED, &QUIC_SPLIT[..1]);
        assert_eq!(out.verdicts, []);
        let mut out = Output::default();
        checker.expire(Instant::now() + HOLD_TIMEOUT, &mut out);
        assert_eq!(out.verdicts, [(1, DENIED)]);
    }

    #[test]
    fn allows_udp_that_isnt_quic_by_address_unless_strict() {
        for (destination, expected) in [(SHARED, ALLOWED), (STRICT, DENIED)] {
            let mut checker = checker(false, LogAllowed::Never);
            let mut out = Output::default();
            checker.packet(&datagram(destination, b"\x17ntp"), Instant::now(), &mut out);
            assert_eq!(out.verdicts, [(1, expected)]);
        }
    }

    fn datagram(destination: [u8; 4], data: &[u8]) -> QueuedPacket {
        datagram_numbered(1, destination, data)
    }

    fn datagram_numbered(id: u32, destination: [u8; 4], data: &[u8]) -> QueuedPacket {
        let port = 40000;
        let key = Tuple {
            protocol: PROTOCOL_UDP,
            source: (IpAddr::from(CLIENT), port),
            destination: (IpAddr::from(destination), 443),
        };
        QueuedPacket {
            id,
            physindev: None,
            hwaddr: None,
            payload: ipv4(CLIENT, destination, PROTOCOL_UDP, &udp(port, 443, data)),
            connection: Some(Tracked {
                original: key,
                reply: false,
                mark: 0,
            }),
        }
    }

    #[test]
    fn only_reports_in_monitor_mode() {
        let mut connection = Connection::new(checker(true, LogAllowed::Never), SHARED, 443);
        connection.open();
        let hello = client_hello_for("files.example.net");
        // Nothing is held.
        let (id, out) = connection.client(0, &hello[..10]);
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
        let (id, out) = connection.client(10, &hello[10..]);
        assert_eq!(out.verdicts, [(id, ALLOWED)]);
        let event = denied(&out);
        assert_eq!(event.verdict, Verdict::WouldDeny);
        assert_eq!(event.name.as_deref(), Some("files.example.net"));
        assert!(connection.checker.connections.is_empty());
        // An allowed one leaves the queue at once.
        let mut connection = Connection::new(checker(true, LogAllowed::Monitor), SHARED, 443);
        connection.open();
        let (id, out) = connection.client(0, &client_hello_for(test_support::HOST));
        assert_eq!(out.verdicts, [(id, ALLOWED)]);
        assert_eq!(denied(&out).verdict, Verdict::Allowed);
    }

    #[test]
    fn reports_a_decision_once_a_minute() {
        let mut checker = checker(false, LogAllowed::Never);
        for (attempt, expected) in [(0_u16, 1), (1, 0)] {
            let mut connection = Connection::new(checker, SHARED, 443);
            connection.key.source.1 += attempt;
            connection.open();
            let (_, out) = connection.client(0, &client_hello_for("files.example.net"));
            assert_eq!(out.events.len(), expected);
            checker = connection.checker;
        }
        let _ = ip;
    }

    #[test]
    fn denies_data_in_a_syn_that_isnt_a_whole_client_hello() {
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        let hello = client_hello_for(test_support::HOST);
        let (id, out) = connection.send(false, TCP_SYN, ISN, 0, &hello[..30]);
        assert_eq!(out.verdicts, [(id, DENIED)]);
        let mut connection = Connection::new(checker(false, LogAllowed::Never), SHARED, 443);
        let (id, out) = connection.send(false, TCP_SYN, ISN, 0, &hello);
        assert_eq!(out.verdicts, [(id, QueueVerdict::Accept)]);
    }

    #[test]
    fn finds_offsets_across_sequence_number_wraps() {
        let stream = Stream {
            initial: Some(u32::MAX - 1),
            next: 5,
            ..Stream::default()
        };
        assert_eq!(stream.offset(u32::MAX), Some(0));
        assert_eq!(stream.offset(3), Some(4));
        let far = Stream {
            initial: Some(0),
            next: (1 << 32) + 10,
            ..Stream::default()
        };
        assert_eq!(far.offset(5), Some((1 << 32) + 4));
        assert_eq!(far.offset(u32::MAX), Some((1 << 32) - 2));
    }
}
