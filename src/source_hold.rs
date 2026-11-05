//! Holds packets from sources the rules don't know yet, instead of denying them.
//!
//! A container can start sending before Portcullis has seen it start and applied rules for
//! it. Its first packets (IPv4, and ARP for its neighbours) come from an address, MAC and
//! bridge port the rules don't know, which looks the same as a spoofed source. Docker also hands the address of a removed container to
//! the next one at once, with a new MAC. The bridge table queues them (NFQUEUE) instead of denying them, and
//! this module holds them:
//!
//! - once a rule update makes the source (address, MAC and port) known, a packet is replayed (`NF_REPEAT`): the
//!   kernel runs it through the rules again, now with the container's own chain, and it is
//!   allowed or denied as if the rules had been there from the start;
//! - if the source is still unknown after a grace period, the packet is replayed with a
//!   mark that the bridge table denies, and reports, like any spoofed source.
//!
//! While a packet is held, the main loop is asked to find its sender from the kernel and
//! Docker's files (`discovery`), without waiting for Docker's events and API; until the
//! container has a process, it is asked again every [`DISCOVER_RETRY`]. A container that
//! just started is then known within milliseconds, so the grace period only runs out for
//! a source that belongs to no container.
//!
//! On enforced networks the queue has no bypass: while Portcullis isn't reading it, such
//! packets are held until the kernel's queue is full and then dropped, so the hold fails
//! closed. Networks in monitor mode use a queue of their own that fails open
//! (`QueueOverflow::Accept`, and a bypass in the rule): a packet past its grace period is
//! replayed with the mark that reports it, and is let through.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{RecvTimeoutError, Sender, unbounded};
use tracing::{debug, warn};

use crate::directory::{Directory, SourceInfo};
use crate::firewall::HOLD_EXPIRED_MARK;
use crate::model::{MacAddress, PortState};
use crate::nfnetlink::{
    ArpPacket, Ipv4Packet, NfqueueSocket, Overruns, QueueOverflow, QueueVerdict, is_overrun,
};

/// Longest wait when nothing is held.
const IDLE_WAIT: Duration = Duration::from_secs(3600);
/// How often to ask again for the sender of a held packet to be found.
const DISCOVER_RETRY: Duration = Duration::from_millis(100);

/// A held packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    id: u32,
    /// `None` when the packet couldn't be parsed.
    source: Option<IpAddr>,
    mac: Option<MacAddress>,
    port: Option<u32>,
    deadline: Instant,
}

/// Releases held packets after rule updates.
pub struct SourceHold {
    wakes: Vec<Sender<()>>,
}

impl SourceHold {
    /// Rules were updated: release packets whose source is now known.
    pub fn rules_applied(&self) {
        for wake in &self.wakes {
            let _ = wake.send(());
        }
    }

    /// Both holds, released together.
    #[must_use]
    pub fn and(mut self, other: Self) -> Self {
        self.wakes.extend(other.wakes);
        self
    }
}

/// Start holding packets queued in NFQUEUE `queue`, for at most `grace` each, asking on
/// `discover` for the containers behind their bridge ports to be found. If reading fails
/// for good, the reading thread says why on `failed` and ends.
pub fn spawn(
    queue: u16,
    overflow: QueueOverflow,
    grace: Duration,
    directory: Arc<Directory>,
    discover: Sender<u32>,
    failed: Sender<String>,
) -> io::Result<SourceHold> {
    let mut socket = NfqueueSocket::bind(queue, overflow)?;
    let writer = socket.verdict_writer()?;
    let pending = Arc::new(Mutex::new(Vec::<Held>::new()));
    let (wake, woken) = unbounded::<()>();

    let receiving = Arc::clone(&pending);
    let wake_on_packet = wake.clone();
    thread::spawn(move || {
        let mut overruns = Overruns::default();
        loop {
            let packets = match socket.receive() {
                Ok(packets) => packets,
                Err(error) if is_overrun(&error) => {
                    if overruns.report() {
                        warn!(
                            "packets of new containers came faster than they could be held; the kernel dropped some"
                        );
                    }
                    continue;
                }
                Err(error) => {
                    let _ = failed.send(format!(
                        "reading held packets of new containers failed: {error}"
                    ));
                    return;
                }
            };
            let now = Instant::now();
            receiving
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(packets.iter().map(|packet| Held {
                    id: packet.id,
                    source: source_address(&packet.payload),
                    mac: packet.hwaddr,
                    port: packet.physindev,
                    deadline: now + grace,
                }));
            // The rules may already know the source.
            let _ = wake_on_packet.send(());
        }
    });

    thread::spawn(move || {
        // When each port's container was last asked to be found.
        let mut asked: HashMap<u32, Instant> = HashMap::new();
        loop {
            let wait = pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(|held| held.deadline.saturating_duration_since(Instant::now()))
                .min()
                .map_or(IDLE_WAIT, |wait| wait.min(DISCOVER_RETRY));
            if let Err(RecvTimeoutError::Disconnected) = woken.recv_timeout(wait) {
                return;
            }
            let now = Instant::now();
            let verdicts = {
                let mut pending = pending.lock().unwrap_or_else(PoisonError::into_inner);
                let verdicts = release(&mut pending, now, |held| {
                    held.source
                        .and_then(|source| directory.source(source))
                        .is_some_and(|info| sent_by(held, &info))
                });
                for port in ports_to_discover(&pending, &mut asked, now) {
                    let _ = discover.send(port);
                }
                verdicts
            };
            for (id, verdict) in verdicts {
                debug!(id, ?verdict, "releasing held packet");
                if let Err(error) = writer.verdict(id, verdict) {
                    warn!(%error, "failed to release a held packet");
                }
            }
        }
    });

    Ok(SourceHold { wakes: vec![wake] })
}

/// The bridge ports of `pending` packets whose containers are to be looked for now: once
/// per port, and again only after [`DISCOVER_RETRY`]. `asked` remembers when each port
/// was last asked for, and forgets ports that haven't been for a while.
fn ports_to_discover(
    pending: &[Held],
    asked: &mut HashMap<u32, Instant>,
    now: Instant,
) -> Vec<u32> {
    asked.retain(|_, when| now.saturating_duration_since(*when) < DISCOVER_RETRY * 10);
    let mut ports = Vec::new();
    for port in pending.iter().filter_map(|held| held.port) {
        let due = asked
            .get(&port)
            .is_none_or(|when| now.saturating_duration_since(*when) >= DISCOVER_RETRY);
        if due {
            asked.insert(port, now);
            ports.push(port);
        }
    }
    ports
}

/// The source address of a held IPv4 packet, or the address an ARP packet announces.
fn source_address(payload: &[u8]) -> Option<IpAddr> {
    Ipv4Packet::parse(payload)
        .map(|packet| packet.source)
        .or_else(|| ArpPacket::parse(payload).map(|packet| packet.sender))
        .map(IpAddr::V4)
}

/// Take the packets that can be released from `pending`: replay those whose source is now
/// known, and those past their deadline with the mark that denies them.
/// Whether `held` matches the source it claims, as the rules check it: the MAC only when
/// Docker reported one, and the port only where Portcullis found it. A container without a
/// port can't have sent anything.
fn sent_by(held: &Held, info: &SourceInfo) -> bool {
    (info.mac.is_none() || info.mac == held.mac)
        && match info.port {
            PortState::Known(port) => Some(port) == held.port,
            PortState::Unknown => true,
            PortState::Absent => false,
        }
}

fn release(
    pending: &mut Vec<Held>,
    now: Instant,
    known: impl Fn(&Held) -> bool,
) -> Vec<(u32, QueueVerdict)> {
    let mut verdicts = Vec::new();
    pending.retain(|held| {
        let verdict = if known(held) {
            QueueVerdict::Repeat { mark: None }
        } else if held.source.is_none() || now >= held.deadline {
            QueueVerdict::Repeat {
                mark: Some(HOLD_EXPIRED_MARK),
            }
        } else {
            return true;
        };
        verdicts.push((held.id, verdict));
        false
    });
    verdicts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("ip")
    }

    #[test]
    fn replays_packets_of_sources_that_became_known() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(3);
        let mut pending = vec![
            Held {
                id: 1,
                source: Some(ip("172.18.0.2")),
                mac: None,
                port: None,
                deadline,
            },
            Held {
                id: 2,
                source: Some(ip("172.18.0.3")),
                mac: None,
                port: None,
                deadline,
            },
        ];
        let verdicts = release(&mut pending, now, |held| {
            held.source == Some(ip("172.18.0.2"))
        });
        assert_eq!(verdicts, vec![(1, QueueVerdict::Repeat { mark: None })]);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.first().map(|held| held.id), Some(2));
    }

    #[test]
    fn asks_for_each_port_once_until_the_retry_is_due() {
        let start = Instant::now();
        let held = |id, port| Held {
            id,
            source: Some(ip("172.18.0.2")),
            mac: None,
            port,
            deadline: start + Duration::from_secs(2),
        };
        let pending = vec![
            held(1, Some(7)),
            held(2, Some(7)),
            held(3, Some(8)),
            held(4, None),
        ];
        let mut asked = HashMap::new();
        assert_eq!(ports_to_discover(&pending, &mut asked, start), vec![7, 8]);
        // Asked already, not yet due.
        let soon = start + DISCOVER_RETRY / 2;
        assert_eq!(
            ports_to_discover(&pending, &mut asked, soon),
            Vec::<u32>::new()
        );
        // Due again.
        let later = start + DISCOVER_RETRY;
        assert_eq!(ports_to_discover(&pending, &mut asked, later), vec![7, 8]);
        // Ports nothing is held from anymore are forgotten.
        let much_later = later + DISCOVER_RETRY * 10;
        assert_eq!(
            ports_to_discover(&[], &mut asked, much_later),
            Vec::<u32>::new()
        );
        assert!(asked.is_empty());
    }

    #[test]
    fn takes_the_source_of_arp_from_the_address_it_announces() {
        use crate::nfnetlink::tests::{arp, ipv4, udp};
        assert_eq!(
            source_address(&arp([2, 0, 0, 0, 0, 1], [172, 18, 0, 5], [172, 18, 0, 1])),
            Some(ip("172.18.0.5"))
        );
        assert_eq!(
            source_address(&ipv4([172, 18, 0, 6], [1; 4], 17, &udp(1, 2, b""))),
            Some(ip("172.18.0.6"))
        );
    }

    #[test]
    fn matches_packets_to_their_source_as_the_rules_do() {
        let mac = Some(MacAddress::new([2, 0, 0, 0, 0, 1]));
        let held = |port| Held {
            id: 1,
            source: Some(ip("172.18.0.2")),
            mac,
            port,
            deadline: Instant::now(),
        };
        let info = |port| SourceInfo {
            container: "web".to_string(),
            network: "net0".to_string(),
            mac,
            port,
            monitor: false,
            quarantine: true,
            ipv6_network: false,
            domains: None,
        };
        assert!(sent_by(&held(Some(7)), &info(PortState::Known(7))));
        assert!(!sent_by(&held(Some(8)), &info(PortState::Known(7))));
        // Where its port couldn't be found, by address and MAC.
        assert!(sent_by(&held(Some(8)), &info(PortState::Unknown)));
        assert!(!sent_by(
            &Held {
                mac: None,
                ..held(Some(8))
            },
            &info(PortState::Unknown)
        ));
        // A container without a port (stopping) sent nothing: whoever did borrowed it.
        assert!(!sent_by(&held(Some(8)), &info(PortState::Absent)));
    }

    #[test]
    fn denies_packets_whose_source_stays_unknown() {
        let now = Instant::now();
        let mut pending = vec![
            Held {
                id: 1,
                source: Some(ip("10.99.0.5")),
                mac: None,
                port: None,
                deadline: now,
            },
            Held {
                id: 2,
                source: None,
                mac: None,
                port: None,
                deadline: now + Duration::from_secs(3),
            },
        ];
        let expired = QueueVerdict::Repeat {
            mark: Some(HOLD_EXPIRED_MARK),
        };
        let verdicts = release(&mut pending, now, |_| false);
        assert_eq!(verdicts, vec![(1, expired), (2, expired)]);
        assert_eq!(pending, [] as [Held; 0]);
    }
}
