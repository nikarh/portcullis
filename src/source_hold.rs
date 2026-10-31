//! Holds packets from sources the rules don't know yet, instead of denying them.
//!
//! A container can start sending before Portcullis has seen it start and applied rules for
//! it. Those first packets come from an address, MAC and bridge port the rules don't know, which looks
//! the same as a spoofed source. Docker also hands the address of a removed container to
//! the next one at once, with a new MAC. The bridge table queues them (NFQUEUE) instead of denying them, and
//! this module holds them:
//!
//! - once a rule update makes the source (address, MAC and port) known, a packet is replayed (`NF_REPEAT`): the
//!   kernel runs it through the rules again, now with the container's own chain, and it is
//!   allowed or denied as if the rules had been there from the start;
//! - if the source is still unknown after a grace period, the packet is replayed with a
//!   mark that the bridge table denies, and reports, like any spoofed source.
//!
//! The queue has no bypass: while Portcullis isn't reading it, such packets are held until
//! the kernel's queue is full and then dropped, so the hold fails closed.

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{RecvTimeoutError, Sender, unbounded};
use tracing::{debug, error, warn};

use crate::directory::Directory;
use crate::firewall::HOLD_EXPIRED_MARK;
use crate::model::MacAddress;
use crate::nfnetlink::{Ipv4Packet, NfqueueSocket, QueueVerdict};

/// Longest wait when nothing is held.
const IDLE_WAIT: Duration = Duration::from_secs(3600);

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
    wake: Sender<()>,
}

impl SourceHold {
    /// Rules were updated: release packets whose source is now known.
    pub fn rules_applied(&self) {
        let _ = self.wake.send(());
    }
}

/// Start holding packets queued in NFQUEUE `queue`, for at most `grace` each.
pub fn spawn(queue: u16, grace: Duration, directory: Arc<Directory>) -> io::Result<SourceHold> {
    let mut socket = NfqueueSocket::bind(queue)?;
    let writer = socket.verdict_writer()?;
    let pending = Arc::new(Mutex::new(Vec::<Held>::new()));
    let (wake, woken) = unbounded::<()>();

    let receiving = Arc::clone(&pending);
    let wake_on_packet = wake.clone();
    thread::spawn(move || {
        loop {
            let packets = match socket.receive() {
                Ok(packets) => packets,
                Err(error) => {
                    error!(%error, "reading held packets failed; packets from unknown sources are dropped from now on");
                    return;
                }
            };
            let now = Instant::now();
            receiving
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(packets.iter().map(|packet| Held {
                    id: packet.id,
                    source:
                        Ipv4Packet::parse(&packet.payload).map(|parsed| IpAddr::V4(parsed.source)),
                    mac: packet.hwaddr,
                    port: packet.physindev,
                    deadline: now + grace,
                }));
            // The rules may already know the source.
            let _ = wake_on_packet.send(());
        }
    });

    thread::spawn(move || {
        loop {
            let wait = pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(|held| held.deadline.saturating_duration_since(Instant::now()))
                .min()
                .unwrap_or(IDLE_WAIT);
            if let Err(RecvTimeoutError::Disconnected) = woken.recv_timeout(wait) {
                return;
            }
            let verdicts = {
                let mut pending = pending.lock().unwrap_or_else(PoisonError::into_inner);
                release(&mut pending, Instant::now(), |held| {
                    // The rules check the MAC only when Docker reported one, and the port
                    // only where Portcullis found it.
                    held.source
                        .and_then(|source| directory.source(source))
                        .is_some_and(|info| {
                            (info.mac.is_none() || info.mac == held.mac)
                                && (info.port.is_none() || info.port == held.port)
                        })
                })
            };
            for (id, verdict) in verdicts {
                debug!(id, ?verdict, "releasing held packet");
                if let Err(error) = writer.verdict(id, verdict) {
                    warn!(%error, "failed to release a held packet");
                }
            }
        }
    });

    Ok(SourceHold { wake })
}

/// Take the packets that can be released from `pending`: replay those whose source is now
/// known, and those past their deadline with the mark that denies them.
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
        assert!(pending.is_empty());
    }
}
