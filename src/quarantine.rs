//! Decides when a container misbehaves badly enough to be cut off from its networks.
//!
//! A well-behaved container never sends with an address or MAC that isn't its own, nor
//! frames enforced networks don't carry: Docker doesn't set it up to. Doing so takes a raw
//! socket and intent, so the first such denial is enough. Source denials that aren't forged
//! (see [`Connection::forged`]) don't count: the container's own traffic, judged by rules
//! that didn't know it yet, or its address on another of its networks. A container whose traffic is
//! denied at a high rate (probing, scanning, flooding) is cut off too, past a threshold of
//! denied flows per minute.
//!
//! The decision is taken here, on the thread reading the firewall's reports; the main loop
//! applies it (see `--quarantine`).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;

use crate::directory::Directory;
use crate::events::{Connection, Reason, Verdict};

/// How long denials are counted towards the threshold.
const WINDOW: Duration = Duration::from_secs(60);
/// The same container is reported to the main loop at most this often.
const REPEAT_AFTER: Duration = Duration::from_secs(10);

/// A container that misbehaved, by name, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Misbehaviour {
    pub container: String,
    pub reason: String,
}

pub struct Watch {
    sender: Sender<Misbehaviour>,
    /// Denied flows per minute past which a container is cut off.
    threshold: usize,
    /// Per container: when its window started, and its denials in it.
    denials: HashMap<String, (Instant, usize)>,
    reported: HashMap<String, Instant>,
}

impl Watch {
    pub fn new(sender: Sender<Misbehaviour>, threshold: usize) -> Self {
        Self {
            sender,
            threshold,
            denials: HashMap::new(),
            reported: HashMap::new(),
        }
    }

    /// Look at a reported connection.
    pub fn observe(&mut self, connection: &Connection, directory: &Directory) {
        self.observe_at(connection, directory, Instant::now());
    }

    fn observe_at(&mut self, connection: &Connection, directory: &Directory, now: Instant) {
        if connection.verdict != Verdict::Denied {
            return;
        }
        let Some(container) = &connection.container else {
            return;
        };
        let Some(info) = directory.container(container) else {
            return;
        };
        if !info.quarantine {
            return;
        }
        let reason = match connection.reason {
            // IPv6 is expected from containers of networks with IPv6 enabled.
            Reason::Frame if connection.protocol == "ipv6" && info.ipv6_network => None,
            Reason::Source if !connection.forged => None,
            Reason::Source | Reason::Frame => Some(format!(
                "sent {}{}",
                connection.protocol,
                connection
                    .detail
                    .as_ref()
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default()
            )),
            _ => self.count(container, now),
        };
        let Some(reason) = reason else {
            return;
        };
        if self
            .reported
            .get(container)
            .is_some_and(|at| now.duration_since(*at) < REPEAT_AFTER)
        {
            return;
        }
        self.reported.insert(container.clone(), now);
        let _ = self.sender.send(Misbehaviour {
            container: container.clone(),
            reason,
        });
    }

    /// Count a denial; the reason, once there are too many.
    fn count(&mut self, container: &str, now: Instant) -> Option<String> {
        self.denials
            .retain(|_, (started, _)| now.duration_since(*started) < WINDOW);
        let (_, count) = self
            .denials
            .entry(container.to_string())
            .or_insert((now, 0));
        *count += 1;
        (*count > self.threshold).then(|| {
            format!(
                "more than {} denied connections within {} seconds",
                self.threshold,
                WINDOW.as_secs()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use crossbeam_channel::unbounded;

    use super::*;
    use crate::firewall::Plan;
    use crate::firewall::test_support::{self, MockResolver};

    fn directory() -> Directory {
        let plan = Plan::build(
            &test_support::icc_state(),
            &mut MockResolver::default(),
            &[],
            false,
        );
        let directory = Directory::default();
        directory.update(&plan);
        directory
    }

    fn denied(reason: Reason, protocol: &str, port: u16) -> Connection {
        Connection {
            verdict: Verdict::Denied,
            reason,
            container: Some("web".to_string()),
            network: None,
            protocol: protocol.to_string().into(),
            source: None,
            source_port: None,
            destination: None,
            destination_port: Some(port),
            destination_container: None,
            domain: None,
            domain_source: None,
            query: None,
            detail: Some("uses the address of other".into()),
            mid_stream: false,
            forged: reason == Reason::Source,
        }
    }

    #[test]
    fn cuts_off_a_container_sending_as_someone_else_at_once() {
        let (sender, receiver) = unbounded();
        let mut watch = Watch::new(sender, 100);
        let now = Instant::now();
        watch.observe_at(&denied(Reason::Source, "udp", 9), &directory(), now);
        assert_eq!(
            receiver.try_recv().ok(),
            Some(Misbehaviour {
                container: "web".to_string(),
                reason: "sent udp (uses the address of other)".to_string(),
            })
        );
        // Reported once for a while.
        watch.observe_at(&denied(Reason::Source, "udp", 9), &directory(), now);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn cuts_off_a_container_past_the_rate_of_denials() {
        let (sender, receiver) = unbounded();
        let mut watch = Watch::new(sender, 3);
        let directory = directory();
        let now = Instant::now();
        for port in 0..3 {
            watch.observe_at(&denied(Reason::Egress, "tcp", port), &directory, now);
        }
        assert!(receiver.try_recv().is_err());
        // The window starts over.
        let later = now + WINDOW;
        for port in 0..3 {
            watch.observe_at(&denied(Reason::Egress, "tcp", port), &directory, later);
        }
        assert!(receiver.try_recv().is_err());
        watch.observe_at(&denied(Reason::Egress, "tcp", 4), &directory, later);
        assert!(
            receiver
                .try_recv()
                .is_ok_and(|misbehaviour| misbehaviour.reason.starts_with("more than 3"))
        );
    }

    #[test]
    fn leaves_containers_whose_source_denials_werent_forged() {
        let (sender, receiver) = unbounded();
        let mut watch = Watch::new(sender, 100);
        let mut early = denied(Reason::Source, "arp", 0);
        early.forged = false;
        early.detail = Some("sent before its rules were in place".into());
        watch.observe(&early, &directory());
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn leaves_containers_that_opted_out_or_were_only_watched() {
        let (sender, receiver) = unbounded();
        let mut watch = Watch::new(sender, 100);
        let mut monitored = denied(Reason::Source, "udp", 9);
        monitored.verdict = Verdict::WouldDeny;
        watch.observe(&monitored, &directory());
        let mut unknown = denied(Reason::Source, "udp", 9);
        unknown.container = None;
        watch.observe(&unknown, &directory());
        assert!(receiver.try_recv().is_err());
    }
}
