//! Limits the names containers can look up (`portcullis.domains.*`).
//!
//! A container that may use a resolver can otherwise look up any name through it, and a
//! name can carry data: a compromised container can send whatever it wants to whoever runs
//! the DNS servers of a domain it chose, and get answers back, through a resolver it is
//! allowed to use. For containers with `portcullis.domains` labels, the firewall holds
//! every DNS query (NFQUEUE) until Portcullis has read the names it asks for. A query for
//! names the labels (or the container's `host:` rules) allow continues through the rules
//! as any other; anything else, including traffic to port 53 that isn't a DNS query, is
//! rejected, and the lookup fails at once. Portcullis never answers or changes queries.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use hickory_proto::op::{Message, MessageType};
use tracing::{debug, warn};

use crate::directory::Directory;
use crate::dns::{domain_matches, normalize};
use crate::events::{Connection, Event, EventBus, Reason, Verdict};
use crate::firewall::{DNS_ALLOWED_MARK, DNS_DENIED_MARK};
use crate::nfnetlink::{
    Ipv4Packet, NfqueueSocket, Overruns, PROTOCOL_TCP, PROTOCOL_UDP, QueueVerdict, is_overrun,
};

/// The same denied name of the same container is reported at most once per interval.
const REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// Start checking DNS queries held in NFQUEUE `queue`. If reading fails for good, the
/// thread says why on `failed` and ends.
pub fn spawn(
    queue: u16,
    directory: Arc<Directory>,
    bus: EventBus,
    failed: Sender<String>,
) -> io::Result<JoinHandle<()>> {
    let mut socket = NfqueueSocket::bind(queue)?;
    Ok(thread::spawn(move || {
        let mut reported: HashMap<(IpAddr, String), Instant> = HashMap::new();
        let mut overruns = Overruns::default();
        loop {
            let packets = match socket.receive() {
                Ok(packets) => packets,
                Err(error) if is_overrun(&error) => {
                    if overruns.report() {
                        warn!(
                            "DNS queries came faster than they could be checked; the kernel dropped some, and those lookups are retried or fail"
                        );
                    }
                    continue;
                }
                Err(error) => {
                    let _ = failed.send(format!("reading held DNS queries failed: {error}"));
                    return;
                }
            };
            for packet in packets {
                let decision = decide(&packet.payload, &directory);
                let allowed = match &decision {
                    Decision::Allowed => true,
                    Decision::Denied { monitor, .. } => *monitor,
                };
                if let Decision::Denied { event, .. } = decision {
                    let now = Instant::now();
                    reported.retain(|_, at| now.duration_since(*at) < REPORT_INTERVAL);
                    let key = (
                        event.source.unwrap_or(IpAddr::from([0, 0, 0, 0])),
                        event.query.clone().unwrap_or_default(),
                    );
                    if reported.insert(key, now).is_none() {
                        bus.publish(&Event::Connection(*event));
                    }
                }
                let mark = if allowed {
                    DNS_ALLOWED_MARK
                } else {
                    DNS_DENIED_MARK
                };
                debug!(id = packet.id, allowed, "releasing held DNS query");
                if let Err(error) =
                    socket.verdict(packet.id, QueueVerdict::Repeat { mark: Some(mark) })
                {
                    warn!(%error, "failed to release a DNS query");
                }
            }
        }
    }))
}

#[derive(Debug)]
enum Decision {
    Allowed,
    /// Denied, or in monitor mode, would be.
    Denied {
        monitor: bool,
        event: Box<Connection>,
    },
}

/// Decide on a held packet of a container's DNS traffic.
fn decide(payload: &[u8], directory: &Directory) -> Decision {
    let Some(packet) = Ipv4Packet::parse(payload) else {
        return denied(None, None, "not an IPv4 packet", directory);
    };
    // TCP segments without data: the handshake, acknowledgements, the end.
    if packet.protocol == PROTOCOL_TCP && packet.data.is_empty() {
        return Decision::Allowed;
    }
    let info = directory.source(IpAddr::V4(packet.source));
    let Some(domains) = info.as_ref().and_then(|info| info.domains.as_ref()) else {
        return denied(Some(&packet), None, "from an unknown container", directory);
    };
    let names = match query_names(&packet) {
        Ok(names) => names,
        Err(reason) => return denied(Some(&packet), None, reason, directory),
    };
    match names
        .iter()
        .find(|name| !domains.iter().any(|pattern| domain_matches(pattern, name)))
    {
        None => Decision::Allowed,
        Some(name) => denied(
            Some(&packet),
            Some(name.clone()),
            "the name isn't allowed by portcullis.domains",
            directory,
        ),
    }
}

/// The names a packet's DNS queries ask for, or why it isn't a DNS query.
fn query_names(packet: &Ipv4Packet<'_>) -> Result<Vec<String>, &'static str> {
    let messages: Vec<&[u8]> = match packet.protocol {
        PROTOCOL_UDP => vec![packet.data],
        // Over TCP, each message comes with its length; a segment must hold whole ones.
        PROTOCOL_TCP => {
            let mut messages = Vec::new();
            let mut data = packet.data;
            while !data.is_empty() {
                let length = data
                    .get(..2)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(|bytes| usize::from(u16::from_be_bytes(bytes)))
                    .ok_or("a DNS message split over TCP segments")?;
                let message = data
                    .get(2..2 + length)
                    .ok_or("a DNS message split over TCP segments")?;
                messages.push(message);
                data = data.get(2 + length..).unwrap_or_default();
            }
            messages
        }
        _ => return Err("not TCP or UDP"),
    };
    let mut names = Vec::new();
    for data in messages {
        let message = Message::from_vec(data).map_err(|_| "not a DNS message")?;
        if message.metadata.message_type != MessageType::Query || message.queries.is_empty() {
            return Err("not a DNS query");
        }
        names.extend(
            message
                .queries
                .iter()
                .map(|query| normalize(&query.name().to_utf8())),
        );
    }
    Ok(names)
}

fn denied(
    packet: Option<&Ipv4Packet<'_>>,
    query: Option<String>,
    detail: &str,
    directory: &Directory,
) -> Decision {
    let source = packet.map(|packet| IpAddr::V4(packet.source));
    let info = source.and_then(|source| directory.source(source));
    let monitor = info.as_ref().is_some_and(|info| info.monitor);
    let event = Connection {
        verdict: if monitor {
            Verdict::WouldDeny
        } else {
            Verdict::Denied
        },
        reason: Reason::Dns,
        container: info.as_ref().map(|info| info.container.clone()),
        network: info.map(|info| info.network),
        protocol: match packet.map(|packet| packet.protocol) {
            Some(PROTOCOL_TCP) => "tcp".to_string(),
            _ => "udp".to_string(),
        },
        source,
        source_port: packet.and_then(|packet| packet.ports).map(|(port, _)| port),
        destination: packet.map(|packet| IpAddr::V4(packet.destination)),
        destination_port: packet.and_then(|packet| packet.ports).map(|(_, port)| port),
        destination_container: None,
        domain: None,
        domain_source: None,
        query,
        detail: Some(detail.to_string()),
    };
    Decision::Denied {
        monitor,
        event: Box::new(event),
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    use super::*;
    use crate::firewall::Plan;
    use crate::firewall::test_support::{self, MockResolver};
    use crate::model::{ContainerPolicy, EgressRule, EgressTarget};
    use crate::nfnetlink::tests::{ipv4, udp};

    fn directory() -> Directory {
        let mut state = test_support::icc_state();
        let policy = ContainerPolicy {
            domains: Some(vec!["*.github.com".to_string()]),
            egress: vec![EgressRule {
                target: EgressTarget::Hostname("API.stripe.com".to_string()),
                ports: Vec::new(),
            }],
            ..ContainerPolicy::default()
        };
        test_support::add_container(
            &mut state,
            "f",
            "filtered",
            &[("net0", "172.18.0.50", &[])],
            policy,
        );
        let plan = Plan::build(&state, &mut MockResolver::default(), &[], false);
        let directory = Directory::default();
        directory.update(&plan);
        directory
    }

    fn query(names: &[&str], message_type: MessageType) -> Vec<u8> {
        let mut message = Message::new(0, message_type, OpCode::Query);
        for name in names {
            message.add_query(Query::query(
                Name::from_ascii(name).expect("name"),
                RecordType::A,
            ));
        }
        message.to_vec().expect("dns")
    }

    fn from_filtered(data: &[u8]) -> Vec<u8> {
        ipv4(
            [172, 18, 0, 50],
            [8, 8, 8, 8],
            PROTOCOL_UDP,
            &udp(5000, 53, data),
        )
    }

    fn query_of(decision: &Decision) -> Option<&str> {
        match decision {
            Decision::Allowed => None,
            Decision::Denied { event, .. } => Some(event.query.as_deref().unwrap_or("-")),
        }
    }

    #[test]
    fn allows_listed_names_and_names_of_host_rules() {
        let directory = directory();
        for name in ["api.github.com.", "api.stripe.com", "Api.Stripe.Com."] {
            let packet = from_filtered(&query(&[name], MessageType::Query));
            assert!(
                matches!(decide(&packet, &directory), Decision::Allowed),
                "{name}"
            );
        }
    }

    #[test]
    fn denies_other_names_and_anything_that_isnt_a_query() {
        let directory = directory();
        let packet = from_filtered(&query(&["secret.evil.test"], MessageType::Query));
        let decision = decide(&packet, &directory);
        assert_eq!(query_of(&decision), Some("secret.evil.test"));
        let Decision::Denied { event, monitor } = decision else {
            unreachable!()
        };
        assert!(!monitor);
        assert_eq!(event.container.as_deref(), Some("filtered"));
        assert_eq!(event.verdict, Verdict::Denied);

        // Every name of a query must be allowed.
        let packet = from_filtered(&query(&["github.com", "x.github.com"], MessageType::Query));
        assert_eq!(query_of(&decide(&packet, &directory)), Some("github.com"));
        // Port 53 isn't a tunnel.
        let packet = from_filtered(b"not dns at all");
        assert_eq!(query_of(&decide(&packet, &directory)), Some("-"));
        let packet = from_filtered(&query(&["x.github.com"], MessageType::Response));
        assert_eq!(query_of(&decide(&packet, &directory)), Some("-"));
    }

    #[test]
    fn checks_queries_over_tcp() {
        let directory = directory();
        let tcp = |data: &[u8]| {
            let mut header = 40000_u16.to_be_bytes().to_vec();
            header.extend_from_slice(&53_u16.to_be_bytes());
            header.extend_from_slice(&[0; 8]);
            header.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
            header.extend_from_slice(data);
            ipv4([172, 18, 0, 50], [8, 8, 8, 8], PROTOCOL_TCP, &header)
        };
        // The handshake passes.
        assert!(matches!(decide(&tcp(&[]), &directory), Decision::Allowed));
        let message = query(&["x.github.com"], MessageType::Query);
        let mut framed = u16::try_from(message.len())
            .expect("length")
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&message);
        assert!(matches!(
            decide(&tcp(&framed), &directory),
            Decision::Allowed
        ));
        // A message split over segments can't be checked.
        let split = framed.get(..framed.len() - 3).expect("split");
        assert_eq!(query_of(&decide(&tcp(split), &directory)), Some("-"));
    }
}
