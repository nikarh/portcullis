//! Transparent inspection of DNS answers to managed containers (NFQUEUE).
//!
//! The firewall holds every DNS answer to a managed container until Portcullis has looked
//! at it. For each answer Portcullis:
//! 1. allows the returned addresses for `host:` rules matching the name (or a CNAME it
//!    resolved through), so the container can connect to whatever it was told;
//! 2. remembers which container got which address for which name, to label connection
//!    events with domains;
//! 3. publishes a DNS event;
//!
//! and only then releases the answer. The container's queries still go to the resolver it
//! chose; Portcullis never answers or changes anything.

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RData;
use tracing::{debug, warn};

use crate::connection_log::SharedHosts;
use crate::directory::Directory;
use crate::dns::normalize;
use crate::events::{Dns, Event, EventBus};
use crate::firewall::{LogAllowed, NftablesFirewall};
use crate::nfnetlink::{
    Ipv4Packet, NfqueueSocket, Overruns, PROTOCOL_TCP, QueueOverflow, QueueVerdict, is_overrun,
};

/// Start inspecting DNS answers held in NFQUEUE `queue`. Answers are reported as events
/// where allowed connections are (`log_allowed`).
pub fn spawn(
    queue: u16,
    log_allowed: LogAllowed,
    firewall: Arc<NftablesFirewall>,
    directory: Arc<Directory>,
    hosts: SharedHosts,
    bus: EventBus,
    failed: Sender<String>,
) -> io::Result<JoinHandle<()>> {
    let mut socket = NfqueueSocket::bind(queue, QueueOverflow::Accept)?;
    Ok(thread::spawn(move || {
        let mut overruns = Overruns::default();
        loop {
            let packets = match socket.receive() {
                Ok(packets) => packets,
                Err(error) if is_overrun(&error) => {
                    if overruns.report() {
                        warn!(
                            "DNS answers came faster than they could be inspected; the kernel let some through uninspected, so their names may be missing from events and their addresses from host: rules"
                        );
                    }
                    continue;
                }
                Err(error) => {
                    let _ = failed.send(format!("reading held DNS answers failed: {error}"));
                    return;
                }
            };
            for packet in packets {
                if let Some(answer) = Answer::parse(&packet.payload) {
                    allow_addresses(&answer, &firewall, &directory, &hosts);
                    let monitor = directory
                        .source(answer.container)
                        .is_some_and(|info| info.monitor);
                    if log_allowed.logs(monitor) {
                        bus.publish(&Event::Dns(answer.event(&directory)));
                    }
                }
                // Answers are always released; inspection never blocks DNS.
                if let Err(error) = socket.verdict(packet.id, QueueVerdict::Accept) {
                    warn!(%error, "failed to release a DNS answer");
                }
            }
        }
    }))
}

/// A DNS answer to a container.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Answer {
    container: IpAddr,
    resolver: IpAddr,
    /// The name asked for, normalized.
    name: String,
    record_type: String,
    response_code: String,
    /// CNAME targets in the answer, normalized.
    aliases: Vec<String>,
    /// Addresses and their TTL.
    addresses: Vec<(IpAddr, Duration)>,
}

impl Answer {
    fn parse(payload: &[u8]) -> Option<Self> {
        let packet = Ipv4Packet::parse(payload)?;
        let data = match packet.protocol {
            // DNS over TCP prefixes messages with their length; segments without a complete
            // message (handshakes, split messages) are skipped.
            PROTOCOL_TCP => {
                let length =
                    usize::from(u16::from_be_bytes(packet.data.get(..2)?.try_into().ok()?));
                packet.data.get(2..2 + length)?
            }
            _ => packet.data,
        };
        let message = Message::from_vec(data).ok()?;
        if message.metadata.message_type != MessageType::Response {
            return None;
        }
        let query = message.queries.first()?;
        let name = normalize(&query.name().to_utf8());

        // The name's CNAME chain, then the addresses of the names in it. Records of other
        // names don't say anything about this one: they mustn't count for host: rules that
        // match it.
        let records: Vec<(String, &RData, u32)> = message
            .answers
            .iter()
            .map(|record| (normalize(&record.name.to_utf8()), &record.data, record.ttl))
            .collect();
        let mut aliases: Vec<String> = Vec::new();
        let mut current = name.clone();
        while let Some(target) = records.iter().find_map(|(owner, data, _)| match data {
            RData::CNAME(target) if *owner == current => Some(normalize(&target.0.to_utf8())),
            _ => None,
        }) {
            if target == name || aliases.contains(&target) {
                break;
            }
            aliases.push(target.clone());
            current = target;
        }
        let in_chain = |owner: &String| *owner == name || aliases.contains(owner);
        let addresses = records
            .iter()
            .filter(|(owner, _, _)| in_chain(owner))
            .filter_map(|(_, data, ttl)| {
                let ttl = Duration::from_secs(u64::from(*ttl));
                match data {
                    RData::A(address) => Some((IpAddr::V4(address.0), ttl)),
                    RData::AAAA(address) => Some((IpAddr::V6(address.0), ttl)),
                    _ => None,
                }
            })
            .collect();

        Some(Self {
            container: IpAddr::V4(packet.destination),
            resolver: IpAddr::V4(packet.source),
            name,
            record_type: query.query_type().to_string(),
            response_code: message.metadata.response_code.to_string(),
            aliases,
            addresses,
        })
    }

    fn event(&self, directory: &Directory) -> Dns {
        let info = directory.attributed(self.container);
        Dns {
            container: info.as_ref().map(|info| info.container.clone()),
            network: info.map(|info| info.network),
            resolver: self.resolver,
            name: self.name.clone(),
            record_type: self.record_type.clone(),
            response_code: self.response_code.clone(),
            aliases: self.aliases.clone(),
            answers: self.addresses.iter().map(|(address, _)| *address).collect(),
        }
    }
}

/// Allow the answer's addresses for matching `host:` rules and remember them for attribution.
fn allow_addresses(
    answer: &Answer,
    firewall: &NftablesFirewall,
    directory: &Directory,
    hosts: &SharedHosts,
) {
    if answer.addresses.is_empty() {
        return;
    }
    // Only the receiving container's rules learn from its answers.
    let Some(owner) = directory.attributed(answer.container) else {
        return;
    };
    let now = Instant::now();
    let mut names = Vec::with_capacity(1 + answer.aliases.len());
    names.push(answer.name.clone());
    names.extend(answer.aliases.iter().cloned());

    for set in directory.host_sets_for(&owner.container, &names) {
        let allowed: Vec<_> = {
            let mut hosts = hosts.lock().unwrap_or_else(PoisonError::into_inner);
            answer
                .addresses
                .iter()
                .filter_map(|(address, ttl)| {
                    let allowed_for =
                        hosts.observe(&owner.container, &set.host, *address, *ttl, now);
                    if allowed_for.is_none() {
                        debug!(container = %owner.container, host = %set.host, %address, "too many addresses for a hostname; not allowing more until some expire");
                    }
                    Some((*address, allowed_for?))
                })
                .collect()
        };
        debug!(host = %set.host, ?allowed, "allowing addresses from a DNS answer");
        if let Err(error) = firewall.add_host_addresses(&set, &allowed) {
            // The set may be gone after a concurrent rule update; the next update includes
            // the addresses anyway.
            debug!(%error, host = %set.host, "failed to add addresses to a hostname set");
        }
    }

    for (address, ttl) in &answer.addresses {
        let valid_for = (*ttl).max(Duration::from_secs(3600));
        directory.observe(answer.container, *address, &answer.name, valid_for);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, CNAME};
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use super::*;
    use crate::nfnetlink::PROTOCOL_UDP;
    use crate::nfnetlink::tests::{ipv4, udp};

    fn response() -> Vec<u8> {
        let name = Name::from_str("www.Example.test.").expect("name");
        let target = Name::from_str("cdn.example.net.").expect("name");
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            name,
            300,
            RData::CNAME(CNAME(target.clone())),
        ));
        message.add_answer(Record::from_rdata(
            target,
            60,
            RData::A(A("198.51.100.3".parse().expect("ip"))),
        ));
        message.to_vec().expect("dns")
    }

    #[test]
    fn parses_udp_answers() {
        let payload = ipv4(
            [198, 51, 100, 2],
            [172, 18, 0, 2],
            PROTOCOL_UDP,
            &udp(53, 5000, &response()),
        );
        let answer = Answer::parse(&payload).expect("answer");
        assert_eq!(
            answer.container,
            "172.18.0.2".parse::<IpAddr>().expect("ip")
        );
        assert_eq!(
            answer.resolver,
            "198.51.100.2".parse::<IpAddr>().expect("ip")
        );
        assert_eq!(answer.name, "www.example.test");
        assert_eq!(answer.record_type, "A");
        assert_eq!(answer.aliases, vec!["cdn.example.net"]);
        assert_eq!(
            answer.addresses,
            vec![("198.51.100.3".parse().expect("ip"), Duration::from_secs(60))]
        );
    }

    #[test]
    fn only_counts_addresses_of_the_name_and_its_aliases() {
        let name = Name::from_str("x.api.test.").expect("name");
        let alias = Name::from_str("edge.cdn.test.").expect("name");
        let other = Name::from_str("evil.test.").expect("name");
        let a = |name: &Name, address: &str| {
            Record::from_rdata(name.clone(), 60, RData::A(A(address.parse().expect("ip"))))
        };
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        message.add_answer(a(&other, "6.6.6.6"));
        message.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::CNAME(CNAME(alias.clone())),
        ));
        // A CNAME of another name doesn't make it an alias of this one.
        message.add_answer(Record::from_rdata(
            other.clone(),
            60,
            RData::CNAME(CNAME(Name::from_str("y.api.test.").expect("name"))),
        ));
        message.add_answer(a(&alias, "198.51.100.7"));
        message.add_answer(a(&name, "198.51.100.8"));
        let payload = ipv4(
            [198, 51, 100, 2],
            [172, 18, 0, 2],
            PROTOCOL_UDP,
            &udp(53, 5000, &message.to_vec().expect("dns")),
        );
        let answer = Answer::parse(&payload).expect("answer");
        assert_eq!(answer.aliases, vec!["edge.cdn.test"]);
        let addresses: Vec<_> = answer
            .addresses
            .iter()
            .map(|(address, _)| *address)
            .collect();
        assert_eq!(
            addresses,
            ["198.51.100.7", "198.51.100.8"].map(|address| address.parse::<IpAddr>().expect("ip"))
        );
    }

    #[test]
    fn stops_at_cname_loops() {
        let name = Name::from_str("a.test.").expect("name");
        let other = Name::from_str("b.test.").expect("name");
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::CNAME(CNAME(other.clone())),
        ));
        message.add_answer(Record::from_rdata(other, 60, RData::CNAME(CNAME(name))));
        let payload = ipv4(
            [198, 51, 100, 2],
            [172, 18, 0, 2],
            PROTOCOL_UDP,
            &udp(53, 5000, &message.to_vec().expect("dns")),
        );
        assert_eq!(
            Answer::parse(&payload).expect("answer").aliases,
            vec!["b.test"]
        );
    }

    #[test]
    fn parses_tcp_answers() {
        let dns = response();
        let mut segment = 53_u16.to_be_bytes().to_vec();
        segment.extend_from_slice(&5000_u16.to_be_bytes());
        segment.extend_from_slice(&[0; 8]);
        segment.extend_from_slice(&[0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        segment.extend_from_slice(&u16::try_from(dns.len()).expect("length").to_be_bytes());
        segment.extend_from_slice(&dns);
        let payload = ipv4([198, 51, 100, 2], [172, 18, 0, 2], PROTOCOL_TCP, &segment);
        assert_eq!(
            Answer::parse(&payload).expect("answer").name,
            "www.example.test"
        );
    }

    #[test]
    fn ignores_queries_and_other_traffic() {
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(
            Name::from_str("a.test.").expect("name"),
            RecordType::A,
        ));
        let payload = ipv4(
            [172, 18, 0, 2],
            [8, 8, 8, 8],
            PROTOCOL_UDP,
            &udp(5000, 53, &query.to_vec().expect("dns")),
        );
        assert!(Answer::parse(&payload).is_none());
        assert!(
            Answer::parse(&ipv4(
                [1, 1, 1, 1],
                [2, 2, 2, 2],
                PROTOCOL_UDP,
                &udp(53, 1, b"junk")
            ))
            .is_none()
        );
    }
}
