//! Turns decisions logged by the firewall rules (NFLOG) into connection events.
//!
//! Every accept or deny rule that reports carries a log prefix `pc:<verdict>:<reason>`:
//! verdict `a` (allowed), `d` (denied) or `w` (would deny, monitor mode), and the reason
//! (`egress`, `dns`, `icc`, `source`). The packet itself gives the addresses and ports; the
//! directory gives the containers and domains.

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use tracing::{debug, error};

use crate::directory::Directory;
use crate::dns::{HostAddresses, SystemUpstreamResolver};
use crate::events::{
    Connection, DomainSource, Event, EventBus, Reason, Verdict, Warning, WarningKind,
};
use crate::firewall::LOG_PREFIX;
use crate::nfnetlink::{Ipv4Packet, LoggedPacket, NflogSocket, PROTOCOL_TCP, PROTOCOL_UDP};

/// Known hostname addresses, shared with planning and DNS inspection.
pub type SharedHosts = Arc<Mutex<HostAddresses<SystemUpstreamResolver>>>;

/// `ENOBUFS`: the kernel dropped messages because the socket's buffer was full.
const ENOBUFS: i32 = 105;
/// At most one "events lost" warning per interval.
const LOST_WARNING_INTERVAL: Duration = Duration::from_secs(60);

/// Start reading logged decisions from NFLOG `group`.
pub fn spawn(
    group: u16,
    directory: Arc<Directory>,
    hosts: SharedHosts,
    bus: EventBus,
) -> io::Result<JoinHandle<()>> {
    let mut socket = NflogSocket::bind(group)?;
    Ok(thread::spawn(move || {
        let mut last_lost: Option<Instant> = None;
        loop {
            match socket.receive() {
                Ok(packets) => {
                    for packet in packets {
                        if let Some(event) = connection_event(&packet, &directory, &hosts) {
                            bus.publish(&Event::Connection(event));
                        }
                    }
                }
                Err(error) if error.raw_os_error() == Some(ENOBUFS) => {
                    if last_lost.is_none_or(|at| at.elapsed() >= LOST_WARNING_INTERVAL) {
                        last_lost = Some(Instant::now());
                        bus.publish(&Event::Warning(Warning {
                            kind: WarningKind::EventsLost,
                            container: None,
                            message: "connection events were lost: the kernel produced them faster than they were read".to_string(),
                        }));
                    }
                }
                Err(error) => {
                    error!(%error, "reading logged connections failed; connection events stop");
                    return;
                }
            }
        }
    }))
}

/// Verdict and reason of a log prefix.
fn parse_prefix(prefix: &str) -> Option<(Verdict, Reason)> {
    let mut parts = prefix.split(':');
    if parts.next()? != LOG_PREFIX {
        return None;
    }
    let verdict = match parts.next()? {
        "a" => Verdict::Allowed,
        "d" => Verdict::Denied,
        "w" => Verdict::WouldDeny,
        _ => return None,
    };
    let reason = match parts.next()? {
        "egress" => Reason::Egress,
        "dns" => Reason::Dns,
        "icc" => Reason::Icc,
        "source" => Reason::Source,
        _ => return None,
    };
    Some((verdict, reason))
}

fn connection_event(
    packet: &LoggedPacket,
    directory: &Directory,
    hosts: &SharedHosts,
) -> Option<Connection> {
    let Some((verdict, reason)) = parse_prefix(&packet.prefix) else {
        debug!(prefix = %packet.prefix, "ignoring packet with an unknown log prefix");
        return None;
    };
    let ip = Ipv4Packet::parse(&packet.payload)?;
    let source = IpAddr::V4(ip.source);
    let destination = IpAddr::V4(ip.destination);

    let mut event = Connection {
        verdict,
        reason,
        container: None,
        network: None,
        protocol: protocol_name(ip.protocol),
        source,
        source_port: ip.ports.map(|(port, _)| port),
        destination,
        destination_port: ip.ports.map(|(_, port)| port),
        destination_container: None,
        domain: None,
        domain_source: None,
        query: None,
        detail: None,
    };

    if reason == Reason::Source {
        attribute_spoofed(&mut event, packet, directory);
    } else if let Some(info) = directory.source(source) {
        event.container = Some(info.container);
        event.network = Some(info.network);
    }

    match reason {
        Reason::Icc => {
            event.destination_container = directory.source(destination).map(|info| info.container);
        }
        Reason::Dns => event.query = query_name(&ip),
        Reason::Egress | Reason::Source => {
            if let Some(domain) = directory.domain(source, destination) {
                event.domain = Some(domain);
                event.domain_source = Some(DomainSource::Dns);
            } else if let Some(host) = rule_domain(directory, hosts, source, destination) {
                event.domain = Some(host);
                event.domain_source = Some(DomainSource::Rule);
            }
        }
    }
    Some(event)
}

/// The hostname of one of the container's own `host:` rules that allows `destination`.
fn rule_domain(
    directory: &Directory,
    hosts: &SharedHosts,
    source: IpAddr,
    destination: IpAddr,
) -> Option<String> {
    let rule_hosts = directory.rule_hosts(source);
    let hosts = hosts.lock().unwrap_or_else(PoisonError::into_inner);
    let now = Instant::now();
    rule_hosts
        .into_iter()
        .find(|host| hosts.allows(host, destination, now))
}

/// A packet whose source address isn't the sender's: name the sender by its MAC, if known,
/// and explain what's wrong with the address.
fn attribute_spoofed(event: &mut Connection, packet: &LoggedPacket, directory: &Directory) {
    let sender = packet.hwaddr.and_then(|mac| directory.by_mac(mac));
    let owner = directory.source(event.source);
    if let Some((_, info)) = &sender {
        event.container = Some(info.container.clone());
        event.network = Some(info.network.clone());
    } else {
        event.network = packet
            .physindev
            .or(packet.indev)
            .and_then(|index| directory.network_of_interface(index));
    }
    event.detail = Some(match (&owner, &sender) {
        (Some(owner), Some((_, sender))) if owner.container != sender.container => {
            format!("uses the address of {}", owner.container)
        }
        (Some(owner), _) => format!(
            "uses the address of {} with another MAC address",
            owner.container
        ),
        (None, Some((address, _))) => {
            format!("uses {} instead of its address {address}", event.source)
        }
        (None, None) => "unknown source address".to_string(),
    });
}

/// The name a DNS query packet asks for.
fn query_name(packet: &Ipv4Packet<'_>) -> Option<String> {
    let data = match packet.protocol {
        // DNS over TCP prefixes messages with their length.
        PROTOCOL_TCP => packet.data.get(2..)?,
        _ => packet.data,
    };
    let message = Message::from_vec(data).ok()?;
    let query = message.queries().first()?;
    Some(crate::dns::normalize(&query.name().to_utf8()))
}

fn protocol_name(protocol: u8) -> String {
    match protocol {
        PROTOCOL_TCP => "tcp".to_string(),
        PROTOCOL_UDP => "udp".to_string(),
        1 => "icmp".to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};

    use super::*;
    use crate::dns::HostAddresses;
    use crate::firewall::Plan;
    use crate::firewall::test_support::{self, MockResolver, ip};
    use crate::nfnetlink::tests::{ipv4, udp};

    fn setup() -> (Directory, SharedHosts) {
        let plan = Plan::build(
            &test_support::icc_state(),
            &mut MockResolver::default(),
            &[],
            false,
        );
        let directory = Directory::default();
        directory.update(&plan);
        let hosts = Arc::new(Mutex::new(HostAddresses::new(
            SystemUpstreamResolver,
            Duration::from_secs(3600),
        )));
        (directory, hosts)
    }

    fn logged(prefix: &str, payload: Vec<u8>) -> LoggedPacket {
        LoggedPacket {
            prefix: prefix.to_string(),
            payload,
            ..LoggedPacket::default()
        }
    }

    fn tcp(source: [u8; 4], destination: [u8; 4], port: u16) -> Vec<u8> {
        let mut header = 40000_u16.to_be_bytes().to_vec();
        header.extend_from_slice(&port.to_be_bytes());
        header.extend_from_slice(&[0; 8]);
        header.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        ipv4(source, destination, PROTOCOL_TCP, &header)
    }

    #[test]
    fn parses_prefixes() {
        assert_eq!(
            parse_prefix("pc:d:egress"),
            Some((Verdict::Denied, Reason::Egress))
        );
        assert_eq!(
            parse_prefix("pc:w:icc"),
            Some((Verdict::WouldDeny, Reason::Icc))
        );
        assert_eq!(
            parse_prefix("pc:a:dns"),
            Some((Verdict::Allowed, Reason::Dns))
        );
        assert_eq!(parse_prefix("other:d:egress"), None);
        assert_eq!(parse_prefix("pc:x:egress"), None);
    }

    #[test]
    fn attributes_egress_to_containers_and_domains() {
        let (directory, hosts) = setup();
        let packet = logged("pc:d:egress", tcp([172, 18, 0, 2], [198, 51, 100, 4], 443));
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.container.as_deref(), Some("web"));
        assert_eq!(event.network.as_deref(), Some("net0"));
        assert_eq!(event.destination_port, Some(443));
        assert_eq!(event.domain, None);

        directory.observe(
            ip("172.18.0.2"),
            ip("198.51.100.4"),
            "other.test",
            Duration::from_secs(60),
        );
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.domain.as_deref(), Some("other.test"));
        assert_eq!(event.domain_source, Some(DomainSource::Dns));

        // An address of a hostname the container has no rule for isn't attributed to it.
        hosts.lock().expect("lock").observe(
            "rule.test",
            ip("198.51.100.5"),
            Duration::from_secs(60),
            Instant::now(),
        );
        let packet = logged("pc:a:egress", tcp([172, 18, 0, 2], [198, 51, 100, 5], 443));
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.domain, None);
    }

    #[test]
    fn attributes_addresses_of_the_containers_own_host_rules() {
        let plan = Plan::build(
            &test_support::hostname_state(),
            &mut MockResolver::default(),
            &[],
            false,
        );
        let directory = Directory::default();
        directory.update(&plan);
        let hosts: SharedHosts = Arc::new(Mutex::new(HostAddresses::new(
            SystemUpstreamResolver,
            Duration::from_secs(3600),
        )));
        hosts.lock().expect("lock").observe(
            test_support::HOST,
            ip("198.51.100.5"),
            Duration::from_secs(60),
            Instant::now(),
        );
        let packet = logged("pc:a:egress", tcp([172, 18, 0, 2], [198, 51, 100, 5], 443));
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.domain.as_deref(), Some(test_support::HOST));
        assert_eq!(event.domain_source, Some(DomainSource::Rule));
    }

    #[test]
    fn names_icc_destinations() {
        let (directory, hosts) = setup();
        let packet = logged("pc:d:icc", tcp([172, 18, 0, 2], [172, 18, 0, 3], 5432));
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.destination_container.as_deref(), Some("other"));
    }

    #[test]
    fn reports_denied_dns_queries() {
        let (directory, hosts) = setup();
        let mut message = Message::new();
        message.add_query(Query::query(
            Name::from_ascii("Blocked.Test.").expect("name"),
            RecordType::A,
        ));
        let data = message.to_vec().expect("dns");
        let packet = logged(
            "pc:d:dns",
            ipv4(
                [172, 18, 0, 2],
                [8, 8, 8, 8],
                PROTOCOL_UDP,
                &udp(5000, 53, &data),
            ),
        );
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.reason, Reason::Dns);
        assert_eq!(event.query.as_deref(), Some("blocked.test"));
    }

    #[test]
    fn explains_spoofed_sources() {
        let (directory, hosts) = setup();
        // "other" (172.18.0.3) sending with web's address.
        let mut packet = logged("pc:d:source", tcp([172, 18, 0, 2], [1, 1, 1, 1], 80));
        packet.hwaddr = test_support::mac_of("172.18.0.3");
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.container.as_deref(), Some("other"));
        assert_eq!(event.detail.as_deref(), Some("uses the address of web"));

        // "other" using an address outside the network.
        let mut packet = logged("pc:d:source", tcp([10, 99, 0, 5], [1, 1, 1, 1], 80));
        packet.hwaddr = test_support::mac_of("172.18.0.3");
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.container.as_deref(), Some("other"));
        assert_eq!(
            event.detail.as_deref(),
            Some("uses 10.99.0.5 instead of its address 172.18.0.3")
        );
    }
}
