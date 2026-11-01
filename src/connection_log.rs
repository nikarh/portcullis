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

use crate::directory::{Directory, SourceInfo};
use crate::dns::{HostAddresses, SystemUpstreamResolver};
use crate::events::{
    Connection, DomainSource, Event, EventBus, Reason, Verdict, Warning, WarningKind,
};
use crate::firewall::LOG_PREFIX;
use crate::model::MacAddress;
use crate::nfnetlink::{
    ArpPacket, Ipv4Packet, LoggedPacket, NflogSocket, PROTOCOL_TCP, PROTOCOL_UDP,
};
use crate::quarantine::Watch;

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
    mut quarantine: Option<Watch>,
) -> io::Result<JoinHandle<()>> {
    let mut socket = NflogSocket::bind(group)?;
    Ok(thread::spawn(move || {
        let mut last_lost: Option<Instant> = None;
        loop {
            match socket.receive() {
                Ok(packets) => {
                    for packet in packets {
                        if let Some(event) = connection_event(&packet, &directory, &hosts) {
                            if let Some(watch) = &mut quarantine {
                                watch.observe(&event, &directory);
                            }
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

/// Verdict and reason of a log prefix, and what a `limit` was about.
fn parse_prefix(prefix: &str) -> Option<(Verdict, Reason, Option<&str>)> {
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
        "frame" => Reason::Frame,
        "limit" => Reason::Limit,
        _ => return None,
    };
    Some((verdict, reason, parts.next()))
}

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_ARP: u16 = 0x0806;
const ETHER_TYPE_IPV6: u16 = 0x86dd;

/// What a logged packet carries.
enum Payload<'a> {
    Ipv4(Ipv4Packet<'a>),
    Arp(ArpPacket),
    /// An IPv6 packet: its source and destination.
    Ipv6(IpAddr, IpAddr),
    /// Any other kind of frame, by ether type.
    Other(u16),
}

impl<'a> Payload<'a> {
    fn parse(packet: &'a LoggedPacket) -> Option<Self> {
        // The routed traffic of the inet table is always IPv4 or IPv6.
        match packet.protocol.unwrap_or(ETHER_TYPE_IPV4) {
            ETHER_TYPE_IPV4 => Ipv4Packet::parse(&packet.payload).map(Self::Ipv4),
            ETHER_TYPE_ARP => ArpPacket::parse(&packet.payload).map(Self::Arp),
            ETHER_TYPE_IPV6 => {
                let address = |range: std::ops::Range<usize>| {
                    let octets: [u8; 16] = packet.payload.get(range)?.try_into().ok()?;
                    Some(IpAddr::from(octets))
                };
                Some(Self::Ipv6(address(8..24)?, address(24..40)?))
            }
            other => Some(Self::Other(other)),
        }
    }
}

fn connection_event(
    packet: &LoggedPacket,
    directory: &Directory,
    hosts: &SharedHosts,
) -> Option<Connection> {
    let Some((verdict, reason, limit)) = parse_prefix(&packet.prefix) else {
        debug!(prefix = %packet.prefix, "ignoring packet with an unknown log prefix");
        return None;
    };
    let payload = Payload::parse(packet)?;
    let mut event = Connection {
        verdict,
        reason,
        container: None,
        network: None,
        protocol: String::new(),
        source: None,
        source_port: None,
        destination: None,
        destination_port: None,
        destination_container: None,
        domain: None,
        domain_source: None,
        query: None,
        detail: None,
    };
    match &payload {
        Payload::Ipv4(ip) => {
            event.protocol = protocol_name(ip.protocol);
            event.source = Some(IpAddr::V4(ip.source));
            event.destination = Some(IpAddr::V4(ip.destination));
            event.source_port = ip.ports.map(|(port, _)| port);
            event.destination_port = ip.ports.map(|(_, port)| port);
            // What the container asked for, as the egress rules see it, not where DNAT
            // sends it (a published port reached through the host).
            if reason == Reason::Egress
                && let Some((destination, port)) = packet.original_destination
            {
                event.destination = Some(destination);
                event.destination_port = port.or(event.destination_port);
            }
        }
        Payload::Arp(arp) => {
            event.protocol = "arp".to_string();
            event.source = Some(IpAddr::V4(arp.sender));
            event.destination = Some(IpAddr::V4(arp.target));
        }
        Payload::Ipv6(source, destination) => {
            event.protocol = "ipv6".to_string();
            event.source = Some(*source);
            event.destination = Some(*destination);
        }
        Payload::Other(ether_type) => event.protocol = format!("ether type {ether_type:#06x}"),
    }

    match reason {
        Reason::Source => attribute_spoofed(&mut event, packet, &payload, directory),
        Reason::Frame => attribute_frame(&mut event, packet, &payload, directory),
        Reason::Limit => {
            attribute_sender(&mut event, packet, directory);
            event.detail = Some(
                if limit == Some("rate") {
                    "opens new connections faster than its limit"
                } else {
                    "has as many connections open as its limit allows"
                }
                .to_string(),
            );
        }
        _ => {
            if let Some(info) = event.source.and_then(|source| directory.source(source)) {
                event.container = Some(info.container);
                event.network = Some(info.network);
            }
        }
    }
    let (Some(source), Some(destination)) = (event.source, event.destination) else {
        return Some(event);
    };
    match (reason, &payload) {
        (Reason::Icc, _) => {
            event.destination_container = directory.source(destination).map(|info| info.container);
        }
        (Reason::Dns, Payload::Ipv4(ip)) => event.query = query_name(ip),
        (Reason::Egress, _) => {
            if let Some(domain) = directory.domain(source, destination) {
                event.domain = Some(domain);
                event.domain_source = Some(DomainSource::Dns);
            } else if let Some(host) = rule_domain(directory, hosts, source, destination) {
                event.domain = Some(host);
                event.domain_source = Some(DomainSource::Rule);
            }
        }
        _ => {}
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
    let container = directory.source(source)?.container;
    let rule_hosts = directory.rule_hosts(source);
    let hosts = hosts.lock().unwrap_or_else(PoisonError::into_inner);
    let now = Instant::now();
    rule_hosts
        .into_iter()
        .find(|host| hosts.allows(&container, host, destination, now))
}

/// The container that sent a frame, by the bridge port it came in on, with its address.
/// Its address and MAC may be borrowed, its port can't. Only a container whose port isn't
/// known is recognised by its MAC.
fn sender(packet: &LoggedPacket, directory: &Directory) -> Option<(IpAddr, SourceInfo)> {
    // The bridge table logs the port as the input interface; the inet table, with
    // `br_netfilter`, as the physical input interface.
    let port = packet.physindev.or(packet.indev);
    if let Some(sender) = port.and_then(|index| directory.by_port(index)) {
        return Some(sender);
    }
    packet
        .hwaddr
        .and_then(|mac| directory.by_mac(mac))
        .filter(|(_, info)| info.port.is_none())
}

/// Name the container a denied frame came from, or else the network.
fn attribute_sender(
    event: &mut Connection,
    packet: &LoggedPacket,
    directory: &Directory,
) -> Option<(IpAddr, SourceInfo)> {
    let sender = sender(packet, directory);
    if let Some((_, info)) = &sender {
        event.container = Some(info.container.clone());
        event.network = Some(info.network.clone());
    } else {
        event.network = packet
            .physindev
            .or(packet.indev)
            .and_then(|index| directory.network_of_interface(index));
    }
    sender
}

/// A packet whose source address or MAC isn't the sender's: name the sender by its port,
/// and explain what it claimed.
fn attribute_spoofed(
    event: &mut Connection,
    packet: &LoggedPacket,
    payload: &Payload<'_>,
    directory: &Directory,
) {
    let sender = attribute_sender(event, packet, directory);
    let claimed = event.source.filter(|address| !address.is_unspecified());
    let mac = match payload {
        // An ARP packet announces a MAC of its own, besides the frame's.
        Payload::Arp(arp) if packet.hwaddr.is_some_and(|mac| mac != arp.sender_mac) => {
            event.detail = Some("announces a MAC address that isn't its own".to_string());
            return;
        }
        _ => packet.hwaddr,
    };
    let owner = claimed.and_then(|address| directory.source(address));
    let detail = match (&sender, claimed, &owner) {
        (None, _, _) => "unknown source address".to_string(),
        (Some((_, sender)), _, Some(owner)) if owner.container != sender.container => {
            format!("uses the address of {}", owner.container)
        }
        (Some((own, _)), Some(address), None) if address != *own => {
            format!("uses {address} instead of its address {own}")
        }
        // Its own address (or none), so the MAC is what's wrong.
        (Some((_, sender)), _, _) => match mac.and_then(|mac| directory.by_mac(mac)) {
            Some((_, other)) if other.container != sender.container => {
                format!("uses the MAC address of {}", other.container)
            }
            _ => "uses a MAC address that isn't its own".to_string(),
        },
    };
    event.detail = Some(detail);
}

/// A kind of frame enforced networks don't carry: name the sender and the kind.
fn attribute_frame(
    event: &mut Connection,
    packet: &LoggedPacket,
    payload: &Payload<'_>,
    directory: &Directory,
) {
    attribute_sender(event, packet, directory);
    let detail = if packet.vlan {
        "a VLAN-tagged frame".to_string()
    } else if let Some(mac) = packet
        .destination_mac
        .filter(|mac| is_link_local_group(*mac))
    {
        format!("a frame to the link-local group address {mac}")
    } else {
        match payload {
            Payload::Ipv6(..) => "IPv6, which Portcullis doesn't manage".to_string(),
            Payload::Other(ether_type) => format!("a frame of ether type {ether_type:#06x}"),
            Payload::Ipv4(_) | Payload::Arp(_) => {
                "a frame of a kind that isn't allowed".to_string()
            }
        }
    };
    event.detail = Some(detail);
}

/// 01:80:c2:00:00:00 to 01:80:c2:00:00:0f: addresses a bridge delivers to the host itself.
fn is_link_local_group(mac: MacAddress) -> bool {
    let [prefix @ .., last] = mac.octets();
    prefix == [0x01, 0x80, 0xc2, 0x00, 0x00] && last & 0xf0 == 0
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
            Some((Verdict::Denied, Reason::Egress, None))
        );
        assert_eq!(
            parse_prefix("pc:w:icc"),
            Some((Verdict::WouldDeny, Reason::Icc, None))
        );
        assert_eq!(
            parse_prefix("pc:a:dns"),
            Some((Verdict::Allowed, Reason::Dns, None))
        );
        assert_eq!(
            parse_prefix("pc:d:limit:rate"),
            Some((Verdict::Denied, Reason::Limit, Some("rate")))
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
            "web",
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
            "web",
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
    fn reports_destinations_before_dnat() {
        let (directory, hosts) = setup();
        let mut packet = logged("pc:d:egress", tcp([172, 18, 0, 2], [172, 18, 0, 3], 8080));
        packet.original_destination = Some((ip("198.51.100.1"), Some(18080)));
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.destination, Some(ip("198.51.100.1")));
        assert_eq!(event.destination_port, Some(18080));
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

    /// The directory of `icc_state`, with web (172.18.0.2) and other (172.18.0.3) on bridge
    /// ports 12 and 13.
    fn setup_with_ports() -> (Directory, SharedHosts) {
        let mut state = test_support::icc_state();
        let port = |name: &str, index| crate::model::BridgePort {
            name: name.to_string(),
            index,
        };
        state.set_ports(
            [
                (ip("172.18.0.2"), port("veth12", 12)),
                (ip("172.18.0.3"), port("veth13", 13)),
            ]
            .into(),
        );
        let plan = Plan::build(&state, &mut MockResolver::default(), &[], false);
        let (directory, hosts) = setup();
        directory.update(&plan);
        (directory, hosts)
    }

    #[test]
    fn names_the_sender_of_spoofed_traffic_by_its_port() {
        let (directory, hosts) = setup_with_ports();
        // "other" sending from its port with web's address and MAC: the MAC would blame web.
        let mut packet = logged("pc:d:source", tcp([172, 18, 0, 2], [1, 1, 1, 1], 80));
        packet.indev = Some(13);
        packet.hwaddr = test_support::mac_of("172.18.0.2");
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.container.as_deref(), Some("other"));
        assert_eq!(event.detail.as_deref(), Some("uses the address of web"));

        // Its own address with web's MAC.
        let mut packet = logged("pc:d:source", tcp([172, 18, 0, 3], [1, 1, 1, 1], 80));
        packet.indev = Some(13);
        packet.hwaddr = test_support::mac_of("172.18.0.2");
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.container.as_deref(), Some("other"));
        assert_eq!(event.detail.as_deref(), Some("uses the MAC address of web"));

        // A port of no managed container.
        let mut packet = logged("pc:d:source", tcp([172, 18, 0, 2], [1, 1, 1, 1], 80));
        packet.indev = Some(99);
        packet.hwaddr = test_support::mac_of("172.18.0.2");
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.container, None);
        assert_eq!(event.detail.as_deref(), Some("unknown source address"));
    }

    #[test]
    fn explains_spoofed_arp() {
        let (directory, hosts) = setup_with_ports();
        let other_mac = test_support::mac_of("172.18.0.3").expect("mac");
        let arp = |sender: [u8; 4]| {
            let mut packet = logged(
                "pc:d:source",
                crate::nfnetlink::tests::arp(other_mac.octets(), sender, [172, 18, 0, 1]),
            );
            packet.protocol = Some(ETHER_TYPE_ARP);
            packet.indev = Some(13);
            packet.hwaddr = Some(other_mac);
            packet
        };
        // "other" claiming the gateway's address.
        let event = connection_event(&arp([172, 18, 0, 1]), &directory, &hosts).expect("event");
        assert_eq!(event.protocol, "arp");
        assert_eq!(event.container.as_deref(), Some("other"));
        assert_eq!(event.source, Some(ip("172.18.0.1")));
        assert_eq!(
            event.detail.as_deref(),
            Some("uses 172.18.0.1 instead of its address 172.18.0.3")
        );
        // ...and web's.
        let event = connection_event(&arp([172, 18, 0, 2]), &directory, &hosts).expect("event");
        assert_eq!(event.detail.as_deref(), Some("uses the address of web"));
        // Its own address, announced with another MAC.
        let mut packet = arp([172, 18, 0, 3]);
        packet.hwaddr = test_support::mac_of("172.18.0.2");
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(
            event.detail.as_deref(),
            Some("announces a MAC address that isn't its own")
        );
    }

    #[test]
    fn reports_frames_enforced_networks_dont_carry() {
        let (directory, hosts) = setup_with_ports();
        let frame = |protocol: u16, payload: Vec<u8>| {
            let mut packet = logged("pc:d:frame", payload);
            packet.protocol = Some(protocol);
            packet.indev = Some(12);
            packet
        };

        let mut ipv6 = vec![0x60, 0, 0, 0, 0, 0, 17, 64];
        ipv6.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ipv6.extend_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let event =
            connection_event(&frame(ETHER_TYPE_IPV6, ipv6), &directory, &hosts).expect("event");
        assert_eq!(event.reason, Reason::Frame);
        assert_eq!(event.container.as_deref(), Some("web"));
        assert_eq!(event.protocol, "ipv6");
        assert_eq!(event.source, Some(ip("fe80::1")));
        assert_eq!(event.destination, Some(ip("ff02::1")));

        let mut tagged = frame(ETHER_TYPE_IPV4, tcp([172, 18, 0, 2], [172, 18, 0, 3], 80));
        tagged.vlan = true;
        let event = connection_event(&tagged, &directory, &hosts).expect("event");
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.destination_port, Some(80));
        assert_eq!(event.detail.as_deref(), Some("a VLAN-tagged frame"));

        let mut link_local = frame(ETHER_TYPE_IPV4, tcp([172, 18, 0, 2], [172, 18, 0, 1], 22));
        link_local.destination_mac = Some(MacAddress::from([0x01, 0x80, 0xc2, 0, 0, 0x0e]));
        let event = connection_event(&link_local, &directory, &hosts).expect("event");
        assert_eq!(
            event.detail.as_deref(),
            Some("a frame to the link-local group address 01:80:c2:00:00:0e")
        );

        let event =
            connection_event(&frame(0x88cc, vec![1, 2, 3]), &directory, &hosts).expect("event");
        assert_eq!(event.protocol, "ether type 0x88cc");
        assert_eq!((event.source, event.destination), (None, None));
        assert_eq!(
            event.detail.as_deref(),
            Some("a frame of ether type 0x88cc")
        );
    }
}
