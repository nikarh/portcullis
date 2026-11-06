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
use std::time::Instant;

use crossbeam_channel::Sender;
use hickory_proto::op::Message;
use tracing::debug;

use crate::directory::{Directory, SourceInfo};
use crate::dns::{HostAddresses, SystemUpstreamResolver};
use crate::events::{
    Connection, DomainSource, Event, EventBus, Reason, Verdict, Warning, WarningKind,
};
use crate::firewall::LOG_PREFIX;
use crate::model::{MacAddress, PortState, Protocol};
use crate::nfnetlink::{
    ArpPacket, Ipv4Packet, LoggedPacket, NflogSocket, Overruns, PROTOCOL_TCP, is_overrun,
};
use crate::quarantine::Watch;

/// Known hostname addresses, shared with planning and DNS inspection.
pub type SharedHosts = Arc<Mutex<HostAddresses<SystemUpstreamResolver>>>;

/// Start reading logged decisions from NFLOG `group`. If reading fails for good, the
/// thread says why on `failed` and ends.
pub fn spawn(
    group: u16,
    directory: Arc<Directory>,
    hosts: SharedHosts,
    bus: EventBus,
    mut quarantine: Option<Watch>,
    failed: Sender<String>,
) -> io::Result<JoinHandle<()>> {
    let mut socket = NflogSocket::bind(group)?;
    Ok(thread::spawn(move || {
        let mut overruns = Overruns::default();
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
                Err(error) if is_overrun(&error) => {
                    if overruns.report() {
                        bus.publish(&Event::Warning(Warning {
                            kind: WarningKind::EventsLost,
                            container: None,
                            message: "connection events were lost: the kernel produced them faster than they were read".to_string(),
                        }));
                    }
                }
                Err(error) => {
                    let _ = failed.send(format!("reading logged connections failed: {error}"));
                    return;
                }
            }
        }
    }))
}

/// Verdict and reason of a log prefix, and what a `limit` was about, or that a `source`
/// packet was `held`.
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
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const ETHER_TYPE_ARP: u16 = 0x0806;
const ETHER_TYPE_IPV6: u16 = 0x86dd;

/// What a logged packet carries.
enum Payload<'a> {
    Ipv4(Ipv4Packet<'a>),
    Arp(ArpPacket),
    /// ARP that isn't for Ethernet and IPv4, or is cut short.
    OtherArp,
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
            ETHER_TYPE_ARP => {
                Some(ArpPacket::parse(&packet.payload).map_or(Self::OtherArp, Self::Arp))
            }
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
        mid_stream: false,
        forged: false,
    };
    match &payload {
        Payload::Ipv4(ip) => {
            event.protocol = protocol_name(ip.protocol);
            event.source = Some(IpAddr::V4(ip.source));
            event.destination = Some(IpAddr::V4(ip.destination));
            event.source_port = ip.ports.map(|(port, _)| port);
            event.destination_port = ip.ports.map(|(_, port)| port);
            // Only a SYN without ACK opens a connection.
            event.mid_stream = ip
                .tcp_flags
                .is_some_and(|flags| flags & TCP_SYN == 0 || flags & TCP_ACK != 0);
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
        Payload::OtherArp => event.protocol = "arp".to_string(),
        Payload::Ipv6(source, destination) => {
            event.protocol = "ipv6".to_string();
            event.source = Some(*source);
            event.destination = Some(*destination);
        }
        Payload::Other(ether_type) => event.protocol = format!("ether type {ether_type:#06x}"),
    }

    match reason {
        Reason::Source => attribute_spoofed(&mut event, packet, &payload, directory, limit),
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
            if let Some(info) = event.source.and_then(|source| directory.attributed(source)) {
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
            event.destination_container =
                directory.attributed(destination).map(|info| info.container);
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
    let container = directory.attributed(source)?.container;
    let rule_hosts = directory.rule_hosts(source);
    let hosts = hosts.lock().unwrap_or_else(PoisonError::into_inner);
    let now = Instant::now();
    rule_hosts
        .into_iter()
        .find(|(host, hold)| hosts.allows(&container, host, destination, *hold, now))
        .map(|(host, _)| host)
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
        .filter(|(_, info)| info.port == PortState::Unknown)
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
/// and explain what it claimed. `kind` is `held` for packets that were held until Portcullis
/// knew their sender, and it didn't in time.
fn attribute_spoofed(
    event: &mut Connection,
    packet: &LoggedPacket,
    payload: &Payload<'_>,
    directory: &Directory,
    kind: Option<&str>,
) {
    let held = kind == Some("held");
    let sender = attribute_sender(event, packet, directory);
    let claimed = event.source.filter(|address| !address.is_unspecified());
    let (forged, detail) = spoofed(sender.as_ref(), claimed, packet, payload, directory);
    // The rules didn't know the sender when they judged a held packet: what it claimed may
    // be the sender's after all, such as an address Docker took from a removed container.
    event.forged = forged && !held;
    event.detail = Some(if held && forged {
        format!("{detail}, before Portcullis knew its port")
    } else {
        detail
    });
}

/// Whether a packet with a source that isn't `sender`'s was forged (see
/// [`Connection::forged`]), and what it claimed.
fn spoofed(
    sender: Option<&(IpAddr, SourceInfo)>,
    claimed: Option<IpAddr>,
    packet: &LoggedPacket,
    payload: &Payload<'_>,
    directory: &Directory,
) -> (bool, String) {
    // An ARP packet announces a MAC of its own, besides the frame's.
    if let Payload::Arp(arp) = payload
        && packet.hwaddr.is_some_and(|mac| mac != arp.sender_mac)
    {
        return (
            true,
            "announces a MAC address that isn't its own".to_string(),
        );
    }
    let Some((own, sender)) = sender else {
        return (false, "unknown source address".to_string());
    };
    // The MAC of the sender's interface on this network, as the rules check it.
    let own_mac = sender.mac.is_none() || packet.hwaddr == sender.mac;
    let owner = claimed.and_then(|address| directory.attributed(address));
    match (claimed, &owner) {
        // Its own address and MAC from its own port: the rules that judged it didn't know
        // them yet (they were being updated), or no longer did.
        (None, _) if own_mac => (false, "sent before its rules were in place".to_string()),
        (Some(address), _) if address == *own && own_mac => {
            (false, "sent before its rules were in place".to_string())
        }
        // Its address on another of its networks, with its MAC on this one: a container
        // on several networks may route a packet out of another network than the one its
        // source address is on (Linux doesn't tie addresses to interfaces). That takes no
        // raw socket, and gets it nowhere it couldn't go.
        (Some(_), Some(owner))
            if owner.container == sender.container && owner.network != sender.network =>
        {
            if own_mac {
                (false, format!("uses its own address on {}", owner.network))
            } else {
                (true, wrong_mac(packet, sender, directory))
            }
        }
        (Some(_), Some(owner)) if owner.container != sender.container => {
            (true, format!("uses the address of {}", owner.container))
        }
        (Some(address), None) if address != *own => {
            (true, format!("uses {address} instead of its address {own}"))
        }
        // Its own address (or none), so the MAC is what's wrong.
        _ => (true, wrong_mac(packet, sender, directory)),
    }
}

fn wrong_mac(packet: &LoggedPacket, sender: &SourceInfo, directory: &Directory) -> String {
    match packet.hwaddr.and_then(|mac| directory.by_mac(mac)) {
        Some((_, other)) if other.container != sender.container => {
            format!("uses the MAC address of {}", other.container)
        }
        _ => "uses a MAC address that isn't its own".to_string(),
    }
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
            Payload::Arp(_) | Payload::OtherArp => {
                "ARP that isn't a plain request or reply for Ethernet and IPv4, or carries more"
                    .to_string()
            }
            Payload::Ipv4(_) => "a frame of a kind that isn't allowed".to_string(),
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
    let query = message.queries.first()?;
    Some(crate::dns::normalize(&query.name().to_utf8()))
}

/// The protocol's name in labels, or its number for those labels can't name.
fn protocol_name(protocol: u8) -> String {
    Protocol::from_number(protocol).map_or_else(
        || protocol.to_string(),
        |protocol| protocol.as_str().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
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
        tcp_flagged(source, destination, port, TCP_SYN)
    }

    fn tcp_flagged(source: [u8; 4], destination: [u8; 4], port: u16, flags: u8) -> Vec<u8> {
        let mut header = 40000_u16.to_be_bytes().to_vec();
        header.extend_from_slice(&port.to_be_bytes());
        header.extend_from_slice(&[0; 8]);
        header.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        ipv4(source, destination, PROTOCOL_TCP, &header)
    }

    #[test]
    fn tells_packets_that_dont_start_a_connection() {
        let (directory, hosts) = setup();
        let event = |flags| {
            connection_event(
                &logged(
                    "pc:d:icc",
                    tcp_flagged([172, 18, 0, 2], [172, 18, 0, 3], 5432, flags),
                ),
                &directory,
                &hosts,
            )
            .expect("event")
        };
        assert!(!event(TCP_SYN).mid_stream);
        assert!(event(TCP_ACK).mid_stream);
        assert!(event(TCP_SYN | TCP_ACK).mid_stream);
        // A reset or FIN without ACK doesn't start one either.
        assert!(event(0x04).mid_stream);
        let udp = connection_event(
            &logged(
                "pc:d:icc",
                ipv4([172, 18, 0, 2], [172, 18, 0, 3], 17, &udp(1, 2, b"x")),
            ),
            &directory,
            &hosts,
        )
        .expect("event");
        assert!(!udp.mid_stream);
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
            Duration::from_secs(3600),
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
            Duration::from_secs(3600),
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
        let mut message = Message::new(0, MessageType::Query, OpCode::Query);
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
                crate::nfnetlink::PROTOCOL_UDP,
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
        assert!(event.forged);

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
            std::collections::HashSet::new(),
        );
        let plan = Plan::build(&state, &mut MockResolver::default(), &[], false);
        let (directory, hosts) = setup();
        directory.update(&plan);
        (directory, hosts)
    }

    #[test]
    fn doesnt_blame_containers_without_a_port_by_their_mac() {
        // web is stopping, without a port; a frame with its MAC came from somewhere else.
        let mut state = test_support::icc_state();
        state.set_ports(
            std::collections::HashMap::new(),
            std::collections::HashSet::from([ip("172.18.0.2")]),
        );
        let plan = Plan::build(&state, &mut MockResolver::default(), &[], false);
        let (directory, hosts) = setup();
        directory.update(&plan);
        let mut packet = logged("pc:d:source", tcp([172, 18, 0, 2], [1, 1, 1, 1], 80));
        packet.indev = Some(99);
        packet.hwaddr = test_support::mac_of("172.18.0.2");
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_ne!(event.container.as_deref(), Some("web"));
        // other's port isn't known: its MAC still names it.
        let mut packet = logged("pc:d:source", tcp([172, 18, 0, 2], [1, 1, 1, 1], 80));
        packet.hwaddr = test_support::mac_of("172.18.0.3");
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(event.container.as_deref(), Some("other"));
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
    fn tells_forged_sources_from_traffic_the_rules_judged_too_early() {
        let mut state = test_support::icc_state();
        let port = |name: &str, index| crate::model::BridgePort {
            name: name.to_string(),
            index,
        };
        // project-db-1 is on net0 (172.18.0.10, port 20) and net1 (172.19.0.10, port 21).
        state.set_ports(
            [
                (ip("172.18.0.3"), port("veth13", 13)),
                (ip("172.18.0.10"), port("veth20", 20)),
                (ip("172.19.0.10"), port("veth21", 21)),
            ]
            .into(),
            std::collections::HashSet::new(),
        );
        let plan = Plan::build(&state, &mut MockResolver::default(), &[], false);
        let (directory, hosts) = setup();
        directory.update(&plan);
        let from_db = |prefix: &str, source: [u8; 4]| {
            let mut packet = logged(prefix, tcp(source, [192, 168, 1, 2], 44300));
            packet.indev = Some(20);
            packet.hwaddr = test_support::mac_of("172.18.0.10");
            connection_event(&packet, &directory, &hosts).expect("event")
        };

        // Its own address, MAC and port: the rules didn't know them when they judged it.
        let event = from_db("pc:d:source", [172, 18, 0, 10]);
        assert_eq!(event.container.as_deref(), Some("project-db-1"));
        assert_eq!(
            event.detail.as_deref(),
            Some("sent before its rules were in place")
        );
        assert!(!event.forged);

        // Its address on net1, routed out of net0, with its MAC on net0.
        let event = from_db("pc:d:source", [172, 19, 0, 10]);
        assert_eq!(event.network.as_deref(), Some("net0"));
        assert_eq!(
            event.detail.as_deref(),
            Some("uses its own address on net1")
        );
        assert!(!event.forged);
        // ...but not with another MAC.
        let mut packet = logged("pc:d:source", tcp([172, 19, 0, 10], [1, 1, 1, 1], 80));
        packet.indev = Some(20);
        packet.hwaddr = test_support::mac_of("172.18.0.3");
        let event = connection_event(&packet, &directory, &hosts).expect("event");
        assert_eq!(
            event.detail.as_deref(),
            Some("uses the MAC address of other")
        );
        assert!(event.forged);

        // Someone else's address is forged...
        let event = from_db("pc:d:source", [172, 18, 0, 3]);
        assert_eq!(event.detail.as_deref(), Some("uses the address of other"));
        assert!(event.forged);
        // ...unless the packet was held and Portcullis didn't know its sender in time.
        let event = from_db("pc:d:source:held", [172, 18, 0, 3]);
        assert_eq!(
            event.detail.as_deref(),
            Some("uses the address of other, before Portcullis knew its port")
        );
        assert!(!event.forged);
        let event = from_db("pc:w:source:held", [172, 18, 0, 10]);
        assert_eq!(event.verdict, Verdict::WouldDeny);
        assert_eq!(
            event.detail.as_deref(),
            Some("sent before its rules were in place")
        );
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
        assert!(event.forged);
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

        // ARP with data after it, and ARP for something else than Ethernet and IPv4.
        let mut carrying = crate::nfnetlink::tests::arp(
            test_support::mac_of("172.18.0.2").expect("mac").octets(),
            [172, 18, 0, 2],
            [172, 18, 0, 3],
        );
        carrying.extend_from_slice(b"data");
        let mut other = carrying.clone();
        other[1] = 6;
        for payload in [carrying, other] {
            let event = connection_event(&frame(ETHER_TYPE_ARP, payload), &directory, &hosts)
                .expect("event");
            assert_eq!(event.protocol, "arp");
            assert_eq!(event.container.as_deref(), Some("web"));
            assert_eq!(
                event.detail.as_deref(),
                Some(
                    "ARP that isn't a plain request or reply for Ethernet and IPv4, or carries more"
                )
            );
        }

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
