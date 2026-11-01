//! Minimal nfnetlink client for the two netfilter interfaces Portcullis uses:
//!
//! - NFLOG: packets matched by an nftables `log group` rule are copied to userspace, with
//!   the rule's prefix. Portcullis turns them into connection events.
//! - NFQUEUE: packets matched by a `queue` rule are held by the kernel until userspace
//!   issues a verdict. Portcullis holds DNS answers until the addresses they contain are
//!   allowed.
//!
//! Only the parts of the protocols Portcullis needs are implemented.

use std::fs::File;
use std::io::{self, Write as _};
use std::net::Ipv4Addr;
use std::os::fd::AsFd;

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};

use crate::model::MacAddress;

pub(crate) const NLMSG_HDRLEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;

const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFNL_SUBSYS_ULOG: u16 = 4;

const AF_UNSPEC: u8 = 0;
const AF_INET: u16 = 2;
const AF_BRIDGE: u16 = 7;

// nfnetlink_log
const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULA_CFG_QTHRESH: u16 = 5;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_CFG_CMD_PF_BIND: u8 = 3;
const NFULNL_CFG_CMD_PF_UNBIND: u8 = 4;
const NFULNL_COPY_PACKET: u8 = 2;
const NFULA_IFINDEX_INDEV: u16 = 4;
const NFULA_IFINDEX_PHYSINDEV: u16 = 6;
const NFULA_HWADDR: u16 = 8;
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;

// nfnetlink_queue
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_COPY_PACKET: u8 = 2;
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3;
const NFQA_IFINDEX_PHYSINDEV: u16 = 7;
const NFQA_HWADDR: u16 = 9;
const NFQA_PAYLOAD: u16 = 10;

const NF_ACCEPT: u32 = 1;
const NF_REPEAT: u32 = 4;

/// What happens to a held packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueVerdict {
    /// Let it continue past the rule that queued it.
    Accept,
    /// Run it through the hook again from the start, with the rules as they are now,
    /// optionally setting the packet mark first.
    Repeat { mark: Option<u32> },
}

fn encode_verdict(queue: u16, id: u32, verdict: QueueVerdict) -> Vec<u8> {
    let code = match verdict {
        QueueVerdict::Accept => NF_ACCEPT,
        QueueVerdict::Repeat { .. } => NF_REPEAT,
    };
    let mut header = Vec::with_capacity(8);
    header.extend_from_slice(&code.to_be_bytes());
    header.extend_from_slice(&id.to_be_bytes());
    let mut attributes = attribute(NFQA_VERDICT_HDR, &header);
    if let QueueVerdict::Repeat { mark: Some(mark) } = verdict {
        attributes.extend(attribute(NFQA_MARK, &mark.to_be_bytes()));
    }
    encode(
        (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT,
        NLM_F_REQUEST,
        0,
        AF_UNSPEC,
        queue,
        &attributes,
    )
}

/// Receive buffer: large enough that bursts of logged packets aren't lost.
const RECEIVE_BUFFER: i32 = 4 << 20;

/// A packet copied to userspace by an nftables `log group` rule.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoggedPacket {
    /// The rule's log prefix.
    pub prefix: String,
    /// Input interface index: the bridge for routed traffic.
    pub indev: Option<u32>,
    /// Input bridge port index, for bridged traffic.
    pub physindev: Option<u32>,
    /// Source MAC address of the frame.
    pub hwaddr: Option<MacAddress>,
    /// The packet, starting at the IP header.
    pub payload: Vec<u8>,
}

/// A packet held by an nftables `queue` rule until a verdict is issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedPacket {
    pub id: u32,
    /// For packets queued from the bridge table: the bridge port the frame came in on.
    pub physindev: Option<u32>,
    /// Source MAC address of the frame, when the kernel knows it.
    pub hwaddr: Option<MacAddress>,
    /// The packet, starting at the IP header.
    pub payload: Vec<u8>,
}

struct NetfilterSocket {
    socket: Socket,
    buffer: Vec<u8>,
    sequence: u32,
}

impl NetfilterSocket {
    fn open() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        // Best effort: the kernel caps it at net.core.rmem_max.
        let _ = socket.set_rx_buf_sz(RECEIVE_BUFFER);
        Ok(Self {
            socket,
            buffer: Vec::with_capacity(1 << 16),
            sequence: 0,
        })
    }

    /// Send a configuration request and wait for the kernel's acknowledgement.
    fn request(&mut self, message_type: u16, res_id: u16, attributes: &[u8]) -> io::Result<()> {
        self.sequence = self.sequence.wrapping_add(1);
        let message = encode(
            message_type,
            NLM_F_REQUEST | NLM_F_ACK,
            self.sequence,
            AF_UNSPEC,
            res_id,
            attributes,
        );
        self.socket.send(&message, 0)?;
        loop {
            self.receive()?;
            for message in messages(&self.buffer) {
                if message.message_type == NLMSG_ERROR && message.sequence == self.sequence {
                    return match ack_error(message.body) {
                        0 => Ok(()),
                        code => Err(io::Error::from_raw_os_error(-code)),
                    };
                }
            }
        }
    }

    fn receive(&mut self) -> io::Result<()> {
        self.buffer.clear();
        self.socket.recv(&mut self.buffer, 0)?;
        Ok(())
    }
}

/// Receives packets logged to an NFLOG group.
pub struct NflogSocket {
    inner: NetfilterSocket,
}

impl NflogSocket {
    pub fn bind(group: u16) -> io::Result<Self> {
        let mut inner = NetfilterSocket::open()?;
        let config = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
        // Make nfnetlink_log the logging backend of the families Portcullis logs from.
        // Only needed on old kernels; newer ones ignore it.
        for family in [AF_INET, AF_BRIDGE] {
            let _ = inner.request(
                config,
                family,
                &attribute(NFULA_CFG_CMD, &[NFULNL_CFG_CMD_PF_UNBIND]),
            );
            let _ = inner.request(
                config,
                family,
                &attribute(NFULA_CFG_CMD, &[NFULNL_CFG_CMD_PF_BIND]),
            );
        }
        inner.request(
            config,
            group,
            &attribute(NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND]),
        )?;
        let mut mode = Vec::with_capacity(8);
        mode.extend_from_slice(&0xffff_u32.to_be_bytes());
        mode.extend_from_slice(&[NFULNL_COPY_PACKET, 0]);
        inner.request(config, group, &attribute(NFULA_CFG_MODE, &mode))?;
        // Deliver every packet at once instead of batching them for up to a second.
        inner.request(
            config,
            group,
            &attribute(NFULA_CFG_QTHRESH, &1_u32.to_be_bytes()),
        )?;
        Ok(Self { inner })
    }

    /// Block until packets arrive. Fails with `ENOBUFS` when the kernel had to drop packets
    /// because they weren't read fast enough; reading can continue after that.
    pub fn receive(&mut self) -> io::Result<Vec<LoggedPacket>> {
        self.inner.receive()?;
        Ok(parse_logged(&self.inner.buffer))
    }
}

/// Receives packets held in an NFQUEUE and issues their verdicts.
pub struct NfqueueSocket {
    inner: NetfilterSocket,
    queue: u16,
}

impl NfqueueSocket {
    pub fn bind(queue: u16) -> io::Result<Self> {
        let mut inner = NetfilterSocket::open()?;
        let config = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
        let mut command = vec![NFQNL_CFG_CMD_BIND, 0];
        command.extend_from_slice(&AF_INET.to_be_bytes());
        inner.request(config, queue, &attribute(NFQA_CFG_CMD, &command))?;
        let mut params = Vec::with_capacity(5);
        params.extend_from_slice(&0xffff_u32.to_be_bytes());
        params.push(NFQNL_COPY_PACKET);
        inner.request(config, queue, &attribute(NFQA_CFG_PARAMS, &params))?;
        Ok(Self { inner, queue })
    }

    /// Block until packets arrive.
    pub fn receive(&mut self) -> io::Result<Vec<QueuedPacket>> {
        self.inner.receive()?;
        Ok(parse_queued(&self.inner.buffer))
    }

    /// Decide what happens to a held packet.
    pub fn verdict(&self, id: u32, verdict: QueueVerdict) -> io::Result<()> {
        self.inner
            .socket
            .send(&encode_verdict(self.queue, id, verdict), 0)?;
        Ok(())
    }

    /// A handle that issues verdicts from another thread while this one waits for packets.
    /// The kernel only accepts verdicts from the socket the queue is bound to; the handle
    /// writes to a duplicate of its file descriptor, which is the same socket.
    pub fn verdict_writer(&self) -> io::Result<VerdictWriter> {
        Ok(VerdictWriter {
            socket: File::from(self.inner.socket.as_fd().try_clone_to_owned()?),
            queue: self.queue,
        })
    }
}

/// Issues verdicts for an [`NfqueueSocket`] from another thread.
#[derive(Debug)]
pub struct VerdictWriter {
    socket: File,
    queue: u16,
}

impl VerdictWriter {
    pub fn verdict(&self, id: u32, verdict: QueueVerdict) -> io::Result<()> {
        let message = encode_verdict(self.queue, id, verdict);
        // One write is one datagram, i.e. one netlink message.
        let written = (&self.socket).write(&message)?;
        if written == message.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short netlink write",
            ))
        }
    }
}

fn parse_logged(buffer: &[u8]) -> Vec<LoggedPacket> {
    messages(buffer)
        .filter(|message| message.message_type == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET)
        .filter_map(|message| {
            let mut packet = LoggedPacket::default();
            for (kind, value) in attributes(message.body.get(NFGENMSG_LEN..)?) {
                match kind {
                    NFULA_PREFIX => {
                        let text = value.split(|byte| *byte == 0).next().unwrap_or_default();
                        packet.prefix = String::from_utf8_lossy(text).into_owned();
                    }
                    NFULA_IFINDEX_INDEV => packet.indev = be_u32(value),
                    NFULA_IFINDEX_PHYSINDEV => packet.physindev = be_u32(value),
                    NFULA_HWADDR => packet.hwaddr = hardware_address(value),
                    NFULA_PAYLOAD => packet.payload = value.to_vec(),
                    _ => {}
                }
            }
            Some(packet)
        })
        .collect()
}

fn parse_queued(buffer: &[u8]) -> Vec<QueuedPacket> {
    messages(buffer)
        .filter(|message| message.message_type == (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)
        .filter_map(|message| {
            let mut id = None;
            let mut physindev = None;
            let mut hwaddr = None;
            let mut payload = Vec::new();
            for (kind, value) in attributes(message.body.get(NFGENMSG_LEN..)?) {
                match kind {
                    NFQA_PACKET_HDR => id = be_u32(value),
                    NFQA_IFINDEX_PHYSINDEV => physindev = be_u32(value),
                    NFQA_HWADDR => hwaddr = hardware_address(value),
                    NFQA_PAYLOAD => payload = value.to_vec(),
                    _ => {}
                }
            }
            Some(QueuedPacket {
                id: id?,
                physindev,
                hwaddr,
                payload,
            })
        })
        .collect()
}

/// `struct nfulnl_msg_packet_hw` and `struct nfqnl_msg_packet_hw`: big-endian length,
/// padding, address.
fn hardware_address(value: &[u8]) -> Option<MacAddress> {
    let length = u16::from_be_bytes(value.get(..2)?.try_into().ok()?);
    if length != 6 {
        return None;
    }
    let octets: [u8; 6] = value.get(4..10)?.try_into().ok()?;
    Some(MacAddress::from(octets))
}

fn be_u32(value: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(value.get(..4)?.try_into().ok()?))
}

/// The error code of an `NLMSG_ERROR` message; 0 is an acknowledgement.
pub(crate) fn ack_error(body: &[u8]) -> i32 {
    body.get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(-libc_eproto(), i32::from_ne_bytes)
}

const fn libc_eproto() -> i32 {
    71
}

pub(crate) const fn align4(length: usize) -> usize {
    (length + 3) & !3
}

fn encode(
    message_type: u16,
    flags: u16,
    sequence: u32,
    family: u8,
    res_id: u16,
    attributes: &[u8],
) -> Vec<u8> {
    let length = NLMSG_HDRLEN + NFGENMSG_LEN + attributes.len();
    let mut message = Vec::with_capacity(length);
    message.extend_from_slice(&u32::try_from(length).unwrap_or(u32::MAX).to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(&[family, 0]);
    message.extend_from_slice(&res_id.to_be_bytes());
    message.extend_from_slice(attributes);
    message
}

pub(crate) fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let length = 4 + value.len();
    let mut attribute = Vec::with_capacity(align4(length));
    attribute.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_ne_bytes());
    attribute.extend_from_slice(&kind.to_ne_bytes());
    attribute.extend_from_slice(value);
    attribute.resize(align4(length), 0);
    attribute
}

pub(crate) struct Message<'a> {
    pub message_type: u16,
    pub sequence: u32,
    pub body: &'a [u8],
}

pub(crate) fn messages(mut buffer: &[u8]) -> impl Iterator<Item = Message<'_>> {
    std::iter::from_fn(move || {
        let header = buffer.get(..NLMSG_HDRLEN)?;
        let length = u32::from_ne_bytes(header.get(..4)?.try_into().ok()?) as usize;
        let message_type = u16::from_ne_bytes(header.get(4..6)?.try_into().ok()?);
        let sequence = u32::from_ne_bytes(header.get(8..12)?.try_into().ok()?);
        let body = buffer.get(NLMSG_HDRLEN..length)?;
        buffer = buffer.get(align4(length)..).unwrap_or_default();
        Some(Message {
            message_type,
            sequence,
            body,
        })
    })
}

pub(crate) fn attributes(mut buffer: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let length = usize::from(u16::from_ne_bytes(buffer.get(..2)?.try_into().ok()?));
        let kind = u16::from_ne_bytes(buffer.get(2..4)?.try_into().ok()?) & NLA_TYPE_MASK;
        if length < 4 {
            return None;
        }
        let value = buffer.get(4..length)?;
        buffer = buffer.get(align4(length)..).unwrap_or_default();
        Some((kind, value))
    })
}

/// IPv4 transport protocol numbers Portcullis cares about.
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;

/// The parts of an IPv4 packet Portcullis looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub protocol: u8,
    /// Ports, for TCP and UDP.
    pub ports: Option<(u16, u16)>,
    /// What follows the TCP or UDP header (DNS messages, for example).
    pub data: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    #[must_use]
    pub fn parse(packet: &'a [u8]) -> Option<Self> {
        let first = *packet.first()?;
        if first >> 4 != 4 {
            return None;
        }
        let header_length = usize::from(first & 0x0f) * 4;
        let total_length = usize::from(u16::from_be_bytes(packet.get(2..4)?.try_into().ok()?));
        let protocol = *packet.get(9)?;
        let source = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(12..16)?).ok()?);
        let destination = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(16..20)?).ok()?);
        // Logged packets may be truncated; don't read past what was copied.
        let transport = packet.get(header_length..total_length.min(packet.len()))?;

        let (ports, data) = match protocol {
            PROTOCOL_TCP | PROTOCOL_UDP => {
                let source_port = u16::from_be_bytes(transport.get(..2)?.try_into().ok()?);
                let destination_port = u16::from_be_bytes(transport.get(2..4)?.try_into().ok()?);
                let data_offset = if protocol == PROTOCOL_TCP {
                    usize::from(transport.get(12)? >> 4) * 4
                } else {
                    8
                };
                (
                    Some((source_port, destination_port)),
                    transport.get(data_offset..).unwrap_or_default(),
                )
            }
            _ => (None, transport),
        };
        Some(Self {
            source,
            destination,
            protocol,
            ports,
            data,
        })
    }
}

/// The parts of an ARP packet (Ethernet and IPv4) Portcullis looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub sender_mac: MacAddress,
    pub sender: Ipv4Addr,
    pub target: Ipv4Addr,
}

impl ArpPacket {
    /// Hardware type Ethernet, protocol type IPv4, 6-byte MACs and 4-byte addresses.
    const HEADER: [u8; 6] = [0, 1, 8, 0, 6, 4];

    #[must_use]
    pub fn parse(packet: &[u8]) -> Option<Self> {
        if packet.get(..6)? != Self::HEADER {
            return None;
        }
        let sender_mac = <[u8; 6]>::try_from(packet.get(8..14)?).ok()?;
        let sender = <[u8; 4]>::try_from(packet.get(14..18)?).ok()?;
        let target = <[u8; 4]>::try_from(packet.get(24..28)?).ok()?;
        Some(Self {
            sender_mac: MacAddress::from(sender_mac),
            sender: Ipv4Addr::from(sender),
            target: Ipv4Addr::from(target),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// An ARP request from `sender` for `target`.
    pub fn arp(sender_mac: [u8; 6], sender: [u8; 4], target: [u8; 4]) -> Vec<u8> {
        let mut packet = ArpPacket::HEADER.to_vec();
        packet.extend_from_slice(&[0, 1]);
        packet.extend_from_slice(&sender_mac);
        packet.extend_from_slice(&sender);
        packet.extend_from_slice(&[0; 6]);
        packet.extend_from_slice(&target);
        packet
    }

    #[test]
    fn parses_arp_packets() {
        let packet = arp([2, 0, 0, 0, 0, 1], [172, 18, 0, 2], [172, 18, 0, 1]);
        assert_eq!(
            ArpPacket::parse(&packet),
            Some(ArpPacket {
                sender_mac: MacAddress::from([2, 0, 0, 0, 0, 1]),
                sender: Ipv4Addr::new(172, 18, 0, 2),
                target: Ipv4Addr::new(172, 18, 0, 1),
            })
        );
        assert_eq!(ArpPacket::parse(&packet[..20]), None);
        assert_eq!(
            ArpPacket::parse(&ipv4([1; 4], [2; 4], PROTOCOL_UDP, &[])),
            None
        );
    }

    /// An IPv4 packet with the given transport header and data.
    pub fn ipv4(source: [u8; 4], destination: [u8; 4], protocol: u8, transport: &[u8]) -> Vec<u8> {
        let total = 20 + transport.len();
        let mut packet = vec![0x45, 0];
        packet.extend_from_slice(&u16::try_from(total).expect("length").to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
        packet.extend_from_slice(&source);
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(transport);
        packet
    }

    pub fn udp(source_port: u16, destination_port: u16, data: &[u8]) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&source_port.to_be_bytes());
        header.extend_from_slice(&destination_port.to_be_bytes());
        header.extend_from_slice(&u16::try_from(8 + data.len()).expect("length").to_be_bytes());
        header.extend_from_slice(&[0, 0]);
        header.extend_from_slice(data);
        header
    }

    fn tcp_syn(source_port: u16, destination_port: u16) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&source_port.to_be_bytes());
        header.extend_from_slice(&destination_port.to_be_bytes());
        header.extend_from_slice(&[0; 8]);
        header.extend_from_slice(&[0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0]);
        header
    }

    #[test]
    fn parses_tcp_and_udp_packets() {
        let tcp = ipv4(
            [172, 18, 0, 2],
            [1, 1, 1, 1],
            PROTOCOL_TCP,
            &tcp_syn(40000, 443),
        );
        let parsed = Ipv4Packet::parse(&tcp).expect("tcp");
        assert_eq!(parsed.source, Ipv4Addr::new(172, 18, 0, 2));
        assert_eq!(parsed.destination, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(parsed.ports, Some((40000, 443)));
        assert!(parsed.data.is_empty());

        let udp = ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            PROTOCOL_UDP,
            &udp(53, 5353, b"dns"),
        );
        let parsed = Ipv4Packet::parse(&udp).expect("udp");
        assert_eq!(parsed.ports, Some((53, 5353)));
        assert_eq!(parsed.data, b"dns");
    }

    #[test]
    fn rejects_non_ipv4_and_truncated_packets() {
        assert!(Ipv4Packet::parse(&[0x60; 40]).is_none());
        assert!(Ipv4Packet::parse(&[0x45, 0, 0]).is_none());
    }

    #[test]
    fn parses_logged_packets() {
        let payload = ipv4(
            [172, 18, 0, 2],
            [1, 1, 1, 1],
            PROTOCOL_TCP,
            &tcp_syn(1, 443),
        );
        let mut hwaddr = vec![0, 6, 0, 0, 2, 0x42, 0xac, 0x12, 0, 2, 0, 0];
        hwaddr.truncate(12);
        let mut attributes = Vec::new();
        attributes.extend(attribute(NFULA_PREFIX, b"pc:d:egress\0"));
        attributes.extend(attribute(NFULA_IFINDEX_INDEV, &7_u32.to_be_bytes()));
        attributes.extend(attribute(NFULA_HWADDR, &hwaddr));
        attributes.extend(attribute(NFULA_PAYLOAD, &payload));
        let mut buffer = encode(
            (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET,
            0,
            0,
            2,
            1,
            &attributes,
        );
        // A second message in the same datagram.
        buffer.extend(encode(
            (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET,
            0,
            0,
            2,
            1,
            &attribute(NFULA_PREFIX, b"pc:a:icc\0"),
        ));

        let packets = parse_logged(&buffer);
        assert_eq!(packets.len(), 2);
        let first = packets.first().expect("first");
        assert_eq!(first.prefix, "pc:d:egress");
        assert_eq!(first.indev, Some(7));
        assert_eq!(
            first.hwaddr.map(|mac| mac.to_string()).as_deref(),
            Some("02:42:ac:12:00:02")
        );
        assert_eq!(first.payload, payload);
        assert_eq!(
            packets.get(1).map(|packet| packet.prefix.as_str()),
            Some("pc:a:icc")
        );
    }

    #[test]
    fn parses_queued_packets() {
        let mut header = 42_u32.to_be_bytes().to_vec();
        header.extend_from_slice(&[0x08, 0x00, 2]);
        let mut attributes = attribute(NFQA_PACKET_HDR, &header);
        attributes.extend(attribute(NFQA_IFINDEX_PHYSINDEV, &5_u32.to_be_bytes()));
        attributes.extend(attribute(
            NFQA_HWADDR,
            &[0, 6, 0, 0, 2, 0x42, 0xac, 0x12, 0, 2, 0, 0],
        ));
        attributes.extend(attribute(NFQA_PAYLOAD, b"packet"));
        let buffer = encode(
            (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET,
            0,
            0,
            2,
            0,
            &attributes,
        );
        assert_eq!(
            parse_queued(&buffer),
            vec![QueuedPacket {
                id: 42,
                physindev: Some(5),
                hwaddr: Some(MacAddress::new([2, 0x42, 0xac, 0x12, 0, 2])),
                payload: b"packet".to_vec()
            }]
        );
    }

    #[test]
    fn encodes_verdicts() {
        let parse = |message: &[u8]| -> Vec<(u16, Vec<u8>)> {
            attributes(
                message
                    .get(NLMSG_HDRLEN + NFGENMSG_LEN..)
                    .expect("attributes"),
            )
            .map(|(kind, value)| (kind, value.to_vec()))
            .collect()
        };
        let accept = parse(&encode_verdict(9, 42, QueueVerdict::Accept));
        assert_eq!(
            accept,
            vec![(
                NFQA_VERDICT_HDR,
                [1_u32.to_be_bytes(), 42_u32.to_be_bytes()].concat()
            )]
        );

        let repeat = parse(&encode_verdict(
            9,
            42,
            QueueVerdict::Repeat { mark: Some(0xabcd) },
        ));
        assert_eq!(
            repeat,
            vec![
                (
                    NFQA_VERDICT_HDR,
                    [4_u32.to_be_bytes(), 42_u32.to_be_bytes()].concat()
                ),
                (NFQA_MARK, 0xabcd_u32.to_be_bytes().to_vec()),
            ]
        );
        let message = encode_verdict(9, 42, QueueVerdict::Accept);
        assert_eq!(
            message.get(NLMSG_HDRLEN + 2..NLMSG_HDRLEN + 4),
            Some(9_u16.to_be_bytes().as_slice())
        );
    }

    #[test]
    fn reads_acknowledgements() {
        assert_eq!(ack_error(&0_i32.to_ne_bytes()), 0);
        assert_eq!(ack_error(&(-16_i32).to_ne_bytes()), -16);
        assert_eq!(ack_error(&[]), -71);
    }
}
