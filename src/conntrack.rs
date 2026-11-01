//! Connection tracking (ctnetlink): forgets the connections of addresses that change hands.
//!
//! Docker hands the address of a removed container to the next container at once, and
//! connection tracking still knows the old container's connections, by address and port.
//! The rules let established traffic through, so the new container could keep using
//! connections it isn't allowed to open, for example a UDP flow to a destination only the
//! old container may reach. Portcullis deletes every tracked connection of such an address
//! before rules for its new owner are applied.

use std::collections::HashSet;
use std::io;
use std::net::IpAddr;

use netlink_sys::protocols::NETLINK_NETFILTER;
use tracing::debug;

use crate::nfnetlink::{attribute, attributes};
use crate::rtnetlink::RouteSocket;

const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_NEW: u16 = 0;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLA_F_NESTED: u16 = 0x8000;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_ZONE: u16 = 18;
const CTA_TUPLE_IP: u16 = 1;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const ENOENT: i32 = 2;

/// A tracked connection, as much of it as is needed to find and delete it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tracked {
    /// Source and destination of the original direction.
    original: (IpAddr, IpAddr),
    /// Source and destination of the reply direction (they differ from the original's
    /// with NAT).
    reply: (IpAddr, IpAddr),
    /// The original tuple attribute as the kernel sent it, which identifies the connection.
    tuple: Vec<u8>,
    zone: Option<Vec<u8>>,
}

impl Tracked {
    fn involves(&self, addresses: &HashSet<IpAddr>) -> bool {
        [self.original.0, self.original.1, self.reply.0, self.reply.1]
            .iter()
            .any(|address| addresses.contains(address))
    }
}

/// Delete every tracked connection from, to or translated to one of `addresses`. Returns
/// how many were deleted.
pub fn forget(addresses: &HashSet<IpAddr>) -> io::Result<usize> {
    if addresses.is_empty() {
        return Ok(0);
    }
    let mut socket = RouteSocket::open_protocol(NETLINK_NETFILTER)?;
    let mut found = Vec::new();
    socket.exchange(
        (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
        NLM_F_DUMP,
        &nfgenmsg(AF_UNSPEC),
        |message_type, body| {
            if message_type == (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW {
                found.extend(parse(body).filter(|tracked| tracked.involves(addresses)));
            }
            false
        },
    )?;
    let mut deleted = 0;
    for tracked in found {
        let family = if tracked.original.0.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        let mut request = nfgenmsg(family);
        request.extend(attribute(CTA_TUPLE_ORIG | NLA_F_NESTED, &tracked.tuple));
        if let Some(zone) = &tracked.zone {
            request.extend(attribute(CTA_ZONE, zone));
        }
        match socket.exchange(
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE,
            NLM_F_ACK,
            &request,
            |_, _| true,
        ) {
            Ok(()) => deleted += 1,
            // Gone in the meantime.
            Err(error) if error.raw_os_error() == Some(ENOENT) => {}
            Err(error) => return Err(error),
        }
    }
    debug!(
        deleted,
        "forgot tracked connections of reassigned addresses"
    );
    Ok(deleted)
}

/// `struct nfgenmsg`: family, version 0, resource ID 0.
fn nfgenmsg(family: u8) -> Vec<u8> {
    vec![family, 0, 0, 0]
}

/// A tracked connection from the body of an `IPCTNL_MSG_CT_NEW` message.
fn parse(body: &[u8]) -> Option<Tracked> {
    let mut original = None;
    let mut reply = None;
    let mut tuple = None;
    let mut zone = None;
    for (kind, value) in attributes(body.get(4..)?) {
        match kind {
            CTA_TUPLE_ORIG => {
                original = addresses(value);
                tuple = Some(value.to_vec());
            }
            CTA_TUPLE_REPLY => reply = addresses(value),
            CTA_ZONE => zone = Some(value.to_vec()),
            _ => {}
        }
    }
    Some(Tracked {
        original: original?,
        reply: reply?,
        tuple: tuple?,
        zone,
    })
}

/// Source and destination of a tuple attribute.
fn addresses(tuple: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let (_, ip) = attributes(tuple).find(|(kind, _)| *kind == CTA_TUPLE_IP)?;
    let mut source = None;
    let mut destination = None;
    for (kind, value) in attributes(ip) {
        let address = match kind {
            CTA_IP_V4_SRC | CTA_IP_V4_DST => <[u8; 4]>::try_from(value).ok().map(IpAddr::from),
            CTA_IP_V6_SRC | CTA_IP_V6_DST => <[u8; 16]>::try_from(value).ok().map(IpAddr::from),
            _ => None,
        };
        match kind {
            CTA_IP_V4_SRC | CTA_IP_V6_SRC => source = address,
            CTA_IP_V4_DST | CTA_IP_V6_DST => destination = address,
            _ => {}
        }
    }
    Some((source?, destination?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut ip = attribute(CTA_IP_V4_SRC, &source);
        ip.extend(attribute(CTA_IP_V4_DST, &destination));
        let mut tuple = attribute(CTA_TUPLE_IP | NLA_F_NESTED, &ip);
        // CTA_TUPLE_PROTO with CTA_PROTO_NUM UDP.
        tuple.extend(attribute(2 | NLA_F_NESTED, &attribute(1, &[17])));
        tuple
    }

    #[test]
    fn parses_tracked_connections() {
        let original = tuple([172, 18, 0, 3], [198, 51, 100, 4]);
        let mut body = nfgenmsg(AF_INET);
        body.extend(attribute(CTA_TUPLE_ORIG | NLA_F_NESTED, &original));
        body.extend(attribute(
            CTA_TUPLE_REPLY | NLA_F_NESTED,
            &tuple([198, 51, 100, 4], [198, 51, 100, 1]),
        ));
        let tracked = parse(&body).expect("tracked");
        assert_eq!(tracked.tuple, original);
        assert_eq!(tracked.zone, None);
        let ip = |value: &str| value.parse::<IpAddr>().expect("ip");
        assert_eq!(tracked.original, (ip("172.18.0.3"), ip("198.51.100.4")));
        assert_eq!(tracked.reply, (ip("198.51.100.4"), ip("198.51.100.1")));

        assert!(tracked.involves(&HashSet::from([ip("172.18.0.3")])));
        // Translated addresses count too: the reply of a published port goes to the
        // container behind it.
        assert!(tracked.involves(&HashSet::from([ip("198.51.100.1")])));
        assert!(!tracked.involves(&HashSet::from([ip("172.18.0.4")])));
    }

    #[test]
    fn skips_messages_without_tuples() {
        assert_eq!(parse(&nfgenmsg(AF_INET)), None);
        assert_eq!(parse(&[]), None);
    }
}
