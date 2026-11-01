//! Minimal rtnetlink client: which bridge port (the host side of a veth pair) belongs to
//! which container.
//!
//! Docker reports each container's network namespace as a file (`SandboxKey`). The kernel
//! tells which ID that namespace has here (`RTM_GETNSID`), and every host interface whose
//! peer lives in another namespace carries that namespace's ID (`IFLA_LINK_NETNSID`). A
//! container's port on a bridge is the interface attached to the bridge (`IFLA_MASTER`)
//! whose peer is in the container's namespace. Nothing runs inside the container's
//! namespace, so nothing the container controls is consulted.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::Path;

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use tracing::warn;

use crate::model::{BridgePort, RuntimeState};

use crate::nfnetlink::{
    NLM_F_REQUEST, NLMSG_ERROR, NLMSG_HDRLEN, ack_error, align4, attribute, attributes, messages,
};

const NLMSG_DONE: u16 = 3;
const NLM_F_DUMP: u16 = 0x300;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWNSID: u16 = 88;
const RTM_GETNSID: u16 = 90;

const IFINFOMSG_LEN: usize = 16;
const RTGENMSG_LEN: usize = 4;

const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFLA_LINK_NETNSID: u16 = 37;

const NETNSA_NSID: u16 = 1;
const NETNSA_FD: u16 = 3;

/// A network interface of the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    /// The bridge (or other master) the interface is attached to.
    pub master: Option<u32>,
    /// For a veth, the namespace of its peer.
    pub peer_namespace: Option<i32>,
}

/// A netlink socket for requests and dumps: `NETLINK_ROUTE` here, `NETLINK_NETFILTER` for
/// connection tracking.
pub struct RouteSocket {
    socket: Socket,
    buffer: Vec<u8>,
    sequence: u32,
}

impl RouteSocket {
    pub fn open() -> io::Result<Self> {
        Self::open_protocol(NETLINK_ROUTE)
    }

    pub fn open_protocol(protocol: isize) -> io::Result<Self> {
        let mut socket = Socket::new(protocol)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            buffer: Vec::with_capacity(1 << 16),
            sequence: 0,
        })
    }

    /// Every interface of the host.
    pub fn links(&mut self) -> io::Result<Vec<Link>> {
        let mut links = Vec::new();
        self.exchange(
            RTM_GETLINK,
            NLM_F_DUMP,
            &[0; IFINFOMSG_LEN],
            |message_type, body| {
                if message_type == RTM_NEWLINK {
                    links.extend(parse_link(body));
                }
                false
            },
        )?;
        Ok(links)
    }

    /// The ID the network namespace at `path` has in this namespace, if it has one.
    pub fn namespace_id(&mut self, path: &Path) -> io::Result<Option<i32>> {
        let namespace = File::open(path)?;
        let fd = u32::try_from(namespace.as_raw_fd()).map_err(io::Error::other)?;
        let mut request = vec![0; RTGENMSG_LEN];
        request.extend(attribute(NETNSA_FD, &fd.to_ne_bytes()));
        let mut id = None;
        self.exchange(RTM_GETNSID, 0, &request, |message_type, body| {
            if message_type == RTM_NEWNSID {
                id = parse_namespace_id(body);
                return true;
            }
            false
        })?;
        // The fd must stay open until the kernel has answered.
        drop(namespace);
        Ok(id.filter(|id| *id >= 0))
    }

    /// Send a request and pass every answer to `handle` until it returns true, the dump
    /// ends, or the kernel reports an error.
    pub fn exchange(
        &mut self,
        message_type: u16,
        flags: u16,
        body: &[u8],
        mut handle: impl FnMut(u16, &[u8]) -> bool,
    ) -> io::Result<()> {
        self.sequence = self.sequence.wrapping_add(1);
        let length = NLMSG_HDRLEN + body.len();
        let mut message = Vec::with_capacity(align4(length));
        message.extend_from_slice(&u32::try_from(length).unwrap_or(u32::MAX).to_ne_bytes());
        message.extend_from_slice(&message_type.to_ne_bytes());
        message.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
        message.extend_from_slice(&self.sequence.to_ne_bytes());
        message.extend_from_slice(&0_u32.to_ne_bytes());
        message.extend_from_slice(body);
        self.socket.send(&message, 0)?;
        loop {
            self.buffer.clear();
            self.socket.recv(&mut self.buffer, 0)?;
            for message in messages(&self.buffer) {
                if message.sequence != self.sequence {
                    continue;
                }
                match message.message_type {
                    NLMSG_DONE => return Ok(()),
                    NLMSG_ERROR => {
                        return match ack_error(message.body) {
                            0 => Ok(()),
                            code => Err(io::Error::from_raw_os_error(-code)),
                        };
                    }
                    other => {
                        if handle(other, message.body) {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

/// The bridge port of every address of a running container on a managed network. Addresses
/// whose port can't be found are left out; their traffic is then only checked by address
/// and MAC.
pub fn container_ports(state: &RuntimeState) -> io::Result<HashMap<IpAddr, BridgePort>> {
    let mut socket = RouteSocket::open()?;
    let links = socket.links()?;
    let mut ports = HashMap::new();
    for container in state.containers().values() {
        if container.attachments.is_empty() {
            continue;
        }
        let Some(sandbox) = &container.sandbox else {
            continue;
        };
        let namespace = match socket.namespace_id(Path::new(sandbox)) {
            Ok(Some(namespace)) => namespace,
            Ok(None) => {
                warn!(container = %container.name, "the container's network namespace has no ID here; checking its traffic by address and MAC only");
                continue;
            }
            Err(error) => {
                warn!(container = %container.name, %error, "can't identify the container's network namespace; checking its traffic by address and MAC only");
                continue;
            }
        };
        for attachment in &container.attachments {
            let Some(network) = state.networks().get(&attachment.network_id) else {
                continue;
            };
            let Some(bridge) = links.iter().find(|link| link.name == network.bridge) else {
                continue;
            };
            let port = links.iter().find(|link| {
                link.master == Some(bridge.index) && link.peer_namespace == Some(namespace)
            });
            if let Some(port) = port {
                ports.insert(
                    attachment.ip_address,
                    BridgePort {
                        name: port.name.clone(),
                        index: port.index,
                    },
                );
            } else {
                warn!(
                    container = %container.name,
                    bridge = %network.bridge,
                    "can't find the container's port on the bridge; checking its traffic by address and MAC only"
                );
            }
        }
    }
    Ok(ports)
}

fn parse_link(body: &[u8]) -> Option<Link> {
    let index = u32::from_ne_bytes(body.get(4..8)?.try_into().ok()?);
    let mut link = Link {
        index,
        name: String::new(),
        master: None,
        peer_namespace: None,
    };
    for (kind, value) in attributes(body.get(IFINFOMSG_LEN..)?) {
        match kind {
            IFLA_IFNAME => {
                let name = value.split(|byte| *byte == 0).next().unwrap_or_default();
                link.name = String::from_utf8_lossy(name).into_owned();
            }
            IFLA_MASTER => link.master = ne_u32(value),
            IFLA_LINK_NETNSID => link.peer_namespace = ne_u32(value).map(u32::cast_signed),
            _ => {}
        }
    }
    Some(link)
}

fn parse_namespace_id(body: &[u8]) -> Option<i32> {
    attributes(body.get(RTGENMSG_LEN..)?)
        .find(|(kind, _)| *kind == NETNSA_NSID)
        .and_then(|(_, value)| ne_u32(value))
        .map(u32::cast_signed)
}

fn ne_u32(value: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(value.get(..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_links() {
        let mut body = vec![0_u8; IFINFOMSG_LEN];
        body.splice(4..8, 7_u32.to_ne_bytes());
        body.extend(attribute(IFLA_IFNAME, b"veth1234\0"));
        body.extend(attribute(IFLA_MASTER, &3_u32.to_ne_bytes()));
        body.extend(attribute(IFLA_LINK_NETNSID, &2_i32.to_ne_bytes()));
        assert_eq!(
            parse_link(&body),
            Some(Link {
                index: 7,
                name: "veth1234".to_string(),
                master: Some(3),
                peer_namespace: Some(2),
            })
        );
    }

    #[test]
    fn parses_namespace_ids() {
        let mut body = vec![0_u8; RTGENMSG_LEN];
        body.extend(attribute(NETNSA_NSID, &(-1_i32).to_ne_bytes()));
        assert_eq!(parse_namespace_id(&body), Some(-1));
    }
}
