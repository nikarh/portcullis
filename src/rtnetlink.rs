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
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::path::Path;

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use tracing::debug;

use crate::model::{BridgePort, ContainerId, MacAddress, RuntimeState};

use crate::nfnetlink::{
    NLM_F_REQUEST, NLMSG_ERROR, NLMSG_HDRLEN, ack_error, align4, attribute, attributes, messages,
};

const NLMSG_DONE: u16 = 3;
const NLM_F_DUMP: u16 = 0x300;

const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWNSID: u16 = 88;
const RTM_GETNSID: u16 = 90;

const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTGENMSG_LEN: usize = 4;

const AF_INET: u8 = 2;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINK: u16 = 5;
const IFLA_MASTER: u16 = 10;
const IFLA_LINK_NETNSID: u16 = 37;
const IFLA_TARGET_NETNSID: u16 = 46;

const IFA_LOCAL: u16 = 2;
const IFA_TARGET_NETNSID: u16 = 10;

const ENODEV: i32 = 19;

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
    /// For a veth, the interface index of its peer, in the peer's namespace.
    pub peer_index: Option<u32>,
    pub mac: Option<MacAddress>,
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

    /// The interface with `index`, in the namespace with ID `namespace` (as this namespace
    /// knows it) or in this one. `None` when there is no such interface.
    pub fn link(&mut self, index: u32, namespace: Option<i32>) -> io::Result<Option<Link>> {
        let mut request = vec![0; IFINFOMSG_LEN];
        request.splice(4..8, index.to_ne_bytes());
        if let Some(namespace) = namespace {
            request.extend(attribute(IFLA_TARGET_NETNSID, &namespace.to_ne_bytes()));
        }
        let mut link = None;
        let result = self.exchange(RTM_GETLINK, 0, &request, |message_type, body| {
            if message_type == RTM_NEWLINK {
                link = parse_link(body);
                return true;
            }
            false
        });
        match result {
            Err(error) if error.raw_os_error() == Some(ENODEV) => Ok(None),
            Err(error) => Err(error),
            Ok(()) => Ok(link),
        }
    }

    /// The IPv4 addresses of interface `index` in the namespace with ID `namespace`. Needs
    /// a socket opened with `open_strict`: without strict checking, the kernel ignores the
    /// target namespace of a dump and answers for this one.
    pub fn ipv4_addresses(&mut self, namespace: i32, index: u32) -> io::Result<Vec<Ipv4Addr>> {
        let mut request = vec![AF_INET];
        request.extend([0; 3]);
        request.extend(index.to_ne_bytes());
        request.extend(attribute(IFA_TARGET_NETNSID, &namespace.to_ne_bytes()));
        let mut addresses = Vec::new();
        self.exchange(RTM_GETADDR, NLM_F_DUMP, &request, |message_type, body| {
            if message_type == RTM_NEWADDR {
                addresses.extend(parse_ipv4_address(body, index));
            }
            false
        })?;
        Ok(addresses)
    }

    /// A `NETLINK_ROUTE` socket with strict checking of requests, see `ipv4_addresses`.
    pub fn open_strict() -> io::Result<Self> {
        let socket = Self::open()?;
        socket.socket.set_netlink_get_strict_chk(true)?;
        Ok(socket)
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

/// Why a container's traffic can't be bound to its bridge port, and is only checked by
/// address and MAC.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PortProblem {
    /// The container's namespace has no ID here, so no port can name it as the peer's.
    NoNamespaceId,
    /// Its namespace couldn't be looked up.
    Namespace(String),
}

impl std::fmt::Display for PortProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoNamespaceId => f.write_str("the container's network namespace has no ID here"),
            Self::Namespace(error) => {
                write!(
                    f,
                    "can't identify the container's network namespace: {error}"
                )
            }
        }
    }
}

/// Bridge ports by container address, and the containers whose port can't be found.
pub type Ports = (HashMap<IpAddr, BridgePort>, Vec<(ContainerId, PortProblem)>);

/// The bridge port of every address of a running container on a managed network, and
/// what kept others from being found; their traffic is then only checked by address and
/// MAC.
pub fn container_ports(state: &RuntimeState) -> io::Result<Ports> {
    let mut socket = RouteSocket::open()?;
    let links = socket.links()?;
    Ok(match_ports(state, &links, |path| socket.namespace_id(path)))
}

/// `container_ports` for the host's `links`, with `namespace_id` telling the ID of a
/// namespace file.
///
/// A container that is stopping isn't a problem: Docker takes its interfaces back to the
/// host and removes them, and its namespace, before it reports the container gone, and a
/// container without a port on a bridge can't send anything there. The kernel names the
/// peer's namespace of every veth whose peer is in another one (giving the namespace an ID
/// if it has none), so a container that has a port is always found by it. Only a
/// container whose namespace can't be identified is a problem.
fn match_ports(
    state: &RuntimeState,
    links: &[Link],
    mut namespace_id: impl FnMut(&Path) -> io::Result<Option<i32>>,
) -> Ports {
    let mut ports = HashMap::new();
    let mut problems = Vec::new();
    for container in state.containers().values() {
        if container.attachments.is_empty() {
            continue;
        }
        let Some(sandbox) = &container.sandbox else {
            continue;
        };
        let namespace = match namespace_id(Path::new(sandbox)) {
            Ok(Some(namespace)) => namespace,
            Ok(None) => {
                problems.push((container.id.clone(), PortProblem::NoNamespaceId));
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                debug!(container = %container.name, "the container's network namespace is gone; it is stopping");
                continue;
            }
            Err(error) => {
                problems.push((
                    container.id.clone(),
                    PortProblem::Namespace(error.to_string()),
                ));
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
            if let Some(port) = links.iter().find(|link| {
                link.master == Some(bridge.index) && link.peer_namespace == Some(namespace)
            }) {
                ports.insert(
                    attachment.ip_address,
                    BridgePort {
                        name: port.name.clone(),
                        index: port.index,
                    },
                );
            } else {
                debug!(container = %container.name, bridge = %network.bridge, "the container has no port on the bridge; it is stopping, or not attached yet");
            }
        }
    }
    (ports, problems)
}

fn parse_link(body: &[u8]) -> Option<Link> {
    let index = u32::from_ne_bytes(body.get(4..8)?.try_into().ok()?);
    let mut link = Link {
        index,
        name: String::new(),
        master: None,
        peer_namespace: None,
        peer_index: None,
        mac: None,
    };
    for (kind, value) in attributes(body.get(IFINFOMSG_LEN..)?) {
        match kind {
            IFLA_IFNAME => {
                let name = value.split(|byte| *byte == 0).next().unwrap_or_default();
                link.name = String::from_utf8_lossy(name).into_owned();
            }
            IFLA_MASTER => link.master = ne_u32(value),
            IFLA_LINK_NETNSID => link.peer_namespace = ne_u32(value).map(u32::cast_signed),
            IFLA_LINK => link.peer_index = ne_u32(value),
            IFLA_ADDRESS => {
                link.mac = <[u8; 6]>::try_from(value).ok().map(MacAddress::from);
            }
            _ => {}
        }
    }
    Some(link)
}

/// The address of an `RTM_NEWADDR` message, if it is an IPv4 address of interface `index`.
fn parse_ipv4_address(body: &[u8], index: u32) -> Option<Ipv4Addr> {
    if *body.first()? != AF_INET || u32::from_ne_bytes(body.get(4..8)?.try_into().ok()?) != index {
        return None;
    }
    attributes(body.get(IFADDRMSG_LEN..)?)
        .find(|(kind, _)| *kind == IFA_LOCAL)
        .and_then(|(_, value)| <[u8; 4]>::try_from(value).ok())
        .map(Ipv4Addr::from)
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

    mod ports {
        use super::super::*;
        use crate::firewall::test_support;
        use crate::model::{ContainerPolicy, RuntimeStateAction};

        /// `app` (172.18.0.2, namespace file `/ns/app`) on `net0` (bridge `br-net0`, index 1).
        fn state() -> RuntimeState {
            let mut state = RuntimeState::default();
            test_support::add_network(&mut state, "net0", "172.18.0.0/16", "172.18.0.1");
            test_support::add_container(
                &mut state,
                "a",
                "app",
                &[("net0", "172.18.0.2", &[])],
                ContainerPolicy::default(),
            );
            let mut app = state.containers().get("a").cloned().expect("app");
            app.sandbox = Some("/ns/app".to_string());
            state.apply_action(RuntimeStateAction::CreateContainer {
                container: Box::new(app),
            });
            state
        }

        fn link(index: u32, name: &str, master: Option<u32>, peer: Option<i32>) -> Link {
            Link {
                index,
                name: name.to_string(),
                master,
                peer_namespace: peer,
                peer_index: None,
                mac: None,
            }
        }

        fn bridge_with(ports: &[Link]) -> Vec<Link> {
            let mut links = vec![link(1, "br-net0", None, None)];
            links.extend_from_slice(ports);
            links
        }

        #[test]
        fn finds_the_port_whose_peer_is_in_the_containers_namespace() {
            let links = bridge_with(&[
                link(7, "veth-other", Some(1), Some(4)),
                link(8, "veth-app", Some(1), Some(5)),
            ]);
            let (ports, problems) = match_ports(&state(), &links, |_| Ok(Some(5)));
            assert_eq!(
                ports
                    .get(&test_support::ip("172.18.0.2"))
                    .map(|port| port.name.as_str()),
                Some("veth-app")
            );
            assert_eq!(problems, []);
        }

        #[test]
        fn a_stopping_container_is_no_problem() {
            // Its namespace is gone...
            let links = bridge_with(&[link(8, "veth-app", Some(1), Some(5))]);
            let gone = |_: &Path| Err(io::Error::from(io::ErrorKind::NotFound));
            let (ports, problems) = match_ports(&state(), &links, gone);
            assert!(ports.is_empty());
            assert_eq!(problems, []);
            // ...or still there, its interface taken back to the host: its port's peer is
            // on the host, and no port's peer is in its namespace.
            let links = bridge_with(&[
                link(7, "veth-other", Some(1), Some(4)),
                link(8, "veth-app", Some(1), None),
            ]);
            let (ports, problems) = match_ports(&state(), &links, |_| Ok(Some(5)));
            assert!(ports.is_empty());
            assert_eq!(problems, []);
        }

        #[test]
        fn reports_what_keeps_a_port_from_being_found() {
            let id = ContainerId::from("a".to_string());
            let links = bridge_with(&[link(8, "veth-app", Some(1), Some(5))]);
            let (_, problems) = match_ports(&state(), &links, |_| Ok(None));
            assert_eq!(problems, [(id.clone(), PortProblem::NoNamespaceId)]);
            let denied = |_: &Path| Err(io::Error::from(io::ErrorKind::PermissionDenied));
            let (_, problems) = match_ports(&state(), &links, denied);
            assert!(matches!(
                problems.as_slice(),
                [(container, PortProblem::Namespace(_))] if *container == id
            ));
        }
    }

    #[test]
    fn parses_links() {
        let mut body = vec![0_u8; IFINFOMSG_LEN];
        body.splice(4..8, 7_u32.to_ne_bytes());
        body.extend(attribute(IFLA_IFNAME, b"veth1234\0"));
        body.extend(attribute(IFLA_MASTER, &3_u32.to_ne_bytes()));
        body.extend(attribute(IFLA_LINK_NETNSID, &2_i32.to_ne_bytes()));
        body.extend(attribute(IFLA_LINK, &12_u32.to_ne_bytes()));
        body.extend(attribute(IFLA_ADDRESS, &[2, 0x42, 0xac, 0x12, 0, 2]));
        assert_eq!(
            parse_link(&body),
            Some(Link {
                index: 7,
                name: "veth1234".to_string(),
                master: Some(3),
                peer_namespace: Some(2),
                peer_index: Some(12),
                mac: Some(MacAddress::new([2, 0x42, 0xac, 0x12, 0, 2])),
            })
        );
    }

    #[test]
    fn parses_ipv4_addresses_of_one_interface() {
        let message = |family: u8, index: u32| {
            let mut body = vec![family, 0, 0, 0];
            body.extend(index.to_ne_bytes());
            body.extend(attribute(IFA_LOCAL, &[172, 18, 0, 2]));
            body
        };
        assert_eq!(
            parse_ipv4_address(&message(AF_INET, 5), 5),
            Some(Ipv4Addr::new(172, 18, 0, 2))
        );
        assert_eq!(parse_ipv4_address(&message(AF_INET, 6), 5), None);
        assert_eq!(parse_ipv4_address(&message(10, 5), 5), None);
    }

    #[test]
    fn parses_namespace_ids() {
        let mut body = vec![0_u8; RTGENMSG_LEN];
        body.extend(attribute(NETNSA_NSID, &(-1_i32).to_ne_bytes()));
        assert_eq!(parse_namespace_id(&body), Some(-1));
    }
}
