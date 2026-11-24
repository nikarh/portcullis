//! Renewing addresses in hostname sets over nfnetlink: a batch of its own for each DNS
//! answer (or lookup of Portcullis's) that renews a hostname's addresses, sent while the
//! answer is held, without a rule update.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::time::Duration;

use std::io;

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};

use super::netlink::{
    NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END, NFPROTO_INET, NFT_MSG_DELSETELEM, NFT_MSG_GETSETELEM,
    NFT_MSG_NEWSETELEM, NFTA_DATA_VALUE, NFTA_LIST_ELEM, NFTA_SET_ELEM_KEY,
    NFTA_SET_ELEM_LIST_ELEMENTS, NFTA_SET_ELEM_LIST_SET, NFTA_SET_ELEM_LIST_TABLE,
    NFTA_SET_ELEM_TIMEOUT, Writer,
};

const NLM_F_CREATE: u16 = 0x400;

/// A hostname set of the inet table and the address family it holds.
#[derive(Clone, Copy)]
pub struct TimeoutSet<'a> {
    pub name: &'a dyn std::fmt::Display,
    pub ipv6: bool,
}

/// Writes the batch that sets how much longer each address stays in each set: added,
/// deleted and added again, so an address that is there already gets the new timeout
/// (adding an existing element doesn't renew it), and packets see the set before or after,
/// never without an address it keeps. A zero timeout only removes the address.
///
/// Writes into `out`, reusing `name` for set names.
pub fn encode_timeouts(
    out: &mut Vec<u8>,
    name: &mut String,
    table: &str,
    sets: &[TimeoutSet<'_>],
    addresses: &[(IpAddr, Duration)],
) {
    out.clear();
    let out = &mut Writer(out);
    let begin = out.begin(NFNL_MSG_BATCH_BEGIN, 0, 0, 0);
    out.finish(begin);
    for set in sets {
        let family = || {
            addresses
                .iter()
                .filter(move |(address, _)| address.is_ipv6() == set.ipv6)
        };
        if family().next().is_none() {
            continue;
        }
        name.clear();
        let _ = write!(name, "{}", set.name);
        for (kind, flags, renewed_only) in [
            (NFT_MSG_NEWSETELEM, NLM_F_CREATE, false),
            (NFT_MSG_DELSETELEM, 0, false),
            (NFT_MSG_NEWSETELEM, NLM_F_CREATE, true),
        ] {
            let mut elements = family()
                .filter(|(_, timeout)| !renewed_only || !timeout.is_zero())
                .peekable();
            if elements.peek().is_none() {
                continue;
            }
            let message = out.message(kind, flags, NFPROTO_INET);
            out.string(NFTA_SET_ELEM_LIST_TABLE, table);
            out.string(NFTA_SET_ELEM_LIST_SET, name);
            let list = out.nest(NFTA_SET_ELEM_LIST_ELEMENTS);
            for (address, timeout) in elements {
                let element = out.nest(NFTA_LIST_ELEM);
                let key = out.nest(NFTA_SET_ELEM_KEY);
                match address {
                    IpAddr::V4(address) => out.attribute(NFTA_DATA_VALUE, &address.octets()),
                    IpAddr::V6(address) => out.attribute(NFTA_DATA_VALUE, &address.octets()),
                }
                out.end(key);
                if kind == NFT_MSG_NEWSETELEM {
                    out.attribute(
                        NFTA_SET_ELEM_TIMEOUT,
                        &(super::ruleset::timeout_seconds(*timeout) * 1000).to_be_bytes(),
                    );
                }
                out.end(element);
            }
            out.end(list);
            out.finish(message);
        }
    }
    let end = out.begin(NFNL_MSG_BATCH_END, 0, 0, 0);
    out.finish(end);
}

/// The request that asks whether `set` of the inet table `table` holds `address`.
fn encode_lookup(out: &mut Vec<u8>, table: &str, set: &str, address: IpAddr, sequence: u32) {
    out.clear();
    let mut out = Writer(out);
    let message = out.begin(
        (super::netlink::NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSETELEM,
        super::netlink::NLM_F_ACK,
        sequence,
        NFPROTO_INET,
    );
    out.string(NFTA_SET_ELEM_LIST_TABLE, table);
    out.string(NFTA_SET_ELEM_LIST_SET, set);
    let list = out.nest(NFTA_SET_ELEM_LIST_ELEMENTS);
    let element = out.nest(NFTA_LIST_ELEM);
    let key = out.nest(NFTA_SET_ELEM_KEY);
    match address {
        IpAddr::V4(address) => out.attribute(NFTA_DATA_VALUE, &address.octets()),
        IpAddr::V6(address) => out.attribute(NFTA_DATA_VALUE, &address.octets()),
    }
    out.end(key);
    out.end(element);
    out.end(list);
    out.finish(message);
}

/// Asks the kernel whether hostname sets hold addresses, one at a time.
pub struct SetLookup {
    socket: Socket,
    table: &'static str,
    sequence: u32,
    request: Vec<u8>,
    response: Vec<u8>,
}

impl SetLookup {
    /// Look up the sets of the inet table `table`.
    pub fn open(table: &'static str) -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            table,
            sequence: 0,
            request: Vec::new(),
            response: Vec::with_capacity(1 << 12),
        })
    }

    /// Whether `set` holds `address`, and it hasn't expired. A set that doesn't exist
    /// holds nothing.
    pub fn contains(&mut self, set: &str, address: IpAddr) -> io::Result<bool> {
        const ENOENT: i32 = 2;
        self.sequence = self.sequence.wrapping_add(1);
        encode_lookup(&mut self.request, self.table, set, address, self.sequence);
        self.socket.send(&self.request, 0)?;
        loop {
            self.response.clear();
            self.socket.recv(&mut self.response, 0)?;
            for message in crate::nfnetlink::messages(&self.response) {
                if message.message_type != crate::nfnetlink::NLMSG_ERROR
                    || message.sequence != self.sequence
                {
                    continue;
                }
                return match -crate::nfnetlink::ack_error(message.body) {
                    0 => Ok(true),
                    ENOENT => Ok(false),
                    code => Err(io::Error::from_raw_os_error(code)),
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::super::netlink::NFNL_SUBSYS_NFTABLES;
    use super::*;
    use crate::nfnetlink::{attributes, messages};

    fn encoded(addresses: &[(IpAddr, Duration)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut name = String::new();
        let sets = [
            TimeoutSet {
                name: &"pc_h4_1",
                ipv6: false,
            },
            TimeoutSet {
                name: &"pc_h6_1",
                ipv6: true,
            },
        ];
        encode_timeouts(&mut out, &mut name, "portcullis", &sets, addresses);
        out
    }

    /// Keys, with their timeouts in milliseconds.
    type Keys = Vec<(Vec<u8>, Option<u64>)>;

    /// (type, set, keys) of each message.
    fn decode(out: &[u8]) -> Vec<(u16, String, Keys)> {
        messages(out)
            .map(|message| {
                let mut set = String::new();
                let mut elements = Vec::new();
                for (kind, value) in attributes(message.body.get(4..).unwrap_or_default()) {
                    match kind {
                        NFTA_SET_ELEM_LIST_SET => {
                            set = String::from_utf8_lossy(value.strip_suffix(&[0]).unwrap())
                                .into_owned();
                        }
                        NFTA_SET_ELEM_LIST_ELEMENTS => {
                            for (_, element) in attributes(value) {
                                let mut key = Vec::new();
                                let mut timeout = None;
                                for (kind, value) in attributes(element) {
                                    match kind {
                                        NFTA_SET_ELEM_KEY => {
                                            key = attributes(value).next().unwrap().1.to_vec();
                                        }
                                        NFTA_SET_ELEM_TIMEOUT => {
                                            timeout =
                                                Some(u64::from_be_bytes(value.try_into().unwrap()));
                                        }
                                        _ => {}
                                    }
                                }
                                elements.push((key, timeout));
                            }
                        }
                        _ => {}
                    }
                }
                (message.message_type, set, elements)
            })
            .collect()
    }

    #[test]
    fn renews_by_adding_deleting_and_adding_again() {
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
        let gone = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let out = encoded(&[
            (v4, Duration::from_millis(1500)),
            (gone, Duration::ZERO),
            (v6, Duration::from_secs(60)),
        ]);
        let new = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM;
        let del = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_DELSETELEM;
        let four = |address: IpAddr| match address {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        assert_eq!(
            decode(&out),
            vec![
                (NFNL_MSG_BATCH_BEGIN, String::new(), vec![]),
                (
                    new,
                    "pc_h4_1".into(),
                    vec![(four(v4), Some(2000)), (four(gone), Some(1000))]
                ),
                (
                    del,
                    "pc_h4_1".into(),
                    vec![(four(v4), None), (four(gone), None)]
                ),
                (new, "pc_h4_1".into(), vec![(four(v4), Some(2000))]),
                (new, "pc_h6_1".into(), vec![(four(v6), Some(60000))]),
                (del, "pc_h6_1".into(), vec![(four(v6), None)]),
                (new, "pc_h6_1".into(), vec![(four(v6), Some(60000))]),
                (NFNL_MSG_BATCH_END, String::new(), vec![]),
            ]
        );
    }

    #[test]
    fn asks_for_one_element() {
        let mut out = Vec::new();
        let address = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
        encode_lookup(&mut out, "portcullis", "pc_h4_1", address, 5);
        assert_eq!(
            decode(&out),
            vec![(
                (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETSETELEM,
                "pc_h4_1".into(),
                vec![(vec![198, 51, 100, 3], None)]
            )]
        );
        let flags = u16::from_ne_bytes([out[6], out[7]]);
        assert_eq!(
            flags,
            crate::nfnetlink::NLM_F_REQUEST | super::super::netlink::NLM_F_ACK
        );
        assert_eq!(out[16], NFPROTO_INET);
    }

    #[test]
    fn writes_nothing_between_the_markers_without_addresses() {
        let out = encoded(&[]);
        assert_eq!(decode(&out).len(), 2);
    }
}
