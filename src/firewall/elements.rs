//! Renewing addresses in hostname sets over nfnetlink, without libnftables.
//!
//! Before it runs a command that adds or deletes set elements, libnftables loads the
//! elements of every set with `flags interval` the kernel holds, in every table, not just
//! the one the command is about. On a host whose other firewall keeps large sets of ranges
//! (block lists, country lists) that takes tens of megabytes and a good part of a second,
//! for every DNS answer that renews a hostname's addresses, while the answer is held.
//! Renewals go to the kernel directly instead: one batch, applied atomically like a script.

use std::fmt::Write as _;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};

use crate::nfnetlink::{NLM_F_REQUEST, NLMSG_ERROR, ack_error, align4, messages};

const NLM_F_ACK: u16 = 0x4;
const NLM_F_CREATE: u16 = 0x400;
const NLA_F_NESTED: u16 = 0x8000;

const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
const NFNL_MSG_BATCH_END: u16 = 0x11;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_DELSETELEM: u16 = 14;
const NFPROTO_INET: u8 = 1;
const AF_UNSPEC: u8 = 0;

const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
const NFTA_DATA_VALUE: u16 = 1;

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
/// Writes into `out`, reusing `name` for set names; returns the sequence number of the last
/// message, whose acknowledgement ends the batch's answers.
pub fn encode_timeouts(
    out: &mut Vec<u8>,
    name: &mut String,
    table: &str,
    sets: &[TimeoutSet<'_>],
    addresses: &[(IpAddr, Duration)],
    mut sequence: u32,
) -> u32 {
    out.clear();
    let batch_begin = begin(out, NFNL_MSG_BATCH_BEGIN, 0, sequence, AF_UNSPEC);
    finish(out, batch_begin);
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
            sequence = sequence.wrapping_add(1);
            let message = begin(
                out,
                (NFNL_SUBSYS_NFTABLES << 8) | kind,
                flags | NLM_F_ACK,
                sequence,
                NFPROTO_INET,
            );
            string(out, NFTA_SET_ELEM_LIST_TABLE, table);
            string(out, NFTA_SET_ELEM_LIST_SET, name);
            let list = nest(out, NFTA_SET_ELEM_LIST_ELEMENTS);
            for (address, timeout) in elements {
                let element = nest(out, NFTA_LIST_ELEM);
                let key = nest(out, NFTA_SET_ELEM_KEY);
                match address {
                    IpAddr::V4(address) => attribute(out, NFTA_DATA_VALUE, &address.octets()),
                    IpAddr::V6(address) => attribute(out, NFTA_DATA_VALUE, &address.octets()),
                }
                end(out, key);
                if kind == NFT_MSG_NEWSETELEM {
                    attribute(
                        out,
                        NFTA_SET_ELEM_TIMEOUT,
                        &timeout_millis(*timeout).to_be_bytes(),
                    );
                }
                end(out, element);
            }
            end(out, list);
            finish(out, message);
        }
    }
    let last = sequence;
    let batch_end = begin(
        out,
        NFNL_MSG_BATCH_END,
        0,
        sequence.wrapping_add(1),
        AF_UNSPEC,
    );
    finish(out, batch_end);
    last
}

/// The timeout as the nft scripts write it: whole seconds, rounded up, at least one.
fn timeout_millis(timeout: Duration) -> u64 {
    let seconds = timeout.as_secs() + u64::from(timeout.subsec_nanos() > 0);
    seconds.max(1) * 1000
}

/// Start a message, returning where it starts; [`finish`] writes its length. Batch markers
/// carry the nftables subsystem in the resource id.
fn begin(out: &mut Vec<u8>, kind: u16, flags: u16, sequence: u32, family: u8) -> usize {
    let start = out.len();
    out.extend_from_slice(&0_u32.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
    out.extend_from_slice(&sequence.to_ne_bytes());
    out.extend_from_slice(&0_u32.to_ne_bytes());
    out.extend_from_slice(&[family, 0]);
    let resource = if matches!(kind, NFNL_MSG_BATCH_BEGIN | NFNL_MSG_BATCH_END) {
        NFNL_SUBSYS_NFTABLES
    } else {
        0
    };
    out.extend_from_slice(&resource.to_be_bytes());
    start
}

fn finish(out: &mut [u8], start: usize) {
    let length = u32::try_from(out.len() - start).unwrap_or(u32::MAX);
    if let Some(field) = out.get_mut(start..start + 4) {
        field.copy_from_slice(&length.to_ne_bytes());
    }
}

fn attribute(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = 4 + value.len();
    out.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    out.resize(out.len() + align4(length) - length, 0);
}

fn string(out: &mut Vec<u8>, kind: u16, value: &str) {
    let length = 4 + value.len() + 1;
    out.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value.as_bytes());
    out.push(0);
    out.resize(out.len() + align4(length) - length, 0);
}

fn nest(out: &mut Vec<u8>, kind: u16) -> usize {
    let start = out.len();
    out.extend_from_slice(&0_u16.to_ne_bytes());
    out.extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
    start
}

fn end(out: &mut [u8], start: usize) {
    let length = u16::try_from(out.len() - start).unwrap_or(u16::MAX);
    if let Some(field) = out.get_mut(start..start + 2) {
        field.copy_from_slice(&length.to_ne_bytes());
    }
}

/// A netlink socket for element batches, with buffers reused from one batch to the next.
pub struct ElementSocket {
    socket: Socket,
    sequence: u32,
    request: Vec<u8>,
    response: Vec<u8>,
    name: String,
}

impl ElementSocket {
    pub fn open() -> io::Result<Self> {
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        Ok(Self {
            socket,
            sequence: 0,
            request: Vec::new(),
            response: Vec::with_capacity(1 << 16),
            name: String::new(),
        })
    }

    /// Send the batch of [`encode_timeouts`] and wait for the kernel's answer to each of its
    /// messages; the first error fails the whole batch, which the kernel then discards.
    pub fn set_timeouts(
        &mut self,
        table: &str,
        sets: &[TimeoutSet<'_>],
        addresses: &[(IpAddr, Duration)],
    ) -> io::Result<()> {
        let first = self.sequence.wrapping_add(1);
        let last = encode_timeouts(
            &mut self.request,
            &mut self.name,
            table,
            sets,
            addresses,
            first,
        );
        self.sequence = last.wrapping_add(1);
        if last == first {
            return Ok(());
        }
        self.socket.send(&self.request, 0)?;
        let mut failure = None;
        loop {
            self.response.clear();
            self.socket.recv(&mut self.response, 0)?;
            for message in messages(&self.response) {
                if message.message_type != NLMSG_ERROR || !in_batch(message.sequence, first, last) {
                    continue;
                }
                let code = ack_error(message.body);
                if code != 0 && failure.is_none() {
                    failure = Some(io::Error::from_raw_os_error(-code));
                }
                if message.sequence == last {
                    return failure.map_or(Ok(()), Err);
                }
            }
        }
    }
}

/// Whether `sequence` numbers one of the element messages after `first`, up to `last`.
fn in_batch(sequence: u32, first: u32, last: u32) -> bool {
    sequence.wrapping_sub(first) <= last.wrapping_sub(first) && sequence != first
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::nfnetlink::attributes;

    fn encoded(addresses: &[(IpAddr, Duration)]) -> (Vec<u8>, u32) {
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
        let last = encode_timeouts(&mut out, &mut name, "portcullis", &sets, addresses, 7);
        (out, last)
    }

    /// Keys, with their timeouts in milliseconds.
    type Keys = Vec<(Vec<u8>, Option<u64>)>;

    /// (type, sequence, set, keys) of each message.
    fn decode(out: &[u8]) -> Vec<(u16, u32, String, Keys)> {
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
                (message.message_type, message.sequence, set, elements)
            })
            .collect()
    }

    #[test]
    fn renews_by_adding_deleting_and_adding_again() {
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
        let gone = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let (out, last) = encoded(&[
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
                (NFNL_MSG_BATCH_BEGIN, 7, String::new(), vec![]),
                (
                    new,
                    8,
                    "pc_h4_1".into(),
                    vec![(four(v4), Some(2000)), (four(gone), Some(1000))]
                ),
                (
                    del,
                    9,
                    "pc_h4_1".into(),
                    vec![(four(v4), None), (four(gone), None)]
                ),
                (new, 10, "pc_h4_1".into(), vec![(four(v4), Some(2000))]),
                (new, 11, "pc_h6_1".into(), vec![(four(v6), Some(60000))]),
                (del, 12, "pc_h6_1".into(), vec![(four(v6), None)]),
                (new, 13, "pc_h6_1".into(), vec![(four(v6), Some(60000))]),
                (NFNL_MSG_BATCH_END, 14, String::new(), vec![]),
            ]
        );
        assert_eq!(last, 13);
    }

    #[test]
    fn writes_nothing_between_the_markers_without_addresses() {
        let (out, last) = encoded(&[]);
        assert_eq!(decode(&out).len(), 2);
        assert_eq!(last, 7);
    }

    #[test]
    fn matches_answers_of_the_batch_only() {
        assert!(in_batch(8, 7, 9));
        assert!(in_batch(9, 7, 9));
        assert!(!in_batch(7, 7, 9));
        assert!(!in_batch(10, 7, 9));
        assert!(in_batch(0, u32::MAX, 1));
    }
}
