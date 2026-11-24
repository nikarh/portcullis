//! The server name of a QUIC connection, from its client's first packets.
//!
//! A QUIC client starts with Initial packets, whose `CRYPTO` frames carry its TLS
//! `ClientHello`. They are encrypted, but with keys anyone can derive (RFC 9001, section 5.2):
//! from the Destination Connection ID the client chose and a salt that depends on the QUIC
//! version. So, as Suricata and Wireshark do, Portcullis removes the header protection,
//! decrypts the packet (AES-128-GCM), and reads the `ClientHello` from the `CRYPTO` frames,
//! which may span several Initial packets, in any order.

use std::collections::BTreeMap;

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::names::{self, MAX_CLIENT_HELLO};

const VERSION_1: u32 = 0x0000_0001;
const VERSION_2: u32 = 0x6b33_43cf;
const SALT_1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
/// Longest connection ID QUIC versions 1 and 2 allow.
const MAX_CID: usize = 20;
const TAG: usize = 16;

/// The keys of a client's Initial packets.
#[derive(Clone, PartialEq, Eq)]
pub struct Keys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys")
    }
}

/// HKDF-Expand-Label of TLS 1.3, with an empty context.
fn expand_label(secret: &Hkdf<Sha256>, label: &[u8], out: &mut [u8]) -> Option<()> {
    let length = u16::try_from(out.len()).ok()?;
    let label_length = u8::try_from(6 + label.len()).ok()?;
    let mut info = Vec::with_capacity(10 + label.len());
    info.extend_from_slice(&length.to_be_bytes());
    info.push(label_length);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    secret.expand(&info, out).ok()
}

impl Keys {
    /// The client's Initial keys for a connection ID chosen by the client.
    pub fn client(version: u32, connection_id: &[u8]) -> Option<Self> {
        let (salt, prefix): (&[u8], &[u8]) = match version {
            VERSION_1 => (&SALT_1, b"quic "),
            VERSION_2 => (&SALT_2, b"quicv2 "),
            _ => return None,
        };
        let (_, initial) = Hkdf::<Sha256>::extract(Some(salt), connection_id);
        // Filled from the secret: nothing of these defaults is left.
        let mut client = <[u8; 32]>::default();
        expand_label(&initial, b"client in", &mut client)?;
        let client = Hkdf::<Sha256>::from_prk(&client).ok()?;
        let label = |name: &[u8]| [prefix, name].concat();
        let mut keys = Self {
            key: <[u8; 16]>::default(),
            iv: <[u8; 12]>::default(),
            hp: <[u8; 16]>::default(),
        };
        expand_label(&client, &label(b"key"), &mut keys.key)?;
        expand_label(&client, &label(b"iv"), &mut keys.iv)?;
        expand_label(&client, &label(b"hp"), &mut keys.hp)?;
        Some(keys)
    }
}

/// A variable-length integer (RFC 9000, section 16) at the start of `data`, and its length.
fn varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let length = 1_usize << (first >> 6);
    let bytes = data.get(..length)?;
    let value = bytes
        .iter()
        .skip(1)
        .fold(u64::from(first & 0x3f), |value, byte| {
            (value << 8) | u64::from(*byte)
        });
    Some((value, length))
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let taken = self.data.get(self.at..self.at.checked_add(length)?)?;
        self.at += length;
        Some(taken)
    }

    fn varint(&mut self) -> Option<u64> {
        let (value, length) = varint(self.data.get(self.at..)?)?;
        self.at += length;
        Some(value)
    }

    fn length(&mut self) -> Option<usize> {
        usize::try_from(self.varint()?).ok()
    }

    const fn is_empty(&self) -> bool {
        self.at >= self.data.len()
    }
}

/// What a UDP datagram is, as far as the server names of QUIC go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datagram {
    /// Not a QUIC Initial packet of a known version.
    NotQuic,
    /// An Initial packet (or several) whose payload doesn't decrypt or parse.
    Unreadable(&'static str),
    /// The `CRYPTO` data of the client's Initial packets in it, by offset, for the
    /// connection ID `connection_id` (the one the keys come from).
    Crypto {
        connection_id: Vec<u8>,
        version: u32,
        frames: Vec<(u64, Vec<u8>)>,
    },
}

/// Decrypt the Initial packets at the start of a datagram.
#[must_use]
pub fn datagram(data: &[u8]) -> Datagram {
    let mut frames = Vec::new();
    let mut first: Option<(Vec<u8>, u32)> = None;
    let mut rest = data;
    while let Some(&byte) = rest.first() {
        // Long header, with the fixed bit.
        if byte & 0xc0 != 0xc0 {
            break;
        }
        let Some(version) = rest
            .get(1..5)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
        else {
            break;
        };
        let kind = (byte >> 4) & 0x03;
        let initial = match version {
            VERSION_1 => kind == 0,
            VERSION_2 => kind == 1,
            _ => break,
        };
        if !initial {
            // 0-RTT or Handshake packets after it, which can't be read.
            break;
        }
        let packet = match packet(rest, version) {
            Ok(packet) => packet,
            Err(reason) if first.is_none() => return Datagram::Unreadable(reason),
            Err(_) => break,
        };
        if let Some((connection_id, _)) = &first
            && *connection_id != packet.connection_id
        {
            break;
        }
        first.get_or_insert((packet.connection_id, version));
        frames.extend(packet.crypto);
        rest = rest.get(packet.length..).unwrap_or_default();
    }
    match first {
        Some((connection_id, version)) => Datagram::Crypto {
            connection_id,
            version,
            frames,
        },
        None => Datagram::NotQuic,
    }
}

struct Packet {
    connection_id: Vec<u8>,
    crypto: Vec<(u64, Vec<u8>)>,
    /// Bytes of the datagram it takes.
    length: usize,
}

/// The Initial packet at the start of `data`.
fn packet(data: &[u8], version: u32) -> Result<Packet, &'static str> {
    const SHORT: &str = "a QUIC Initial packet cut short";
    let mut reader = Reader { data, at: 5 };
    let dcid_length = usize::from(reader.byte().ok_or(SHORT)?);
    if dcid_length > MAX_CID {
        return Err("a QUIC connection ID longer than 20 bytes");
    }
    let connection_id = reader.take(dcid_length).ok_or(SHORT)?.to_vec();
    let scid_length = usize::from(reader.byte().ok_or(SHORT)?);
    if scid_length > MAX_CID {
        return Err("a QUIC connection ID longer than 20 bytes");
    }
    reader.take(scid_length).ok_or(SHORT)?;
    let token = reader.length().ok_or(SHORT)?;
    reader.take(token).ok_or(SHORT)?;
    let length = reader.length().ok_or(SHORT)?;
    let number_offset = reader.at;
    let end = number_offset.checked_add(length).ok_or(SHORT)?;
    if data.len() < end || length < 4 + TAG {
        return Err(SHORT);
    }
    let keys = Keys::client(version, &connection_id).ok_or("unknown QUIC version")?;

    // Header protection: a mask from a sample of the ciphertext.
    let sample = data
        .get(number_offset + 4..number_offset + 20)
        .ok_or(SHORT)?;
    let cipher = aes::Aes128::new_from_slice(&keys.hp).map_err(|_| SHORT)?;
    let mut mask = aes::Block::try_from(sample).map_err(|_| SHORT)?;
    cipher.encrypt_block(&mut mask);
    let mut header = data.get(..number_offset + 4).ok_or(SHORT)?.to_vec();
    let first = header.first_mut().ok_or(SHORT)?;
    *first ^= mask.first().copied().unwrap_or_default() & 0x0f;
    let number_length = usize::from(*first & 0x03) + 1;
    header.truncate(number_offset + number_length);
    let mut number = 0_u64;
    for (index, byte) in header.iter_mut().skip(number_offset).enumerate() {
        *byte ^= mask.get(1 + index).copied().unwrap_or_default();
        number = (number << 8) | u64::from(*byte);
    }

    let mut nonce = keys.iv;
    for (slot, byte) in nonce.iter_mut().skip(4).zip(number.to_be_bytes()) {
        *slot ^= byte;
    }
    let ciphertext = data.get(number_offset + number_length..end).ok_or(SHORT)?;
    let aead = Aes128Gcm::new_from_slice(&keys.key).map_err(|_| SHORT)?;
    let nonce = Nonce::<U12>::try_from(&nonce[..]).map_err(|_| SHORT)?;
    let plaintext = aead
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &header,
            },
        )
        .map_err(|_| "a QUIC Initial packet that doesn't decrypt")?;
    Ok(Packet {
        connection_id,
        crypto: crypto_frames(&plaintext)?,
        length: end,
    })
}

/// The `CRYPTO` frames of an Initial packet's payload, by offset.
fn crypto_frames(payload: &[u8]) -> Result<Vec<(u64, Vec<u8>)>, &'static str> {
    const MALFORMED: &str = "a malformed frame in a QUIC Initial packet";
    let mut reader = Reader {
        data: payload,
        at: 0,
    };
    let mut frames = Vec::new();
    while !reader.is_empty() {
        match reader.varint().ok_or(MALFORMED)? {
            // PADDING, PING.
            0x00 | 0x01 => {}
            // ACK, with ECN counts for 0x03.
            kind @ (0x02 | 0x03) => {
                for _ in 0..3 {
                    reader.varint().ok_or(MALFORMED)?;
                }
                let ranges = reader.varint().ok_or(MALFORMED)?;
                if ranges > 1024 {
                    return Err(MALFORMED);
                }
                for _ in 0..ranges * 2 {
                    reader.varint().ok_or(MALFORMED)?;
                }
                if kind == 0x03 {
                    for _ in 0..3 {
                        reader.varint().ok_or(MALFORMED)?;
                    }
                }
            }
            // CRYPTO.
            0x06 => {
                let offset = reader.varint().ok_or(MALFORMED)?;
                let length = reader.length().ok_or(MALFORMED)?;
                let data = reader.take(length).ok_or(MALFORMED)?;
                frames.push((offset, data.to_vec()));
            }
            // CONNECTION_CLOSE.
            0x1c => {
                reader.varint().ok_or(MALFORMED)?;
                reader.varint().ok_or(MALFORMED)?;
                let length = reader.length().ok_or(MALFORMED)?;
                reader.take(length).ok_or(MALFORMED)?;
            }
            _ => return Err("a frame QUIC Initial packets don't carry"),
        }
    }
    Ok(frames)
}

/// The `CRYPTO` data of a connection's Initial packets so far, put together by offset.
#[derive(Debug, Default, Clone)]
pub struct Crypto {
    frames: BTreeMap<u64, Vec<u8>>,
    bytes: usize,
}

/// What the `CRYPTO` data says so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hello {
    NeedMore,
    /// A whole `ClientHello`: its server name, and whether it has an ECH extension.
    Complete {
        name: Option<String>,
        ech: bool,
    },
    Refused(&'static str),
}

impl Crypto {
    /// Take more frames in; data that overlaps what came before must be the same.
    pub fn add(&mut self, frames: Vec<(u64, Vec<u8>)>) -> Result<(), &'static str> {
        for (offset, data) in frames {
            if data.is_empty() {
                continue;
            }
            let end = offset
                .checked_add(data.len() as u64)
                .ok_or("a CRYPTO frame past the end of its stream")?;
            if end > (MAX_CLIENT_HELLO as u64) * 2 {
                return Err("more CRYPTO data than a ClientHello");
            }
            for (start, known) in self.frames.range(..end) {
                let known_end = start + known.len() as u64;
                let from = offset.max(*start);
                let to = end.min(known_end);
                if from >= to {
                    continue;
                }
                let ours = data.get(usize::try_from(from - offset).unwrap_or(usize::MAX)..);
                let theirs = known.get(usize::try_from(from - start).unwrap_or(usize::MAX)..);
                let length = usize::try_from(to - from).unwrap_or(usize::MAX);
                if ours.and_then(|ours| ours.get(..length))
                    != theirs.and_then(|theirs| theirs.get(..length))
                {
                    return Err("CRYPTO frames that overlap and differ");
                }
            }
            self.bytes += data.len();
            if self.bytes > MAX_CLIENT_HELLO * 4 {
                return Err("more CRYPTO data than a ClientHello");
            }
            self.frames.entry(offset).or_insert(data);
        }
        Ok(())
    }

    /// The `ClientHello`, if the data from the start holds it whole.
    #[must_use]
    pub fn hello(&self) -> Hello {
        let mut stream = Vec::new();
        for (start, data) in &self.frames {
            let have = stream.len() as u64;
            if *start > have {
                break;
            }
            let skip = usize::try_from(have - start).unwrap_or(usize::MAX);
            if let Some(rest) = data.get(skip..) {
                stream.extend_from_slice(rest);
            }
        }
        match names::handshake_client_hello(&stream) {
            Ok(Some((name, ech))) => Hello::Complete { name, ech },
            Ok(None) => Hello::NeedMore,
            Err(reason) => Hello::Refused(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn derives_the_initial_keys_of_rfc_9001_and_9369() {
        let connection_id = hex("8394c8f03e515708");
        let keys = Keys::client(VERSION_1, &connection_id).expect("keys");
        assert_eq!(keys.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(keys.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(keys.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
        let keys = Keys::client(VERSION_2, &connection_id).expect("keys");
        assert_eq!(keys.key.to_vec(), hex("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(keys.iv.to_vec(), hex("91f73e2351d8fa91660e909f"));
        assert_eq!(keys.hp.to_vec(), hex("45b95e15235d6f45a6b19cbcb0294ba9"));
        assert_eq!(Keys::client(2, &connection_id), None);
    }

    const V1: [&[u8]; 2] = [
        include_bytes!("testdata/quic-v1-api.example.com-0.bin"),
        include_bytes!("testdata/quic-v1-api.example.com-1.bin"),
    ];
    const V2: [&[u8]; 2] = [
        include_bytes!("testdata/quic-v2-api.example.com-0.bin"),
        include_bytes!("testdata/quic-v2-api.example.com-1.bin"),
    ];
    const SPLIT: [&[u8]; 3] = [
        include_bytes!("testdata/quic-v1-split.example.org-0.bin"),
        include_bytes!("testdata/quic-v1-split.example.org-1.bin"),
        include_bytes!("testdata/quic-v1-split.example.org-2.bin"),
    ];

    /// The `ClientHello` of `datagrams`, read in the order given.
    fn hello(datagrams: &[&[u8]]) -> Vec<Hello> {
        let mut crypto = Crypto::default();
        datagrams
            .iter()
            .map(|data| {
                match datagram(data) {
                    Datagram::Crypto { frames, .. } => crypto.add(frames).expect("frames"),
                    other => panic!("not an Initial: {other:?}"),
                }
                crypto.hello()
            })
            .collect()
    }

    fn named(name: &str) -> Hello {
        Hello::Complete {
            name: Some(name.to_string()),
            ech: false,
        }
    }

    #[test]
    fn reads_the_server_name_of_real_initial_packets() {
        // Captured from aioquic, for QUIC version 1 and 2.
        for datagrams in [V1, V2] {
            assert_eq!(hello(&datagrams).last(), Some(&named("api.example.com")));
        }
    }

    #[test]
    fn puts_a_client_hello_together_from_several_initial_packets() {
        let read = hello(&SPLIT);
        assert_eq!(read[0], Hello::NeedMore);
        assert_eq!(read.last(), Some(&named("split.example.org")));
        // In any order.
        let reversed: Vec<&[u8]> = SPLIT.iter().rev().copied().collect();
        assert_eq!(hello(&reversed).last(), Some(&named("split.example.org")));
    }

    #[test]
    fn tells_quic_from_what_isnt() {
        assert_eq!(datagram(b"\x17ntp"), Datagram::NotQuic);
        assert_eq!(datagram(&[]), Datagram::NotQuic);
        // A version it doesn't know.
        let mut unknown = V1[0].to_vec();
        unknown[1..5].copy_from_slice(&[0, 0, 0, 2]);
        assert_eq!(datagram(&unknown), Datagram::NotQuic);
        // Changed on the way: it doesn't decrypt.
        let mut changed = V1[0].to_vec();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert_eq!(
            datagram(&changed),
            Datagram::Unreadable("a QUIC Initial packet that doesn't decrypt")
        );
        assert!(matches!(datagram(&V1[0][..40]), Datagram::Unreadable(_)));
    }

    #[test]
    fn refuses_crypto_data_that_overlaps_and_differs() {
        let mut crypto = Crypto::default();
        crypto.add(vec![(0, vec![2, 2, 3, 4])]).expect("first");
        crypto
            .add(vec![(2, vec![3, 4, 5])])
            .expect("the same again, and more");
        assert!(crypto.add(vec![(1, vec![9])]).is_err());
        assert_eq!(
            crypto.hello(),
            Hello::Refused("a TLS handshake that doesn't start with a ClientHello")
        );
    }

    #[test]
    fn reads_variable_length_integers() {
        assert_eq!(varint(&hex("25")), Some((37, 1)));
        assert_eq!(varint(&hex("7bbd")), Some((15_293, 2)));
        assert_eq!(varint(&hex("9d7f3e7d")), Some((494_878_333, 4)));
        assert_eq!(
            varint(&hex("c2197c5eff14e88c")),
            Some((151_288_809_941_952_652, 8))
        );
        assert_eq!(varint(&hex("7b")), None);
    }
}
