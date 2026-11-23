use std::collections::HashMap;
use std::fmt::Write as _;

use super::*;
use crate::firewall::Plan;
use crate::firewall::nftables::{DenyAction, LogAllowed, Options, fresh_batch};
use crate::firewall::ruleset::{Chain, Part, SetFlags};
use crate::firewall::test_support::{self, MockResolver};
use crate::model::BridgePort;
use crate::nfnetlink::attributes;

/// The messages of an encoded batch: type, flags and attributes.
fn messages(batch: &[u8]) -> Vec<(u16, u16, Vec<u8>)> {
    parse(batch)
        .map(|message| {
            (
                message.kind,
                message.flags,
                message.body.get(4..).unwrap_or_default().to_vec(),
            )
        })
        .collect()
}

fn attribute(attributes_: &[u8], kind: u16) -> Option<&[u8]> {
    attributes(attributes_).find_map(|(found, value)| (found == kind).then_some(value))
}

/// 32-bit words in the host's byte order, as libnftnl prints register data.
fn words(data: &[u8]) -> String {
    data.chunks(4)
        .map(|chunk| {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            format!("0x{:08x}", u32::from_ne_bytes(word))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn be32(value: &[u8]) -> u32 {
    u32::from_be_bytes(value.try_into().expect("32 bits"))
}

fn data(value: &[u8]) -> String {
    words(attribute(value, NFTA_DATA_VALUE).expect("value"))
}

/// One expression as `nft --debug=netlink` prints it (from libnftnl).
#[allow(clippy::too_many_lines)]
fn describe_expr(expr: &[u8]) -> String {
    let name = attribute(expr, NFTA_EXPR_NAME).expect("name");
    let name = std::str::from_utf8(name.strip_suffix(&[0]).expect("string")).expect("utf-8");
    let data_ = attribute(expr, NFTA_EXPR_DATA).unwrap_or_default();
    let get = |kind| attribute(data_, kind);
    let u32_ = |kind| get(kind).map(be32);
    let text = |kind| {
        get(kind)
            .and_then(|value| value.strip_suffix(&[0]))
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .unwrap_or_default()
    };
    let op = |kind| if u32_(kind) == Some(0) { "eq" } else { "neq" };
    match name {
        "meta" => {
            let key = match u32_(2).expect("key") {
                0 => "len",
                1 => "protocol",
                3 => "mark",
                6 => "iifname",
                7 => "oifname",
                8 => "iiftype",
                15 => "nfproto",
                16 => "l4proto",
                17 => "bri_iifname",
                other => panic!("meta key {other}"),
            };
            match (u32_(1), u32_(3)) {
                (Some(dreg), _) => format!("meta load {key} => reg {dreg}"),
                (None, Some(sreg)) => format!("meta set {key} with reg {sreg}"),
                _ => panic!("meta without register"),
            }
        }
        "payload" => format!(
            "payload load {}b @ {} header + {} => reg {}",
            u32_(4).expect("len"),
            ["link", "network", "transport"][u32_(2).expect("base") as usize],
            u32_(3).expect("offset"),
            u32_(1).expect("dreg")
        ),
        "cmp" => format!(
            "cmp {} reg {} {}",
            op(2),
            u32_(1).expect("sreg"),
            data(get(3).expect("data"))
        ),
        "range" => format!(
            "range {} reg {} {} {}",
            op(2),
            u32_(1).expect("sreg"),
            data(get(3).expect("from")),
            data(get(4).expect("to"))
        ),
        "bitwise" => format!(
            "bitwise reg {} = ( reg {} & {} ) ^ {}",
            u32_(2).expect("dreg"),
            u32_(1).expect("sreg"),
            data(get(4).expect("mask")),
            data(get(5).expect("xor"))
        ),
        "ct" => {
            let key = match u32_(2).expect("key") {
                0 => "state",
                1 => "direction",
                2 => "status",
                12 => "proto_dst",
                19 => "src_ip",
                20 => "dst_ip",
                21 => "src_ip6",
                22 => "dst_ip6",
                other => panic!("ct key {other}"),
            };
            let direction = match get(3) {
                Some([0]) => " , dir original",
                Some([1]) => " , dir reply",
                _ => "",
            };
            format!("ct load {key} => reg {}{direction}", u32_(1).expect("dreg"))
        }
        "fib" => format!("fib daddr type => reg {}", u32_(1).expect("dreg")),
        "lookup" => {
            let mut out = format!("lookup reg {} set {}", u32_(2).expect("sreg"), text(1));
            if let Some(dreg) = u32_(3) {
                let _ = write!(out, " dreg {dreg}");
            }
            if let Some(flags) = u32_(5).filter(|flags| *flags != 0) {
                let _ = write!(out, " 0x{flags:x}");
            }
            out
        }
        "dynset" => {
            let op = ["add", "update", "delete"][u32_(3).expect("op") as usize];
            let mut out = format!(
                "dynset {op} reg_key {} set {} ",
                u32_(4).expect("sreg"),
                text(1)
            );
            if let Some(expr) = get(7) {
                let _ = write!(out, "expr [ {} ] ", describe_expr(expr));
            }
            out.trim_end().to_string()
        }
        "connlimit" => format!(
            "connlimit count {} flags {}",
            u32_(1).expect("count"),
            u32_(2).unwrap_or(0)
        ),
        "limit" => {
            let rate = get(1).map(|value| u64::from_be_bytes(value.try_into().expect("64 bits")));
            format!(
                "limit rate {}/second burst {} type packets flags 0x{:x}",
                rate.expect("rate"),
                u32_(3).expect("burst"),
                u32_(5).unwrap_or(0)
            )
        }
        "log" => format!(
            "log prefix {} group {} snaplen {} qthreshold 0",
            text(2),
            u16::from_be_bytes(get(1).expect("group").try_into().expect("16 bits")),
            u32_(3).expect("snaplen")
        ),
        "immediate" => {
            let dreg = u32_(1).expect("dreg");
            let value = get(2).expect("data");
            match attribute(value, NFTA_DATA_VERDICT) {
                Some(verdict) => {
                    let code = i32::from_be_bytes(
                        attribute(verdict, NFTA_VERDICT_CODE)
                            .expect("code")
                            .try_into()
                            .expect("32 bits"),
                    );
                    let chain = attribute(verdict, NFTA_VERDICT_CHAIN)
                        .and_then(|value| value.strip_suffix(&[0]))
                        .map(|value| String::from_utf8_lossy(value).into_owned());
                    let verdict = match (code, chain) {
                        (NF_ACCEPT, None) => "accept".to_string(),
                        (NF_DROP, None) => "drop".to_string(),
                        (NFT_JUMP, Some(chain)) => format!("jump -> {chain}"),
                        (NFT_GOTO, Some(chain)) => format!("goto -> {chain}"),
                        other => panic!("verdict {other:?}"),
                    };
                    format!("immediate reg {dreg} {verdict}")
                }
                None => format!("immediate reg {dreg} {}", data(value)),
            }
        }
        "reject" => format!(
            "reject type {} code {}",
            u32_(1).expect("type"),
            get(2).map_or(0, |code| code[0])
        ),
        "queue" => {
            let number = u16::from_be_bytes(get(1).expect("num").try_into().expect("16 bits"));
            let flags = get(3).map_or(0, |flags| {
                u16::from_be_bytes(flags.try_into().expect("16 bits"))
            });
            format!(
                "queue num {number}{}",
                if flags & 1 != 0 { " bypass" } else { "" }
            )
        }
        other => panic!("expression {other}"),
    }
}

/// The expressions of a rule, as `nft --debug=netlink` prints them.
pub fn describe(expressions: &[u8]) -> Vec<String> {
    attributes(expressions)
        .map(|(_, expr)| format!("[ {} ]", describe_expr(expr)))
        .collect()
}

/// Encoded `batch`, and the commands of its messages.
fn encode(batch: &Batch) -> (Vec<u8>, Vec<usize>) {
    let mut out = Vec::new();
    let origins = Encoder::new(&mut out).batch(batch);
    (out, origins)
}

/// What nft generates for rules, see `nft-bytecode.txt`.
fn nft_bytecode() -> HashMap<String, Vec<String>> {
    let mut rules = HashMap::new();
    let text = include_str!("nft-bytecode.txt");
    for block in text.split("\n\n") {
        let mut lines = block.lines().filter(|line| !line.starts_with('#'));
        if let Some(rule) = lines.next() {
            rules.insert(rule.to_string(), lines.map(String::from).collect());
        }
    }
    rules
}

/// The plans and options the bytecode in `nft-bytecode.txt` was generated for.
fn fixtures() -> Vec<(Plan, Options)> {
    let full = Options {
        deny: DenyAction::Reject,
        log_group: 7,
        log_allowed: LogAllowed::Always,
        dns_queue: Some(3),
        source_queue: Some(4),
        monitor_source_queue: Some(5),
        connection_limit: Some(1000),
        dns_query_queue: Some(6),
    };
    let states = [
        test_support::hostname_state(),
        test_support::icc_state(),
        test_support::ipv6_state(),
        test_support::services_state(),
    ];
    let mut fixtures = Vec::new();
    for mut state in states {
        state.set_ports(
            [(
                test_support::ip("172.18.0.2"),
                BridgePort {
                    name: "veth2".into(),
                    index: 2,
                },
            )]
            .into(),
            std::collections::HashSet::new(),
        );
        for (options, monitor) in [
            (full, false),
            (full, true),
            (
                Options {
                    deny: DenyAction::Drop,
                    ..Options::default()
                },
                false,
            ),
        ] {
            let plan = Plan::build(
                &state,
                &mut MockResolver::default(),
                &test_support::host_resolvers(),
                monitor,
            );
            fixtures.push((plan, options));
        }
    }
    fixtures
}

#[test]
fn encodes_rules_as_nft_does() {
    let expected = nft_bytecode();
    let mut checked = 0;
    for (plan, options) in fixtures() {
        let batch = fresh_batch(&plan, options);
        let (encoded, origins) = encode(&batch);
        let rules = messages(&encoded)
            .into_iter()
            .skip(1)
            .zip(&origins)
            .filter(|((kind, _, _), _)| *kind == (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE);
        for ((_, _, message), origin) in rules {
            let rule = batch.commands[*origin].to_string();
            let Some(expected) = expected.get(&rule) else {
                panic!("no bytecode of nft for {rule}");
            };
            let expressions = attribute(&message, NFTA_RULE_EXPRESSIONS).expect("expressions");
            assert_eq!(&describe(expressions), expected, "{rule}");
            checked += 1;
        }
    }
    assert!(checked > 1000, "{checked}");
}

/// A set as the kernel holds it, as nft created it: flags, key type and length, data type,
/// timeout, size and user data.
fn set_attributes(decl: &SetDecl) -> Vec<(u16, Vec<u8>)> {
    let batch = Batch::of(vec![Command::AddSet(decl.clone())]);
    let (encoded, _) = encode(&batch);
    let (_, _, message) = messages(&encoded).swap_remove(1);
    attributes(&message)
        .filter(|(kind, _)| !matches!(*kind, NFTA_SET_TABLE | NFTA_SET_NAME | NFTA_SET_ID))
        .map(|(kind, value)| (kind, value.to_vec()))
        .collect()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn creates_sets_as_nft_does() {
    // As the kernel lists the sets nft created for the same declarations.
    let ifname = SetDecl::set(Table::Bridge, "bridges", &[KeyType::Ifname]);
    assert_eq!(
        set_attributes(&ifname),
        [
            (NFTA_SET_KEY_TYPE, hex("00000029")),
            (NFTA_SET_KEY_LEN, hex("00000010")),
            (NFTA_SET_USERDATA, hex("00040100000003080004040000000100")),
        ]
    );
    let logged = SetDecl {
        flags: SetFlags {
            dynamic: true,
            timeout: true,
        },
        timeout: Some(std::time::Duration::from_secs(60)),
        size: Some(65_536),
        ..SetDecl::set(
            Table::Inet,
            "logged4",
            &[
                KeyType::Ipv4,
                KeyType::Ipv4,
                KeyType::InetProto,
                KeyType::InetService,
            ],
        )
    };
    assert_eq!(
        set_attributes(&logged),
        [
            (NFTA_SET_FLAGS, hex("00000030")),
            (NFTA_SET_KEY_TYPE, hex("001c730d")),
            (NFTA_SET_KEY_LEN, hex("00000010")),
            (NFTA_SET_TIMEOUT, hex("000000000000ea60")),
            (NFTA_SET_DESC, hex("0800010000010000")),
            (
                NFTA_SET_USERDATA,
                hex("000400000000031200040d000000010a00000004040000000100")
            ),
        ]
    );
    let map = SetDecl {
        map: true,
        ..SetDecl::set(
            Table::Bridge,
            "sources_by_port",
            &[KeyType::Ifname, KeyType::Ipv4, KeyType::Ether],
        )
    };
    assert_eq!(
        set_attributes(&map),
        [
            (NFTA_SET_FLAGS, hex("00000008")),
            (NFTA_SET_KEY_TYPE, hex("000291c9")),
            (NFTA_SET_KEY_LEN, hex("0000001c")),
            (NFTA_SET_DATA_TYPE, hex("ffffff00")),
            (
                NFTA_SET_USERDATA,
                hex(
                    "000400000000010400000000031200040d000000010a0000000404000000010004080004040000000100060400000000"
                )
            ),
        ]
    );
    let egress = SetDecl {
        map: true,
        ..SetDecl::set(Table::Inet, "egress4", &[KeyType::Ipv4])
    };
    assert_eq!(
        set_attributes(&egress).last(),
        Some(&(
            NFTA_SET_USERDATA,
            hex("0004020000000104000000000308000404000000010004080004040000000100060400000000")
        ))
    );
}

#[test]
fn encodes_elements_with_padded_keys() {
    let decl = SetDecl {
        map: true,
        ..SetDecl::set(
            Table::Bridge,
            "sources_by_port",
            &[KeyType::Ifname, KeyType::Ipv4, KeyType::Ether],
        )
    };
    let element = Element::of(&[
        Part::Ifname("veth2"),
        Part::Address(test_support::ip("172.18.0.2")),
        Part::Mac(test_support::mac_of("172.18.0.2").expect("mac")),
    ])
    .with_verdict(Verdict::Goto(Chain::Icc(3)));
    assert_eq!(
        element.key(),
        hex("76657468320000000000000000000000ac1200020242ac1200020000")
    );
    let batch = Batch::of(vec![Command::AddElements(decl, vec![element])]);
    let (encoded, _) = encode(&batch);
    let (kind, _, message) = messages(&encoded).swap_remove(1);
    assert_eq!(kind, (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM);
    let list = attribute(&message, NFTA_SET_ELEM_LIST_ELEMENTS).expect("elements");
    let element = attribute(list, NFTA_LIST_ELEM).expect("element");
    let verdict = attribute(element, NFTA_SET_ELEM_DATA)
        .and_then(|data| attribute(data, NFTA_DATA_VERDICT))
        .expect("verdict");
    assert_eq!(
        attribute(verdict, NFTA_VERDICT_CODE),
        Some(&NFT_GOTO.to_be_bytes()[..])
    );
    assert_eq!(attribute(verdict, NFTA_VERDICT_CHAIN), Some(&b"icc3\0"[..]));
}

#[test]
fn splits_many_elements_over_messages() {
    let decl = SetDecl::set(Table::Inet, "bridges", &[KeyType::Ifname]);
    let names: Vec<String> = (0..5000).map(|index| format!("br-{index}")).collect();
    let elements = names
        .iter()
        .map(|name| Element::of(&[Part::Ifname(name)]))
        .collect();
    let batch = Batch::of(vec![Command::AddElements(decl, elements)]);
    let (encoded, origins) = encode(&batch);
    let messages = messages(&encoded);
    assert!(messages.len() > 4, "{}", messages.len());
    assert!(origins.iter().all(|origin| *origin == 0));
    let mut count = 0;
    for (_, _, message) in &messages[1..messages.len() - 1] {
        let list = attribute(message, NFTA_SET_ELEM_LIST_ELEMENTS).expect("elements");
        assert!(list.len() < 65_536);
        count += attributes(list).count();
    }
    assert_eq!(count, 5000);
}

#[test]
fn frames_batches() {
    let (encoded, origins) = encode(&Batch::of(vec![
        Command::ResetTable(Table::Inet),
        Command::AddChain(Chain::Base(Table::Inet)),
    ]));
    let kinds: Vec<u16> = messages(&encoded).iter().map(|message| message.0).collect();
    let nft = |kind| (NFNL_SUBSYS_NFTABLES << 8) | kind;
    assert_eq!(
        kinds,
        [
            NFNL_MSG_BATCH_BEGIN,
            nft(NFT_MSG_NEWTABLE),
            nft(NFT_MSG_DELTABLE),
            nft(NFT_MSG_NEWCHAIN),
            NFNL_MSG_BATCH_END
        ]
    );
    assert_eq!(origins, [0, 0, 1]);
}

#[test]
fn reads_errors_and_their_reasons() {
    let mut body = (-22_i32).to_ne_bytes().to_vec();
    body.extend_from_slice(&[0; 16]);
    let mut out = Vec::new();
    Writer(&mut out).string(NLMSGERR_ATTR_MSG, "Could not process rule");
    body.extend_from_slice(&out);
    assert_eq!(
        error(NLM_F_ACK_TLVS, &body),
        (-22, Some("Could not process rule".to_string()))
    );
    assert_eq!(error(0, &0_i32.to_ne_bytes()), (0, None));
}
