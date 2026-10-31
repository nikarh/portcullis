//! Shared fixtures for planner and backend tests.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use ipnet::IpNet;

use crate::dns::{DnsError, HostResolver};
use crate::model::{
    Container, ContainerPolicy, DnsTarget, EgressRule, EgressTarget, IccAllowRule, IccMode,
    MacAddress, Network, NetworkAttachment, PortSpec, Protocol, RuntimeState, RuntimeStateAction,
};

pub const HOST: &str = "api.example.com";
/// A hostname [`MockResolver`] fails to resolve.
pub const UNRESOLVABLE_HOST: &str = "unresolvable.example.com";

/// Resolves [`HOST`] to one IPv4 and one IPv6 address and counts lookups.
#[derive(Default)]
pub struct MockResolver {
    pub calls: usize,
}

/// How long test addresses stay allowed.
pub const HOLD: Duration = Duration::from_secs(3600);

impl HostResolver for MockResolver {
    fn addresses(
        &mut self,
        _container: &str,
        host: &str,
    ) -> Result<Vec<(IpAddr, Duration)>, DnsError> {
        self.calls += 1;
        if host == HOST {
            return Ok(vec![(ip("1.1.1.1"), HOLD), (ip("2606:4700::1111"), HOLD)]);
        }
        Err(DnsError::LookupFailed {
            host: host.to_string(),
            message: "host not found".to_string(),
        })
    }
}

/// The host's DNS servers in tests.
pub fn host_resolvers() -> [IpAddr; 1] {
    [ip("9.9.9.9")]
}

pub fn ip(value: &str) -> IpAddr {
    value.parse().expect("ip fixture should parse")
}

pub fn net(value: &str) -> IpNet {
    value.parse().expect("subnet fixture should parse")
}

pub const fn tcp(port: u16) -> PortSpec {
    PortSpec {
        protocol: Protocol::Tcp,
        port,
    }
}

pub fn add_network(state: &mut RuntimeState, id: &str, subnet: &str, gateway: &str) {
    state.apply_action(RuntimeStateAction::UpsertNetwork {
        network: Network {
            id: id.into(),
            name: id.to_string(),
            subnet: net(subnet),
            gateway: Some(ip(gateway)),
            bridge: format!("br-{id}"),
            monitor: false,
        },
    });
}

/// The MAC Docker derives from an IPv4 address: 02:42 followed by the address.
pub fn mac_of(address: &str) -> Option<MacAddress> {
    match ip(address) {
        IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            Some(MacAddress::new([0x02, 0x42, a, b, c, d]))
        }
        IpAddr::V6(_) => None,
    }
}

/// Add a container with `(network_id, ip, aliases)` attachments.
pub fn add_container(
    state: &mut RuntimeState,
    id: &str,
    name: &str,
    attachments: &[(&str, &str, &[&str])],
    policy: ContainerPolicy,
) {
    state.apply_action(RuntimeStateAction::CreateContainer {
        container: Box::new(Container {
            id: id.to_string().into(),
            name: name.to_string().into(),
            attachments: attachments
                .iter()
                .map(|(network_id, address, aliases)| NetworkAttachment {
                    network_id: (*network_id).into(),
                    ip_address: ip(address),
                    mac_address: mac_of(address),
                    aliases: aliases.iter().map(ToString::to_string).collect(),
                })
                .collect(),
            runtime_dns_servers: HashSet::new(),
            policy,
            sandbox: None,
        }),
    });
}

pub fn host_egress() -> EgressRule {
    EgressRule {
        target: EgressTarget::Hostname(HOST.to_string()),
        ports: vec![tcp(443)],
    }
}

pub fn policy(icc_mode: IccMode, egress: Vec<EgressRule>) -> ContainerPolicy {
    ContainerPolicy {
        icc_mode,
        egress,
        icc_allow: Vec::new(),
        dns_targets: vec![DnsTarget::Docker],
    }
}

/// `web` (172.18.0.2) on `net0` with a hostname egress rule and a CIDR egress rule.
pub fn hostname_state() -> RuntimeState {
    let mut state = RuntimeState::default();
    add_network(&mut state, "net0", "172.18.0.0/16", "172.18.0.1");
    add_container(
        &mut state,
        "abc",
        "web",
        &[("net0", "172.18.0.2", &["web"])],
        policy(
            IccMode::Deny,
            vec![
                host_egress(),
                EgressRule {
                    target: EgressTarget::IpCidr(net("8.8.8.0/24")),
                    ports: vec![tcp(853)],
                },
            ],
        ),
    );
    state
}

/// Two containers using the same hostname rule.
pub fn shared_hostname_state() -> RuntimeState {
    let mut state = hostname_state();
    add_container(
        &mut state,
        "def",
        "worker",
        &[("net0", "172.18.0.3", &[])],
        policy(IccMode::Deny, vec![host_egress()]),
    );
    state
}

/// - `web` (172.18.0.2, net0): allow-listed, may reach `db` on tcp/5432.
/// - `peer` (172.18.0.10 on net0, 172.19.0.10 on net1): alias `db` on both networks.
/// - `other` (172.18.0.3, net0): ICC allow.
pub fn icc_state() -> RuntimeState {
    let mut state = RuntimeState::default();
    add_network(&mut state, "net0", "172.18.0.0/16", "172.18.0.1");
    add_network(&mut state, "net1", "172.19.0.0/16", "172.19.0.1");

    let mut web = policy(IccMode::AllowListed, Vec::new());
    web.icc_allow = vec![IccAllowRule {
        target_container: "db".to_string().into(),
        ports: vec![tcp(5432)],
    }];
    add_container(
        &mut state,
        "abc",
        "web",
        &[("net0", "172.18.0.2", &["web"])],
        web,
    );
    add_container(
        &mut state,
        "peer",
        "project-db-1",
        &[
            ("net0", "172.18.0.10", &["db"]),
            ("net1", "172.19.0.10", &["db"]),
        ],
        ContainerPolicy::default(),
    );
    add_container(
        &mut state,
        "other",
        "other",
        &[("net0", "172.18.0.3", &[])],
        ContainerPolicy::default(),
    );
    state
}

/// IPv6-only network with a hostname rule and an IPv6 CIDR rule.
pub fn ipv6_state() -> RuntimeState {
    let mut state = RuntimeState::default();
    add_network(&mut state, "net6", "fd00::/64", "fd00::1");
    add_container(
        &mut state,
        "v6",
        "v6",
        &[("net6", "fd00::2", &[])],
        policy(
            IccMode::Deny,
            vec![
                host_egress(),
                EgressRule {
                    target: EgressTarget::IpCidr(net("2001:db8::/32")),
                    ports: vec![tcp(443)],
                },
            ],
        ),
    );
    state
}

/// `web` with one hostname rule that can't be resolved and one CIDR rule.
pub fn unresolvable_state() -> RuntimeState {
    let mut state = RuntimeState::default();
    add_network(&mut state, "net0", "172.18.0.0/16", "172.18.0.1");
    add_container(
        &mut state,
        "abc",
        "web",
        &[("net0", "172.18.0.2", &[])],
        policy(
            IccMode::Deny,
            vec![
                EgressRule {
                    target: EgressTarget::Hostname(UNRESOLVABLE_HOST.to_string()),
                    ports: vec![tcp(443)],
                },
                EgressRule {
                    target: EgressTarget::IpCidr(net("8.8.8.0/24")),
                    ports: vec![tcp(853)],
                },
            ],
        ),
    );
    state
}
