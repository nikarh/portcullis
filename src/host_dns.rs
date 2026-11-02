//! The host's DNS servers, as Docker's embedded DNS server uses them.
//!
//! Docker's DNS server (127.0.0.11 inside containers) forwards names it can't answer to the
//! container's `--dns` servers or, without those, to the host's. It sends those queries from
//! the container's own address, so a container policy has to allow them.

use std::net::IpAddr;

use tracing::warn;

const RESOLV_CONF: &str = "/etc/resolv.conf";
/// Where systemd-resolved lists its real upstream servers. Docker reads this file instead
/// of `/etc/resolv.conf` when the latter only points at the local stub resolver.
const SYSTEMD_RESOLV_CONF: &str = "/run/systemd/resolve/resolv.conf";

/// The host's DNS servers that containers' DNS traffic is forwarded to. Loopback servers are
/// left out: Docker contacts those from the host's network namespace, not the container's.
#[must_use]
pub fn host_resolvers() -> Vec<IpAddr> {
    let contents = match std::fs::read_to_string(RESOLV_CONF) {
        Ok(contents) => contents,
        Err(error) => {
            warn!(path = RESOLV_CONF, %error, "failed to read host DNS configuration");
            return Vec::new();
        }
    };
    resolvers_from(&contents, || {
        std::fs::read_to_string(SYSTEMD_RESOLV_CONF).ok()
    })
}

/// Where Docker's daemon configuration lives.
const DOCKER_DAEMON_CONFIG: &str = "/etc/docker/daemon.json";

/// DNS servers set daemon-wide with `dns` in Docker's `daemon.json`. With these, Docker's
/// DNS server forwards every container's lookups from the container's own address, where
/// Portcullis can see them, even for containers without DNS servers of their own.
#[must_use]
pub fn docker_daemon_dns() -> Vec<IpAddr> {
    std::fs::read_to_string(DOCKER_DAEMON_CONFIG)
        .map(|contents| daemon_dns_from(&contents))
        .unwrap_or_default()
}

fn daemon_dns_from(contents: &str) -> Vec<IpAddr> {
    serde_json::from_str::<serde_json::Value>(contents)
        .ok()
        .and_then(|config| {
            config.get("dns")?.as_array().map(|servers| {
                servers
                    .iter()
                    .filter_map(|server| server.as_str()?.parse().ok())
                    .collect()
            })
        })
        .unwrap_or_default()
}

fn resolvers_from(
    resolv_conf: &str,
    systemd_resolv_conf: impl FnOnce() -> Option<String>,
) -> Vec<IpAddr> {
    let servers = nameservers(resolv_conf);
    let only_stub = !servers.is_empty()
        && servers
            .iter()
            .all(|server| *server == IpAddr::from([127, 0, 0, 53]));
    let mut servers = if only_stub {
        systemd_resolv_conf()
            .map(|contents| nameservers(&contents))
            .unwrap_or_default()
    } else {
        servers
    };
    servers.retain(|server| !server.is_loopback());
    servers.sort_unstable();
    servers.dedup();
    servers
}

/// `nameserver` entries of a resolv.conf. Entries that aren't plain addresses (such as IPv6
/// link-local addresses with a zone) are skipped.
fn nameservers(contents: &str) -> Vec<IpAddr> {
    contents
        .lines()
        .filter_map(|line| line.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next()?.parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("ip")
    }

    #[test]
    fn reads_nameservers() {
        let servers = resolvers_from(
            "# comment\nsearch lan\nnameserver 192.168.1.1\nnameserver  9.9.9.9 \noptions edns0\nnameserver fe80::1%eth0\n",
            || panic!("systemd file must not be read"),
        );
        assert_eq!(servers, vec![ip("9.9.9.9"), ip("192.168.1.1")]);
    }

    #[test]
    fn follows_the_systemd_resolved_stub() {
        let servers = resolvers_from("nameserver 127.0.0.53\noptions edns0\n", || {
            Some("nameserver 10.0.2.3\nnameserver 127.0.0.1\n".to_string())
        });
        assert_eq!(servers, vec![ip("10.0.2.3")]);
    }

    #[test]
    fn reads_daemon_dns() {
        assert_eq!(
            daemon_dns_from(r#"{"dns": ["10.0.0.1", "bogus"], "log-driver": "local"}"#),
            vec![ip("10.0.0.1")]
        );
        assert_eq!(daemon_dns_from("{}"), [] as [std::net::IpAddr; 0]);
        assert_eq!(daemon_dns_from("not json"), [] as [std::net::IpAddr; 0]);
    }

    #[test]
    fn leaves_out_loopback_servers() {
        let servers = resolvers_from("nameserver 127.0.0.1\nnameserver ::1\n", || None);
        assert_eq!(servers, [] as [std::net::IpAddr; 0]);
    }
}
