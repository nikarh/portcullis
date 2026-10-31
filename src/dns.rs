//! Addresses of the hostnames used in `host:` rules.
//!
//! Addresses come from two places:
//! - DNS answers containers receive, which Portcullis inspects (see `dns_inspect`), with the
//!   answer's TTL; they only count for the container that received the answer;
//! - Portcullis's own lookup through the host's resolver when a hostname has no known
//!   addresses, so that containers that resolved it before Portcullis started aren't cut
//!   off.
//!
//! Every address stays allowed for at least the hold time after it was last seen, since
//! applications often keep using an address for longer than its TTL.

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::trace;

/// How long a failed lookup is remembered before it is retried.
const RETRY_AFTER: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("dns lookup failed for host {host}: {message}")]
    LookupFailed { host: String, message: String },
}

/// Resolves hostnames through some resolver.
pub trait UpstreamResolver {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError>;
}

/// The addresses currently allowed for a hostname in a container's rules, with how long
/// each stays allowed.
pub trait HostResolver {
    fn addresses(
        &mut self,
        container: &str,
        host: &str,
    ) -> Result<Vec<(IpAddr, Duration)>, DnsError>;
}

/// The host's resolver (`getaddrinfo`).
#[derive(Debug, Clone, Copy)]
pub struct SystemUpstreamResolver;

impl UpstreamResolver for SystemUpstreamResolver {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        trace!(%host, "performing system DNS lookup");
        let mut ips: Vec<_> = (host, 0)
            .to_socket_addrs()
            .map_err(|error| DnsError::LookupFailed {
                host: host.to_string(),
                message: error.to_string(),
            })?
            .map(|address| address.ip())
            .collect();
        ips.sort_unstable();
        ips.dedup();
        trace!(%host, result_count = ips.len(), ?ips, "system DNS lookup result");
        Ok(ips)
    }
}

#[derive(Debug, Default)]
struct HostEntry {
    /// Address and when it stops being allowed.
    addresses: HashMap<IpAddr, Instant>,
    /// After a failed lookup: don't look the hostname up again before this.
    retry_at: Option<Instant>,
}

/// Known addresses of hostnames, normalized to lower case without a trailing dot.
///
/// Addresses from DNS answers belong to the container that received the answer: a
/// container that may use a resolver of its choice could otherwise make another
/// container's `host:` rules allow whatever that resolver claims. Addresses Portcullis
/// resolves itself, through the host's resolver, apply to every container.
#[derive(Debug)]
pub struct HostAddresses<R> {
    resolver: R,
    hold: Duration,
    /// Portcullis's own lookups, by hostname.
    resolved: HashMap<String, HostEntry>,
    /// Addresses from DNS answers, by container name and hostname.
    observed: HashMap<(String, String), HashMap<IpAddr, Instant>>,
}

impl<R> HostAddresses<R>
where
    R: UpstreamResolver,
{
    pub fn new(resolver: R, hold: Duration) -> Self {
        Self {
            resolver,
            hold,
            resolved: HashMap::new(),
            observed: HashMap::new(),
        }
    }

    /// Record an address a DNS answer to `container` gave for `host`. Returns how long it
    /// is allowed.
    pub fn observe(
        &mut self,
        container: &str,
        host: &str,
        address: IpAddr,
        ttl: Duration,
        now: Instant,
    ) -> Duration {
        let allowed_for = ttl.max(self.hold);
        let expires = now + allowed_for;
        let current = self
            .observed
            .entry((container.to_string(), normalize(host)))
            .or_default()
            .entry(address)
            .or_insert(expires);
        *current = (*current).max(expires);
        allowed_for
    }

    /// Whether `address` is currently allowed for `host` in `container`'s rules.
    #[must_use]
    pub fn allows(&self, container: &str, host: &str, address: IpAddr, now: Instant) -> bool {
        let host = normalize(host);
        let live = |expires: Option<&Instant>| expires.is_some_and(|expires| *expires > now);
        live(
            self.observed
                .get(&(container.to_string(), host.clone()))
                .and_then(|addresses| addresses.get(&address)),
        ) || live(
            self.resolved
                .get(&host)
                .and_then(|entry| entry.addresses.get(&address)),
        )
    }

    /// Forget expired addresses, and containers without any left.
    pub fn prune(&mut self, now: Instant) {
        self.observed.retain(|_, addresses| {
            addresses.retain(|_, expires| *expires > now);
            !addresses.is_empty()
        });
    }

    fn addresses_at(
        &mut self,
        container: &str,
        host: &str,
        now: Instant,
    ) -> Result<Vec<(IpAddr, Duration)>, DnsError> {
        let host = normalize(host);
        let mut addresses: HashMap<IpAddr, Instant> = self
            .observed
            .get_mut(&(container.to_string(), host.clone()))
            .map(|observed| {
                observed.retain(|_, expires| *expires > now);
                observed.clone()
            })
            .unwrap_or_default();

        let entry = self.resolved.entry(host.clone()).or_default();
        entry.addresses.retain(|_, expires| *expires > now);
        // Look the hostname up when nothing is known for this container: it may have
        // resolved the name before Portcullis started, or where Portcullis can't see it.
        if addresses.is_empty()
            && entry.addresses.is_empty()
            && entry.retry_at.is_none_or(|retry_at| retry_at <= now)
        {
            match self.resolver.resolve_host(&host) {
                Ok(resolved) => {
                    entry.retry_at = None;
                    for address in resolved {
                        entry.addresses.insert(address, now + self.hold);
                    }
                }
                Err(error) => {
                    entry.retry_at = Some(now + RETRY_AFTER);
                    return Err(error);
                }
            }
        }
        for (address, expires) in &entry.addresses {
            let current = addresses.entry(*address).or_insert(*expires);
            *current = (*current).max(*expires);
        }

        let mut addresses: Vec<_> = addresses
            .into_iter()
            .map(|(address, expires)| (address, expires.saturating_duration_since(now)))
            .collect();
        addresses.sort_unstable();
        Ok(addresses)
    }
}

impl<R> HostResolver for HostAddresses<R>
where
    R: UpstreamResolver,
{
    fn addresses(
        &mut self,
        container: &str,
        host: &str,
    ) -> Result<Vec<(IpAddr, Duration)>, DnsError> {
        self.addresses_at(container, host, Instant::now())
    }
}

/// Lower case without the trailing dot of fully qualified names.
#[must_use]
pub fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct MockResolver {
        calls: Arc<Mutex<usize>>,
        answer: Vec<IpAddr>,
    }

    impl UpstreamResolver for MockResolver {
        fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
            *self.calls.lock().expect("lock") += 1;
            if self.answer.is_empty() {
                return Err(DnsError::LookupFailed {
                    host: host.to_string(),
                    message: "not found".to_string(),
                });
            }
            Ok(self.answer.clone())
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("ip")
    }

    const HOLD: Duration = Duration::from_secs(3600);

    #[test]
    fn looks_up_unknown_hostnames_once() {
        let resolver = MockResolver {
            answer: vec![ip("1.1.1.1")],
            ..MockResolver::default()
        };
        let mut hosts = HostAddresses::new(resolver.clone(), HOLD);
        let now = Instant::now();
        assert_eq!(
            hosts
                .addresses_at("web", "API.example.com.", now)
                .expect("addresses"),
            vec![(ip("1.1.1.1"), HOLD)]
        );
        hosts
            .addresses_at("db", "api.example.com", now)
            .expect("addresses");
        assert_eq!(*resolver.calls.lock().expect("lock"), 1);
    }

    #[test]
    fn retries_failed_lookups_after_a_while() {
        let resolver = MockResolver::default();
        let mut hosts = HostAddresses::new(resolver.clone(), HOLD);
        let now = Instant::now();
        assert!(hosts.addresses_at("web", "missing.test", now).is_err());
        assert!(
            hosts
                .addresses_at("web", "missing.test", now)
                .expect("cached")
                .is_empty()
        );
        assert_eq!(*resolver.calls.lock().expect("lock"), 1);
        assert!(
            hosts
                .addresses_at("web", "missing.test", now + RETRY_AFTER)
                .is_err()
        );
        assert_eq!(*resolver.calls.lock().expect("lock"), 2);
    }

    #[test]
    fn observed_addresses_are_held_at_least_the_hold_time() {
        let mut hosts = HostAddresses::new(MockResolver::default(), HOLD);
        let now = Instant::now();
        assert_eq!(
            hosts.observe(
                "web",
                "api.test",
                ip("1.1.1.1"),
                Duration::from_secs(60),
                now
            ),
            HOLD
        );
        let long = Duration::from_secs(7200);
        assert_eq!(
            hosts.observe("web", "api.test", ip("2.2.2.2"), long, now),
            long
        );
        assert_eq!(
            hosts
                .addresses_at("web", "api.test", now)
                .expect("addresses"),
            vec![(ip("1.1.1.1"), HOLD), (ip("2.2.2.2"), long)]
        );
        // Expired addresses are gone; the hostname is then looked up again.
        assert!(hosts.addresses_at("web", "api.test", now + long).is_err());
    }

    #[test]
    fn tells_which_addresses_a_host_allows() {
        let mut hosts = HostAddresses::new(MockResolver::default(), HOLD);
        let now = Instant::now();
        hosts.observe("web", "a.test", ip("1.1.1.1"), HOLD, now);
        hosts.observe("web", "b.test", ip("2.2.2.2"), HOLD, now);
        assert!(hosts.allows("web", "A.test.", ip("1.1.1.1"), now));
        assert!(!hosts.allows("web", "b.test", ip("1.1.1.1"), now));
        assert!(!hosts.allows("web", "a.test", ip("1.1.1.1"), now + HOLD));
    }

    #[test]
    fn answers_only_count_for_the_container_that_received_them() {
        let resolver = MockResolver {
            answer: vec![ip("1.1.1.1")],
            ..MockResolver::default()
        };
        let mut hosts = HostAddresses::new(resolver, HOLD);
        let now = Instant::now();
        hosts.observe("rogue", "api.test", ip("6.6.6.6"), HOLD, now);
        assert!(hosts.allows("rogue", "api.test", ip("6.6.6.6"), now));
        assert!(!hosts.allows("web", "api.test", ip("6.6.6.6"), now));
        // Without answers of its own, a container gets what Portcullis resolves itself.
        assert_eq!(
            hosts
                .addresses_at("web", "api.test", now)
                .expect("addresses"),
            vec![(ip("1.1.1.1"), HOLD)]
        );
        // Portcullis's own lookups count for everyone.
        assert!(hosts.allows("rogue", "api.test", ip("1.1.1.1"), now));

        hosts.prune(now + HOLD);
        assert!(!hosts.allows("rogue", "api.test", ip("6.6.6.6"), now));
    }
}
