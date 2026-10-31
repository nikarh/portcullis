//! Addresses of the hostnames used in `host:` rules.
//!
//! Addresses come from two places:
//! - DNS answers containers receive, which Portcullis inspects (see `dns_inspect`), with the
//!   answer's TTL;
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

/// The addresses currently allowed for a hostname, with how long each stays allowed.
pub trait HostResolver {
    fn addresses(&mut self, host: &str) -> Result<Vec<(IpAddr, Duration)>, DnsError>;
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
#[derive(Debug)]
pub struct HostAddresses<R> {
    resolver: R,
    hold: Duration,
    entries: HashMap<String, HostEntry>,
}

impl<R> HostAddresses<R>
where
    R: UpstreamResolver,
{
    pub fn new(resolver: R, hold: Duration) -> Self {
        Self {
            resolver,
            hold,
            entries: HashMap::new(),
        }
    }

    /// Record an address a DNS answer gave for `host`. Returns how long it is allowed.
    pub fn observe(
        &mut self,
        host: &str,
        address: IpAddr,
        ttl: Duration,
        now: Instant,
    ) -> Duration {
        let allowed_for = ttl.max(self.hold);
        let expires = now + allowed_for;
        let entry = self.entries.entry(normalize(host)).or_default();
        let current = entry.addresses.entry(address).or_insert(expires);
        *current = (*current).max(expires);
        entry.retry_at = None;
        allowed_for
    }

    /// Whether `address` is currently allowed for `host`.
    #[must_use]
    pub fn allows(&self, host: &str, address: IpAddr, now: Instant) -> bool {
        self.entries
            .get(&normalize(host))
            .and_then(|entry| entry.addresses.get(&address))
            .is_some_and(|expires| *expires > now)
    }

    fn addresses_at(
        &mut self,
        host: &str,
        now: Instant,
    ) -> Result<Vec<(IpAddr, Duration)>, DnsError> {
        let host = normalize(host);
        let entry = self.entries.entry(host.clone()).or_default();
        entry.addresses.retain(|_, expires| *expires > now);

        if entry.addresses.is_empty() && entry.retry_at.is_none_or(|retry_at| retry_at <= now) {
            match self.resolver.resolve_host(&host) {
                Ok(addresses) => {
                    for address in addresses {
                        entry.addresses.insert(address, now + self.hold);
                    }
                }
                Err(error) => {
                    entry.retry_at = Some(now + RETRY_AFTER);
                    return Err(error);
                }
            }
        }

        let mut addresses: Vec<_> = entry
            .addresses
            .iter()
            .map(|(address, expires)| (*address, expires.saturating_duration_since(now)))
            .collect();
        addresses.sort_unstable();
        Ok(addresses)
    }
}

impl<R> HostResolver for HostAddresses<R>
where
    R: UpstreamResolver,
{
    fn addresses(&mut self, host: &str) -> Result<Vec<(IpAddr, Duration)>, DnsError> {
        self.addresses_at(host, Instant::now())
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
                .addresses_at("API.example.com.", now)
                .expect("addresses"),
            vec![(ip("1.1.1.1"), HOLD)]
        );
        hosts
            .addresses_at("api.example.com", now)
            .expect("addresses");
        assert_eq!(*resolver.calls.lock().expect("lock"), 1);
    }

    #[test]
    fn retries_failed_lookups_after_a_while() {
        let resolver = MockResolver::default();
        let mut hosts = HostAddresses::new(resolver.clone(), HOLD);
        let now = Instant::now();
        assert!(hosts.addresses_at("missing.test", now).is_err());
        assert!(
            hosts
                .addresses_at("missing.test", now)
                .expect("cached")
                .is_empty()
        );
        assert_eq!(*resolver.calls.lock().expect("lock"), 1);
        assert!(
            hosts
                .addresses_at("missing.test", now + RETRY_AFTER)
                .is_err()
        );
        assert_eq!(*resolver.calls.lock().expect("lock"), 2);
    }

    #[test]
    fn observed_addresses_are_held_at_least_the_hold_time() {
        let mut hosts = HostAddresses::new(MockResolver::default(), HOLD);
        let now = Instant::now();
        assert_eq!(
            hosts.observe("api.test", ip("1.1.1.1"), Duration::from_secs(60), now),
            HOLD
        );
        let long = Duration::from_secs(7200);
        assert_eq!(hosts.observe("api.test", ip("2.2.2.2"), long, now), long);
        assert_eq!(
            hosts.addresses_at("api.test", now).expect("addresses"),
            vec![(ip("1.1.1.1"), HOLD), (ip("2.2.2.2"), long)]
        );
        // Expired addresses are gone; the hostname is then looked up again.
        assert!(hosts.addresses_at("api.test", now + long).is_err());
    }

    #[test]
    fn tells_which_addresses_a_host_allows() {
        let mut hosts = HostAddresses::new(MockResolver::default(), HOLD);
        let now = Instant::now();
        hosts.observe("a.test", ip("1.1.1.1"), HOLD, now);
        hosts.observe("b.test", ip("2.2.2.2"), HOLD, now);
        assert!(hosts.allows("A.test.", ip("1.1.1.1"), now));
        assert!(!hosts.allows("b.test", ip("1.1.1.1"), now));
        assert!(!hosts.allows("a.test", ip("1.1.1.1"), now + HOLD));
    }
}
