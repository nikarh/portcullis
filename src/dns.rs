use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::{debug, trace};

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("dns lookup failed for host {host}: {message}")]
    LookupFailed { host: String, message: String },
}

pub trait HostnameIpResolver {
    fn resolve(&mut self, host: &str) -> Result<Arc<[IpAddr]>, DnsError>;
}

pub trait UpstreamResolver {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError>;
}

#[derive(Debug, Clone, Copy)]
pub struct SystemUpstreamResolver;

impl UpstreamResolver for SystemUpstreamResolver {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        trace!(%host, "performing system DNS lookup");
        let addresses = (host, 0)
            .to_socket_addrs()
            .map_err(|error| DnsError::LookupFailed {
                host: host.to_string(),
                message: error.to_string(),
            })?;

        let mut ips: Vec<IpAddr> = addresses.map(|address| address.ip()).collect();
        ips.sort_unstable();
        ips.dedup();

        trace!(%host, result_count = ips.len(), ?ips, "system DNS lookup result");
        Ok(ips)
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    values: Arc<[IpAddr]>,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct DnsProxyCache<R>
where
    R: UpstreamResolver,
{
    resolver: R,
    max_size: usize,
    ttl: Duration,
    entries: HashMap<String, CacheEntry>,
    lru: VecDeque<String>,
}

impl<R> DnsProxyCache<R>
where
    R: UpstreamResolver,
{
    pub fn new(resolver: R, ttl: Duration, max_size: usize) -> Self {
        Self {
            resolver,
            max_size,
            ttl,
            entries: HashMap::new(),
            lru: VecDeque::new(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn purge_expired(&mut self, now: Instant) {
        if self.entries.is_empty() {
            return;
        }

        trace!(
            entry_count = self.entries.len(),
            "purging expired DNS cache entries"
        );

        let mut expired_keys = Vec::new();
        for (host, entry) in &self.entries {
            if entry.expires_at <= now {
                expired_keys.push(host.clone());
            }
        }

        for key in &expired_keys {
            self.entries.remove(key);
        }

        if !expired_keys.is_empty() {
            self.lru.retain(|host| !expired_keys.contains(host));
            debug!(
                expired_count = expired_keys.len(),
                "expired DNS cache entries removed"
            );
        }
    }

    fn touch_lru(&mut self, host: &str) {
        self.lru.retain(|entry| entry != host);
        self.lru.push_back(host.to_string());
    }

    fn enforce_limit(&mut self) {
        while self.entries.len() > self.max_size {
            let Some(oldest) = self.lru.pop_front() else {
                break;
            };
            if self.entries.remove(&oldest).is_some() {
                debug!(%oldest, max_size = self.max_size, "evicted DNS cache entry due to size limit");
            }
        }
    }
}

impl<R> HostnameIpResolver for DnsProxyCache<R>
where
    R: UpstreamResolver,
{
    fn resolve(&mut self, host: &str) -> Result<Arc<[IpAddr]>, DnsError> {
        let now = Instant::now();
        self.purge_expired(now);

        if let Some(entry) = self.entries.get(host)
            && entry.expires_at > now
        {
            let values = Arc::clone(&entry.values);
            let value_count = values.len();
            self.touch_lru(host);
            trace!(%host, ip_count = value_count, "DNS cache hit");
            return Ok(values);
        }

        trace!(%host, "DNS cache miss");
        let values = self.resolver.resolve_host(host)?;

        // Allocation note:
        // 1) `values` allocates a Vec for upstream results.
        // 2) `Arc<[IpAddr]>` allocates once to store deduplicated addresses for cheap cache-hit cloning.
        // 3) Host key String is stored in HashMap and LRU deque.
        let addresses: Arc<[IpAddr]> = Arc::<[IpAddr]>::from(values.into_boxed_slice());
        let expires_at = now + self.ttl;

        self.entries.insert(
            host.to_string(),
            CacheEntry {
                values: Arc::clone(&addresses),
                expires_at,
            },
        );
        self.touch_lru(host);
        self.enforce_limit();

        trace!(
            %host,
            ip_count = addresses.len(),
            ttl_secs = self.ttl.as_secs(),
            cache_size = self.entries.len(),
            "stored DNS cache entry"
        );

        Ok(addresses)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone)]
    struct MockResolver {
        calls: Arc<Mutex<Vec<String>>>,
        mapping: HashMap<String, Vec<IpAddr>>,
    }

    impl MockResolver {
        fn with_mapping(mapping: &[(&str, &[&str])]) -> Self {
            let mut values = HashMap::new();
            for (host, ips) in mapping {
                let mut parsed = Vec::new();
                for ip in *ips {
                    let value = match ip.parse() {
                        Ok(address) => address,
                        Err(error) => panic!("failed to parse test ip address: {error}"),
                    };
                    parsed.push(value);
                }
                values.insert((*host).to_string(), parsed);
            }

            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                mapping: values,
            }
        }

        fn call_count(&self) -> usize {
            let guard = match self.calls.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock call list: {error}"),
            };
            guard.len()
        }
    }

    impl UpstreamResolver for MockResolver {
        fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
            let mut guard = match self.calls.lock() {
                Ok(value) => value,
                Err(error) => panic!("failed to lock call list: {error}"),
            };
            guard.push(host.to_string());

            self.mapping
                .get(host)
                .cloned()
                .ok_or_else(|| DnsError::LookupFailed {
                    host: host.to_string(),
                    message: "missing host mapping".to_string(),
                })
        }
    }

    #[test]
    fn cache_hit_returns_cached_addresses() {
        let resolver = MockResolver::with_mapping(&[("api.example.com", &["1.1.1.1"])]);
        let mut cache = DnsProxyCache::new(resolver.clone(), Duration::from_secs(300), 128);

        let first = cache.resolve("api.example.com");
        assert!(first.is_ok());

        let second = cache.resolve("api.example.com");
        assert!(second.is_ok());
        assert_eq!(resolver.call_count(), 1);
    }

    #[test]
    fn ttl_zero_forces_relookup() {
        let resolver = MockResolver::with_mapping(&[("api.example.com", &["1.1.1.1"])]);
        let mut cache = DnsProxyCache::new(resolver.clone(), Duration::from_secs(0), 128);

        let _ = cache.resolve("api.example.com");
        let _ = cache.resolve("api.example.com");

        assert_eq!(resolver.call_count(), 2);
    }

    #[test]
    fn max_size_enforces_eviction() {
        let resolver = MockResolver::with_mapping(&[
            ("a.example.com", &["1.1.1.1"]),
            ("b.example.com", &["2.2.2.2"]),
            ("c.example.com", &["3.3.3.3"]),
        ]);
        let mut cache = DnsProxyCache::new(resolver, Duration::from_secs(300), 2);

        let _ = cache.resolve("a.example.com");
        let _ = cache.resolve("b.example.com");
        let _ = cache.resolve("c.example.com");

        assert_eq!(cache.len(), 2);
    }
}
