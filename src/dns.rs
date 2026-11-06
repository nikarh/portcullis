//! Addresses of the hostnames used in `host:` rules.
//!
//! Addresses come from two places:
//! - DNS answers containers receive, which Portcullis inspects (see `dns_inspect`), with the
//!   answer's TTL; they only count for the container that received the answer;
//! - Portcullis's own lookups through the host's resolver, for every container with a rule
//!   for the name. The first one when a rule needs the name, then again on a schedule (see
//!   `host_refresh`), so an address stays allowed while DNS still returns it, also for
//!   containers that resolved it once and kept it, or where Portcullis can't see.
//!
//! Every address stays allowed for the container's hold time after it was last seen, since
//! applications often keep using an address for longer than its TTL. That is also the
//! grace an address DNS no longer returns gets: DNS answers with a different subset of a
//! pool at every lookup, so an address missing from an answer isn't necessarily stale.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::trace;

/// How long after a lookup the resolver didn't answer the hostname is looked up again.
pub const RETRY_AFTER: Duration = Duration::from_secs(30);

/// `--hostname-hold` when not set.
pub const DEFAULT_HOLD: Duration = Duration::from_secs(3600);
/// The shortest hold: shorter ones would need lookups more often than every few seconds.
pub const MIN_HOLD: Duration = Duration::from_secs(10);
/// The longest hold. An address a week after anything last said it belongs to a name is
/// likely someone else's; it also keeps every expiry far from overflowing.
pub const MAX_HOLD: Duration = Duration::from_hours(7 * 24);

/// What a hold value has to look like, for messages about invalid ones.
pub const HOLD_EXPECTED: &str =
    "seconds, or a number with s, m, h or d (30m, 2h, 1d), from 10s to 7d";

/// Parse a hold: seconds (`3600`), or a number with a unit (`90s`, `30m`, `2h`, `1d`).
pub fn parse_hold(value: &str) -> Result<Duration, &'static str> {
    let value = value.trim();
    let (number, unit) = match value.find(|c: char| !c.is_ascii_digit()) {
        Some(index) => value.split_at(index),
        None => (value, "s"),
    };
    let unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 24 * 3600,
        _ => return Err(HOLD_EXPECTED),
    };
    let hold = number
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(unit))
        .map(Duration::from_secs)
        .ok_or(HOLD_EXPECTED)?;
    if (MIN_HOLD..=MAX_HOLD).contains(&hold) {
        Ok(hold)
    } else {
        Err(HOLD_EXPECTED)
    }
}

/// How often Portcullis looks up a hostname whose shortest hold is `hold`: four times per
/// hold, so an address DNS keeps returning never runs out between two lookups.
#[must_use]
pub fn refresh_interval(hold: Duration) -> Duration {
    (hold / 4).max(MIN_HOLD / 2)
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("dns lookup failed for host {host}: {message}")]
    LookupFailed {
        host: String,
        message: String,
        /// The resolver said the name doesn't exist, rather than not answering.
        missing: bool,
    },
}

/// Resolves hostnames through some resolver.
pub trait UpstreamResolver {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError>;
}

/// The addresses currently allowed for a hostname in a container's rules, with how long
/// each stays allowed.
pub trait HostResolver {
    /// The hold of containers without a `portcullis.hostname-hold` label.
    fn default_hold(&self) -> Duration;

    fn addresses(
        &mut self,
        container: &str,
        host: &str,
        hold: Duration,
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
            .map_err(|error| {
                let message = error.to_string();
                DnsError::LookupFailed {
                    host: host.to_string(),
                    missing: says_missing(&message),
                    message,
                }
            })?
            .map(|address| address.ip())
            .collect();
        ips.sort_unstable();
        ips.dedup();
        trace!(%host, result_count = ips.len(), ?ips, "system DNS lookup result");
        Ok(ips)
    }
}

/// Whether a `getaddrinfo` error says the name doesn't exist (`EAI_NONAME`, `EAI_NODATA`),
/// as glibc and musl word it. The standard library only passes the message on. Anything
/// else, such as a resolver that doesn't answer (`EAI_AGAIN`), counts as DNS being
/// unavailable.
fn says_missing(message: &str) -> bool {
    [
        "Name or service not known",
        "No address associated with hostname",
        "Name does not resolve",
        "Address not available",
    ]
    .iter()
    .any(|text| message.contains(text))
}

/// Portcullis's own lookups of a hostname.
#[derive(Debug, Default)]
struct Lookups {
    /// Address and when a lookup last returned it.
    addresses: HashMap<IpAddr, Instant>,
    /// When the hostname was last looked up.
    attempted: Option<Instant>,
    /// Why the last lookup failed, if it did.
    failure: Option<DnsError>,
}

impl Lookups {
    /// Until when an address a lookup returned at `confirmed` stays allowed. While DNS is
    /// unavailable (lookups fail, but not because the name is gone), one hold longer: the
    /// addresses were real, and containers that don't need DNS right then keep working.
    fn until(&self, confirmed: Instant, hold: Duration) -> Instant {
        let unavailable = matches!(
            self.failure,
            Some(DnsError::LookupFailed { missing: false, .. })
        );
        confirmed + if unavailable { hold * 2 } else { hold }
    }
}

/// Addresses one container may learn for one hostname from DNS answers, while they are
/// allowed. A container that may ask a resolver of its own could otherwise answer itself
/// with millions of addresses, each held for at least `--hostname-hold`, and make every
/// rule update of every container slow. Real hostnames come nowhere near it; past it, new
/// addresses are refused (and connections to them denied) until old ones expire.
pub const MAX_ADDRESSES_PER_HOST: usize = 4096;

/// Known addresses of hostnames, normalized to lower case without a trailing dot.
///
/// Addresses from DNS answers belong to the container that received the answer: a
/// container that may use a resolver of its choice could otherwise make another
/// container's `host:` rules allow whatever that resolver claims. Addresses Portcullis
/// resolves itself, through the host's resolver, apply to every container.
///
/// Each container has a hold of its own (`portcullis.hostname-hold`), passed in by callers.
#[derive(Debug)]
pub struct HostAddresses<R> {
    resolver: R,
    hold: Duration,
    /// Portcullis's own lookups, by hostname.
    lookups: HashMap<String, Lookups>,
    /// Addresses from DNS answers and when they stop being allowed, by container name and
    /// hostname.
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
            lookups: HashMap::new(),
            observed: HashMap::new(),
        }
    }

    /// The resolver Portcullis's own lookups go through.
    pub const fn resolver(&self) -> &R {
        &self.resolver
    }

    /// Record an address a DNS answer to `container` gave for `host`. Returns how long it
    /// is allowed from `now` on (by this answer, or by anything else that allows it
    /// longer), or `None` when the container's addresses for the hostname are at
    /// [`MAX_ADDRESSES_PER_HOST`].
    pub fn observe(
        &mut self,
        container: &str,
        host: &str,
        address: IpAddr,
        ttl: Duration,
        hold: Duration,
        now: Instant,
    ) -> Option<Duration> {
        let host = normalize(host);
        // A TTL can say 68 years; past the longest hold it says nothing useful.
        let expires = now + ttl.min(MAX_HOLD).max(hold);
        let addresses = self
            .observed
            .entry((container.to_string(), host.clone()))
            .or_default();
        if addresses.len() >= MAX_ADDRESSES_PER_HOST && !addresses.contains_key(&address) {
            addresses.retain(|_, expires| *expires > now);
            if addresses.len() >= MAX_ADDRESSES_PER_HOST {
                return None;
            }
        }
        let current = addresses.entry(address).or_insert(expires);
        *current = (*current).max(expires);
        Some(self.remaining(container, &host, address, hold, now))
    }

    /// How much longer `address` is allowed for `host` in the rules of `container`, whose
    /// hold is `hold`; zero when it isn't.
    #[must_use]
    pub fn remaining(
        &self,
        container: &str,
        host: &str,
        address: IpAddr,
        hold: Duration,
        now: Instant,
    ) -> Duration {
        let observed = self
            .observed
            .get(&(container.to_string(), host.to_string()))
            .and_then(|addresses| addresses.get(&address).copied());
        let looked_up = self.lookups.get(host).and_then(|lookups| {
            lookups
                .addresses
                .get(&address)
                .map(|confirmed| lookups.until(*confirmed, hold))
        });
        observed
            .into_iter()
            .chain(looked_up)
            .max()
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
    }

    /// Whether `address` is currently allowed for `host` in `container`'s rules.
    #[must_use]
    pub fn allows(
        &self,
        container: &str,
        host: &str,
        address: IpAddr,
        hold: Duration,
        now: Instant,
    ) -> bool {
        !self
            .remaining(container, &normalize(host), address, hold, now)
            .is_zero()
    }

    /// Forget expired addresses and containers without any left, given the longest hold
    /// any container has, and the lookups of hostnames no rule uses anymore.
    pub fn prune(&mut self, now: Instant, longest_hold: Duration, hosts: &HashSet<String>) {
        self.observed.retain(|_, addresses| {
            addresses.retain(|_, expires| *expires > now);
            !addresses.is_empty()
        });
        self.lookups.retain(|host, lookups| {
            let until = |confirmed| lookups.until(confirmed, longest_hold);
            let live: HashMap<_, _> = lookups
                .addresses
                .iter()
                .filter(|(_, confirmed)| until(**confirmed) > now)
                .map(|(address, confirmed)| (*address, *confirmed))
                .collect();
            lookups.addresses = live;
            hosts.contains(host)
        });
    }

    /// When `host`, used by rules whose shortest hold is `hold`, is due to be looked up
    /// again: right away if it never was, [`RETRY_AFTER`] after a lookup the resolver didn't
    /// answer. A name the resolver says doesn't exist is asked for at the usual pace: it may
    /// only exist for the resolvers containers use, and asking every few seconds would only
    /// fill the resolver's logs.
    #[must_use]
    pub fn lookup_due(&self, host: &str, hold: Duration, now: Instant) -> Instant {
        let interval = refresh_interval(hold);
        match self.lookups.get(host) {
            Some(Lookups {
                attempted: Some(attempted),
                failure,
                ..
            }) => {
                let unavailable =
                    matches!(failure, Some(DnsError::LookupFailed { missing: false, .. }));
                *attempted
                    + if unavailable {
                        RETRY_AFTER.min(interval)
                    } else {
                        interval
                    }
            }
            _ => now,
        }
    }

    /// Record the result of looking `host` up. Returns whether it resolved where the
    /// lookup before it had failed.
    pub fn record_lookup(
        &mut self,
        host: &str,
        result: Result<Vec<IpAddr>, DnsError>,
        now: Instant,
    ) -> bool {
        let lookups = self.lookups.entry(host.to_string()).or_default();
        let failed_before = lookups.failure.is_some();
        lookups.attempted = Some(now);
        match result {
            Ok(addresses) => {
                lookups.failure = None;
                let resolved = !addresses.is_empty();
                for address in addresses {
                    lookups.addresses.insert(address, now);
                }
                resolved && failed_before
            }
            Err(error) => {
                lookups.failure = Some(error);
                false
            }
        }
    }

    /// The addresses lookups of `host` have returned and that may still be in its sets.
    #[must_use]
    pub fn looked_up(&self, host: &str) -> Vec<IpAddr> {
        self.lookups
            .get(host)
            .map(|lookups| lookups.addresses.keys().copied().collect())
            .unwrap_or_default()
    }

    fn addresses_at(
        &mut self,
        container: &str,
        host: &str,
        hold: Duration,
        now: Instant,
    ) -> Result<Vec<(IpAddr, Duration)>, DnsError> {
        let host = normalize(host);
        // A pattern (`*.example.com`) can't be looked up: only answers to the container fill
        // it. A hostname is looked up the first time a rule needs it, then on a schedule.
        let exact = !host.contains('*');
        let mut failed = None;
        if exact
            && self
                .lookups
                .get(&host)
                .is_none_or(|lookups| lookups.attempted.is_none())
        {
            let result = self.resolver.resolve_host(&host);
            failed = result.as_ref().err().cloned();
            self.record_lookup(&host, result, now);
        }

        let mut addresses: HashMap<IpAddr, Instant> = self
            .observed
            .get_mut(&(container.to_string(), host.clone()))
            .map(|observed| {
                observed.retain(|_, expires| *expires > now);
                observed.clone()
            })
            .unwrap_or_default();
        let lookups = self.lookups.get(&host);
        for (address, confirmed) in lookups.iter().flat_map(|lookups| &lookups.addresses) {
            let until = lookups.map_or(*confirmed, |lookups| lookups.until(*confirmed, hold));
            if until > now {
                let current = addresses.entry(*address).or_insert(until);
                *current = (*current).max(until);
            }
        }
        // Only the lookup that failed reports it; until a later one succeeds, the hostname
        // just has no addresses, which every rule update lists.
        if addresses.is_empty()
            && let Some(error) = failed
        {
            return Err(error);
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
    fn default_hold(&self) -> Duration {
        self.hold
    }

    fn addresses(
        &mut self,
        container: &str,
        host: &str,
        hold: Duration,
    ) -> Result<Vec<(IpAddr, Duration)>, DnsError> {
        self.addresses_at(container, host, hold, Instant::now())
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
        /// When there's no answer: the name doesn't exist, rather than DNS not answering.
        missing: bool,
    }

    impl UpstreamResolver for MockResolver {
        fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
            *self.calls.lock().expect("lock") += 1;
            if self.answer.is_empty() {
                return Err(DnsError::LookupFailed {
                    host: host.to_string(),
                    message: "not found".to_string(),
                    missing: self.missing,
                });
            }
            Ok(self.answer.clone())
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("ip")
    }

    fn resolving(addresses: &[&str]) -> MockResolver {
        MockResolver {
            answer: addresses.iter().map(|address| ip(address)).collect(),
            ..MockResolver::default()
        }
    }

    const HOLD: Duration = Duration::from_secs(3600);
    const TTL: Duration = Duration::from_secs(60);

    #[test]
    fn parses_holds() {
        for (value, seconds) in [
            ("10", 10),
            ("3600", 3600),
            ("90s", 90),
            ("30m", 1800),
            ("2h", 7200),
            ("7d", 604_800),
        ] {
            assert_eq!(
                parse_hold(value),
                Ok(Duration::from_secs(seconds)),
                "{value}"
            );
        }
        for value in [
            "",
            "9",
            "8d",
            "1w",
            "1.5h",
            "-1",
            "h",
            "1h30m",
            "99999999999999999999d",
        ] {
            assert_eq!(parse_hold(value), Err(HOLD_EXPECTED), "{value}");
        }
        assert_eq!(refresh_interval(HOLD), Duration::from_mins(15));
        assert_eq!(refresh_interval(MIN_HOLD), Duration::from_secs(5));
    }

    #[test]
    fn tells_a_missing_name_from_dns_not_answering() {
        assert!(says_missing(
            "failed to lookup address information: Name or service not known"
        ));
        assert!(says_missing(
            "failed to lookup address information: No address associated with hostname"
        ));
        assert!(says_missing(
            "failed to lookup address information: Name does not resolve"
        ));
        assert!(!says_missing(
            "failed to lookup address information: Temporary failure in name resolution"
        ));
        assert!(!says_missing(
            "failed to lookup address information: Try again"
        ));
    }

    #[test]
    fn looks_up_unknown_hostnames_once() {
        let resolver = resolving(&["1.1.1.1"]);
        let mut hosts = HostAddresses::new(resolver.clone(), HOLD);
        let now = Instant::now();
        assert_eq!(
            hosts
                .addresses_at("web", "API.example.com.", HOLD, now)
                .expect("addresses"),
            vec![(ip("1.1.1.1"), HOLD)]
        );
        hosts
            .addresses_at("db", "api.example.com", HOLD, now)
            .expect("addresses");
        assert_eq!(*resolver.calls.lock().expect("lock"), 1);
    }

    #[test]
    fn reports_a_failed_lookup_once_and_leaves_retrying_to_the_schedule() {
        let resolver = MockResolver::default();
        let mut hosts = HostAddresses::new(resolver.clone(), HOLD);
        let now = Instant::now();
        assert!(
            hosts
                .addresses_at("web", "missing.test", HOLD, now)
                .is_err()
        );
        assert_eq!(
            hosts
                .addresses_at("web", "missing.test", HOLD, now + RETRY_AFTER)
                .expect("no addresses"),
            []
        );
        assert_eq!(*resolver.calls.lock().expect("lock"), 1);
        // The resolver didn't answer: soon.
        assert_eq!(
            hosts.lookup_due("missing.test", HOLD, now),
            now + RETRY_AFTER
        );
        // It said the name doesn't exist: at the usual pace.
        let error = DnsError::LookupFailed {
            host: "missing.test".to_string(),
            message: "not found".to_string(),
            missing: true,
        };
        hosts.record_lookup("missing.test", Err(error), now);
        assert_eq!(
            hosts.lookup_due("missing.test", HOLD, now),
            now + refresh_interval(HOLD)
        );
    }

    #[test]
    fn lookups_count_for_every_container_with_its_own_hold() {
        let mut hosts = HostAddresses::new(resolving(&["1.1.1.1"]), HOLD);
        let now = Instant::now();
        // A container with answers of its own gets the lookups too.
        hosts.observe("web", "api.test", ip("2.2.2.2"), TTL, HOLD, now);
        let short = Duration::from_secs(600);
        assert_eq!(
            hosts
                .addresses_at("web", "api.test", HOLD, now)
                .expect("addresses"),
            vec![(ip("1.1.1.1"), HOLD), (ip("2.2.2.2"), HOLD)]
        );
        assert_eq!(
            hosts
                .addresses_at("job", "api.test", short, now)
                .expect("addresses"),
            vec![(ip("1.1.1.1"), short)]
        );
        let later = now + short;
        assert!(hosts.allows("web", "api.test", ip("1.1.1.1"), HOLD, later));
        assert!(!hosts.allows("job", "api.test", ip("1.1.1.1"), short, later));
    }

    #[test]
    fn a_lookup_renews_what_it_returns_and_lets_the_rest_run_out() {
        let mut hosts = HostAddresses::new(resolving(&["1.1.1.1"]), HOLD);
        let now = Instant::now();
        hosts
            .addresses_at("web", "api.test", HOLD, now)
            .expect("addresses");
        let later = now + Duration::from_mins(15);
        hosts.record_lookup("api.test", Ok(vec![ip("2.2.2.2")]), later);
        assert_eq!(
            hosts
                .addresses_at("web", "api.test", HOLD, later)
                .expect("addresses"),
            vec![
                (ip("1.1.1.1"), HOLD.saturating_sub(Duration::from_mins(15))),
                (ip("2.2.2.2"), HOLD)
            ]
        );
        assert!(!hosts.allows("web", "api.test", ip("1.1.1.1"), HOLD, now + HOLD));
        assert!(hosts.allows("web", "api.test", ip("2.2.2.2"), HOLD, now + HOLD));
    }

    #[test]
    fn keeps_addresses_one_more_hold_while_dns_is_unavailable() {
        for (missing, until) in [(false, 2 * HOLD), (true, HOLD)] {
            let mut hosts = HostAddresses::new(resolving(&["1.1.1.1"]), HOLD);
            let now = Instant::now();
            hosts
                .addresses_at("web", "api.test", HOLD, now)
                .expect("addresses");
            let error = DnsError::LookupFailed {
                host: "api.test".to_string(),
                message: "failed".to_string(),
                missing,
            };
            hosts.record_lookup("api.test", Err(error), now + Duration::from_mins(15));
            assert_eq!(
                hosts.remaining("web", "api.test", ip("1.1.1.1"), HOLD, now),
                until,
                "missing: {missing}"
            );
        }
    }

    #[test]
    fn observed_addresses_are_held_at_least_the_hold_time() {
        let mut hosts = HostAddresses::new(MockResolver::default(), HOLD);
        let now = Instant::now();
        assert_eq!(
            hosts.observe("web", "*.api.test", ip("1.1.1.1"), TTL, HOLD, now),
            Some(HOLD)
        );
        let long = Duration::from_secs(7200);
        assert_eq!(
            hosts.observe("web", "*.api.test", ip("2.2.2.2"), long, HOLD, now),
            Some(long)
        );
        assert_eq!(
            hosts
                .addresses_at("web", "*.api.test", HOLD, now)
                .expect("addresses"),
            vec![(ip("1.1.1.1"), HOLD), (ip("2.2.2.2"), long)]
        );
        // A TTL of years counts for no more than the longest hold.
        let years = Duration::from_secs(u64::from(u32::MAX));
        assert_eq!(
            hosts.observe("web", "*.api.test", ip("3.3.3.3"), years, HOLD, now),
            Some(MAX_HOLD)
        );
        assert_eq!(
            hosts
                .addresses_at("web", "*.api.test", HOLD, now + MAX_HOLD)
                .expect("addresses"),
            []
        );
    }

    #[test]
    fn observing_an_address_again_renews_it_but_never_shortens_it() {
        let mut hosts = HostAddresses::new(MockResolver::default(), HOLD);
        let now = Instant::now();
        let later = now + Duration::from_secs(300);
        hosts.observe("web", "api.test", ip("1.1.1.1"), TTL, HOLD, now);
        assert_eq!(
            hosts.observe("web", "api.test", ip("1.1.1.1"), TTL, HOLD, later),
            Some(HOLD),
            "a full hold from the answer seen again"
        );
        assert!(hosts.allows("web", "api.test", ip("1.1.1.1"), HOLD, now + HOLD));

        let long = Duration::from_secs(7200);
        hosts.observe("web", "api.test", ip("2.2.2.2"), long, HOLD, now);
        assert_eq!(
            hosts.observe("web", "api.test", ip("2.2.2.2"), TTL, HOLD, later),
            Some(Duration::from_mins(115)),
            "what's left of the longer TTL from before"
        );
    }

    #[test]
    fn an_answer_never_shortens_what_a_lookup_allows() {
        let mut hosts = HostAddresses::new(resolving(&["1.1.1.1"]), HOLD);
        let now = Instant::now();
        hosts
            .addresses_at("web", "api.test", HOLD, now)
            .expect("addresses");
        let error = DnsError::LookupFailed {
            host: "api.test".to_string(),
            message: "failed".to_string(),
            missing: false,
        };
        hosts.record_lookup("api.test", Err(error), now);
        assert_eq!(
            hosts.observe("web", "api.test", ip("1.1.1.1"), TTL, HOLD, now),
            Some(2 * HOLD)
        );
    }

    #[test]
    fn limits_the_addresses_a_container_learns_for_a_hostname() {
        let mut hosts = HostAddresses::new(MockResolver::default(), HOLD);
        let now = Instant::now();
        let address = |index: usize| {
            let index = u32::try_from(index).expect("index");
            IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + index))
        };
        let observe = |hosts: &mut HostAddresses<_>, container, host, address, now| {
            hosts.observe(container, host, address, HOLD, HOLD, now)
        };
        for index in 0..MAX_ADDRESSES_PER_HOST {
            assert!(observe(&mut hosts, "rogue", "api.test", address(index), now).is_some());
        }
        let extra = address(MAX_ADDRESSES_PER_HOST);
        assert_eq!(observe(&mut hosts, "rogue", "api.test", extra, now), None);
        assert!(!hosts.allows("rogue", "api.test", extra, HOLD, now));
        // Known addresses are renewed, other hostnames and containers aren't affected, and
        // room frees up as addresses expire.
        assert!(observe(&mut hosts, "rogue", "api.test", address(0), now).is_some());
        assert!(observe(&mut hosts, "rogue", "b.test", extra, now).is_some());
        assert!(observe(&mut hosts, "web", "api.test", extra, now).is_some());
        let later = now + HOLD + Duration::from_secs(1);
        assert!(observe(&mut hosts, "rogue", "api.test", extra, later).is_some());
    }

    #[test]
    fn patterns_are_only_filled_by_answers() {
        let resolver = resolving(&["1.1.1.1"]);
        let mut hosts = HostAddresses::new(resolver.clone(), HOLD);
        let now = Instant::now();
        assert_eq!(
            hosts
                .addresses_at("web", "*.api.test", HOLD, now)
                .expect("addresses"),
            []
        );
        hosts.observe("web", "*.api.test", ip("2.2.2.2"), HOLD, HOLD, now);
        assert_eq!(
            hosts
                .addresses_at("web", "*.api.test", HOLD, now)
                .expect("addresses"),
            vec![(ip("2.2.2.2"), HOLD)]
        );
        assert_eq!(*resolver.calls.lock().expect("lock"), 0);
    }

    #[test]
    fn tells_which_addresses_a_host_allows() {
        let mut hosts = HostAddresses::new(MockResolver::default(), HOLD);
        let now = Instant::now();
        hosts.observe("web", "a.test", ip("1.1.1.1"), HOLD, HOLD, now);
        hosts.observe("web", "b.test", ip("2.2.2.2"), HOLD, HOLD, now);
        assert!(hosts.allows("web", "A.test.", ip("1.1.1.1"), HOLD, now));
        assert!(!hosts.allows("web", "b.test", ip("1.1.1.1"), HOLD, now));
        assert!(!hosts.allows("web", "a.test", ip("1.1.1.1"), HOLD, now + HOLD));
    }

    #[test]
    fn answers_only_count_for_the_container_that_received_them() {
        let mut hosts = HostAddresses::new(resolving(&["1.1.1.1"]), HOLD);
        let now = Instant::now();
        hosts.observe("rogue", "api.test", ip("6.6.6.6"), HOLD, HOLD, now);
        assert!(hosts.allows("rogue", "api.test", ip("6.6.6.6"), HOLD, now));
        assert!(!hosts.allows("web", "api.test", ip("6.6.6.6"), HOLD, now));
        assert_eq!(
            hosts
                .addresses_at("web", "api.test", HOLD, now)
                .expect("addresses"),
            vec![(ip("1.1.1.1"), HOLD)]
        );
        // Portcullis's own lookups count for everyone.
        assert!(hosts.allows("rogue", "api.test", ip("1.1.1.1"), HOLD, now));

        let used = HashSet::from(["api.test".to_string()]);
        hosts.prune(now + HOLD, HOLD, &used);
        assert!(!hosts.allows("rogue", "api.test", ip("6.6.6.6"), HOLD, now));
    }
}
