//! Portcullis's own lookups of the hostnames of `host:` rules, on a schedule.
//!
//! Every hostname a rule uses (not patterns, which can't be looked up) is looked up again
//! four times per hold of the containers that use it, and [`RETRY_AFTER`] after a lookup the
//! resolver didn't answer. The addresses a lookup returns are allowed for a full hold from then on in the
//! rules of every container with a rule for the hostname, right away, without a rule
//! update. So an address stays allowed while DNS still returns it, even for a container
//! that resolved it once and kept it, and one DNS no longer returns runs out a hold after
//! it was last returned.
//!
//! Lookups go through the host's resolver and can take seconds, so they run here, without
//! holding the addresses that rule updates and DNS inspection use.
//!
//! [`RETRY_AFTER`]: crate::dns::RETRY_AFTER

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use tracing::debug;

use crate::connection_log::SharedHosts;
use crate::directory::Directory;
use crate::dns::{HostAddresses, HostResolver, UpstreamResolver};
use crate::firewall::{HostSet, NftablesFirewall};

/// How long the thread sleeps when no hostname is due, until a rule update wakes it.
const IDLE: Duration = Duration::from_secs(3600);

/// Look the hostnames of the current rules up whenever they are due. A message on `wake`
/// says the rules changed; one is sent on `resolved` when a hostname that failed to
/// resolve has addresses now, for a rule update to report it.
pub fn spawn(
    firewall: Arc<NftablesFirewall>,
    directory: Arc<Directory>,
    hosts: SharedHosts,
    wake: Receiver<()>,
    resolved: Sender<()>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            let outcome = refresh(
                &directory.host_sets(),
                &hosts,
                Instant::now,
                |set, addresses| {
                    if let Err(error) = firewall.update_host_addresses(set, addresses) {
                        // The set may be gone after a concurrent rule update, which has the
                        // addresses anyway.
                        debug!(%error, host = %set.host, "failed to update the addresses of a hostname set");
                    }
                },
            );
            if outcome.resolved && resolved.send(()).is_err() {
                return;
            }
            let wait = outcome
                .next
                .map_or(IDLE, |next| next.saturating_duration_since(Instant::now()));
            match wake.recv_timeout(wait) {
                Ok(()) => while wake.try_recv().is_ok() {},
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Outcome {
    /// When the next hostname is due, if any is used.
    next: Option<Instant>,
    /// A hostname that failed to resolve did.
    resolved: bool,
}

/// Look up the hostnames of `sets` that are due, and set what each lookup returned in the
/// sets of every container that uses the hostname with `update`.
fn refresh<R>(
    sets: &[HostSet],
    hosts: &Mutex<HostAddresses<R>>,
    clock: impl Fn() -> Instant,
    mut update: impl FnMut(&HostSet, &[(IpAddr, Duration)]),
) -> Outcome
where
    R: UpstreamResolver + Clone,
{
    // Each hostname with the shortest hold of the containers that use it.
    let mut names: HashMap<&str, Duration> = HashMap::new();
    for set in sets.iter().filter(|set| set.pattern.is_exact()) {
        let hold = names.entry(set.host.as_str()).or_insert(set.hold);
        *hold = (*hold).min(set.hold);
    }
    let lock = || hosts.lock().unwrap_or_else(PoisonError::into_inner);

    let now = clock();
    let (resolver, due) = {
        let mut hosts = lock();
        let longest = sets
            .iter()
            .map(|set| set.hold)
            .max()
            .unwrap_or_else(|| hosts.default_hold());
        let used: HashSet<String> = names.keys().map(|name| (*name).to_string()).collect();
        hosts.prune(now, longest, &used);
        let due: Vec<&str> = names
            .iter()
            .filter(|(name, hold)| hosts.lookup_due(name, **hold, now) <= now)
            .map(|(name, _)| *name)
            .collect();
        (hosts.resolver().clone(), due)
    };

    let mut outcome = Outcome::default();
    for name in due {
        let result = resolver.resolve_host(name);
        if let Err(error) = &result {
            debug!(%error, "looking a hostname up again failed");
        }
        let now = clock();
        let mut updates = Vec::new();
        {
            let mut hosts = lock();
            outcome.resolved |= hosts.record_lookup(name, result, now);
            let looked_up = hosts.looked_up(name);
            for set in sets
                .iter()
                .filter(|set| set.host == name && set.pattern.is_exact())
            {
                let addresses: Vec<_> = looked_up
                    .iter()
                    .map(|address| {
                        let left = hosts.remaining(&set.container, name, *address, set.hold, now);
                        (*address, left)
                    })
                    .collect();
                updates.push((set, addresses));
            }
        }
        for (set, addresses) in updates {
            update(set, &addresses);
        }
    }

    let now = clock();
    let hosts = lock();
    outcome.next = names
        .iter()
        .map(|(name, hold)| hosts.lookup_due(name, *hold, now))
        .min();
    outcome
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::dns::{DnsError, RETRY_AFTER, refresh_interval};
    use crate::firewall::HostSetId;
    use crate::pattern::NamePattern;

    /// Answers with what the test sets, and counts lookups.
    #[derive(Clone)]
    struct Resolver {
        answer: Arc<Mutex<Result<Vec<IpAddr>, bool>>>,
        calls: Arc<Mutex<usize>>,
    }

    impl Default for Resolver {
        fn default() -> Self {
            Self {
                answer: Arc::new(Mutex::new(Ok(Vec::new()))),
                calls: Arc::default(),
            }
        }
    }

    impl Resolver {
        fn answer(&self, addresses: &[&str]) {
            *self.answer.lock().expect("lock") = Ok(addresses.iter().map(|a| ip(a)).collect());
        }

        /// Fail; `missing` says the name doesn't exist.
        fn fail(&self, missing: bool) {
            *self.answer.lock().expect("lock") = Err(missing);
        }

        fn calls(&self) -> usize {
            *self.calls.lock().expect("lock")
        }
    }

    impl UpstreamResolver for Resolver {
        fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
            *self.calls.lock().expect("lock") += 1;
            self.answer
                .lock()
                .expect("lock")
                .clone()
                .map_err(|missing| DnsError::LookupFailed {
                    host: host.to_string(),
                    message: "failed".to_string(),
                    missing,
                })
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("ip")
    }

    const HOLD: Duration = Duration::from_secs(3600);
    const HOST: &str = "api.test";

    fn set(container: &str, host: &str, hold: Duration) -> HostSet {
        HostSet {
            id: HostSetId::for_host(container, host),
            container: container.to_string().into(),
            host: host.to_string(),
            pattern: NamePattern::parse(host, crate::pattern::NameKind::Host).expect("pattern"),
            addresses: Vec::new(),
            hold,
            used_v4: true,
            used_v6: true,
        }
    }

    /// Runs `refresh` at a time the test moves, and keeps what it set in each set.
    struct Harness {
        resolver: Resolver,
        hosts: Mutex<HostAddresses<Resolver>>,
        start: Instant,
        now: Cell<Instant>,
        sets: Vec<HostSet>,
    }

    impl Harness {
        fn new(sets: Vec<HostSet>) -> Self {
            let resolver = Resolver::default();
            resolver.answer(&["192.0.2.1"]);
            let start = Instant::now();
            Self {
                hosts: Mutex::new(HostAddresses::new(resolver.clone(), HOLD)),
                resolver,
                start,
                now: Cell::new(start),
                sets,
            }
        }

        fn at(&self, seconds: u64) -> &Self {
            self.now.set(self.start + Duration::from_secs(seconds));
            self
        }

        /// What `refresh` set, by container.
        fn refresh(&self) -> (Outcome, HashMap<String, Vec<(IpAddr, Duration)>>) {
            let mut updates = HashMap::new();
            let outcome = refresh(
                &self.sets,
                &self.hosts,
                || self.now.get(),
                |set, addresses| {
                    let mut addresses = addresses.to_vec();
                    addresses.sort_unstable();
                    updates.insert(set.container.to_string(), addresses);
                },
            );
            (outcome, updates)
        }

        /// The addresses a rule update would put in the set of `container`.
        fn planned(&self, container: &str, hold: Duration) -> Vec<(IpAddr, Duration)> {
            let mut hosts = self.hosts.lock().expect("lock");
            // A rule update at the harness's time: only the lookup time matters here.
            hosts.addresses(container, HOST, hold).unwrap_or_default()
        }
    }

    #[test]
    fn looks_hostnames_up_again_four_times_per_hold() {
        let harness = Harness::new(vec![set("web", HOST, HOLD)]);
        let (outcome, updates) = harness.at(0).refresh();
        assert_eq!(updates["web"], [(ip("192.0.2.1"), HOLD)]);
        assert_eq!(outcome.next, Some(harness.start + refresh_interval(HOLD)));
        assert_eq!(harness.resolver.calls(), 1);

        // Not due yet: nothing is looked up.
        let (_, updates) = harness.at(60).refresh();
        assert!(updates.is_empty());
        assert_eq!(harness.resolver.calls(), 1);

        // DNS moved on: the new address gets a full hold, the old one keeps what is left
        // of its own, a hold after it was last returned.
        harness.resolver.answer(&["192.0.2.2"]);
        let (_, updates) = harness.at(900).refresh();
        assert_eq!(
            updates["web"],
            [
                (
                    ip("192.0.2.1"),
                    HOLD.saturating_sub(Duration::from_mins(15))
                ),
                (ip("192.0.2.2"), HOLD)
            ]
        );
        // Once it ran out (the kernel removed it on time), it is forgotten.
        let (_, updates) = harness.at(3600 + 900).refresh();
        assert_eq!(updates["web"], [(ip("192.0.2.2"), HOLD)]);
    }

    #[test]
    fn an_address_dns_keeps_returning_never_runs_out() {
        let harness = Harness::new(vec![set("web", HOST, HOLD)]);
        let mut seconds = 0;
        while seconds < 5 * 3600 {
            let (outcome, updates) = harness.at(seconds).refresh();
            if let Some(addresses) = updates.get("web") {
                assert_eq!(addresses, &[(ip("192.0.2.1"), HOLD)]);
            }
            let next = outcome.next.expect("next");
            seconds = (next - harness.start).as_secs();
        }
        assert_eq!(harness.resolver.calls(), 20);
    }

    #[test]
    fn each_container_gets_its_own_hold_and_the_shortest_sets_the_pace() {
        let short = Duration::from_secs(600);
        let harness = Harness::new(vec![set("web", HOST, HOLD), set("job", HOST, short)]);
        let (outcome, updates) = harness.at(0).refresh();
        assert_eq!(updates["web"], [(ip("192.0.2.1"), HOLD)]);
        assert_eq!(updates["job"], [(ip("192.0.2.1"), short)]);
        assert_eq!(outcome.next, Some(harness.start + refresh_interval(short)));
    }

    #[test]
    fn retries_failed_lookups_and_reports_when_they_resolve() {
        let harness = Harness::new(vec![set("web", HOST, HOLD)]);
        // The resolver doesn't answer: soon.
        harness.resolver.fail(false);
        let (outcome, updates) = harness.at(0).refresh();
        assert_eq!(updates["web"], []);
        assert!(!outcome.resolved);
        assert_eq!(outcome.next, Some(harness.start + RETRY_AFTER));
        // It says the name doesn't exist: at the usual pace.
        harness.resolver.fail(true);
        let (outcome, _) = harness.at(30).refresh();
        assert_eq!(
            outcome.next,
            Some(harness.start + Duration::from_secs(30) + refresh_interval(HOLD))
        );

        harness.resolver.answer(&["192.0.2.1"]);
        let (outcome, updates) = harness.at(30 + 900).refresh();
        assert_eq!(updates["web"], [(ip("192.0.2.1"), HOLD)]);
        assert!(
            outcome.resolved,
            "a rule update reports the hostname resolved"
        );
        // Only when it changes.
        let (outcome, _) = harness.at(30 + 1800).refresh();
        assert!(!outcome.resolved);
    }

    #[test]
    fn keeps_addresses_one_more_hold_while_dns_is_unavailable() {
        let harness = Harness::new(vec![set("web", HOST, HOLD)]);
        harness.at(0).refresh();
        // The resolver doesn't answer: the address gets one more hold, from its last lookup.
        harness.resolver.fail(false);
        let (_, updates) = harness.at(900).refresh();
        assert_eq!(
            updates["web"],
            [(
                ip("192.0.2.1"),
                (2 * HOLD).saturating_sub(Duration::from_mins(15))
            )]
        );
        assert_eq!(
            harness.planned("web", HOLD).len(),
            1,
            "rule updates keep it too"
        );
        // ...and no more than that: then it runs out, and is forgotten.
        let (_, updates) = harness.at(2 * 3600).refresh();
        assert_eq!(updates["web"], []);
    }

    #[test]
    fn takes_the_extra_hold_back_when_dns_answers_again() {
        let harness = Harness::new(vec![set("web", HOST, HOLD)]);
        harness.at(0).refresh();
        harness.resolver.fail(false);
        harness.at(900).refresh();
        // DNS is back, and moved on: the old address keeps what is left of its hold...
        harness.resolver.answer(&["192.0.2.2"]);
        let (_, updates) = harness.at(930).refresh();
        assert_eq!(
            updates["web"],
            [
                (
                    ip("192.0.2.1"),
                    HOLD.saturating_sub(Duration::from_secs(930))
                ),
                (ip("192.0.2.2"), HOLD)
            ]
        );
        // ...and is removed when that is up, though the kernel would have kept it longer.
        harness.resolver.fail(false);
        harness.at(3500).refresh();
        harness.resolver.answer(&["192.0.2.2"]);
        let (_, updates) = harness.at(3700).refresh();
        assert_eq!(
            updates["web"],
            [(ip("192.0.2.1"), Duration::ZERO), (ip("192.0.2.2"), HOLD)]
        );
    }

    #[test]
    fn lets_addresses_run_out_when_the_name_is_gone() {
        let harness = Harness::new(vec![set("web", HOST, HOLD)]);
        harness.at(0).refresh();
        harness.resolver.fail(true);
        let (_, updates) = harness.at(900).refresh();
        assert_eq!(
            updates["web"],
            [(
                ip("192.0.2.1"),
                HOLD.saturating_sub(Duration::from_mins(15))
            )]
        );
    }

    #[test]
    fn does_not_look_patterns_up_and_forgets_hostnames_no_rule_uses() {
        let mut harness = Harness::new(vec![set("web", "*.api.test", HOLD)]);
        let (outcome, updates) = harness.at(0).refresh();
        assert!(updates.is_empty());
        assert_eq!(outcome.next, None);
        assert_eq!(harness.resolver.calls(), 0);

        harness.sets = vec![set("web", HOST, HOLD)];
        harness.at(0).refresh();
        harness.sets = Vec::new();
        harness.at(1).refresh();
        assert_eq!(
            harness.hosts.lock().expect("lock").looked_up(HOST),
            [] as [std::net::IpAddr; 0]
        );
    }
}
