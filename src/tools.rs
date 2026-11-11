//! Command-line tools working on events: `portcullis watch` and `portcullis audit`.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write as _};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::connection_log::unforged;
use crate::events::{Connection, Event, Line, Reason, Verdict, WarningKind, text};
use crate::firewall::{PRIVATE_V4, PRIVATE_V6};
use crate::model::Protocol;

/// Where `watch` connects to unless told otherwise; run the daemon with
/// `--events-socket /run/portcullis.sock` to match.
pub const DEFAULT_EVENTS_SOCKET: &str = "/run/portcullis.sock";

/// Print a running daemon's events as they happen, as text.
pub fn watch(socket: &Path) -> io::Result<()> {
    let stream = UnixStream::connect(socket).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("can't connect to {}: {error}", socket.display()),
        )
    })?;
    let mut stdout = io::stdout().lock();
    for line in BufReader::new(stream).lines() {
        let line = line?;
        match serde_json::from_str::<Line>(&line) {
            Ok(event) => writeln!(stdout, "{}", text(&event.time, &event.event))?,
            Err(_) => writeln!(stdout, "{line}")?,
        }
    }
    Ok(())
}

/// Read JSON events (one per line; other lines are skipped) and print, per container, the
/// labels that would allow what was denied, or would have been denied in monitor mode.
/// Events from before `since` (an event time, or a prefix of one) are left out.
pub fn audit(input: Option<&Path>, since: Option<&str>) -> io::Result<()> {
    let reader: Box<dyn BufRead> = match input {
        Some(path) if path != Path::new("-") => Box::new(BufReader::new(File::open(path)?)),
        _ => Box::new(io::stdin().lock()),
    };
    let mut report = Report::default();
    for line in reader.lines() {
        if let Ok(line) = serde_json::from_str::<Line>(&line?)
            && since.is_none_or(|since| line.time.as_str() >= since)
        {
            report.add(line.event);
        }
    }
    io::stdout().lock().write_all(report.render().as_bytes())
}

/// The earliest event time `audit --since` keeps: a time as events have it, or a prefix of
/// one (`2026-11-06`, `2026-11-06T10:30`), in UTC; or how long ago (`30m`, `12h`, `7d`).
pub fn since(value: &str) -> io::Result<String> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "--since: expected a UTC time such as 2026-11-06T10:30, or how long ago such as 30m, 12h or 7d, not {value:?}"
            ),
        )
    };
    let date = value.as_bytes();
    if date.len() >= 10 && date.iter().take(4).all(u8::is_ascii_digit) && date.get(4) == Some(&b'-')
    {
        return Ok(value.trim_end_matches('Z').to_string());
    }
    let (number, unit) = value
        .find(|c: char| !c.is_ascii_digit())
        .map_or((value, ""), |index| value.split_at(index));
    let unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(invalid()),
    };
    let ago = number
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(unit))
        .map(std::time::Duration::from_secs)
        .ok_or_else(invalid)?;
    let at = std::time::SystemTime::now()
        .checked_sub(ago)
        .ok_or_else(invalid)?;
    Ok(crate::events::timestamp(at))
}

/// What was sent to a destination: protocol and destination port (none for protocols
/// without ports).
type Services = BTreeSet<(Cow<'static, str>, Option<u16>)>;

/// Examples of a kind of finding kept per container; more are only counted.
const EXAMPLES: usize = 5;

/// Hostnames under one parent domain, with the same services, folded into one pattern.
const FOLD_HOSTS: usize = 3;

/// Public addresses with the same services folded into `ip:public`; as many with services
/// of their own are folded too.
const FOLD_PUBLIC: usize = 10;

/// Ports of one protocol listed one by one; more become one range, from the lowest to the
/// highest.
const LIST_PORTS: usize = 10;

/// What starts the detail of egress to the Docker host.
const DOCKER_HOST: &str = "the Docker host";

#[derive(Debug, Default)]
struct Findings {
    /// Denied or would-be-denied connections.
    count: usize,
    /// `host:<domain>` or `ip:<address>` to services.
    egress: BTreeMap<String, Services>,
    /// Egress targets that are the Docker host, with what the events said about them.
    docker_host: BTreeMap<String, Cow<'static, str>>,
    /// `container:<name>` or `multicast:<group>` to services.
    icc: BTreeMap<String, Services>,
    /// ICC destinations that aren't known containers.
    icc_unknown: BTreeSet<IpAddr>,
    /// Resolvers queried.
    dns: BTreeSet<IpAddr>,
    /// Sources that aren't the container's own.
    spoofed: BTreeSet<Cow<'static, str>>,
    /// Source denials that weren't forged, see `connection_log::unforged`.
    unforged: BTreeSet<Cow<'static, str>>,
    /// Packets of connections the firewall didn't track, and how many.
    mid_stream: (BTreeSet<String>, usize),
    /// Traffic of protocols labels can't name.
    unsupported: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct Report {
    containers: BTreeMap<String, Findings>,
    warnings: BTreeSet<(String, String)>,
}

impl Report {
    fn add(&mut self, event: Event) {
        match event {
            Event::Connection(connection)
                if matches!(connection.verdict, Verdict::Denied | Verdict::WouldDeny) =>
            {
                self.add_connection(connection);
            }
            Event::Warning(warning)
                if matches!(
                    warning.kind,
                    WarningKind::DnsNotObservable
                        | WarningKind::InvalidLabel
                        | WarningKind::PolicyFile
                        | WarningKind::InvalidNetwork
                ) =>
            {
                self.warnings.insert((
                    warning.container.unwrap_or_else(|| "-".to_string()),
                    warning.message,
                ));
            }
            _ => {}
        }
    }

    fn add_connection(&mut self, connection: Connection) {
        let Connection {
            reason,
            container,
            protocol,
            source,
            source_port,
            destination,
            destination_port,
            destination_container,
            domain,
            detail,
            mid_stream,
            ..
        } = connection;
        let container = container.unwrap_or_else(|| match source {
            Some(source) => format!("unknown container at {source}"),
            None => "unknown container".to_string(),
        });
        let findings = self.containers.entry(container).or_default();
        findings.count += 1;
        let routed = matches!(reason, Reason::Egress | Reason::Icc | Reason::Dns);
        // Replies, and the rest of connections the firewall lost track of: rules don't
        // need to allow them, they allow the connections.
        if routed && mid_stream {
            let (examples, count) = &mut findings.mid_stream;
            *count += 1;
            if examples.len() < EXAMPLES {
                examples.insert(format!(
                    "{protocol} {} to {}",
                    endpoint(source, source_port, None),
                    endpoint(
                        destination,
                        destination_port,
                        destination_container.as_deref()
                    )
                ));
            }
            return;
        }
        let service = match Protocol::from_name(&protocol) {
            Some(known) if known.has_ports() => (protocol, destination_port),
            None if routed => {
                findings.unsupported.insert(format!(
                    "IP protocol {protocol} to {}",
                    endpoint(destination, None, destination_container.as_deref())
                ));
                return;
            }
            // Protocols without ports, and frames (ARP, IPv6).
            _ => (protocol, None),
        };
        match reason {
            Reason::Egress => {
                let target = match (domain, destination) {
                    (Some(mut domain), _) => {
                        domain.insert_str(0, "host:");
                        domain
                    }
                    (None, Some(destination)) => format!("ip:{destination}"),
                    (None, None) => return,
                };
                if let Some(detail) = detail.filter(|detail| detail.starts_with(DOCKER_HOST))
                    && !findings.docker_host.contains_key(&target)
                {
                    findings.docker_host.insert(target.clone(), detail);
                }
                findings.egress.entry(target).or_default().insert(service);
            }
            Reason::Icc => {
                let target = match (destination_container, destination) {
                    (Some(mut container), _) => {
                        container.insert_str(0, "container:");
                        container
                    }
                    (None, Some(group)) if group.is_multicast() => format!("multicast:{group}"),
                    (None, destination) => {
                        findings.icc_unknown.extend(destination);
                        return;
                    }
                };
                findings.icc.entry(target).or_default().insert(service);
            }
            Reason::Dns => {
                findings.dns.extend(destination);
            }
            Reason::Source | Reason::Frame | Reason::Limit => {
                let detail = detail.unwrap_or_else(|| {
                    format!("sent {} it isn't allowed to send", service.0).into()
                });
                if reason == Reason::Source && unforged(&detail) {
                    findings.unforged.insert(detail);
                } else {
                    findings.spoofed.insert(detail);
                }
            }
        }
    }

    fn render(self) -> String {
        let mut out = String::new();
        if self.containers.is_empty() && self.warnings.is_empty() {
            out.push_str("No denied or would-be-denied traffic found.\n");
            return out;
        }
        for (container, findings) in self.containers {
            let _ = writeln!(
                out,
                "{container} ({} denied or would-be-denied connections)",
                findings.count
            );
            let suggestions = fold_egress(findings.egress);
            let names = label_names(&suggestions);
            for (suggestion, name) in suggestions.iter().zip(names) {
                let _ = write!(out, "  portcullis.egress.{name}={},", suggestion.target);
                write_services(&mut out, &suggestion.services);
                out.push('\n');
                suggestion.write_note(&mut out);
                if let Some(detail) = findings.docker_host.get(&suggestion.target) {
                    let _ = writeln!(
                        out,
                        "    (careful: {detail}; this lets the container reach services on the host. Traffic Docker's userland proxy forwards to the container comes from this address too, so the container may only have learned it from that)"
                    );
                }
                if suggestion
                    .services
                    .iter()
                    .any(|(protocol, _)| protocol == "igmp")
                {
                    out.push_str("    (IGMP: the container joins multicast groups; only needed when the host relays multicast, such as with igmpproxy)\n");
                }
            }
            for (target, services) in &findings.icc {
                let _ = write!(
                    out,
                    "  portcullis.icc.allow.{}={target},",
                    Slug(target_value(target))
                );
                write_services(&mut out, services);
                out.push('\n');
            }
            if !findings.icc.is_empty() {
                out.push_str("    (with portcullis.icc.mode=allow-listed)\n");
            }
            for destination in &findings.icc_unknown {
                if *destination == IpAddr::from([255, 255, 255, 255]) {
                    let _ = writeln!(
                        out,
                        "  broadcast to every container on the network, which labels can't allow"
                    );
                } else {
                    let _ = writeln!(
                        out,
                        "  traffic to {destination} on the same network, which isn't a known container"
                    );
                }
            }
            for resolver in &findings.dns {
                let _ = writeln!(out, "  portcullis.dns.{}=ip:{resolver}", Slug(resolver));
            }
            for unsupported in &findings.unsupported {
                let _ = writeln!(out, "  {unsupported}, which labels can't allow");
            }
            let (examples, count) = &findings.mid_stream;
            if *count > 0 {
                let _ = writeln!(
                    out,
                    "  {count} packets of connections the firewall didn't track (replies, or connections it lost track of; no label needed), such as:"
                );
                for example in examples {
                    let _ = writeln!(out, "    {example}");
                }
            }
            for detail in &findings.spoofed {
                let _ = writeln!(out, "  suspicious: {detail}");
            }
            for detail in &findings.unforged {
                let _ = writeln!(out, "  denied, but not crafted (no label needed): {detail}");
            }
        }
        if !self.warnings.is_empty() {
            out.push_str("Warnings\n");
            for (container, message) in &self.warnings {
                let _ = writeln!(out, "  {container}: {message}");
            }
        }
        out
    }
}

/// `address:port`, or the container's name for the address.
fn endpoint(
    address: Option<IpAddr>,
    port: Option<u16>,
    container: Option<&str>,
) -> impl fmt::Display {
    fmt::from_fn(move |f| {
        match (container, address) {
            (Some(container), _) => f.write_str(container)?,
            (None, Some(address)) => write!(f, "{address}")?,
            (None, None) => f.write_str("?")?,
        }
        match port {
            Some(port) => write!(f, ":{port}"),
            None => Ok(()),
        }
    })
}

/// A suggested egress label: its target, services, and what was folded into it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Suggestion {
    target: String,
    services: Services,
    /// Hostnames, or public addresses, folded into a pattern or `ip:public`.
    folded: usize,
    /// The target of one of them.
    example: Option<String>,
}

impl Suggestion {
    const fn new(target: String, services: Services) -> Self {
        Self {
            target,
            services,
            folded: 0,
            example: None,
        }
    }

    /// Take `other` in: its services, and what it stands for.
    fn absorb(&mut self, mut other: Self) {
        self.services.append(&mut other.services);
        self.folded += other.folded.max(1);
        if self.example.is_none() {
            self.example = other.example.or(Some(other.target));
        }
    }

    /// What was folded into it, as a line of the report.
    fn write_note(&self, out: &mut String) {
        let Some(example) = &self.example else {
            return;
        };
        let (folded, example) = (self.folded, target_value(example));
        let _ = if self.target == "ip:public" {
            writeln!(
                out,
                "    ({folded} public addresses, such as {example}; or list them as ip: labels)"
            )
        } else {
            writeln!(out, "    ({folded} names, such as {example})")
        };
    }
}

/// What a target names: `api.test` of `host:api.test`.
fn target_value(target: &str) -> &str {
    target.split_once(':').map_or(target, |(_, value)| value)
}

/// One suggestion for each of `targets`, all with `services`.
fn spread(targets: Vec<String>, services: Services, suggestions: &mut Vec<Suggestion>) {
    let mut targets = targets.into_iter().peekable();
    while let Some(target) = targets.next() {
        let services = if targets.peek().is_some() {
            services.clone()
        } else {
            return suggestions.push(Suggestion::new(target, services));
        };
        suggestions.push(Suggestion::new(target, services));
    }
}

/// Egress targets with their services, folded: hostnames under one domain with the same
/// services become a pattern, which also takes in names it covers; many public addresses
/// `ip:public`. One label per target.
fn fold_egress(egress: BTreeMap<String, Services>) -> Vec<Suggestion> {
    // Hostnames, and public addresses, by their services.
    let mut by_services: BTreeMap<Services, (Vec<String>, Vec<String>)> = BTreeMap::new();
    let mut suggestions = Vec::new();
    for (target, services) in egress {
        let public = target
            .strip_prefix("ip:")
            .and_then(|address| address.parse::<IpAddr>().ok())
            .is_some_and(is_public);
        if target.starts_with("host:") {
            by_services.entry(services).or_default().0.push(target);
        } else if public {
            by_services.entry(services).or_default().1.push(target);
        } else {
            suggestions.push(Suggestion::new(target, services));
        }
    }
    // Public addresses that weren't folded with others of the same services.
    let mut lone_public: Vec<(Vec<String>, Services)> = Vec::new();
    for (services, (mut hosts, public)) in by_services {
        while let Some(target) = widest_parent(&hosts) {
            let pattern = target_value(&target);
            let parent = pattern
                .trim_start_matches('*')
                .strip_prefix('.')
                .unwrap_or(pattern);
            let mut members = hosts
                .extract_if(.., |host| below(target_value(host), parent).is_some())
                .peekable();
            let example = members.next();
            let folded = members.count() + usize::from(example.is_some());
            suggestions.push(Suggestion {
                target,
                services: services.clone(),
                folded,
                example,
            });
        }
        if public.len() >= FOLD_PUBLIC {
            let mut public = public.into_iter();
            suggestions.push(Suggestion {
                target: "ip:public".to_string(),
                services: services.clone(),
                folded: public.len(),
                example: public.next(),
            });
            spread(hosts, services, &mut suggestions);
        } else if public.is_empty() {
            spread(hosts, services, &mut suggestions);
        } else {
            spread(hosts, services.clone(), &mut suggestions);
            lone_public.push((public, services));
        }
    }
    // Many public addresses each with ports of their own, such as peers of a peer-to-peer
    // protocol: their services together.
    let lone = lone_public
        .iter()
        .map(|(public, _)| public.len())
        .sum::<usize>();
    if lone >= FOLD_PUBLIC {
        let mut folded = Suggestion::new("ip:public".to_string(), Services::new());
        folded.folded = lone;
        for (public, mut services) in lone_public {
            folded.services.append(&mut services);
            if folded.example.is_none() {
                folded.example = public.into_iter().next();
            }
        }
        suggestions.push(folded);
    } else {
        for (public, services) in lone_public {
            spread(public, services, &mut suggestions);
        }
    }
    merge(suggestions)
}

/// One suggestion per target, and none for a name or pattern a pattern covers: labels with
/// the same target, or a name a pattern already allows, are one rule.
fn merge(mut suggestions: Vec<Suggestion>) -> Vec<Suggestion> {
    suggestions.sort_unstable_by(|a, b| a.target.cmp(&b.target));
    suggestions.dedup_by(|later, kept| {
        if later.target != kept.target {
            return false;
        }
        kept.services.append(&mut later.services);
        kept.folded += later.folded;
        if kept.example.is_none() {
            kept.example = later.example.take();
        }
        true
    });
    // The narrowest patterns first, so that what they took in ends up in the widest.
    let mut patterns: Vec<usize> = (0..suggestions.len())
        .filter(|index| {
            suggestions
                .get(*index)
                .is_some_and(|suggestion| suggestion.target.starts_with("host:*"))
        })
        .collect();
    let dots = |suggestions: &[Suggestion], index: usize| {
        suggestions
            .get(index)
            .map_or(0, |suggestion| suggestion.target.matches('.').count())
    };
    patterns.sort_by_key(|index| std::cmp::Reverse(dots(&suggestions, *index)));
    let mut taken = vec![false; suggestions.len()];
    for pattern in patterns {
        for index in 0..suggestions.len() {
            let (Some(target), Some(by)) = (suggestions.get(index), suggestions.get(pattern))
            else {
                continue;
            };
            if index == pattern
                || taken.get(index) == Some(&true)
                || !covers(target_value(&by.target), &target.target)
            {
                continue;
            }
            let covered = suggestions.get_mut(index).map(std::mem::take);
            if let (Some(covered), Some(into)) = (covered, suggestions.get_mut(pattern)) {
                into.absorb(covered);
            }
            if let Some(slot) = taken.get_mut(index) {
                *slot = true;
            }
        }
    }
    suggestions
        .into_iter()
        .zip(taken)
        .filter_map(|(suggestion, taken)| (!taken).then_some(suggestion))
        .collect()
}

/// What is below `parent` in `name`: `a.b` of `a.b.parent`.
fn below<'a>(name: &'a str, parent: &str) -> Option<&'a str> {
    name.strip_suffix(parent)?.strip_suffix('.')
}

/// Whether the name pattern `pattern` (`*.parent` or `**.parent`) allows everything the
/// `host:` target `target` does.
fn covers(pattern: &str, target: &str) -> bool {
    let Some(name) = target.strip_prefix("host:") else {
        return false;
    };
    let (deep, parent) = match pattern.split_once('.') {
        Some(("**", parent)) => (true, parent),
        Some(("*", parent)) => (false, parent),
        _ => return false,
    };
    match name.split_once('.') {
        // A pattern: as wide as this one at most.
        Some(("**", inner)) => deep && (inner == parent || below(inner, parent).is_some()),
        Some(("*", inner)) => inner == parent || (deep && below(inner, parent).is_some()),
        _ => below(name, parent).is_some_and(|below| deep || !below.contains('.')),
    }
}

/// A distinct label key for each suggestion, from what it names. A pattern that would share
/// its key with a name gets `-subdomains`.
fn label_names(suggestions: &[Suggestion]) -> Vec<String> {
    let mut names: Vec<String> = suggestions
        .iter()
        .map(|suggestion| Slug(target_value(&suggestion.target)).to_string())
        .collect();
    let shared: Vec<bool> = names
        .iter()
        .map(|name| names.iter().filter(|other| *other == name).count() > 1)
        .collect();
    for ((suggestion, name), shared) in suggestions.iter().zip(&mut names).zip(shared) {
        if shared && target_value(&suggestion.target).starts_with('*') {
            name.push_str("-subdomains");
        }
    }
    // Still the same (a pattern and a name both with dashes where the other has dots):
    // numbered.
    for index in 1..names.len() {
        let (before, rest) = names.split_at_mut(index);
        let Some(name) = rest.first_mut() else {
            continue;
        };
        if before.contains(name) {
            let base = name.len();
            for counter in 2.. {
                name.truncate(base);
                let _ = write!(name, "-{counter}");
                if !before.contains(name) {
                    break;
                }
            }
        }
    }
    names
}

/// The pattern target (`host:*.parent` when all are one level below it, else
/// `host:**.parent`) for the parent domain the most `hosts` targets are below, if at least
/// [`FOLD_HOSTS`] are.
fn widest_parent(hosts: &[String]) -> Option<String> {
    // Per parent: how many names are below it, and whether all one level below.
    let mut parents: BTreeMap<&str, (usize, bool)> = BTreeMap::new();
    for host in hosts {
        let name = target_value(host);
        // Parents of two labels and more (what follows a dot, and has a dot), but not
        // public suffixes like co.uk.
        for (index, (dot, _)) in name.match_indices('.').enumerate() {
            let Some(parent) = name.get(dot + 1..) else {
                continue;
            };
            if !parent.contains('.') || is_public_suffix(parent) {
                continue;
            }
            let (count, one_level) = parents.entry(parent).or_insert((0, true));
            *count += 1;
            *one_level &= index == 0;
        }
    }
    parents
        .into_iter()
        .filter(|(_, (count, _))| *count >= FOLD_HOSTS)
        // The most names; between as many, the most specific domain.
        .max_by_key(|(parent, (count, _))| (*count, parent.matches('.').count()))
        .map(|(parent, (_, one_level))| {
            format!("host:{}.{parent}", if one_level { "*" } else { "**" })
        })
}

/// Second-level domains under a country's domain that anyone can register under, like
/// `co.uk`.
fn is_public_suffix(domain: &str) -> bool {
    matches!(
        domain.split_once('.'),
        Some((second, country)) if country.len() == 2
            && matches!(second, "co" | "com" | "net" | "org" | "gov" | "edu" | "ac" | "or" | "ne")
    )
}

fn is_public(address: IpAddr) -> bool {
    let private = match address {
        IpAddr::V4(_) => PRIVATE_V4.as_slice(),
        IpAddr::V6(_) => PRIVATE_V6.as_slice(),
    };
    !private.iter().any(|range| {
        range
            .parse::<ipnet::IpNet>()
            .is_ok_and(|range| range.contains(&address))
    })
}

/// Services as in labels: `tcp:80,443,8000-8002,udp:53,icmp`. More than [`LIST_PORTS`]
/// ports of one protocol become one range.
fn write_services(out: &mut String, services: &Services) {
    let mut ports: BTreeMap<&str, Vec<u16>> = BTreeMap::new();
    let mut any_port: BTreeSet<&str> = BTreeSet::new();
    let mut without_ports: BTreeSet<&str> = BTreeSet::new();
    for (protocol, port) in services {
        match (Protocol::from_name(protocol), port) {
            (Some(known), Some(port)) if known.has_ports() => {
                ports.entry(protocol).or_default().push(*port);
            }
            (Some(known), None) if known.has_ports() => {
                any_port.insert(protocol);
            }
            _ => {
                without_ports.insert(protocol);
            }
        }
    }
    let mut first = true;
    let mut separate = |out: &mut String| {
        if !std::mem::take(&mut first) {
            out.push(',');
        }
    };
    for protocol in &any_port {
        separate(out);
        let _ = write!(out, "{protocol}:*");
    }
    for (protocol, mut ports) in ports {
        if any_port.contains(protocol) {
            continue;
        }
        ports.sort_unstable();
        ports.dedup();
        let mut ranges: Vec<(u16, u16)> = Vec::new();
        if ports.len() > LIST_PORTS {
            ranges.extend(ports.first().zip(ports.last()).map(|(a, b)| (*a, *b)));
        } else {
            for port in ports {
                match ranges.last_mut() {
                    Some((_, last)) if last.checked_add(1) == Some(port) => *last = port,
                    _ => ranges.push((port, port)),
                }
            }
        }
        separate(out);
        let _ = write!(out, "{protocol}:");
        for (index, (first, last)) in ranges.into_iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            if first == last {
                let _ = write!(out, "{first}");
            } else {
                let _ = write!(out, "{first}-{last}");
            }
        }
    }
    for protocol in without_ports {
        separate(out);
        out.push_str(protocol);
    }
}

/// A label key segment: lower case letters, digits and dashes for everything else, without
/// dashes at either end.
struct Slug<T>(T);

impl<T: fmt::Display> fmt::Display for Slug<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// Writes what it is given as a slug: dashes only once something follows them.
        struct Writer<'a, 'b> {
            f: &'a mut fmt::Formatter<'b>,
            started: bool,
            dashes: usize,
        }
        impl fmt::Write for Writer<'_, '_> {
            fn write_str(&mut self, text: &str) -> fmt::Result {
                for character in text.chars() {
                    if !character.is_ascii_alphanumeric() {
                        self.dashes += usize::from(self.started);
                        continue;
                    }
                    for _ in 0..std::mem::take(&mut self.dashes) {
                        self.f.write_char('-')?;
                    }
                    self.started = true;
                    self.f.write_char(character.to_ascii_lowercase())?;
                }
                Ok(())
            }
        }
        write!(
            Writer {
                f,
                started: false,
                dashes: 0,
            },
            "{}",
            self.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(events: &[&str]) -> Report {
        let mut report = Report::default();
        for event in events {
            let line: Line = serde_json::from_str(event).expect("event");
            report.add(line.event);
        }
        report
    }

    const EGRESS: &str = r#"{"time":"T","event":"connection","verdict":"would_deny","reason":"egress","container":"web","network":"backend","protocol":"tcp","source":"172.18.0.2","source_port":1,"destination":"104.18.3.4","destination_port":443,"destination_container":null,"domain":"api.stripe.com","domain_source":"dns","query":null,"detail":null}"#;

    #[test]
    fn suggests_labels_for_denied_traffic() {
        let report = lines(&[
            EGRESS,
            &EGRESS.replace("443", "80"),
            &EGRESS.replace(r#""domain":"api.stripe.com""#, r#""domain":null"#),
            r#"{"time":"T","event":"connection","verdict":"denied","reason":"icc","container":"web","network":"backend","protocol":"tcp","source":"172.18.0.2","source_port":1,"destination":"172.18.0.5","destination_port":5432,"destination_container":"db","domain":null,"domain_source":null,"query":null,"detail":null}"#,
            r#"{"time":"T","event":"connection","verdict":"denied","reason":"dns","container":"web","network":"backend","protocol":"udp","source":"172.18.0.2","source_port":1,"destination":"9.9.9.9","destination_port":53,"destination_container":null,"domain":null,"domain_source":null,"query":"x.test","detail":null}"#,
            r#"{"time":"T","event":"connection","verdict":"allowed","reason":"egress","container":"web","network":"backend","protocol":"tcp","source":"172.18.0.2","source_port":1,"destination":"1.1.1.1","destination_port":443,"destination_container":null,"domain":null,"domain_source":null,"query":null,"detail":null}"#,
            r#"{"time":"T","event":"warning","kind":"dns_not_observable","container":"web","message":"no DNS"}"#,
        ]);
        let output = report.render();
        assert_eq!(
            output,
            "\
web (5 denied or would-be-denied connections)
  portcullis.egress.api-stripe-com=host:api.stripe.com,tcp:80,443
  portcullis.egress.104-18-3-4=ip:104.18.3.4,tcp:443
  portcullis.icc.allow.db=container:db,tcp:5432
    (with portcullis.icc.mode=allow-listed)
  portcullis.dns.9-9-9-9=ip:9.9.9.9
Warnings
  web: no DNS
"
        );
    }

    /// An egress event of `container` to `destination` (`domain`, or address) and port.
    fn egress(container: &str, protocol: &str, destination: &str, port: Option<u16>) -> String {
        let (domain, address) = match destination.parse::<IpAddr>() {
            Ok(_) => ("null".to_string(), destination.to_string()),
            Err(_) => (format!("\"{destination}\""), "203.0.113.9".to_string()),
        };
        let port = port.map_or_else(|| "null".to_string(), |port| port.to_string());
        format!(
            r#"{{"time":"T","event":"connection","verdict":"would_deny","reason":"egress","container":"{container}","network":"n","protocol":"{protocol}","source":"172.18.0.2","source_port":1,"destination":"{address}","destination_port":{port},"destination_container":null,"domain":{domain},"domain_source":"dns","query":null,"detail":null}}"#
        )
    }

    #[test]
    fn names_protocols_without_ports() {
        let report = lines(&[
            &egress("player", "igmp", "224.0.0.22", None),
            &egress("player", "icmp", "1.1.1.1", None),
            &egress("player", "41", "192.0.2.1", None),
        ]);
        assert_eq!(
            report.render(),
            "\
player (3 denied or would-be-denied connections)
  portcullis.egress.1-1-1-1=ip:1.1.1.1,icmp
  portcullis.egress.224-0-0-22=ip:224.0.0.22,igmp
    (IGMP: the container joins multicast groups; only needed when the host relays multicast, such as with igmpproxy)
  IP protocol 41 to 192.0.2.1, which labels can't allow
"
        );
    }

    #[test]
    fn suggests_multicast_groups_between_containers() {
        let icc = |destination: &str, port: u16| {
            format!(
                r#"{{"time":"T","event":"connection","verdict":"would_deny","reason":"icc","container":"api","network":"n","protocol":"udp","source":"172.18.0.2","source_port":1,"destination":"{destination}","destination_port":{port},"destination_container":null,"domain":null,"domain_source":null,"query":null,"detail":null}}"#
            )
        };
        let report = lines(&[&icc("224.2.2.3", 54327), &icc("255.255.255.255", 21027)]);
        assert_eq!(
            report.render(),
            "\
api (2 denied or would-be-denied connections)
  portcullis.icc.allow.224-2-2-3=multicast:224.2.2.3,udp:54327
    (with portcullis.icc.mode=allow-listed)
  broadcast to every container on the network, which labels can't allow
"
        );
    }

    #[test]
    fn leaves_out_packets_of_connections_the_firewall_didnt_track() {
        let reply = r#"{"time":"T","event":"connection","verdict":"would_deny","reason":"icc","container":"app-cache","network":"n","protocol":"tcp","source":"172.20.0.18","source_port":6379,"destination":"172.20.0.19","destination_port":42076,"destination_container":"app","domain":null,"domain_source":null,"query":null,"detail":null,"mid_stream":true}"#;
        let report = lines(&[reply]);
        assert_eq!(
            report.render(),
            "\
app-cache (1 denied or would-be-denied connections)
  1 packets of connections the firewall didn't track (replies, or connections it lost track of; no label needed), such as:
    tcp 172.20.0.18:6379 to app:42076
"
        );
    }

    #[test]
    fn folds_hostnames_into_patterns() {
        let mut events = Vec::new();
        for host in [
            "ia800.us.example.org",
            "ia601.us.example.org",
            "dn7.ca.example.org",
        ] {
            events.push(egress("media", "tcp", host, Some(443)));
        }
        for host in ["i.example.net", "v.example.net", "preview.example.net"] {
            events.push(egress("reader", "tcp", host, Some(443)));
        }
        // Two names aren't enough, nor names with other ports, nor a public suffix.
        for host in ["a.example.com", "b.example.com"] {
            events.push(egress("media", "tcp", host, Some(443)));
        }
        events.push(egress("media", "tcp", "c.example.com", Some(80)));
        for host in ["a.co.uk", "b.co.uk", "c.co.uk"] {
            events.push(egress("other", "tcp", host, Some(443)));
        }
        let events: Vec<&str> = events.iter().map(String::as_str).collect();
        assert_eq!(
            lines(&events).render(),
            "\
media (6 denied or would-be-denied connections)
  portcullis.egress.example-org=host:**.example.org,tcp:443
    (3 names, such as dn7.ca.example.org)
  portcullis.egress.a-example-com=host:a.example.com,tcp:443
  portcullis.egress.b-example-com=host:b.example.com,tcp:443
  portcullis.egress.c-example-com=host:c.example.com,tcp:80
other (3 denied or would-be-denied connections)
  portcullis.egress.a-co-uk=host:a.co.uk,tcp:443
  portcullis.egress.b-co-uk=host:b.co.uk,tcp:443
  portcullis.egress.c-co-uk=host:c.co.uk,tcp:443
reader (3 denied or would-be-denied connections)
  portcullis.egress.example-net=host:*.example.net,tcp:443
    (3 names, such as i.example.net)
"
        );
    }

    #[test]
    fn folds_public_addresses_and_port_ranges() {
        let mut events = Vec::new();
        for index in 1..=12 {
            for port in [22000, 22001, 22002, 3478] {
                events.push(egress(
                    "sync",
                    "udp",
                    &format!("45.1.2.{index}"),
                    Some(port),
                ));
            }
        }
        // Not public: listed on its own.
        events.push(egress("sync", "tcp", "192.168.1.5", Some(22000)));
        let events: Vec<&str> = events.iter().map(String::as_str).collect();
        assert_eq!(
            lines(&events).render(),
            "\
sync (49 denied or would-be-denied connections)
  portcullis.egress.192-168-1-5=ip:192.168.1.5,tcp:22000
  portcullis.egress.public=ip:public,udp:3478,22000-22002
    (12 public addresses, such as 45.1.2.1; or list them as ip: labels)
"
        );
    }

    #[test]
    fn suggests_one_label_per_target_with_distinct_names() {
        let mut events = Vec::new();
        // Names on two levels under example.org on 80 and 443, others on 443 alone, a
        // pattern of its own on 8080 below them, and example.org itself.
        for index in 0..3 {
            for port in [80, 443] {
                events.push(egress(
                    "media",
                    "tcp",
                    &format!("dn{index}.ca.example.org"),
                    Some(port),
                ));
                events.push(egress(
                    "media",
                    "tcp",
                    &format!("ia{index}.example.org"),
                    Some(port),
                ));
            }
            events.push(egress(
                "media",
                "tcp",
                &format!("dn{index}.eu.example.org"),
                Some(443),
            ));
            events.push(egress(
                "media",
                "tcp",
                &format!("eu{index}.example.org"),
                Some(443),
            ));
            events.push(egress(
                "media",
                "tcp",
                &format!("ia{index}.us.example.org"),
                Some(8080),
            ));
        }
        events.push(egress("media", "tcp", "example.org", Some(443)));
        let events: Vec<&str> = events.iter().map(String::as_str).collect();
        assert_eq!(
            lines(&events).render(),
            "\
media (22 denied or would-be-denied connections)
  portcullis.egress.example-org-subdomains=host:**.example.org,tcp:80,443,8080
    (15 names, such as dn0.ca.example.org)
  portcullis.egress.example-org=host:example.org,tcp:443
"
        );
    }

    #[test]
    fn folds_public_addresses_with_ports_of_their_own() {
        let mut events = Vec::new();
        // Peers of a peer-to-peer protocol, each on a port of its own, and some on the
        // usual port.
        for index in 1..=12 {
            events.push(egress(
                "peers",
                "udp",
                &format!("45.1.2.{index}"),
                Some(20_000 + index),
            ));
        }
        for index in 1..=10 {
            events.push(egress(
                "peers",
                "udp",
                &format!("46.1.2.{index}"),
                Some(6881),
            ));
        }
        let events: Vec<&str> = events.iter().map(String::as_str).collect();
        assert_eq!(
            lines(&events).render(),
            "\
peers (22 denied or would-be-denied connections)
  portcullis.egress.public=ip:public,udp:6881-20012
    (22 public addresses, such as 46.1.2.1; or list them as ip: labels)
"
        );
    }

    #[test]
    fn keeps_ports_with_their_protocol() {
        let services: Services = [
            ("udp".into(), Some(5351)),
            ("tcp".into(), Some(3994)),
            ("udp".into(), Some(22000)),
            ("tcp".into(), Some(22000)),
            ("icmp".into(), None),
            ("sctp".into(), None),
        ]
        .into();
        let mut out = String::new();
        write_services(&mut out, &services);
        assert_eq!(out, "sctp:*,tcp:3994,22000,udp:5351,22000,icmp");
    }

    #[test]
    fn warns_about_egress_to_the_docker_host() {
        let to_host = egress("sync", "tcp", "172.18.0.1", Some(22000)).replace(
            r#""detail":null"#,
            r#""detail":"the Docker host, the gateway of backend""#,
        );
        let output = lines(&[&to_host]).render();
        assert!(
            output.contains("  portcullis.egress.172-18-0-1=ip:172.18.0.1,tcp:22000\n    (careful: the Docker host, the gateway of backend;"),
            "{output}"
        );
    }

    #[test]
    fn tells_crafted_sources_from_others() {
        let source = |detail: &str| {
            format!(
                r#"{{"time":"T","event":"connection","verdict":"would_deny","reason":"source","container":"proxy","network":"n","protocol":"arp","source":"172.18.0.5","source_port":null,"destination":"172.18.0.5","destination_port":null,"destination_container":null,"domain":null,"domain_source":null,"query":null,"detail":"{detail}"}}"#
            )
        };
        let report = lines(&[
            &source("sent before its rules were in place"),
            &source("uses the address of other"),
        ]);
        assert_eq!(
            report.render(),
            "\
proxy (2 denied or would-be-denied connections)
  suspicious: uses the address of other
  denied, but not crafted (no label needed): sent before its rules were in place
"
        );
    }

    #[test]
    fn leaves_out_events_before_since() {
        let earlier = EGRESS.replace(r#""time":"T""#, r#""time":"2026-11-05T23:59:59.000Z""#);
        let later = EGRESS.replace(r#""time":"T""#, r#""time":"2026-11-06T10:00:00.000Z""#);
        let start = since("2026-11-06").expect("date");
        let kept: Vec<bool> = [earlier, later]
            .iter()
            .map(|line| {
                let line: Line = serde_json::from_str(line).expect("event");
                line.time.as_str() >= start.as_str()
            })
            .collect();
        assert_eq!(kept, [false, true]);
        assert!(since("12h").is_ok_and(|time| time.ends_with('Z')));
        assert!(since("yesterday").is_err());
    }

    #[test]
    fn reports_nothing_without_denials() {
        assert_eq!(
            Report::default().render(),
            "No denied or would-be-denied traffic found.\n"
        );
    }
}
