//! Command-line tools working on events: `portcullis watch` and `portcullis audit`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
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
            report.add(&line.event);
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
type Services = BTreeSet<(String, Option<u16>)>;

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
    docker_host: BTreeMap<String, String>,
    /// `container:<name>` or `multicast:<group>` to services.
    icc: BTreeMap<String, Services>,
    /// ICC destinations that aren't known containers.
    icc_unknown: BTreeSet<IpAddr>,
    /// Resolvers queried.
    dns: BTreeSet<IpAddr>,
    /// Sources that aren't the container's own.
    spoofed: BTreeSet<String>,
    /// Source denials that weren't forged, see `connection_log::unforged`.
    unforged: BTreeSet<String>,
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
    fn add(&mut self, event: &Event) {
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
                        | WarningKind::InvalidNetwork
                ) =>
            {
                self.warnings.insert((
                    warning.container.clone().unwrap_or_else(|| "-".to_string()),
                    warning.message.clone(),
                ));
            }
            _ => {}
        }
    }

    fn add_connection(&mut self, connection: &Connection) {
        let container = connection
            .container
            .clone()
            .unwrap_or_else(|| match connection.source {
                Some(source) => format!("unknown container at {source}"),
                None => "unknown container".to_string(),
            });
        let findings = self.containers.entry(container).or_default();
        findings.count += 1;
        let routed = matches!(
            connection.reason,
            Reason::Egress | Reason::Icc | Reason::Dns
        );
        // Replies, and the rest of connections the firewall lost track of: rules don't
        // need to allow them, they allow the connections.
        if routed && connection.mid_stream {
            let (examples, count) = &mut findings.mid_stream;
            *count += 1;
            if examples.len() < EXAMPLES {
                examples.insert(format!(
                    "{} {} to {}",
                    connection.protocol,
                    endpoint(connection.source, connection.source_port, None),
                    endpoint(
                        connection.destination,
                        connection.destination_port,
                        connection.destination_container.as_deref()
                    )
                ));
            }
            return;
        }
        let protocol = connection.protocol.as_str();
        let service = match Protocol::from_name(protocol) {
            Some(known) if known.has_ports() => (protocol.to_string(), connection.destination_port),
            None if routed => {
                findings.unsupported.insert(format!(
                    "IP protocol {protocol} to {}",
                    endpoint(
                        connection.destination,
                        None,
                        connection.destination_container.as_deref()
                    )
                ));
                return;
            }
            // Protocols without ports, and frames (ARP, IPv6).
            _ => (protocol.to_string(), None),
        };
        match connection.reason {
            Reason::Egress => {
                let target = match (&connection.domain, connection.destination) {
                    (Some(domain), _) => format!("host:{domain}"),
                    (None, Some(destination)) => format!("ip:{destination}"),
                    (None, None) => return,
                };
                if let Some(detail) = connection
                    .detail
                    .as_ref()
                    .filter(|detail| detail.starts_with(DOCKER_HOST))
                {
                    findings.docker_host.insert(target.clone(), detail.clone());
                }
                findings.egress.entry(target).or_default().insert(service);
            }
            Reason::Icc => {
                let target = match (&connection.destination_container, connection.destination) {
                    (Some(container), _) => format!("container:{container}"),
                    (None, Some(group)) if group.is_multicast() => format!("multicast:{group}"),
                    (None, destination) => {
                        findings.icc_unknown.extend(destination);
                        return;
                    }
                };
                findings.icc.entry(target).or_default().insert(service);
            }
            Reason::Dns => {
                findings.dns.extend(connection.destination);
            }
            Reason::Source | Reason::Frame | Reason::Limit => {
                let detail = connection.detail.clone().unwrap_or_else(|| {
                    format!("sent {} it isn't allowed to send", connection.protocol)
                });
                if connection.reason == Reason::Source && unforged(&detail) {
                    findings.unforged.insert(detail);
                } else {
                    findings.spoofed.insert(detail);
                }
            }
        }
    }

    fn render(&self) -> String {
        let mut out = String::new();
        if self.containers.is_empty() && self.warnings.is_empty() {
            out.push_str("No denied or would-be-denied traffic found.\n");
            return out;
        }
        for (container, findings) in &self.containers {
            let _ = writeln!(
                out,
                "{container} ({} denied or would-be-denied connections)",
                findings.count
            );
            let suggestions = fold_egress(&findings.egress);
            let names = label_names(&suggestions);
            for (suggestion, name) in suggestions.iter().zip(names) {
                let _ = writeln!(
                    out,
                    "  portcullis.egress.{name}={},{}",
                    suggestion.target,
                    service_list(&suggestion.services)
                );
                if let Some(note) = suggestion.note() {
                    let _ = writeln!(out, "    ({note})");
                }
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
                let name = target
                    .split_once(':')
                    .map_or(target.as_str(), |(_, name)| name);
                let _ = writeln!(
                    out,
                    "  portcullis.icc.allow.{}={target},{}",
                    slug(name),
                    service_list(services)
                );
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
                let _ = writeln!(
                    out,
                    "  portcullis.dns.{}=ip:{resolver}",
                    slug(&resolver.to_string())
                );
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
fn endpoint(address: Option<IpAddr>, port: Option<u16>, container: Option<&str>) -> String {
    let host = container.map_or_else(
        || address.map_or_else(|| "?".to_string(), |address| address.to_string()),
        ToString::to_string,
    );
    match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

/// A suggested egress label: its target, services, and what was folded into it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Suggestion {
    target: String,
    services: Services,
    /// Hostnames, or public addresses, folded into a pattern or `ip:public`.
    folded: usize,
    example: Option<String>,
}

impl Suggestion {
    fn new(target: String, services: Services) -> Self {
        Self {
            target,
            services,
            folded: 0,
            example: None,
        }
    }

    /// Take `other` in: its services, and what it stands for.
    fn absorb(&mut self, other: Self) {
        self.services.extend(other.services);
        self.folded += other.folded.max(1);
        if self.example.is_none() {
            self.example = other
                .example
                .or_else(|| Some(target_value(&other.target).to_string()));
        }
    }

    fn note(&self) -> Option<String> {
        let example = self.example.as_deref()?;
        Some(if self.target == "ip:public" {
            format!(
                "{} public addresses, such as {example}; or list them as ip: labels",
                self.folded
            )
        } else {
            format!("{} names, such as {example}", self.folded)
        })
    }
}

/// What a target names: `api.test` of `host:api.test`.
fn target_value(target: &str) -> &str {
    target.split_once(':').map_or(target, |(_, value)| value)
}

/// Egress targets with their services, folded: hostnames under one domain with the same
/// services become a pattern, which also takes in names it covers; many public addresses
/// `ip:public`. One label per target.
fn fold_egress(egress: &BTreeMap<String, Services>) -> Vec<Suggestion> {
    let mut by_services: BTreeMap<&Services, (Vec<&str>, Vec<IpAddr>)> = BTreeMap::new();
    let mut suggestions = Vec::new();
    for (target, services) in egress {
        let (hosts, public) = by_services.entry(services).or_default();
        if let Some(host) = target.strip_prefix("host:") {
            hosts.push(host);
            continue;
        }
        if let Some(address) = target
            .strip_prefix("ip:")
            .and_then(|address| address.parse::<IpAddr>().ok())
            .filter(|address| is_public(*address))
        {
            public.push(address);
            continue;
        }
        suggestions.push(Suggestion::new(target.clone(), services.clone()));
    }
    // Public addresses that weren't folded with others of the same services.
    let mut lone_public = Vec::new();
    for (services, (mut hosts, public)) in by_services {
        while let Some((parent, members)) = widest_parent(&hosts) {
            let one_level = members.iter().all(|host| {
                host.strip_suffix(parent.as_str())
                    .and_then(|below| below.strip_suffix('.'))
                    .is_some_and(|below| !below.contains('.'))
            });
            let pattern = format!("{}.{parent}", if one_level { "*" } else { "**" });
            hosts.retain(|host| !members.contains(host));
            suggestions.push(Suggestion {
                target: format!("host:{pattern}"),
                services: services.clone(),
                folded: members.len(),
                example: members.first().map(ToString::to_string),
            });
        }
        suggestions.extend(
            hosts
                .into_iter()
                .map(|host| Suggestion::new(format!("host:{host}"), services.clone())),
        );
        if public.len() >= FOLD_PUBLIC {
            suggestions.push(Suggestion {
                target: "ip:public".to_string(),
                services: services.clone(),
                folded: public.len(),
                example: public.first().map(ToString::to_string),
            });
        } else {
            lone_public.extend(public.into_iter().map(|address| (address, services)));
        }
    }
    // Many public addresses each with ports of their own, such as peers of a peer-to-peer
    // protocol: their services together.
    if lone_public.len() >= FOLD_PUBLIC {
        let mut folded = Suggestion::new("ip:public".to_string(), Services::new());
        for (address, services) in lone_public {
            folded.absorb(Suggestion::new(format!("ip:{address}"), services.clone()));
        }
        suggestions.push(folded);
    } else {
        suggestions.extend(
            lone_public.into_iter().map(|(address, services)| {
                Suggestion::new(format!("ip:{address}"), services.clone())
            }),
        );
    }
    merge(suggestions)
}

/// One suggestion per target, and none for a name or pattern a pattern covers: labels with
/// the same target, or a name a pattern already allows, are one rule.
fn merge(suggestions: Vec<Suggestion>) -> Vec<Suggestion> {
    let mut merged: BTreeMap<String, Suggestion> = BTreeMap::new();
    for suggestion in suggestions {
        match merged.get_mut(&suggestion.target) {
            Some(existing) => {
                existing.services.extend(suggestion.services);
                existing.folded += suggestion.folded;
                if existing.example.is_none() {
                    existing.example = suggestion.example;
                }
            }
            None => {
                merged.insert(suggestion.target.clone(), suggestion);
            }
        }
    }
    let patterns: Vec<String> = merged
        .keys()
        .filter(|target| target.starts_with("host:*"))
        .cloned()
        .collect();
    // The widest patterns first, so that what a narrower one took in ends up in the widest.
    let mut patterns = patterns;
    patterns.sort_by_key(|pattern| pattern.matches('.').count());
    for pattern in patterns.iter().rev() {
        let covered: Vec<String> = merged
            .keys()
            .filter(|target| *target != pattern && covers(target_value(pattern), target))
            .cloned()
            .collect();
        for target in covered {
            if let Some(taken) = merged.remove(&target)
                && let Some(into) = merged.get_mut(pattern)
            {
                into.absorb(taken);
            }
        }
    }
    merged.into_values().collect()
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
    let below = |name: &str| {
        name.strip_suffix(parent)
            .and_then(|below| below.strip_suffix('.'))
            .map(ToString::to_string)
    };
    match name.split_once('.') {
        // A pattern: as wide as this one at most.
        Some(("**", inner)) => deep && (inner == parent || below(inner).is_some()),
        Some(("*", inner)) => inner == parent || (deep && below(inner).is_some()),
        _ => below(name).is_some_and(|below| deep || !below.contains('.')),
    }
}

/// A distinct label key for each suggestion, from what it names. A pattern that would share
/// its key with a name gets `-subdomains`.
fn label_names(suggestions: &[Suggestion]) -> Vec<String> {
    let names: Vec<String> = suggestions
        .iter()
        .map(|suggestion| slug(target_value(&suggestion.target)))
        .collect();
    let mut taken = BTreeSet::new();
    let mut unique = Vec::with_capacity(names.len());
    for (suggestion, name) in suggestions.iter().zip(&names) {
        let shared = names.iter().filter(|other| *other == name).count() > 1;
        let mut candidate = if shared && target_value(&suggestion.target).starts_with('*') {
            format!("{name}-subdomains")
        } else {
            name.clone()
        };
        let mut counter = 2;
        while taken.contains(&candidate) {
            candidate = format!("{name}-{counter}");
            counter += 1;
        }
        taken.insert(candidate.clone());
        unique.push(candidate);
    }
    unique
}

/// The parent domain the most `hosts` are below, if at least [`FOLD_HOSTS`] are.
fn widest_parent<'a>(hosts: &[&'a str]) -> Option<(String, Vec<&'a str>)> {
    let mut parents: BTreeMap<String, Vec<&'a str>> = BTreeMap::new();
    for host in hosts {
        let labels: Vec<&str> = host.split('.').collect();
        // Parents of two labels and more, but not public suffixes like co.uk.
        for start in 1..labels.len().saturating_sub(1) {
            let parent = labels.get(start..).unwrap_or_default();
            if is_public_suffix(parent) {
                continue;
            }
            parents.entry(parent.join(".")).or_default().push(host);
        }
    }
    parents
        .into_iter()
        .filter(|(_, members)| members.len() >= FOLD_HOSTS)
        // The most names; between as many, the most specific domain.
        .max_by_key(|(parent, members)| (members.len(), parent.matches('.').count()))
}

/// Second-level domains under a country's domain that anyone can register under, like
/// `co.uk`.
fn is_public_suffix(labels: &[&str]) -> bool {
    matches!(
        labels,
        [second, country] if country.len() == 2
            && matches!(*second, "co" | "com" | "net" | "org" | "gov" | "edu" | "ac" | "or" | "ne")
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
fn service_list(services: &Services) -> String {
    let mut ports: BTreeMap<&str, Vec<u16>> = BTreeMap::new();
    let mut any_port: BTreeSet<&str> = BTreeSet::new();
    let mut without_ports: BTreeSet<&str> = BTreeSet::new();
    for (protocol, port) in services {
        match (Protocol::from_name(protocol), port) {
            (Some(known), Some(port)) if known.has_ports() => {
                ports.entry(protocol.as_str()).or_default().push(*port);
            }
            (Some(known), None) if known.has_ports() => {
                any_port.insert(protocol.as_str());
            }
            _ => {
                without_ports.insert(protocol.as_str());
            }
        }
    }
    let mut out = String::new();
    let separate = |out: &mut String| {
        if !out.is_empty() {
            out.push(',');
        }
    };
    for protocol in &any_port {
        separate(&mut out);
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
        separate(&mut out);
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
        separate(&mut out);
        out.push_str(protocol);
    }
    out
}

/// A label key segment: lower case letters, digits and dashes.
fn slug(value: &str) -> String {
    let slug: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    slug.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(events: &[&str]) -> Report {
        let mut report = Report::default();
        for event in events {
            let line: Line = serde_json::from_str(event).expect("event");
            report.add(&line.event);
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
            &egress("jellyfin", "igmp", "224.0.0.22", None),
            &egress("jellyfin", "icmp", "1.1.1.1", None),
            &egress("jellyfin", "41", "192.0.2.1", None),
        ]);
        assert_eq!(
            report.render(),
            "\
jellyfin (3 denied or would-be-denied connections)
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
        let reply = r#"{"time":"T","event":"connection","verdict":"would_deny","reason":"icc","container":"outline-redis","network":"n","protocol":"tcp","source":"172.20.0.18","source_port":6379,"destination":"172.20.0.19","destination_port":42076,"destination_container":"outline","domain":null,"domain_source":null,"query":null,"detail":null,"mid_stream":true}"#;
        let report = lines(&[reply]);
        assert_eq!(
            report.render(),
            "\
outline-redis (1 denied or would-be-denied connections)
  1 packets of connections the firewall didn't track (replies, or connections it lost track of; no label needed), such as:
    tcp 172.20.0.18:6379 to outline:42076
"
        );
    }

    #[test]
    fn folds_hostnames_into_patterns() {
        let mut events = Vec::new();
        for host in [
            "ia800.us.archive.org",
            "ia601.us.archive.org",
            "dn7.ca.archive.org",
        ] {
            events.push(egress("beets", "tcp", host, Some(443)));
        }
        for host in ["i.redd.it", "v.redd.it", "preview.redd.it"] {
            events.push(egress("redlib", "tcp", host, Some(443)));
        }
        // Two names aren't enough, nor names with other ports, nor a public suffix.
        for host in ["a.example.com", "b.example.com"] {
            events.push(egress("beets", "tcp", host, Some(443)));
        }
        events.push(egress("beets", "tcp", "c.example.com", Some(80)));
        for host in ["a.co.uk", "b.co.uk", "c.co.uk"] {
            events.push(egress("other", "tcp", host, Some(443)));
        }
        let events: Vec<&str> = events.iter().map(String::as_str).collect();
        assert_eq!(
            lines(&events).render(),
            "\
beets (6 denied or would-be-denied connections)
  portcullis.egress.archive-org=host:**.archive.org,tcp:443
    (3 names, such as dn7.ca.archive.org)
  portcullis.egress.a-example-com=host:a.example.com,tcp:443
  portcullis.egress.b-example-com=host:b.example.com,tcp:443
  portcullis.egress.c-example-com=host:c.example.com,tcp:80
other (3 denied or would-be-denied connections)
  portcullis.egress.a-co-uk=host:a.co.uk,tcp:443
  portcullis.egress.b-co-uk=host:b.co.uk,tcp:443
  portcullis.egress.c-co-uk=host:c.co.uk,tcp:443
redlib (3 denied or would-be-denied connections)
  portcullis.egress.redd-it=host:*.redd.it,tcp:443
    (3 names, such as i.redd.it)
"
        );
    }

    #[test]
    fn folds_public_addresses_and_port_ranges() {
        let mut events = Vec::new();
        for index in 1..=12 {
            for port in [22000, 22001, 22002, 3478] {
                events.push(egress(
                    "syncthing",
                    "udp",
                    &format!("45.1.2.{index}"),
                    Some(port),
                ));
            }
        }
        // Not public: listed on its own.
        events.push(egress("syncthing", "tcp", "192.168.1.5", Some(22000)));
        let events: Vec<&str> = events.iter().map(String::as_str).collect();
        assert_eq!(
            lines(&events).render(),
            "\
syncthing (49 denied or would-be-denied connections)
  portcullis.egress.192-168-1-5=ip:192.168.1.5,tcp:22000
  portcullis.egress.public=ip:public,udp:3478,22000-22002
    (12 public addresses, such as 45.1.2.1; or list them as ip: labels)
"
        );
    }

    #[test]
    fn suggests_one_label_per_target_with_distinct_names() {
        let mut events = Vec::new();
        // Names on two levels under archive.org on 80 and 443, others on 443 alone, a
        // pattern of its own on 8080 below them, and archive.org itself.
        for index in 0..3 {
            for port in [80, 443] {
                events.push(egress(
                    "beets",
                    "tcp",
                    &format!("dn{index}.ca.archive.org"),
                    Some(port),
                ));
                events.push(egress(
                    "beets",
                    "tcp",
                    &format!("ia{index}.archive.org"),
                    Some(port),
                ));
            }
            events.push(egress(
                "beets",
                "tcp",
                &format!("dn{index}.eu.archive.org"),
                Some(443),
            ));
            events.push(egress(
                "beets",
                "tcp",
                &format!("eu{index}.archive.org"),
                Some(443),
            ));
            events.push(egress(
                "beets",
                "tcp",
                &format!("ia{index}.us.archive.org"),
                Some(8080),
            ));
        }
        events.push(egress("beets", "tcp", "archive.org", Some(443)));
        let events: Vec<&str> = events.iter().map(String::as_str).collect();
        assert_eq!(
            lines(&events).render(),
            "\
beets (22 denied or would-be-denied connections)
  portcullis.egress.archive-org-subdomains=host:**.archive.org,tcp:80,443,8080
    (15 names, such as dn0.ca.archive.org)
  portcullis.egress.archive-org=host:archive.org,tcp:443
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
                "torrent",
                "udp",
                &format!("45.1.2.{index}"),
                Some(20_000 + index),
            ));
        }
        for index in 1..=10 {
            events.push(egress(
                "torrent",
                "udp",
                &format!("46.1.2.{index}"),
                Some(6881),
            ));
        }
        let events: Vec<&str> = events.iter().map(String::as_str).collect();
        assert_eq!(
            lines(&events).render(),
            "\
torrent (22 denied or would-be-denied connections)
  portcullis.egress.public=ip:public,udp:6881-20012
    (22 public addresses, such as 46.1.2.1; or list them as ip: labels)
"
        );
    }

    #[test]
    fn keeps_ports_with_their_protocol() {
        let services: Services = [
            ("udp".to_string(), Some(5351)),
            ("tcp".to_string(), Some(3994)),
            ("udp".to_string(), Some(22000)),
            ("tcp".to_string(), Some(22000)),
            ("icmp".to_string(), None),
            ("sctp".to_string(), None),
        ]
        .into();
        assert_eq!(
            service_list(&services),
            "sctp:*,tcp:3994,22000,udp:5351,22000,icmp"
        );
    }

    #[test]
    fn warns_about_egress_to_the_docker_host() {
        let to_host = egress("syncthing", "tcp", "172.20.0.129", Some(22000)).replace(
            r#""detail":null"#,
            r#""detail":"the Docker host, the gateway of files_net""#,
        );
        let output = lines(&[&to_host]).render();
        assert!(
            output.contains("  portcullis.egress.172-20-0-129=ip:172.20.0.129,tcp:22000\n    (careful: the Docker host, the gateway of files_net;"),
            "{output}"
        );
    }

    #[test]
    fn tells_crafted_sources_from_others() {
        let source = |detail: &str| {
            format!(
                r#"{{"time":"T","event":"connection","verdict":"would_deny","reason":"source","container":"traefik","network":"n","protocol":"arp","source":"172.20.0.101","source_port":null,"destination":"172.20.0.101","destination_port":null,"destination_container":null,"domain":null,"domain_source":null,"query":null,"detail":"{detail}"}}"#
            )
        };
        let report = lines(&[
            &source("sent before its rules were in place"),
            &source("uses the address of switcheroo"),
        ]);
        assert_eq!(
            report.render(),
            "\
traefik (2 denied or would-be-denied connections)
  suspicious: uses the address of switcheroo
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
