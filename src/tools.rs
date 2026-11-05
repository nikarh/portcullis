//! Command-line tools working on events: `portcullis watch` and `portcullis audit`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write as _};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;

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
pub fn audit(input: Option<&Path>) -> io::Result<()> {
    let reader: Box<dyn BufRead> = match input {
        Some(path) if path != Path::new("-") => Box::new(BufReader::new(File::open(path)?)),
        _ => Box::new(io::stdin().lock()),
    };
    let mut report = Report::default();
    for line in reader.lines() {
        if let Ok(line) = serde_json::from_str::<Line>(&line?) {
            report.add(&line.event);
        }
    }
    io::stdout().lock().write_all(report.render().as_bytes())
}

/// What was sent to a destination: protocol and destination port (none for protocols
/// without ports).
type Services = BTreeSet<(String, Option<u16>)>;

/// Examples of a kind of finding kept per container; more are only counted.
const EXAMPLES: usize = 5;

/// Hostnames under one parent domain, with the same services, folded into one pattern.
const FOLD_HOSTS: usize = 3;

/// Public addresses with the same services folded into `ip:public`.
const FOLD_PUBLIC: usize = 10;

#[derive(Debug, Default)]
struct Findings {
    /// Denied or would-be-denied connections.
    count: usize,
    /// `host:<domain>` or `ip:<address>` to services.
    egress: BTreeMap<String, Services>,
    /// Destination container to services.
    icc: BTreeMap<String, Services>,
    /// ICC destinations that aren't known containers.
    icc_unknown: BTreeSet<IpAddr>,
    /// Resolvers queried.
    dns: BTreeSet<IpAddr>,
    /// Sources that aren't the container's own.
    spoofed: BTreeSet<String>,
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
                findings.egress.entry(target).or_default().insert(service);
            }
            Reason::Icc => match &connection.destination_container {
                Some(destination) => {
                    findings
                        .icc
                        .entry(destination.clone())
                        .or_default()
                        .insert(service);
                }
                None => {
                    findings.icc_unknown.extend(connection.destination);
                }
            },
            Reason::Dns => {
                findings.dns.extend(connection.destination);
            }
            Reason::Source | Reason::Frame | Reason::Limit => {
                let detail = connection.detail.clone().unwrap_or_else(|| {
                    format!("sent {} it isn't allowed to send", connection.protocol)
                });
                findings.spoofed.insert(detail);
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
            for (target, services, note) in fold_egress(&findings.egress) {
                let name = slug(
                    target
                        .split_once(':')
                        .map_or(target.as_str(), |(_, value)| value),
                );
                let _ = writeln!(
                    out,
                    "  portcullis.egress.{name}={target},{}",
                    service_list(&services)
                );
                if let Some(note) = note {
                    let _ = writeln!(out, "    ({note})");
                }
                if services.iter().any(|(protocol, _)| protocol == "igmp") {
                    out.push_str("    (IGMP: the container joins multicast groups; only needed when the host relays multicast, such as with igmpproxy)\n");
                }
            }
            for (destination, services) in &findings.icc {
                let _ = writeln!(
                    out,
                    "  portcullis.icc.allow.{}=container:{destination},{}",
                    slug(destination),
                    service_list(services)
                );
            }
            if !findings.icc.is_empty() {
                out.push_str("    (with portcullis.icc.mode=allow-listed)\n");
            }
            for destination in &findings.icc_unknown {
                let _ = writeln!(
                    out,
                    "  traffic to {destination} on the same network, which isn't a known container"
                );
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

/// Egress targets with their services, and a note on what was folded into them: hostnames
/// under one domain with the same services become a pattern, and many public addresses
/// with the same services `ip:public`.
fn fold_egress(egress: &BTreeMap<String, Services>) -> Vec<(String, Services, Option<String>)> {
    let mut by_services: BTreeMap<&Services, (Vec<&str>, Vec<IpAddr>)> = BTreeMap::new();
    let mut folded = Vec::new();
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
        folded.push((target.clone(), services.clone(), None));
    }
    for (services, (mut hosts, public)) in by_services {
        while let Some((parent, members)) = widest_parent(&hosts) {
            let one_level = members.iter().all(|host| {
                host.strip_suffix(parent.as_str())
                    .and_then(|below| below.strip_suffix('.'))
                    .is_some_and(|below| !below.contains('.'))
            });
            let pattern = format!("{}.{parent}", if one_level { "*" } else { "**" });
            let note = format!(
                "{} names, such as {}",
                members.len(),
                members.first().copied().unwrap_or_default()
            );
            hosts.retain(|host| !members.contains(host));
            folded.push((format!("host:{pattern}"), services.clone(), Some(note)));
        }
        folded.extend(
            hosts
                .into_iter()
                .map(|host| (format!("host:{host}"), services.clone(), None)),
        );
        if public.len() >= FOLD_PUBLIC {
            let note = format!(
                "{} public addresses, such as {}; or list them as ip: labels",
                public.len(),
                public.first().map(ToString::to_string).unwrap_or_default()
            );
            folded.push(("ip:public".to_string(), services.clone(), Some(note)));
        } else {
            folded.extend(
                public
                    .into_iter()
                    .map(|address| (format!("ip:{address}"), services.clone(), None)),
            );
        }
    }
    folded.sort_by(|a, b| a.0.cmp(&b.0));
    folded
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

/// Services as in labels: `tcp:80,443,8000-8002,udp:53,icmp`.
fn service_list(services: &Services) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut ports: BTreeMap<&str, Vec<u16>> = BTreeMap::new();
    for (protocol, port) in services {
        match (Protocol::from_name(protocol), port) {
            (Some(known), Some(port)) if known.has_ports() => {
                ports.entry(protocol.as_str()).or_default().push(*port);
            }
            (Some(known), None) if known.has_ports() => parts.push(format!("{protocol}:*")),
            _ => parts.push(protocol.clone()),
        }
    }
    for (protocol, ports) in ports {
        let mut ranges: Vec<(u16, u16)> = Vec::new();
        for port in ports {
            match ranges.last_mut() {
                Some((_, last)) if last.checked_add(1) == Some(port) => *last = port,
                _ => ranges.push((port, port)),
            }
        }
        for (index, (first, last)) in ranges.into_iter().enumerate() {
            let range = if first == last {
                first.to_string()
            } else {
                format!("{first}-{last}")
            };
            parts.push(if index == 0 {
                format!("{protocol}:{range}")
            } else {
                range
            });
        }
    }
    parts.sort_by_key(|part| !part.contains(':'));
    parts.dedup();
    parts.join(",")
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
    fn reports_nothing_without_denials() {
        assert_eq!(
            Report::default().render(),
            "No denied or would-be-denied traffic found.\n"
        );
    }
}
