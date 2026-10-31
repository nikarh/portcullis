//! Command-line tools working on events: `portcullis watch` and `portcullis audit`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write as _};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::events::{Connection, Event, Line, Reason, Verdict, WarningKind, text};

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

/// Ports per destination, as `protocol:port`.
type Ports = BTreeSet<(String, u16)>;

#[derive(Debug, Default)]
struct Findings {
    /// Denied or would-be-denied connections.
    count: usize,
    /// `host:<domain>` or `ip:<address>` to ports.
    egress: BTreeMap<String, Ports>,
    /// Destination container to ports.
    icc: BTreeMap<String, Ports>,
    /// ICC destinations that aren't known containers.
    icc_unknown: BTreeSet<IpAddr>,
    /// Resolvers queried.
    dns: BTreeSet<IpAddr>,
    /// Sources that aren't the container's own.
    spoofed: BTreeSet<String>,
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
            .unwrap_or_else(|| format!("unknown container at {}", connection.source));
        let findings = self.containers.entry(container).or_default();
        findings.count += 1;
        let port = || {
            connection
                .destination_port
                .map(|port| (connection.protocol.clone(), port))
        };
        match connection.reason {
            Reason::Egress => {
                let target = connection.domain.as_ref().map_or_else(
                    || format!("ip:{}", connection.destination),
                    |domain| format!("host:{domain}"),
                );
                findings.egress.entry(target).or_default().extend(port());
            }
            Reason::Icc => match &connection.destination_container {
                Some(destination) => findings
                    .icc
                    .entry(destination.clone())
                    .or_default()
                    .extend(port()),
                None => {
                    findings.icc_unknown.insert(connection.destination);
                }
            },
            Reason::Dns => {
                findings.dns.insert(connection.destination);
            }
            Reason::Source => {
                findings.spoofed.insert(
                    connection
                        .detail
                        .clone()
                        .unwrap_or_else(|| format!("sent from {}", connection.source)),
                );
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
            for (target, ports) in &findings.egress {
                let name = slug(
                    target
                        .split_once(':')
                        .map_or(target.as_str(), |(_, value)| value),
                );
                let _ = writeln!(
                    out,
                    "  portcullis.egress.{name}={target}{}",
                    port_list(ports)
                );
            }
            for (destination, ports) in &findings.icc {
                let _ = writeln!(
                    out,
                    "  portcullis.icc.allow.{}=container:{destination}{}",
                    slug(destination),
                    port_list(ports)
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

fn port_list(ports: &Ports) -> String {
    ports
        .iter()
        .fold(String::new(), |mut list, (protocol, port)| {
            let _ = write!(list, ",{protocol}:{port}");
            list
        })
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
  portcullis.egress.api-stripe-com=host:api.stripe.com,tcp:80,tcp:443
  portcullis.egress.104-18-3-4=ip:104.18.3.4,tcp:443
  portcullis.icc.allow.db=container:db,tcp:5432
    (with portcullis.icc.mode=allow-listed)
  portcullis.dns.9-9-9-9=ip:9.9.9.9
Warnings
  web: no DNS
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
