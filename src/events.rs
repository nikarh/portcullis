//! Events: what Portcullis decides and observes.
//!
//! Every event goes to the configured sinks:
//! - stdout, one line per event, as text or JSON (`--log-format`);
//! - the event socket (`--events-socket`), as JSON lines, for tools;
//! - the alert hook (`--alert-exec`), for denials and warnings, de-duplicated.
//!
//! Diagnostic logs go to stderr and are not events.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write as _};
use std::net::IpAddr;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::logging::LogFormat;

/// Socket permissions: owner only. The stream exposes container addresses and errors.
const SOCKET_MODE: u32 = 0o600;
/// A client that can't take a line within this time is disconnected, so a stalled reader
/// never delays anything else.
const WRITE_TIMEOUT: Duration = Duration::from_millis(200);
/// An alert command running longer than this is killed.
const ALERT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allowed,
    Denied,
    /// Monitor mode: the policy would have denied this, but it was let through.
    WouldDeny,
}

/// Which part of the policy decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Outbound traffic, decided by `portcullis.egress.*`.
    Egress,
    /// DNS traffic, decided by `portcullis.dns.*`.
    Dns,
    /// Traffic to a container on the same network, decided by `portcullis.icc.*`.
    Icc,
    /// A source address or MAC that doesn't belong to the container sending it.
    Source,
    /// A kind of frame enforced networks don't carry: IPv6, VLAN-tagged, or not IP at all.
    Frame,
    /// More open connections, or new connections per second, than the container's limit.
    Limit,
}

/// Where a connection's domain comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainSource {
    /// The container looked the name up, and Portcullis saw the answer.
    Dns,
    /// The address belongs to a `host:` rule.
    Rule,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub verdict: Verdict,
    pub reason: Reason,
    /// The container that sent the traffic, if known.
    pub container: Option<String>,
    pub network: Option<String>,
    /// `tcp`, `udp`, `icmp` or another IP protocol number; for frames that aren't IPv4,
    /// `arp`, `ipv6` or the ether type. Mostly fixed names, which aren't copied.
    pub protocol: Cow<'static, str>,
    /// The source address the packet claims; none for frames without one.
    pub source: Option<IpAddr>,
    pub source_port: Option<u16>,
    pub destination: Option<IpAddr>,
    pub destination_port: Option<u16>,
    /// The container at the destination, for traffic between containers.
    pub destination_container: Option<String>,
    pub domain: Option<String>,
    pub domain_source: Option<DomainSource>,
    /// The name a denied DNS query asked for.
    pub query: Option<String>,
    /// Extra explanation, e.g. why a source is considered spoofed. Mostly fixed texts,
    /// which aren't copied.
    pub detail: Option<Cow<'static, str>>,
    /// A TCP packet that doesn't start a connection, of a connection the firewall doesn't
    /// track (it lost track, or the packet doesn't fit the connection). Rules are written
    /// for new connections; what they decide about these says little about the policy.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub mid_stream: bool,
    /// For `source`: the packet claims an address or MAC that isn't the sender's, which
    /// takes a raw socket. Not so for the sender's own traffic that the rules judged before
    /// they knew it, nor for its address on another of its networks, which its routing may
    /// send out of this one. Decides quarantine; not reported.
    #[serde(skip)]
    pub forged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dns {
    pub container: Option<String>,
    pub network: Option<String>,
    pub resolver: IpAddr,
    pub name: String,
    pub record_type: String,
    pub response_code: String,
    /// CNAME targets the name resolved through.
    pub aliases: Vec<String>,
    pub answers: Vec<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningKind {
    /// A container label is invalid and was ignored.
    InvalidLabel,
    /// A container's policy file can't be used; the container is denied everything.
    PolicyFile,
    /// A network's configuration prevents enforcing it.
    InvalidNetwork,
    /// Portcullis can't see this container's DNS lookups.
    DnsNotObservable,
    /// The kernel dropped logged packets because they weren't read fast enough.
    EventsLost,
    /// A container raised so many alerts that further ones are held back for a while.
    AlertsSuppressed,
    /// A container on an enforced network is also on a network that isn't enforced.
    UnenforcedNetwork,
    /// A container has `portcullis.*` labels that have no effect.
    UnusedLabels,
    /// A container shares another container's network namespace.
    SharedNetwork,
    /// A restricted container has the Docker socket.
    DockerSocket,
    /// A restricted container is privileged.
    Privileged,
    /// A restricted container has the `NET_ADMIN` capability.
    NetAdmin,
    /// An enforced network has IPv6 enabled.
    Ipv6Network,
    /// A container misbehaved and was cut off from its networks (or would have been).
    Quarantined,
}

impl WarningKind {
    /// Configuration warnings a `portcullis.ack` label can acknowledge, by the name the
    /// label uses.
    pub const ACKNOWLEDGEABLE: [(&'static str, Self); 8] = [
        ("dns-not-observable", Self::DnsNotObservable),
        ("unenforced-network", Self::UnenforcedNetwork),
        ("unused-labels", Self::UnusedLabels),
        ("shared-network", Self::SharedNetwork),
        ("docker-socket", Self::DockerSocket),
        ("privileged", Self::Privileged),
        ("net-admin", Self::NetAdmin),
        ("ipv6-network", Self::Ipv6Network),
    ];

    /// The warning a `portcullis.ack` value names.
    #[must_use]
    pub fn acknowledgeable(name: &str) -> Option<Self> {
        Self::ACKNOWLEDGEABLE
            .iter()
            .find(|(ack, _)| *ack == name)
            .map(|(_, kind)| *kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Warning {
    pub kind: WarningKind,
    pub container: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Enforce,
    Monitor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerAction {
    /// Rules now apply to this container address.
    Managed,
    /// Rules no longer apply to this container address.
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerChange {
    pub action: ContainerAction,
    pub container: String,
    pub network: String,
    pub address: IpAddr,
    pub mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// Rules were applied.
    Applied {
        /// Increases by one with every successful apply.
        generation: u64,
        /// Managed container addresses.
        sources: Vec<IpAddr>,
        /// Hostnames of `host:` rules with no known addresses; their rules allow nothing.
        unresolved_hosts: Vec<String>,
    },
    /// Applying rules failed; the previous rules stay in place.
    ApplyFailed {
        error: String,
    },
    Container(ContainerChange),
    Connection(Connection),
    Dns(Dns),
    Warning(Warning),
}

impl Event {
    /// The de-duplication key of events that raise alerts.
    fn alert_key(&self) -> Option<String> {
        match self {
            Self::Connection(connection) if connection.verdict == Verdict::Denied => {
                let destination = connection
                    .destination_container
                    .clone()
                    .or_else(|| connection.domain.clone())
                    .or_else(|| connection.query.clone())
                    .or_else(|| connection.destination.map(|address| address.to_string()))
                    .unwrap_or_default();
                Some(format!(
                    "connection {} {:?} {} {}/{}",
                    connection.container.as_deref().unwrap_or("?"),
                    connection.reason,
                    destination,
                    connection.protocol,
                    connection.destination_port.unwrap_or_default(),
                ))
            }
            Self::ApplyFailed { error } => Some(format!("apply_failed {error}")),
            Self::Warning(warning) => Some(format!(
                "warning {:?} {} {}",
                warning.kind,
                warning.container.as_deref().unwrap_or("?"),
                warning.message
            )),
            _ => None,
        }
    }
}

/// An event with its time, as written to every sink.
#[derive(Serialize)]
struct Record<'a> {
    time: &'a str,
    #[serde(flatten)]
    event: &'a Event,
}

/// Configuration of the event sinks.
#[derive(Debug, Clone, Default)]
pub struct Sinks {
    /// Write events to stdout in this format.
    pub stdout: Option<LogFormat>,
    pub socket: Option<PathBuf>,
    pub alert_command: Option<String>,
    pub alert_interval: Duration,
}

/// Publishes events to the configured sinks. Cheap to clone; usable from any thread.
#[derive(Clone)]
pub struct EventBus {
    inner: Arc<Inner>,
}

struct Inner {
    stdout: Option<LogFormat>,
    socket: Option<SocketSink>,
    alerts: Option<AlertSink>,
    generation: AtomicU64,
}

impl EventBus {
    pub fn new(sinks: &Sinks) -> io::Result<Self> {
        let socket = sinks.socket.as_deref().map(SocketSink::bind).transpose()?;
        let alerts = sinks
            .alert_command
            .clone()
            .map(|command| AlertSink::start(command, sinks.alert_interval));
        Ok(Self {
            inner: Arc::new(Inner {
                stdout: sinks.stdout,
                socket,
                alerts,
                generation: AtomicU64::new(0),
            }),
        })
    }

    pub fn applied(&self, sources: Vec<IpAddr>, unresolved_hosts: Vec<String>) {
        let generation = self.inner.generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.publish(&Event::Applied {
            generation,
            sources,
            unresolved_hosts,
        });
    }

    pub fn publish(&self, event: &Event) {
        let time = timestamp(SystemTime::now());
        let record = Record { time: &time, event };
        let json = serde_json::to_string(&record).unwrap_or_default();

        match self.inner.stdout {
            Some(LogFormat::Json) => print_line(&json),
            Some(LogFormat::Text) => print_line(&text(&time, event)),
            None => {}
        }
        if let Some(socket) = &self.inner.socket {
            socket.send(&json, matches!(event, Event::Applied { .. }));
        }
        let (Some(alerts), Some(key)) = (&self.inner.alerts, event.alert_key()) else {
            return;
        };
        let container = match event {
            Event::Connection(connection) => Some(connection.container.as_deref().unwrap_or("?")),
            _ => None,
        };
        match alerts.admit(key, container) {
            Admission::Raise => alerts.raise(json),
            Admission::Duplicate | Admission::Suppressed => {}
            Admission::StartSuppressing { container, until } => {
                alerts.raise(json);
                self.publish(&Event::Warning(Warning {
                    kind: WarningKind::AlertsSuppressed,
                    container: Some(container),
                    message: format!(
                        "more than {ALERTS_PER_CONTAINER} alerts within {} s; until {}, its denials are only reported as events",
                        alerts.interval.as_secs(),
                        timestamp(until),
                    ),
                }));
            }
        }
    }
}

fn print_line(line: &str) {
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{line}");
    let _ = stdout.flush();
}

/// An event with its time, as read back from a sink.
#[derive(Debug, Deserialize)]
pub struct Line {
    pub time: String,
    #[serde(flatten)]
    pub event: Event,
}

/// One human-readable line.
pub fn text(time: &str, event: &Event) -> String {
    let mut line = format!("{time} ");
    let _ = match event {
        Event::Applied {
            generation,
            sources,
            unresolved_hosts,
        } => {
            let _ = write!(
                line,
                "applied rules (generation {generation}, {} container addresses)",
                sources.len()
            );
            if unresolved_hosts.is_empty() {
                Ok(())
            } else {
                write!(line, ", unresolved: {}", unresolved_hosts.join(", "))
            }
        }
        Event::ApplyFailed { error } => write!(line, "failed to apply rules: {error}"),
        Event::Container(change) => write!(
            line,
            "{} {} {} on {} ({})",
            match change.action {
                ContainerAction::Managed => "managing",
                ContainerAction::Released => "releasing",
            },
            change.container,
            change.address,
            change.network,
            match change.mode {
                Mode::Enforce => "enforce",
                Mode::Monitor => "monitor",
            }
        ),
        Event::Connection(connection) => write_connection(&mut line, connection),
        Event::Dns(dns) => {
            let _ = write!(
                line,
                "dns {} {} {} via {}: {}",
                dns.container.as_deref().unwrap_or("?"),
                dns.record_type,
                dns.name,
                dns.resolver,
                dns.response_code
            );
            if !dns.aliases.is_empty() {
                let _ = write!(line, " (via {})", dns.aliases.join(", "));
            }
            for answer in &dns.answers {
                let _ = write!(line, " {answer}");
            }
            Ok(())
        }
        Event::Warning(warning) => write!(
            line,
            "warning {}: {}",
            warning.container.as_deref().unwrap_or("-"),
            warning.message
        ),
    };
    line
}

fn write_connection(line: &mut String, connection: &Connection) -> std::fmt::Result {
    let verdict = match connection.verdict {
        Verdict::Allowed => "allowed",
        Verdict::Denied => "DENIED",
        Verdict::WouldDeny => "would deny",
    };
    let reason = match connection.reason {
        Reason::Egress => "egress",
        Reason::Dns => "dns",
        Reason::Icc => "icc",
        Reason::Source => "source",
        Reason::Frame => "frame",
        Reason::Limit => "limit",
    };
    let address =
        |address: Option<IpAddr>| address.map_or_else(|| "-".to_string(), |a| a.to_string());
    let destination = address(connection.destination);
    write!(
        line,
        "{verdict} {reason} {} {}",
        connection.container.as_deref().unwrap_or("?"),
        address(connection.source)
    )?;
    write!(line, " -> ")?;
    if let Some(container) = &connection.destination_container {
        write!(line, "{container} ({destination})")?;
    } else if let Some(domain) = &connection.domain {
        write!(line, "{domain} ({destination})")?;
    } else {
        write!(line, "{destination}")?;
    }
    match connection.destination_port {
        Some(port) => write!(line, " {}/{port}", connection.protocol)?,
        None => write!(line, " {}", connection.protocol)?,
    }
    if let Some(query) = &connection.query {
        write!(line, " query {query}")?;
    }
    if let Some(detail) = &connection.detail {
        write!(line, " ({detail})")?;
    }
    Ok(())
}

/// RFC 3339 UTC timestamp with millisecond precision.
pub fn timestamp(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = since_epoch.as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap_or_default();
    let of_day = seconds % 86_400;
    // Howard Hinnant's days-to-civil algorithm.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60,
        since_epoch.subsec_millis()
    )
}

struct SocketSink {
    path: PathBuf,
    clients: Arc<Mutex<Vec<UnixStream>>>,
    /// The latest `applied` line, sent to clients when they connect.
    last_applied: Arc<Mutex<Option<String>>>,
}

impl SocketSink {
    /// Listen on `path`. A stale socket left at `path` is replaced; any other existing file
    /// is an error.
    fn bind(path: &Path) -> io::Result<Self> {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if !metadata.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            fs::remove_file(path)?;
        }

        // Bind under a temporary name and restrict it before it appears at `path`, so the
        // socket is never reachable with default permissions under its real name.
        let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
        let _ = fs::remove_file(&temporary);
        let listener = UnixListener::bind(&temporary)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(SOCKET_MODE))?;
        fs::rename(&temporary, path)?;

        let clients = Arc::new(Mutex::new(Vec::new()));
        let last_applied = Arc::new(Mutex::new(None));
        let (accept_clients, accept_last) = (Arc::clone(&clients), Arc::clone(&last_applied));
        thread::spawn(move || accept(&listener, &accept_clients, &accept_last));

        Ok(Self {
            path: path.to_path_buf(),
            clients,
            last_applied,
        })
    }

    fn send(&self, json: &str, is_applied: bool) {
        let mut line = String::with_capacity(json.len() + 1);
        line.push_str(json);
        line.push('\n');
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        if is_applied {
            *self
                .last_applied
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(line.clone());
        }
        clients.retain_mut(|client| client.write_all(line.as_bytes()).is_ok());
    }
}

impl Drop for SocketSink {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn accept(
    listener: &UnixListener,
    clients: &Mutex<Vec<UnixStream>>,
    last_applied: &Mutex<Option<String>>,
) {
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                warn!(%error, "failed to accept event stream client");
                // Out of file descriptors, say: don't spin.
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        if stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err() {
            continue;
        }
        debug!("event stream client connected");

        // Hold the client list while sending the current state, so no event can slip in
        // between the state and the client being registered.
        let mut clients = clients.lock().unwrap_or_else(PoisonError::into_inner);
        let snapshot = last_applied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(line) = snapshot
            && stream.write_all(line.as_bytes()).is_err()
        {
            continue;
        }
        clients.push(stream);
    }
}

/// Distinct alerts one container may raise per alert interval. A container probing many
/// destinations would otherwise raise an alert for each, and since alerts run one after
/// another, bury every later alert, of any container, under hours of backlog.
const ALERTS_PER_CONTAINER: usize = 10;
/// Alerts waiting for the command at most; more are dropped.
const ALERT_QUEUE: usize = 256;

/// Runs the alert command for alert-worthy events, at most once per key and interval, and
/// at most [`ALERTS_PER_CONTAINER`] times per container and interval.
struct AlertSink {
    sender: SyncSender<String>,
    interval: Duration,
    state: Mutex<AlertState>,
}

#[derive(Default)]
struct AlertState {
    last_raised: HashMap<String, Instant>,
    /// Per container: when its current interval started, and how many alerts it raised.
    per_container: HashMap<String, (Instant, usize)>,
}

/// What to do with an alert.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    Raise,
    /// Raised within the interval already.
    Duplicate,
    /// The container's last alert before its alerts are held back until `until`.
    StartSuppressing {
        container: String,
        until: SystemTime,
    },
    Suppressed,
}

impl AlertSink {
    fn start(command: String, interval: Duration) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<String>(ALERT_QUEUE);
        thread::spawn(move || {
            for json in receiver {
                run_alert(&command, &json);
            }
        });
        Self {
            sender,
            interval,
            state: Mutex::new(AlertState::default()),
        }
    }

    /// Decide on the alert `key` of `container` (none for alerts about Portcullis itself).
    fn admit(&self, key: String, container: Option<&str>) -> Admission {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let interval = self.interval;
        state
            .last_raised
            .retain(|_, raised| now.duration_since(*raised) < interval);
        state
            .per_container
            .retain(|_, (started, _)| now.duration_since(*started) < interval);
        if state.last_raised.contains_key(&key) {
            return Admission::Duplicate;
        }
        let admission = match container {
            None => Admission::Raise,
            Some(container) => {
                let (started, count) = state
                    .per_container
                    .entry(container.to_string())
                    .or_insert((now, 0));
                *count += 1;
                match (*count).cmp(&ALERTS_PER_CONTAINER) {
                    std::cmp::Ordering::Less => Admission::Raise,
                    std::cmp::Ordering::Equal => Admission::StartSuppressing {
                        container: container.to_string(),
                        until: SystemTime::now() + interval.saturating_sub(now - *started),
                    },
                    std::cmp::Ordering::Greater => return Admission::Suppressed,
                }
            }
        };
        state.last_raised.insert(key, now);
        admission
    }

    fn raise(&self, json: String) {
        if let Err(TrySendError::Full(_)) = self.sender.try_send(json) {
            warn!("too many alerts waiting for the alert command; dropping one");
        }
    }
}

/// Run `command` with `sh -c`, the event as JSON on stdin.
fn run_alert(command: &str, json: &str) {
    let child = Command::new("/bin/sh")
        .args(["-c", command])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) => {
            warn!(%error, "failed to run alert command");
            return;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(json.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    warn!(%status, "alert command failed");
                }
                return;
            }
            Ok(None) if started.elapsed() < ALERT_TIMEOUT => {
                thread::sleep(Duration::from_millis(50));
            }
            _ => {
                warn!("alert command timed out; killing it");
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("portcullis-events-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir");
        dir.join(name)
    }

    fn read_json(reader: &mut BufReader<UnixStream>) -> serde_json::Value {
        let mut line = String::new();
        reader.read_line(&mut line).expect("line");
        serde_json::from_str(&line).expect("json")
    }

    fn denied(port: u16) -> Event {
        Event::Connection(Connection {
            verdict: Verdict::Denied,
            reason: Reason::Egress,
            container: Some("web".to_string()),
            network: Some("backend".to_string()),
            protocol: "tcp".into(),
            source: Some("172.18.0.2".parse().expect("ip")),
            source_port: Some(40000),
            destination: Some("104.18.3.4".parse().expect("ip")),
            destination_port: Some(port),
            destination_container: None,
            domain: Some("api.stripe.com".to_string()),
            domain_source: Some(DomainSource::Dns),
            query: None,
            detail: None,
            mid_stream: false,
            forged: false,
        })
    }

    #[test]
    fn formats_timestamps() {
        let time = UNIX_EPOCH + Duration::from_millis(1_793_389_871_123);
        assert_eq!(timestamp(time), "2026-10-30T19:51:11.123Z");
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            timestamp(UNIX_EPOCH + Duration::from_hours(264_384)),
            "2000-02-29T00:00:00.000Z"
        );
    }

    #[test]
    fn formats_connection_events_as_text() {
        let line = text("T", &denied(443));
        assert_eq!(
            line,
            "T DENIED egress web 172.18.0.2 -> api.stripe.com (104.18.3.4) tcp/443"
        );
    }

    #[test]
    fn serializes_events_with_their_kind() {
        let json = serde_json::to_value(Record {
            time: "T",
            event: &denied(443),
        })
        .expect("json");
        assert_eq!(json["event"], "connection");
        assert_eq!(json["verdict"], "denied");
        assert_eq!(json["reason"], "egress");
        assert_eq!(json["domain_source"], "dns");
        assert_eq!(json["time"], "T");
    }

    #[test]
    fn only_denials_and_problems_raise_alerts() {
        assert!(denied(443).alert_key().is_some());
        let Event::Connection(mut monitored) = denied(443) else {
            unreachable!()
        };
        monitored.verdict = Verdict::WouldDeny;
        assert!(Event::Connection(monitored).alert_key().is_none());
        assert!(
            Event::ApplyFailed { error: "x".into() }
                .alert_key()
                .is_some()
        );
        assert!(
            Event::Applied {
                generation: 1,
                sources: Vec::new(),
                unresolved_hosts: Vec::new()
            }
            .alert_key()
            .is_none()
        );
    }

    #[test]
    fn alerts_are_limited_per_container() {
        let sink = AlertSink::start("true".to_string(), Duration::from_secs(600));
        let admissions: Vec<Admission> = (0..12)
            .map(|port| sink.admit(format!("probe {port}"), Some("attacker")))
            .collect();
        assert!(
            admissions
                .iter()
                .take(ALERTS_PER_CONTAINER - 1)
                .all(|admission| *admission == Admission::Raise)
        );
        assert!(matches!(
            admissions.get(ALERTS_PER_CONTAINER - 1),
            Some(Admission::StartSuppressing { container, .. }) if container == "attacker"
        ));
        assert!(
            admissions
                .iter()
                .skip(ALERTS_PER_CONTAINER)
                .all(|admission| *admission == Admission::Suppressed)
        );
        // Other containers, and Portcullis itself, still raise alerts.
        assert_eq!(sink.admit("probe".into(), Some("other")), Admission::Raise);
        assert_eq!(sink.admit("apply_failed".into(), None), Admission::Raise);
        assert_eq!(
            sink.admit("apply_failed".into(), None),
            Admission::Duplicate
        );
    }

    #[test]
    fn alerts_are_deduplicated() {
        let output = temp_path("alerts.log");
        let _ = fs::remove_file(&output);
        let bus = EventBus::new(&Sinks {
            alert_command: Some(format!("cat >> {}", output.display())),
            alert_interval: Duration::from_secs(600),
            ..Sinks::default()
        })
        .expect("bus");
        bus.publish(&denied(443));
        bus.publish(&denied(443));
        bus.publish(&denied(80));
        // Wait for the worker: it handles alerts in order, so a marker alert run after
        // them proves they're done.
        let marker = temp_path("alerts.done");
        let _ = fs::remove_file(&marker);
        run_alert(&format!("touch {}", marker.display()), "");
        let deadline = Instant::now() + Duration::from_secs(5);
        while fs::read_to_string(&output).map_or(0, |text| text.lines().count()) < 2
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(10));
        }
        let lines = fs::read_to_string(&output).expect("alerts");
        assert_eq!(lines.lines().count(), 2, "{lines}");
        assert!(lines.contains("\"destination_port\":443"));
        assert!(lines.contains("\"destination_port\":80"));
    }

    #[test]
    fn streams_events_and_sends_state_on_connect() {
        let path = temp_path("stream.sock");
        let bus = EventBus::new(&Sinks {
            socket: Some(path.clone()),
            ..Sinks::default()
        })
        .expect("bus");
        let mode = fs::metadata(&path).expect("socket").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        bus.applied(
            vec!["172.18.0.2".parse().expect("ip")],
            vec!["broken.test".to_string()],
        );

        // A client connecting later gets the current state first.
        let mut reader = BufReader::new(UnixStream::connect(&path).expect("connect"));
        let snapshot = read_json(&mut reader);
        assert_eq!(snapshot["event"], "applied");
        assert_eq!(snapshot["generation"], 1);
        assert_eq!(snapshot["sources"][0], "172.18.0.2");
        assert_eq!(snapshot["unresolved_hosts"][0], "broken.test");

        // Wait until the client is registered before publishing more.
        let socket = bus.inner.socket.as_ref().expect("socket");
        while socket.clients.lock().expect("lock").is_empty() {
            thread::yield_now();
        }
        bus.publish(&denied(443));
        bus.applied(Vec::new(), Vec::new());
        assert_eq!(read_json(&mut reader)["event"], "connection");
        assert_eq!(read_json(&mut reader)["generation"], 2);

        drop(bus);
        assert!(!path.exists());
    }

    #[test]
    fn refuses_to_replace_a_regular_file() {
        let path = temp_path("not-a-socket");
        fs::write(&path, "data").expect("write");
        assert!(SocketSink::bind(&path).is_err());
        assert!(path.exists());
    }
}
