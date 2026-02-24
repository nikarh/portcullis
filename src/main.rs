mod dns;
mod firewall;
mod labels;
mod logging;
mod model;
mod monitor;

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io::{BufRead, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pico_args::Arguments;
use thiserror::Error;
use tracing::{debug, error, info, trace};

use crate::dns::{DnsProxyCache, SystemUpstreamResolver};
use crate::firewall::{CommandIptablesRunner, FirewallError, IptablesFirewall, NftablesFirewall};
use crate::logging::{LogLevel, LoggingError};
use crate::monitor::{
    DockerEvent, DockerEventAction, DockerEventKind, DockerFirewallBackend, DockerMonitor,
    MonitorError, RuntimeChangeTracker, RuntimeState, SocketDockerApi,
};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirewallBackend {
    Auto,
    Nftables,
    Iptables,
}

impl FromStr for FirewallBackend {
    type Err = MainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "auto" => Ok(Self::Auto),
            "nftables" => Ok(Self::Nftables),
            "iptables" => Ok(Self::Iptables),
            _ => Err(MainError::InvalidFirewallBackend(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    docker_socket: String,
    firewall_backend: FirewallBackend,
    log_level: LogLevel,
    fail_closed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            docker_socket: "/var/run/docker.sock".to_string(),
            firewall_backend: FirewallBackend::Auto,
            log_level: LogLevel::Info,
            fail_closed: false,
        }
    }
}

#[derive(Debug, Error)]
enum MainError {
    #[error("argument parsing failed: {0}")]
    Args(#[from] pico_args::Error),
    #[error("invalid firewall backend: {0}")]
    InvalidFirewallBackend(String),
    #[error("unexpected positional arguments: {0:?}")]
    UnexpectedArguments(Vec<std::ffi::OsString>),
    #[error("failed to initialize logging: {0}")]
    Logging(#[from] LoggingError),
    #[error("monitoring failed: {0}")]
    Monitor(#[from] MonitorError),
    #[error("firewall apply failed: {0}")]
    Firewall(#[from] FirewallError),
    #[error("failed to install signal handler: {0}")]
    SignalHandler(String),
    #[error("service state error: {0}")]
    ServiceState(String),
}

fn main() {
    let mut args = Arguments::from_env();
    if args.contains(["-h", "--help"]) {
        if let Err(error) = print_help() {
            let _ = write_stderr_line(&format!("failed to print help: {error}"));
            std::process::exit(1);
        }
        return;
    }

    let config = match parse_config(args) {
        Ok(value) => value,
        Err(error) => {
            let _ = write_stderr_line(&error.to_string());
            std::process::exit(1);
        }
    };

    if let Err(error) = run(&config) {
        error!(%error, "portcullis run failed");
        std::process::exit(1);
    }
}

fn parse_config(mut args: Arguments) -> Result<Config, MainError> {
    let mut config = Config::default();

    if let Some(socket) = args.opt_value_from_str::<_, String>("--docker-socket")? {
        config.docker_socket = socket;
    }
    if let Some(backend) = args.opt_value_from_str::<_, String>("--firewall-backend")? {
        config.firewall_backend = FirewallBackend::from_str(&backend)?;
    }
    if let Some(level) = args.opt_value_from_str::<_, String>("--log-level")? {
        config.log_level = LogLevel::from_str(&level)?;
    }
    if args.contains("--fail-closed") {
        config.fail_closed = true;
    }

    let remaining = args.finish();
    if !remaining.is_empty() {
        return Err(MainError::UnexpectedArguments(remaining));
    }

    Ok(config)
}

fn print_help() -> Result<(), std::io::Error> {
    let usage = "\
portcullis prototype

USAGE:
  portcullis [--docker-socket <path>] [--firewall-backend <auto|nftables|iptables>] [--log-level <error|warn|info|debug|trace>] [--fail-closed]

OPTIONS:
  --docker-socket      Path to Docker Unix socket (default: /var/run/docker.sock)
  --firewall-backend   Firewall implementation: auto, nftables, or iptables (default: auto)
  --log-level          Logging level (default: info)
  --fail-closed        Force default-deny for all discovered containers, even without labels
  -h, --help           Show this help
";
    std::io::stdout().write_all(usage.as_bytes())
}

fn write_stderr_line(message: &str) -> Result<(), std::io::Error> {
    std::io::stderr().write_all(format!("{message}\n").as_bytes())
}

enum ActiveFirewall {
    Nftables(NftablesFirewall<crate::firewall::LibNftablesRunner>),
    Iptables(IptablesFirewall<CommandIptablesRunner>),
}

impl ActiveFirewall {
    fn apply(
        &self,
        snapshot: &crate::model::RuntimeSnapshot,
        dns_cache: &mut DnsProxyCache<SystemUpstreamResolver>,
    ) -> Result<(), FirewallError> {
        match self {
            Self::Nftables(firewall) => firewall.apply_with_dns(snapshot, dns_cache),
            Self::Iptables(firewall) => firewall.apply_with_dns(snapshot, dns_cache),
        }
    }

    fn cleanup(&self) -> Result<(), FirewallError> {
        match self {
            Self::Nftables(firewall) => firewall.cleanup(),
            Self::Iptables(firewall) => firewall.cleanup(),
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run(config: &Config) -> Result<(), MainError> {
    logging::init_logging_with_level(config.log_level)?;

    info!(
        docker_socket = %config.docker_socket,
        firewall_backend = ?config.firewall_backend,
        log_level = ?config.log_level,
        fail_closed = config.fail_closed,
        "portcullis prototype started"
    );

    let api = SocketDockerApi::new(config.docker_socket.clone());
    let monitor = DockerMonitor::new(api);

    let selected_backend = match config.firewall_backend {
        FirewallBackend::Auto => match monitor.firewall_backend()? {
            DockerFirewallBackend::Nftables => FirewallBackend::Nftables,
            DockerFirewallBackend::Iptables => FirewallBackend::Iptables,
        },
        backend => backend,
    };
    info!(
        configured_backend = ?config.firewall_backend,
        selected_backend = ?selected_backend,
        "selected firewall backend"
    );

    let firewall = match selected_backend {
        FirewallBackend::Auto => unreachable!("auto backend must be resolved before execution"),
        FirewallBackend::Nftables => {
            ActiveFirewall::Nftables(NftablesFirewall::with_libnftables()?)
        }
        FirewallBackend::Iptables => ActiveFirewall::Iptables(IptablesFirewall::with_cli()),
    };

    info!("performing startup firewall cleanup");
    firewall.cleanup()?;

    let terminate = Arc::new(AtomicBool::new(false));
    let terminate_flag = Arc::clone(&terminate);
    ctrlc::set_handler(move || {
        terminate_flag.store(true, Ordering::Relaxed);
    })
    .map_err(|error| MainError::SignalHandler(error.to_string()))?;

    let mut tracker = RuntimeChangeTracker::new();
    let mut dns_cache = DnsProxyCache::new(SystemUpstreamResolver, Duration::from_secs(300), 2048);
    let mut runtime_state = monitor.collect_state()?;
    let mut event_stream = connect_event_stream(&config.docker_socket)?;

    apply_runtime_state(
        &runtime_state,
        &firewall,
        &mut tracker,
        &mut dns_cache,
        config.fail_closed,
        true,
    )?;

    info!("subscribed to docker container events");
    loop {
        if terminate.load(Ordering::Relaxed) {
            info!("termination signal received; cleanup will start now");
            break;
        }

        match event_stream.next_event() {
            Ok(Some(event)) => {
                trace!(event = ?event, "docker event received");
                if !event.is_relevant_for_policy_refresh() {
                    trace!(action = ?event.action, "docker event ignored");
                    continue;
                }

                info!(
                    action = ?event.action,
                    object_id = %event.id,
                    object_name = ?event.name,
                    kind = ?event.kind,
                    "docker event may require firewall refresh"
                );

                let update_result = monitor
                    .resolve_event_action(&runtime_state, &event)
                    .map(|action| action.is_some_and(|value| runtime_state.apply_action(value)))
                    .map_err(MainError::from);

                match update_result {
                    Ok(false) => {
                        trace!(event = ?event, "docker event produced no policy state changes");
                    }
                    Ok(true) => {
                        if let Err(error) = apply_runtime_state(
                            &runtime_state,
                            &firewall,
                            &mut tracker,
                            &mut dns_cache,
                            config.fail_closed,
                            false,
                        ) {
                            error!(%error, "firewall refresh failed; continuing");
                        }
                    }
                    Err(error) => {
                        error!(%error, "runtime state refresh failed; continuing");
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                error!(%error, "docker event stream failed");
                if terminate.load(Ordering::Relaxed) {
                    break;
                }
                match connect_event_stream(&config.docker_socket) {
                    Ok(stream) => event_stream = stream,
                    Err(reconnect_error) => {
                        error!(%reconnect_error, "docker event stream reconnect failed; retrying");
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
        }
    }

    info!("shutdown requested; cleaning up firewall rules");
    if let Err(error) = firewall.cleanup() {
        error!(%error, "shutdown cleanup failed");
        return Err(MainError::Firewall(error));
    }
    info!("shutdown cleanup completed");
    Ok(())
}

fn connect_event_stream(socket: &str) -> Result<DockerSocketEventStream, MainError> {
    let stream = DockerSocketEventStream::connect(socket)?;
    info!("docker event stream connected");
    Ok(stream)
}

fn apply_runtime_state(
    runtime_state: &RuntimeState,
    firewall: &ActiveFirewall,
    tracker: &mut RuntimeChangeTracker,
    dns_cache: &mut DnsProxyCache<SystemUpstreamResolver>,
    fail_closed: bool,
    force_apply: bool,
) -> Result<(), MainError> {
    let mut snapshot = runtime_state.snapshot();
    if fail_closed {
        enforce_fail_closed_defaults(&mut snapshot);
    }
    let changes = tracker.detect_and_log(&snapshot);
    debug!(change_count = changes.len(), "runtime changes computed");
    trace!(?snapshot, "runtime snapshot for firewall apply");
    if !force_apply && changes.is_empty() {
        debug!("skipping firewall apply because no runtime changes were detected");
        return Ok(());
    }
    firewall.apply(&snapshot, dns_cache)?;
    info!("firewall rules applied");
    Ok(())
}

fn enforce_fail_closed_defaults(snapshot: &mut crate::model::RuntimeSnapshot) {
    for container in &mut snapshot.containers {
        if !container.policy.enabled {
            container.policy.enabled = true;
            container.policy.egress.clear();
            container.policy.icc_allow.clear();
        }
    }
}

fn current_unix_epoch_seconds() -> Result<i64, MainError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| MainError::ServiceState(error.to_string()))?;
    i64::try_from(duration.as_secs()).map_err(|error| MainError::ServiceState(error.to_string()))
}

struct DockerSocketEventStream {
    reader: BufReader<UnixStream>,
}

impl DockerSocketEventStream {
    fn connect(socket: &str) -> Result<Self, MainError> {
        let socket_path = if let Some(path) = socket.strip_prefix("unix://") {
            path
        } else {
            socket
        };

        let mut stream = UnixStream::connect(socket_path)
            .map_err(|error| MainError::ServiceState(error.to_string()))?;
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|error| MainError::ServiceState(error.to_string()))?;

        let since = current_unix_epoch_seconds()?;
        let path = build_events_path(since)?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|error| MainError::ServiceState(error.to_string()))?;

        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(|error| MainError::ServiceState(error.to_string()))?;
        if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
            return Err(MainError::ServiceState(format!(
                "docker events subscribe failed: {status_line}"
            )));
        }

        loop {
            let mut header_line = String::new();
            reader
                .read_line(&mut header_line)
                .map_err(|error| MainError::ServiceState(error.to_string()))?;
            if header_line == "\r\n" {
                break;
            }
        }

        Ok(Self { reader })
    }

    fn next_event(&mut self) -> Result<Option<DockerEvent>, MainError> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => Err(MainError::ServiceState(
                "docker event stream closed".to_string(),
            )),
            Ok(_) => parse_container_event_line(&line),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(MainError::ServiceState(error.to_string())),
        }
    }
}

fn parse_container_event_line(line: &str) -> Result<Option<DockerEvent>, MainError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if is_chunk_size_line(trimmed) {
        return Ok(None);
    }

    let parsed: DockerEventLine = serde_json::from_str(trimmed)
        .map_err(|error| MainError::ServiceState(format!("invalid docker event json: {error}")))?;
    let action = parsed.action.or(parsed.status);
    let kind = parsed.kind.or(parsed.event_type);
    let Some(action) = action else {
        return Ok(None);
    };
    let kind = kind.unwrap_or(DockerEventKind::Container);
    let actor_id = parsed.actor.as_ref().and_then(|actor| actor.id.clone());
    let id = parsed.id.or(actor_id).unwrap_or_default();
    if id.is_empty() {
        return Ok(None);
    }

    let attributes = parsed
        .actor
        .as_ref()
        .and_then(|actor| actor.attributes.as_ref())
        .cloned()
        .unwrap_or_default();

    let name = attributes.get("name").cloned();

    Ok(Some(DockerEvent {
        id,
        action,
        name,
        kind,
        attributes,
    }))
}

fn is_chunk_size_line(line: &str) -> bool {
    let size_part = line.split(';').next().unwrap_or_default().trim();
    !size_part.is_empty() && size_part.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn build_events_path(since: i64) -> Result<String, MainError> {
    let filters = serde_json::json!({
        "type": ["container", "network"],
        "event": [
            "create",
            "rename",
            "update",
            "destroy",
            "connect",
            "disconnect"
        ]
    });
    let raw = serde_json::to_string(&filters)
        .map_err(|error| MainError::ServiceState(error.to_string()))?;
    Ok(format!(
        "/events?filters={}&since={since}",
        percent_encode_query_value(&raw)
    ))
}

fn percent_encode_query_value(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                encoded.push('%');
                let _ = write!(encoded, "{byte:02X}");
            }
        }
    }
    encoded
}

#[derive(Debug, Clone, Deserialize)]
struct DockerEventLine {
    #[serde(rename = "Type")]
    event_type: Option<DockerEventKind>,
    #[serde(rename = "type")]
    kind: Option<DockerEventKind>,
    #[serde(rename = "Action")]
    action: Option<DockerEventAction>,
    #[serde(rename = "status")]
    status: Option<DockerEventAction>,
    #[serde(rename = "id")]
    id: Option<String>,
    #[serde(rename = "Actor")]
    actor: Option<DockerEventActor>,
}

#[derive(Debug, Clone, Deserialize)]
struct DockerEventActor {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Attributes")]
    attributes: Option<HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config_uses_defaults() {
        let args = Arguments::from_vec(Vec::new());
        let config = parse_config(args).ok();
        assert_eq!(
            config,
            Some(Config {
                docker_socket: "/var/run/docker.sock".to_string(),
                firewall_backend: FirewallBackend::Auto,
                log_level: LogLevel::Info,
                fail_closed: false,
            })
        );
    }

    #[test]
    fn parse_config_reads_all_values() {
        let args = Arguments::from_vec(vec![
            "--docker-socket".into(),
            "/tmp/docker.sock".into(),
            "--firewall-backend".into(),
            "nftables".into(),
            "--log-level".into(),
            "debug".into(),
            "--fail-closed".into(),
        ]);
        let config = parse_config(args).ok();
        assert_eq!(
            config,
            Some(Config {
                docker_socket: "/tmp/docker.sock".to_string(),
                firewall_backend: FirewallBackend::Nftables,
                log_level: LogLevel::Debug,
                fail_closed: true,
            })
        );
    }

    #[test]
    fn parse_config_rejects_invalid_backend() {
        let args = Arguments::from_vec(vec!["--firewall-backend".into(), "bad".into()]);
        let result = parse_config(args);
        assert!(matches!(result, Err(MainError::InvalidFirewallBackend(_))));
    }

    #[test]
    fn socket_api_construction_accepts_unix_prefixed_path() {
        let _api = SocketDockerApi::new("unix:///var/run/docker.sock".to_string());
    }

    #[test]
    fn parse_container_event_line_parses_container_event() {
        let line = "{\"Type\":\"container\",\"Action\":\"start\",\"Actor\":{\"ID\":\"abc\",\"Attributes\":{\"name\":\"web\"}}}";
        let event = parse_container_event_line(line).expect("event parse should succeed");
        assert_eq!(
            event,
            Some(DockerEvent {
                id: "abc".to_string(),
                action: DockerEventAction::Start,
                name: Some("web".to_string()),
                kind: DockerEventKind::Container,
                attributes: std::collections::HashMap::from([(
                    "name".to_string(),
                    "web".to_string(),
                )]),
            })
        );
    }

    #[test]
    fn parse_container_event_line_parses_network_event() {
        let line = "{\"Type\":\"network\",\"Action\":\"create\",\"Actor\":{\"ID\":\"net0\",\"Attributes\":{\"name\":\"pc-managed\"}}}";
        let event = parse_container_event_line(line).expect("event parse should succeed");
        assert_eq!(
            event,
            Some(DockerEvent {
                id: "net0".to_string(),
                action: DockerEventAction::Create,
                name: Some("pc-managed".to_string()),
                kind: DockerEventKind::Network,
                attributes: std::collections::HashMap::from([(
                    "name".to_string(),
                    "pc-managed".to_string(),
                )]),
            })
        );
    }

    #[test]
    fn parse_container_event_line_ignores_unrelated_event_type() {
        let line = "{\"Type\":\"volume\",\"Action\":\"create\",\"Actor\":{\"ID\":\"vol0\"}}";
        let result = parse_container_event_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn parse_container_event_line_ignores_chunk_size_lines() {
        let event = parse_container_event_line("173\r\n").expect("event parse should succeed");
        assert!(event.is_none());
    }

    #[test]
    fn parse_container_event_line_ignores_chunk_size_with_extensions() {
        let event =
            parse_container_event_line("173;foo=bar\r\n").expect("event parse should succeed");
        assert!(event.is_none());
    }

    #[test]
    fn build_events_path_includes_type_and_event_filters() {
        let path = build_events_path(123).expect("events path should build");
        assert!(path.starts_with("/events?filters="));
        assert!(path.contains("&since=123"));
        assert!(path.contains("%22type%22"));
        assert!(path.contains("%22event%22"));
        assert!(path.contains("connect"));
        assert!(path.contains("disconnect"));
    }
}
