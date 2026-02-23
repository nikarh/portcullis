use std::io::{BufRead, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pico_args::Arguments;
use thiserror::Error;
use tracing::{debug, error, info, trace};

use portcullis::dns::{DnsProxyCache, SystemUpstreamResolver};
use portcullis::firewall::{
    CommandIptablesRunner, FirewallError, IptablesFirewall, NftablesFirewall,
};
use portcullis::logging::{self, LogLevel, LoggingError};
use portcullis::monitor::{
    DockerContainerEvent, DockerFirewallBackend, DockerMonitor, MonitorError, RuntimeChangeTracker,
    SocketDockerApi,
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            docker_socket: "/var/run/docker.sock".to_string(),
            firewall_backend: FirewallBackend::Auto,
            log_level: LogLevel::Info,
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
  portcullis [--docker-socket <path>] [--firewall-backend <auto|nftables|iptables>] [--log-level <error|warn|info|debug|trace>]

OPTIONS:
  --docker-socket      Path to Docker Unix socket (default: /var/run/docker.sock)
  --firewall-backend   Firewall implementation: auto, nftables, or iptables (default: auto)
  --log-level          Logging level (default: info)
  -h, --help           Show this help
";
    std::io::stdout().write_all(usage.as_bytes())
}

fn write_stderr_line(message: &str) -> Result<(), std::io::Error> {
    std::io::stderr().write_all(format!("{message}\n").as_bytes())
}

enum ActiveFirewall {
    Nftables(NftablesFirewall<portcullis::firewall::LibNftablesRunner>),
    Iptables(IptablesFirewall<CommandIptablesRunner>),
}

impl ActiveFirewall {
    fn apply(
        &self,
        snapshot: &portcullis::model::RuntimeSnapshot,
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

fn run(config: &Config) -> Result<(), MainError> {
    logging::init_logging_with_level(config.log_level)?;

    info!(
        docker_socket = %config.docker_socket,
        firewall_backend = ?config.firewall_backend,
        log_level = ?config.log_level,
        "portcullis prototype started"
    );

    let api = SocketDockerApi::new(config.docker_socket.clone());
    let monitor = DockerMonitor::new(api);
    let detected_backend = monitor.firewall_backend()?;

    let selected_backend = match config.firewall_backend {
        FirewallBackend::Auto => match detected_backend {
            DockerFirewallBackend::Nftables => FirewallBackend::Nftables,
            DockerFirewallBackend::Iptables => FirewallBackend::Iptables,
        },
        backend => backend,
    };
    info!(
        configured_backend = ?config.firewall_backend,
        detected_backend = ?detected_backend,
        selected_backend = ?selected_backend,
        "selected firewall backend"
    );

    let firewall = match selected_backend {
        FirewallBackend::Auto => unreachable!("auto backend must be resolved before execution"),
        FirewallBackend::Nftables => {
            ActiveFirewall::Nftables(NftablesFirewall::with_libnftables()?)
        }
        FirewallBackend::Iptables => {
            ActiveFirewall::Iptables(IptablesFirewall::<CommandIptablesRunner>::with_cli())
        }
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
    let mut event_stream = DockerSocketEventStream::connect(&config.docker_socket)?;

    apply_snapshot(&monitor, &firewall, &mut tracker, &mut dns_cache)?;

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
                    trace!(action = %event.action, "docker event ignored");
                    continue;
                }

                info!(
                    action = %event.action,
                    container_id = %event.id,
                    container_name = ?event.name,
                    "docker event requires firewall refresh"
                );
                apply_snapshot(&monitor, &firewall, &mut tracker, &mut dns_cache)?;
            }
            Ok(None) => {}
            Err(error) => {
                error!(%error, "docker event stream failed");
                if terminate.load(Ordering::Relaxed) {
                    break;
                }
                event_stream = DockerSocketEventStream::connect(&config.docker_socket)?;
                info!("docker event stream reconnected");
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

fn apply_snapshot<A>(
    monitor: &DockerMonitor<A>,
    firewall: &ActiveFirewall,
    tracker: &mut RuntimeChangeTracker,
    dns_cache: &mut DnsProxyCache<SystemUpstreamResolver>,
) -> Result<(), MainError>
where
    A: portcullis::monitor::DockerApi,
{
    let snapshot = monitor.snapshot()?;
    let changes = tracker.detect_and_log(&snapshot);
    debug!(change_count = changes.len(), "runtime changes computed");
    trace!(?snapshot, "runtime snapshot for firewall apply");
    firewall.apply(&snapshot, dns_cache)?;
    info!("firewall rules applied");
    Ok(())
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
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(|error| MainError::ServiceState(error.to_string()))?;

        let since = current_unix_epoch_seconds()?;
        let request = format!(
            "GET /events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D&since={since} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
        );
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

    fn next_event(&mut self) -> Result<Option<DockerContainerEvent>, MainError> {
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

fn parse_container_event_line(line: &str) -> Result<Option<DockerContainerEvent>, MainError> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if is_chunk_size_line(trimmed) {
        return Ok(None);
    }

    let parsed: DockerEventLine = serde_json::from_str(trimmed)
        .map_err(|error| MainError::ServiceState(format!("invalid docker event json: {error}")))?;
    let action = parsed.action.or(parsed.status).unwrap_or_default();
    let kind = parsed.kind.or(parsed.event_type).unwrap_or_default();
    if !kind.is_empty() && kind != "container" {
        return Ok(None);
    }
    let actor_id = parsed.actor.as_ref().and_then(|actor| actor.id.clone());
    let id = parsed.id.or(actor_id).unwrap_or_default();
    if id.is_empty() || action.is_empty() {
        return Ok(None);
    }

    let name = parsed
        .actor
        .as_ref()
        .and_then(|actor| actor.attributes.as_ref())
        .and_then(|attributes| attributes.get("name").cloned());

    Ok(Some(DockerContainerEvent { id, action, name }))
}

fn is_chunk_size_line(line: &str) -> bool {
    let size_part = line.split(';').next().unwrap_or_default().trim();
    !size_part.is_empty() && size_part.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Deserialize)]
struct DockerEventLine {
    #[serde(rename = "Type")]
    event_type: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(rename = "Action")]
    action: Option<String>,
    #[serde(rename = "status")]
    status: Option<String>,
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
    attributes: Option<std::collections::BTreeMap<String, String>>,
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
        ]);
        let config = parse_config(args).ok();
        assert_eq!(
            config,
            Some(Config {
                docker_socket: "/tmp/docker.sock".to_string(),
                firewall_backend: FirewallBackend::Nftables,
                log_level: LogLevel::Debug,
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
            Some(DockerContainerEvent {
                id: "abc".to_string(),
                action: "start".to_string(),
                name: Some("web".to_string()),
            })
        );
    }

    #[test]
    fn parse_container_event_line_ignores_non_container_event() {
        let line = "{\"Type\":\"network\",\"Action\":\"connect\",\"Actor\":{\"ID\":\"net0\"}}";
        let event = parse_container_event_line(line).expect("event parse should succeed");
        assert!(event.is_none());
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
}
