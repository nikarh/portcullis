mod dns;
mod docker;
mod firewall;
mod labels;
mod logging;
mod model;
mod monitor;

use std::ffi::OsString;
use std::io::Write as _;
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

use pico_args::Arguments;
use thiserror::Error;
use tracing::{debug, error, info, trace};

use crate::dns::{DnsProxyCache, SystemUpstreamResolver};
use crate::docker::{DockerClient, DockerError, DockerEventStream, DockerFirewallBackend};
use crate::firewall::{ActiveFirewall, FirewallError};
use crate::logging::{LogLevel, LoggingError};
use crate::monitor::{DockerMonitor, MonitorError, RuntimeChangeTracker, RuntimeState};

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
    UnexpectedArguments(Vec<OsString>),
    #[error("failed to initialize logging: {0}")]
    Logging(#[from] LoggingError),
    #[error("monitoring failed: {0}")]
    Monitor(#[from] MonitorError),
    #[error("docker client failed: {0}")]
    Docker(#[from] DockerError),
    #[error("firewall apply failed: {0}")]
    Firewall(#[from] FirewallError),
    #[error("failed to install signal handler: {0}")]
    SignalHandler(String),
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

    let monitor = DockerMonitor::new(DockerClient::new(config.docker_socket.clone()));
    let event_client = DockerClient::new(config.docker_socket.clone());

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
        FirewallBackend::Nftables => ActiveFirewall::with_nftables()?,
        FirewallBackend::Iptables => ActiveFirewall::with_iptables(),
    };

    info!("performing startup firewall cleanup");
    firewall.cleanup()?;
    firewall.initialize()?;

    let terminate = Arc::new(AtomicBool::new(false));
    let terminate_flag = Arc::clone(&terminate);
    ctrlc::set_handler(move || {
        terminate_flag.store(true, Ordering::Relaxed);
    })
    .map_err(|error| MainError::SignalHandler(error.to_string()))?;

    let mut tracker = RuntimeChangeTracker::new();
    let mut dns_cache = DnsProxyCache::new(SystemUpstreamResolver, Duration::from_secs(300), 2048);
    let mut runtime_state = monitor.collect_state()?;
    let mut event_stream = connect_event_stream(&event_client)?;

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
                    .resolve_event_action(&runtime_state, event)
                    .map(|action| action.is_some_and(|value| runtime_state.apply_action(value)))
                    .map_err(MainError::from);

                match update_result {
                    Ok(false) => {
                        trace!("docker event produced no policy state changes");
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
                match connect_event_stream(&event_client) {
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

fn connect_event_stream(client: &DockerClient) -> Result<DockerEventStream, MainError> {
    let stream = client.subscribe_events()?;
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
    fn docker_client_construction_accepts_unix_prefixed_path() {
        let _client = DockerClient::new("unix:///var/run/docker.sock".to_string());
    }
}
