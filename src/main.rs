#![allow(clippy::multiple_crate_versions)]

mod dns;
mod dns_proxy;
mod docker;
mod firewall;
mod labels;
mod logging;
mod model;
mod monitor;

use std::collections::HashSet;
use std::ffi::OsString;
use std::io::Write as _;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, select, unbounded};
use pico_args::Arguments;
use thiserror::Error;
use tracing::{debug, error, info, trace};

use crate::dns::{CacheOnlyDnsResolver, DnsProxyCache, SystemUpstreamResolver};
use crate::dns_proxy::{
    DnsApplyAck, DnsResolvedEvent, DnsRuntimeHandle, DnsRuntimeMode, spawn_dns_runtime,
};
use crate::docker::{
    DockerApi, DockerClient, DockerError, DockerEvent, DockerEventClient, DockerFirewallBackend,
};
use crate::firewall::{ActiveFirewall, FirewallError};
use crate::logging::{LogLevel, LoggingError};
use crate::model::{EgressTarget, RuntimeState};
use crate::monitor::{DockerMonitor, MonitorError};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsMode {
    Proxy,
    Lazy,
}

impl FromStr for DnsMode {
    type Err = MainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "proxy" => Ok(Self::Proxy),
            "lazy" => Ok(Self::Lazy),
            _ => Err(MainError::InvalidDnsMode(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    docker_socket: String,
    firewall_backend: FirewallBackend,
    dns_mode: DnsMode,
    dns_proxy_bind: SocketAddr,
    log_level: LogLevel,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            docker_socket: "/var/run/docker.sock".to_string(),
            firewall_backend: FirewallBackend::Auto,
            dns_mode: DnsMode::Lazy,
            dns_proxy_bind: SocketAddr::from(([127, 0, 0, 1], 1053)),
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
    #[error("invalid DNS mode: {0}")]
    InvalidDnsMode(String),
    #[error("invalid DNS proxy bind address: {0}")]
    InvalidDnsProxyBind(String),
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
    #[error("failed to start DNS runtime: {0}")]
    DnsRuntimeStart(String),
}

#[derive(Debug)]
enum DockerWorkerEvent {
    Event(DockerEvent),
    Reconnected,
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
    if let Some(mode) = args.opt_value_from_str::<_, String>("--dns-mode")? {
        config.dns_mode = DnsMode::from_str(&mode)?;
    }
    if let Some(bind) = args.opt_value_from_str::<_, String>("--dns-proxy-bind")? {
        config.dns_proxy_bind = bind
            .parse()
            .map_err(|_| MainError::InvalidDnsProxyBind(bind.clone()))?;
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
  portcullis [--docker-socket <path>] [--firewall-backend <auto|nftables|iptables>] [--dns-mode <lazy|proxy>] [--dns-proxy-bind <host:port>] [--log-level <error|warn|info|debug|trace>]

OPTIONS:
  --docker-socket      Path to Docker Unix socket (default: /var/run/docker.sock)
  --firewall-backend   Firewall implementation: auto, nftables, or iptables (default: auto)
  --dns-mode           DNS behavior mode: lazy or proxy (default: lazy)
  --dns-proxy-bind     UDP bind address for DNS proxy mode (default: 127.0.0.1:1053)
  --log-level          Logging level (default: info)
  -h, --help           Show this help
";
    std::io::stdout().write_all(usage.as_bytes())
}

fn write_stderr_line(message: &str) -> Result<(), std::io::Error> {
    std::io::stderr().write_all(format!("{message}\n").as_bytes())
}

fn apply_firewall(
    firewall: &ActiveFirewall,
    state: &RuntimeState,
    dns_cache: &mut DnsProxyCache<SystemUpstreamResolver>,
) -> Result<(), MainError> {
    let mut resolver = CacheOnlyDnsResolver::new(dns_cache);
    firewall
        .apply(state, &mut resolver)
        .map_err(MainError::Firewall)
}

fn collect_policy_hostnames(state: &RuntimeState) -> HashSet<String> {
    let mut hostnames = HashSet::new();
    for container in state.containers().values() {
        for rule in &container.policy.egress {
            if let EgressTarget::Hostname(host) = &rule.target {
                hostnames.insert(host.to_ascii_lowercase());
            }
        }
    }
    hostnames
}

fn refresh_dns_tracking(runtime: &DnsRuntimeHandle, state: &RuntimeState, mode: DnsMode) {
    runtime.set_tracked_hosts(collect_policy_hostnames(state));
    if matches!(mode, DnsMode::Lazy) {
        runtime.request_refresh();
    }
}

fn stop_requested(stop_rx: &Receiver<()>) -> bool {
    stop_rx.try_recv().is_ok()
}

fn sleep_or_stop(stop_rx: &Receiver<()>, duration: Duration) -> bool {
    match stop_rx.recv_timeout(duration) {
        Ok(()) | Err(RecvTimeoutError::Disconnected) => true,
        Err(RecvTimeoutError::Timeout) => false,
    }
}

fn spawn_docker_event_worker(
    docker_socket: String,
    event_tx: Sender<DockerWorkerEvent>,
    stop_rx: Receiver<()>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut event_client = loop {
            if stop_requested(&stop_rx) {
                return;
            }
            match DockerEventClient::connect(&docker_socket) {
                Ok(client) => break client,
                Err(error) => {
                    error!(%error, "docker event stream connect failed; retrying");
                    if sleep_or_stop(&stop_rx, Duration::from_secs(1)) {
                        return;
                    }
                }
            }
        };

        loop {
            if stop_requested(&stop_rx) {
                return;
            }

            match event_client.next_event() {
                Ok(Some(event)) => {
                    if event_tx.send(DockerWorkerEvent::Event(event)).is_err() {
                        return;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    error!(%error, "docker event stream failed");
                    loop {
                        if sleep_or_stop(&stop_rx, Duration::from_secs(1)) {
                            return;
                        }
                        match DockerEventClient::connect(&docker_socket) {
                            Ok(client) => {
                                event_client = client;
                                let _ = event_tx.send(DockerWorkerEvent::Reconnected);
                                break;
                            }
                            Err(reconnect_error) => {
                                error!(%reconnect_error, "docker event reconnect failed; retrying");
                            }
                        }
                    }
                }
            }
        }
    })
}

#[allow(clippy::too_many_lines)]
fn run(config: &Config) -> Result<(), MainError> {
    logging::init_logging_with_level(config.log_level)?;

    info!(
        docker_socket = %config.docker_socket,
        firewall_backend = ?config.firewall_backend,
        dns_mode = ?config.dns_mode,
        dns_proxy_bind = %config.dns_proxy_bind,
        log_level = ?config.log_level,
        "portcullis prototype started"
    );

    let mut monitor_client = DockerClient::connect(&config.docker_socket)?;

    let selected_backend = match config.firewall_backend {
        FirewallBackend::Auto => match monitor_client.firewall_backend()? {
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

    let mut monitor = DockerMonitor::new(monitor_client);

    let firewall = match selected_backend {
        FirewallBackend::Auto => unreachable!("auto backend must be resolved before execution"),
        FirewallBackend::Nftables => ActiveFirewall::with_nftables()?,
        FirewallBackend::Iptables => ActiveFirewall::with_iptables(),
    };

    info!("performing startup firewall cleanup");
    firewall.cleanup()?;
    firewall.initialize()?;

    let mut dns_cache = DnsProxyCache::new(SystemUpstreamResolver, Duration::from_secs(300), 2048);
    let mut runtime_state = monitor.initialize()?;
    apply_firewall(&firewall, &runtime_state, &mut dns_cache)?;
    info!("firewall rules applied");

    let (docker_tx, docker_rx) = unbounded::<DockerWorkerEvent>();
    let (docker_stop_tx, docker_stop_rx) = unbounded::<()>();
    let (dns_tx, dns_rx) = unbounded::<DnsResolvedEvent>();
    let (terminate_tx, terminate_rx) = unbounded::<()>();

    ctrlc::set_handler(move || {
        let _ = terminate_tx.send(());
    })
    .map_err(|error| MainError::SignalHandler(error.to_string()))?;

    let dns_runtime = spawn_dns_runtime(
        match config.dns_mode {
            DnsMode::Proxy => DnsRuntimeMode::Proxy,
            DnsMode::Lazy => DnsRuntimeMode::Lazy,
        },
        config.dns_proxy_bind,
        dns_tx,
    )
    .map_err(|error| MainError::DnsRuntimeStart(error.to_string()))?;

    refresh_dns_tracking(&dns_runtime, &runtime_state, config.dns_mode);

    let docker_thread =
        spawn_docker_event_worker(config.docker_socket.clone(), docker_tx, docker_stop_rx);

    loop {
        select! {
            recv(terminate_rx) -> _ => {
                info!("termination signal received; cleanup will start now");
                break;
            }
            recv(docker_rx) -> message => {
                let Ok(message) = message else {
                    break;
                };
                match message {
                    DockerWorkerEvent::Event(event) => {
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
                            .map(|action| action.is_some_and(|value| runtime_state.apply_action(value)));

                        match update_result {
                            Ok(false) => {
                                trace!("docker event produced no policy state changes");
                            }
                            Ok(true) => {
                                if let Err(error) = apply_firewall(&firewall, &runtime_state, &mut dns_cache) {
                                    error!(%error, "firewall apply failed; continuing");
                                } else {
                                    refresh_dns_tracking(&dns_runtime, &runtime_state, config.dns_mode);
                                    info!("firewall rules applied");
                                }
                            }
                            Err(error) => {
                                error!(%error, "runtime state refresh failed; continuing");
                            }
                        }
                    }
                    DockerWorkerEvent::Reconnected => {
                        info!("docker event stream reconnected; reinitializing monitor state");
                        match DockerClient::connect(&config.docker_socket) {
                            Ok(client) => {
                                monitor = DockerMonitor::new(client);
                                match monitor.initialize() {
                                    Ok(state) => {
                                        runtime_state = state;
                                        if let Err(error) = apply_firewall(&firewall, &runtime_state, &mut dns_cache) {
                                            error!(%error, "firewall apply failed after reconnect; continuing");
                                        } else {
                                            refresh_dns_tracking(&dns_runtime, &runtime_state, config.dns_mode);
                                            info!("firewall rules applied after reconnect");
                                        }
                                    }
                                    Err(error) => {
                                        error!(%error, "monitor reinitialize failed after reconnect");
                                    }
                                }
                            }
                            Err(error) => {
                                error!(%error, "docker client reconnect for monitor failed");
                            }
                        }
                    }
                }
            }
            recv(dns_rx) -> message => {
                let Ok(event) = message else {
                    continue;
                };
                debug!(host = %event.host, ip_count = event.addresses.len(), "received DNS resolution event");
                dns_cache.insert_with_ttl(&event.host, event.addresses.clone(), event.ttl);
                let apply_result = apply_firewall(&firewall, &runtime_state, &mut dns_cache);
                if let Some(ack) = event.ack {
                    let _ = ack.send(if apply_result.is_ok() {
                        DnsApplyAck::Applied
                    } else {
                        DnsApplyAck::Rejected
                    });
                }

                if let Err(error) = apply_result {
                    error!(%error, "firewall apply failed after DNS update; continuing");
                }
            }
        }
    }

    let _ = docker_stop_tx.send(());
    let _ = docker_thread.join();
    dns_runtime.shutdown();

    info!("shutdown requested; cleaning up firewall rules");
    if let Err(error) = firewall.cleanup() {
        error!(%error, "shutdown cleanup failed");
        return Err(MainError::Firewall(error));
    }
    info!("shutdown cleanup completed");

    Ok(())
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
                dns_mode: DnsMode::Lazy,
                dns_proxy_bind: SocketAddr::from(([127, 0, 0, 1], 1053)),
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
            "--dns-mode".into(),
            "proxy".into(),
            "--dns-proxy-bind".into(),
            "127.0.0.1:5300".into(),
            "--log-level".into(),
            "debug".into(),
        ]);
        let config = parse_config(args).ok();
        assert_eq!(
            config,
            Some(Config {
                docker_socket: "/tmp/docker.sock".to_string(),
                firewall_backend: FirewallBackend::Nftables,
                dns_mode: DnsMode::Proxy,
                dns_proxy_bind: SocketAddr::from(([127, 0, 0, 1], 5300)),
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
    fn parse_config_rejects_invalid_dns_mode() {
        let args = Arguments::from_vec(vec!["--dns-mode".into(), "bad".into()]);
        let result = parse_config(args);
        assert!(matches!(result, Err(MainError::InvalidDnsMode(_))));
    }

    #[test]
    fn parse_config_rejects_invalid_dns_proxy_bind() {
        let args = Arguments::from_vec(vec!["--dns-proxy-bind".into(), "bad".into()]);
        let result = parse_config(args);
        assert!(matches!(result, Err(MainError::InvalidDnsProxyBind(_))));
    }
}
