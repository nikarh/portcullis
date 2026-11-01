#![allow(clippy::multiple_crate_versions)]

mod connection_log;
mod conntrack;
mod directory;
mod dns;
mod dns_inspect;
mod docker;
mod events;
mod firewall;
mod host_dns;
mod labels;
mod logging;
mod model;
mod monitor;
mod nfnetlink;
mod rtnetlink;
mod source_hold;
mod tools;

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, select, unbounded};
use pico_args::Arguments;
use thiserror::Error;
use tracing::{error, info, trace, warn};

use crate::connection_log::SharedHosts;
use crate::directory::Directory;
use crate::dns::{HostAddresses, SystemUpstreamResolver};
use crate::docker::{DockerClient, DockerError, DockerEvent, DockerEventClient};
use crate::events::{
    ContainerAction, ContainerChange, Event, EventBus, Mode, Sinks, Warning, WarningKind,
};
use crate::firewall::{DenyAction, FirewallError, LogAllowed, NftablesFirewall, Options, Plan};
use crate::logging::{LogFormat, LogLevel, LoggingError};
use crate::model::{ContainerId, MacAddress, RuntimeState};
use crate::monitor::{DockerMonitor, MonitorError};
use crate::source_hold::SourceHold;

/// NFLOG group the firewall rules log decisions to.
const NFLOG_GROUP: u16 = 4242;
/// NFQUEUE number DNS answers are held in for inspection.
const DNS_QUEUE: u16 = 4242;
/// NFQUEUE number packets of not yet known containers are held in.
const SOURCE_QUEUE: u16 = 4243;
/// How long such packets are held before they are denied.
const SOURCE_HOLD_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    docker_socket: String,
    events_socket: Option<PathBuf>,
    deny_action: DenyAction,
    monitor: bool,
    log_allowed: LogAllowed,
    hostname_hold: Duration,
    alert_exec: Option<String>,
    alert_interval: Duration,
    log_level: LogLevel,
    log_format: LogFormat,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            docker_socket: "/var/run/docker.sock".to_string(),
            events_socket: None,
            deny_action: DenyAction::Reject,
            monitor: false,
            log_allowed: LogAllowed::Monitor,
            hostname_hold: Duration::from_secs(3600),
            alert_exec: None,
            alert_interval: Duration::from_secs(600),
            log_level: LogLevel::Info,
            log_format: LogFormat::Text,
        }
    }
}

#[derive(Debug, Error)]
enum MainError {
    #[error("argument parsing failed: {0}")]
    Args(#[from] pico_args::Error),
    #[error("invalid deny action: {0}")]
    InvalidDenyAction(String),
    #[error("invalid --log-allowed value: {0}")]
    InvalidLogAllowed(String),
    #[error("unexpected arguments: {0:?}")]
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
    #[error("failed to open the events socket: {0}")]
    EventsSocket(std::io::Error),
    #[error("failed to listen for logged connections (NFLOG): {0}")]
    ConnectionLog(std::io::Error),
    #[error("failed to listen for DNS answers (NFQUEUE): {0}")]
    DnsInspection(std::io::Error),
    #[error("failed to listen for packets of new containers (NFQUEUE): {0}")]
    SourceHold(std::io::Error),
    #[error("{0}")]
    Tool(std::io::Error),
}

#[derive(Debug)]
enum DockerWorkerEvent {
    Event(DockerEvent),
    Reconnected,
}

fn main() {
    let mut args = Arguments::from_env();
    if args.contains(["-h", "--help"]) {
        print_help();
        return;
    }

    let result = match args.subcommand() {
        Ok(Some(command)) if command == "watch" => run_watch(args),
        Ok(Some(command)) if command == "audit" => run_audit(args),
        Ok(Some(command)) => Err(MainError::UnexpectedArguments(vec![command.into()])),
        Ok(None) => parse_config(args).and_then(|config| run(&config)),
        Err(error) => Err(error.into()),
    };
    if let Err(error) = result {
        let _ = std::io::stderr().write_all(format!("portcullis: {error}\n").as_bytes());
        std::process::exit(1);
    }
}

fn run_watch(mut args: Arguments) -> Result<(), MainError> {
    let socket = args
        .opt_value_from_str::<_, PathBuf>("--events-socket")?
        .unwrap_or_else(|| PathBuf::from(tools::DEFAULT_EVENTS_SOCKET));
    finish(args)?;
    tools::watch(&socket).map_err(MainError::Tool)
}

fn run_audit(mut args: Arguments) -> Result<(), MainError> {
    let input = args.opt_free_from_str::<PathBuf>()?;
    finish(args)?;
    tools::audit(input.as_deref()).map_err(MainError::Tool)
}

fn finish(args: Arguments) -> Result<(), MainError> {
    let remaining = args.finish();
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(MainError::UnexpectedArguments(remaining))
    }
}

fn parse_config(mut args: Arguments) -> Result<Config, MainError> {
    let mut config = Config::default();

    if let Some(socket) = args.opt_value_from_str::<_, String>("--docker-socket")? {
        config.docker_socket = socket;
    }
    config.events_socket = args.opt_value_from_str::<_, PathBuf>("--events-socket")?;
    if let Some(action) = args.opt_value_from_str::<_, String>("--deny-action")? {
        config.deny_action = match action.as_str() {
            "reject" => DenyAction::Reject,
            "drop" => DenyAction::Drop,
            _ => return Err(MainError::InvalidDenyAction(action)),
        };
    }
    config.monitor = args.contains("--monitor");
    if let Some(value) = args.opt_value_from_str::<_, String>("--log-allowed")? {
        config.log_allowed = match value.as_str() {
            "always" => LogAllowed::Always,
            "monitor" => LogAllowed::Monitor,
            "never" => LogAllowed::Never,
            _ => return Err(MainError::InvalidLogAllowed(value)),
        };
    }
    if let Some(seconds) = args.opt_value_from_str::<_, u64>("--hostname-hold")? {
        config.hostname_hold = Duration::from_secs(seconds);
    }
    config.alert_exec = args.opt_value_from_str::<_, String>("--alert-exec")?;
    if let Some(seconds) = args.opt_value_from_str::<_, u64>("--alert-interval")? {
        config.alert_interval = Duration::from_secs(seconds);
    }
    if let Some(level) = args.opt_value_from_str::<_, String>("--log-level")? {
        config.log_level = LogLevel::from_str(&level)?;
    }
    if let Some(format) = args.opt_value_from_str::<_, String>("--log-format")? {
        config.log_format = LogFormat::from_str(&format)?;
    }

    finish(args)?;
    Ok(config)
}

fn print_help() {
    let usage = "\
Portcullis limits what Docker containers can connect to, using labels on networks and
containers.

USAGE:
  portcullis [OPTIONS]                 run the firewall daemon
  portcullis watch [--events-socket <path>]
                                       show live events of a running daemon
  portcullis audit [FILE]              summarize what containers tried that their labels
                                       don't allow, from JSON events (FILE or stdin)

OPTIONS:
  --docker-socket <path>       Docker API socket (default: /var/run/docker.sock)
  --monitor                    Monitor mode everywhere: report what would be denied, deny
                               nothing
  --deny-action <reject|drop>  Reject denied traffic with an ICMP error, or drop it
                               silently (default: reject)
  --log-allowed <always|monitor|never>
                               Which allowed connections and DNS lookups are reported;
                               denied ones always are (default: monitor, i.e. on networks
                               in monitor mode)
  --hostname-hold <seconds>    How long an address of a host: rule stays allowed after it
                               was last seen in a DNS answer (default: 3600)
  --events-socket <path>       Serve events as JSON lines on this Unix socket (mode 0600;
                               off by default)
  --alert-exec <command>       Run this command with sh -c for every denial and warning,
                               the event as JSON on stdin
  --alert-interval <seconds>   Raise the same alert at most once per interval
                               (default: 600)
  --log-format <text|json>     Format of events (stdout) and diagnostics (stderr)
                               (default: text)
  --log-level <level>          error, warn, info, debug or trace (default: info)
  -h, --help                   Show this help
";
    let _ = std::io::stdout().write_all(usage.as_bytes());
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

/// What a managed container address looked like at the last apply.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Managed {
    container: String,
    network: String,
    monitor: bool,
}

/// Applies rules and reports what changed.
/// Who an address belongs to: a recreated container has a new ID, and usually a new MAC.
type Owner = (ContainerId, Option<MacAddress>);

struct Applier {
    source_hold: SourceHold,
    firewall: Arc<NftablesFirewall>,
    hosts: SharedHosts,
    directory: Arc<Directory>,
    bus: EventBus,
    monitor_all: bool,
    managed: HashMap<IpAddr, Managed>,
    /// The container (and its MAC) each container address belonged to at the last update.
    owners: HashMap<IpAddr, Owner>,
    /// Containers already reported as not having observable DNS.
    unobservable_reported: HashSet<String>,
}

impl Applier {
    fn apply(&mut self, state: &mut RuntimeState) -> Result<(), MainError> {
        // Re-read on every update, so changes to the host's DNS configuration are picked up.
        let host_resolvers = host_dns::host_resolvers();
        state.set_daemon_dns(host_dns::docker_daemon_dns());
        let ports = rtnetlink::container_ports(state).unwrap_or_else(|error| {
            warn!(%error, "can't find containers' bridge ports; checking their traffic by address and MAC only");
            HashMap::new()
        });
        state.set_ports(ports);
        let state = &*state;
        self.forget_reassigned_connections(state);
        let result = {
            let mut hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
            hosts.prune(Instant::now());
            self.firewall
                .apply(state, &mut *hosts, &host_resolvers, self.monitor_all)
        };
        match result {
            Ok(plan) => {
                self.directory.update(&plan);
                // "applied" closes an update: everything it caused comes before it.
                self.report_changes(state, &plan);
                self.bus.applied(
                    plan.sources.iter().map(|source| source.address).collect(),
                    plan.unresolved_hosts.clone(),
                );
                self.source_hold.rules_applied();
                info!("firewall rules applied");
                Ok(())
            }
            Err(error) => {
                self.bus.publish(&Event::ApplyFailed {
                    error: error.to_string(),
                });
                Err(MainError::Firewall(error))
            }
        }
    }

    /// Delete the tracked connections of addresses that left their container, before rules
    /// for a new owner are applied (see `conntrack`). Addresses that just appeared keep
    /// theirs: that is every address when Portcullis starts.
    fn forget_reassigned_connections(&mut self, state: &RuntimeState) {
        let owners: HashMap<IpAddr, Owner> = state
            .containers()
            .values()
            .flat_map(|container| {
                container.attachments.iter().map(|attachment| {
                    (
                        attachment.ip_address,
                        (container.id.clone(), attachment.mac_address),
                    )
                })
            })
            .collect();
        let reassigned: HashSet<IpAddr> = self
            .owners
            .iter()
            .filter(|(address, owner)| owners.get(address) != Some(owner))
            .map(|(address, _)| *address)
            .collect();
        self.owners = owners;
        if let Err(error) = conntrack::forget(&reassigned) {
            warn!(%error, "can't forget the tracked connections of reassigned addresses; a container that got a removed container's address may keep using its connections");
        }
    }

    /// Container addresses that became managed or released, and containers whose DNS
    /// lookups Portcullis can't see.
    fn report_changes(&mut self, state: &RuntimeState, plan: &Plan) {
        let current: HashMap<IpAddr, Managed> = plan
            .sources
            .iter()
            .map(|source| {
                (
                    source.address,
                    Managed {
                        container: source.container.to_string(),
                        network: source.network.clone(),
                        monitor: source.monitor,
                    },
                )
            })
            .collect();
        let change = |action, address: IpAddr, managed: &Managed| {
            Event::Container(ContainerChange {
                action,
                container: managed.container.clone(),
                network: managed.network.clone(),
                address,
                mode: if managed.monitor {
                    Mode::Monitor
                } else {
                    Mode::Enforce
                },
            })
        };
        for (address, managed) in &self.managed {
            if current.get(address) != Some(managed) {
                self.bus
                    .publish(&change(ContainerAction::Released, *address, managed));
            }
        }
        for (address, managed) in &current {
            if self.managed.get(address) != Some(managed) {
                self.bus
                    .publish(&change(ContainerAction::Managed, *address, managed));
            }
        }
        self.managed = current;

        for container in state.containers().values() {
            if container.attachments.is_empty()
                || !container.runtime_dns_servers.is_empty()
                || !state.daemon_dns().is_empty()
                || !self
                    .unobservable_reported
                    .insert(container.name.to_string())
            {
                continue;
            }
            self.bus.publish(&Event::Warning(Warning {
                kind: WarningKind::DnsNotObservable,
                container: Some(container.name.to_string()),
                message: "Docker resolves this container's names from the host, where Portcullis can't see them: no domains on its events, and host: rules only allow what Portcullis resolves itself. Set dns in /etc/docker/daemon.json or on the container.".to_string(),
            }));
        }
        let names: HashSet<String> = state
            .containers()
            .values()
            .map(|container| container.name.to_string())
            .collect();
        self.unobservable_reported
            .retain(|name| names.contains(name));
    }
}

fn publish_warnings<A: docker::DockerApi>(monitor: &mut DockerMonitor<A>, bus: &EventBus) {
    for warning in monitor.take_warnings() {
        bus.publish(&Event::Warning(warning));
    }
}

#[allow(clippy::too_many_lines)]
fn run(config: &Config) -> Result<(), MainError> {
    logging::init_logging(config.log_level, config.log_format)?;
    info!(
        docker_socket = %config.docker_socket,
        monitor = config.monitor,
        "portcullis started"
    );

    let bus = EventBus::new(&Sinks {
        stdout: Some(config.log_format),
        socket: config.events_socket.clone(),
        alert_command: config.alert_exec.clone(),
        alert_interval: config.alert_interval,
    })
    .map_err(MainError::EventsSocket)?;

    let monitor_client = DockerClient::connect(&config.docker_socket)?;
    let mut monitor = DockerMonitor::new(monitor_client);
    let firewall = Arc::new(NftablesFirewall::with_libnftables(Options {
        deny: config.deny_action,
        log_group: NFLOG_GROUP,
        log_allowed: config.log_allowed,
        dns_queue: Some(DNS_QUEUE),
        source_queue: Some(SOURCE_QUEUE),
    })?);

    info!("performing startup firewall cleanup");
    firewall.cleanup()?;

    let directory = Arc::new(Directory::default());
    let hosts: SharedHosts = Arc::new(Mutex::new(HostAddresses::new(
        SystemUpstreamResolver,
        config.hostname_hold,
    )));
    connection_log::spawn(
        NFLOG_GROUP,
        Arc::clone(&directory),
        Arc::clone(&hosts),
        bus.clone(),
    )
    .map_err(MainError::ConnectionLog)?;
    dns_inspect::spawn(
        DNS_QUEUE,
        config.log_allowed,
        Arc::clone(&firewall),
        Arc::clone(&directory),
        Arc::clone(&hosts),
        bus.clone(),
    )
    .map_err(MainError::DnsInspection)?;

    let source_hold = source_hold::spawn(SOURCE_QUEUE, SOURCE_HOLD_GRACE, Arc::clone(&directory))
        .map_err(MainError::SourceHold)?;

    let mut applier = Applier {
        source_hold,
        firewall: Arc::clone(&firewall),
        hosts,
        directory,
        bus: bus.clone(),
        monitor_all: config.monitor,
        managed: HashMap::new(),
        owners: HashMap::new(),
        unobservable_reported: HashSet::new(),
    };

    let mut runtime_state = monitor.initialize()?;
    publish_warnings(&mut monitor, &bus);
    applier.apply(&mut runtime_state)?;

    let (docker_tx, docker_rx) = unbounded::<DockerWorkerEvent>();
    let (docker_stop_tx, docker_stop_rx) = unbounded::<()>();
    let (terminate_tx, terminate_rx) = unbounded::<()>();

    ctrlc::set_handler(move || {
        let _ = terminate_tx.send(());
    })
    .map_err(|error| MainError::SignalHandler(error.to_string()))?;

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
                            continue;
                        }
                        let update = monitor
                            .resolve_event_action(&runtime_state, event)
                            .map(|action| action.is_some_and(|value| runtime_state.apply_action(value)));
                        publish_warnings(&mut monitor, &bus);
                        match update {
                            Ok(false) => trace!("docker event produced no policy state changes"),
                            Ok(true) => {
                                if let Err(error) = applier.apply(&mut runtime_state) {
                                    error!(%error, "firewall apply failed; continuing");
                                }
                            }
                            Err(error) => error!(%error, "runtime state refresh failed; continuing"),
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
                                        publish_warnings(&mut monitor, &bus);
                                        if let Err(error) = applier.apply(&mut runtime_state) {
                                            error!(%error, "firewall apply failed after reconnect; continuing");
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
        }
    }

    let _ = docker_stop_tx.send(());
    let _ = docker_thread.join();

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
        let config = parse_config(Arguments::from_vec(Vec::new())).ok();
        assert_eq!(config, Some(Config::default()));
    }

    #[test]
    fn parse_config_reads_all_values() {
        let args = Arguments::from_vec(
            [
                "--docker-socket",
                "/tmp/docker.sock",
                "--events-socket",
                "/run/portcullis.sock",
                "--deny-action",
                "drop",
                "--monitor",
                "--log-allowed",
                "always",
                "--hostname-hold",
                "60",
                "--alert-exec",
                "notify-send",
                "--alert-interval",
                "30",
                "--log-level",
                "debug",
                "--log-format",
                "json",
            ]
            .into_iter()
            .map(OsString::from)
            .collect(),
        );
        assert_eq!(
            parse_config(args).ok(),
            Some(Config {
                docker_socket: "/tmp/docker.sock".to_string(),
                events_socket: Some(PathBuf::from("/run/portcullis.sock")),
                deny_action: DenyAction::Drop,
                monitor: true,
                log_allowed: LogAllowed::Always,
                hostname_hold: Duration::from_secs(60),
                alert_exec: Some("notify-send".to_string()),
                alert_interval: Duration::from_secs(30),
                log_level: LogLevel::Debug,
                log_format: LogFormat::Json,
            })
        );
    }

    #[test]
    fn parse_config_rejects_invalid_values() {
        for (flag, value) in [
            ("--deny-action", "bad"),
            ("--log-allowed", "bad"),
            ("--log-format", "bad"),
            ("--hostname-hold", "soon"),
        ] {
            let args = Arguments::from_vec(vec![flag.into(), value.into()]);
            assert!(parse_config(args).is_err(), "{flag} {value}");
        }
    }

    #[test]
    fn parse_config_rejects_unknown_arguments() {
        let args = Arguments::from_vec(vec!["--bogus".into()]);
        assert!(matches!(
            parse_config(args),
            Err(MainError::UnexpectedArguments(_))
        ));
    }
}
