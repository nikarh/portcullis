#![allow(clippy::multiple_crate_versions)]

mod checks;
mod connection_log;
mod conntrack;
mod directory;
mod dns;
mod dns_filter;
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
mod quarantine;
mod rtnetlink;
mod source_hold;
mod systemd;
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
use tracing::{debug, error, info, trace, warn};

use crate::connection_log::SharedHosts;
use crate::directory::Directory;
use crate::dns::{HostAddresses, SystemUpstreamResolver};
use crate::docker::{
    DockerClient, DockerError, DockerEvent, DockerEventAction, DockerEventClient, DockerEventKind,
};
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
/// File in the state directory the rules of every update are saved to.
const SAVED_RULES: &str = "rules.nft";
const DEFAULT_STATE_DIR: &str = "/var/lib/portcullis";
/// NFQUEUE number DNS queries of containers with `portcullis.domains` labels are held in.
const DNS_QUERY_QUEUE: u16 = 4244;
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
    on_exit: OnExit,
    connection_limit: Option<u32>,
    quarantine: QuarantineMode,
    quarantine_denials: usize,
    state_dir: PathBuf,
}

/// What happens to a container that misbehaves, see `quarantine`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum QuarantineMode {
    /// Cut it off from its networks until it restarts.
    #[default]
    Isolate,
    /// Only report that it would be.
    Report,
    Off,
}

/// What happens to the firewall rules when Portcullis stops.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum OnExit {
    /// Leave the last rules in place: containers stay restricted, and those that start
    /// meanwhile on an enforced network can't send at all. `portcullis cleanup` removes
    /// them.
    #[default]
    Keep,
    /// Remove all rules: containers are unrestricted until Portcullis runs again.
    Remove,
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
            on_exit: OnExit::Keep,
            connection_limit: Some(firewall::DEFAULT_CONNECTION_LIMIT),
            quarantine: QuarantineMode::Isolate,
            quarantine_denials: 1000,
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
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
    #[error("invalid --on-exit value: {0}")]
    InvalidOnExit(String),
    #[error("invalid --connection-limit value: {0}, expected a positive number or none")]
    InvalidConnectionLimit(String),
    #[error("invalid --quarantine value: {0}, expected isolate, report or off")]
    InvalidQuarantine(String),
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
    #[error("{0}; stopping, for the service manager to start Portcullis again")]
    Failed(String),
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
        Ok(Some(command)) if command == "cleanup" => run_cleanup(args),
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

/// Remove every rule Portcullis owns, and the saved ones, for when it isn't going to run
/// again.
fn run_cleanup(mut args: Arguments) -> Result<(), MainError> {
    let state_dir = args
        .opt_value_from_str::<_, PathBuf>("--state-dir")?
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
    finish(args)?;
    let firewall = NftablesFirewall::with_libnftables(Options::default())?
        .saving_to(state_dir.join(SAVED_RULES));
    firewall.cleanup()?;
    firewall.forget_saved()?;
    let _ = std::io::stdout().write_all(b"portcullis: firewall rules removed\n");
    Ok(())
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
    if let Some(value) = args.opt_value_from_str::<_, String>("--connection-limit")? {
        config.connection_limit = match value.as_str() {
            "none" => None,
            _ => Some(
                value
                    .parse::<u32>()
                    .ok()
                    .filter(|limit| *limit > 0)
                    .ok_or(MainError::InvalidConnectionLimit(value))?,
            ),
        };
    }
    if let Some(value) = args.opt_value_from_str::<_, String>("--quarantine")? {
        config.quarantine = match value.as_str() {
            "isolate" => QuarantineMode::Isolate,
            "report" => QuarantineMode::Report,
            "off" => QuarantineMode::Off,
            _ => return Err(MainError::InvalidQuarantine(value)),
        };
    }
    if let Some(count) = args.opt_value_from_str::<_, usize>("--quarantine-denials")? {
        config.quarantine_denials = count;
    }
    if let Some(directory) = args.opt_value_from_str::<_, PathBuf>("--state-dir")? {
        config.state_dir = directory;
    }
    if let Some(value) = args.opt_value_from_str::<_, String>("--on-exit")? {
        config.on_exit = match value.as_str() {
            "keep" => OnExit::Keep,
            "remove" => OnExit::Remove,
            _ => return Err(MainError::InvalidOnExit(value)),
        };
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
  portcullis cleanup [--state-dir <path>]
                                       remove all firewall rules Portcullis left in place,
                                       and the saved ones

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
  --connection-limit <n|none>  Open connections a container may have at a time, unless
                               its labels say otherwise (default: 16384)
  --quarantine <isolate|report|off>
                               Cut off containers that send with someone else's address
                               or MAC, or whose traffic is denied too often, until they
                               restart; or only report it (default: isolate)
  --quarantine-denials <n>     Denied connections per minute past which a container is
                               quarantined (default: 1000)
  --state-dir <path>           Where the rules are saved, to be put back first thing at
                               the next start (default: /var/lib/portcullis)
  --on-exit <keep|remove>      Keep the firewall rules in place when stopping, or remove
                               them (default: keep; remove them later with
                               portcullis cleanup)
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

/// Read Docker's events from `since` on (when the state was read), and send them on
/// `event_tx`. After the stream fails, events may have been missed: once it is back,
/// `Reconnected` says the state has to be read again.
fn spawn_docker_event_worker(
    docker_socket: String,
    since: Option<i64>,
    event_tx: Sender<DockerWorkerEvent>,
    stop_rx: Receiver<()>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut since = since;
        let mut missed = false;
        loop {
            let mut event_client = loop {
                if stop_requested(&stop_rx) {
                    return;
                }
                match DockerEventClient::connect(&docker_socket, since) {
                    Ok(client) => break client,
                    Err(error) => {
                        error!(%error, "docker event stream connect failed; retrying");
                        (since, missed) = (None, true);
                        if sleep_or_stop(&stop_rx, Duration::from_secs(1)) {
                            return;
                        }
                    }
                }
            };
            if missed && event_tx.send(DockerWorkerEvent::Reconnected).is_err() {
                return;
            }
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
                        (since, missed) = (None, true);
                        if sleep_or_stop(&stop_rx, Duration::from_secs(1)) {
                            return;
                        }
                        break;
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
                || container
                    .policy
                    .acknowledged
                    .contains(&WarningKind::DnsNotObservable)
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

/// Cut a misbehaving container off from its networks, or report that it would be.
fn quarantine_container(
    mode: QuarantineMode,
    misbehaviour: &quarantine::Misbehaviour,
    state: &mut RuntimeState,
    applier: &mut Applier,
    bus: &EventBus,
) {
    let Some(id) = state
        .containers()
        .values()
        .find(|container| *container.name == *misbehaviour.container)
        .map(|container| container.id.clone())
    else {
        return;
    };
    let message = match mode {
        QuarantineMode::Off => return,
        QuarantineMode::Report => format!(
            "would be cut off from its networks (--quarantine report): {}",
            misbehaviour.reason
        ),
        QuarantineMode::Isolate => {
            if !state.quarantine(&id) {
                return;
            }
            if let Err(error) = applier.apply(state) {
                error!(%error, "firewall apply failed; continuing");
            }
            format!(
                "cut off from its networks: {}. Restart the container to let it back",
                misbehaviour.reason
            )
        }
    };
    warn!(container = %misbehaviour.container, "{message}");
    bus.publish(&Event::Warning(Warning {
        kind: WarningKind::Quarantined,
        container: Some(misbehaviour.container.clone()),
        message,
    }));
}

fn publish_warnings<A: docker::DockerApi>(monitor: &mut DockerMonitor<A>, bus: &EventBus) {
    for warning in monitor.take_warnings() {
        bus.publish(&Event::Warning(warning));
    }
}

#[allow(clippy::too_many_lines)]
fn run(config: &Config) -> Result<(), MainError> {
    logging::init_logging(config.log_level, config.log_format)?;
    exit_on_panic();
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

    let firewall = Arc::new(
        NftablesFirewall::with_libnftables(Options {
            deny: config.deny_action,
            log_group: NFLOG_GROUP,
            log_allowed: config.log_allowed,
            dns_queue: Some(DNS_QUEUE),
            source_queue: Some(SOURCE_QUEUE),
            connection_limit: config.connection_limit,
            dns_query_queue: Some(DNS_QUERY_QUEUE),
        })?
        .saving_to(config.state_dir.join(SAVED_RULES)),
    );

    // Before anything else, put the last run's rules back: after a reboot there are none,
    // and Docker may be about to start containers. Their bridge ports are new, so their
    // packets are held until this run's first update has rules for them. That update
    // replaces these rules in one step.
    match firewall.restore() {
        Ok(true) => info!("restored the rules of the last run"),
        Ok(false) => info!("no rules of a last run to restore"),
        Err(error) => warn!(%error, "can't restore the rules of the last run"),
    }

    let directory = Arc::new(Directory::default());
    let hosts: SharedHosts = Arc::new(Mutex::new(HostAddresses::new(
        SystemUpstreamResolver,
        config.hostname_hold,
    )));
    let (misbehaviour_tx, misbehaviour_rx) = unbounded::<quarantine::Misbehaviour>();
    // Threads that read the kernel's queues and logs say here when they can't go on.
    let (failed_tx, failed_rx) = unbounded::<String>();
    connection_log::spawn(
        NFLOG_GROUP,
        Arc::clone(&directory),
        Arc::clone(&hosts),
        bus.clone(),
        (config.quarantine != QuarantineMode::Off)
            .then(|| quarantine::Watch::new(misbehaviour_tx, config.quarantine_denials)),
        failed_tx.clone(),
    )
    .map_err(MainError::ConnectionLog)?;
    dns_filter::spawn(
        DNS_QUERY_QUEUE,
        Arc::clone(&directory),
        bus.clone(),
        failed_tx.clone(),
    )
    .map_err(MainError::DnsInspection)?;
    dns_inspect::spawn(
        DNS_QUEUE,
        config.log_allowed,
        Arc::clone(&firewall),
        Arc::clone(&directory),
        Arc::clone(&hosts),
        bus.clone(),
        failed_tx.clone(),
    )
    .map_err(MainError::DnsInspection)?;

    let source_hold = source_hold::spawn(
        SOURCE_QUEUE,
        SOURCE_HOLD_GRACE,
        Arc::clone(&directory),
        failed_tx,
    )
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

    let (terminate_tx, terminate_rx) = unbounded::<()>();
    ctrlc::set_handler(move || {
        let _ = terminate_tx.send(());
    })
    .map_err(|error| MainError::SignalHandler(error.to_string()))?;

    // Ready: the rules are in place and their queues are read. Docker can start.
    systemd::notify("READY=1\nSTATUS=Waiting for Docker");
    let Some((mut monitor, mut runtime_state, since)) =
        wait_for_docker(config, &terminate_rx, &failed_rx)?
    else {
        return shut_down(config, &firewall);
    };
    systemd::notify("STATUS=Running");
    monitor.check_containers(&runtime_state);
    publish_warnings(&mut monitor, &bus);
    applier.apply(&mut runtime_state)?;

    let (docker_tx, docker_rx) = unbounded::<DockerWorkerEvent>();
    let (docker_stop_tx, docker_stop_rx) = unbounded::<()>();

    // Events from when the state was read on: a container started while the rules were
    // being applied isn't missed.
    let docker_thread = spawn_docker_event_worker(
        config.docker_socket.clone(),
        since,
        docker_tx,
        docker_stop_rx,
    );

    let outcome = loop {
        select! {
            recv(terminate_rx) -> _ => {
                info!("termination signal received; cleanup will start now");
                break Ok(());
            }
            recv(failed_rx) -> message => break Err(failure(message)),
            recv(misbehaviour_rx) -> message => {
                if let Ok(misbehaviour) = message {
                    quarantine_container(
                        config.quarantine,
                        &misbehaviour,
                        &mut runtime_state,
                        &mut applier,
                        &bus,
                    );
                }
            }
            recv(docker_rx) -> message => {
                let Ok(message) = message else {
                    break Ok(());
                };
                match message {
                    DockerWorkerEvent::Event(event) => {
                        trace!(event = ?event, "docker event received");
                        if event.kind == DockerEventKind::Container
                            && event.action == DockerEventAction::Start
                        {
                            monitor.check_container(&runtime_state, &event.id);
                            publish_warnings(&mut monitor, &bus);
                            // A restart starts it over from a clean state.
                            if runtime_state.release(&event.id.clone().into()) {
                                info!(container = %event.id, "quarantined container restarted; letting it back");
                                if let Err(error) = applier.apply(&mut runtime_state) {
                                    error!(%error, "firewall apply failed; continuing");
                                }
                            }
                        }
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
                                        monitor.check_containers(&runtime_state);
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
    };

    let _ = docker_stop_tx.send(());
    let _ = docker_thread.join();
    // A failure leaves the rules in place, whatever --on-exit says: Portcullis is about to
    // be started again.
    outcome?;
    shut_down(config, &firewall)
}

/// Why a thread Portcullis can't do without ended.
fn failure(message: Result<String, crossbeam_channel::RecvError>) -> MainError {
    MainError::Failed(
        message.unwrap_or_else(|_| "the threads reading the kernel's queues ended".to_string()),
    )
}

/// A panic anywhere stops Portcullis with an error, for its service manager to start it
/// again: a thread that ended on its own would leave it running without part of its job.
fn exit_on_panic() {
    std::panic::set_hook(Box::new(|info| {
        error!("{info}; stopping, for the service manager to start Portcullis again");
        std::process::exit(101);
    }));
}

/// Docker's state, and when it was read.
type Connected = (DockerMonitor<DockerClient>, RuntimeState, Option<i64>);

/// Connect to Docker and read its state, retrying until it answers: Portcullis starts
/// before Docker when it runs as a service. With the state, when it was read (see
/// `DockerEventClient::connect`). `None` when Portcullis is asked to stop first.
fn wait_for_docker(
    config: &Config,
    terminate_rx: &Receiver<()>,
    failed_rx: &Receiver<String>,
) -> Result<Option<Connected>, MainError> {
    const FIRST_RETRY: Duration = Duration::from_millis(250);
    const LAST_RETRY: Duration = Duration::from_secs(5);
    let mut retry = FIRST_RETRY;
    let mut waiting = false;
    loop {
        let since = docker::events::current_unix_epoch_seconds().ok();
        let attempt = DockerClient::connect(&config.docker_socket)
            .map_err(MonitorError::from)
            .and_then(|client| {
                let mut monitor = DockerMonitor::new(client);
                monitor.initialize().map(|state| (monitor, state, since))
            });
        match attempt {
            Ok(connected) => {
                if waiting {
                    info!("Docker is up");
                }
                return Ok(Some(connected));
            }
            Err(error) if !waiting => {
                waiting = true;
                warn!(%error, socket = %config.docker_socket, "waiting for Docker; the rules of the last run stay in place meanwhile");
            }
            Err(error) => debug!(%error, "Docker isn't up yet"),
        }
        select! {
            recv(terminate_rx) -> _ => return Ok(None),
            recv(failed_rx) -> message => return Err(failure(message)),
            default(retry) => {}
        }
        retry = (retry * 2).min(LAST_RETRY);
    }
}

/// Keep the rules in place when stopping, or remove them with `--on-exit remove` (and the
/// saved ones, so the next start doesn't bring them back).
fn shut_down(config: &Config, firewall: &NftablesFirewall) -> Result<(), MainError> {
    systemd::notify("STOPPING=1");
    if config.on_exit == OnExit::Keep {
        info!("stopped; firewall rules stay in place (remove them with portcullis cleanup)");
        return Ok(());
    }
    info!("shutdown requested; cleaning up firewall rules");
    firewall.cleanup()?;
    firewall.forget_saved()?;
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
                "--on-exit",
                "remove",
                "--connection-limit",
                "100",
                "--quarantine",
                "report",
                "--quarantine-denials",
                "5",
                "--state-dir",
                "/tmp/portcullis",
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
                on_exit: OnExit::Remove,
                connection_limit: Some(100),
                quarantine: QuarantineMode::Report,
                quarantine_denials: 5,
                state_dir: PathBuf::from("/tmp/portcullis"),
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
