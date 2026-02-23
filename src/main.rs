use std::io::Write as _;
use std::process::Command;
use std::str::FromStr;

use pico_args::Arguments;
use thiserror::Error;
use tracing::{debug, error, info, trace};

use portcullis::dns::{DnsProxyCache, SystemUpstreamResolver};
use portcullis::firewall::{
    CommandIptablesRunner, FirewallError, IptablesFirewall, NftablesFirewall,
};
use portcullis::logging::{self, LogLevel, LoggingError};
use portcullis::monitor::{
    CommandDockerApi, CommandRunner, DockerFirewallBackend, DockerMonitor, MonitorError,
    RuntimeChangeTracker,
};

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

fn run(config: &Config) -> Result<(), MainError> {
    logging::init_logging_with_level(config.log_level)?;

    info!(
        docker_socket = %config.docker_socket,
        firewall_backend = ?config.firewall_backend,
        log_level = ?config.log_level,
        "portcullis prototype started"
    );

    let runner = DockerSocketCommandRunner::new(config.docker_socket.clone());
    let api = CommandDockerApi::new(runner);
    let monitor = DockerMonitor::new(api);
    let snapshot = monitor.snapshot()?;
    let detected_backend = monitor.firewall_backend()?;

    let mut tracker = RuntimeChangeTracker::new();
    let changes = tracker.detect_and_log(&snapshot);
    debug!(change_count = changes.len(), "runtime changes computed");
    trace!(?snapshot, "runtime snapshot for firewall apply");
    let mut dns_cache = DnsProxyCache::new(
        SystemUpstreamResolver,
        std::time::Duration::from_secs(300),
        2048,
    );

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

    match selected_backend {
        FirewallBackend::Auto => unreachable!("auto backend must be resolved before execution"),
        FirewallBackend::Nftables => {
            let firewall = NftablesFirewall::with_libnftables()?;
            firewall.apply_with_dns(&snapshot, &mut dns_cache)?;
        }
        FirewallBackend::Iptables => {
            let firewall = IptablesFirewall::<CommandIptablesRunner>::with_cli();
            firewall.apply_with_dns(&snapshot, &mut dns_cache)?;
        }
    }

    info!("firewall rules applied");
    Ok(())
}

#[derive(Debug, Clone)]
struct DockerSocketCommandRunner {
    docker_host: String,
}

impl DockerSocketCommandRunner {
    fn new(socket: String) -> Self {
        let docker_host = if socket.starts_with("unix://") {
            socket
        } else {
            format!("unix://{socket}")
        };
        Self { docker_host }
    }
}

impl CommandRunner for DockerSocketCommandRunner {
    fn run_capture(&self, program: &str, args: &[&str]) -> Result<String, MonitorError> {
        debug!(%program, ?args, docker_host = %self.docker_host, "running command with configured docker host");
        let output = Command::new(program)
            .args(args)
            .env("DOCKER_HOST", &self.docker_host)
            .output()
            .map_err(|error| MonitorError::CommandExecution {
                program: program.to_string(),
                message: error.to_string(),
            })?;

        if !output.status.success() {
            return Err(MonitorError::CommandFailure {
                program: program.to_string(),
                code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }

        String::from_utf8(output.stdout).map_err(|_| MonitorError::InvalidUtf8 {
            program: program.to_string(),
        })
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
    fn runner_normalizes_docker_socket() {
        let runner = DockerSocketCommandRunner::new("/var/run/docker.sock".to_string());
        assert_eq!(runner.docker_host, "unix:///var/run/docker.sock");
    }
}
