//! The daemon's settings: defaults, then the config file, then command line flags, each
//! overriding the one before.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use pico_args::Arguments;
use serde::Deserialize;
use thiserror::Error;

use crate::firewall::{self, DenyAction, LogAllowed};
use crate::logging::{LogFormat, LogLevel};
use crate::tools;

/// Read when it exists, unless `--config` names another file.
pub const DEFAULT_CONFIG: &str = "/etc/portcullis/config.toml";
pub const DEFAULT_STATE_DIR: &str = "/var/lib/portcullis";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub docker_socket: String,
    pub events_socket: Option<PathBuf>,
    pub deny_action: DenyAction,
    pub monitor: bool,
    /// Networks managed in monitor mode without a `portcullis.enable` label, by name; `*`
    /// is every bridge network.
    pub monitor_networks: Vec<String>,
    pub log_allowed: LogAllowed,
    pub hostname_hold: Duration,
    pub alert_exec: Option<String>,
    pub alert_interval: Duration,
    pub log_level: LogLevel,
    pub log_format: LogFormat,
    pub on_exit: OnExit,
    pub connection_limit: Option<u32>,
    pub quarantine: QuarantineMode,
    pub quarantine_denials: usize,
    pub state_dir: PathBuf,
}

/// What happens to a container that misbehaves, see `quarantine`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum QuarantineMode {
    /// Cut it off from its networks until it restarts.
    #[default]
    Isolate,
    /// Only report that it would be.
    Report,
    Off,
}

/// What happens to the firewall rules when Portcullis stops.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OnExit {
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
            monitor_networks: Vec::new(),
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
pub enum ConfigError {
    #[error("argument parsing failed: {0}")]
    Args(#[from] pico_args::Error),
    #[error("unexpected arguments: {0:?}")]
    UnexpectedArguments(Vec<OsString>),
    #[error("failed to read {path}: {error}")]
    Read {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("invalid config file {path}: {error}")]
    Parse {
        path: PathBuf,
        error: Box<toml::de::Error>,
    },
    #[error("invalid {setting} value: {value}, expected {expected}")]
    Invalid {
        setting: String,
        value: String,
        expected: &'static str,
    },
}

/// Settings as given in the config file or on the command line, before they are checked.
/// Keys are the flags without their `--`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct Settings {
    docker_socket: Option<String>,
    events_socket: Option<PathBuf>,
    deny_action: Option<String>,
    monitor: Option<bool>,
    monitor_networks: Option<Vec<String>>,
    log_allowed: Option<String>,
    hostname_hold: Option<u64>,
    alert_exec: Option<String>,
    alert_interval: Option<u64>,
    log_level: Option<String>,
    log_format: Option<String>,
    on_exit: Option<String>,
    connection_limit: Option<Limit>,
    quarantine: Option<String>,
    quarantine_denials: Option<usize>,
    state_dir: Option<PathBuf>,
}

/// A number, or a word such as `none`.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Limit {
    Number(i64),
    Word(String),
}

impl FromStr for Limit {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(value
            .parse()
            .map_or_else(|_| Self::Word(value.to_string()), Self::Number))
    }
}

impl std::fmt::Display for Limit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Number(number) => write!(formatter, "{number}"),
            Self::Word(word) => formatter.write_str(word),
        }
    }
}

/// Where settings came from, to name them in errors as the user wrote them.
enum Origin<'a> {
    Flags,
    File(&'a Path),
}

impl Origin<'_> {
    fn setting(&self, key: &str) -> String {
        match self {
            Self::Flags => format!("--{key}"),
            Self::File(path) => format!("{key} (in {})", path.display()),
        }
    }
}

/// The daemon's config: the defaults, overridden by the config file (`--config`, or
/// `DEFAULT_CONFIG` if it exists), overridden by flags.
pub fn load(mut args: Arguments) -> Result<Config, ConfigError> {
    let mut config = Config::default();
    let (path, file) = read_file(&mut args)?;
    config.apply(file, &Origin::File(&path))?;
    let flags = flags(&mut args)?;
    finish(args)?;
    config.apply(flags, &Origin::Flags)?;
    Ok(config)
}

/// The events socket `portcullis watch` connects to: `--events-socket`, or the daemon's
/// from the config file, or the default one of the service.
pub fn watch_socket(mut args: Arguments) -> Result<PathBuf, ConfigError> {
    let (_, file) = read_file(&mut args)?;
    let socket = args.opt_value_from_str::<_, PathBuf>("--events-socket")?;
    finish(args)?;
    Ok(socket
        .or(file.events_socket)
        .unwrap_or_else(|| PathBuf::from(tools::DEFAULT_EVENTS_SOCKET)))
}

/// The state directory `portcullis cleanup` removes saved rules from: `--state-dir`, or
/// the daemon's from the config file, or the default.
pub fn cleanup_state_dir(mut args: Arguments) -> Result<PathBuf, ConfigError> {
    let (_, file) = read_file(&mut args)?;
    let state_dir = args.opt_value_from_str::<_, PathBuf>("--state-dir")?;
    finish(args)?;
    Ok(state_dir
        .or(file.state_dir)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR)))
}

pub fn finish(args: Arguments) -> Result<(), ConfigError> {
    let remaining = args.finish();
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::UnexpectedArguments(remaining))
    }
}

/// The settings of the config file named by `--config`, or of `DEFAULT_CONFIG`. Only the
/// default one may be missing.
fn read_file(args: &mut Arguments) -> Result<(PathBuf, Settings), ConfigError> {
    let explicit = args.opt_value_from_str::<_, PathBuf>("--config")?;
    let path = explicit
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG));
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let settings = parse_file(&text).map_err(|error| ConfigError::Parse {
                path: path.clone(),
                error: Box::new(error),
            })?;
            Ok((path, settings))
        }
        Err(error) if explicit.is_none() && error.kind() == std::io::ErrorKind::NotFound => {
            Ok((path, Settings::default()))
        }
        Err(error) => Err(ConfigError::Read { path, error }),
    }
}

fn parse_file(text: &str) -> Result<Settings, toml::de::Error> {
    toml::from_str(text)
}

fn flags(args: &mut Arguments) -> Result<Settings, ConfigError> {
    Ok(Settings {
        docker_socket: args.opt_value_from_str("--docker-socket")?,
        events_socket: args.opt_value_from_str("--events-socket")?,
        deny_action: args.opt_value_from_str("--deny-action")?,
        monitor: args.contains("--monitor").then_some(true),
        monitor_networks: Some(args.values_from_str::<_, String>("--monitor-network")?)
            .filter(|names| !names.is_empty()),
        log_allowed: args.opt_value_from_str("--log-allowed")?,
        hostname_hold: args.opt_value_from_str("--hostname-hold")?,
        alert_exec: args.opt_value_from_str("--alert-exec")?,
        alert_interval: args.opt_value_from_str("--alert-interval")?,
        log_level: args.opt_value_from_str("--log-level")?,
        log_format: args.opt_value_from_str("--log-format")?,
        on_exit: args.opt_value_from_str("--on-exit")?,
        connection_limit: args.opt_value_from_str("--connection-limit")?,
        quarantine: args.opt_value_from_str("--quarantine")?,
        quarantine_denials: args.opt_value_from_str("--quarantine-denials")?,
        state_dir: args.opt_value_from_str("--state-dir")?,
    })
}

impl Config {
    fn apply(&mut self, settings: Settings, origin: &Origin<'_>) -> Result<(), ConfigError> {
        let invalid = |key: &str, value: String, expected: &'static str| ConfigError::Invalid {
            setting: origin.setting(key),
            value,
            expected,
        };

        if let Some(socket) = settings.docker_socket {
            self.docker_socket = socket;
        }
        if let Some(socket) = settings.events_socket {
            self.events_socket = Some(socket);
        }
        if let Some(value) = settings.deny_action {
            self.deny_action = match value.as_str() {
                "reject" => DenyAction::Reject,
                "drop" => DenyAction::Drop,
                _ => return Err(invalid("deny-action", value, "reject or drop")),
            };
        }
        if let Some(monitor) = settings.monitor {
            self.monitor = monitor;
        }
        if let Some(names) = settings.monitor_networks {
            self.monitor_networks = network_names(names, origin)?;
        }
        if let Some(value) = settings.log_allowed {
            self.log_allowed = match value.as_str() {
                "always" => LogAllowed::Always,
                "monitor" => LogAllowed::Monitor,
                "never" => LogAllowed::Never,
                _ => return Err(invalid("log-allowed", value, "always, monitor or never")),
            };
        }
        if let Some(seconds) = settings.hostname_hold {
            self.hostname_hold = Duration::from_secs(seconds);
        }
        if let Some(command) = settings.alert_exec {
            self.alert_exec = Some(command);
        }
        if let Some(seconds) = settings.alert_interval {
            self.alert_interval = Duration::from_secs(seconds);
        }
        if let Some(value) = settings.log_level {
            self.log_level = LogLevel::from_str(&value)
                .map_err(|_| invalid("log-level", value, "error, warn, info, debug or trace"))?;
        }
        if let Some(value) = settings.log_format {
            self.log_format = LogFormat::from_str(&value)
                .map_err(|_| invalid("log-format", value, "text or json"))?;
        }
        if let Some(value) = settings.on_exit {
            self.on_exit = match value.as_str() {
                "keep" => OnExit::Keep,
                "remove" => OnExit::Remove,
                _ => return Err(invalid("on-exit", value, "keep or remove")),
            };
        }
        if let Some(limit) = settings.connection_limit {
            self.connection_limit = match &limit {
                Limit::Word(word) if word == "none" => None,
                Limit::Number(number) => Some(
                    u32::try_from(*number)
                        .ok()
                        .filter(|limit| *limit > 0)
                        .ok_or_else(|| {
                            invalid(
                                "connection-limit",
                                limit.to_string(),
                                "a positive number or none",
                            )
                        })?,
                ),
                Limit::Word(_) => {
                    return Err(invalid(
                        "connection-limit",
                        limit.to_string(),
                        "a positive number or none",
                    ));
                }
            };
        }
        if let Some(value) = settings.quarantine {
            self.quarantine = match value.as_str() {
                "isolate" => QuarantineMode::Isolate,
                "report" => QuarantineMode::Report,
                "off" => QuarantineMode::Off,
                _ => return Err(invalid("quarantine", value, "isolate, report or off")),
            };
        }
        if let Some(count) = settings.quarantine_denials {
            self.quarantine_denials = count;
        }
        if let Some(directory) = settings.state_dir {
            self.state_dir = directory;
        }
        Ok(())
    }
}

/// The names of `monitor-networks`, none of them empty.
fn network_names(names: Vec<String>, origin: &Origin<'_>) -> Result<Vec<String>, ConfigError> {
    match names.iter().find(|name| name.trim().is_empty()) {
        Some(name) => Err(ConfigError::Invalid {
            setting: origin.setting(match origin {
                Origin::Flags => "monitor-network",
                Origin::File(_) => "monitor-networks",
            }),
            value: format!("{name:?}"),
            expected: "a network name or *",
        }),
        None => Ok(names),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Arguments {
        Arguments::from_vec(values.iter().map(OsString::from).collect())
    }

    fn all_set() -> Config {
        Config {
            docker_socket: "/tmp/docker.sock".to_string(),
            events_socket: Some(PathBuf::from("/run/portcullis.sock")),
            deny_action: DenyAction::Drop,
            monitor: true,
            monitor_networks: vec!["backend".to_string(), "frontend".to_string()],
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
        }
    }

    fn from_file(text: &str) -> Result<Config, ConfigError> {
        let settings = parse_file(text).map_err(|error| ConfigError::Parse {
            path: PathBuf::from("test.toml"),
            error: Box::new(error),
        })?;
        let mut config = Config::default();
        config.apply(settings, &Origin::File(Path::new("test.toml")))?;
        Ok(config)
    }

    fn from_flags(values: &[&str]) -> Result<Config, ConfigError> {
        let mut args = args(values);
        let settings = flags(&mut args)?;
        finish(args)?;
        let mut config = Config::default();
        config.apply(settings, &Origin::Flags)?;
        Ok(config)
    }

    #[test]
    fn defaults_without_flags_or_file() {
        assert_eq!(from_flags(&[]).ok(), Some(Config::default()));
        assert_eq!(from_file("").ok(), Some(Config::default()));
    }

    #[test]
    fn reads_all_flags() {
        let config = from_flags(&[
            "--docker-socket",
            "/tmp/docker.sock",
            "--events-socket",
            "/run/portcullis.sock",
            "--deny-action",
            "drop",
            "--monitor",
            "--monitor-network",
            "backend",
            "--monitor-network",
            "frontend",
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
        ]);
        assert_eq!(config.ok(), Some(all_set()));
    }

    #[test]
    fn reads_all_file_settings() {
        let config = from_file(
            r#"
            docker-socket = "/tmp/docker.sock"
            events-socket = "/run/portcullis.sock"
            deny-action = "drop"
            monitor = true
            monitor-networks = ["backend", "frontend"]
            log-allowed = "always"
            hostname-hold = 60
            alert-exec = "notify-send"
            alert-interval = 30
            log-level = "debug"
            log-format = "json"
            on-exit = "remove"
            connection-limit = 100
            quarantine = "report"
            quarantine-denials = 5
            state-dir = "/tmp/portcullis"
            "#,
        );
        assert_eq!(config.ok(), Some(all_set()));
    }

    #[test]
    fn connection_limit_can_be_none() {
        let config = from_file(r#"connection-limit = "none""#);
        assert_eq!(
            config.ok().map(|config| config.connection_limit),
            Some(None)
        );
        let config = from_flags(&["--connection-limit", "none"]);
        assert_eq!(
            config.ok().map(|config| config.connection_limit),
            Some(None)
        );
    }

    #[test]
    fn flags_override_the_file() {
        let mut config = from_file("monitor = true\ndeny-action = \"drop\"").unwrap_or_default();
        let mut flags_args = args(&["--deny-action", "reject"]);
        let settings = flags(&mut flags_args);
        assert!(settings.is_ok());
        if let Ok(settings) = settings {
            assert!(config.apply(settings, &Origin::Flags).is_ok());
        }
        assert!(config.monitor);
        assert_eq!(config.deny_action, DenyAction::Reject);
    }

    #[test]
    fn rejects_invalid_flag_values() {
        for (flag, value) in [
            ("--deny-action", "bad"),
            ("--log-allowed", "bad"),
            ("--log-format", "bad"),
            ("--log-level", "bad"),
            ("--on-exit", "bad"),
            ("--quarantine", "bad"),
            ("--hostname-hold", "soon"),
            ("--connection-limit", "0"),
            ("--connection-limit", "many"),
            ("--monitor-network", ""),
        ] {
            assert!(from_flags(&[flag, value]).is_err(), "{flag} {value}");
        }
    }

    #[test]
    fn rejects_invalid_file_settings() {
        for text in [
            r#"deny-action = "bad""#,
            r#"hostname-hold = "soon""#,
            "monitor = \"yes\"",
            "connection-limit = -1",
            "connection-limit = 0",
            r#"connection-limit = "many""#,
            "bogus = 1",
            "not toml",
        ] {
            assert!(from_file(text).is_err(), "{text}");
        }
    }

    #[test]
    fn names_the_setting_as_written() {
        let error = from_file(r#"deny-action = "bad""#)
            .err()
            .map(|e| e.to_string());
        assert_eq!(
            error.as_deref(),
            Some("invalid deny-action (in test.toml) value: bad, expected reject or drop")
        );
        let error = from_flags(&["--deny-action", "bad"])
            .err()
            .map(|e| e.to_string());
        assert_eq!(
            error.as_deref(),
            Some("invalid --deny-action value: bad, expected reject or drop")
        );
    }

    #[test]
    fn rejects_unknown_flags() {
        assert!(matches!(
            from_flags(&["--bogus"]),
            Err(ConfigError::UnexpectedArguments(_))
        ));
    }

    #[test]
    fn explicit_config_must_exist() {
        let result = load(args(&["--config", "/nonexistent/portcullis.toml"]));
        assert!(matches!(result, Err(ConfigError::Read { .. })));
    }

    #[test]
    fn shipped_config_is_the_defaults_plus_the_events_socket() {
        let config = from_file(include_str!("../dist/config.toml"));
        assert_eq!(
            config.ok(),
            Some(Config {
                events_socket: Some(PathBuf::from(tools::DEFAULT_EVENTS_SOCKET)),
                ..Config::default()
            })
        );
    }
}
