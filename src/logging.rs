use std::str::FromStr;

use thiserror::Error;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("failed to initialize tracing subscriber: {0}")]
    Init(String),
    #[error("invalid log level: {0}")]
    InvalidLogLevel(String),
    #[error("invalid log format: {0}")]
    InvalidLogFormat(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    const fn as_filter_value(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

impl FromStr for LogLevel {
    type Err = LoggingError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(LoggingError::InvalidLogLevel(value.to_string())),
        }
    }
}

/// Output format of diagnostic logs and of events written to stdout.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

impl FromStr for LogFormat {
    type Err = LoggingError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => Err(LoggingError::InvalidLogFormat(value.to_string())),
        }
    }
}

/// Diagnostic logs go to stderr; stdout carries events (see `events`).
pub fn init_logging(level: LogLevel, format: LogFormat) -> Result<(), LoggingError> {
    let filter = EnvFilter::new(format!(
        "{},portcullis={}",
        level.as_filter_value(),
        level.as_filter_value()
    ));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_writer(std::io::stderr);
    match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    }
    .map_err(|error| LoggingError::Init(error.to_string()))
}

#[cfg(test)]
fn default_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,portcullis=info"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_env_filter_includes_portcullis_directive() {
        let filter = default_env_filter();
        let rendered = filter.to_string();
        assert!(rendered.contains("portcullis"));
    }

    #[test]
    fn parse_log_level_from_str() {
        let value = "debug".parse::<LogLevel>();
        assert_eq!(value.ok(), Some(LogLevel::Debug));
    }
}
