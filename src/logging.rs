use std::str::FromStr;

use thiserror::Error;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("failed to initialize tracing subscriber: {0}")]
    Init(String),
    #[error("invalid log level: {0}")]
    InvalidLogLevel(String),
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

pub fn init_logging_with_level(level: LogLevel) -> Result<(), LoggingError> {
    let filter = EnvFilter::new(format!(
        "{},portcullis={}",
        level.as_filter_value(),
        level.as_filter_value()
    ));
    init_subscriber(filter)
}

fn init_subscriber(filter: EnvFilter) -> Result<(), LoggingError> {
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .try_init()
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
