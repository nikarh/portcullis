use thiserror::Error;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("failed to initialize tracing subscriber: {0}")]
    Init(String),
}

pub fn init_logging() -> Result<(), LoggingError> {
    let filter = default_env_filter();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .try_init()
        .map_err(|error| LoggingError::Init(error.to_string()))
}

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
}
