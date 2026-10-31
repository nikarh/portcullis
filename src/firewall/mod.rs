mod nftables;
mod plan;
#[cfg(test)]
mod test_support;

use thiserror::Error;

pub use nftables::{DenyAction, NftablesFirewall};

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("failed to format firewall script: {0}")]
    ScriptFormat(#[from] std::fmt::Error),
    #[error("failed to create libnftables context")]
    LibContextCreate,
    #[error("failed to configure libnftables {buffer}: return code {code}")]
    LibBufferConfig { buffer: &'static str, code: i32 },
    #[error("script contains NUL byte and cannot be passed to libnftables")]
    ScriptContainsNul,
    #[error("libnftables command failed with code {code}: {stderr}")]
    LibCommandFailure { code: i32, stderr: String },
    #[error("libnftables context lock poisoned")]
    LibContextLock,
}
