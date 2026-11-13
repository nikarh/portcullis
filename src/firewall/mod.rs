mod elements;
mod nftables;
mod plan;
#[cfg(test)]
pub mod test_support;

use thiserror::Error;

pub use nftables::{
    DEFAULT_CONNECTION_LIMIT, DNS_ALLOWED_MARK, DNS_DENIED_MARK, DenyAction, HOLD_EXPIRED_MARK,
    LOG_PREFIX, LogAllowed, NftablesFirewall, Options, Restored,
};
#[cfg(test)]
pub use plan::HostSetId;
pub use plan::{Destination, HostSet, PRIVATE_V4, PRIVATE_V6, Plan, Rule};

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
    #[error("nftables netlink request failed: {0}")]
    Netlink(std::io::Error),
    #[error("saved rules: {0}")]
    Saved(std::io::Error),
}
