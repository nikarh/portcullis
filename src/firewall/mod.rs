mod elements;
mod netlink;
mod nftables;
mod plan;
mod ruleset;
#[cfg(test)]
pub mod test_support;

use thiserror::Error;

pub use nftables::{
    DEFAULT_CONNECTION_LIMIT, DNS_ALLOWED_MARK, DNS_DENIED_MARK, DenyAction, HOLD_EXPIRED_MARK,
    LOG_PREFIX, LogAllowed, NftablesFirewall, Options, Restored, Update,
};
#[cfg(test)]
pub use plan::HostSetId;
pub use plan::{Destination, HostSet, PRIVATE_V4, PRIVATE_V6, Plan, Rule};

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("nftables netlink request failed: {0}")]
    Netlink(std::io::Error),
    #[error("the kernel refused `{command}`: {error}{}", reason.as_ref().map(|reason| format!(" ({reason})")).unwrap_or_default())]
    Refused {
        /// The command, as an nft script would have it.
        command: String,
        error: std::io::Error,
        /// The kernel's explanation, if any.
        reason: Option<String>,
    },
    #[error("saved rules: {0}")]
    Saved(std::io::Error),
}
