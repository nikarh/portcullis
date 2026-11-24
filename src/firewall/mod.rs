mod elements;
#[cfg(test)]
mod kernel_tests;
mod netlink;
mod nftables;
mod plan;
mod ruleset;
#[cfg(test)]
pub mod test_support;

use thiserror::Error;

pub use elements::SetLookup;
pub use nftables::{
    CtMarkBits, DEFAULT_CONNECTION_LIMIT, DEFAULT_CT_MARK_MASK, DNS_ALLOWED_MARK, DNS_DENIED_MARK,
    DenyAction, HOLD_EXPIRED_MARK, LOG_PREFIX, LogAllowed, NAME_ALLOWED_MARK, NAME_DENIED_MARK,
    NAME_WATCH_MARK, NameChecks, NftablesFirewall, Options, Restored, Update,
};
#[cfg(test)]
pub use plan::HostSetId;
pub use plan::{
    Destination, HostSet, PRIVATE_V4, PRIVATE_V6, Plan, Rule, SET_PREFIX_V4, SET_PREFIX_V6, Source,
};
pub use ruleset::TABLE_NAME;

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
