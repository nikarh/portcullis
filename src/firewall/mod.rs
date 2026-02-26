mod iptables;
mod nftables;

use thiserror::Error;

use crate::dns::{DnsProxyCache, SystemUpstreamResolver};
use crate::model::RuntimeSnapshot;
use crate::monitor::RuntimeState;

pub use iptables::{CommandIptablesRunner, IptablesFirewall};
pub use nftables::NftablesFirewall;

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("failed to run firewall command: {0}")]
    CommandExecution(#[from] std::io::Error),
    #[error("failed to format firewall command script: {0}")]
    CommandScriptFormat(#[from] std::fmt::Error),
    #[error("{program} stdin unavailable")]
    CommandStdinUnavailable { program: &'static str },
    #[error("firewall command failed with code {code}: {stderr}")]
    CommandFailure { code: i32, stderr: String },
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
    #[error("dns resolve failed for host {host}: {message}")]
    DnsResolve { host: String, message: String },
}

pub enum ActiveFirewall {
    Nftables(NftablesFirewall),
    Iptables(IptablesFirewall<CommandIptablesRunner>),
}

impl ActiveFirewall {
    pub fn with_nftables() -> Result<Self, FirewallError> {
        Ok(Self::Nftables(NftablesFirewall::with_libnftables()?))
    }

    #[must_use]
    pub fn with_iptables() -> Self {
        Self::Iptables(IptablesFirewall::with_cli())
    }

    pub fn initialize(&self) -> Result<(), FirewallError> {
        match self {
            Self::Nftables(_) => Ok(()),
            Self::Iptables(firewall) => firewall.initialize(),
        }
    }

    /// Apply the firewall rules for the given `RuntimeSnapshot`.
    pub fn apply(
        &self,
        state: &RuntimeState,
        dns_cache: &mut DnsProxyCache<SystemUpstreamResolver>,
    ) -> Result<(), FirewallError> {
        match self {
            Self::Nftables(firewall) => firewall.apply(state, dns_cache),
            Self::Iptables(firewall) => firewall.apply(state, dns_cache),
        }
    }

    pub fn cleanup(&self) -> Result<(), FirewallError> {
        match self {
            Self::Nftables(firewall) => firewall.cleanup(),
            Self::Iptables(firewall) => firewall.cleanup(),
        }
    }
}
