use std::collections::BTreeMap;
use std::net::IpAddr;

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize)]
pub struct DockerContainerSummary {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Names")]
    pub names: Option<Vec<String>>,
    #[serde(rename = "Labels", default)]
    pub labels: IndexMap<String, String>,
    #[serde(rename = "HostConfig")]
    pub host_config: Option<DockerHostConfig>,
    #[serde(rename = "NetworkSettings")]
    pub network_settings: Option<DockerContainerSummaryNetworkSettings>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerContainerSummaryNetworkSettings {
    #[serde(rename = "Networks")]
    pub networks: Option<BTreeMap<String, DockerContainerSummaryEndpoint>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerContainerSummaryEndpoint {
    #[serde(rename = "NetworkID")]
    pub network_id: Option<String>,
    #[serde(rename = "IPAddress")]
    #[serde(deserialize_with = "deserialize_optional_ipaddr")]
    pub ip_address: Option<IpAddr>,
    #[serde(rename = "Aliases")]
    pub aliases: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerContainerInspect {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Config", default)]
    pub config: DockerContainerConfig,
    #[serde(rename = "HostConfig")]
    pub host_config: Option<DockerHostConfig>,
    #[serde(rename = "NetworkSettings")]
    pub network_settings: Option<DockerNetworkSettings>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DockerContainerConfig {
    #[serde(rename = "Labels", default)]
    pub labels: IndexMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerHostConfig {
    #[serde(rename = "Dns")]
    pub dns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerNetworkSettings {
    #[serde(rename = "Networks")]
    pub networks: Option<BTreeMap<String, DockerEndpoint>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerEndpoint {
    #[serde(rename = "NetworkID")]
    pub network_id: Option<String>,
    #[serde(rename = "IPAddress")]
    #[serde(deserialize_with = "deserialize_optional_ipaddr")]
    pub ip_address: Option<IpAddr>,
    #[serde(rename = "Aliases")]
    pub aliases: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerNetworkInspect {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Driver")]
    pub driver: DockerNetworkDriver,
    #[serde(rename = "IPAM")]
    pub ipam: Option<DockerIpam>,
    #[serde(rename = "Labels")]
    pub labels: Option<IndexMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerNetworkDriver {
    Bridge,
    Host,
    Ipvlan,
    Macvlan,
    None,
    Overlay,
    Other(String),
}

impl DockerNetworkDriver {
    #[must_use]
    pub fn is_bridge(&self) -> bool {
        matches!(self, Self::Bridge)
    }
}

impl From<String> for DockerNetworkDriver {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "bridge" => Self::Bridge,
            "host" => Self::Host,
            "ipvlan" => Self::Ipvlan,
            "macvlan" => Self::Macvlan,
            "none" | "null" => Self::None,
            "overlay" => Self::Overlay,
            _ => Self::Other(value),
        }
    }
}

impl<'de> Deserialize<'de> for DockerNetworkDriver {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from(value))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerIpam {
    #[serde(rename = "Config")]
    pub config: Option<Vec<DockerIpamConfig>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerIpamConfig {
    #[serde(rename = "Subnet")]
    pub subnet: Option<String>,
    #[serde(rename = "Gateway")]
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DockerInfo {
    #[serde(rename = "FirewallBackend")]
    pub firewall_backend: Option<DockerFirewallInfo>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum DockerFirewallInfo {
    Value(String),
    Object {
        #[serde(rename = "Driver")]
        driver: Option<String>,
        #[serde(rename = "Backend")]
        backend: Option<String>,
        #[serde(rename = "Name")]
        name: Option<String>,
    },
}

impl DockerFirewallInfo {
    #[must_use]
    pub fn into_backend(self) -> Option<String> {
        match self {
            Self::Value(value) => Some(value),
            Self::Object {
                driver,
                backend,
                name,
            } => driver.or(backend).or(name),
        }
    }
}

fn deserialize_optional_ipaddr<'de, D>(deserializer: D) -> Result<Option<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<IpAddr>()
        .map(Some)
        .map_err(serde::de::Error::custom)
}
