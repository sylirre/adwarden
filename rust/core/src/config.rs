//! Runtime configuration handed from Kotlin as JSON at session start and on
//! updates.

use serde::Deserialize;

fn default_mtu() -> usize {
    1500
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_mtu")]
    pub mtu: usize,
    /// Upstream resolvers advertised on the TUN, used by the DNS sinkhole to
    /// forward allowed queries (P1-B).
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub block_encrypted_dns: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config { mtu: default_mtu(), dns_servers: Vec::new(), block_encrypted_dns: false }
    }
}

impl Config {
    pub fn from_json(s: &str) -> Config {
        serde_json::from_str(s).unwrap_or_default()
    }
}
