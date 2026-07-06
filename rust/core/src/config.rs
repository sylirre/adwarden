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
    /// TLS interception (P2): terminate & re-originate HTTPS so the datapath
    /// sees cleartext. Requires the CA PEMs below; a start-time setting.
    #[serde(default)]
    pub intercept_tls: bool,
    /// The interception root CA, PEM-encoded. `ca_key_pem` is app-private.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    #[serde(default)]
    pub ca_key_pem: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mtu: default_mtu(),
            dns_servers: Vec::new(),
            block_encrypted_dns: false,
            intercept_tls: false,
            ca_cert_pem: None,
            ca_key_pem: None,
        }
    }
}

impl Config {
    pub fn from_json(s: &str) -> Config {
        serde_json::from_str(s).unwrap_or_default()
    }
}
