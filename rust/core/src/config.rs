// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! Runtime configuration handed from Kotlin as JSON at session start and on
//! updates.

use serde::Deserialize;

use crate::proxy::ProxyConfig;

fn default_mtu() -> usize {
    1500
}

fn default_dns_port() -> u16 {
    53
}

/// How the datapath treats encrypted DNS (DoT/DoH). `Off` leaves it untouched;
/// `Block` drops it so clients fall back to plaintext we can filter; `Filter`
/// TLS-intercepts it and runs the inner queries through the blocklist engine,
/// degrading to a drop whenever a flow can't be intercepted (no CA, pinning,
/// Private DNS strict, ECH, QUIC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptedDnsMode {
    #[default]
    Off,
    Block,
    Filter,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_mtu")]
    pub mtu: usize,
    /// Upstream resolver(s) the DNS sinkhole forwards allowed queries to (P1-B).
    /// A single IP literal (v4 or v6) is the norm; the first parseable entry wins.
    /// Empty ⇒ the built-in public default (Cloudflare).
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// Port to reach the upstream resolver on (P6). Default 53; a custom port lets
    /// users point at a self-hosted resolver (Pi-hole/AdGuard Home) on a
    /// non-standard port. Live-updatable. `0` is treated as 53.
    #[serde(default = "default_dns_port")]
    pub dns_port: u16,
    /// Encrypted-DNS handling (DoT/DoH). Absent/unknown ⇒ `Off`.
    #[serde(default)]
    pub encrypted_dns_mode: EncryptedDnsMode,
    /// TLS interception (P2): terminate & re-originate HTTPS so the datapath
    /// sees cleartext. Requires the CA PEMs below; a start-time setting.
    #[serde(default)]
    pub intercept_tls: bool,
    /// The interception root CA, PEM-encoded. `ca_key_pem` is app-private.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    #[serde(default)]
    pub ca_key_pem: Option<String>,
    /// Whether the live traffic log / a capture is open (P3-4). When false (and
    /// no app is engaged) the datapath coalesces allowed-flow telemetry into
    /// coarse aggregates and relaxes its wakeup cadence. Driven live via
    /// [`crate::runtime::Command::SetLogOpen`]; the start value is just the seed.
    #[serde(default)]
    pub log_open: bool,
    /// Element hiding (P4): inject hostname cosmetic CSS into `text/html` on
    /// inspected flows. Off leaves today's behavior exactly. Driven live via
    /// [`crate::runtime::Command::SetCosmetic`].
    #[serde(default)]
    pub cosmetic_element_hiding: bool,
    /// Scriptlet injection (P4): inject scriptlet JS. Requires
    /// `cosmetic_element_hiding` and a loaded scriptlet resource pack. Off by default.
    #[serde(default)]
    pub cosmetic_scriptlets: bool,
    /// Upstream proxy (P5): forward allowed flows through an HTTP/HTTPS/SOCKS5
    /// proxy instead of dialing origins directly. A start-time setting (the dial
    /// path is fixed for a session); toggling it takes effect on the next VPN
    /// start / re-establish. Absent ⇒ disabled (direct).
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Route DNS through an HTTP/HTTPS proxy via DNS-over-TCP (P5) rather than
    /// resolving it directly. Only affects HTTP/HTTPS proxies — a SOCKS5 proxy
    /// always carries DNS over UDP ASSOCIATE. Live-updatable. Off by default: it
    /// requires the proxy to permit CONNECT to the resolver's port (53), which
    /// many forward proxies refuse, so it's opt-in.
    #[serde(default)]
    pub proxy_dns_over_tcp: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mtu: default_mtu(),
            dns_servers: Vec::new(),
            dns_port: default_dns_port(),
            encrypted_dns_mode: EncryptedDnsMode::Off,
            intercept_tls: false,
            ca_cert_pem: None,
            ca_key_pem: None,
            log_open: false,
            cosmetic_element_hiding: false,
            cosmetic_scriptlets: false,
            proxy: ProxyConfig::default(),
            proxy_dns_over_tcp: false,
        }
    }
}

impl Config {
    pub fn from_json(s: &str) -> Config {
        serde_json::from_str(s).unwrap_or_default()
    }
}
