//! Runtime certificate authority for TLS interception (P2).
//!
//! Adwarden mints a private root CA on first run. The user installs it (the
//! CA-install wizard walks them through it per Android version), after which the
//! device trusts the leaf certificates we generate on the fly for each
//! intercepted HTTPS host. Only apps that trust user-installed CAs and don't pin
//! are decryptable — that boundary is surfaced honestly in the UI; this crate is
//! just the certificate machinery.
//!
//! Responsibilities:
//! - generate a fresh root CA, and round-trip it to/from PEM so Kotlin can
//!   persist it (install-once) and export it to the user;
//! - mint a leaf certificate for a given SNI hostname, signed by the CA, cached
//!   so repeat visits don't re-run keygen on the datapath;
//! - hand rustls a [`rustls::server::ResolvesServerCert`] that does the minting
//!   as ClientHellos arrive.
//!
//! The `ring` crypto backend is pinned for both rcgen and rustls (see the
//! workspace manifest) so everything cross-compiles to the Android ABIs.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

mod mitm;
pub use mitm::{MitmIo, TlsMitm};

/// Build the rustls client config used to re-originate intercepted flows to the
/// real upstream, verifying the server against the bundled Mozilla root store
/// (webpki-roots). Sites rooted outside that set won't be decryptable — an
/// accepted limitation surfaced in the metadata-only fallback UX.
pub fn upstream_client_config() -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The rustls configs needed to intercept flows, bundled so callers (the native
/// core) don't depend on rustls directly. Build once per session from the CA
/// PEMs; cheap to mint a per-flow splice from.
pub struct MitmConfigs {
    server_config: Arc<rustls::ServerConfig>,
    client_config: Arc<rustls::ClientConfig>,
}

impl MitmConfigs {
    /// Load the CA from PEM and build the server (leaf-minting) and client
    /// (upstream-verifying) configs. Errors are human-readable for logging.
    pub fn build(ca_cert_pem: &str, ca_key_pem: &str) -> Result<Self, String> {
        let ca = Arc::new(
            CertAuthority::from_pem(ca_cert_pem, ca_key_pem).map_err(|e| format!("CA load: {e}"))?,
        );
        let server_config = ca.server_config().map_err(|e| format!("server config: {e}"))?;
        let client_config = upstream_client_config().map_err(|e| format!("client config: {e}"))?;
        Ok(MitmConfigs { server_config, client_config })
    }

    /// Start a fresh interception splice for one flow.
    pub fn new_splice(&self) -> Result<TlsMitm, rustls::Error> {
        TlsMitm::new(self.server_config.clone(), self.client_config.clone())
    }
}

/// Distinguished-name fields for the root CA. Kept fixed so that a CA restored
/// from a persisted key reconstructs an identical issuer identity (same subject
/// DN, and — since rcgen derives the key id from the key via `KeyIdMethod::Sha256`
/// — the same authority key identifier), letting leaves chain to the installed CA.
const CA_COMMON_NAME: &str = "Adwarden Root CA";
const CA_ORG_NAME: &str = "Adwarden";

/// A self-signed root CA plus an on-demand, cached leaf-minting facility.
pub struct CertAuthority {
    /// The CA certificate in DER, appended to every minted leaf chain. On a
    /// restored CA this is the exact bytes the user installed.
    ca_der: CertificateDer<'static>,
    /// PEM of the CA cert and key, retained so Kotlin can persist/export them.
    ca_cert_pem: String,
    ca_key_pem: String,
    /// The issuer used to sign leaves: `signed_by` reads its DN / key-usage /
    /// key-id method. Reconstructed from fixed params, so it matches the CA the
    /// user installed.
    ca_cert: Certificate,
    ca_key: KeyPair,
    /// Minted leaves keyed by lowercased SNI hostname.
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl CertAuthority {
    /// Generate a brand-new root CA. Call once on first run; persist the PEMs.
    pub fn generate() -> Result<Self, rcgen::Error> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = ca_params()?.self_signed(&key)?;
        let ca_der = cert.der().clone();
        Ok(CertAuthority {
            ca_cert_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
            ca_der,
            ca_cert: cert,
            ca_key: key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// Restore a previously-generated CA from its stored PEMs. The issuer is
    /// rebuilt from the key with fixed params; the leaf chain still presents the
    /// stored CA DER so the bytes match what the user installed.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, rcgen::Error> {
        let key = KeyPair::from_pem(key_pem)?;
        let cert = ca_params()?.self_signed(&key)?;
        let ca_der = pem_to_der(cert_pem).ok_or(rcgen::Error::CouldNotParseCertificate)?;
        Ok(CertAuthority {
            ca_der: CertificateDer::from(ca_der),
            ca_cert_pem: cert_pem.to_string(),
            ca_key_pem: key_pem.to_string(),
            ca_cert: cert,
            ca_key: key,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate in PEM — exported to the user for installation.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// The CA private key in PEM — persisted (app-private) so the CA is stable.
    pub fn ca_key_pem(&self) -> &str {
        &self.ca_key_pem
    }

    /// The CA certificate in DER — for the install wizard's `.crt` export.
    pub fn ca_cert_der(&self) -> &[u8] {
        self.ca_der.as_ref()
    }

    /// Mint (or return a cached) leaf certificate + key for `host`, as a rustls
    /// [`CertifiedKey`] ready to serve. The chain is `[leaf, ca]`.
    pub fn certified_key_for(&self, host: &str) -> Result<Arc<CertifiedKey>, rcgen::Error> {
        let key = host.to_ascii_lowercase();
        if let Some(existing) = self.cache.lock().unwrap().get(&key).cloned() {
            return Ok(existing);
        }
        let certified = Arc::new(self.mint(host)?);
        self.cache.lock().unwrap().insert(key, certified.clone());
        Ok(certified)
    }

    fn mint(&self, host: &str) -> Result<CertifiedKey, rcgen::Error> {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2037, 1, 1);

        let leaf = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;
        let leaf_der = leaf.der().clone();
        let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&PrivateKeyDer::from(key_der))
            .map_err(|_| rcgen::Error::CouldNotParseKeyPair)?;
        Ok(CertifiedKey::new(vec![leaf_der, self.ca_der.clone()], signing_key))
    }

    /// Build a rustls server config that mints leaves per SNI via this CA.
    pub fn server_config(self: &Arc<Self>) -> Result<Arc<rustls::ServerConfig>, rustls::Error> {
        let resolver = Arc::new(MintingResolver { ca: self.clone() });
        let config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
        Ok(Arc::new(config))
    }
}

/// Fixed root-CA parameters (see [`CA_COMMON_NAME`] for why they must be stable).
fn ca_params() -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(Vec::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, CA_COMMON_NAME);
    params.distinguished_name.push(DnType::OrganizationName, CA_ORG_NAME);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2037, 1, 1);
    Ok(params)
}

/// rustls cert resolver: mints (or reuses) a leaf for the ClientHello's SNI.
struct MintingResolver {
    ca: Arc<CertAuthority>,
}

impl fmt::Debug for MintingResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintingResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for MintingResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // No SNI -> we can't mint a matching leaf; let the handshake fail rather
        // than serve a bogus cert. (Interception targets name-based HTTPS.)
        let host = client_hello.server_name()?;
        match self.ca.certified_key_for(host) {
            Ok(ck) => Some(ck),
            Err(e) => {
                log::warn!("leaf mint failed for {host}: {e}");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, RootCertStore, ServerConnection};

    /// A rustls client that trusts *only* the given CA — so a completed
    /// handshake proves the minted leaf chains to it and matches the SNI.
    fn client_trusting(ca: &CertAuthority) -> Arc<rustls::ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.ca_cert_der().to_vec()))
            .unwrap();
        Arc::new(
            rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        )
    }

    /// Drive a client/server pair through the handshake over in-memory buffers.
    fn handshake(host: &'static str, server_cfg: Arc<rustls::ServerConfig>, ca: &CertAuthority) {
        let mut client =
            ClientConnection::new(client_trusting(ca), ServerName::try_from(host).unwrap()).unwrap();
        let mut server = ServerConnection::new(server_cfg).unwrap();
        for _ in 0..30 {
            let mut c2s = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut c2s).unwrap();
            }
            let mut cur = &c2s[..];
            while !cur.is_empty() && server.read_tls(&mut cur).unwrap() > 0 {}
            server.process_new_packets().unwrap();

            let mut s2c = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut s2c).unwrap();
            }
            let mut cur = &s2c[..];
            while !cur.is_empty() && client.read_tls(&mut cur).unwrap() > 0 {}
            client.process_new_packets().unwrap();

            if !client.is_handshaking() && !server.is_handshaking() {
                return; // both sides satisfied -> chain + SNI verified
            }
        }
        panic!("TLS handshake did not converge for {host}");
    }

    #[test]
    fn mints_leaf_that_chains_to_ca_and_matches_sni() {
        let ca = Arc::new(CertAuthority::generate().unwrap());
        handshake("example.com", ca.server_config().unwrap(), &ca);
    }

    #[test]
    fn restored_ca_round_trips_and_still_chains() {
        let original = CertAuthority::generate().unwrap();
        let restored =
            Arc::new(CertAuthority::from_pem(original.ca_cert_pem(), original.ca_key_pem()).unwrap());
        // The installed bytes survive the PEM round-trip (also exercises the
        // base64 decoder against rcgen's PEM encoder).
        assert_eq!(original.ca_cert_der(), restored.ca_cert_der());
        // Leaves minted by the restored CA still chain to the same installed CA.
        handshake("api.example.org", restored.server_config().unwrap(), &restored);
    }

    #[test]
    fn caches_leaves_case_insensitively() {
        let ca = CertAuthority::generate().unwrap();
        let a = ca.certified_key_for("Example.COM").unwrap();
        let b = ca.certified_key_for("example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "repeat SNI should hit the leaf cache");
        let c = ca.certified_key_for("other.com").unwrap();
        assert!(!Arc::ptr_eq(&a, &c), "distinct host should mint a fresh leaf");
    }
}

/// Extract the DER body of the first certificate in a PEM string.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let mut b64 = String::new();
    let mut in_cert = false;
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
        } else if line.starts_with("-----END CERTIFICATE-----") {
            break;
        } else if in_cert {
            b64.push_str(line);
        }
    }
    if b64.is_empty() {
        return None;
    }
    base64_decode(&b64)
}

/// Minimal standard-alphabet base64 decoder, enough for PEM bodies. Avoids
/// pulling a base64 dependency into the datapath crate.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}
