//! RFC 6962 client: signed tree heads, entries, leaf parsing and STH signature checks.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use x509_parser::prelude::*;

use crate::cert::{self, CertInfo};

/// Upper bound for any HTTP body Herald reads (get-entries pages, log list).
pub const MAX_BODY: usize = 32 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LeafError {
    #[error("truncated input")]
    Truncated,
    #[error("unsupported leaf version {0} or type {1}")]
    UnsupportedLeaf(u8, u8),
    #[error("unknown entry type {0}")]
    UnknownEntryType(u16),
    #[error("certificate parse error: {0}")]
    Cert(String),
}

/// Minimal big-endian TLS-style reader; every read is bounds checked.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], LeafError> {
        if self.0.len() < n {
            return Err(LeafError::Truncated);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn uint(&mut self, n: usize) -> Result<u64, LeafError> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }
    fn opaque24(&mut self) -> Result<&'a [u8], LeafError> {
        let len = self.uint(3)? as usize;
        self.take(len)
    }
}

/// A decoded log entry.
#[derive(Debug, Clone)]
pub struct ParsedEntry {
    pub timestamp_ms: u64,
    pub cert: CertInfo,
}

/// Parses `leaf_input` (MerkleTreeLeaf) and `extra_data` of a get-entries item.
///
/// For x509_entry the leaf certificate is in `leaf_input`. For precert_entry the
/// TBSCertificate in `leaf_input` already carries the final issuer, so it is used
/// directly; the pre-certificate in `extra_data` is the fallback.
pub fn parse_leaf(leaf_input: &[u8], extra_data: &[u8]) -> Result<ParsedEntry, LeafError> {
    let mut r = Reader(leaf_input);
    let version = r.uint(1)? as u8;
    let leaf_type = r.uint(1)? as u8;
    if version != 0 || leaf_type != 0 {
        return Err(LeafError::UnsupportedLeaf(version, leaf_type));
    }
    let timestamp_ms = r.uint(8)?;
    let entry_type = r.uint(2)? as u16;
    let cert = match entry_type {
        0 => {
            let der = r.opaque24()?;
            cert::parse_cert_der(der).map_err(|e| LeafError::Cert(format!("{e:#}")))?
        }
        1 => {
            r.take(32)?; // issuer_key_hash
            let tbs = r.opaque24()?;
            match cert::parse_tbs_der(tbs, true) {
                Ok(info) => info,
                Err(_) => {
                    let pre = Reader(extra_data).opaque24()?;
                    let mut info =
                        cert::parse_cert_der(pre).map_err(|e| LeafError::Cert(format!("{e:#}")))?;
                    info.precert = true;
                    info
                }
            }
        }
        other => return Err(LeafError::UnknownEntryType(other)),
    };
    Ok(ParsedEntry { timestamp_ms, cert })
}

#[derive(Debug, Clone, Deserialize)]
pub struct Sth {
    pub tree_size: u64,
    pub timestamp: u64,
    pub sha256_root_hash: String,
    pub tree_head_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct EntriesResponse {
    pub entries: Vec<RawEntry>,
}

#[derive(Debug, Deserialize)]
pub struct RawEntry {
    pub leaf_input: String,
    pub extra_data: String,
}

/// Parsed public key of a log, ready for STH verification.
#[derive(Debug, Clone)]
pub struct LogKey {
    alg: KeyAlg,
    key: Vec<u8>,
    /// RFC 6962 LogID: SHA-256 of the DER SubjectPublicKeyInfo.
    log_id: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAlg {
    EcdsaP256,
    Rsa,
}

impl LogKey {
    pub fn log_id(&self) -> &[u8; 32] {
        &self.log_id
    }

    /// Decodes a base64 DER SubjectPublicKeyInfo as published in the log list.
    pub fn from_spki_b64(b64: &str) -> Result<Self> {
        let der = B64
            .decode(b64.trim())
            .context("log key is not valid base64")?;
        let (_, spki) =
            SubjectPublicKeyInfo::from_der(&der).map_err(|e| anyhow!("bad log key SPKI: {e}"))?;
        let key = spki.subject_public_key.data.to_vec();
        let alg = match spki.algorithm.algorithm.to_id_string().as_str() {
            "1.2.840.10045.2.1" => KeyAlg::EcdsaP256,
            "1.2.840.113549.1.1.1" => KeyAlg::Rsa,
            other => bail!("unsupported log key algorithm {other}"),
        };
        let mut log_id = [0u8; 32];
        log_id.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, &der).as_ref());
        Ok(Self { alg, key, log_id })
    }

    /// Verifies the STH signature (RFC 6962 section 3.5, TreeHeadSignature).
    pub fn verify_sth(&self, sth: &Sth) -> Result<()> {
        let root = B64
            .decode(&sth.sha256_root_hash)
            .context("root hash is not base64")?;
        if root.len() != 32 {
            bail!("root hash must be 32 bytes");
        }
        let sig = B64
            .decode(&sth.tree_head_signature)
            .context("signature is not base64")?;
        let mut r = [0u8; 32];
        r.copy_from_slice(&root);
        self.verify_tree_head(sth.timestamp, sth.tree_size, &r, &sig)
    }

    /// Verifies a TLS `digitally-signed` TreeHeadSignature over (timestamp, size, root).
    pub fn verify_tree_head(
        &self,
        timestamp: u64,
        tree_size: u64,
        root: &[u8; 32],
        sig: &[u8],
    ) -> Result<()> {
        let mut r = Reader(sig);
        let hash_alg = r.uint(1).map_err(|_| anyhow!("signature truncated"))?;
        let sig_alg = r.uint(1).map_err(|_| anyhow!("signature truncated"))?;
        let len = r.uint(2).map_err(|_| anyhow!("signature truncated"))? as usize;
        let sig_bytes = r.take(len).map_err(|_| anyhow!("signature truncated"))?;
        if hash_alg != 4 {
            bail!("unsupported hash algorithm {hash_alg}");
        }
        let mut msg = Vec::with_capacity(50);
        msg.extend_from_slice(&[0, 1]); // v1, tree_hash
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(&tree_size.to_be_bytes());
        msg.extend_from_slice(root);
        let alg: &dyn ring::signature::VerificationAlgorithm = match (self.alg, sig_alg) {
            (KeyAlg::EcdsaP256, 3) => &ring::signature::ECDSA_P256_SHA256_ASN1,
            (KeyAlg::Rsa, 1) => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            _ => bail!("signature algorithm {sig_alg} does not match the log key"),
        };
        ring::signature::UnparsedPublicKey::new(alg, &self.key)
            .verify(&msg, sig_bytes)
            .map_err(|_| anyhow!("STH signature does not verify"))
    }
}

/// HTTP error classes the tailer reacts to differently.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("rate limited or server error (HTTP {0})")]
    Retryable(u16),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub fn http_client() -> Result<reqwest::Client> {
    http_client_with_timeout(Duration::from_secs(30))
}

pub fn http_client_with_timeout(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("herald/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("cannot build HTTP client")
}

/// GETs a URL and reads at most `MAX_BODY` bytes of the response.
pub async fn get_capped(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, FetchError> {
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow!("request failed: {}", e.without_url()))?;
    let status = resp.status();
    if status.as_u16() == 429 || status.is_server_error() {
        return Err(FetchError::Retryable(status.as_u16()));
    }
    if !status.is_success() {
        return Err(anyhow!("HTTP {status}").into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| anyhow!("reading body failed: {}", e.without_url()))?
    {
        if body.len() + chunk.len() > MAX_BODY {
            return Err(anyhow!("response larger than {MAX_BODY} bytes").into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Clone)]
pub struct LogClient {
    client: reqwest::Client,
    base: String,
}

impl LogClient {
    pub fn new(client: reqwest::Client, url: &str) -> Self {
        let base = if url.ends_with('/') {
            url.to_string()
        } else {
            format!("{url}/")
        };
        Self { client, base }
    }

    pub async fn get_sth(&self) -> Result<Sth, FetchError> {
        let body = get_capped(&self.client, &format!("{}ct/v1/get-sth", self.base)).await?;
        Ok(serde_json::from_slice(&body).context("invalid get-sth JSON")?)
    }

    /// RFC 6962 section 4.4 consistency proof between two tree sizes.
    pub async fn get_consistency(
        &self,
        first: u64,
        second: u64,
    ) -> Result<Vec<[u8; 32]>, FetchError> {
        #[derive(Deserialize)]
        struct Proof {
            consistency: Vec<String>,
        }
        let url = format!(
            "{}ct/v1/get-sth-consistency?first={first}&second={second}",
            self.base
        );
        let body = get_capped(&self.client, &url).await?;
        let p: Proof = serde_json::from_slice(&body).context("invalid get-sth-consistency JSON")?;
        if p.consistency.len() > 128 {
            return Err(anyhow!("consistency proof too long").into());
        }
        p.consistency
            .iter()
            .map(|h| {
                let v = B64.decode(h).context("proof hash is not base64")?;
                <[u8; 32]>::try_from(v.as_slice())
                    .map_err(|_| anyhow!("proof hash must be 32 bytes").into())
            })
            .collect()
    }

    pub async fn get_entries(&self, start: u64, end: u64) -> Result<Vec<RawEntry>, FetchError> {
        let url = format!("{}ct/v1/get-entries?start={start}&end={end}", self.base);
        let body = get_capped(&self.client, &url).await?;
        let resp: EntriesResponse =
            serde_json::from_slice(&body).context("invalid get-entries JSON")?;
        Ok(resp.entries)
    }
}

pub fn decode_entry(e: &RawEntry) -> Result<ParsedEntry, LeafError> {
    let leaf = B64
        .decode(&e.leaf_input)
        .map_err(|_| LeafError::Cert("leaf_input is not base64".into()))?;
    let extra = B64
        .decode(&e.extra_data)
        .map_err(|_| LeafError::Cert("extra_data is not base64".into()))?;
    parse_leaf(&leaf, &extra)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::cert::tests::make_cert;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    fn u24(n: usize) -> [u8; 3] {
        [(n >> 16) as u8, (n >> 8) as u8, n as u8]
    }

    pub fn x509_leaf(der: &[u8], ts: u64) -> Vec<u8> {
        let mut v = vec![0, 0];
        v.extend_from_slice(&ts.to_be_bytes());
        v.extend_from_slice(&[0, 0]);
        v.extend_from_slice(&u24(der.len()));
        v.extend_from_slice(der);
        v.extend_from_slice(&[0, 0]);
        v
    }

    #[test]
    fn parses_x509_entry() {
        let (der, _) = make_cert(&["example.net"], "example.net", "Org", &[1, 2]);
        let e = parse_leaf(&x509_leaf(&der, 1_700_000_000_000), &[0, 0, 0]).unwrap();
        assert_eq!(e.timestamp_ms, 1_700_000_000_000);
        assert_eq!(e.cert.dns_names, vec!["example.net"]);
        assert!(!e.cert.precert);
    }

    #[test]
    fn parses_precert_entry_from_tbs() {
        let (der, _) = make_cert(&["login.example.org"], "login.example.org", "Org", &[9]);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let tbs = cert.tbs_certificate.as_ref();
        let mut leaf = vec![0, 0];
        leaf.extend_from_slice(&5u64.to_be_bytes());
        leaf.extend_from_slice(&[0, 1]);
        leaf.extend_from_slice(&[0xaa; 32]);
        leaf.extend_from_slice(&u24(tbs.len()));
        leaf.extend_from_slice(tbs);
        leaf.extend_from_slice(&[0, 0]);
        let e = parse_leaf(&leaf, &[]).unwrap();
        assert!(e.cert.precert);
        assert_eq!(e.cert.dns_names, vec!["login.example.org"]);
        assert_eq!(e.cert.serial_hex, "09");
    }

    #[test]
    fn precert_falls_back_to_extra_data() {
        let (der, _) = make_cert(&["a.example.com"], "a.example.com", "Org", &[7]);
        let mut leaf = vec![0, 0];
        leaf.extend_from_slice(&5u64.to_be_bytes());
        leaf.extend_from_slice(&[0, 1]);
        leaf.extend_from_slice(&[0; 32]);
        leaf.extend_from_slice(&u24(2));
        leaf.extend_from_slice(&[0x30, 0x00]);
        let mut extra = u24(der.len()).to_vec();
        extra.extend_from_slice(&der);
        let e = parse_leaf(&leaf, &extra).unwrap();
        assert!(e.cert.precert);
        assert_eq!(e.cert.dns_names, vec!["a.example.com"]);
    }

    #[test]
    fn malformed_leaves_are_errors() {
        assert!(matches!(parse_leaf(&[], &[]), Err(LeafError::Truncated)));
        assert!(matches!(
            parse_leaf(&[1, 0], &[]),
            Err(LeafError::UnsupportedLeaf(1, 0))
        ));
        let mut v = vec![0, 0];
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&[0, 7]);
        assert!(matches!(
            parse_leaf(&v, &[]),
            Err(LeafError::UnknownEntryType(7))
        ));
        // Length prefix larger than the remaining data.
        let mut v = vec![0, 0];
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&[0, 0, 0xff, 0xff, 0xff, 1]);
        assert!(matches!(parse_leaf(&v, &[]), Err(LeafError::Truncated)));
        let mut v = vec![0, 0];
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&[0, 0, 0, 0, 2, 0x30, 0x00]);
        assert!(matches!(parse_leaf(&v, &[]), Err(LeafError::Cert(_))));
    }

    /// DER SPKI prefix for an uncompressed P-256 public key.
    pub const P256_SPKI_PREFIX: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

    pub fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn verifies_ecdsa_sth_and_rejects_tampering() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let mut spki = unhex(P256_SPKI_PREFIX);
        spki.extend_from_slice(kp.public_key().as_ref());
        let key = LogKey::from_spki_b64(&B64.encode(&spki)).unwrap();

        let root = [7u8; 32];
        let (ts, size) = (1_700_000_000_123u64, 4242u64);
        let mut msg = vec![0, 1];
        msg.extend_from_slice(&ts.to_be_bytes());
        msg.extend_from_slice(&size.to_be_bytes());
        msg.extend_from_slice(&root);
        let sig = kp.sign(&rng, &msg).unwrap();
        let mut ds = vec![4, 3];
        ds.extend_from_slice(&(sig.as_ref().len() as u16).to_be_bytes());
        ds.extend_from_slice(sig.as_ref());

        let mut sth = Sth {
            tree_size: size,
            timestamp: ts,
            sha256_root_hash: B64.encode(root),
            tree_head_signature: B64.encode(&ds),
        };
        key.verify_sth(&sth).unwrap();
        sth.tree_size += 1;
        assert!(key.verify_sth(&sth).is_err());
    }
}
