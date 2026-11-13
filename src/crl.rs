//! Revocation status from CRL distribution points, with a per-URL cache.
//!
//! Limitation: the CRL signature is not verified (Herald only sees the leaf or
//! TBS certificate in CT, not a trusted issuer certificate), so the result is
//! informational. See README "Roadmap".

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use serde::Serialize;
use x509_parser::prelude::*;
use x509_parser::revocation_list::CertificateRevocationList;

use crate::cert::{hex, CertInfo};
use crate::ct::{get_capped, FetchError};

const MIN_TTL: Duration = Duration::from_secs(3600);
const MAX_TTL: Duration = Duration::from_secs(6 * 3600);
const MAX_CACHED: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum Revocation {
    Good,
    Revoked { at: i64 },
    Unknown { reason: String },
}

struct Entry {
    fetched: Instant,
    ttl: Duration,
    revoked: HashMap<String, i64>,
}

#[derive(Default)]
pub struct CrlCache {
    entries: HashMap<String, Entry>,
}

/// Parses a DER CRL into (serial hex -> revocation time, seconds until nextUpdate).
pub fn parse_crl(der: &[u8], now: i64) -> Result<(HashMap<String, i64>, Option<i64>)> {
    let (_, crl) =
        CertificateRevocationList::from_der(der).map_err(|e| anyhow!("invalid CRL: {e}"))?;
    let revoked = crl
        .iter_revoked_certificates()
        .map(|r| (hex(r.raw_serial()), r.revocation_date.timestamp()))
        .collect();
    let next = crl.next_update().map(|t| t.timestamp() - now);
    Ok((revoked, next))
}

impl CrlCache {
    pub async fn check(&mut self, client: &reqwest::Client, cert: &CertInfo) -> Revocation {
        if cert.crl_urls.is_empty() {
            return Revocation::Unknown {
                reason: "no CRL distribution point".into(),
            };
        }
        let mut last_err = String::new();
        for url in &cert.crl_urls {
            match self.lookup(client, url).await {
                Ok(set) => {
                    return match set.get(&cert.serial_hex) {
                        Some(at) => Revocation::Revoked { at: *at },
                        None => Revocation::Good,
                    }
                }
                Err(e) => last_err = format!("{e:#}"),
            }
        }
        Revocation::Unknown { reason: last_err }
    }

    async fn lookup(
        &mut self,
        client: &reqwest::Client,
        url: &str,
    ) -> Result<&HashMap<String, i64>> {
        let fresh = self
            .entries
            .get(url)
            .is_some_and(|e| e.fetched.elapsed() < e.ttl);
        if !fresh {
            let der = get_capped(client, url).await.map_err(|e| match e {
                FetchError::Retryable(c) => anyhow!("CRL fetch HTTP {c}"),
                FetchError::Other(e) => e,
            })?;
            let now = chrono::Utc::now().timestamp();
            let (revoked, next) = parse_crl(&der, now)?;
            let ttl = next
                .map(|s| Duration::from_secs(s.max(0) as u64))
                .unwrap_or(MAX_TTL)
                .clamp(MIN_TTL, MAX_TTL);
            if self.entries.len() >= MAX_CACHED {
                self.entries.clear();
            }
            self.entries.insert(
                url.to_string(),
                Entry {
                    fetched: Instant::now(),
                    ttl,
                    revoked,
                },
            );
        }
        self.entries
            .get(url)
            .map(|e| &e.revoked)
            .ok_or_else(|| anyhow!("CRL cache miss"))
    }
}

/// Serial numbers of a CRL.
#[cfg(test)]
fn serials(der: &[u8]) -> Result<std::collections::HashSet<String>> {
    Ok(parse_crl(der, 0)?.0.into_keys().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        CertificateParams, CertificateRevocationListParams, IsCa, KeyIdMethod, KeyPair,
        RevocationReason, RevokedCertParams, SerialNumber,
    };

    #[test]
    fn parses_revoked_serials() {
        let key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::KeyCertSign,
        ];
        let issuer = rcgen::Issuer::new(ca, key);
        let now = rcgen::date_time_ymd(2026, 1, 1);
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: rcgen::date_time_ymd(2026, 1, 8),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from_slice(&[0x03, 0xab]),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl = params.signed_by(&issuer).unwrap();
        let set = serials(crl.der()).unwrap();
        assert!(set.contains("03ab"));
        assert!(!set.contains("03ac"));
        let (_, next) = parse_crl(crl.der(), 1_767_225_600).unwrap();
        assert_eq!(next, Some(7 * 86_400));
        assert!(parse_crl(b"\x30\x00", 0).is_err());
    }
}
