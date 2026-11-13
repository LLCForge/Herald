//! Extraction of the fields Herald cares about from X.509 structures.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use x509_parser::prelude::*;

/// Certificate fields relevant for matching and alerting. All strings come from
/// attacker-controlled input and must be escaped before rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CertInfo {
    /// DNS names from the SAN extension, lowercased.
    pub dns_names: Vec<String>,
    pub subject_cn: Option<String>,
    pub issuer_o: Option<String>,
    pub issuer_cn: Option<String>,
    /// Full issuer DN (RFC 4514 style), used as part of the dedup key.
    pub issuer_dn: String,
    /// Serial number as lowercase hex without separators.
    pub serial_hex: String,
    pub not_before: i64,
    pub not_after: i64,
    pub precert: bool,
    /// HTTP(S) CRL distribution point URLs (at most 4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crl_urls: Vec<String>,
}

impl CertInfo {
    pub fn from_tbs(tbs: &TbsCertificate<'_>, precert: bool) -> Self {
        let mut dns_names = Vec::new();
        // A malformed or duplicate SAN extension yields no SAN names; CN is still checked.
        if let Ok(Some(san)) = tbs.subject_alternative_name() {
            for gn in &san.value.general_names {
                if let GeneralName::DNSName(name) = gn {
                    dns_names.push(name.trim_end_matches('.').to_ascii_lowercase());
                }
            }
        }
        dns_names.dedup();
        let mut crl_urls = Vec::new();
        for ext in tbs.extensions() {
            if let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() {
                for p in points.iter() {
                    if let Some(DistributionPointName::FullName(names)) = &p.distribution_point {
                        for n in names {
                            if let GeneralName::URI(u) = n {
                                if (u.starts_with("http://") || u.starts_with("https://"))
                                    && u.len() <= 512
                                    && crl_urls.len() < 4
                                {
                                    crl_urls.push(u.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        Self {
            dns_names,
            subject_cn: first_attr(tbs.subject().iter_common_name()),
            issuer_o: first_attr(tbs.issuer().iter_organization()),
            issuer_cn: first_attr(tbs.issuer().iter_common_name()),
            issuer_dn: tbs.issuer().to_string(),
            serial_hex: hex(tbs.raw_serial()),
            not_before: tbs.validity().not_before.timestamp(),
            not_after: tbs.validity().not_after.timestamp(),
            precert,
            crl_urls,
        }
    }

    /// Names to match: SAN DNS names plus the subject CN when it looks like a hostname.
    pub fn match_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.dns_names.iter().map(String::as_str).collect();
        if let Some(cn) = &self.subject_cn {
            if cn.contains('.') && !cn.contains(' ') && !names.iter().any(|n| n == cn) {
                names.push(cn);
            }
        }
        names
    }

    /// Short issuer label, e.g. "Let's Encrypt (R11)".
    pub fn issuer_label(&self) -> String {
        match (&self.issuer_o, &self.issuer_cn) {
            (Some(o), Some(cn)) => format!("{o} ({cn})"),
            (Some(o), None) => o.clone(),
            (None, Some(cn)) => cn.clone(),
            (None, None) => self.issuer_dn.clone(),
        }
    }

    pub fn crtsh_url(&self) -> String {
        format!("https://crt.sh/?serial={}", self.serial_hex)
    }
}

fn first_attr<'a>(mut it: impl Iterator<Item = &'a AttributeTypeAndValue<'a>>) -> Option<String> {
    it.next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.trim().to_string())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_cert_der(der: &[u8]) -> Result<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).context("not a valid X.509 certificate")?;
    Ok(CertInfo::from_tbs(&cert.tbs_certificate, is_precert(&cert)))
}

pub fn parse_tbs_der(der: &[u8], precert: bool) -> Result<CertInfo> {
    let (_, tbs) = TbsCertificate::from_der(der).context("not a valid TBSCertificate")?;
    Ok(CertInfo::from_tbs(&tbs, precert))
}

/// CT precertificate poison extension (RFC 6962, 1.3.6.1.4.1.11129.2.4.3).
fn is_precert(cert: &X509Certificate<'_>) -> bool {
    cert.extensions()
        .iter()
        .any(|e| e.oid.to_id_string() == "1.3.6.1.4.1.11129.2.4.3")
}

/// Parses a certificate file in PEM or DER form (first certificate only).
pub fn parse_cert_file(bytes: &[u8]) -> Result<CertInfo> {
    let trimmed = bytes.trim_ascii_start();
    if trimmed.starts_with(b"-----BEGIN") {
        let (_, pem) = x509_parser::pem::parse_x509_pem(trimmed)
            .map_err(|e| anyhow::anyhow!("invalid PEM: {e}"))?;
        if pem.label != "CERTIFICATE" {
            bail!("PEM block is {:?}, expected CERTIFICATE", pem.label);
        }
        parse_cert_der(&pem.contents)
    } else {
        parse_cert_der(bytes)
    }
}

/// Formats a unix timestamp as `YYYY-MM-DD HH:MM UTC`.
pub fn fmt_time(ts: i64) -> String {
    let fmt = ::time::macros::format_description!("[year]-[month]-[day] [hour]:[minute] UTC");
    ::time::OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|t| t.format(&fmt).ok())
        .unwrap_or_else(|| ts.to_string())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SerialNumber};

    /// Builds a leaf certificate signed by a throwaway CA. Returns (leaf DER, leaf PEM).
    pub fn make_cert(
        sans: &[&str],
        cn: &str,
        issuer_org: &str,
        serial: &[u8],
    ) -> (Vec<u8>, String) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, issuer_org);
        dn.push(DnType::CommonName, "Test Issuing CA");
        ca_params.distinguished_name = dn;
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let key = KeyPair::generate().unwrap();
        let mut params =
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.serial_number = Some(SerialNumber::from_slice(serial));
        let cert = params.signed_by(&key, &issuer).unwrap();
        (cert.der().to_vec(), cert.pem())
    }

    #[test]
    fn extracts_fields_from_der_and_pem() {
        let (der, pem) = make_cert(
            &["www.example.net", "Example.NET"],
            "www.example.net",
            "Test CA Org",
            &[0x03, 0xab, 0xcd],
        );
        for info in [
            parse_cert_file(&der).unwrap(),
            parse_cert_file(pem.as_bytes()).unwrap(),
        ] {
            assert_eq!(info.dns_names, vec!["www.example.net", "example.net"]);
            assert_eq!(info.subject_cn.as_deref(), Some("www.example.net"));
            assert_eq!(info.issuer_o.as_deref(), Some("Test CA Org"));
            assert_eq!(info.issuer_cn.as_deref(), Some("Test Issuing CA"));
            assert_eq!(info.serial_hex, "03abcd");
            assert!(!info.precert);
            assert!(info.not_after > info.not_before);
            assert_eq!(info.crtsh_url(), "https://crt.sh/?serial=03abcd");
            assert_eq!(info.issuer_label(), "Test CA Org (Test Issuing CA)");
        }
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert!(parse_cert_file(b"").is_err());
        assert!(parse_cert_file(b"\x30\x82\xff\xff").is_err());
        assert!(
            parse_cert_file(b"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n")
                .is_err()
        );
        assert!(parse_tbs_der(&[0x30, 0x03, 0x02, 0x01, 0x01], true).is_err());
    }

    #[test]
    fn formats_time() {
        assert_eq!(fmt_time(0), "1970-01-01 00:00 UTC");
    }
}
