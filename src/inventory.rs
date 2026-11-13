//! Certificate inventory: every certificate Herald matched (from the logs or a
//! crt.sh backfill), persisted as JSON. Drives expiry warnings, the hostname
//! report, Telegram verdicts and takedown (revocation) tracking.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cert::{fmt_time, CertInfo};
use crate::matcher::{MatchKind, Matcher};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvCert {
    pub issuer_dn: String,
    pub issuer: String,
    pub serial: String,
    pub names: Vec<String>,
    /// Watched domain the certificate matched.
    pub domain: String,
    pub kind: MatchKind,
    pub precert: bool,
    pub not_before: i64,
    pub not_after: i64,
    pub first_seen: i64,
    pub source: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crl_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
}

impl InvCert {
    pub fn key(&self) -> String {
        key(&self.issuer_dn, &self.serial)
    }
}

pub fn key(issuer_dn: &str, serial: &str) -> String {
    format!("{issuer_dn}|{serial}")
}

#[derive(Default, Serialize, Deserialize)]
struct Stored {
    certs: Vec<InvCert>,
}

pub struct Inventory {
    path: Option<PathBuf>,
    max: usize,
    pub certs: BTreeMap<String, InvCert>,
    dirty: bool,
}

impl Inventory {
    pub fn in_memory(max: usize) -> Self {
        Self {
            path: None,
            max,
            certs: BTreeMap::new(),
            dirty: false,
        }
    }

    /// Opens `<data_dir>/inventory.json`. A corrupt file is an error (it holds user verdicts).
    pub fn open(path: &Path, max: usize) -> Result<Self> {
        let mut inv = Self::in_memory(max);
        inv.path = Some(path.to_path_buf());
        match std::fs::read(path) {
            Ok(b) => {
                let s: Stored = serde_json::from_slice(&b)
                    .with_context(|| format!("corrupt inventory {}", path.display()))?;
                for c in s.certs {
                    inv.certs.insert(c.key(), c);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        }
        Ok(inv)
    }

    pub fn save(&mut self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if !self.dirty {
            return Ok(());
        }
        let s = Stored {
            certs: self.certs.values().cloned().collect(),
        };
        crate::checkpoint::atomic_write(path, &serde_json::to_vec(&s)?)?;
        self.dirty = false;
        Ok(())
    }

    /// Adds or merges a certificate (a final certificate replaces its precertificate flag).
    pub fn record(
        &mut self,
        cert: &CertInfo,
        domain: &str,
        kind: MatchKind,
        source: &str,
        now: i64,
    ) {
        let k = key(&cert.issuer_dn, &cert.serial_hex);
        if let Some(e) = self.certs.get_mut(&k) {
            if e.precert && !cert.precert {
                e.precert = false;
                self.dirty = true;
            }
            for n in &cert.dns_names {
                if !e.names.contains(n) && e.names.len() < 100 {
                    e.names.push(n.clone());
                    self.dirty = true;
                }
            }
            if e.crl_urls.is_empty() && !cert.crl_urls.is_empty() {
                e.crl_urls = cert.crl_urls.clone();
                self.dirty = true;
            }
            return;
        }
        if self.certs.len() >= self.max {
            self.evict(now);
        }
        self.certs.insert(
            k,
            InvCert {
                issuer_dn: cert.issuer_dn.clone(),
                issuer: cert.issuer_label(),
                serial: cert.serial_hex.clone(),
                names: cert
                    .match_names()
                    .iter()
                    .take(100)
                    .map(|s| s.to_string())
                    .collect(),
                domain: domain.to_string(),
                kind,
                precert: cert.precert,
                not_before: cert.not_before,
                not_after: cert.not_after,
                first_seen: now,
                source: source.chars().take(200).collect(),
                crl_urls: cert.crl_urls.clone(),
                verdict: None,
                verdict_by: None,
                revoked_at: None,
            },
        );
        self.dirty = true;
    }

    /// Drops the certificates that expired longest ago (10 % of the cap).
    fn evict(&mut self, now: i64) {
        let mut by_expiry: Vec<(i64, String)> = self
            .certs
            .iter()
            .filter(|(_, c)| c.not_after < now)
            .map(|(k, c)| (c.not_after, k.clone()))
            .collect();
        if by_expiry.is_empty() {
            by_expiry = self
                .certs
                .iter()
                .map(|(k, c)| (c.not_after, k.clone()))
                .collect();
        }
        by_expiry.sort();
        for (_, k) in by_expiry.into_iter().take((self.max / 10).max(1)) {
            self.certs.remove(&k);
        }
        self.dirty = true;
    }

    pub fn set_verdict(&mut self, k: &str, verdict: &str, by: &str) -> Option<&InvCert> {
        let e = self.certs.get_mut(k)?;
        e.verdict = Some(verdict.to_string());
        e.verdict_by = Some(by.chars().take(64).collect());
        self.dirty = true;
        Some(e)
    }

    pub fn set_revoked(&mut self, k: &str, at: i64) {
        if let Some(e) = self.certs.get_mut(k) {
            e.revoked_at = Some(at);
            self.dirty = true;
        }
    }

    /// Lookalike/typosquat/suspicious certificates whose takedown is tracked via CRLs.
    pub fn takedown_candidates(&self, now: i64) -> Vec<InvCert> {
        self.certs
            .values()
            .filter(|c| {
                (c.kind.is_impersonation() || c.verdict.as_deref() == Some("suspicious"))
                    && c.revoked_at.is_none()
                    && c.not_after > now
                    && !c.crl_urls.is_empty()
            })
            .take(500)
            .cloned()
            .collect()
    }

    /// Per-name view of your own certificates (direct matches only).
    pub fn hostnames(&self, domain: Option<&str>) -> BTreeMap<String, HostSummary> {
        let mut out: BTreeMap<String, HostSummary> = BTreeMap::new();
        for c in self.certs.values() {
            if c.kind.is_impersonation() || domain.is_some_and(|d| d != c.domain) {
                continue;
            }
            for n in &c.names {
                let covered = *n == c.domain || n.ends_with(&format!(".{}", c.domain));
                if !covered {
                    continue;
                }
                let h = out.entry(n.clone()).or_insert_with(|| HostSummary {
                    domain: c.domain.clone(),
                    first_seen: c.not_before,
                    latest_expiry: i64::MIN,
                    certificates: 0,
                    issuers: BTreeSet::new(),
                });
                h.first_seen = h.first_seen.min(c.not_before);
                if c.revoked_at.is_none() {
                    h.latest_expiry = h.latest_expiry.max(c.not_after);
                }
                // Precertificate and final certificate share one entry.
                h.certificates += 1;
                if h.issuers.len() < 16 {
                    h.issuers.insert(c.issuer.clone());
                }
            }
        }
        out
    }

    /// Names whose newest certificate expires within `warn_secs` (and has not expired yet).
    pub fn expiring(&self, now: i64, warn_secs: i64) -> Vec<(String, HostSummary)> {
        self.hostnames(None)
            .into_iter()
            .filter(|(_, h)| h.latest_expiry > now && h.latest_expiry - now <= warn_secs)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostSummary {
    pub domain: String,
    pub first_seen: i64,
    pub latest_expiry: i64,
    pub certificates: u32,
    pub issuers: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ReportFormat {
    Text,
    Json,
    Markdown,
}

/// Hostname inventory report (item 84).
pub fn render_report(
    inv: &Inventory,
    domain: Option<&str>,
    format: ReportFormat,
    now: i64,
) -> String {
    let hosts = inv.hostnames(domain);
    let days = |t: i64| (t - now).div_euclid(86_400);
    match format {
        ReportFormat::Json => {
            let rows: Vec<serde_json::Value> = hosts
                .iter()
                .map(|(n, h)| {
                    serde_json::json!({
                        "name": n, "domain": h.domain, "first_seen": h.first_seen,
                        "latest_expiry": h.latest_expiry, "days_left": days(h.latest_expiry),
                        "certificates": h.certificates, "issuers": h.issuers,
                    })
                })
                .collect();
            serde_json::to_string_pretty(&serde_json::json!({ "hostnames": rows }))
                .unwrap_or_default()
        }
        ReportFormat::Markdown | ReportFormat::Text => {
            let md = format == ReportFormat::Markdown;
            let mut out = String::new();
            if md {
                out.push_str("| Name | First seen | Expires | Days left | Certs | Issuers |\n|---|---|---|---|---|---|\n");
            } else {
                let _ = writeln!(
                    out,
                    "{:<40} {:<11} {:<21} {:>5} {:>5}  ISSUERS",
                    "NAME", "FIRST SEEN", "EXPIRES", "DAYS", "CERTS"
                );
            }
            for (n, h) in &hosts {
                let first = fmt_time(h.first_seen);
                let exp = if h.latest_expiry == i64::MIN {
                    "revoked".to_string()
                } else {
                    fmt_time(h.latest_expiry)
                };
                let left = if h.latest_expiry == i64::MIN {
                    "-".to_string()
                } else {
                    days(h.latest_expiry).to_string()
                };
                let issuers = if md {
                    h.issuers.iter().cloned().collect::<Vec<_>>().join(", ")
                } else {
                    short_issuers(&h.issuers)
                };
                let safe = |s: &str| -> String {
                    s.chars()
                        .map(|c| {
                            if c.is_control() || (md && c == '|') {
                                '?'
                            } else {
                                c
                            }
                        })
                        .collect()
                };
                if md {
                    let _ = writeln!(
                        out,
                        "| {} | {} | {} | {} | {} | {} |",
                        safe(n),
                        &first[..10.min(first.len())],
                        exp,
                        left,
                        h.certificates,
                        safe(&issuers)
                    );
                } else {
                    let _ = writeln!(
                        out,
                        "{:<40} {:<11} {:<21} {:>5} {:>5}  {}",
                        safe(n),
                        &first[..10.min(first.len())],
                        exp,
                        left,
                        h.certificates,
                        safe(&issuers)
                    );
                }
            }
            if hosts.is_empty() {
                out.push_str("(no certificates in the inventory yet; run `herald backfill` or `herald run`)\n");
            }
            out
        }
    }
}

/// Issuer organisations (without the intermediate CN), at most three plus a count.
fn short_issuers(issuers: &BTreeSet<String>) -> String {
    let orgs: BTreeSet<&str> = issuers
        .iter()
        .map(|i| i.split(" (").next().unwrap_or(i))
        .collect();
    let mut out: Vec<&str> = orgs.iter().copied().take(3).collect();
    let extra = orgs.len().saturating_sub(3);
    let more = format!("+{extra}");
    if extra > 0 {
        out.push(&more);
    }
    out.join(", ")
}

/// One row of crt.sh's JSON output.
#[derive(Debug, Deserialize)]
pub struct CrtShRow {
    pub issuer_name: String,
    #[serde(default)]
    pub common_name: Option<String>,
    pub name_value: String,
    pub not_before: String,
    pub not_after: String,
    pub serial_number: String,
}

fn parse_crtsh_time(s: &str) -> Option<i64> {
    let fmt = time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    time::PrimitiveDateTime::parse(s.get(..19)?, &fmt)
        .ok()
        .map(|t| t.assume_utc().unix_timestamp())
}

fn dn_attr(dn: &str, attr: &str) -> Option<String> {
    dn.split(", ")
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(attr))
        .map(|(_, v)| v.trim().trim_matches('"').to_string())
}

/// Converts crt.sh rows into certificates (both precert and final entries carry the same serial).
pub fn crtsh_rows_to_certs(rows: &[CrtShRow]) -> Vec<CertInfo> {
    rows.iter()
        .filter_map(|r| {
            let serial = r.serial_number.trim().to_ascii_lowercase();
            if serial.is_empty()
                || serial.len() > 80
                || !serial.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return None;
            }
            let mut names: Vec<String> = r
                .name_value
                .split('\n')
                .map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|n| !n.is_empty() && n.len() <= 253)
                .take(100)
                .collect();
            names.dedup();
            Some(CertInfo {
                dns_names: names,
                subject_cn: r.common_name.clone(),
                issuer_o: dn_attr(&r.issuer_name, "O"),
                issuer_cn: dn_attr(&r.issuer_name, "CN"),
                issuer_dn: r.issuer_name.clone(),
                serial_hex: serial,
                not_before: parse_crtsh_time(&r.not_before)?,
                not_after: parse_crtsh_time(&r.not_after)?,
                precert: false,
                crl_urls: Vec::new(),
            })
        })
        .collect()
}

/// Backfills the inventory from crt.sh for one domain (item 80). Returns new certificates.
pub async fn backfill_crtsh(
    client: &reqwest::Client,
    base: &str,
    domain: &str,
    subdomains: bool,
    matcher: &Matcher,
    inv: &mut Inventory,
    now: i64,
) -> Result<usize> {
    let q = if subdomains {
        format!("%.{domain}")
    } else {
        domain.to_string()
    };
    let mut url = reqwest::Url::parse(base).context("invalid crt.sh URL")?;
    url.query_pairs_mut()
        .append_pair("q", &q)
        .append_pair("output", "json");
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        crate::ct::get_capped(client, url.as_str()),
    )
    .await
    .map_err(|_| anyhow!("crt.sh did not answer within 120 s"))?
    .map_err(|e| match e {
        crate::ct::FetchError::Retryable(c) => anyhow!("crt.sh answered HTTP {c}; try again later"),
        crate::ct::FetchError::Other(e) => e,
    })?;
    let rows: Vec<CrtShRow> =
        serde_json::from_slice(&body).context("crt.sh returned invalid JSON")?;
    if rows.len() > 200_000 {
        bail!("crt.sh returned too many rows");
    }
    let before = inv.certs.len();
    for c in crtsh_rows_to_certs(&rows) {
        for m in matcher.check(&c) {
            if m.domain == domain && !m.kind.is_impersonation() {
                inv.record(&c, &m.domain, m.kind, "crt.sh", now);
            }
        }
    }
    Ok(inv.certs.len() - before)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DomainRule;

    pub fn cert(names: &[&str], serial: &str, nb: i64, na: i64) -> CertInfo {
        CertInfo {
            dns_names: names.iter().map(|s| s.to_string()).collect(),
            subject_cn: None,
            issuer_o: Some("Example CA".into()),
            issuer_cn: Some("R1".into()),
            issuer_dn: "O=Example CA, CN=R1".into(),
            serial_hex: serial.into(),
            not_before: nb,
            not_after: na,
            precert: true,
            crl_urls: vec![],
        }
    }

    #[test]
    fn records_merges_and_reports_expiry() {
        let day = 86_400;
        let now = 1_800_000_000;
        let mut inv = Inventory::in_memory(1000);
        let a = cert(&["www.example.net"], "01", now - 80 * day, now + 10 * day);
        inv.record(&a, "example.net", MatchKind::Subdomain, "log", now);
        let mut final_a = a.clone();
        final_a.precert = false;
        inv.record(&final_a, "example.net", MatchKind::Subdomain, "log", now);
        assert_eq!(inv.certs.len(), 1);
        assert!(!inv.certs.values().next().unwrap().precert);
        let b = cert(&["api.example.net"], "02", now - day, now + 89 * day);
        inv.record(&b, "example.net", MatchKind::Subdomain, "log", now);
        let phish = cert(&["examp1e.net"], "03", now, now + 90 * day);
        inv.record(&phish, "example.net", MatchKind::Lookalike, "log", now);

        let exp = inv.expiring(now, 14 * day);
        assert_eq!(exp.len(), 1);
        assert_eq!(exp[0].0, "www.example.net");
        // A renewal clears the warning.
        let renewed = cert(&["www.example.net"], "04", now, now + 90 * day);
        inv.record(&renewed, "example.net", MatchKind::Subdomain, "log", now);
        assert!(inv.expiring(now, 14 * day).is_empty());

        let hosts = inv.hostnames(None);
        assert_eq!(hosts.len(), 2, "lookalikes are not your hostnames");
        assert_eq!(hosts["www.example.net"].certificates, 2);
        assert_eq!(inv.takedown_candidates(now).len(), 0, "no CRL URL");
        let text = render_report(&inv, None, ReportFormat::Text, now);
        assert!(text.contains("www.example.net") && text.contains("api.example.net"));
        let md = render_report(&inv, Some("example.net"), ReportFormat::Markdown, now);
        assert!(md.starts_with("| Name |"));
        let json: serde_json::Value =
            serde_json::from_str(&render_report(&inv, None, ReportFormat::Json, now)).unwrap();
        assert_eq!(json["hostnames"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn persists_and_bounds() {
        let dir = std::env::temp_dir().join(format!("herald-inv-{}", std::process::id()));
        let path = dir.join("inventory.json");
        let mut inv = Inventory::open(&path, 100).unwrap();
        for i in 0..150 {
            let c = cert(&["a.example.net"], &format!("{i:04x}"), i, 1000 + i);
            inv.record(&c, "example.net", MatchKind::Subdomain, "log", 5000);
        }
        assert!(inv.certs.len() <= 100);
        let k = inv.certs.keys().last().unwrap().clone();
        inv.set_verdict(&k, "known", "tg:1").unwrap();
        inv.save().unwrap();
        let again = Inventory::open(&path, 100).unwrap();
        assert_eq!(again.certs.len(), inv.certs.len());
        assert_eq!(again.certs[&k].verdict.as_deref(), Some("known"));
        std::fs::write(&path, b"{bad").unwrap();
        assert!(Inventory::open(&path, 100).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn converts_crtsh_rows() {
        let json = r#"[{"issuer_ca_id":1,"issuer_name":"C=US, O=Let's Encrypt, CN=R11","common_name":"www.example.net",
            "name_value":"example.net\nwww.example.net","id":5,"entry_timestamp":"2026-01-01T00:00:00.5",
            "not_before":"2026-01-01T00:00:00","not_after":"2026-04-01T00:00:00","serial_number":"03ABCD"},
            {"issuer_name":"x","name_value":"a","not_before":"bad","not_after":"bad","serial_number":"zz"}]"#;
        let rows: Vec<CrtShRow> = serde_json::from_str(json).unwrap();
        let certs = crtsh_rows_to_certs(&rows);
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].serial_hex, "03abcd");
        assert_eq!(certs[0].issuer_o.as_deref(), Some("Let's Encrypt"));
        assert_eq!(certs[0].issuer_cn.as_deref(), Some("R11"));
        assert_eq!(certs[0].not_before, 1_767_225_600);
        let rule = DomainRule {
            name: "example.net".into(),
            include_subdomains: true,
            wildcards: true,
            lookalikes: false,
            typosquats: false,
            typo_distance: 1,
            caa: false,
            expected_issuers: vec![],
        };
        let m = Matcher::new(&[rule]);
        let mut inv = Inventory::in_memory(100);
        for c in &certs {
            for x in m.check(c) {
                inv.record(c, &x.domain, x.kind, "crt.sh", 0);
            }
        }
        assert_eq!(inv.hostnames(None).len(), 2);
    }
}
