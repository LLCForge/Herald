//! CAA (RFC 8659) lookups over DNS-over-HTTPS (RFC 8484), UDP or TCP, and the
//! "is this issuer allowed by CAA?" decision.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cert::CertInfo;

const TYPE_CAA: u16 = 257;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS: usize = 65_535;

/// The CAA record set that governs a domain (found at `found_at` by tree climbing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaaPolicy {
    pub found_at: String,
    /// CA domains from `issue` properties (empty = no CA may issue).
    pub issue: Vec<String>,
    /// CA domains from `issuewild`, when any `issuewild` property exists.
    pub issuewild: Option<Vec<String>>,
}

/// Domain -> policy (`None`: no CAA records anywhere up the tree, every CA allowed).
pub type CaaCache = Arc<RwLock<HashMap<String, Option<CaaPolicy>>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaaRecord {
    pub flags: u8,
    pub tag: String,
    pub value: String,
}

pub fn build_query(id: u16, name: &str) -> Result<Vec<u8>> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, 1 question
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            bail!("invalid DNS name {name:?}");
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&TYPE_CAA.to_be_bytes());
    q.extend_from_slice(&[0, 1]); // IN
    if q.len() > 300 {
        bail!("DNS name too long");
    }
    Ok(q)
}

struct Msg<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Msg<'_> {
    fn u8(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).context("DNS message truncated")?;
        self.pos += 1;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from(self.u8()?) << 8 | u16::from(self.u8()?))
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.buf.len() {
            bail!("DNS message truncated");
        }
        self.pos += n;
        Ok(())
    }
    fn skip_name(&mut self) -> Result<()> {
        for _ in 0..128 {
            let len = self.u8()?;
            match len {
                0 => return Ok(()),
                l if l & 0xc0 == 0xc0 => {
                    self.u8()?;
                    return Ok(());
                }
                l if l & 0xc0 == 0 => self.skip(usize::from(l))?,
                _ => bail!("unsupported DNS label type"),
            }
        }
        bail!("DNS name too long")
    }
}

/// Parsed response: (truncated flag, CAA records). NXDOMAIN yields no records.
pub fn parse_response(id: u16, buf: &[u8]) -> Result<(bool, Vec<CaaRecord>)> {
    let mut m = Msg { buf, pos: 0 };
    if m.u16()? != id {
        bail!("DNS response id mismatch");
    }
    let flags = m.u16()?;
    if flags & 0x8000 == 0 {
        bail!("DNS message is not a response");
    }
    let truncated = flags & 0x0200 != 0;
    match flags & 0x000f {
        0 | 3 => {}
        rcode => bail!("DNS server answered rcode {rcode}"),
    }
    let (qd, an) = (m.u16()?, m.u16()?);
    m.skip(4)?;
    for _ in 0..qd {
        m.skip_name()?;
        m.skip(4)?;
    }
    let mut out = Vec::new();
    for _ in 0..an.min(256) {
        m.skip_name()?;
        let ty = m.u16()?;
        m.skip(6)?; // class, ttl
        let len = usize::from(m.u16()?);
        let start = m.pos;
        m.skip(len)?;
        if ty != TYPE_CAA || len < 2 {
            continue;
        }
        let rd = &buf[start..start + len];
        let tag_len = usize::from(rd[1]);
        if 2 + tag_len > rd.len() {
            continue;
        }
        out.push(CaaRecord {
            flags: rd[0],
            tag: String::from_utf8_lossy(&rd[2..2 + tag_len]).to_ascii_lowercase(),
            value: String::from_utf8_lossy(&rd[2 + tag_len..]).into_owned(),
        });
    }
    Ok((truncated, out))
}

fn random_id() -> u16 {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 2];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    u16::from_be_bytes(b)
}

fn host_port(rest: &str) -> String {
    let has_port = if rest.starts_with('[') {
        rest.contains("]:")
    } else {
        rest.matches(':').count() == 1
    };
    if has_port {
        rest.to_string()
    } else if rest.contains(':') && !rest.starts_with('[') {
        format!("[{rest}]:53")
    } else {
        format!("{rest}:53")
    }
}

async fn query_udp(server: &str, q: &[u8], id: u16) -> Result<(bool, Vec<CaaRecord>)> {
    let addr = tokio::net::lookup_host(server)
        .await?
        .next()
        .ok_or_else(|| anyhow!("cannot resolve {server}"))?;
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = tokio::net::UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    sock.send(q).await?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(DNS_TIMEOUT, sock.recv(&mut buf))
        .await
        .context("DNS over UDP timed out")??;
    parse_response(id, &buf[..n])
}

async fn query_tcp(server: &str, q: &[u8], id: u16) -> Result<(bool, Vec<CaaRecord>)> {
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(server).await?;
        let mut framed = (q.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(q);
        s.write_all(&framed).await?;
        let len = usize::from(s.read_u16().await?);
        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf).await?;
        anyhow::Ok(buf)
    };
    let buf = tokio::time::timeout(DNS_TIMEOUT, fut)
        .await
        .context("DNS over TCP timed out")??;
    parse_response(id, &buf)
}

async fn query_doh(
    client: &reqwest::Client,
    url: &str,
    q: &[u8],
) -> Result<(bool, Vec<CaaRecord>)> {
    let resp = tokio::time::timeout(
        DNS_TIMEOUT * 2,
        client
            .post(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(q.to_vec())
            .send(),
    )
    .await
    .context("DoH request timed out")?
    .map_err(|e| anyhow!("DoH request failed: {}", e.without_url()))?;
    if !resp.status().is_success() {
        bail!("DoH server answered HTTP {}", resp.status());
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| anyhow!("DoH body: {}", e.without_url()))?;
    if body.len() > MAX_DNS {
        bail!("DoH response too large");
    }
    parse_response(0, &body)
}

/// CAA records at exactly `name` (no tree climbing).
pub async fn query(client: &reqwest::Client, resolver: &str, name: &str) -> Result<Vec<CaaRecord>> {
    if resolver.starts_with("https://") {
        let q = build_query(0, name)?;
        return Ok(query_doh(client, resolver, &q).await?.1);
    }
    let id = random_id();
    let q = build_query(id, name)?;
    if let Some(rest) = resolver.strip_prefix("tcp://") {
        return Ok(query_tcp(&host_port(rest), &q, id).await?.1);
    }
    let server = host_port(resolver.trim_start_matches("udp://"));
    let (truncated, recs) = query_udp(&server, &q, id).await?;
    if truncated {
        return Ok(query_tcp(&server, &q, id).await?.1);
    }
    Ok(recs)
}

/// CA domain from an `issue`/`issuewild` value: `"letsencrypt.org; validationmethods=dns-01"`.
pub fn value_domain(v: &str) -> Option<String> {
    let d = v
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    (!d.is_empty()).then_some(d)
}

pub fn policy_from_records(found_at: &str, recs: &[CaaRecord]) -> Option<CaaPolicy> {
    if recs.is_empty() {
        return None;
    }
    let collect = |tag: &str| -> Vec<String> {
        recs.iter()
            .filter(|r| r.tag == tag)
            .filter_map(|r| value_domain(&r.value))
            .collect()
    };
    Some(CaaPolicy {
        found_at: found_at.to_string(),
        issue: collect("issue"),
        issuewild: recs
            .iter()
            .any(|r| r.tag == "issuewild")
            .then(|| collect("issuewild")),
    })
}

/// RFC 8659 tree climbing from `domain` up to (excluding) the top-level label.
pub async fn lookup_policy(
    client: &reqwest::Client,
    resolver: &str,
    domain: &str,
) -> Result<Option<CaaPolicy>> {
    let mut name = domain.trim_end_matches('.');
    loop {
        let recs = query(client, resolver, name).await?;
        if let Some(p) = policy_from_records(name, &recs) {
            return Ok(Some(p));
        }
        match name.split_once('.') {
            Some((_, parent)) if parent.contains('.') => name = parent,
            _ => return Ok(None),
        }
    }
}

/// Built-in issuer organisation -> CAA identifiers (from the CAs' published CP/CPS).
const BUILTIN: &[(&str, &[&str])] = &[
    ("let's encrypt", &["letsencrypt.org"]),
    ("google trust services", &["pki.goog", "google.com"]),
    (
        "digicert",
        &[
            "digicert.com",
            "www.digicert.com",
            "symantec.com",
            "thawte.com",
            "geotrust.com",
            "rapidssl.com",
            "digicert.ne.jp",
        ],
    ),
    (
        "sectigo",
        &[
            "sectigo.com",
            "comodoca.com",
            "comodo.com",
            "usertrust.com",
            "trust-provider.com",
        ],
    ),
    ("comodo", &["sectigo.com", "comodoca.com", "comodo.com"]),
    ("zerossl", &["sectigo.com", "zerossl.com"]),
    (
        "amazon",
        &[
            "amazon.com",
            "amazontrust.com",
            "awstrust.com",
            "amazonaws.com",
        ],
    ),
    ("globalsign", &["globalsign.com"]),
    ("entrust", &["entrust.net", "affirmtrust.com"]),
    ("godaddy", &["godaddy.com", "starfieldtech.com"]),
    ("starfield", &["starfieldtech.com", "godaddy.com"]),
    ("buypass", &["buypass.com", "buypass.no"]),
    ("ssl corporation", &["ssl.com"]),
    ("microsoft", &["microsoft.com"]),
    ("certum", &["certum.pl", "certum.eu"]),
    ("asseco", &["certum.pl", "certum.eu"]),
    ("actalis", &["actalis.it"]),
    ("harica", &["harica.gr"]),
    ("hellenic academic", &["harica.gr"]),
    ("identrust", &["identrust.com"]),
];

/// CAA identifiers an issuer is known by (config overrides first, then the built-in table).
pub fn issuer_caa_domains(
    cert: &CertInfo,
    overrides: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let hay: Vec<String> = [&cert.issuer_o, &cert.issuer_cn]
        .into_iter()
        .flatten()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let hit = |needle: &str| {
        let n = needle.to_ascii_lowercase();
        hay.iter().any(|h| h.contains(&n))
    };
    let mut out: Vec<String> = overrides
        .iter()
        .filter(|(k, _)| hit(k))
        .flat_map(|(_, v)| v.iter().map(|d| d.to_ascii_lowercase()))
        .collect();
    if out.is_empty() {
        out = BUILTIN
            .iter()
            .filter(|(k, _)| hit(k))
            .flat_map(|(_, v)| v.iter().map(|d| d.to_string()))
            .collect();
    }
    out.sort();
    out.dedup();
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    /// The issuer is not authorised by the CAA record set.
    Violation(String),
    /// The issuer could not be mapped to a CAA identifier.
    UnknownIssuer,
}

pub fn evaluate(policy: &CaaPolicy, wildcard: bool, issuer_domains: &[String]) -> Verdict {
    let allowed = match (&policy.issuewild, wildcard) {
        (Some(w), true) => w,
        _ => &policy.issue,
    };
    if issuer_domains.is_empty() {
        return Verdict::UnknownIssuer;
    }
    if issuer_domains.iter().any(|d| allowed.contains(d)) {
        Verdict::Allowed
    } else if allowed.is_empty() {
        Verdict::Violation(format!("CAA at {} forbids all issuance", policy.found_at))
    } else {
        Verdict::Violation(format!(
            "CAA at {} allows only {}",
            policy.found_at,
            allowed.join(", ")
        ))
    }
}

/// Refreshes the CAA cache for `domains` every `every` until the task is aborted.
pub async fn refresher(
    client: reqwest::Client,
    resolver: String,
    domains: Vec<String>,
    cache: CaaCache,
    every: Duration,
) {
    loop {
        for d in &domains {
            match lookup_policy(&client, &resolver, d).await {
                Ok(p) => {
                    tracing::debug!(domain = %d, policy = ?p, "CAA refreshed");
                    if let Ok(mut c) = cache.write() {
                        c.insert(d.clone(), p);
                    }
                }
                // Keep the last known policy; an outage must not turn into false violations.
                Err(e) => {
                    tracing::warn!(domain = %d, error = %format!("{e:#}"), "CAA lookup failed")
                }
            }
        }
        tokio::time::sleep(every).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(id: u16, name: &str, records: &[(u8, &str, &str)], flags: u16) -> Vec<u8> {
        let mut m = build_query(id, name).unwrap();
        m[2..4].copy_from_slice(&(0x8180u16 | flags).to_be_bytes());
        m[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for (f, tag, value) in records {
            m.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
            m.extend_from_slice(&TYPE_CAA.to_be_bytes());
            m.extend_from_slice(&[0, 1, 0, 0, 0x0e, 0x10]);
            let rd_len = 2 + tag.len() + value.len();
            m.extend_from_slice(&(rd_len as u16).to_be_bytes());
            m.push(*f);
            m.push(tag.len() as u8);
            m.extend_from_slice(tag.as_bytes());
            m.extend_from_slice(value.as_bytes());
        }
        m
    }

    #[test]
    fn parses_caa_answers() {
        let msg = response(
            7,
            "example.net",
            &[
                (0, "issue", "letsencrypt.org"),
                (0, "issuewild", ";"),
                (128, "iodef", "mailto:x"),
            ],
            0,
        );
        let (tc, recs) = parse_response(7, &msg).unwrap();
        assert!(!tc);
        assert_eq!(recs.len(), 3);
        let p = policy_from_records("example.net", &recs).unwrap();
        assert_eq!(p.issue, vec!["letsencrypt.org"]);
        assert_eq!(p.issuewild, Some(vec![]));
        assert!(parse_response(8, &msg).is_err());
        let (tc, _) = parse_response(7, &response(7, "example.net", &[], 0x0200)).unwrap();
        assert!(tc);
        // Truncated / garbage messages are errors, not panics.
        for cut in 0..msg.len() {
            let _ = parse_response(7, &msg[..cut]);
        }
        assert!(build_query(1, "bad..name").is_err());
    }

    fn cert(org: &str) -> CertInfo {
        CertInfo {
            dns_names: vec![],
            subject_cn: None,
            issuer_o: Some(org.into()),
            issuer_cn: Some("R11".into()),
            issuer_dn: String::new(),
            serial_hex: "01".into(),
            not_before: 0,
            not_after: 1,
            precert: false,
            crl_urls: vec![],
        }
    }

    #[test]
    fn evaluates_issuers_against_policy() {
        let p = CaaPolicy {
            found_at: "example.net".into(),
            issue: vec!["letsencrypt.org".into()],
            issuewild: Some(vec![]),
        };
        let none = BTreeMap::new();
        let le = issuer_caa_domains(&cert("Let's Encrypt"), &none);
        assert_eq!(evaluate(&p, false, &le), Verdict::Allowed);
        assert!(matches!(evaluate(&p, true, &le), Verdict::Violation(_)));
        let dc = issuer_caa_domains(&cert("DigiCert Inc"), &none);
        assert!(matches!(evaluate(&p, false, &dc), Verdict::Violation(_)));
        assert_eq!(
            evaluate(&p, false, &issuer_caa_domains(&cert("Mystery CA"), &none)),
            Verdict::UnknownIssuer
        );
        let mut ov = BTreeMap::new();
        ov.insert("Mystery".to_string(), vec!["letsencrypt.org".to_string()]);
        assert_eq!(
            evaluate(&p, false, &issuer_caa_domains(&cert("Mystery CA"), &ov)),
            Verdict::Allowed
        );
        assert_eq!(
            value_domain(" LetsEncrypt.org ; accounturi=x").as_deref(),
            Some("letsencrypt.org")
        );
        assert_eq!(value_domain(";"), None);
        assert_eq!(host_port("192.0.2.53"), "192.0.2.53:53");
        assert_eq!(host_port("192.0.2.53:5353"), "192.0.2.53:5353");
        assert_eq!(host_port("2001:db8::53"), "[2001:db8::53]:53");
        assert_eq!(host_port("[2001:db8::53]:53"), "[2001:db8::53]:53");
    }
}
