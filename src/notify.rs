//! Certificate alerts: rendering, CAA evaluation, inventory recording, dedup and
//! hand-off to the shared llcforge-beacon dispatcher (and Telegram action cards).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use llcforge_beacon::{Alert as KitAlert, AlertHandle, Severity, SilenceStore};
use serde::Serialize;
use tokio::sync::mpsc;

use crate::caa::{self, CaaCache, Verdict};
use crate::cert::{fmt_time, CertInfo};
use crate::config::DomainRule;
use crate::dedup::Dedup;
use crate::inventory::Inventory;
use crate::matcher::{Match, MatchKind};
use crate::metrics::Metrics;
use crate::tgactions::{Card, TgActions};

pub const TOOL: &str = "herald";

/// A certificate that matched at least one rule.
#[derive(Debug, Clone, Serialize)]
pub struct CertAlert {
    pub log: String,
    pub index: u64,
    /// Log timestamp of the entry (milliseconds since the epoch).
    pub logged_ms: u64,
    pub cert: CertInfo,
    pub matches: Vec<Match>,
}

/// Maximum characters kept from any single certificate-derived string.
const MAX_FIELD: usize = 200;
/// Maximum SANs listed in a message (Telegram messages are capped at 4096 characters).
const MAX_SANS: usize = 15;

/// Escapes text for Telegram's HTML parse mode.
pub fn html_escape(s: &str) -> String {
    llcforge_beacon::sink::telegram::escape_html(s)
}

/// Truncates and replaces control characters (no terminal escape injection via stdout).
pub fn clip(s: &str) -> String {
    let mut out: String = s
        .chars()
        .take(MAX_FIELD)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if s.chars().count() > MAX_FIELD {
        out.push('…');
    }
    out
}

impl CertAlert {
    fn headline(&self) -> &Match {
        self.matches
            .iter()
            .find(|m| m.kind.is_impersonation())
            .unwrap_or(&self.matches[0])
    }

    fn match_line(m: &Match, esc: &dyn Fn(&str) -> String) -> String {
        // Show how a punycode lookalike renders in a browser.
        let (unicode, _) = idna::domain_to_unicode(&m.name);
        let shown = if unicode != m.name {
            format!(" (displays as {})", esc(&unicode))
        } else {
            String::new()
        };
        let detail = m
            .detail
            .as_deref()
            .map(|d| format!(" [{}]", esc(d)))
            .unwrap_or_default();
        format!(
            "{} {} via {}{shown}{detail}",
            m.kind.label(),
            esc(&m.domain),
            esc(&m.name)
        )
    }

    /// Message body. `html` selects Telegram HTML (escaped) or plain text.
    pub fn render(&self, html: bool) -> String {
        let esc = |s: &str| {
            let c = clip(s);
            if html {
                html_escape(&c)
            } else {
                c
            }
        };
        let bold = |s: String| if html { format!("<b>{s}</b>") } else { s };
        let head = self.headline();
        let mut lines = Vec::new();
        let title = match head.kind {
            MatchKind::Lookalike => {
                format!("Herald: LOOKALIKE certificate for {}", esc(&head.domain))
            }
            MatchKind::Typosquat => {
                format!("Herald: TYPOSQUAT certificate for {}", esc(&head.domain))
            }
            _ => format!("Herald: new certificate for {}", esc(&head.domain)),
        };
        lines.push(bold(title));
        for m in &self.matches {
            lines.push(format!("Match: {}", Self::match_line(m, &esc)));
        }
        lines.push(format!("Type: {}", self.type_label()));
        if let Some(cn) = &self.cert.subject_cn {
            lines.push(format!("Subject CN: {}", esc(cn)));
        }
        lines.push(format!("SANs: {}", self.sans(&esc)));
        lines.push(format!("Issuer: {}", esc(&self.cert.issuer_label())));
        lines.push(format!(
            "Valid: {} -> {}",
            fmt_time(self.cert.not_before),
            fmt_time(self.cert.not_after)
        ));
        lines.push(format!("Serial: {}", esc(&self.cert.serial_hex)));
        lines.push(format!("Log: {} #{}", esc(&self.log), self.index));
        lines.push(format!(
            "Logged: {}",
            fmt_time((self.logged_ms / 1000) as i64)
        ));
        let url = self.cert.crtsh_url();
        if html {
            lines.push(format!(
                "<a href=\"{}\">View on crt.sh</a>",
                html_escape(&url)
            ));
        } else {
            lines.push(format!("crt.sh: {url}"));
        }
        lines.join("\n")
    }

    fn type_label(&self) -> &'static str {
        if self.cert.precert {
            "precertificate"
        } else {
            "certificate"
        }
    }

    fn sans(&self, esc: &dyn Fn(&str) -> String) -> String {
        let mut sans: Vec<String> = self
            .cert
            .dns_names
            .iter()
            .take(MAX_SANS)
            .map(|s| esc(s))
            .collect();
        if self.cert.dns_names.len() > MAX_SANS {
            sans.push(format!("+{} more", self.cert.dns_names.len() - MAX_SANS));
        }
        sans.join(", ")
    }

    /// Converts to the shared `llcforge.alert.v1` schema. `caa` carries a CAA
    /// violation reason, which turns the alert into a critical `caa_violation`.
    pub fn to_kit(&self, caa: Option<&str>) -> KitAlert {
        let head = self.headline();
        let kind = if caa.is_some() {
            "caa_violation"
        } else {
            head.kind.alert_kind()
        };
        let severity = if caa.is_some() || head.kind.is_impersonation() {
            Severity::Critical
        } else {
            Severity::Warning
        };
        let name = clip(&head.name);
        let title = match (caa.is_some(), head.kind) {
            (true, _) => format!(
                "CAA violation: {} issued {name}",
                clip(&self.cert.issuer_label())
            ),
            (_, MatchKind::Lookalike) => {
                format!("Lookalike certificate for {}: {name}", head.domain)
            }
            (_, MatchKind::Typosquat) => {
                format!("Typosquat certificate for {}: {name}", head.domain)
            }
            _ => format!("New certificate for {}: {name}", head.domain),
        };
        let plain = |s: &str| clip(s);
        let mut a = KitAlert::new(TOOL, kind, severity, title)
            .resource(head.domain.clone())
            .id(format!(
                "{TOOL}:{kind}:{}:{}",
                head.domain, self.cert.serial_hex
            ));
        if let Some(reason) = caa {
            a = a.summary(reason.to_string());
        }
        for m in &self.matches {
            a = a.field("match", Self::match_line(m, &plain));
        }
        a = a.field("type", self.type_label());
        if let Some(cn) = &self.cert.subject_cn {
            a = a.field("subject_cn", clip(cn));
        }
        a = a
            .field("sans", self.sans(&plain))
            .field("issuer", clip(&self.cert.issuer_label()))
            .field(
                "valid",
                format!(
                    "{} -> {}",
                    fmt_time(self.cert.not_before),
                    fmt_time(self.cert.not_after)
                ),
            )
            .field("serial", clip(&self.cert.serial_hex))
            .field("log", format!("{} #{}", clip(&self.log), self.index))
            .link("crt.sh", self.cert.crtsh_url());
        if let Some(t) = chrono::DateTime::from_timestamp_millis(self.logged_ms as i64) {
            a = a.first_seen(t);
        }
        a
    }
}

/// Everything the alert pipeline needs besides the incoming matches.
pub struct Pipeline {
    pub handle: AlertHandle,
    pub dedup: Dedup,
    pub rules: HashMap<String, DomainRule>,
    pub caa: CaaCache,
    pub caa_overrides: BTreeMap<String, Vec<String>>,
    pub inventory: Arc<Mutex<Inventory>>,
    pub metrics: Arc<Metrics>,
    pub silences: Arc<SilenceStore>,
    pub tg: Option<TgActions>,
}

impl Pipeline {
    /// Applies CAA (marks allowed issuers expected, returns a violation reason).
    fn apply_caa(&self, alert: &mut CertAlert) -> Option<String> {
        let cache = self.caa.read().ok()?;
        let issuers = caa::issuer_caa_domains(&alert.cert, &self.caa_overrides);
        let mut violation = None;
        for m in alert.matches.iter_mut() {
            if m.kind.is_impersonation() || !self.rules.get(&m.domain).is_some_and(|r| r.caa) {
                continue;
            }
            let Some(Some(policy)) = cache.get(&m.domain) else {
                continue; // unknown yet, or no CAA at all: every CA may issue
            };
            match caa::evaluate(policy, m.name.starts_with("*."), &issuers) {
                Verdict::Allowed => m.expected_issuer = true,
                Verdict::Violation(r) => violation = Some(r),
                Verdict::UnknownIssuer => {
                    tracing::info!(issuer = %alert.cert.issuer_label(), "issuer not in the CAA identifier map; add [caa.issuer_domains]");
                }
            }
        }
        violation
    }

    /// Processes one matched certificate. Returns the alert sent, if any.
    pub fn handle(&mut self, mut alert: CertAlert, now: i64) -> Option<KitAlert> {
        if !self
            .dedup
            .first_seen(&alert.cert.issuer_dn, &alert.cert.serial_hex, now)
        {
            Metrics::inc(&self.metrics.deduplicated);
            return None;
        }
        if let Ok(mut inv) = self.inventory.lock() {
            for m in &alert.matches {
                inv.record(&alert.cert, &m.domain, m.kind, &alert.log, now);
            }
        }
        let violation = self.apply_caa(&mut alert);
        if violation.is_some() {
            Metrics::inc(&self.metrics.caa_violations);
        }
        if violation.is_none() && alert.matches.iter().all(|m| m.expected_issuer) {
            Metrics::inc(&self.metrics.muted);
            tracing::debug!(serial = %alert.cert.serial_hex, "match muted by expected issuers / CAA");
            return None;
        }
        if alert.matches.iter().any(|m| m.kind == MatchKind::Typosquat) {
            Metrics::inc(&self.metrics.typosquats);
        }
        let kit = alert.to_kit(violation.as_deref());
        if !self.handle.send(kit.clone()) {
            Metrics::inc(&self.metrics.alerts_failed);
        }
        if let Some(tg) = &self.tg {
            if self
                .silences
                .silenced_by(&kit, chrono::Utc::now())
                .is_none()
            {
                let mut text = alert.render(true);
                if let Some(v) = &violation {
                    text = format!("<b>CAA VIOLATION</b>: {}\n{text}", html_escape(&clip(v)));
                }
                tg.offer(Card {
                    text,
                    key: crate::inventory::key(&alert.cert.issuer_dn, &alert.cert.serial_hex),
                    domain: kit.resource.clone().unwrap_or_default(),
                    kind: kit.kind.clone(),
                    title: kit.title.clone(),
                });
            }
        }
        Some(kit)
    }
}

/// Consumes matched entries until all senders drop; persists dedup state periodically.
pub async fn run(mut rx: mpsc::Receiver<CertAlert>, mut p: Pipeline) {
    let mut last_save = Instant::now();
    while let Some(alert) = rx.recv().await {
        p.handle(alert, chrono::Utc::now().timestamp());
        if last_save.elapsed() > Duration::from_secs(30) {
            if let Err(e) = p.dedup.save() {
                tracing::warn!(error = %format!("{e:#}"), "cannot persist dedup state");
            }
            last_save = Instant::now();
        }
    }
    if let Err(e) = p.dedup.save() {
        tracing::warn!(error = %format!("{e:#}"), "cannot persist dedup state");
    }
}

/// A fixed sample alert used by `herald test-alert`.
pub fn sample_alert(domain: &str) -> CertAlert {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    CertAlert {
        log: "Herald test alert (not a real log entry)".into(),
        index: 0,
        logged_ms: (now as u64) * 1000,
        cert: CertInfo {
            dns_names: vec![format!("test.{domain}")],
            subject_cn: Some(format!("test.{domain}")),
            issuer_o: Some("Herald".into()),
            issuer_cn: Some("Test".into()),
            issuer_dn: "O=Herald, CN=Test".into(),
            serial_hex: "00".into(),
            not_before: now,
            not_after: now + 90 * 86_400,
            precert: false,
            crl_urls: vec![],
        },
        matches: vec![Match {
            domain: domain.into(),
            kind: MatchKind::Subdomain,
            name: format!("test.{domain}"),
            expected_issuer: false,
            detail: None,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caa::CaaPolicy;
    use std::sync::RwLock;

    fn hostile_alert() -> CertAlert {
        let mut a = sample_alert("example.com");
        a.cert.dns_names = vec!["<b>x</b>.example.com".into(), "a&b.example.com".into()];
        a.cert.subject_cn = Some("<script>alert(1)</script>".into());
        a.cert.issuer_o = Some("Evil \"CA\" <a href=x>".into());
        a.log = "Log </b><i>".into();
        a
    }

    #[test]
    fn escapes_html() {
        assert_eq!(
            html_escape("<a href=\"x\">&</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;"
        );
    }

    #[test]
    fn html_render_escapes_all_certificate_fields() {
        let text = hostile_alert().render(true);
        assert!(!text.contains("<script>"));
        assert!(!text.contains("<b>x</b>"));
        assert!(!text.contains("<a href=x>"));
        assert!(!text.contains("</b><i>"));
        assert!(text.contains("&lt;script&gt;"));
        assert!(text.contains("a&amp;b.example.com"));
        // Only Herald's own tags remain.
        let tags: Vec<&str> = text
            .match_indices('<')
            .map(|(i, _)| &text[i..i + 3])
            .collect();
        assert!(
            tags.iter()
                .all(|t| ["<b>", "</b", "<a ", "</a"].contains(t)),
            "{tags:?}"
        );
    }

    #[test]
    fn plain_render_strips_control_chars_and_truncates() {
        let mut a = sample_alert("example.com");
        a.cert.subject_cn = Some(format!("\u{1b}[31m{}", "x".repeat(500)));
        let text = a.render(false);
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains('…'));
    }

    #[test]
    fn many_sans_are_summarised() {
        let mut a = sample_alert("example.com");
        a.cert.dns_names = (0..40).map(|i| format!("h{i}.example.com")).collect();
        let text = a.render(true);
        assert!(text.contains("+25 more"));
        assert!(text.len() < 4096);
    }

    #[test]
    fn converts_to_kit_schema() {
        let a = sample_alert("example.net");
        let k = a.to_kit(None);
        assert_eq!(k.kind, "certificate");
        assert_eq!(k.severity, Severity::Warning);
        assert_eq!(k.resource.as_deref(), Some("example.net"));
        assert_eq!(k.id, "herald:certificate:example.net:00");
        assert!(k.clone().normalize().is_ok());
        let mut l = a.clone();
        l.matches[0].kind = MatchKind::Typosquat;
        l.matches[0].detail = Some("bitflip".into());
        let k = l.to_kit(None);
        assert_eq!(
            (k.kind.as_str(), k.severity),
            ("typosquat", Severity::Critical)
        );
        assert!(k.fields.iter().any(|f| f.value.contains("[bitflip]")));
        let k = a.to_kit(Some("CAA at example.net allows only letsencrypt.org"));
        assert_eq!(
            (k.kind.as_str(), k.severity),
            ("caa_violation", Severity::Critical)
        );
        // Hostile names stay plain text without control characters.
        let mut h = hostile_alert();
        h.cert.subject_cn = Some("\u{1b}]52;evil".into());
        assert!(!serde_json::to_string(&h.to_kit(None))
            .unwrap()
            .contains("\\u001b"));
    }

    fn pipeline(caa_rule: bool) -> Pipeline {
        let rule = DomainRule {
            name: "example.net".into(),
            include_subdomains: true,
            wildcards: true,
            lookalikes: false,
            typosquats: false,
            typo_distance: 1,
            caa: caa_rule,
            expected_issuers: vec![],
        };
        let cache: CaaCache = Arc::new(RwLock::new(HashMap::new()));
        cache.write().unwrap().insert(
            "example.net".into(),
            Some(CaaPolicy {
                found_at: "example.net".into(),
                issue: vec!["letsencrypt.org".into()],
                issuewild: None,
            }),
        );
        Pipeline {
            handle: AlertHandle::disabled(TOOL),
            dedup: Dedup::new(3600),
            rules: [("example.net".to_string(), rule)].into_iter().collect(),
            caa: cache,
            caa_overrides: BTreeMap::new(),
            inventory: Arc::new(Mutex::new(Inventory::in_memory(100))),
            metrics: Arc::new(Metrics::default()),
            silences: Arc::new(SilenceStore::in_memory()),
            tg: None,
        }
    }

    #[test]
    fn caa_mutes_allowed_and_flags_violations() {
        let mut p = pipeline(true);
        let mut le = sample_alert("example.net");
        le.cert.issuer_o = Some("Let's Encrypt".into());
        assert!(p.handle(le, 100).is_none(), "allowed by CAA -> muted");
        let mut other = sample_alert("example.net");
        other.cert.issuer_o = Some("DigiCert Inc".into());
        other.cert.issuer_dn = "O=DigiCert Inc".into();
        let sent = p.handle(other.clone(), 100).unwrap();
        assert_eq!(sent.kind, "caa_violation");
        // Same issuer + serial again: deduplicated (precert + final cert).
        assert!(p.handle(other, 101).is_none());
        // Every match lands in the inventory, muted or not.
        assert_eq!(p.inventory.lock().unwrap().certs.len(), 2);
        // Without caa = true the rule behaves as before.
        let mut p = pipeline(false);
        let mut le = sample_alert("example.net");
        le.cert.issuer_o = Some("Let's Encrypt".into());
        assert_eq!(p.handle(le, 100).unwrap().kind, "certificate");
    }
}
