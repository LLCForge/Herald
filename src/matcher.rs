//! Domain rules: exact, subdomain, wildcard, lookalike and typosquat matching.
//!
//! Lookalikes: every certificate name is decoded from punycode to Unicode and reduced
//! to its Unicode TR39 confusable skeleton (full confusables.txt table, see
//! `confusables.rs`). If the skeleton equals the watched domain's skeleton, or ends
//! with `.<skeleton>`, while the real name is not covered by the domain, it is a lookalike.
//!
//! Typosquats compare the registrable part of a name (as many trailing labels as the
//! watched domain has) with the watched domain: Damerau-Levenshtein distance, single
//! bit flips, TLD swaps and combo names such as `example-login`.

use serde::{Deserialize, Serialize};

use crate::cert::CertInfo;
use crate::config::DomainRule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    Exact,
    Subdomain,
    Wildcard,
    Lookalike,
    Typosquat,
}

impl MatchKind {
    /// Lookalikes and typosquats are third-party certificates for names you do not own.
    pub fn is_impersonation(self) -> bool {
        matches!(self, Self::Lookalike | Self::Typosquat)
    }

    /// Alert kind (`llcforge.alert.v1` `kind`).
    pub fn alert_kind(self) -> &'static str {
        match self {
            Self::Lookalike => "lookalike",
            Self::Typosquat => "typosquat",
            _ => "certificate",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Subdomain => "subdomain",
            Self::Wildcard => "wildcard",
            Self::Lookalike => "LOOKALIKE",
            Self::Typosquat => "TYPOSQUAT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Match {
    /// The configured domain this certificate matched.
    pub domain: String,
    pub kind: MatchKind,
    /// The certificate name that triggered the match.
    pub name: String,
    /// True when the issuer is in the rule's `expected_issuers` (alert is muted).
    pub expected_issuer: bool,
    /// Typosquat technique (`bitflip`, `distance-1`, `tld-swap`, `combo`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

struct Rule {
    cfg: DomainRule,
    suffix: String,
    wildcard_suffix: String,
    skeleton: String,
    /// Watched domain split as (first label, remaining labels), e.g. ("example", "org").
    label: String,
    rest: String,
    labels: usize,
}

pub struct Matcher {
    rules: Vec<Rule>,
}

impl Matcher {
    /// Expects names already normalised by config validation (lowercase ASCII).
    pub fn new(domains: &[DomainRule]) -> Self {
        let rules = domains
            .iter()
            .map(|d| {
                let (label, rest) = d.name.split_once('.').unwrap_or((&d.name, ""));
                Rule {
                    suffix: format!(".{}", d.name),
                    wildcard_suffix: format!("*.{}", d.name),
                    skeleton: skeleton(&d.name),
                    label: label.to_string(),
                    rest: rest.to_string(),
                    labels: d.name.split('.').count(),
                    cfg: d.clone(),
                }
            })
            .collect();
        Self { rules }
    }

    /// Returns at most one match per configured domain (the strongest one).
    pub fn check(&self, cert: &CertInfo) -> Vec<Match> {
        let names = cert.match_names();
        let mut out = Vec::new();
        for rule in &self.rules {
            let mut best: Option<(MatchKind, &str, Option<String>)> = None;
            for name in &names {
                if let Some(kind) = rule.direct(name) {
                    if best.as_ref().is_none_or(|(k, _, _)| rank(kind) < rank(*k)) {
                        best = Some((kind, name, None));
                    }
                }
            }
            if best.is_none() && rule.cfg.lookalikes {
                best = names
                    .iter()
                    .find(|n| rule.is_lookalike(n))
                    .map(|n| (MatchKind::Lookalike, *n, None));
            }
            if best.is_none() && rule.cfg.typosquats {
                best = names.iter().find_map(|n| {
                    rule.typosquat(n)
                        .map(|why| (MatchKind::Typosquat, *n, Some(why)))
                });
            }
            if let Some((kind, name, detail)) = best {
                // Impersonations are never muted: a phishing domain from your own CA is still phishing.
                let expected_issuer = !kind.is_impersonation() && rule.issuer_expected(cert);
                out.push(Match {
                    domain: rule.cfg.name.clone(),
                    kind,
                    name: name.to_string(),
                    expected_issuer,
                    detail,
                });
            }
        }
        out
    }
}

fn rank(k: MatchKind) -> u8 {
    match k {
        MatchKind::Exact => 0,
        MatchKind::Wildcard => 1,
        MatchKind::Subdomain => 2,
        MatchKind::Lookalike => 3,
        MatchKind::Typosquat => 4,
    }
}

impl Rule {
    fn direct(&self, name: &str) -> Option<MatchKind> {
        if name == self.cfg.name {
            Some(MatchKind::Exact)
        } else if self.cfg.wildcards && name == self.wildcard_suffix {
            Some(MatchKind::Wildcard)
        } else if self.cfg.include_subdomains && name.ends_with(&self.suffix) {
            Some(MatchKind::Subdomain)
        } else {
            None
        }
    }

    fn is_lookalike(&self, name: &str) -> bool {
        let covered = name == self.cfg.name || name.ends_with(&self.suffix);
        if covered {
            return false;
        }
        let sk = skeleton(name);
        sk == self.skeleton
            || (sk.len() > self.skeleton.len()
                && sk.ends_with(&self.skeleton)
                && sk.as_bytes()[sk.len() - self.skeleton.len() - 1] == b'.')
    }

    /// Returns the typosquat technique when `name` imitates the watched domain.
    fn typosquat(&self, name: &str) -> Option<String> {
        let name = name.trim_start_matches("*.");
        if name == self.cfg.name || name.ends_with(&self.suffix) || name.len() > 253 {
            return None;
        }
        let labels: Vec<&str> = name.split('.').collect();
        if labels.len() < self.labels {
            return None;
        }
        let tail = &labels[labels.len() - self.labels..];
        let (label, rest) = (tail[0], tail[1..].join("."));
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label == self.label {
            return (rest != self.rest).then(|| "tld-swap".to_string());
        }
        if rest == self.rest {
            if is_bitflip(label, &self.label) {
                return Some("bitflip".into());
            }
            let max = usize::from(self.cfg.typo_distance);
            if let Some(d) = damerau(label, &self.label, max) {
                return Some(format!("distance-{d}"));
            }
        }
        if self.label.len() >= 4 && label.contains(self.label.as_str()) {
            return Some("combo".into());
        }
        None
    }

    fn issuer_expected(&self, cert: &CertInfo) -> bool {
        self.cfg.expected_issuers.iter().any(|exp| {
            [&cert.issuer_o, &cert.issuer_cn]
                .into_iter()
                .flatten()
                .any(|v| v.eq_ignore_ascii_case(exp.trim()))
        })
    }
}

/// Unicode-decodes a hostname and reduces it to its TR39 confusable skeleton.
pub fn skeleton(name: &str) -> String {
    let name = name.trim_start_matches("*.");
    let (unicode, _) = idna::domain_to_unicode(name);
    crate::confusables::skeleton_str(&unicode)
}

/// True when `a` and `b` differ in exactly one byte by a single bit and the
/// flipped byte is still a valid host name character.
fn is_bitflip(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diffs: Vec<(u8, u8)> = a.bytes().zip(b.bytes()).filter(|(x, y)| x != y).collect();
    matches!(diffs.as_slice(), [(x, y)] if (x ^ y).count_ones() == 1
        && (x.is_ascii_lowercase() || x.is_ascii_digit() || *x == b'-'))
}

/// Damerau-Levenshtein (optimal string alignment) distance if it is in `1..=max`.
fn damerau(a: &str, b: &str, max: usize) -> Option<usize> {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if max == 0 || a.len().abs_diff(b.len()) > max || a == b {
        return None;
    }
    let w = b.len() + 1;
    let mut d = vec![0usize; (a.len() + 1) * w];
    for i in 0..=a.len() {
        d[i * w] = i;
    }
    for (j, cell) in d.iter_mut().enumerate().take(w) {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut v = (d[(i - 1) * w + j] + 1)
                .min(d[i * w + j - 1] + 1)
                .min(d[(i - 1) * w + j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(d[(i - 2) * w + j - 2] + 1);
            }
            d[i * w + j] = v;
        }
    }
    let dist = d[a.len() * w + b.len()];
    (1..=max).contains(&dist).then_some(dist)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, subs: bool, look: bool, issuers: &[&str]) -> DomainRule {
        DomainRule {
            name: name.into(),
            include_subdomains: subs,
            wildcards: true,
            lookalikes: look,
            typosquats: false,
            typo_distance: 1,
            caa: false,
            expected_issuers: issuers.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn cert(names: &[&str], org: &str) -> CertInfo {
        CertInfo {
            dns_names: names.iter().map(|s| s.to_string()).collect(),
            subject_cn: None,
            issuer_o: Some(org.into()),
            issuer_cn: Some("R11".into()),
            issuer_dn: format!("O={org}, CN=R11"),
            serial_hex: "01".into(),
            not_before: 0,
            not_after: 1,
            precert: false,
            crl_urls: vec![],
        }
    }

    #[test]
    fn exact_subdomain_wildcard() {
        let m = Matcher::new(&[rule("example.net", false, false, &[])]);
        assert_eq!(
            m.check(&cert(&["example.net"], "X"))[0].kind,
            MatchKind::Exact
        );
        assert_eq!(
            m.check(&cert(&["*.example.net"], "X"))[0].kind,
            MatchKind::Wildcard
        );
        assert!(m.check(&cert(&["www.example.net"], "X")).is_empty());
        assert!(m.check(&cert(&["notexample.net"], "X")).is_empty());

        let m = Matcher::new(&[rule("example.net", true, false, &[])]);
        let r = m.check(&cert(&["a.b.example.net", "example.net"], "X"));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].kind, MatchKind::Exact);
        assert_eq!(
            m.check(&cert(&["a.b.example.net"], "X"))[0].kind,
            MatchKind::Subdomain
        );
        assert!(m.check(&cert(&["example.net.example.com"], "X")).is_empty());
    }

    #[test]
    fn cn_is_checked_when_no_san() {
        let m = Matcher::new(&[rule("example.org", false, false, &[])]);
        let mut c = cert(&[], "X");
        c.subject_cn = Some("example.org".into());
        assert_eq!(m.check(&c)[0].name, "example.org");
    }

    #[test]
    fn expected_issuer_mutes_but_not_lookalikes() {
        let m = Matcher::new(&[rule("example.org", true, true, &["Let's Encrypt"])]);
        assert!(m.check(&cert(&["www.example.org"], "let's encrypt"))[0].expected_issuer);
        assert!(!m.check(&cert(&["www.example.org"], "Other CA"))[0].expected_issuer);
        let r = m.check(&cert(&["examp1e.org"], "Let's Encrypt"));
        assert_eq!(r[0].kind, MatchKind::Lookalike);
        assert!(!r[0].expected_issuer);
    }

    #[test]
    fn lookalikes() {
        let m = Matcher::new(&[rule("example.org", false, true, &[])]);
        // Cyrillic 'а' in punycode form, as it appears in certificates.
        let puny = idna::domain_to_ascii("exаmple.org").unwrap();
        assert!(puny.starts_with("xn--"));
        for n in [
            puny.as_str(),
            "examp1e.org",
            "login.ex4mple.org.example.com",
            "secure.3xample.org",
        ] {
            let r = m.check(&cert(&[n], "X"));
            if n.starts_with("login.ex4") {
                assert!(r.is_empty(), "{n} should not match (4 is not folded)");
            } else {
                assert_eq!(r[0].kind, MatchKind::Lookalike, "{n}");
            }
        }
        // The real domain and unrelated names are not lookalikes.
        assert_eq!(
            m.check(&cert(&["example.org"], "X"))[0].kind,
            MatchKind::Exact
        );
        assert!(m.check(&cert(&["www.example.org"], "X")).is_empty());
        assert!(m.check(&cert(&["example.com"], "X")).is_empty());
        assert!(m.check(&cert(&["myexample.org"], "X")).is_empty());
        // Disabled by default.
        let m = Matcher::new(&[rule("example.org", false, false, &[])]);
        assert!(m.check(&cert(&["examp1e.org"], "X")).is_empty());
    }

    #[test]
    fn skeleton_folds() {
        assert_eq!(skeleton("ЕХАМРLЕ.org"), skeleton("example.org"));
        assert_eq!(skeleton("*.g00gle.example"), skeleton("google.example"));
        // TR39: "rn" renders like "m".
        assert_eq!(skeleton("exarnple.org"), skeleton("example.org"));
    }

    #[test]
    fn full_tr39_lookalikes() {
        let m = Matcher::new(&[rule("example.org", false, true, &[])]);
        for n in ["exarnple.org", "login.exarnple.org", "\u{435}xample.org"] {
            let puny = idna::domain_to_ascii(n).unwrap();
            assert_eq!(
                m.check(&cert(&[&puny], "X"))[0].kind,
                MatchKind::Lookalike,
                "{n}"
            );
        }
    }

    #[test]
    fn typosquats() {
        let mut r = rule("example.org", false, false, &[]);
        r.typosquats = true;
        let m = Matcher::new(&[r]);
        let detail = |n: &str| {
            m.check(&cert(&[n], "X"))
                .first()
                .filter(|x| x.kind == MatchKind::Typosquat)
                .and_then(|x| x.detail.clone())
        };
        assert_eq!(detail("exampel.org").as_deref(), Some("distance-1")); // transposition
        assert_eq!(detail("exmple.org").as_deref(), Some("distance-1")); // deletion
        assert_eq!(detail("www.examples.org").as_deref(), Some("distance-1")); // insertion
        assert_eq!(detail("exampme.org").as_deref(), Some("bitflip")); // l (0x6c) -> m (0x6d)
        assert_eq!(detail("example.net").as_deref(), Some("tld-swap"));
        assert_eq!(detail("example-login.org").as_deref(), Some("combo"));
        assert_eq!(detail("secure-example.com").as_deref(), Some("combo"));
        assert_eq!(detail("exaaaple.org"), None); // distance 2 > 1
        assert_eq!(detail("unrelated.org"), None);
        // Your own names are never typosquats.
        assert_eq!(
            m.check(&cert(&["example.org"], "X"))[0].kind,
            MatchKind::Exact
        );
        assert!(m.check(&cert(&["a.example.org"], "X")).is_empty());
        assert_eq!(damerau("kitten", "sitting", 3), Some(3));
        assert_eq!(damerau("abc", "abc", 2), None);
        assert!(!is_bitflip("example", "exbmple")); // a ^ b has two bits set
    }
}
