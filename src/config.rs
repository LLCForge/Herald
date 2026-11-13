//! TOML configuration: loading, legacy translation and validation.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use llcforge_beacon::config::SinkKind;
use llcforge_beacon::{AlertsConfig, HealthConfig, LogFormat, SilencesConfig};
use serde::Deserialize;

pub const DEFAULT_LOG_LIST_URL: &str = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
pub const DEFAULT_DOH: &str = "https://cloudflare-dns.com/dns-query";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Checkpoints, dedup state, inventory, alert queue and silences live here.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub logs: LogsConfig,
    #[serde(default)]
    pub dedup: DedupConfig,
    #[serde(default, rename = "domain")]
    pub domains: Vec<DomainRule>,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub silences: SilencesConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub caa: CaaConfig,
    #[serde(default)]
    pub inventory: InventoryConfig,
    #[serde(default)]
    pub telegram_actions: Option<TelegramActionsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogsConfig {
    #[serde(default = "default_list_url")]
    pub list_url: String,
    #[serde(default = "default_list_refresh")]
    pub list_refresh_secs: u64,
    #[serde(default = "default_poll")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_batch")]
    pub batch_size: u64,
    /// Upper bound of pages (RFC 6962) or data tiles (static-ct-api) fetched in
    /// parallel per log; the tailer adapts between 1 and this value.
    #[serde(default = "default_concurrency")]
    pub fetch_concurrency: usize,
    /// Entries to backfill on the first start of a log (0 = start at the current tree size).
    #[serde(default)]
    pub backfill: u64,
    #[serde(default = "default_true")]
    pub verify_sth: bool,
    /// Also tail static-ct-api (tiled) logs from the log list.
    #[serde(default = "default_true")]
    pub include_tiled: bool,
    /// When non-empty, these logs are used and `list_url` is ignored.
    #[serde(default, rename = "static")]
    pub static_logs: Vec<StaticLog>,
}

impl Default for LogsConfig {
    fn default() -> Self {
        Self {
            list_url: default_list_url(),
            list_refresh_secs: default_list_refresh(),
            poll_interval_secs: default_poll(),
            batch_size: default_batch(),
            fetch_concurrency: default_concurrency(),
            backfill: 0,
            verify_sth: true,
            include_tiled: true,
            static_logs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticLog {
    /// RFC 6962 base URL, or the monitoring prefix of a tiled log.
    pub url: String,
    /// Base64 DER SubjectPublicKeyInfo of the log; enables STH/checkpoint verification.
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// The log implements the static-ct-api (checkpoint + tiles).
    #[serde(default)]
    pub tiled: bool,
    /// Expected checkpoint origin (submission prefix without scheme and trailing slash).
    #[serde(default)]
    pub origin: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DedupConfig {
    #[serde(default = "default_dedup_window")]
    pub window_secs: u64,
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            window_secs: default_dedup_window(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainRule {
    pub name: String,
    #[serde(default)]
    pub include_subdomains: bool,
    #[serde(default = "default_true")]
    pub wildcards: bool,
    #[serde(default)]
    pub lookalikes: bool,
    /// Edit distance / bitflip / TLD swap / combo-name detection.
    #[serde(default)]
    pub typosquats: bool,
    /// Maximum Damerau-Levenshtein distance for typosquats (1..=3).
    #[serde(default = "default_typo_distance")]
    pub typo_distance: u8,
    /// Derive expected CAs from the domain's CAA records and alarm on violations.
    #[serde(default)]
    pub caa: bool,
    #[serde(default)]
    pub expected_issuers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Management listener: `/metrics`, `/healthz`, `/readyz`, silences and reload APIs.
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    pub format: LogFormat,
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Text,
            level: "info".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CaaConfig {
    /// `https://.../dns-query` (RFC 8484), `udp://host[:port]` or `tcp://host[:port]`.
    pub resolver: String,
    pub refresh_secs: u64,
    /// Extra issuer-organisation -> CAA identifier mappings (case-insensitive substring of O/CN).
    pub issuer_domains: BTreeMap<String, Vec<String>>,
}

impl Default for CaaConfig {
    fn default() -> Self {
        Self {
            resolver: DEFAULT_DOH.into(),
            refresh_secs: 3600,
            issuer_domains: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct InventoryConfig {
    /// Warn when the newest certificate of one of your names expires within this many days (0 = off).
    pub expiry_warn_days: u32,
    pub check_interval_secs: u64,
    /// Re-check CRLs of lookalike/typosquat/suspicious certificates (takedown tracking).
    pub revocation_check: bool,
    pub max_certs: usize,
}

impl Default for InventoryConfig {
    fn default() -> Self {
        Self {
            expiry_warn_days: 14,
            check_interval_secs: 3600,
            revocation_check: true,
            max_certs: 100_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramActionsConfig {
    pub bot_token_env: String,
    pub chat_id: i64,
    /// Telegram user ids allowed to press the buttons (required, deny by default).
    pub allowed_user_ids: Vec<i64>,
    #[serde(default = "default_mute_days")]
    pub mute_days: u32,
    /// Override for a self-hosted Bot API server.
    #[serde(default)]
    pub api_base: Option<String>,
}

fn default_data_dir() -> PathBuf {
    // systemd StateDirectory= / the container image set STATE_DIRECTORY.
    match std::env::var_os("STATE_DIRECTORY").filter(|v| !v.is_empty()) {
        Some(d) => {
            let s = d.to_string_lossy().into_owned();
            PathBuf::from(s.split(':').next().unwrap_or(&s))
        }
        None => PathBuf::from("herald-data"),
    }
}
fn default_list_url() -> String {
    DEFAULT_LOG_LIST_URL.to_string()
}
fn default_list_refresh() -> u64 {
    86_400
}
fn default_poll() -> u64 {
    10
}
fn default_batch() -> u64 {
    256
}
fn default_concurrency() -> usize {
    4
}
fn default_true() -> bool {
    true
}
fn default_dedup_window() -> u64 {
    86_400
}
fn default_typo_distance() -> u8 {
    1
}
fn default_mute_days() -> u32 {
    7
}

/// Translates the pre-0.2 `[alerts] stdout / telegram / webhook` keys into
/// `[[alerts.sink]]` entries so old configuration files keep working.
fn translate_legacy_alerts(root: &mut toml::Table) -> Result<()> {
    let alerts = root
        .entry("alerts")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    let Some(alerts) = alerts.as_table_mut() else {
        bail!("[alerts] must be a table");
    };
    let mut sinks: Vec<toml::Value> = match alerts.remove("sink") {
        Some(toml::Value::Array(a)) => a,
        Some(_) => bail!("alerts.sink must be an array of tables ([[alerts.sink]])"),
        None => Vec::new(),
    };
    let had_sinks = !sinks.is_empty();
    let stdout = match alerts.remove("stdout") {
        Some(toml::Value::Boolean(b)) => Some(b),
        Some(_) => bail!("alerts.stdout must be true or false"),
        None => None,
    };
    let mut legacy = Vec::new();
    if stdout == Some(true) || (stdout.is_none() && !had_sinks) {
        let mut t = toml::Table::new();
        t.insert("type".into(), "stdout".into());
        t.insert("format".into(), "text".into());
        legacy.push(toml::Value::Table(t));
    }
    if let Some(v) = alerts.remove("telegram") {
        let mut t = v
            .as_table()
            .context("alerts.telegram must be a table")?
            .clone();
        t.insert("type".into(), "telegram".into());
        if !t.contains_key("bot_token_env") {
            t.insert("bot_token_env".into(), "HERALD_TELEGRAM_TOKEN".into());
        }
        if let Some(ms) = t.remove("min_interval_ms").and_then(|v| v.as_integer()) {
            let per_min = (60_000 / ms.max(1)).clamp(1, 600);
            t.insert("rate_per_minute".into(), per_min.into());
        }
        legacy.push(toml::Value::Table(t));
    }
    if let Some(v) = alerts.remove("webhook") {
        let mut t = v
            .as_table()
            .context("alerts.webhook must be a table")?
            .clone();
        t.insert("type".into(), "webhook".into());
        legacy.push(toml::Value::Table(t));
    }
    legacy.append(&mut sinks);
    alerts.insert("sink".into(), toml::Value::Array(legacy));
    Ok(())
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config file {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid config file {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut root: toml::Table = toml::from_str(text)?;
        translate_legacy_alerts(&mut root)?;
        let mut cfg: Config = toml::Value::Table(root).try_into()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates and normalises the configuration (domain names become lowercase ASCII/punycode).
    fn validate(&mut self) -> Result<()> {
        if self.domains.is_empty() {
            bail!("at least one [[domain]] is required");
        }
        for d in &mut self.domains {
            let trimmed = d.name.trim().trim_end_matches('.');
            let ascii = idna::domain_to_ascii(trimmed)
                .map_err(|_| anyhow::anyhow!("domain {:?} is not a valid domain name", d.name))?;
            if ascii.is_empty() || !ascii.contains('.') || ascii.starts_with('*') {
                bail!(
                    "domain {:?} must be a plain registered name like example.net",
                    d.name
                );
            }
            if !(1..=3).contains(&d.typo_distance) {
                bail!("domain {}: typo_distance must be 1, 2 or 3", ascii);
            }
            d.name = ascii;
        }
        let l = &self.logs;
        if !(1..=1024).contains(&l.batch_size) {
            bail!("logs.batch_size must be between 1 and 1024");
        }
        if !(1..=64).contains(&l.fetch_concurrency) {
            bail!("logs.fetch_concurrency must be between 1 and 64");
        }
        if l.poll_interval_secs == 0 {
            bail!("logs.poll_interval_secs must be at least 1");
        }
        if l.list_refresh_secs < 60 {
            bail!("logs.list_refresh_secs must be at least 60");
        }
        if l.static_logs.is_empty() {
            check_url(&l.list_url, "logs.list_url")?;
        }
        for s in &l.static_logs {
            check_url(&s.url, "logs.static.url")?;
        }
        if self.alerts.sinks.is_empty() {
            bail!("no alert sink enabled: add an [[alerts.sink]] (or set alerts.stdout = true)");
        }
        let caa = &self.caa.resolver;
        if !(caa.starts_with("https://") || caa.starts_with("udp://") || caa.starts_with("tcp://"))
        {
            bail!("caa.resolver must be https://..., udp://host[:port] or tcp://host[:port]");
        }
        if self.caa.refresh_secs < 60 {
            bail!("caa.refresh_secs must be at least 60");
        }
        if self.inventory.check_interval_secs < 60 {
            bail!("inventory.check_interval_secs must be at least 60");
        }
        if !(100..=1_000_000).contains(&self.inventory.max_certs) {
            bail!("inventory.max_certs must be between 100 and 1000000");
        }
        if let Some(t) = &self.telegram_actions {
            if t.allowed_user_ids.is_empty() {
                bail!("telegram_actions.allowed_user_ids must list at least one Telegram user id");
            }
            if !(1..=365).contains(&t.mute_days) {
                bail!("telegram_actions.mute_days must be between 1 and 365");
            }
        }
        Ok(())
    }

    /// Listener for `/metrics` + health + admin APIs (`[metrics]` wins over `[health]`).
    pub fn admin_listen(&self) -> Option<SocketAddr> {
        self.metrics
            .as_ref()
            .map(|m| m.listen)
            .or(self.health.listen)
    }

    pub fn silences_path(&self) -> PathBuf {
        self.silences.path_or(&self.data_dir)
    }

    /// Every environment variable the configuration names.
    pub fn env_names(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for s in &self.alerts.sinks {
            match &s.kind {
                SinkKind::Stdout(_) => {}
                SinkKind::Webhook(w) => names.extend(
                    [&w.url_env, &w.bearer_token_env, &w.hmac_secret_env]
                        .into_iter()
                        .flatten()
                        .cloned(),
                ),
                SinkKind::Telegram(t) => names.push(t.bot_token_env.clone()),
                SinkKind::Slack(c) | SinkKind::Discord(c) | SinkKind::Teams(c) => {
                    names.push(c.url_env.clone())
                }
                SinkKind::Email(e) => names.extend(
                    [&e.username_env, &e.password_env]
                        .into_iter()
                        .flatten()
                        .cloned(),
                ),
                SinkKind::Pagerduty(p) => names.push(p.routing_key_env.clone()),
                SinkKind::Opsgenie(o) => names.push(o.api_key_env.clone()),
                SinkKind::Syslog(_) => {}
            }
        }
        names.extend(self.silences.api_token_env.clone());
        names.extend(self.health.admin_token_env.clone());
        if let Some(t) = &self.telegram_actions {
            names.push(t.bot_token_env.clone());
        }
        names.sort();
        names.dedup();
        names
    }

    /// Environment variables the configuration expects but that are not set.
    pub fn missing_env(&self) -> Vec<String> {
        self.env_names()
            .into_iter()
            .filter(|n| {
                std::env::var(n)
                    .map(|v| v.trim().is_empty())
                    .unwrap_or(true)
            })
            .collect()
    }

    /// Sink names for display (`type` or the configured name).
    pub fn sink_labels(&self) -> Vec<String> {
        self.alerts
            .sinks
            .iter()
            .map(|s| {
                s.common
                    .name
                    .clone()
                    .unwrap_or_else(|| s.kind.type_name().to_string())
            })
            .collect()
    }
}

fn check_url(raw: &str, field: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw).with_context(|| format!("{field}: invalid URL"))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        bail!("{field}: only http(s) URLs are supported");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_and_normalises() {
        let cfg = Config::parse(
            r#"
            [[domain]]
            name = "Example.NET."
            include_subdomains = true
            "#,
        )
        .unwrap();
        assert_eq!(cfg.domains[0].name, "example.net");
        assert!(cfg.domains[0].wildcards);
        assert_eq!(cfg.logs.batch_size, 256);
        // Default sink is stdout, as before.
        assert_eq!(cfg.sink_labels(), vec!["stdout"]);
        assert!(cfg.logs.include_tiled);
    }

    #[test]
    fn unicode_domain_becomes_punycode() {
        let cfg = Config::parse("[[domain]]\nname = \"bücher.example\"\n").unwrap();
        assert_eq!(cfg.domains[0].name, "xn--bcher-kva.example");
    }

    #[test]
    fn rejects_bad_configs() {
        assert!(Config::parse("").is_err());
        assert!(Config::parse("[[domain]]\nname = \"com\"\n").is_err());
        assert!(Config::parse("[[domain]]\nname = \"example.net\"\nbogus = 1\n").is_err());
        assert!(
            Config::parse("[logs]\nbatch_size = 0\n[[domain]]\nname = \"example.net\"\n").is_err()
        );
        assert!(
            Config::parse("[alerts]\nstdout = false\n[[domain]]\nname = \"example.net\"\n")
                .is_err()
        );
        assert!(Config::parse(
            "[[domain]]\nname = \"example.net\"\n[telegram_actions]\nbot_token_env = \"T\"\nchat_id = 1\nallowed_user_ids = []\n"
        )
        .is_err());
        assert!(Config::parse(
            "[caa]\nresolver = \"ftp://x\"\n[[domain]]\nname = \"example.net\"\n"
        )
        .is_err());
    }

    #[test]
    fn legacy_alert_sections_become_sinks() {
        let cfg = Config::parse(
            "[[domain]]\nname = \"example.net\"\n[alerts.telegram]\nchat_id = -1001234567890\nmin_interval_ms = 1000\nmax_retries = 5\n[alerts.webhook]\nurl = \"https://hooks.example.com/herald\"\nbearer_token_env = \"HERALD_WEBHOOK_TOKEN\"\n",
        )
        .unwrap();
        assert_eq!(cfg.sink_labels(), vec!["stdout", "telegram", "webhook"]);
        let tg = &cfg.alerts.sinks[1];
        assert_eq!(tg.common.rate_per_minute, 60);
        assert_eq!(tg.common.max_retries, 5);
        match &tg.kind {
            SinkKind::Telegram(t) => {
                assert_eq!(t.chat_id, "-1001234567890");
                assert_eq!(t.bot_token_env, "HERALD_TELEGRAM_TOKEN");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            cfg.env_names(),
            vec!["HERALD_TELEGRAM_TOKEN", "HERALD_WEBHOOK_TOKEN"]
        );
        // String chat ids still work.
        let cfg = Config::parse(
            "[[domain]]\nname = \"example.net\"\n[alerts]\nstdout = false\n[alerts.telegram]\nchat_id = \"@herald_alerts\"\n",
        )
        .unwrap();
        assert_eq!(cfg.sink_labels(), vec!["telegram"]);
    }

    #[test]
    fn new_style_sinks_and_sections() {
        let cfg = Config::parse(
            r#"
            [[domain]]
            name = "example.net"
            typosquats = true
            caa = true
            [[alerts.sink]]
            type = "webhook"
            url = "https://hooks.example.com/herald"
            hmac_secret_env = "HERALD_WEBHOOK_HMAC"
            resources = ["example.net"]
            [metrics]
            listen = "127.0.0.1:9898"
            [inventory]
            expiry_warn_days = 21
            [telegram_actions]
            bot_token_env = "HERALD_TG_ACTIONS"
            chat_id = -100123
            allowed_user_ids = [111]
            "#,
        )
        .unwrap();
        assert_eq!(cfg.sink_labels(), vec!["webhook"]);
        assert_eq!(cfg.alerts.sinks[0].common.resources, vec!["example.net"]);
        assert!(cfg.domains[0].typosquats && cfg.domains[0].caa);
        assert_eq!(cfg.inventory.expiry_warn_days, 21);
        assert_eq!(cfg.admin_listen().unwrap().port(), 9898);
        assert_eq!(
            cfg.env_names(),
            vec!["HERALD_TG_ACTIONS", "HERALD_WEBHOOK_HMAC"]
        );
    }
}
