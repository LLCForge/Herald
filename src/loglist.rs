//! CT log list (v3 JSON) loading and filtering.

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::LogsConfig;
use crate::ct::{self, FetchError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogInfo {
    pub url: String,
    pub description: String,
    /// Base64 DER SubjectPublicKeyInfo, when known.
    pub key: Option<String>,
    /// static-ct-api log: `url` is the monitoring prefix.
    pub tiled: bool,
    /// Expected checkpoint origin of a tiled log.
    pub origin: Option<String>,
}

impl LogInfo {
    pub fn rfc6962(url: &str, description: &str, key: Option<String>) -> Self {
        Self {
            url: url.to_string(),
            description: description.to_string(),
            key,
            tiled: false,
            origin: None,
        }
    }
}

#[derive(Deserialize)]
struct LogList {
    operators: Vec<Operator>,
}

#[derive(Deserialize)]
struct Operator {
    #[serde(default)]
    logs: Vec<ListedLog>,
    #[serde(default)]
    tiled_logs: Vec<ListedTiledLog>,
}

#[derive(Deserialize)]
struct ListedTiledLog {
    #[serde(default)]
    description: String,
    key: String,
    submission_url: String,
    monitoring_url: String,
    #[serde(default)]
    state: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    temporal_interval: Option<TemporalInterval>,
}

#[derive(Deserialize)]
struct ListedLog {
    #[serde(default)]
    description: String,
    key: String,
    url: String,
    #[serde(default)]
    state: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    temporal_interval: Option<TemporalInterval>,
}

#[derive(Deserialize)]
struct TemporalInterval {
    end_exclusive: String,
}

fn is_current(
    state: &Option<HashMap<String, serde_json::Value>>,
    interval: &Option<TemporalInterval>,
    now: time::OffsetDateTime,
) -> bool {
    let active = state
        .as_ref()
        .is_some_and(|s| s.contains_key("usable") || s.contains_key("qualified"));
    let expired = interval.as_ref().is_some_and(|t| {
        time::OffsetDateTime::parse(
            &t.end_exclusive,
            &time::format_description::well_known::Rfc3339,
        )
        .is_ok_and(|end| end <= now)
    });
    active && !expired
}

/// Checkpoint origin of a static-ct-api log: the submission prefix without
/// scheme and trailing slashes.
pub fn origin_from_submission(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .to_string()
}

/// Keeps logs in state `usable` or `qualified` whose temporal shard has not ended.
/// Tiled (static-ct-api) logs from `tiled_logs` are included when `include_tiled`.
pub fn parse_log_list(
    json: &[u8],
    now: time::OffsetDateTime,
    include_tiled: bool,
) -> Result<Vec<LogInfo>> {
    let list: LogList = serde_json::from_slice(json).context("invalid CT log list JSON")?;
    let mut out = Vec::new();
    for op in list.operators {
        for log in op.logs {
            if is_current(&log.state, &log.temporal_interval, now)
                && log.url.starts_with("https://")
            {
                out.push(LogInfo::rfc6962(&log.url, &log.description, Some(log.key)));
            }
        }
        if !include_tiled {
            continue;
        }
        for log in op.tiled_logs {
            if is_current(&log.state, &log.temporal_interval, now)
                && log.monitoring_url.starts_with("https://")
            {
                out.push(LogInfo {
                    url: log.monitoring_url,
                    description: log.description,
                    key: Some(log.key),
                    tiled: true,
                    origin: Some(origin_from_submission(&log.submission_url)),
                });
            }
        }
    }
    Ok(out)
}

/// Resolves the logs to monitor: the static override, or the fetched log list.
pub async fn load(client: &reqwest::Client, cfg: &LogsConfig) -> Result<Vec<LogInfo>> {
    if !cfg.static_logs.is_empty() {
        return Ok(cfg
            .static_logs
            .iter()
            .map(|s| LogInfo {
                url: s.url.clone(),
                description: s.description.clone().unwrap_or_else(|| s.url.clone()),
                key: s.key.clone(),
                tiled: s.tiled,
                origin: s.origin.clone(),
            })
            .collect());
    }
    let body = ct::get_capped(client, &cfg.list_url)
        .await
        .map_err(|e| match e {
            FetchError::Retryable(code) => anyhow::anyhow!("log list fetch failed: HTTP {code}"),
            FetchError::Other(e) => e.context("log list fetch failed"),
        })?;
    parse_log_list(&body, time::OffsetDateTime::now_utc(), cfg.include_tiled)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = r#"{
      "version": "test",
      "operators": [{
        "name": "Example Operator",
        "email": [],
        "logs": [
          {"description": "Usable 2026", "log_id": "x", "key": "a2V5", "url": "https://ct.example.com/2026/",
           "mmd": 86400, "state": {"usable": {"timestamp": "2024-01-01T00:00:00Z"}},
           "temporal_interval": {"start_inclusive": "2026-01-01T00:00:00Z", "end_exclusive": "2027-01-01T00:00:00Z"}},
          {"description": "Qualified", "log_id": "x", "key": "a2V5", "url": "https://ct.example.com/q/",
           "mmd": 86400, "state": {"qualified": {"timestamp": "2024-01-01T00:00:00Z"}}},
          {"description": "Retired", "log_id": "x", "key": "a2V5", "url": "https://ct.example.com/r/",
           "mmd": 86400, "state": {"retired": {"timestamp": "2024-01-01T00:00:00Z"}}},
          {"description": "Expired shard", "log_id": "x", "key": "a2V5", "url": "https://ct.example.com/2025/",
           "mmd": 86400, "state": {"usable": {"timestamp": "2024-01-01T00:00:00Z"}},
           "temporal_interval": {"start_inclusive": "2025-01-01T00:00:00Z", "end_exclusive": "2026-01-01T00:00:00Z"}},
          {"description": "Pending", "log_id": "x", "key": "a2V5", "url": "https://ct.example.com/p/",
           "mmd": 86400, "state": {"pending": {"timestamp": "2024-01-01T00:00:00Z"}}}
        ],
        "tiled_logs": [{"description": "Tiled", "log_id": "x", "key": "a2V5",
          "submission_url": "https://log.ct.example.org/2026h2/", "monitoring_url": "https://mon.ct.example.org/2026h2/",
          "mmd": 60, "state": {"usable": {"timestamp": "2025-11-27T03:00:00Z"}}}]
      }]
    }"#;

    #[test]
    fn keeps_only_usable_and_qualified_current_logs() {
        let now = time::macros::datetime!(2026-06-01 0:00 UTC);
        let logs = parse_log_list(LIST.as_bytes(), now, false).unwrap();
        let names: Vec<&str> = logs.iter().map(|l| l.description.as_str()).collect();
        assert_eq!(names, vec!["Usable 2026", "Qualified"]);
        assert_eq!(logs[0].key.as_deref(), Some("a2V5"));
        let logs = parse_log_list(LIST.as_bytes(), now, true).unwrap();
        let tiled = logs.iter().find(|l| l.tiled).unwrap();
        assert_eq!(tiled.url, "https://mon.ct.example.org/2026h2/");
        assert_eq!(tiled.origin.as_deref(), Some("log.ct.example.org/2026h2"));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_log_list(b"{}", time::OffsetDateTime::now_utc(), true).is_err());
        assert!(parse_log_list(b"not json", time::OffsetDateTime::now_utc(), true).is_err());
    }
}
