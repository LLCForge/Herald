//! Prometheus text-format metrics, served at `GET /metrics` on the management listener.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

#[derive(Debug, Default, Clone)]
pub struct LogStats {
    pub tree_size: u64,
    pub next_index: u64,
    pub entries: u64,
    pub malformed: u64,
    pub sth_failures: u64,
    pub fetch_errors: u64,
    pub consistency_failures: u64,
    pub concurrency: u64,
    pub tiled: bool,
}

/// (name, type, help, accessor) of a per-log metric.
type MetricDef = (
    &'static str,
    &'static str,
    &'static str,
    fn(&LogStats) -> u64,
);

#[derive(Default)]
pub struct Metrics {
    logs: Mutex<BTreeMap<String, LogStats>>,
    pub matches: AtomicU64,
    pub muted: AtomicU64,
    pub deduplicated: AtomicU64,
    pub alerts_sent: AtomicU64,
    pub alerts_failed: AtomicU64,
    pub caa_violations: AtomicU64,
    pub typosquats: AtomicU64,
    pub expiring_names: AtomicU64,
    pub inventory_certs: AtomicU64,
    pub revoked_takedowns: AtomicU64,
    /// Metrics of the current alert dispatcher (replaced on reload).
    pub dispatcher: Mutex<Option<Arc<llcforge_alert::Metrics>>>,
}

impl Metrics {
    pub fn update_log(&self, log: &str, f: impl FnOnce(&mut LogStats)) {
        if let Ok(mut map) = self.logs.lock() {
            f(map.entry(log.to_string()).or_default());
        }
    }

    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let logs = self.logs.lock().map(|m| m.clone()).unwrap_or_default();
        let per_log: [MetricDef; 8] = [
            (
                "herald_log_tree_size",
                "gauge",
                "Latest verified tree size",
                |s| s.tree_size,
            ),
            (
                "herald_log_lag_entries",
                "gauge",
                "Entries behind the tree head",
                |s| s.tree_size.saturating_sub(s.next_index),
            ),
            (
                "herald_entries_processed_total",
                "counter",
                "Entries parsed",
                |s| s.entries,
            ),
            (
                "herald_entries_malformed_total",
                "counter",
                "Entries skipped as malformed",
                |s| s.malformed,
            ),
            (
                "herald_sth_verify_failures_total",
                "counter",
                "STH signature failures",
                |s| s.sth_failures,
            ),
            (
                "herald_fetch_errors_total",
                "counter",
                "Failed log requests",
                |s| s.fetch_errors,
            ),
            (
                "herald_consistency_failures_total",
                "counter",
                "Tree heads that failed the consistency check against the previous one",
                |s| s.consistency_failures,
            ),
            (
                "herald_log_fetch_concurrency",
                "gauge",
                "Current adaptive fetch parallelism",
                |s| s.concurrency,
            ),
        ];
        for (name, kind, help, get) in per_log {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
            for (log, s) in &logs {
                let api = if s.tiled { "static" } else { "rfc6962" };
                let _ = writeln!(
                    out,
                    "{name}{{log=\"{}\",api=\"{api}\"}} {}",
                    escape_label(log),
                    get(s)
                );
            }
        }
        let globals = [
            (
                "herald_matches_total",
                "Certificates matching a rule",
                &self.matches,
            ),
            (
                "herald_alerts_muted_total",
                "Matches muted by expected_issuers",
                &self.muted,
            ),
            (
                "herald_alerts_deduplicated_total",
                "Duplicate precert/cert alerts",
                &self.deduplicated,
            ),
            (
                "herald_alerts_sent_total",
                "Alert deliveries that succeeded",
                &self.alerts_sent,
            ),
            (
                "herald_alerts_failed_total",
                "Alerts the dispatcher refused (queue full)",
                &self.alerts_failed,
            ),
            (
                "herald_caa_violations_total",
                "Certificates issued by a CA the domain's CAA records do not allow",
                &self.caa_violations,
            ),
            (
                "herald_typosquats_total",
                "Typosquat certificates detected",
                &self.typosquats,
            ),
            (
                "herald_takedowns_revoked_total",
                "Tracked lookalike/typosquat certificates found revoked",
                &self.revoked_takedowns,
            ),
        ];
        for (name, help, v) in globals {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}",
                v.load(Ordering::Relaxed)
            );
        }
        for (name, help, v) in [
            (
                "herald_expiring_names",
                "Own host names whose newest certificate expires within the warning window",
                &self.expiring_names,
            ),
            (
                "herald_inventory_certificates",
                "Certificates in the inventory",
                &self.inventory_certs,
            ),
        ] {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {}",
                v.load(Ordering::Relaxed)
            );
        }
        if let Some(d) = self.dispatcher.lock().ok().and_then(|d| d.clone()) {
            d.render_prometheus(&mut out);
        }
        out
    }

    pub fn set(gauge: &AtomicU64, v: u64) {
        gauge.store(v, Ordering::Relaxed);
    }
}

fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

async fn metrics_handler(State(m): State<Arc<Metrics>>) -> impl IntoResponse {
    ([("content-type", "text/plain; version=0.0.4")], m.render())
}

/// `GET /metrics`, merged into the management router.
pub fn router(metrics: Arc<Metrics>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_lag_and_escapes_labels() {
        let m = Metrics::default();
        m.update_log("Log \"A\"", |s| {
            s.tree_size = 100;
            s.next_index = 90;
        });
        Metrics::inc(&m.matches);
        let text = m.render();
        assert!(text.contains("herald_log_lag_entries{log=\"Log \\\"A\\\"\",api=\"rfc6962\"} 10"));
        assert!(text.contains("herald_matches_total 1"));
    }
}
