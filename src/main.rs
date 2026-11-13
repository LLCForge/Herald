//! Herald: Certificate Transparency log monitor (RFC 6962 and static-ct-api logs)
//! with lookalike, typosquat, CAA and expiry alerts.

mod caa;
mod cert;
mod checkpoint;
mod config;
mod confusables;
mod crl;
mod ct;
mod dedup;
mod inventory;
mod loglist;
mod matcher;
mod merkle;
mod metrics;
mod notify;
mod tailer;
mod tgactions;
mod tiled;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use llcforge_alert::cli::{run_silence_command, ServiceCommand, SilenceCommand};
use llcforge_alert::{
    health_router, init_logging, reload_router, run_service_command, silences_router,
    Alert as KitAlert, ApiToken, Dispatcher, DispatcherOptions, LogFormat, Readiness, ReloadSignal,
    ServiceSpec, Severity, Shutdown, SilenceStore,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::inventory::{Inventory, ReportFormat};
use crate::matcher::Matcher;
use crate::metrics::Metrics;
use crate::notify::{CertAlert, TOOL};

const SPEC: ServiceSpec = ServiceSpec {
    bin: "herald",
    display_name: "Herald",
    description: "Certificate Transparency log monitor with typosquat, CAA and expiry alerts",
};

#[derive(Parser)]
#[command(
    name = "herald",
    version,
    about = "Certificate Transparency log monitor with typosquat, CAA and expiry alerts"
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, global = true, default_value = "herald.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Tail the CT logs and send alerts.
    Run,
    /// Validate the configuration and report missing environment variables.
    CheckConfig,
    /// Parse a certificate file (PEM or DER) and show what Herald would alert.
    Inspect {
        /// Certificate file.
        file: PathBuf,
        /// Also look up the CAA policy (network).
        #[arg(long)]
        caa: bool,
        /// Also check the certificate's CRL (network).
        #[arg(long)]
        revocation: bool,
    },
    /// Send a test alert through every configured sink.
    TestAlert,
    /// Seed the certificate inventory from crt.sh (no alerts are sent).
    Backfill {
        /// Only this configured domain (default: all).
        #[arg(long)]
        domain: Option<String>,
        #[arg(long, default_value = "https://crt.sh/")]
        crtsh_url: String,
    },
    /// Hostname inventory report: every name seen in CT for your domains.
    Report {
        #[arg(long, value_enum, default_value = "text")]
        format: ReportFormat,
        #[arg(long)]
        domain: Option<String>,
    },
    /// Manage silences / maintenance windows.
    Silence {
        #[command(subcommand)]
        cmd: SilenceCommand,
    },
    /// Install, remove or run Herald as a system service.
    Service {
        #[command(subcommand)]
        cmd: ServiceCommand,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    // Logging follows [logging] when the config parses; HERALD_LOG overrides the filter.
    let (format, level) = Config::load(&cli.config)
        .map(|c| (c.logging.format, c.logging.level))
        .unwrap_or((LogFormat::Text, "info".into()));
    let filter = std::env::var("HERALD_LOG").ok();
    if let Err(e) = init_logging(format, &level, filter.as_deref()) {
        eprintln!("error: {e:#}");
        return std::process::ExitCode::FAILURE;
    }
    let result = match cli.command {
        // Both build their own runtime (Windows service dispatcher needs the main thread).
        Command::Run => llcforge_alert::service::run_foreground(cli.config, daemon),
        Command::Service { cmd } => run_service_command(&SPEC, cmd.into_action(cli.config), daemon),
        Command::Silence { cmd } => {
            Config::load(&cli.config).and_then(|cfg| run_silence_command(cmd, &cfg.silences_path()))
        }
        other => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("cannot start async runtime")
            .and_then(|rt| rt.block_on(oneshot(other, &cli.config))),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn oneshot(cmd: Command, config: &Path) -> Result<()> {
    let cfg = Config::load(config)?;
    match cmd {
        Command::CheckConfig => check_config(&cfg),
        Command::Inspect {
            file,
            caa,
            revocation,
        } => inspect(&cfg, &file, caa, revocation).await,
        Command::TestAlert => test_alert(cfg).await,
        Command::Backfill { domain, crtsh_url } => backfill(&cfg, domain, &crtsh_url).await,
        Command::Report { format, domain } => {
            let inv = Inventory::open(
                &cfg.data_dir.join("inventory.json"),
                cfg.inventory.max_certs,
            )?;
            print!(
                "{}",
                inventory::render_report(
                    &inv,
                    domain.as_deref(),
                    format,
                    chrono::Utc::now().timestamp()
                )
            );
            Ok(())
        }
        Command::Run | Command::Silence { .. } | Command::Service { .. } => {
            bail!("internal: command dispatched to the wrong runner")
        }
    }
}

fn check_config(cfg: &Config) -> Result<()> {
    println!("configuration OK");
    println!("  domains: {}", cfg.domains.len());
    for d in &cfg.domains {
        println!(
            "    {} (subdomains: {}, wildcards: {}, lookalikes: {}, typosquats: {}, caa: {}, expected issuers: {})",
            d.name,
            d.include_subdomains,
            d.wildcards,
            d.lookalikes,
            d.typosquats,
            d.caa,
            d.expected_issuers.len()
        );
    }
    if cfg.logs.static_logs.is_empty() {
        println!(
            "  logs: from {} (tiled logs: {})",
            cfg.logs.list_url, cfg.logs.include_tiled
        );
    } else {
        println!("  logs: {} static", cfg.logs.static_logs.len());
    }
    println!("  sinks: {}", cfg.sink_labels().join(", "));
    println!("  data dir: {}", cfg.data_dir.display());
    if let Some(a) = cfg.admin_listen() {
        println!("  management listener: {a}");
    }
    println!("  TR39 confusables: {} mappings", confusables::table_len());
    let missing = cfg.missing_env();
    if !missing.is_empty() {
        bail!("environment variables not set: {}", missing.join(", "));
    }
    Ok(())
}

async fn inspect(cfg: &Config, file: &Path, with_caa: bool, revocation: bool) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("cannot read {}", file.display()))?;
    let info = cert::parse_cert_file(&bytes)?;
    let matches = Matcher::new(&cfg.domains).check(&info);
    let kind = if info.precert {
        "precertificate"
    } else {
        "certificate"
    };
    let plain = |s: &str| notify::clip(s);
    println!("Type:        {kind}");
    println!(
        "Subject CN:  {}",
        plain(info.subject_cn.as_deref().unwrap_or("-"))
    );
    println!("SANs:        {}", plain(&info.dns_names.join(", ")));
    println!("Issuer:      {}", plain(&info.issuer_label()));
    println!("Serial:      {}", info.serial_hex);
    println!(
        "Valid:       {} -> {}",
        cert::fmt_time(info.not_before),
        cert::fmt_time(info.not_after)
    );
    let client = ct::http_client()?;
    if revocation {
        let status = crl::CrlCache::default().check(&client, &info).await;
        println!("Revocation:  {}", serde_json::to_string(&status)?);
    }
    println!();
    if matches.is_empty() {
        println!("Verdict:     no rule matched, no alert");
        return Ok(());
    }
    for m in &matches {
        println!(
            "Rule:        {} {} via {}{}{}",
            m.kind.label(),
            m.domain,
            plain(&m.name),
            m.detail
                .as_deref()
                .map(|d| format!(" [{d}]"))
                .unwrap_or_default(),
            if m.expected_issuer {
                " (muted: expected issuer)"
            } else {
                ""
            }
        );
    }
    let mut violation = None;
    if with_caa {
        let issuers = caa::issuer_caa_domains(&info, &cfg.caa.issuer_domains);
        for m in matches.iter().filter(|m| !m.kind.is_impersonation()) {
            match caa::lookup_policy(&client, &cfg.caa.resolver, &m.domain).await? {
                None => println!(
                    "CAA:         {} has no CAA records (any CA may issue)",
                    m.domain
                ),
                Some(p) => {
                    let v = caa::evaluate(&p, m.name.starts_with("*."), &issuers);
                    println!(
                        "CAA:         {} issue={:?} issuewild={:?} -> {v:?}",
                        p.found_at, p.issue, p.issuewild
                    );
                    if let caa::Verdict::Violation(r) = v {
                        violation = Some(r);
                    }
                }
            }
        }
    }
    if violation.is_none() && matches.iter().all(|m| m.expected_issuer) {
        println!("Verdict:     muted by expected_issuers, no alert");
        return Ok(());
    }
    println!("Verdict:     ALERT -> {}", cfg.sink_labels().join(", "));
    let alert = CertAlert {
        log: format!("local file {}", file.display()),
        index: 0,
        logged_ms: (time::OffsetDateTime::now_utc().unix_timestamp() as u64) * 1000,
        cert: info,
        matches,
    };
    let kit = alert.to_kit(violation.as_deref());
    println!("Alert:       {}", kit.headline());
    println!("\nTelegram message (HTML):\n{}", alert.render(true));
    Ok(())
}

async fn test_alert(cfg: Config) -> Result<()> {
    let mut alerts = cfg.alerts.clone();
    // A test must not linger in the persistent queue and reappear later.
    alerts.queue.persistent = false;
    let dispatcher = Dispatcher::start(
        &alerts,
        DispatcherOptions {
            tool: TOOL.into(),
            data_dir: None,
            silences: None,
            http: None,
        },
    )?;
    let metrics = dispatcher.metrics();
    let mut kit = notify::sample_alert(&cfg.domains[0].name).to_kit(None);
    kit.severity = Severity::Info;
    kit.title = format!("Test alert: {}", kit.title);
    dispatcher.handle().send(kit);
    dispatcher.shutdown(Duration::from_secs(30)).await;
    let mut failed = 0;
    for s in &metrics.sinks {
        let snap = s.snapshot();
        let ok = snap.sent > 0;
        failed += usize::from(!ok);
        println!(
            "  {:<20} {}",
            s.name,
            if ok {
                "delivered"
            } else {
                "NOT delivered (see log)"
            }
        );
    }
    if failed > 0 {
        bail!("{failed} sink(s) did not accept the test alert");
    }
    println!("test alert delivered to {} sink(s)", metrics.sinks.len());
    Ok(())
}

async fn backfill(cfg: &Config, only: Option<String>, crtsh: &str) -> Result<()> {
    let client = ct::http_client_with_timeout(Duration::from_secs(120))?;
    let matcher = Matcher::new(&cfg.domains);
    let path = cfg.data_dir.join("inventory.json");
    let mut inv = Inventory::open(&path, cfg.inventory.max_certs)?;
    let now = chrono::Utc::now().timestamp();
    let mut done = 0;
    for d in &cfg.domains {
        if only.as_deref().is_some_and(|o| o != d.name) {
            continue;
        }
        let mut added =
            inventory::backfill_crtsh(&client, crtsh, &d.name, false, &matcher, &mut inv, now)
                .await?;
        if d.include_subdomains {
            added +=
                inventory::backfill_crtsh(&client, crtsh, &d.name, true, &matcher, &mut inv, now)
                    .await?;
        }
        println!("{}: {added} new certificate(s) from crt.sh", d.name);
        done += 1;
    }
    if done == 0 {
        bail!("no configured domain matches --domain");
    }
    inv.save()?;
    println!(
        "inventory: {} certificate(s) in {}",
        inv.certs.len(),
        path.display()
    );
    Ok(())
}

/// State that survives configuration reloads.
struct Shared {
    metrics: Arc<Metrics>,
    silences: Arc<SilenceStore>,
    readiness: Readiness,
    client: reqwest::Client,
}

struct Running {
    handle: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

/// Everything started from one configuration.
struct Instance {
    stop: watch::Sender<bool>,
    manager: JoinHandle<()>,
    notifier: JoinHandle<()>,
    background: Vec<JoinHandle<()>>,
    dispatcher: Dispatcher,
    inventory: Arc<Mutex<Inventory>>,
}

fn daemon(config: PathBuf, mut shutdown: Shutdown) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start async runtime")?
        .block_on(async move {
            let mut cfg = Config::load(&config)?;
            let missing = cfg.missing_env();
            if !missing.is_empty() {
                bail!("environment variables not set: {}", missing.join(", "));
            }
            std::fs::create_dir_all(&cfg.data_dir)
                .with_context(|| format!("cannot create data dir {}", cfg.data_dir.display()))?;
            let shared = Shared {
                metrics: Arc::new(Metrics::default()),
                silences: Arc::new(SilenceStore::open(cfg.silences_path())?),
                readiness: Readiness::new(),
                client: ct::http_client()?,
            };
            shared.readiness.register("logs");
            let mut reload = ReloadSignal::standard(Some(config.clone()))?;
            if let Some(addr) = cfg.admin_listen() {
                let mut admin = metrics::router(shared.metrics.clone())
                    .merge(health_router(shared.readiness.clone()));
                if let Some(var) = &cfg.silences.api_token_env {
                    admin = admin.merge(silences_router(shared.silences.clone(), ApiToken::from_env(var)?));
                }
                if let Some(var) = &cfg.health.admin_token_env {
                    admin = admin.merge(reload_router(reload.trigger(), ApiToken::from_env(var)?));
                }
                let mut sd = shutdown.clone();
                tokio::spawn(async move {
                    if let Err(e) = llcforge_alert::serve(addr, admin, async move { sd.wait().await }).await {
                        tracing::error!(error = %e, "management listener failed");
                    }
                });
            }
            loop {
                let inst = start_instance(&cfg, &shared)?;
                let stop_reason = tokio::select! {
                    _ = shutdown.wait() => None,
                    r = reload.recv() => r,
                };
                match stop_reason {
                    None => {
                        tracing::info!("shutting down, flushing checkpoints");
                        stop_instance(inst, &shared).await;
                        return Ok(());
                    }
                    Some(reason) => match Config::load(&config) {
                        Ok(new) if new.missing_env().is_empty() => {
                            tracing::info!(?reason, "configuration reloaded, restarting tailers");
                            if new.admin_listen() != cfg.admin_listen() {
                                tracing::warn!("management listener address changes need a restart");
                            }
                            stop_instance(inst, &shared).await;
                            cfg = new;
                        }
                        Ok(new) => {
                            tracing::error!(missing = ?new.missing_env(), "reload refused: environment variables not set; keeping the old configuration");
                            // Keep running the current instance.
                            wait_instance_again(inst, &shared, &mut shutdown, &mut reload, &config, &mut cfg).await?;
                            if shutdown.is_triggered() {
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %format!("{e:#}"), "invalid configuration; keeping the old one");
                            wait_instance_again(inst, &shared, &mut shutdown, &mut reload, &config, &mut cfg).await?;
                            if shutdown.is_triggered() {
                                return Ok(());
                            }
                        }
                    },
                }
            }
        })
}

/// Keeps an instance running after a refused reload until shutdown or a valid reload.
async fn wait_instance_again(
    inst: Instance,
    shared: &Shared,
    shutdown: &mut Shutdown,
    reload: &mut ReloadSignal,
    config: &Path,
    cfg: &mut Config,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.wait() => {
                stop_instance(inst, shared).await;
                return Ok(());
            }
            Some(reason) = reload.recv() => {
                match Config::load(config) {
                    Ok(new) if new.missing_env().is_empty() => {
                        tracing::info!(?reason, "configuration reloaded, restarting tailers");
                        stop_instance(inst, shared).await;
                        *cfg = new;
                        return Ok(());
                    }
                    Ok(_) => tracing::error!("reload refused: environment variables not set"),
                    Err(e) => tracing::error!(error = %format!("{e:#}"), "invalid configuration; keeping the old one"),
                }
            }
        }
    }
}

fn start_instance(cfg: &Config, shared: &Shared) -> Result<Instance> {
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("cannot create data dir {}", cfg.data_dir.display()))?;
    let dispatcher = Dispatcher::start(
        &cfg.alerts,
        DispatcherOptions {
            tool: TOOL.into(),
            data_dir: Some(cfg.data_dir.clone()),
            silences: Some(shared.silences.clone()),
            http: None,
        },
    )?;
    if let Ok(mut d) = shared.metrics.dispatcher.lock() {
        *d = Some(dispatcher.metrics());
    }
    let kit = dispatcher.handle();
    let now = chrono::Utc::now().timestamp();
    let inventory = Arc::new(Mutex::new(Inventory::open(
        &cfg.data_dir.join("inventory.json"),
        cfg.inventory.max_certs,
    )?));
    let mut background = Vec::new();

    let caa_cache: caa::CaaCache = Arc::new(RwLock::new(HashMap::new()));
    let caa_domains: Vec<String> = cfg
        .domains
        .iter()
        .filter(|d| d.caa)
        .map(|d| d.name.clone())
        .collect();
    if !caa_domains.is_empty() {
        background.push(tokio::spawn(caa::refresher(
            shared.client.clone(),
            cfg.caa.resolver.clone(),
            caa_domains,
            caa_cache.clone(),
            Duration::from_secs(cfg.caa.refresh_secs),
        )));
    }
    let tg = match &cfg.telegram_actions {
        Some(t) => {
            let (tg, handles) = tgactions::start(
                t,
                shared.client.clone(),
                kit.clone(),
                inventory.clone(),
                shared.silences.clone(),
            )?;
            background.extend(handles);
            Some(tg)
        }
        None => None,
    };
    background.push(tokio::spawn(inventory_task(
        cfg.clone(),
        inventory.clone(),
        kit.clone(),
        shared.metrics.clone(),
        shared.client.clone(),
    )));

    let (tx, rx) = mpsc::channel::<CertAlert>(1024);
    let pipeline = notify::Pipeline {
        handle: kit.clone(),
        dedup: dedup::Dedup::open(cfg.dedup.window_secs, &cfg.data_dir.join("dedup.json"), now),
        rules: cfg
            .domains
            .iter()
            .map(|d| (d.name.clone(), d.clone()))
            .collect(),
        caa: caa_cache,
        caa_overrides: cfg.caa.issuer_domains.clone(),
        inventory: inventory.clone(),
        metrics: shared.metrics.clone(),
        silences: shared.silences.clone(),
        tg,
    };
    let notifier = tokio::spawn(notify::run(rx, pipeline));
    let ctx = Arc::new(tailer::TailerCtx {
        client: shared.client.clone(),
        data_dir: cfg.data_dir.clone(),
        logs: cfg.logs.clone(),
        matcher: Arc::new(Matcher::new(&cfg.domains)),
        alerts: tx,
        metrics: shared.metrics.clone(),
        kit,
    });
    let (stop, stop_rx) = watch::channel(false);
    let manager = tokio::spawn(manage_logs(ctx, stop_rx, shared.readiness.clone()));
    Ok(Instance {
        stop,
        manager,
        notifier,
        background,
        dispatcher,
        inventory,
    })
}

async fn stop_instance(inst: Instance, shared: &Shared) {
    let _ = inst.stop.send(true);
    if tokio::time::timeout(Duration::from_secs(60), inst.manager)
        .await
        .is_err()
    {
        tracing::warn!("tailers did not stop in time");
    }
    if tokio::time::timeout(Duration::from_secs(30), inst.notifier)
        .await
        .is_err()
    {
        tracing::warn!("pending matches were not all processed before exit");
    }
    for b in inst.background {
        b.abort();
    }
    if let Ok(mut inv) = inst.inventory.lock() {
        if let Err(e) = inv.save() {
            tracing::error!(error = %format!("{e:#}"), "cannot save the inventory");
        }
    }
    inst.dispatcher.shutdown(Duration::from_secs(10)).await;
    shared.readiness.set("logs", false);
}

/// Loads the log list periodically, runs one tailer per log, stops them all on `stop`.
async fn manage_logs(
    ctx: Arc<tailer::TailerCtx>,
    mut stop: watch::Receiver<bool>,
    readiness: Readiness,
) {
    let mut running: HashMap<String, Running> = HashMap::new();
    loop {
        let next_refresh = match loglist::load(&ctx.client, &ctx.logs).await {
            Ok(logs) => {
                reconcile(&mut running, logs, &ctx);
                readiness.set("logs", !running.is_empty());
                Duration::from_secs(ctx.logs.list_refresh_secs)
            }
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "cannot load CT log list");
                Duration::from_secs(60)
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(next_refresh) => {}
            _ = stop.changed() => break,
        }
    }
    drop(ctx);
    for r in running.values() {
        let _ = r.stop.send(true);
    }
    for (_, r) in running {
        if tokio::time::timeout(Duration::from_secs(45), r.handle)
            .await
            .is_err()
        {
            tracing::warn!("a tailer did not stop in time");
        }
    }
}

/// Starts tailers for new logs and stops tailers for logs that left the list.
fn reconcile(
    running: &mut HashMap<String, Running>,
    logs: Vec<loglist::LogInfo>,
    ctx: &Arc<tailer::TailerCtx>,
) {
    let wanted: HashMap<String, loglist::LogInfo> =
        logs.into_iter().map(|l| (l.url.clone(), l)).collect();
    running.retain(|url, r| {
        if !wanted.contains_key(url) {
            tracing::info!(%url, "log left the list, stopping its tailer");
            let _ = r.stop.send(true);
            return false;
        }
        // A tailer that exited on its own (bad key, unreadable checkpoint) is retried here.
        !r.handle.is_finished()
    });
    let mut started = 0u32;
    for (url, log) in wanted {
        if running.contains_key(&url) {
            continue;
        }
        let (stop, stop_rx) = watch::channel(false);
        let delay = Duration::from_millis(250 * u64::from(started.min(120)));
        started += 1;
        let handle = tokio::spawn(tailer::run(log, ctx.clone(), stop_rx, delay));
        running.insert(url, Running { handle, stop });
    }
    tracing::info!(logs = running.len(), "monitoring CT logs");
}

/// Persists the inventory, raises expiry warnings (79) and tracks takedowns via CRLs (83).
async fn inventory_task(
    cfg: Config,
    inventory: Arc<Mutex<Inventory>>,
    kit: llcforge_alert::AlertHandle,
    metrics: Arc<Metrics>,
    client: reqwest::Client,
) {
    let mut crls = crl::CrlCache::default();
    let mut expiring: BTreeSet<String> = BTreeSet::new();
    let check_every = Duration::from_secs(cfg.inventory.check_interval_secs);
    let mut last_check: Option<Instant> = None;
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let now = chrono::Utc::now().timestamp();
        let (warn, candidates) = {
            let Ok(mut inv) = inventory.lock() else {
                return;
            };
            if let Err(e) = inv.save() {
                tracing::error!(error = %format!("{e:#}"), "cannot save the inventory");
            }
            Metrics::set(&metrics.inventory_certs, inv.certs.len() as u64);
            if last_check.is_some_and(|t| t.elapsed() < check_every) {
                continue;
            }
            let warn = if cfg.inventory.expiry_warn_days > 0 {
                inv.expiring(now, i64::from(cfg.inventory.expiry_warn_days) * 86_400)
            } else {
                Vec::new()
            };
            let candidates = if cfg.inventory.revocation_check {
                inv.takedown_candidates(now)
            } else {
                Vec::new()
            };
            (warn, candidates)
        };
        last_check = Some(Instant::now());
        Metrics::set(&metrics.expiring_names, warn.len() as u64);
        let current: BTreeSet<String> = warn.iter().map(|(n, _)| n.clone()).collect();
        for (name, h) in &warn {
            if expiring.contains(name) {
                continue;
            }
            let days = (h.latest_expiry - now).div_euclid(86_400);
            kit.send(
                KitAlert::new(
                    TOOL,
                    "cert_expiring",
                    Severity::Warning,
                    format!("Certificate for {name} expires in {days} days"),
                )
                .resource(h.domain.clone())
                .id(format!("{TOOL}:cert_expiring:{name}"))
                .summary("No newer certificate for this name has appeared in CT.")
                .field("name", name)
                .field("expires", cert::fmt_time(h.latest_expiry))
                .field(
                    "issuers",
                    h.issuers.iter().cloned().collect::<Vec<_>>().join(", "),
                ),
            );
        }
        for name in expiring.difference(&current) {
            let domain = cfg
                .domains
                .iter()
                .find(|d| name == &d.name || name.ends_with(&format!(".{}", d.name)))
                .map(|d| d.name.clone())
                .unwrap_or_default();
            kit.send(
                KitAlert::new(
                    TOOL,
                    "cert_expiring",
                    Severity::Warning,
                    format!("Certificate for {name} renewed"),
                )
                .resource(domain)
                .id(format!("{TOOL}:cert_expiring:{name}"))
                .resolved(true),
            );
        }
        expiring = current;
        for c in candidates {
            let info = cert::CertInfo {
                dns_names: c.names.clone(),
                subject_cn: None,
                issuer_o: None,
                issuer_cn: None,
                issuer_dn: c.issuer_dn.clone(),
                serial_hex: c.serial.clone(),
                not_before: c.not_before,
                not_after: c.not_after,
                precert: c.precert,
                crl_urls: c.crl_urls.clone(),
            };
            if let crl::Revocation::Revoked { at } = crls.check(&client, &info).await {
                Metrics::inc(&metrics.revoked_takedowns);
                if let Ok(mut inv) = inventory.lock() {
                    inv.set_revoked(&c.key(), at);
                }
                kit.send(
                    KitAlert::new(
                        TOOL,
                        "cert_revoked",
                        Severity::Info,
                        format!(
                            "Tracked {} certificate revoked: {}",
                            c.kind.alert_kind(),
                            c.names.first().map(String::as_str).unwrap_or("?")
                        ),
                    )
                    .resource(c.domain.clone())
                    .id(format!("{TOOL}:cert_revoked:{}:{}", c.domain, c.serial))
                    .field("serial", &c.serial)
                    .field("issuer", &c.issuer)
                    .field("revoked", cert::fmt_time(at)),
                );
            }
        }
    }
}
