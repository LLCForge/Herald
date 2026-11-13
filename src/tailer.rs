//! One task per CT log: poll the tree head (RFC 6962 STH or static-ct-api
//! checkpoint), verify its signature and consistency with the previous one,
//! fetch new entries with adaptive parallelism, match, checkpoint.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use llcforge_alert::{Alert as KitAlert, AlertHandle, Severity};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::checkpoint::{start_index, CheckpointStore};
use crate::config::LogsConfig;
use crate::ct::{self, FetchError, LeafError, LogClient, LogKey, ParsedEntry};
use crate::loglist::LogInfo;
use crate::matcher::Matcher;
use crate::merkle::{self, Hash, TileId, TileTree};
use crate::metrics::Metrics;
use crate::notify::{CertAlert, TOOL};
use crate::tiled::{self, TiledClient};

pub struct TailerCtx {
    pub client: reqwest::Client,
    pub data_dir: PathBuf,
    pub logs: LogsConfig,
    pub matcher: Arc<Matcher>,
    pub alerts: mpsc::Sender<CertAlert>,
    pub metrics: Arc<Metrics>,
    pub kit: AlertHandle,
}

const MAX_BACKOFF: Duration = Duration::from_secs(600);
/// Hash tiles kept in memory per tiled log (8 KiB each).
const TILE_CACHE: usize = 1024;

/// Additive-increase / multiplicative-decrease parallelism (item 81).
#[derive(Debug, Clone, Copy)]
pub struct Adaptive {
    pub current: usize,
    pub max: usize,
}

impl Adaptive {
    pub fn new(max: usize) -> Self {
        Self {
            current: max.clamp(1, 2),
            max: max.max(1),
        }
    }
    /// After a successful round: grow while far behind.
    pub fn on_success(&mut self, backlog: u64, per_request: u64) {
        if backlog
            > per_request
                .saturating_mul(self.current as u64)
                .saturating_mul(2)
        {
            self.current = (self.current + 1).min(self.max);
        }
    }
    /// On rate limiting or server errors: halve.
    pub fn on_throttle(&mut self) {
        self.current = (self.current / 2).max(1);
    }
}

struct Tailer {
    log: LogInfo,
    ctx: Arc<TailerCtx>,
    client: LogClient,
    tiles: Option<(TiledClient, TileTree)>,
    key: Option<LogKey>,
    store: CheckpointStore,
    next: Option<u64>,
    batch: u64,
    par: Adaptive,
}

/// `delay` staggers start-up so dozens of logs do not connect at the same instant.
pub async fn run(
    log: LogInfo,
    ctx: Arc<TailerCtx>,
    mut stop: watch::Receiver<bool>,
    delay: Duration,
) {
    tokio::select! {
        _ = tokio::time::sleep(delay) => {}
        _ = stop.changed() => return,
    }
    let key = match (&log.key, ctx.logs.verify_sth) {
        (Some(k), true) => match LogKey::from_spki_b64(k) {
            Ok(k) => Some(k),
            Err(e) => {
                tracing::error!(log = %log.description, error = %e, "unusable log key, not tailing");
                return;
            }
        },
        (None, true) => {
            tracing::warn!(log = %log.description, "no public key configured, tree head signatures not verified");
            None
        }
        (_, false) => None,
    };
    let mut store = CheckpointStore::new(&ctx.data_dir, &log.url);
    let next = match store.load() {
        Ok(n) => n,
        Err(e) => {
            // Refuse to guess: restarting at the tree head would silently skip entries.
            tracing::error!(log = %log.description, error = %format!("{e:#}"), "checkpoint unreadable, not tailing; fix or delete it");
            return;
        }
    };
    let tiles = log.tiled.then(|| {
        (
            TiledClient::new(ctx.client.clone(), &log.url),
            TileTree::new(0),
        )
    });
    let mut t = Tailer {
        client: LogClient::new(ctx.client.clone(), &log.url),
        tiles,
        batch: ctx.logs.batch_size,
        par: Adaptive::new(ctx.logs.fetch_concurrency),
        log,
        ctx,
        key,
        store,
        next,
    };
    let tiled = t.tiles.is_some();
    t.ctx
        .metrics
        .update_log(&t.log.description, |s| s.tiled = tiled);
    tracing::info!(log = %t.log.description, tiled, resume = ?t.next, "tailer started");
    let poll = Duration::from_secs(t.ctx.logs.poll_interval_secs);
    let mut failures = 0u32;
    loop {
        let res = if tiled {
            t.cycle_tiled(&mut stop).await
        } else {
            t.cycle(&mut stop).await
        };
        match res {
            Ok(()) => failures = 0,
            Err(e) => {
                failures += 1;
                t.ctx
                    .metrics
                    .update_log(&t.log.description, |s| s.fetch_errors += 1);
                tracing::warn!(log = %t.log.description, error = %format!("{e:#}"), failures, "tailer cycle failed");
            }
        }
        if *stop.borrow() {
            break;
        }
        let wait = (poll * 2u32.pow(failures.min(10))).min(MAX_BACKOFF.max(poll));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = stop.changed() => break,
        }
    }
    tracing::info!(log = %t.log.description, next = ?t.next, "tailer stopped");
}

impl Tailer {
    fn report_inconsistency(&self, err: &anyhow::Error) {
        self.ctx
            .metrics
            .update_log(&self.log.description, |s| s.consistency_failures += 1);
        tracing::error!(log = %self.log.description, error = %format!("{err:#}"), "CT log tree heads are inconsistent");
        self.ctx.kit.send(
            KitAlert::new(
                TOOL,
                "log_inconsistent",
                Severity::Critical,
                format!(
                    "CT log {} served an inconsistent tree head",
                    self.log.description
                ),
            )
            .resource(self.log.url.clone())
            .summary(format!("{err:#}"))
            .field("log", &self.log.description),
        );
    }

    /// Verifies the new tree head against the last verified one (RFC 6962 proof).
    async fn check_consistency(&mut self, size: u64, root: &Hash) -> Result<bool> {
        let Some((old, old_root)) = self.store.head() else {
            return Ok(true);
        };
        let res = if old == size {
            if &old_root == root {
                Ok(())
            } else {
                Err(anyhow!("tree size {size} has two different root hashes"))
            }
        } else if old < size {
            let proof = self
                .client
                .get_consistency(old, size)
                .await
                .map_err(fetch_err)?;
            merkle::verify_consistency(old, size, &old_root, root, &proof)
        } else {
            // A lagging frontend may serve an older head; it must still be a prefix.
            let proof = self
                .client
                .get_consistency(size, old)
                .await
                .map_err(fetch_err)?;
            merkle::verify_consistency(size, old, root, &old_root, &proof)
        };
        if let Err(e) = res {
            self.report_inconsistency(&e);
            return Err(e.context("rejecting tree head"));
        }
        Ok(old <= size)
    }

    async fn cycle(&mut self, stop: &mut watch::Receiver<bool>) -> Result<()> {
        let sth = tokio::select! {
            r = self.client.get_sth() => r.map_err(fetch_err)?,
            _ = stop.changed() => return Ok(()),
        };
        if let Some(key) = &self.key {
            if let Err(e) = key.verify_sth(&sth) {
                self.ctx
                    .metrics
                    .update_log(&self.log.description, |s| s.sth_failures += 1);
                return Err(e.context("rejecting tree head"));
            }
        }
        let tree_size = sth.tree_size;
        let head_before = self.store.head();
        if self.ctx.logs.verify_sth {
            let root: Hash = B64
                .decode(&sth.sha256_root_hash)
                .ok()
                .and_then(|v| v.try_into().ok())
                .context("STH root hash must be 32 bytes of base64")?;
            if !self.check_consistency(tree_size, &root).await? {
                return Ok(()); // stale head from a lagging frontend
            }
            self.store.set_head(tree_size, root);
        }
        let next = match self.next {
            Some(n) => n,
            None => start_index(None, tree_size, self.ctx.logs.backfill),
        };
        if self.next.is_none() || self.store.head() != head_before {
            self.store.save(next)?;
        }
        self.next = Some(next);
        self.ctx.metrics.update_log(&self.log.description, |s| {
            s.tree_size = tree_size;
            s.next_index = next;
        });
        let mut next = next;
        while next < tree_size {
            if *stop.borrow() {
                return Ok(());
            }
            // Fetch consecutive pages in parallel, process them in order.
            let mut ranges = Vec::new();
            let mut start = next;
            while ranges.len() < self.par.current && start < tree_size {
                let end = (start + self.batch).min(tree_size) - 1;
                ranges.push((start, end));
                start = end + 1;
            }
            let mut set = JoinSet::new();
            for (i, &(s, e)) in ranges.iter().enumerate() {
                let client = self.client.clone();
                set.spawn(async move { (i, client.get_entries(s, e).await) });
            }
            let mut pages: Vec<Option<Result<Vec<ct::RawEntry>, FetchError>>> =
                ranges.iter().map(|_| None).collect();
            loop {
                tokio::select! {
                    r = set.join_next() => match r {
                        Some(Ok((i, page))) => pages[i] = Some(page),
                        Some(Err(e)) => return Err(anyhow!("fetch task failed: {e}")),
                        None => break,
                    },
                    // Dropping the JoinSet aborts in-flight requests; nothing was processed yet.
                    _ = stop.changed() => return Ok(()),
                }
            }
            for (&(s, e), page) in ranges.iter().zip(pages) {
                let entries = match page.ok_or_else(|| anyhow!("missing page {s}..={e}"))? {
                    Ok(p) => p,
                    Err(err) => return Err(self.throttle(err)),
                };
                if entries.is_empty() {
                    return Err(anyhow!("log returned no entries for {s}..={e}"));
                }
                let requested = e - s + 1;
                let got = (entries.len() as u64).min(requested);
                for (i, raw) in entries.iter().take(got as usize).enumerate() {
                    self.process(s + i as u64, ct::decode_entry(raw)).await?;
                }
                next = s + got;
                self.save_progress(next, got)?;
                if got < requested {
                    // The log caps its page size: use that size and refetch the rest.
                    self.batch = got;
                    break;
                }
            }
            self.par.on_success(tree_size - next, self.batch);
            self.publish_par();
        }
        Ok(())
    }

    fn throttle(&mut self, err: FetchError) -> anyhow::Error {
        if matches!(err, FetchError::Retryable(_)) {
            self.par.on_throttle();
            self.publish_par();
        }
        fetch_err(err)
    }

    fn publish_par(&self) {
        let c = self.par.current as u64;
        self.ctx
            .metrics
            .update_log(&self.log.description, |s| s.concurrency = c);
    }

    fn save_progress(&mut self, next: u64, got: u64) -> Result<()> {
        self.store.save(next)?;
        self.next = Some(next);
        self.ctx.metrics.update_log(&self.log.description, |st| {
            st.next_index = next;
            st.entries += got;
        });
        Ok(())
    }

    /// Fetches the hash tiles a computation needs (in parallel) until it completes.
    async fn resolve(
        client: &TiledClient,
        tree: &mut TileTree,
        size: u64,
        known: Option<(u64, u64, Hash)>,
    ) -> Result<Hash> {
        for _ in 0..12 {
            let missing = match tree.root_with(size, known) {
                Ok(h) => return Ok(h),
                Err(m) => m,
            };
            let mut set = JoinSet::new();
            for id in missing.into_iter().take(64) {
                if id.width == 0 {
                    bail!("tile {id:?} cannot exist in a tree of {}", tree.size());
                }
                let c = client.clone();
                set.spawn(async move { (id, c.hash_tile(id).await) });
            }
            while let Some(r) = set.join_next().await {
                let (id, tile): (TileId, _) = r.map_err(|e| anyhow!("tile task failed: {e}"))?;
                tree.insert(id, tile.map_err(fetch_err)?);
            }
        }
        bail!("tile computation did not converge")
    }

    async fn cycle_tiled(&mut self, stop: &mut watch::Receiver<bool>) -> Result<()> {
        let Some((tclient, _)) = self.tiles.as_ref() else {
            bail!("not a tiled log");
        };
        let tclient = tclient.clone();
        let body = tokio::select! {
            r = tclient.checkpoint() => r.map_err(fetch_err)?,
            _ = stop.changed() => return Ok(()),
        };
        let key = if self.ctx.logs.verify_sth {
            self.key.as_ref()
        } else {
            None
        };
        let cp = match tiled::parse_checkpoint(&body, key, self.log.origin.as_deref()) {
            Ok(cp) => cp,
            Err(e) => {
                self.ctx
                    .metrics
                    .update_log(&self.log.description, |s| s.sth_failures += 1);
                return Err(e.context("rejecting checkpoint"));
            }
        };
        let n = cp.size;
        let verify = self.ctx.logs.verify_sth;
        let head_before = self.store.head();
        if verify && head_before != Some((n, cp.root)) {
            if let Some((old, old_root)) = head_before {
                // Consistency via tiles: both roots must come out of the same node hashes.
                let res = if old > n {
                    let mut older = TileTree::new(old);
                    Self::resolve(&tclient, &mut older, n, None)
                        .await
                        .and_then(|r| {
                            if r == cp.root {
                                Ok(())
                            } else {
                                Err(anyhow!(
                                    "checkpoint {n} is not a prefix of the verified tree {old}"
                                ))
                            }
                        })
                } else {
                    let tree = &mut self.tiles.as_mut().context("tiles")?.1;
                    tree.set_size(n);
                    tree.trim(TILE_CACHE);
                    let new_root = Self::resolve(&tclient, tree, n, None).await?;
                    let old_calc = Self::resolve(&tclient, tree, old, None).await?;
                    if new_root != cp.root {
                        Err(anyhow!("tiles do not hash to the checkpoint root"))
                    } else if old_calc != old_root {
                        Err(anyhow!(
                            "tree {n} is not consistent with the verified tree {old}"
                        ))
                    } else {
                        Ok(())
                    }
                };
                if let Err(e) = res {
                    self.report_inconsistency(&e);
                    return Err(e.context("rejecting checkpoint"));
                }
                if old > n {
                    return Ok(()); // stale checkpoint from a cache
                }
            }
            self.store.set_head(n, cp.root);
        }
        if let Some((_, tree)) = self.tiles.as_mut() {
            tree.set_size(n);
        }
        let next = match self.next {
            Some(x) => x,
            None => start_index(None, n, self.ctx.logs.backfill),
        };
        if self.next.is_none() || self.store.head() != head_before {
            self.store.save(next)?;
        }
        self.next = Some(next);
        self.ctx.metrics.update_log(&self.log.description, |s| {
            s.tree_size = n;
            s.next_index = next;
        });
        let mut next = next;
        while next < n {
            if *stop.borrow() {
                return Ok(());
            }
            let mut tiles = Vec::new();
            let mut t = next / 256;
            while tiles.len() < self.par.current && t * 256 < n {
                tiles.push((t, merkle::tile_width(n, 0, t)));
                t += 1;
            }
            let mut set = JoinSet::new();
            for (i, &(idx, w)) in tiles.iter().enumerate() {
                let c = tclient.clone();
                set.spawn(async move { (i, c.data_tile(idx, w).await) });
            }
            let mut bodies: Vec<Option<Result<Vec<u8>, FetchError>>> =
                tiles.iter().map(|_| None).collect();
            loop {
                tokio::select! {
                    r = set.join_next() => match r {
                        Some(Ok((i, b))) => bodies[i] = Some(b),
                        Some(Err(e)) => return Err(anyhow!("fetch task failed: {e}")),
                        None => break,
                    },
                    _ = stop.changed() => return Ok(()),
                }
            }
            for (&(idx, w), body) in tiles.iter().zip(bodies) {
                let data = match body.ok_or_else(|| anyhow!("missing data tile {idx}"))? {
                    Ok(d) => d,
                    Err(err) => return Err(self.throttle(err)),
                };
                let entries = tiled::parse_data_tile_lenient(&data, w)
                    .with_context(|| format!("data tile {idx}"))?;
                let lo = idx * 256;
                if verify {
                    let hashes: Vec<Hash> = entries.iter().map(|e| e.leaf_hash).collect();
                    let local = merkle::mth(&hashes);
                    let tree = &mut self.tiles.as_mut().context("tiles")?.1;
                    tree.trim(TILE_CACHE);
                    let root =
                        Self::resolve(&tclient, tree, n, Some((lo, lo + u64::from(w), local)))
                            .await?;
                    if root != cp.root {
                        bail!("data tile {idx} does not hash to the checkpoint root");
                    }
                }
                for (i, e) in entries.iter().enumerate() {
                    let index = lo + i as u64;
                    if e.leaf_index.is_some_and(|li| li != index) {
                        bail!("entry {index} carries leaf_index {:?}", e.leaf_index);
                    }
                }
                let skip = (next - lo) as usize;
                let got = entries.len().saturating_sub(skip) as u64;
                for (i, e) in entries.into_iter().enumerate().skip(skip) {
                    self.process(lo + i as u64, e.parsed).await?;
                }
                next = lo + u64::from(w);
                self.save_progress(next, got)?;
            }
            self.par.on_success(n - next, 256);
            self.publish_par();
        }
        Ok(())
    }

    async fn process(&self, index: u64, parsed: Result<ParsedEntry, LeafError>) -> Result<()> {
        let entry = match parsed {
            Ok(e) => e,
            Err(e) => {
                self.ctx
                    .metrics
                    .update_log(&self.log.description, |s| s.malformed += 1);
                tracing::debug!(log = %self.log.description, index, error = %e, "skipping malformed entry");
                return Ok(());
            }
        };
        let matches = self.ctx.matcher.check(&entry.cert);
        if matches.is_empty() {
            return Ok(());
        }
        Metrics::inc(&self.ctx.metrics.matches);
        let alert = CertAlert {
            log: self.log.description.clone(),
            index,
            logged_ms: entry.timestamp_ms,
            cert: entry.cert,
            matches,
        };
        self.ctx
            .alerts
            .send(alert)
            .await
            .map_err(|_| anyhow!("alert queue closed"))
    }
}

fn fetch_err(e: FetchError) -> anyhow::Error {
    match e {
        FetchError::Retryable(code) => anyhow!("log answered HTTP {code}, backing off"),
        FetchError::Other(e) => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_parallelism_grows_and_backs_off() {
        let mut a = Adaptive::new(8);
        assert_eq!(a.current, 2);
        a.on_success(1_000_000, 256);
        a.on_success(1_000_000, 256);
        assert_eq!(a.current, 4);
        for _ in 0..10 {
            a.on_success(1_000_000, 256);
        }
        assert_eq!(a.current, 8, "capped at max");
        a.on_throttle();
        assert_eq!(a.current, 4);
        a.on_success(100, 256); // caught up: no growth
        assert_eq!(a.current, 4);
        for _ in 0..5 {
            a.on_throttle();
        }
        assert_eq!(a.current, 1);
        assert_eq!(Adaptive::new(1).current, 1);
    }
}
