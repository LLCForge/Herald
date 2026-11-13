//! Collapses a precertificate and its final certificate (same issuer + serial) into one
//! alert. The state is persisted so a restart does not re-alert recent certificates.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Hard cap on remembered keys so a flood of matches cannot grow memory without bound.
const MAX_KEYS: usize = 100_000;

pub struct Dedup {
    window_secs: i64,
    seen: HashMap<(String, String), i64>,
    path: Option<PathBuf>,
    dirty: bool,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    /// `[issuer_dn, serial_hex, unix_seconds]`.
    seen: Vec<(String, String, i64)>,
}

impl Dedup {
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_secs: i64::try_from(window_secs).unwrap_or(i64::MAX),
            seen: HashMap::new(),
            path: None,
            dirty: false,
        }
    }

    /// Loads `path` if it exists (unreadable state is logged and ignored: worst case is a duplicate alert).
    pub fn open(window_secs: u64, path: &Path, now: i64) -> Self {
        let mut d = Self::new(window_secs);
        d.path = Some(path.to_path_buf());
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<Stored>(&bytes) {
                Ok(s) => {
                    for (issuer, serial, t) in s.seen.into_iter().take(MAX_KEYS) {
                        if now - t < d.window_secs {
                            d.seen.insert((issuer, serial), t);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "dedup state corrupt, starting empty")
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "dedup state unreadable, starting empty")
            }
        }
        d
    }

    /// Returns true the first time a key is seen within the window.
    pub fn first_seen(&mut self, issuer: &str, serial: &str, now: i64) -> bool {
        if self.seen.len() >= MAX_KEYS {
            let window = self.window_secs;
            self.seen.retain(|_, t| now - *t < window);
            if self.seen.len() >= MAX_KEYS {
                self.seen.clear();
            }
        }
        let key = (issuer.to_string(), serial.to_string());
        match self.seen.get(&key) {
            Some(t) if now - *t < self.window_secs => false,
            _ => {
                self.seen.insert(key, now);
                self.dirty = true;
                true
            }
        }
    }

    /// Persists the state if it changed.
    pub fn save(&mut self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if !self.dirty {
            return Ok(());
        }
        let stored = Stored {
            seen: self
                .seen
                .iter()
                .map(|((i, s), t)| (i.clone(), s.clone(), *t))
                .collect(),
        };
        let body = serde_json::to_vec(&stored).context("serialising dedup state")?;
        crate::checkpoint::atomic_write(path, &body)?;
        self.dirty = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precert_and_cert_collapse_within_window() {
        let mut d = Dedup::new(60);
        let t0 = 1_700_000_000;
        assert!(d.first_seen("CN=R11", "03ab", t0));
        assert!(!d.first_seen("CN=R11", "03ab", t0 + 30));
        assert!(d.first_seen("CN=R10", "03ab", t0));
        assert!(d.first_seen("CN=R11", "03ac", t0));
        assert!(d.first_seen("CN=R11", "03ab", t0 + 61));
    }

    #[test]
    fn survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("herald-dedup-{}", std::process::id()));
        let path = dir.join("dedup.json");
        let t0 = 1_700_000_000;
        let mut d = Dedup::open(3600, &path, t0);
        assert!(d.first_seen("CN=R11", "01", t0));
        d.save().unwrap();
        let mut again = Dedup::open(3600, &path, t0 + 10);
        assert!(!again.first_seen("CN=R11", "01", t0 + 10));
        // Expired entries are dropped on load.
        let mut later = Dedup::open(3600, &path, t0 + 7200);
        assert!(later.first_seen("CN=R11", "01", t0 + 7200));
        std::fs::write(&path, b"{garbage").unwrap();
        let mut corrupt = Dedup::open(3600, &path, t0);
        assert!(corrupt.first_seen("CN=R11", "01", t0));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
