//! Per-log checkpoints: the next entry index to fetch and the last verified tree
//! head (for consistency checks), persisted with atomic writes.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub url: String,
    pub next_index: u64,
    /// Last tree head whose signature (and consistency) was verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_hash: Option<String>,
}

pub struct CheckpointStore {
    path: PathBuf,
    url: String,
    head: Option<(u64, [u8; 32])>,
}

impl CheckpointStore {
    /// One file per log, named after the SHA-256 of its URL.
    pub fn new(dir: &Path, url: &str) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, url.as_bytes());
        let name = crate::cert::hex(&digest.as_ref()[..16]);
        Self {
            path: dir.join("checkpoints").join(format!("{name}.json")),
            url: url.to_string(),
            head: None,
        }
    }

    /// Last verified tree head (size, root), available after [`CheckpointStore::load`].
    pub fn head(&self) -> Option<(u64, [u8; 32])> {
        self.head
    }

    /// Records a verified tree head; persisted with the next [`CheckpointStore::save`].
    pub fn set_head(&mut self, size: u64, root: [u8; 32]) {
        self.head = Some((size, root));
    }

    pub fn load(&mut self) -> Result<Option<u64>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.path.display())),
        };
        let cp: Checkpoint = serde_json::from_str(&text)
            .with_context(|| format!("corrupt checkpoint {}", self.path.display()))?;
        if cp.url != self.url {
            anyhow::bail!("checkpoint {} belongs to {}", self.path.display(), cp.url);
        }
        if let (Some(size), Some(root)) = (cp.tree_size, cp.root_hash.as_deref()) {
            use base64::Engine;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(root)
                .ok()
                .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
                .with_context(|| format!("corrupt root hash in {}", self.path.display()))?;
            self.head = Some((size, raw));
        }
        Ok(Some(cp.next_index))
    }

    /// Writes to a temporary file, syncs it, then renames over the old checkpoint.
    pub fn save(&self, next_index: u64) -> Result<()> {
        use base64::Engine;
        let body = serde_json::to_vec_pretty(&Checkpoint {
            url: self.url.clone(),
            next_index,
            tree_size: self.head.map(|h| h.0),
            root_hash: self
                .head
                .map(|h| base64::engine::general_purpose::STANDARD.encode(h.1)),
        })?;
        atomic_write(&self.path, &body)
    }
}

/// Writes `body` to `path` via a synced temporary file and a rename.
pub fn atomic_write(path: &Path, body: &[u8]) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    {
        use std::io::Write;
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(body)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Where a tailer starts: the saved checkpoint, or `tree_size - backfill` on first start.
pub fn start_index(saved: Option<u64>, tree_size: u64, backfill: u64) -> u64 {
    match saved {
        Some(i) => i,
        None => tree_size.saturating_sub(backfill),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("herald-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn save_load_resume() {
        let dir = tmpdir("cp");
        let mut a = CheckpointStore::new(&dir, "https://ct.example.com/a/");
        let mut b = CheckpointStore::new(&dir, "https://ct.example.com/b/");
        assert_eq!(a.load().unwrap(), None);
        a.save(100).unwrap();
        a.save(356).unwrap();
        assert_eq!(a.load().unwrap(), Some(356));
        assert_eq!(b.load().unwrap(), None);
        // A restart resumes from the checkpoint, not from the new tree head.
        assert_eq!(start_index(a.load().unwrap(), 10_000, 0), 356);
        assert_eq!(start_index(None, 10_000, 0), 10_000);
        assert_eq!(start_index(None, 10_000, 500), 9_500);
        assert_eq!(start_index(None, 10, 500), 0);
        // Verified tree heads survive a restart; old files without them still load.
        assert_eq!(a.head(), None);
        a.set_head(4242, [7; 32]);
        a.save(400).unwrap();
        let mut again = CheckpointStore::new(&dir, "https://ct.example.com/a/");
        assert_eq!(again.load().unwrap(), Some(400));
        assert_eq!(again.head(), Some((4242, [7; 32])));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_checkpoint_is_an_error() {
        let dir = tmpdir("corrupt");
        let mut a = CheckpointStore::new(&dir, "https://ct.example.com/a/");
        a.save(1).unwrap();
        std::fs::write(&a.path, b"{not json").unwrap();
        assert!(a.load().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
