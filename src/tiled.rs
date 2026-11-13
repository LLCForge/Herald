//! Static CT API (c2sp.org/static-ct-api) client: checkpoints, hash tiles and data tiles.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::ct::{self, FetchError, LeafError, LogKey, ParsedEntry};
use crate::merkle::{self, Hash, TileId};

/// Maximum checkpoint size accepted (signed notes stay far below this).
const MAX_NOTE: usize = 64 * 1024;

/// A parsed (and, when a key is configured, verified) checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
    /// RFC 6962 TreeHeadSignature timestamp (0 when unverified).
    pub timestamp: u64,
}

/// Key ID of an RFC 6962 note signature: `SHA-256(origin || 0x0A || 0x05 || LogID)[:4]`.
pub fn rfc6962_key_id(origin: &str, log_id: &Hash) -> [u8; 4] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(origin.as_bytes());
    ctx.update(&[0x0a, 0x05]);
    ctx.update(log_id);
    let d = ctx.finish();
    [d.as_ref()[0], d.as_ref()[1], d.as_ref()[2], d.as_ref()[3]]
}

/// Parses a checkpoint note. With `key`, an RFC 6962 note signature by that
/// key under the origin name must be present and valid.
pub fn parse_checkpoint(
    note: &[u8],
    key: Option<&LogKey>,
    expected_origin: Option<&str>,
) -> Result<Checkpoint> {
    if note.len() > MAX_NOTE {
        bail!("checkpoint larger than {MAX_NOTE} bytes");
    }
    let text = std::str::from_utf8(note).context("checkpoint is not UTF-8")?;
    if text.chars().any(|c| c.is_control() && c != '\n') {
        bail!("checkpoint contains control characters");
    }
    let split = text
        .rfind("\n\n")
        .ok_or_else(|| anyhow!("checkpoint has no signature block"))?;
    let body = &text[..split + 1];
    let sigs = &text[split + 2..];
    let lines: Vec<&str> = body.trim_end_matches('\n').split('\n').collect();
    if lines.len() < 3 {
        bail!("checkpoint body needs origin, size and root hash");
    }
    let origin = lines[0];
    if origin.is_empty() {
        bail!("checkpoint origin is empty");
    }
    if let Some(exp) = expected_origin {
        if origin != exp {
            bail!("checkpoint origin {origin:?} does not match the expected {exp:?}");
        }
    }
    let size: u64 = lines[1]
        .parse()
        .ok()
        .filter(|_| lines[1] == "0" || !lines[1].starts_with('0'))
        .ok_or_else(|| anyhow!("invalid checkpoint tree size"))?;
    let root_vec = B64
        .decode(lines[2])
        .context("checkpoint root hash is not base64")?;
    let root: Hash = root_vec
        .try_into()
        .map_err(|_| anyhow!("checkpoint root hash must be 32 bytes"))?;
    let mut cp = Checkpoint {
        origin: origin.to_string(),
        size,
        root,
        timestamp: 0,
    };
    let Some(key) = key else {
        return Ok(cp);
    };
    if lines.len() > 3 {
        bail!("RFC 6962 checkpoints must not carry extension lines");
    }
    let want_id = rfc6962_key_id(origin, key.log_id());
    let mut verified = false;
    for line in sigs.lines() {
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            continue;
        };
        let Some((name, sig_b64)) = rest.split_once(' ') else {
            continue;
        };
        if name != origin {
            continue;
        }
        let Ok(sig) = B64.decode(sig_b64) else {
            continue;
        };
        if sig.len() < 12 || sig[..4] != want_id {
            continue;
        }
        let ts = u64::from_be_bytes(sig[4..12].try_into().unwrap_or([0; 8]));
        key.verify_tree_head(ts, size, &root, &sig[12..])
            .context("checkpoint signature from the log key does not verify")?;
        cp.timestamp = ts;
        verified = true;
        break;
    }
    if !verified {
        bail!("checkpoint carries no signature from the log key");
    }
    Ok(cp)
}

/// Encodes a tile index as 3-digit path elements: 1234067 -> `x001/x234/067`.
pub fn encode_index(mut n: u64) -> String {
    let mut parts = Vec::new();
    loop {
        parts.push(n % 1000);
        n /= 1000;
        if n == 0 {
            break;
        }
    }
    parts
        .iter()
        .rev()
        .enumerate()
        .map(|(i, p)| {
            if i + 1 == parts.len() {
                format!("{p:03}")
            } else {
                format!("x{p:03}")
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub fn tile_path(id: &TileId) -> String {
    let mut p = format!("tile/{}/{}", id.level, encode_index(id.index));
    if id.width < 256 {
        p.push_str(&format!(".p/{}", id.width));
    }
    p
}

pub fn data_tile_path(index: u64, width: u16) -> String {
    let mut p = format!("tile/data/{}", encode_index(index));
    if width < 256 {
        p.push_str(&format!(".p/{width}"));
    }
    p
}

/// One entry of a data tile, with the leaf hash it contributes to the tree.
#[derive(Debug)]
pub struct TileEntry {
    pub leaf_hash: Hash,
    pub parsed: Result<ParsedEntry, LeafError>,
    pub leaf_index: Option<u64>,
}

struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("data tile truncated");
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
    fn uint(&mut self, n: usize) -> Result<u64> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |a, b| (a << 8) | u64::from(*b)))
    }
    fn vec(&mut self, len_bytes: usize) -> Result<&'a [u8]> {
        let n = self.uint(len_bytes)? as usize;
        self.take(n)
    }
}

fn leaf_index_ext(mut ext: &[u8]) -> Option<u64> {
    while ext.len() >= 3 {
        let ty = ext[0];
        let len = usize::from(u16::from_be_bytes([ext[1], ext[2]]));
        let data = ext.get(3..3 + len)?;
        if ty == 0 && len == 5 {
            return Some(data.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)));
        }
        ext = &ext[3 + len..];
    }
    None
}

/// Parses a data tile into exactly `width` entries. Structural errors fail the
/// whole tile (its hashes could not be checked); unparseable certificates do not.
pub fn parse_data_tile(data: &[u8], width: u16) -> Result<Vec<TileEntry>> {
    let mut r = Rd(data);
    let mut out = Vec::with_capacity(usize::from(width));
    while !r.0.is_empty() {
        if out.len() >= usize::from(width) {
            bail!("data tile has more than {width} entries");
        }
        let start = r.0;
        r.take(8)?; // timestamp
        let entry_type = r.uint(2)?;
        match entry_type {
            0 => {
                r.vec(3)?;
            }
            1 => {
                r.take(32)?;
                r.vec(3)?;
            }
            other => bail!("unknown entry type {other} in data tile"),
        }
        let ext = r.vec(2)?;
        let te_len = start.len() - r.0.len();
        let timestamped = &start[..te_len];
        let pre = if entry_type == 1 {
            Some(r.vec(3)?)
        } else {
            None
        };
        let chain = r.vec(2)?;
        if chain.len() % 32 != 0 {
            bail!("certificate_chain is not a list of fingerprints");
        }
        let mut leaf = Vec::with_capacity(te_len + 2);
        leaf.extend_from_slice(&[0, 0]);
        leaf.extend_from_slice(timestamped);
        let mut extra = Vec::new();
        if let Some(p) = pre {
            extra.extend_from_slice(&(p.len() as u32).to_be_bytes()[1..]);
            extra.extend_from_slice(p);
        }
        out.push(TileEntry {
            leaf_hash: merkle::leaf_hash(&leaf),
            parsed: ct::parse_leaf(&leaf, &extra),
            leaf_index: leaf_index_ext(ext),
        });
    }
    if out.len() != usize::from(width) {
        bail!("data tile has {} entries, expected {width}", out.len());
    }
    Ok(out)
}

/// HTTP client for one tiled log's monitoring prefix.
#[derive(Clone)]
pub struct TiledClient {
    client: reqwest::Client,
    base: String,
}

impl TiledClient {
    pub fn new(client: reqwest::Client, monitoring_url: &str) -> Self {
        let base = if monitoring_url.ends_with('/') {
            monitoring_url.to_string()
        } else {
            format!("{monitoring_url}/")
        };
        Self { client, base }
    }

    pub async fn checkpoint(&self) -> Result<Vec<u8>, FetchError> {
        ct::get_capped(&self.client, &format!("{}checkpoint", self.base)).await
    }

    async fn get_with_full_fallback(
        &self,
        partial: String,
        full: String,
        is_partial: bool,
    ) -> Result<Vec<u8>, FetchError> {
        let res = match ct::get_capped(&self.client, &format!("{}{partial}", self.base)).await {
            Err(FetchError::Other(e)) if is_partial => {
                // Partial tiles may be gone once the full tile exists (spec: fall back).
                tracing::debug!(error = %format!("{e:#}"), "partial tile unavailable, trying the full tile");
                ct::get_capped(&self.client, &format!("{}{full}", self.base)).await
            }
            r => r,
        };
        res.map_err(|e| match e {
            FetchError::Other(e) => FetchError::Other(e.context(partial)),
            r => r,
        })
    }

    /// Fetches a hash tile; a full tile is truncated to the requested width.
    pub async fn hash_tile(&self, id: TileId) -> Result<Vec<Hash>, FetchError> {
        let full = TileId { width: 256, ..id };
        let body = self
            .get_with_full_fallback(tile_path(&id), tile_path(&full), id.width < 256)
            .await?;
        if body.len() % 32 != 0 || body.len() / 32 < usize::from(id.width) {
            return Err(anyhow!("hash tile {} has {} bytes", tile_path(&id), body.len()).into());
        }
        Ok(body
            .chunks_exact(32)
            .take(usize::from(id.width))
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(c);
                h
            })
            .collect())
    }

    pub async fn data_tile(&self, index: u64, width: u16) -> Result<Vec<u8>, FetchError> {
        self.get_with_full_fallback(
            data_tile_path(index, width),
            data_tile_path(index, 256),
            width < 256,
        )
        .await
    }
}

/// Data tiles may come back as the full tile when the partial one is gone;
/// keeps only the first `width` entries in that case.
pub fn parse_data_tile_lenient(data: &[u8], width: u16) -> Result<Vec<TileEntry>> {
    match parse_data_tile(data, width) {
        Ok(v) => Ok(v),
        Err(e) if width < 256 => match parse_data_tile(data, 256) {
            Ok(mut v) => {
                v.truncate(usize::from(width));
                Ok(v)
            }
            Err(_) => Err(e),
        },
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::tests::make_cert;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    #[test]
    fn index_encoding() {
        assert_eq!(encode_index(0), "000");
        assert_eq!(encode_index(5), "005");
        assert_eq!(encode_index(1000), "x001/000");
        assert_eq!(encode_index(1_234_067), "x001/x234/067");
        let id = TileId {
            level: 1,
            index: 1_234_067,
            width: 17,
        };
        assert_eq!(tile_path(&id), "tile/1/x001/x234/067.p/17");
        assert_eq!(data_tile_path(3, 256), "tile/data/003");
    }

    fn signed_checkpoint(
        origin: &str,
        size: u64,
        root: &Hash,
        other_sig: bool,
    ) -> (Vec<u8>, LogKey) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let mut spki = crate::ct::tests::unhex(crate::ct::tests::P256_SPKI_PREFIX);
        spki.extend_from_slice(kp.public_key().as_ref());
        let key = LogKey::from_spki_b64(&B64.encode(&spki)).unwrap();
        let ts = 1_760_000_000_000u64;
        let mut msg = vec![0, 1];
        msg.extend_from_slice(&ts.to_be_bytes());
        msg.extend_from_slice(&size.to_be_bytes());
        msg.extend_from_slice(root);
        let sig = kp.sign(&rng, &msg).unwrap();
        let mut blob = rfc6962_key_id(origin, key.log_id()).to_vec();
        blob.extend_from_slice(&ts.to_be_bytes());
        blob.extend_from_slice(&[4, 3]);
        blob.extend_from_slice(&(sig.as_ref().len() as u16).to_be_bytes());
        blob.extend_from_slice(sig.as_ref());
        let mut note = format!("{origin}\n{size}\n{}\n\n", B64.encode(root));
        if other_sig {
            note.push_str(&format!(
                "\u{2014} grease.invalid {}\n",
                B64.encode([1u8; 40])
            ));
        }
        note.push_str(&format!("\u{2014} {origin} {}\n", B64.encode(&blob)));
        (note.into_bytes(), key)
    }

    #[test]
    fn verifies_rfc6962_note_signature() {
        let root = [9u8; 32];
        let (note, key) = signed_checkpoint("ct.example.net/2026h2", 1234, &root, true);
        let cp = parse_checkpoint(&note, Some(&key), Some("ct.example.net/2026h2")).unwrap();
        assert_eq!((cp.size, cp.root), (1234, root));
        assert_eq!(cp.timestamp, 1_760_000_000_000);
        // Wrong origin, tampered size, unknown key.
        assert!(parse_checkpoint(&note, Some(&key), Some("ct.example.org/x")).is_err());
        let tampered = String::from_utf8(note.clone())
            .unwrap()
            .replace("\n1234\n", "\n1235\n");
        assert!(parse_checkpoint(tampered.as_bytes(), Some(&key), None).is_err());
        let (_, other_key) = signed_checkpoint("ct.example.net/2026h2", 1, &root, false);
        assert!(parse_checkpoint(&note, Some(&other_key), None).is_err());
        // Without a key the note is only parsed.
        assert_eq!(parse_checkpoint(&note, None, None).unwrap().size, 1234);
        assert!(parse_checkpoint(b"x\n1\n\n", None, None).is_err());
        assert!(parse_checkpoint(b"x\n01\nAAAA\n\n", None, None).is_err());
    }

    /// Builds a TileLeaf for an x509 entry with a leaf_index extension.
    pub fn tile_leaf(der: &[u8], index: u64) -> (Vec<u8>, Hash) {
        let mut te = Vec::new();
        te.extend_from_slice(&1_760_000_000_000u64.to_be_bytes());
        te.extend_from_slice(&[0, 0]);
        te.extend_from_slice(&(der.len() as u32).to_be_bytes()[1..]);
        te.extend_from_slice(der);
        te.extend_from_slice(&[0, 8, 0, 0, 5]);
        te.extend_from_slice(&index.to_be_bytes()[3..]);
        let mut leaf = vec![0, 0];
        leaf.extend_from_slice(&te);
        let mut out = te;
        out.extend_from_slice(&[0, 32]);
        out.extend_from_slice(&[0xab; 32]);
        (out, merkle::leaf_hash(&leaf))
    }

    #[test]
    fn parses_data_tiles() {
        let (der, _) = make_cert(&["www.example.net"], "www.example.net", "Org", &[1]);
        let mut tile = Vec::new();
        let mut hashes = Vec::new();
        for i in 0..3u64 {
            let (b, h) = tile_leaf(&der, 512 + i);
            tile.extend_from_slice(&b);
            hashes.push(h);
        }
        let entries = parse_data_tile(&tile, 3).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].leaf_index, Some(514));
        assert_eq!(entries[1].leaf_hash, hashes[1]);
        assert_eq!(
            entries[0].parsed.as_ref().unwrap().cert.dns_names,
            vec!["www.example.net"]
        );
        // Wrong width, truncation and trailing garbage are errors, never panics.
        assert!(parse_data_tile(&tile, 2).is_err());
        assert!(parse_data_tile(&tile, 4).is_err());
        assert!(parse_data_tile(&tile[..tile.len() - 1], 3).is_err());
        assert!(parse_data_tile_lenient(&tile, 2).is_err());
        // A full tile served in place of a partial one is truncated to the width.
        let (one, _) = tile_leaf(&der, 0);
        let full: Vec<u8> = one.iter().copied().cycle().take(one.len() * 256).collect();
        assert_eq!(parse_data_tile_lenient(&full, 5).unwrap().len(), 5);
        for cut in 0..tile.len().min(200) {
            let _ = parse_data_tile(&tile[..cut], 3);
        }
    }
}
