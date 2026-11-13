//! RFC 6962 / RFC 9162 Merkle tree hashing, consistency proof verification and
//! tree-hash computation from tlog tiles (c2sp.org/tlog-tiles).

use std::collections::HashMap;

use anyhow::{bail, Result};

pub type Hash = [u8; 32];

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for p in parts {
        ctx.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Leaf hash: `SHA-256(0x00 || MerkleTreeLeaf)`.
pub fn leaf_hash(leaf: &[u8]) -> Hash {
    sha256(&[&[0], leaf])
}

/// Interior node hash: `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[1], left, right])
}

/// Merkle Tree Hash over a list of leaf hashes (RFC 6962 section 2.1).
pub fn mth(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => sha256(&[]),
        1 => leaves[0],
        n => {
            let k = largest_pow2_below(n as u64) as usize;
            node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// Largest power of two strictly smaller than `n` (n >= 2).
fn largest_pow2_below(n: u64) -> u64 {
    1u64 << (63 - (n - 1).leading_zeros())
}

/// Verifies an RFC 6962 consistency proof between two tree heads (RFC 9162 section 2.1.4.2).
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &Hash,
    second_root: &Hash,
    proof: &[Hash],
) -> Result<()> {
    if first > second {
        bail!("old tree size {first} is larger than new tree size {second}");
    }
    if first == second {
        if !proof.is_empty() || first_root != second_root {
            bail!("same tree size but different root hashes");
        }
        return Ok(());
    }
    if first == 0 {
        // Every tree is consistent with the empty tree.
        return Ok(());
    }
    if proof.len() > 128 {
        bail!("consistency proof too long");
    }
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);
    let Some((first_hash, rest)) = path.split_first() else {
        bail!("empty consistency proof");
    };
    let (mut fn_, mut sn) = (first - 1, second - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (*first_hash, *first_hash);
    for c in rest {
        if sn == 0 {
            bail!("consistency proof has too many elements");
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && fn_ != 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    if sn != 0 {
        bail!("consistency proof is too short");
    }
    if &fr != first_root || &sr != second_root {
        bail!("consistency proof does not match the tree heads");
    }
    Ok(())
}

/// Identifies one hash tile: level, index and width (1..=256).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TileId {
    pub level: u8,
    pub index: u64,
    pub width: u16,
}

/// Width of hash tile `index` at `level` in a tree of `size` leaves (0 = tile does not exist).
pub fn tile_width(size: u64, level: u8, index: u64) -> u16 {
    let count = size >> (8 * u32::from(level));
    let full = count / 256;
    if index < full {
        256
    } else if index == full {
        (count % 256) as u16
    } else {
        0
    }
}

/// Computes tree hashes of a tree of `size` leaves from hash tiles. Tiles are
/// supplied by the caller; [`TileTree::missing`] lists those still needed.
pub struct TileTree {
    size: u64,
    tiles: HashMap<TileId, Vec<Hash>>,
    missing: Vec<TileId>,
}

impl TileTree {
    pub fn new(size: u64) -> Self {
        Self {
            size,
            tiles: HashMap::new(),
            missing: Vec::new(),
        }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Re-targets the tree to a new size; cached full tiles stay valid.
    pub fn set_size(&mut self, size: u64) {
        self.size = size;
    }

    pub fn insert(&mut self, id: TileId, hashes: Vec<Hash>) {
        self.tiles.insert(id, hashes);
    }

    /// Drops cached tiles once the cache grows past `max` entries.
    pub fn trim(&mut self, max: usize) {
        if self.tiles.len() > max {
            self.tiles.clear();
        }
    }

    pub fn take_missing(&mut self) -> Vec<TileId> {
        let mut m = std::mem::take(&mut self.missing);
        m.sort_by_key(|t| (t.level, t.index));
        m.dedup();
        m
    }

    /// Hash of the perfect subtree of height `h` at position `i` (covers leaves
    /// `i * 2^h .. (i + 1) * 2^h`). Records a missing tile and returns zeros if needed.
    fn node(&mut self, h: u32, i: u64) -> Hash {
        let level = (h / 8) as u8;
        let below = h % 8;
        if below == 0 {
            let id = TileId {
                level,
                index: i / 256,
                width: tile_width(self.size, level, i / 256),
            };
            let pos = (i % 256) as usize;
            return match self.tiles.get(&id) {
                Some(t) if pos < t.len() => t[pos],
                _ => {
                    self.missing.push(id);
                    [0; 32]
                }
            };
        }
        let left = self.node(h - 1, i * 2);
        let right = self.node(h - 1, i * 2 + 1);
        node_hash(&left, &right)
    }

    /// MTH of leaves `lo..hi`; `target` substitutes a known hash for one range.
    fn range(&mut self, lo: u64, hi: u64, target: Option<(u64, u64, Hash)>) -> Hash {
        if let Some((tlo, thi, th)) = target {
            if (lo, hi) == (tlo, thi) {
                return th;
            }
        }
        let n = hi - lo;
        let contains_target = target.is_some_and(|(tlo, thi, _)| tlo >= lo && thi <= hi);
        if n.is_power_of_two() && !contains_target {
            return self.node(n.trailing_zeros(), lo >> n.trailing_zeros());
        }
        if n == 1 {
            return self.node(0, lo);
        }
        let k = if n.is_power_of_two() {
            n / 2
        } else {
            largest_pow2_below(n)
        };
        let left = self.range(lo, lo + k, target);
        let right = self.range(lo + k, hi, target);
        node_hash(&left, &right)
    }

    /// Root hash of the first `size` leaves (any `size <= self.size`), or the
    /// tiles that must be fetched first.
    #[cfg(test)]
    pub fn root(&mut self, size: u64) -> std::result::Result<Hash, Vec<TileId>> {
        self.root_with(size, None)
    }

    /// Like [`TileTree::root`], but leaves `lo..hi` hash to `known` (computed
    /// locally from entry data) instead of being read from tiles.
    pub fn root_with(
        &mut self,
        size: u64,
        known: Option<(u64, u64, Hash)>,
    ) -> std::result::Result<Hash, Vec<TileId>> {
        if size == 0 {
            return Ok(sha256(&[]));
        }
        let h = self.range(0, size, known);
        let missing = self.take_missing();
        if missing.is_empty() {
            Ok(h)
        } else {
            Err(missing)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn leaves(n: u64) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&i.to_be_bytes())).collect()
    }

    /// RFC 6962 SUBPROOF, used to generate proofs for the verifier tests.
    fn subproof(m: usize, d: &[Hash], b: bool) -> Vec<Hash> {
        let n = d.len();
        if m == n {
            return if b { vec![] } else { vec![mth(d)] };
        }
        let k = largest_pow2_below(n as u64) as usize;
        if m <= k {
            let mut p = subproof(m, &d[..k], b);
            p.push(mth(&d[k..]));
            p
        } else {
            let mut p = subproof(m - k, &d[k..], false);
            p.push(mth(&d[..k]));
            p
        }
    }

    #[test]
    fn consistency_proofs_verify_and_reject_tampering() {
        let d = leaves(70);
        for second in 1..=70u64 {
            for first in 1..=second {
                let proof = if first == second {
                    vec![]
                } else {
                    subproof(first as usize, &d[..second as usize], true)
                };
                let r1 = mth(&d[..first as usize]);
                let r2 = mth(&d[..second as usize]);
                verify_consistency(first, second, &r1, &r2, &proof)
                    .unwrap_or_else(|e| panic!("{first}->{second}: {e}"));
                if !proof.is_empty() {
                    let mut bad = proof.clone();
                    bad[0][0] ^= 1;
                    assert!(verify_consistency(first, second, &r1, &r2, &bad).is_err());
                    assert!(verify_consistency(first, second, &r2, &r1, &proof).is_err());
                }
            }
        }
        assert!(verify_consistency(5, 4, &[0; 32], &[0; 32], &[]).is_err());
    }

    /// Builds every tile a log of `size` leaves would serve.
    pub fn tiles_for(d: &[Hash]) -> HashMap<TileId, Vec<Hash>> {
        let size = d.len() as u64;
        let mut out = HashMap::new();
        let mut level_hashes: Vec<Hash> = d.to_vec();
        for level in 0..4u8 {
            if level_hashes.is_empty() {
                break;
            }
            for (idx, chunk) in level_hashes.chunks(256).enumerate() {
                let id = TileId {
                    level,
                    index: idx as u64,
                    width: tile_width(size, level, idx as u64),
                };
                out.insert(id, chunk.to_vec());
            }
            level_hashes = level_hashes
                .chunks(256)
                .filter(|c| c.len() == 256)
                .map(mth)
                .collect();
        }
        out
    }

    fn resolve(tree: &mut TileTree, all: &HashMap<TileId, Vec<Hash>>, size: u64) -> Hash {
        for _ in 0..8 {
            match tree.root(size) {
                Ok(h) => return h,
                Err(missing) => {
                    for id in missing {
                        tree.insert(id, all[&id].clone());
                    }
                }
            }
        }
        panic!("did not converge")
    }

    #[test]
    fn tile_widths_follow_the_spec_example() {
        // Tree of 70,000: 273 full level-0 tiles + width 112, one full level-1 + width 17, level-2 width 1.
        assert_eq!(tile_width(70_000, 0, 272), 256);
        assert_eq!(tile_width(70_000, 0, 273), 112);
        assert_eq!(tile_width(70_000, 1, 0), 256);
        assert_eq!(tile_width(70_000, 1, 1), 17);
        assert_eq!(tile_width(70_000, 2, 0), 1);
        assert_eq!(tile_width(256, 1, 0), 1);
        assert_eq!(tile_width(256, 0, 1), 0);
    }

    #[test]
    fn roots_from_tiles_match_direct_hashing() {
        for size in [1u64, 2, 255, 256, 257, 511, 70_000] {
            let d = leaves(size);
            let all = tiles_for(&d);
            let mut tree = TileTree::new(size);
            assert_eq!(resolve(&mut tree, &all, size), mth(&d), "size {size}");
            // Old tree heads are recomputed from the new tree's tiles (tiled consistency).
            for old in [1u64, size / 3 + 1, size.saturating_sub(1).max(1)] {
                assert_eq!(
                    resolve(&mut tree, &all, old),
                    mth(&d[..old as usize]),
                    "{old} in {size}"
                );
            }
        }
    }

    #[test]
    fn data_tile_hash_is_bound_to_the_root() {
        let size = 70_000u64;
        let d = leaves(size);
        let all = tiles_for(&d);
        let mut tree = TileTree::new(size);
        for (lo, hi) in [(0u64, 256u64), (256 * 100, 256 * 101), (256 * 273, size)] {
            let local = mth(&d[lo as usize..hi as usize]);
            let mut root = None;
            for _ in 0..8 {
                match tree.root_with(size, Some((lo, hi, local))) {
                    Ok(h) => {
                        root = Some(h);
                        break;
                    }
                    Err(m) => m
                        .into_iter()
                        .for_each(|id| tree.insert(id, all[&id].clone())),
                }
            }
            assert_eq!(root.unwrap(), mth(&d), "{lo}..{hi}");
            // A forged entry changes the computed root.
            let forged = leaf_hash(b"forged");
            assert_ne!(
                tree.root_with(size, Some((lo, hi, forged))).unwrap(),
                mth(&d)
            );
        }
    }
}
