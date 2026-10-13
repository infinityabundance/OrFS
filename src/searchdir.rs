//! **Global search directory (research §9).**
//!
//! The per-object positional trigram index (Phase 9) accelerates a query *within*
//! one file, but the query engine must still examine every file to discover which
//! ones are relevant. This module adds the higher-level structure §9 asks for: a
//! **version-qualified directory mapping a trigram to the set of object ids that
//! contain it**, so a whole-tree query can restrict itself to candidate objects
//! and never open the rest.
//!
//! Posting sets are stored **density-adaptively** (Roaring-style): a sorted id
//! array when sparse, a packed 64-bit bitmap when the set is dense over a bounded
//! id universe. Intersection walks the cheaper representation. The court
//! (`tests/search_directory.rs`) reports both representations' bytes so the choice
//! is measured, not assumed.
//!
//! The directory is **derived**, never authoritative: it is built from committed
//! per-object indexes at a committed root, every candidate is still verified
//! against committed content, and a missing, stale, or incomplete directory only
//! ever makes a query fall back to the existing path — it can never change the
//! result set.

use std::collections::BTreeMap;

use crate::trigram::{pattern_trigram_keys, TrigramIndex, MIN_PATTERN};

/// The density numerator/denominator at or above which a posting set becomes a
/// bitmap: `len / universe >= 1/8`.
const BITMAP_DENSITY_NUM: u64 = 1;
const BITMAP_DENSITY_DEN: u64 = 8;

/// Bitmaps are used only when the id universe (max id + 1) is at most this, so a
/// dense bitmap can never cost unbounded memory.
const BITMAP_MAX_UNIVERSE: u64 = 1 << 22;

/// A compact set of object ids, stored sparse (sorted array) or dense (bitmap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostingSet {
    /// Ascending, distinct ids (the sparse representation).
    Array(Vec<u64>),
    /// A packed bitmap over `[0, cap)`.
    Bitmap { cap: u64, words: Vec<u64> },
}

impl PostingSet {
    /// Build from ascending, distinct ids, choosing the representation by density.
    pub fn from_sorted(ids: Vec<u64>) -> PostingSet {
        debug_assert!(
            ids.windows(2).all(|w| w[0] < w[1]),
            "posting ids must be ascending and distinct"
        );
        let len = ids.len() as u64;
        let cap = ids.last().map(|m| m + 1).unwrap_or(0);
        if !ids.is_empty()
            && cap <= BITMAP_MAX_UNIVERSE
            && len.saturating_mul(BITMAP_DENSITY_DEN) >= cap.saturating_mul(BITMAP_DENSITY_NUM)
        {
            let mut words = vec![0u64; cap.div_ceil(64) as usize];
            for &id in &ids {
                words[(id / 64) as usize] |= 1u64 << (id % 64);
            }
            PostingSet::Bitmap { cap, words }
        } else {
            PostingSet::Array(ids)
        }
    }

    /// The number of ids in the set.
    pub fn len(&self) -> usize {
        match self {
            PostingSet::Array(v) => v.len(),
            PostingSet::Bitmap { words, .. } => words.iter().map(|w| w.count_ones() as usize).sum(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `id` is a member.
    pub fn contains(&self, id: u64) -> bool {
        match self {
            PostingSet::Array(v) => v.binary_search(&id).is_ok(),
            PostingSet::Bitmap { cap, words } => {
                id < *cap && (words[(id / 64) as usize] >> (id % 64)) & 1 == 1
            }
        }
    }

    /// The ids as an ascending `Vec` (the query-facing form).
    pub fn ids(&self) -> Vec<u64> {
        match self {
            PostingSet::Array(v) => v.clone(),
            PostingSet::Bitmap { cap, words } => {
                let mut out = Vec::new();
                for (wi, w) in words.iter().enumerate() {
                    let mut bits = *w;
                    while bits != 0 {
                        let b = bits.trailing_zeros();
                        let id = (wi as u64) * 64 + b as u64;
                        if id < *cap {
                            out.push(id);
                        }
                        bits &= bits - 1;
                    }
                }
                out
            }
        }
    }

    /// Structural bytes (a documented lower bound; no allocator overhead).
    pub fn encoded_bytes(&self) -> u64 {
        match self {
            PostingSet::Array(v) => (v.len() * 8) as u64,
            PostingSet::Bitmap { words, .. } => (words.len() * 8) as u64,
        }
    }

    /// The intersection of two posting sets, in the cheaper representation.
    pub fn intersect(&self, other: &PostingSet) -> PostingSet {
        match (self, other) {
            (PostingSet::Array(a), PostingSet::Array(b)) => {
                let mut out = Vec::with_capacity(a.len().min(b.len()));
                let (mut i, mut j) = (0usize, 0usize);
                while i < a.len() && j < b.len() {
                    match a[i].cmp(&b[j]) {
                        std::cmp::Ordering::Less => i += 1,
                        std::cmp::Ordering::Greater => j += 1,
                        std::cmp::Ordering::Equal => {
                            out.push(a[i]);
                            i += 1;
                            j += 1;
                        }
                    }
                }
                PostingSet::from_sorted(out)
            }
            (PostingSet::Bitmap { words: wa, .. }, PostingSet::Bitmap { words: wb, .. }) => {
                let n = wa.len().min(wb.len());
                let words: Vec<u64> = (0..n).map(|i| wa[i] & wb[i]).collect();
                // The result's universe is bounded by the smaller cap.
                let cap = match (self, other) {
                    (PostingSet::Bitmap { cap: ca, .. }, PostingSet::Bitmap { cap: cb, .. }) => {
                        (*ca).min(*cb)
                    }
                    _ => unreachable!(),
                };
                bitmap_or_compact(cap, words)
            }
            (PostingSet::Array(a), bitmap @ PostingSet::Bitmap { .. })
            | (bitmap @ PostingSet::Bitmap { .. }, PostingSet::Array(a)) => {
                let out: Vec<u64> = a
                    .iter()
                    .copied()
                    .filter(|id| bitmap.contains(*id))
                    .collect();
                PostingSet::from_sorted(out)
            }
        }
    }
}

/// Rebuild a bitmap posting set from AND-ed words, spilling to an array when it is
/// now sparse.
fn bitmap_or_compact(cap: u64, words: Vec<u64>) -> PostingSet {
    let bitmap = PostingSet::Bitmap { cap, words };
    if bitmap.is_empty() {
        return PostingSet::Array(Vec::new());
    }
    // Re-evaluate: an AND can make a previously dense set sparse.
    PostingSet::from_sorted(bitmap.ids())
}

/// The plan a directory yields for a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryPlan {
    /// The pattern is shorter than a trigram; the directory cannot accelerate it.
    Unsupported,
    /// A pattern trigram is absent from every indexed object: no file can match.
    Impossible,
    /// The objects that must be examined (ascending), still to be verified.
    Candidates(Vec<u64>),
}

/// A version-qualified, derived directory: trigram → the object ids containing it.
#[derive(Debug, Clone)]
pub struct GlobalSearchDirectory {
    root: u64,
    volume_uuid: [u8; 16],
    postings: BTreeMap<u32, PostingSet>,
    objects: u64,
    source_bytes: u64,
    /// Every file at `root` was covered by a usable per-object index. When this is
    /// false the directory must not be used to prune (it would risk false
    /// negatives); callers fall back to the full path.
    complete: bool,
}

impl GlobalSearchDirectory {
    /// The committed root this directory is qualified for.
    pub fn root(&self) -> u64 {
        self.root
    }

    /// The owning volume UUID.
    pub fn volume_uuid(&self) -> [u8; 16] {
        self.volume_uuid
    }

    /// Whether the directory covers every file at the root.
    pub fn complete(&self) -> bool {
        self.complete
    }

    /// The number of objects folded.
    pub fn objects(&self) -> u64 {
        self.objects
    }

    /// The total content bytes the folded indexes describe.
    pub fn source_bytes(&self) -> u64 {
        self.source_bytes
    }

    /// The number of distinct trigram keys.
    pub fn trigram_count(&self) -> usize {
        self.postings.len()
    }

    /// The number of bitmap-represented posting sets.
    pub fn bitmap_sets(&self) -> usize {
        self.postings
            .values()
            .filter(|s| matches!(s, PostingSet::Bitmap { .. }))
            .count()
    }

    /// Structural bytes of every posting set.
    pub fn posting_bytes(&self) -> u64 {
        self.postings.values().map(|s| s.encoded_bytes()).sum()
    }

    /// The candidate plan for `pattern`: the intersection of every pattern
    /// trigram's posting set, or [`DirectoryPlan::Impossible`] when any is absent.
    pub fn candidates(&self, pattern: &[u8]) -> DirectoryPlan {
        if pattern.len() < MIN_PATTERN {
            return DirectoryPlan::Unsupported;
        }
        let keys = pattern_trigram_keys(pattern);
        let mut sets: Vec<&PostingSet> = Vec::with_capacity(keys.len());
        for key in &keys {
            match self.postings.get(key) {
                None => return DirectoryPlan::Impossible,
                Some(set) => sets.push(set),
            }
        }
        if sets.is_empty() {
            return DirectoryPlan::Impossible;
        }
        // Start from the smallest set so the intersection shrinks fastest.
        sets.sort_by_key(|s| s.len());
        let mut acc: PostingSet = sets[0].clone();
        for set in &sets[1..] {
            acc = acc.intersect(set);
            if acc.is_empty() {
                break;
            }
        }
        DirectoryPlan::Candidates(acc.ids())
    }

    /// A JSON projection for evidence and the CLI.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "root": self.root,
            "objects": self.objects,
            "source_bytes": self.source_bytes,
            "complete": self.complete,
            "trigram_keys": self.trigram_count(),
            "bitmap_sets": self.bitmap_sets(),
            "posting_bytes": self.posting_bytes(),
        })
    }
}

/// Incremental builder: fold one object's index at a time, in ascending id order.
#[derive(Debug)]
pub struct DirectoryBuilder {
    root: u64,
    volume_uuid: [u8; 16],
    postings: BTreeMap<u32, Vec<u64>>,
    objects: u64,
    source_bytes: u64,
    complete: bool,
}

impl DirectoryBuilder {
    pub fn new(root: u64, volume_uuid: [u8; 16]) -> DirectoryBuilder {
        DirectoryBuilder {
            root,
            volume_uuid,
            postings: BTreeMap::new(),
            objects: 0,
            source_bytes: 0,
            complete: true,
        }
    }

    /// Fold one object's positional index. Ids must be folded in ascending order
    /// (the caller enumerates objects in ascending inode order).
    pub fn fold(&mut self, inode: u64, index: &TrigramIndex) {
        for key in index.keys() {
            self.postings.entry(key).or_default().push(inode);
        }
        self.objects += 1;
        self.source_bytes = self.source_bytes.saturating_add(index.logical_size());
    }

    /// Record that some file at the root had no usable index; the directory is then
    /// incomplete and must not be used to prune.
    pub fn mark_incomplete(&mut self) {
        self.complete = false;
    }

    /// Finish, converting each posting list to its density-chosen representation.
    pub fn finish(self) -> GlobalSearchDirectory {
        let postings: BTreeMap<u32, PostingSet> = self
            .postings
            .into_iter()
            .map(|(k, v)| (k, PostingSet::from_sorted(v)))
            .collect();
        GlobalSearchDirectory {
            root: self.root,
            volume_uuid: self.volume_uuid,
            postings,
            objects: self.objects,
            source_bytes: self.source_bytes,
            complete: self.complete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(source: &[u8]) -> TrigramIndex {
        TrigramIndex::build(source)
    }

    #[test]
    fn posting_sets_choose_a_representation_by_density() {
        // Sparse over a large universe -> array.
        let sparse = PostingSet::from_sorted(vec![1, 1_000_000, 5_000_000]);
        assert!(matches!(sparse, PostingSet::Array(_)));
        // Dense over a small universe -> bitmap.
        let dense = PostingSet::from_sorted((0..1000).collect());
        assert!(matches!(dense, PostingSet::Bitmap { .. }));
        assert_eq!(dense.len(), 1000);
        assert!(dense.contains(999) && !dense.contains(1000));
    }

    #[test]
    fn intersection_matches_a_naive_set_intersection() {
        let a = PostingSet::from_sorted((0..200).collect());
        let b = PostingSet::from_sorted((100..400).collect());
        let c = a.intersect(&b);
        assert_eq!(c.ids(), (100..200).collect::<Vec<u64>>());

        let sparse = PostingSet::from_sorted(vec![5, 100_000, 200_000]);
        let dense = PostingSet::from_sorted((0..300).collect());
        assert_eq!(sparse.intersect(&dense).ids(), vec![5]);
        assert_eq!(dense.intersect(&sparse).ids(), vec![5]);
    }

    #[test]
    fn directory_plans_candidates_and_impossibility() {
        let mut b = DirectoryBuilder::new(7, [1; 16]);
        b.fold(10, &idx(b"the quick brown fox"));
        b.fold(20, &idx(b"the lazy dog"));
        b.fold(30, &idx(b"unrelated content"));
        let dir = b.finish();
        assert!(dir.complete());
        assert_eq!(dir.objects(), 3);

        // "quick" appears only in object 10.
        match dir.candidates(b"quick") {
            DirectoryPlan::Candidates(ids) => assert_eq!(ids, vec![10]),
            other => panic!("expected candidates, got {other:?}"),
        }
        // "the" appears in 10 and 20.
        match dir.candidates(b"the") {
            DirectoryPlan::Candidates(ids) => assert_eq!(ids, vec![10, 20]),
            other => panic!("expected candidates, got {other:?}"),
        }
        // A trigram not present anywhere is impossible.
        assert_eq!(dir.candidates(b"zzz"), DirectoryPlan::Impossible);
        // A pattern shorter than a trigram is unsupported.
        assert_eq!(dir.candidates(b"ab"), DirectoryPlan::Unsupported);
    }
}
