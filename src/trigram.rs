//! Positional trigram index (research §11.1) — a concealed, version-qualified
//! structure for byte-oriented substring search.
//!
//! A trigram key is a packed 24-bit window `(b0, b1, b2)`. The index maps each
//! distinct trigram to the ascending list of byte positions at which it occurs
//! in the source. The required components named by research §11.1 are all
//! present:
//!
//! | §11.1 component | here |
//! |---|---|
//! | trigram key | `u32` (three bytes, big-endian inside the word) |
//! | posting list | `Vec<u32>` positions, delta+LEB128 on disk |
//! | source inode version | [`TrigramManifest::inode_version`] |
//! | source logical size | [`TrigramManifest::source_logical_size`] |
//! | posting encoding | [`PostingEncoding`] |
//! | verification metadata | [`TrigramManifest::source_blake3`] |
//!
//! **Candidates are never matches.** The index only ever yields *candidate*
//! positions; every candidate is verified against the actual logical file
//! content by the query engine (`src/query.rs`) before it is reported. A
//! trigram index therefore cannot produce a false match.
//!
//! The structure is version-qualified (research §2 I6): a manifest is usable
//! only for the exact `(inode, inode_version, root)` it was built for, and only
//! when its recorded logical size matches the inode's current size. Anything
//! else (absent, stale, partial, corrupt) is rejected and the query falls back
//! to an authoritative full scan with identical results.
//!
//! Construction is asynchronous via a bounded worker pool that reuses the
//! Phase-7 job/worker/publication discipline: jobs are queued with backpressure,
//! cancellable, superseded by a newer inode version, and published through an
//! immutable, self-validating manifest advertised in a `HEAD` index.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use parking_lot::{Condvar, Mutex, RwLock};

use crate::error::{OrfsError, Result};
use crate::manifestation::{dir_bytes, Dec, Enc};
use crate::segment::fsync_dir;

/// The concealed subdirectory holding trigram payloads and manifests.
pub const TRIGRAM_DIR: &str = "trigram";
/// The trigram payload format schema (bump on any incompatible change).
pub const TRIGRAM_SCHEMA: u32 = 1;
/// The trigram index format identifier surfaced in evidence.
pub const TRIGRAM_VERSION: &str = "1";
/// The minimum pattern length that a trigram index can accelerate.
pub const MIN_PATTERN: usize = 3;

const TRIGRAM_MAGIC: u32 = 0x4F52_5452; // "ORTR"
const PAYLOAD_MAGIC: u32 = 0x4F52_5450; // "ORTP"
const HEAD_MAGIC: u32 = 0x4F52_5448; // "ORTH"

fn trigram_key(a: u8, b: u8, c: u8) -> u32 {
    ((a as u32) << 16) | ((b as u32) << 8) | (c as u32)
}

// ---------------------------------------------------------------------------
// Trigram presence sketch (a compact exact-absence filter carried in the
// manifest). A positional trigram index is roughly as large as its source, so
// loading one per file would be a net loss. The sketch is ~1 KiB; it is compact,
// has no false negatives (every key is inserted), and lets a query *provably*
// skip a file whose pattern trigrams are absent without reading the payload.
// ---------------------------------------------------------------------------

const SKETCH_K: u32 = 4;
const SKETCH_MIN_BITS: u32 = 1024;
const SKETCH_MAX_BITS: u32 = 65536;

/// A bit budget sized to the number of distinct keys (≈10 bits/key, power of
/// two, clamped).
fn sketch_bits_for(distinct: usize) -> u32 {
    let target = (distinct as u64)
        .saturating_mul(10)
        .max(SKETCH_MIN_BITS as u64);
    let mut bits = SKETCH_MIN_BITS;
    while (bits as u64) < target && bits < SKETCH_MAX_BITS {
        bits <<= 1;
    }
    bits.min(SKETCH_MAX_BITS)
}

fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn sketch_slot(bits: u32, key: u32, i: u32) -> u32 {
    let h = splitmix((key as u64) ^ ((i as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15)));
    (h as u32) % bits
}

fn sketch_set(data: &mut [u8], bits: u32, key: u32) {
    for i in 0..SKETCH_K {
        let idx = sketch_slot(bits, key, i);
        data[(idx / 8) as usize] |= 1u8 << (idx % 8);
    }
}

fn sketch_get(data: &[u8], bits: u32, key: u32) -> bool {
    (0..SKETCH_K).all(|i| {
        let idx = sketch_slot(bits, key, i);
        data[(idx / 8) as usize] & (1u8 << (idx % 8)) != 0
    })
}

/// Whether `pattern` *might* occur, given a manifest's sketch. Returns `true`
/// when the sketch cannot refute it (including when no sketch is present), and
/// `false` only when a pattern trigram is definitely absent — a sound pruning
/// that can never hide a real match.
///
/// A pattern shorter than a trigram is never refuted by the sketch.
pub fn sketch_possible(bits: u32, data: &[u8], pattern: &[u8]) -> bool {
    if pattern.len() < MIN_PATTERN || bits == 0 || data.is_empty() {
        return true;
    }
    if (bits as usize).div_ceil(8) > data.len() {
        return true;
    }
    for i in 0..=pattern.len() - MIN_PATTERN {
        let key = trigram_key(pattern[i], pattern[i + 1], pattern[i + 2]);
        if !sketch_get(data, bits, key) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// The index itself
// ---------------------------------------------------------------------------

/// How posting lists are encoded on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PostingEncoding {
    /// Ascending positions stored as absolute-first-then-delta, each LEB128.
    DeltaLeb128 = 1,
}

impl PostingEncoding {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        match self {
            PostingEncoding::DeltaLeb128 => "delta-leb128",
        }
    }

    const fn from_code(code: u8) -> Option<PostingEncoding> {
        match code {
            1 => Some(PostingEncoding::DeltaLeb128),
            _ => None,
        }
    }
}

/// A positional trigram index over one immutable byte sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrigramIndex {
    entries: BTreeMap<u32, Vec<u32>>,
    logical_size: u64,
    source_blake3: [u8; 32],
    encoding: PostingEncoding,
    posting_count: u64,
}

/// The candidate plan for a pattern: positions the pattern *could* start at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidatePlan {
    /// The pattern is shorter than a trigram; the index cannot accelerate it.
    Unsupported,
    /// The pattern contains a trigram absent from the source: there can be no
    /// match, and no content need be read.
    Impossible,
    /// Candidate start offsets (ascending, deduplicated). Each must still be
    /// verified against the actual content.
    Candidates(Vec<u64>),
}

impl TrigramIndex {
    /// Build the index over `source` (O(n) time and O(n) postings).
    pub fn build(source: &[u8]) -> TrigramIndex {
        let mut entries: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        if source.len() >= MIN_PATTERN {
            for i in 0..=source.len() - MIN_PATTERN {
                let key = trigram_key(source[i], source[i + 1], source[i + 2]);
                entries.entry(key).or_default().push(i as u32);
            }
        }
        let posting_count = entries.values().map(|v| v.len() as u64).sum();
        TrigramIndex {
            entries,
            logical_size: source.len() as u64,
            source_blake3: *blake3::hash(source).as_bytes(),
            encoding: PostingEncoding::DeltaLeb128,
            posting_count,
        }
    }

    /// Build the compact presence sketch over the index's distinct keys.
    pub fn build_sketch(&self) -> (u32, Vec<u8>) {
        let bits = sketch_bits_for(self.entries.len());
        let mut data = vec![0u8; (bits / 8) as usize];
        for &key in self.entries.keys() {
            sketch_set(&mut data, bits, key);
        }
        (bits, data)
    }

    /// The source logical size the index was built over.
    pub fn logical_size(&self) -> u64 {
        self.logical_size
    }

    /// The BLAKE3 of the source bytes captured at construction (verification
    /// metadata).
    pub fn source_blake3(&self) -> [u8; 32] {
        self.source_blake3
    }

    /// The posting encoding used on disk.
    pub fn encoding(&self) -> PostingEncoding {
        self.encoding
    }

    /// The number of distinct trigram keys.
    pub fn trigram_count(&self) -> u64 {
        self.entries.len() as u64
    }

    /// The total number of stored positions across all posting lists.
    pub fn posting_count(&self) -> u64 {
        self.posting_count
    }

    /// The posting list for one trigram key (ascending positions).
    pub fn postings(&self, key: u32) -> Option<&[u32]> {
        self.entries.get(&key).map(|v| v.as_slice())
    }

    /// Plan the candidates for `pattern`.
    ///
    /// The rarest trigram in the pattern is selected so the candidate set is as
    /// small as possible; this is *not* a match set. When the pattern is shorter
    /// than a trigram the index declines (`Unsupported`); when any pattern
    /// trigram is absent it reports `Impossible` (a definite non-match).
    pub fn plan(&self, pattern: &[u8]) -> CandidatePlan {
        if pattern.len() < MIN_PATTERN {
            return CandidatePlan::Unsupported;
        }
        // Choose the rarest posting list among the pattern's distinct trigrams.
        let mut best: Option<(usize, u32, &[u32])> = None;
        for i in 0..=pattern.len() - MIN_PATTERN {
            let key = trigram_key(pattern[i], pattern[i + 1], pattern[i + 2]);
            match self.entries.get(&key) {
                None => return CandidatePlan::Impossible,
                Some(list) => {
                    if best.is_none_or(|(_, _, cur)| list.len() < cur.len()) {
                        best = Some((i, key, list.as_slice()));
                    }
                }
            }
        }
        let Some((rel, _, list)) = best else {
            return CandidatePlan::Impossible;
        };
        let mut starts: Vec<u64> = list
            .iter()
            .map(|p| (*p as u64).saturating_sub(rel as u64))
            .collect();
        starts.sort_unstable();
        starts.dedup();
        CandidatePlan::Candidates(starts)
    }

    /// Serialise the index to its canonical on-disk payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u32(PAYLOAD_MAGIC);
        e.u32(TRIGRAM_SCHEMA);
        e.u8(self.encoding.code());
        e.u64(self.logical_size);
        e.arr(&self.source_blake3);
        e.u32(self.entries.len() as u32);
        for (key, positions) in &self.entries {
            e.u32(*key);
            e.u32(positions.len() as u32);
            let mut prev: u64 = 0;
            for p in positions {
                let delta = (*p as u64).saturating_sub(prev);
                leb128(&mut e, delta);
                prev = *p as u64;
            }
        }
        e.into_vec()
    }

    /// Decode a payload produced by [`TrigramIndex::encode`], rejecting any
    /// truncation, trailing bytes, unknown encoding, or non-ascending posting.
    pub fn decode(bytes: &[u8]) -> Result<TrigramIndex> {
        let mut d = Dec::new(bytes);
        let corrupt = |what: &str| OrfsError::Corrupt(format!("trigram payload {what}"));
        if d.u32()? != PAYLOAD_MAGIC {
            return Err(corrupt("has a bad magic"));
        }
        if d.u32()? != TRIGRAM_SCHEMA {
            return Err(corrupt("has an unknown schema"));
        }
        let encoding = PostingEncoding::from_code(d.u8()?).ok_or_else(|| corrupt("encoding"))?;
        let logical_size = d.u64()?;
        let source_blake3 = d.arr32()?;
        let count = d.u32()? as usize;
        // A trigram index can never hold more distinct keys than 2^24, and every
        // entry needs at least a 4-byte key, so bound the count by the bytes that
        // actually remain before iterating (no work driven by an untrusted length).
        if count > (1 << 24) || count > d.remaining() / 4 {
            return Err(corrupt("declares too many keys"));
        }
        let mut entries: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut posting_count = 0u64;
        for _ in 0..count {
            let key = d.u32()?;
            if key > 0x00FF_FFFF {
                return Err(corrupt("has an out-of-range key"));
            }
            let n = d.u32()? as usize;
            // Every position lies in [0, logical_size).
            if (n as u64) > logical_size {
                return Err(corrupt("declares an oversized posting list"));
            }
            // Each position is at least one LEB128 byte, so a declared count that
            // exceeds the remaining input is corrupt. This bound is enforced
            // *before* the allocation below, so no untrusted length can drive an
            // unbounded `with_capacity` (research §28, bounded allocation).
            if n > d.remaining() {
                return Err(corrupt("declares more positions than input bytes"));
            }
            let mut positions = Vec::with_capacity(n);
            let mut prev: u64 = 0;
            for _ in 0..n {
                let delta = read_leb128(&mut d)?;
                let pos = prev.checked_add(delta).ok_or_else(|| corrupt("position"))?;
                if pos >= logical_size {
                    return Err(corrupt("has an out-of-range position"));
                }
                positions.push(pos as u32);
                prev = pos;
            }
            posting_count += n as u64;
            entries.insert(key, positions);
        }
        if d.remaining() != 0 {
            return Err(corrupt("has trailing bytes"));
        }
        Ok(TrigramIndex {
            entries,
            logical_size,
            source_blake3,
            encoding,
            posting_count,
        })
    }
}

fn leb128(e: &mut Enc, mut v: u64) {
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        e.u8(byte);
        if v == 0 {
            break;
        }
    }
}

fn read_leb128(d: &mut Dec) -> Result<u64> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = d.u8()?;
        if shift >= 63 {
            return Err(OrfsError::Corrupt("trigram payload LEB128 overflow".into()));
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

// ---------------------------------------------------------------------------
// The version-qualified manifest
// ---------------------------------------------------------------------------

/// A committed, self-validating trigram generation manifest (research §11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrigramManifest {
    pub schema: u32,
    pub generation: u64,
    pub volume_uuid: [u8; 16],
    pub inode: u64,
    pub inode_version: u64,
    pub root: u64,
    pub source_logical_size: u64,
    pub source_blake3: [u8; 32],
    pub posting_encoding: u8,
    pub trigram_count: u64,
    pub posting_count: u64,
    /// Bit width of the compact presence sketch (0 = none).
    pub sketch_bits: u32,
    /// The compact presence sketch bytes (exact-absence filter).
    pub sketch: Vec<u8>,
    pub payload_rel_path: String,
    pub payload_blake3: [u8; 32],
    pub payload_bytes: u64,
    pub manifest_blake3: [u8; 32],
}

impl TrigramManifest {
    /// Whether this structure is usable for exactly this identity. Any mismatch
    /// (inode, version, root, or logical size) is a refusal, not a warning.
    pub fn usable_for(&self, inode: u64, inode_version: u64, root: u64, logical_size: u64) -> bool {
        self.inode == inode
            && self.inode_version == inode_version
            && self.root == root
            && self.source_logical_size == logical_size
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u32(TRIGRAM_MAGIC);
        e.u32(self.schema);
        e.u64(self.generation);
        e.arr(&self.volume_uuid);
        e.u64(self.inode);
        e.u64(self.inode_version);
        e.u64(self.root);
        e.u64(self.source_logical_size);
        e.arr(&self.source_blake3);
        e.u8(self.posting_encoding);
        e.u64(self.trigram_count);
        e.u64(self.posting_count);
        e.u32(self.sketch_bits);
        e.u32(self.sketch.len() as u32);
        e.arr(&self.sketch);
        e.str(&self.payload_rel_path);
        e.arr(&self.payload_blake3);
        e.u64(self.payload_bytes);
        e.into_vec()
    }

    /// The self-integrity digest over every preceding canonical field.
    pub fn compute_digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// Seal: stamp the self-digest.
    pub fn sealed(mut self) -> TrigramManifest {
        self.manifest_blake3 = self.compute_digest();
        self
    }

    fn is_sealed(&self) -> bool {
        self.manifest_blake3 == self.compute_digest()
    }

    /// Encode the sealed manifest.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.canonical_bytes();
        bytes.extend_from_slice(&self.manifest_blake3);
        bytes
    }

    /// Decode and validate a manifest (self-digest, magic, schema, no trailing
    /// bytes). Any failure is an error; the caller treats it as uncommitted.
    pub fn decode(bytes: &[u8]) -> Result<TrigramManifest> {
        let tail = bytes
            .len()
            .checked_sub(32)
            .ok_or_else(|| OrfsError::Corrupt("trigram manifest is truncated".into()))?;
        let (body, digest) = bytes.split_at(tail);
        let mut d = Dec::new(body);
        let corrupt = |what: &str| OrfsError::Corrupt(format!("trigram manifest {what}"));
        if d.u32()? != TRIGRAM_MAGIC {
            return Err(corrupt("has a bad magic"));
        }
        let schema = d.u32()?;
        let generation = d.u64()?;
        let volume_uuid = d.arr16()?;
        let inode = d.u64()?;
        let inode_version = d.u64()?;
        let root = d.u64()?;
        let source_logical_size = d.u64()?;
        let source_blake3 = d.arr32()?;
        let posting_encoding = d.u8()?;
        let trigram_count = d.u64()?;
        let posting_count = d.u64()?;
        let sketch_bits = d.u32()?;
        let sketch_len = d.u32()? as usize;
        if sketch_len > (SKETCH_MAX_BITS / 8) as usize {
            return Err(corrupt("declares an oversized sketch"));
        }
        let sketch = d.take(sketch_len)?.to_vec();
        let payload_rel_path = d.string()?;
        let payload_blake3 = d.arr32()?;
        let payload_bytes = d.u64()?;
        if d.remaining() != 0 {
            return Err(corrupt("has trailing bytes"));
        }
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(digest);
        let m = TrigramManifest {
            schema,
            generation,
            volume_uuid,
            inode,
            inode_version,
            root,
            source_logical_size,
            source_blake3,
            posting_encoding,
            trigram_count,
            posting_count,
            sketch_bits,
            sketch,
            payload_rel_path,
            payload_blake3,
            payload_bytes,
            manifest_blake3: digest_arr,
        };
        if !m.is_sealed() {
            return Err(corrupt("fails its self-digest"));
        }
        Ok(m)
    }

    /// A JSON projection for evidence and the CLI.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "generation": self.generation,
            "volume_uuid": hex(&self.volume_uuid),
            "inode": self.inode,
            "inode_version": self.inode_version,
            "root": self.root,
            "source_logical_size": self.source_logical_size,
            "source_blake3": hex(&self.source_blake3),
            "posting_encoding": self.posting_encoding,
            "trigram_count": self.trigram_count,
            "posting_count": self.posting_count,
            "sketch_bits": self.sketch_bits,
            "sketch_bytes": self.sketch.len(),
            "payload_rel_path": self.payload_rel_path,
            "payload_blake3": hex(&self.payload_blake3),
            "payload_bytes": self.payload_bytes,
            "manifest_blake3": hex(&self.manifest_blake3),
        })
    }
}

/// Lowercase hex of a byte slice.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// The generation store
// ---------------------------------------------------------------------------

/// A recovery summary of the committed trigram set.
#[derive(Debug, Clone, Default)]
pub struct TrigramRecovery {
    /// Valid committed manifests, ascending by generation.
    pub generations: Vec<TrigramManifest>,
    /// Candidates rejected (torn, corrupt, or with a missing/torn payload).
    pub rejected: usize,
    /// Whether `HEAD` was used for discovery.
    pub head_used: bool,
    /// Whether discovery fell back to a full scan of `*.manifest`.
    pub head_fallback: bool,
}

impl TrigramRecovery {
    /// The newest valid manifest per inode.
    pub fn newest_per_inode(&self) -> BTreeMap<u64, TrigramManifest> {
        let mut out: BTreeMap<u64, TrigramManifest> = BTreeMap::new();
        for m in &self.generations {
            let replace = match out.get(&m.inode) {
                Some(cur) => (m.inode_version, m.generation) > (cur.inode_version, cur.generation),
                None => true,
            };
            if replace {
                out.insert(m.inode, m.clone());
            }
        }
        out
    }
}

/// The on-disk trigram store rooted at `<volume>/.or_bloom/trigram`.
#[derive(Debug, Clone)]
pub struct TrigramStore {
    volume_root: PathBuf,
    root_dir: PathBuf,
}

impl TrigramStore {
    /// The store for a volume backing directory.
    pub fn new(volume_root: &Path) -> TrigramStore {
        let root_dir = volume_root.join(".or_bloom").join(TRIGRAM_DIR);
        TrigramStore {
            volume_root: volume_root.to_path_buf(),
            root_dir,
        }
    }

    /// The trigram subdirectory.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Create the directory (idempotent).
    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.root_dir)?;
        Ok(())
    }

    /// The relative payload path for a generation.
    pub fn payload_rel_path(&self, generation: u64, inode: u64, version: u64, root: u64) -> String {
        format!(".or_bloom/{TRIGRAM_DIR}/{inode}-v{version}-r{root}-g{generation}.tri")
    }

    /// The absolute payload path for a generation.
    pub fn payload_path(&self, generation: u64, inode: u64, version: u64, root: u64) -> PathBuf {
        self.volume_root
            .join(self.payload_rel_path(generation, inode, version, root))
    }

    fn manifest_path(&self, generation: u64) -> PathBuf {
        self.root_dir.join(format!("{generation:020}.manifest"))
    }

    fn head_path(&self) -> PathBuf {
        self.root_dir.join("HEAD")
    }

    /// The set of generation numbers with a manifest file on disk.
    pub fn manifest_generations(&self) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.root_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(stem) = name.strip_suffix(".manifest") {
                if let Ok(gen) = stem.parse::<u64>() {
                    out.push(gen);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// The next unused generation number.
    pub fn next_generation(&self) -> Result<u64> {
        Ok(self
            .manifest_generations()?
            .into_iter()
            .max()
            .map(|m| m + 1)
            .unwrap_or(1))
    }

    /// Load and validate one manifest by generation number.
    pub fn load_generation(&self, generation: u64) -> Result<Option<TrigramManifest>> {
        let bytes = match fs::read(self.manifest_path(generation)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(TrigramManifest::decode(&bytes).ok())
    }

    /// Validate a manifest's payload against its recorded BLAKE3, when present.
    pub fn payload_matches(&self, m: &TrigramManifest) -> bool {
        let path = self.volume_root.join(&m.payload_rel_path);
        match hash_file(&path) {
            Ok((digest, _)) => digest == m.payload_blake3,
            Err(_) => false,
        }
    }

    /// Load and decode the index for a committed manifest, verifying the payload
    /// BLAKE3 first. Never returns an index that does not match its manifest.
    pub fn load_index(&self, m: &TrigramManifest) -> Result<TrigramIndex> {
        let path = self.volume_root.join(&m.payload_rel_path);
        let bytes = fs::read(&path)?;
        if *blake3::hash(&bytes).as_bytes() != m.payload_blake3 {
            return Err(OrfsError::Corrupt(
                "trigram payload fails its recorded digest".into(),
            ));
        }
        TrigramIndex::decode(&bytes)
    }

    /// Publish a generation: payload (tmp+fsync+rename), manifest
    /// (tmp+fsync+rename+fsync dir), then advertise in `HEAD`.
    pub fn publish(&self, manifest: &TrigramManifest, payload: &[u8]) -> Result<()> {
        self.ensure_dirs()?;
        let payload_path = self.volume_root.join(&manifest.payload_rel_path);
        let tmp = payload_path.with_extension("tri.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(payload)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &payload_path)?;

        let final_path = self.manifest_path(manifest.generation);
        let mtmp = final_path.with_extension("manifest.tmp");
        {
            let mut f = File::create(&mtmp)?;
            f.write_all(&manifest.encode())?;
            f.sync_all()?;
        }
        fs::rename(&mtmp, &final_path)?;
        fsync_dir(&self.root_dir)?;

        let mut gens = self.read_head().unwrap_or_default();
        gens.push(manifest.generation);
        gens.sort_unstable();
        gens.dedup();
        self.write_head(&gens)?;
        Ok(())
    }

    /// Read the advertised generation numbers, if `HEAD` is present and valid.
    pub fn read_head(&self) -> Option<Vec<u64>> {
        decode_head(&fs::read(self.head_path()).ok()?)
    }

    /// Write the `HEAD` advertisement atomically.
    pub fn write_head(&self, generations: &[u64]) -> Result<()> {
        self.ensure_dirs()?;
        let path = self.head_path();
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&encode_head(generations))?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        fsync_dir(&self.root_dir)?;
        Ok(())
    }

    /// Recover the committed trigram set (same discipline as generation recovery:
    /// prefer `HEAD`, validate each candidate, skip invalid ones).
    pub fn recover(&self) -> Result<TrigramRecovery> {
        let head = self.read_head();
        let all = self.manifest_generations()?;
        let (candidates, head_used, head_fallback) = match &head {
            Some(list) => {
                let mut merged = list.clone();
                for g in &all {
                    if !merged.contains(g) {
                        merged.push(*g);
                    }
                }
                merged.sort_unstable();
                merged.dedup();
                (merged, true, false)
            }
            None => (all, false, true),
        };
        let mut generations = Vec::new();
        let mut rejected = 0usize;
        for gen in candidates {
            match self.load_generation(gen)? {
                Some(m) if self.payload_matches(&m) => generations.push(m),
                _ => rejected += 1,
            }
        }
        generations.sort_by_key(|m| m.generation);
        Ok(TrigramRecovery {
            generations,
            rejected,
            head_used,
            head_fallback,
        })
    }

    /// Bytes under the trigram subdirectory (for accounting/evidence).
    pub fn bytes(&self) -> u64 {
        dir_bytes(&self.root_dir)
    }
}

fn encode_head(generations: &[u64]) -> Vec<u8> {
    let mut e = Enc::new();
    e.u32(HEAD_MAGIC);
    e.u32(TRIGRAM_SCHEMA);
    e.u32(generations.len() as u32);
    for g in generations {
        e.u64(*g);
    }
    e.into_vec()
}

fn decode_head(bytes: &[u8]) -> Option<Vec<u64>> {
    let mut d = Dec::new(bytes);
    if d.u32().ok()? != HEAD_MAGIC || d.u32().ok()? != TRIGRAM_SCHEMA {
        return None;
    }
    let count = d.u32().ok()? as usize;
    // Bound by the remaining input (8 bytes per generation) before allocating.
    if count > 1_000_000 || count > d.remaining() / 8 {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(d.u64().ok()?);
    }
    if d.remaining() != 0 {
        return None;
    }
    Some(out)
}

fn hash_file(path: &Path) -> Result<([u8; 32], u64)> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((*hasher.finalize().as_bytes(), total))
}

// ---------------------------------------------------------------------------
// Published state (shared with the namespace)
// ---------------------------------------------------------------------------

/// The published trigram manifest set, shared between engine and namespace.
pub struct TrigramState {
    store: TrigramStore,
    uuid: [u8; 16],
    published: RwLock<BTreeMap<u64, TrigramManifest>>,
}

impl TrigramState {
    /// Recover the published set from disk.
    pub fn recover(store: TrigramStore, uuid: [u8; 16]) -> Result<Arc<TrigramState>> {
        let recovery = store.recover()?;
        Ok(Arc::new(TrigramState {
            store,
            uuid,
            published: RwLock::new(recovery.newest_per_inode()),
        }))
    }

    /// The generation store.
    pub fn store(&self) -> &TrigramStore {
        &self.store
    }

    /// The owning volume UUID.
    pub fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    /// Every currently published generation (newest per inode).
    pub fn published(&self) -> Vec<TrigramManifest> {
        self.published.read().values().cloned().collect()
    }

    /// The number of published generations (newest per inode).
    pub fn generation_count(&self) -> u64 {
        self.published.read().len() as u64
    }

    /// Total published payload bytes.
    pub fn manifested_bytes_total(&self) -> u64 {
        self.published
            .read()
            .values()
            .map(|m| m.payload_bytes)
            .sum()
    }

    /// The newest published manifest for an inode, if any.
    pub fn latest_for(&self, inode: u64) -> Option<TrigramManifest> {
        self.published.read().get(&inode).cloned()
    }

    /// The newest manifest *exactly* qualified for `(inode, version, root)` and
    /// matching `logical_size`. Any mismatch yields `None` (I6).
    pub fn usable_for(
        &self,
        inode: u64,
        inode_version: u64,
        root: u64,
        logical_size: u64,
    ) -> Option<TrigramManifest> {
        let guard = self.published.read();
        let m = guard.get(&inode)?;
        if m.usable_for(inode, inode_version, root, logical_size) {
            Some(m.clone())
        } else {
            None
        }
    }

    fn record_published(&self, manifest: TrigramManifest) {
        let mut guard = self.published.write();
        let replace = match guard.get(&manifest.inode) {
            Some(cur) => {
                (manifest.inode_version, manifest.generation) > (cur.inode_version, cur.generation)
            }
            None => true,
        };
        if replace {
            guard.insert(manifest.inode, manifest);
        }
    }
}

// ---------------------------------------------------------------------------
// The asynchronous build engine
// ---------------------------------------------------------------------------

/// Configuration for the trigram build engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrigramConfig {
    /// Worker threads; `0` selects `available_parallelism()`.
    pub workers: usize,
    /// Bounded job-queue capacity (backpressure).
    pub queue_capacity: usize,
    /// Whether the caller waits for construction before acknowledging.
    pub synchronous: bool,
    /// Objects larger than this are not indexed (capture cost bound).
    pub max_source_bytes: u64,
}

impl Default for TrigramConfig {
    fn default() -> Self {
        TrigramConfig {
            workers: 0,
            queue_capacity: 64,
            synchronous: false,
            max_source_bytes: 16 * 1024 * 1024,
        }
    }
}

/// A truthful report of what the trigram engine engaged.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrigramEngineReport {
    pub workers: usize,
    pub queue_capacity: usize,
    pub synchronous: bool,
    pub trigram_version: String,
    pub recovered_generations: u64,
    pub recovered_rejected: usize,
}

/// How a trigram build job concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrigramBuildStatus {
    Published,
    Canceled,
    Superseded,
    Skipped,
    Failed,
}

impl TrigramBuildStatus {
    pub const fn name(self) -> &'static str {
        match self {
            TrigramBuildStatus::Published => "published",
            TrigramBuildStatus::Canceled => "canceled",
            TrigramBuildStatus::Superseded => "superseded",
            TrigramBuildStatus::Skipped => "skipped",
            TrigramBuildStatus::Failed => "failed",
        }
    }
}

/// The outcome of one trigram build job.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TrigramBuildOutcome {
    pub inode: u64,
    pub inode_version: u64,
    pub status: &'static str,
    pub generation: Option<u64>,
    pub payload_bytes: u64,
    pub trigram_count: u64,
    pub posting_count: u64,
    pub detail: Option<String>,
}

/// Cumulative engine statistics.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TrigramEngineStats {
    pub submitted: u64,
    pub dropped_full: u64,
    pub published: u64,
    pub canceled: u64,
    pub superseded: u64,
    pub skipped: u64,
    pub failed: u64,
}

/// The queue was full; the optional construction was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrigramQueueFull;

impl std::fmt::Display for TrigramQueueFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "trigram build queue is full")
    }
}

impl std::error::Error for TrigramQueueFull {}

/// A job request: identity plus the authoritative source bytes captured at
/// enqueue time. Workers never touch the authoritative log.
#[derive(Debug, Clone)]
pub struct TrigramJob {
    pub inode: u64,
    pub inode_version: u64,
    pub root: u64,
    pub source: Vec<u8>,
}

struct JobShared {
    cancel: AtomicBool,
    completed: Mutex<Option<TrigramBuildOutcome>>,
    cond: Condvar,
}

impl JobShared {
    fn new() -> JobShared {
        JobShared {
            cancel: AtomicBool::new(false),
            completed: Mutex::new(None),
            cond: Condvar::new(),
        }
    }

    fn finish(&self, outcome: TrigramBuildOutcome) {
        *self.completed.lock() = Some(outcome);
        self.cond.notify_all();
    }
}

/// A handle to an asynchronously submitted trigram build.
pub struct TrigramBuildHandle {
    shared: Arc<JobShared>,
}

impl TrigramBuildHandle {
    /// Request cancellation.
    pub fn cancel(&self) {
        self.shared.cancel.store(true, Ordering::SeqCst);
    }

    /// Whether the job has concluded.
    pub fn is_done(&self) -> bool {
        self.shared.completed.lock().is_some()
    }

    /// Wait up to `timeout` for the job to conclude.
    pub fn wait(&self, timeout: Duration) -> Option<TrigramBuildOutcome> {
        let deadline = std::time::Instant::now() + timeout;
        let mut slot = self.shared.completed.lock();
        loop {
            if let Some(o) = slot.clone() {
                return Some(o);
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return None;
            }
            self.shared.cond.wait_for(&mut slot, deadline - now);
        }
    }
}

struct QueuedJob {
    spec: TrigramJob,
    shared: Arc<JobShared>,
}

struct EngineInner {
    store: TrigramStore,
    uuid: [u8; 16],
    cfg: TrigramConfig,
    queue: Mutex<VecDeque<QueuedJob>>,
    not_empty: Condvar,
    shutdown: AtomicBool,
    next_generation: Mutex<u64>,
    latest: Mutex<HashMap<u64, u64>>,
    in_flight: AtomicUsize,
    state: Arc<TrigramState>,
    stats: Mutex<TrigramEngineStats>,
}

impl EngineInner {
    fn is_superseded(&self, inode: u64, version: u64) -> bool {
        self.latest.lock().get(&inode).is_some_and(|v| *v > version)
    }

    fn note_version(&self, inode: u64, version: u64) {
        let mut latest = self.latest.lock();
        let e = latest.entry(inode).or_insert(0);
        if *e < version {
            *e = version;
        }
    }

    fn alloc_generation(&self) -> u64 {
        let mut g = self.next_generation.lock();
        let v = *g;
        *g = v + 1;
        v
    }

    fn bump(&self, f: impl FnOnce(&mut TrigramEngineStats)) {
        f(&mut self.stats.lock());
    }

    fn bump_outcome(&self, outcome: &TrigramBuildOutcome) {
        self.bump(|s| match outcome.status {
            "published" => s.published += 1,
            "canceled" => s.canceled += 1,
            "superseded" => s.superseded += 1,
            "skipped" => s.skipped += 1,
            _ => s.failed += 1,
        });
    }

    fn skipped(&self, spec: &TrigramJob, detail: &str) -> TrigramBuildOutcome {
        TrigramBuildOutcome {
            inode: spec.inode,
            inode_version: spec.inode_version,
            status: "skipped",
            generation: None,
            payload_bytes: 0,
            trigram_count: 0,
            posting_count: 0,
            detail: Some(detail.to_string()),
        }
    }

    fn cancelled(
        &self,
        spec: &TrigramJob,
        status: TrigramBuildStatus,
        detail: Option<String>,
    ) -> TrigramBuildOutcome {
        TrigramBuildOutcome {
            inode: spec.inode,
            inode_version: spec.inode_version,
            status: status.name(),
            generation: None,
            payload_bytes: 0,
            trigram_count: 0,
            posting_count: 0,
            detail,
        }
    }

    fn execute(&self, spec: &TrigramJob, shared: &JobShared) -> TrigramBuildOutcome {
        if shared.cancel.load(Ordering::SeqCst) {
            return self.cancelled(spec, TrigramBuildStatus::Canceled, None);
        }
        self.publish_spec(spec, shared)
    }

    fn publish_spec(&self, spec: &TrigramJob, shared: &JobShared) -> TrigramBuildOutcome {
        if spec.source.len() < MIN_PATTERN || spec.source.len() as u64 > self.cfg.max_source_bytes {
            return self.skipped(spec, "source too small or too large to index");
        }
        let index = TrigramIndex::build(&spec.source);
        // Cancellation/supersession is checked again after construction: a newer
        // inode version must never receive a stale structure (research §10.3).
        if shared.cancel.load(Ordering::SeqCst)
            || self.is_superseded(spec.inode, spec.inode_version)
        {
            let status = if shared.cancel.load(Ordering::SeqCst) {
                TrigramBuildStatus::Canceled
            } else {
                TrigramBuildStatus::Superseded
            };
            return self.cancelled(spec, status, None);
        }

        let generation = self.alloc_generation();
        let rel =
            self.store
                .payload_rel_path(generation, spec.inode, spec.inode_version, spec.root);
        let payload = index.encode();
        let (sketch_bits, sketch) = index.build_sketch();
        let manifest = TrigramManifest {
            schema: TRIGRAM_SCHEMA,
            generation,
            volume_uuid: self.uuid,
            inode: spec.inode,
            inode_version: spec.inode_version,
            root: spec.root,
            source_logical_size: index.logical_size(),
            source_blake3: index.source_blake3(),
            posting_encoding: index.encoding().code(),
            trigram_count: index.trigram_count(),
            posting_count: index.posting_count(),
            sketch_bits,
            sketch,
            payload_rel_path: rel,
            payload_blake3: *blake3::hash(&payload).as_bytes(),
            payload_bytes: payload.len() as u64,
            manifest_blake3: [0u8; 32],
        }
        .sealed();

        if let Err(e) = self.store.publish(&manifest, &payload) {
            return TrigramBuildOutcome {
                inode: spec.inode,
                inode_version: spec.inode_version,
                status: "failed",
                generation: None,
                payload_bytes: 0,
                trigram_count: 0,
                posting_count: 0,
                detail: Some(e.to_string()),
            };
        }
        self.state.record_published(manifest);
        TrigramBuildOutcome {
            inode: spec.inode,
            inode_version: spec.inode_version,
            status: "published",
            generation: Some(generation),
            payload_bytes: payload.len() as u64,
            trigram_count: index.trigram_count(),
            posting_count: index.posting_count(),
            detail: None,
        }
    }
}

/// The bounded, asynchronous trigram build engine.
pub struct TrigramEngine {
    inner: Arc<EngineInner>,
    workers: Vec<JoinHandle<()>>,
}

impl TrigramEngine {
    /// Recover the published set and start a bounded worker pool.
    pub fn start(
        store: TrigramStore,
        uuid: [u8; 16],
        cfg: TrigramConfig,
    ) -> Result<(Arc<TrigramEngine>, TrigramEngineReport)> {
        let recovery = store.recover()?;
        let state = Arc::new(TrigramState {
            store: store.clone(),
            uuid,
            published: RwLock::new(recovery.newest_per_inode()),
        });
        let next_generation = store.next_generation()?;
        let workers = if cfg.workers == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
                .clamp(1, 8)
        } else {
            cfg.workers
        };
        let inner = Arc::new(EngineInner {
            store,
            uuid,
            cfg: cfg.clone(),
            queue: Mutex::new(VecDeque::new()),
            not_empty: Condvar::new(),
            shutdown: AtomicBool::new(false),
            next_generation: Mutex::new(next_generation),
            latest: Mutex::new(HashMap::new()),
            in_flight: AtomicUsize::new(0),
            state,
            stats: Mutex::new(TrigramEngineStats::default()),
        });
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let inner = inner.clone();
            handles.push(std::thread::spawn(move || worker_loop(inner)));
        }
        let report = TrigramEngineReport {
            workers,
            queue_capacity: cfg.queue_capacity,
            synchronous: cfg.synchronous,
            trigram_version: TRIGRAM_VERSION.to_string(),
            recovered_generations: recovery.generations.len() as u64,
            recovered_rejected: recovery.rejected,
        };
        Ok((
            Arc::new(TrigramEngine {
                inner,
                workers: handles,
            }),
            report,
        ))
    }

    /// The shared published-manifest state.
    pub fn state(&self) -> Arc<TrigramState> {
        self.inner.state.clone()
    }

    /// The effective configuration.
    pub fn config(&self) -> &TrigramConfig {
        &self.inner.cfg
    }

    /// Record an inode's newest committed version so older jobs are superseded.
    pub fn note_committed_version(&self, inode: u64, version: u64) {
        self.inner.note_version(inode, version);
    }

    /// Enqueue a build asynchronously. Returns `Err(QueueFull)` under
    /// backpressure; the authoritative commit is never blocked or failed.
    pub fn submit(
        &self,
        spec: TrigramJob,
    ) -> std::result::Result<TrigramBuildHandle, TrigramQueueFull> {
        let shared = Arc::new(JobShared::new());
        let mut queue = self.inner.queue.lock();
        if queue.len() >= self.inner.cfg.queue_capacity {
            drop(queue);
            self.inner.bump(|s| s.dropped_full += 1);
            return Err(TrigramQueueFull);
        }
        queue.push_back(QueuedJob {
            spec,
            shared: shared.clone(),
        });
        self.inner.in_flight.fetch_add(1, Ordering::SeqCst);
        self.inner.bump(|s| s.submitted += 1);
        self.inner.not_empty.notify_one();
        Ok(TrigramBuildHandle { shared })
    }

    /// Build and publish synchronously on the calling thread.
    pub fn publish_now(&self, spec: TrigramJob) -> TrigramBuildOutcome {
        let shared = JobShared::new();
        let outcome = self.inner.execute(&spec, &shared);
        self.inner.bump_outcome(&outcome);
        outcome
    }

    /// Cumulative statistics.
    pub fn stats(&self) -> TrigramEngineStats {
        self.inner.stats.lock().clone()
    }

    /// Whether all queued/in-flight jobs have concluded.
    pub fn is_idle(&self) -> bool {
        self.inner.in_flight.load(Ordering::SeqCst) == 0
    }

    /// Wait until the engine is idle (`true`) or `timeout` elapses (`false`).
    pub fn wait_idle(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while self.inner.in_flight.load(Ordering::SeqCst) != 0 {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        true
    }

    fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        self.inner.not_empty.notify_all();
    }
}

impl Drop for TrigramEngine {
    fn drop(&mut self) {
        self.shutdown();
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
    }
}

fn worker_loop(inner: Arc<EngineInner>) {
    loop {
        let job = {
            let mut q = inner.queue.lock();
            loop {
                if inner.shutdown.load(Ordering::SeqCst) {
                    return;
                }
                if let Some(j) = q.pop_front() {
                    break j;
                }
                inner.not_empty.wait(&mut q);
            }
        };
        let outcome = inner.execute(&job.spec, &job.shared);
        inner.bump_outcome(&outcome);
        job.shared.finish(outcome);
        inner.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_never_false_negatives_and_detects_impossible() {
        let src = b"the quick brown fox jumps over the lazy dog";
        let idx = TrigramIndex::build(src);
        // For every pattern: the plan must be a superset of the true starts (or
        // Impossible exactly when there are none), and never a false negative.
        for pat in [
            &b"the"[..],
            &b"quick"[..],
            &b"brown fox"[..],
            &b"o"[..],
            &b"xyz"[..],
        ] {
            let mut expect: Vec<u64> = Vec::new();
            for start in 0..=src.len().saturating_sub(pat.len()) {
                if &src[start..start + pat.len()] == pat {
                    expect.push(start as u64);
                }
            }
            match idx.plan(pat) {
                CandidatePlan::Candidates(cands) => {
                    for s in &expect {
                        assert!(cands.contains(s), "missed candidate {s} for {pat:?}");
                    }
                }
                CandidatePlan::Impossible => assert!(expect.is_empty(), "false Impossible {pat:?}"),
                CandidatePlan::Unsupported => assert!(pat.len() < MIN_PATTERN),
            }
        }
        assert_eq!(idx.plan(b"zzz"), CandidatePlan::Impossible);
        assert_eq!(idx.plan(b"ab"), CandidatePlan::Unsupported);
        // "the" is the only two-occurrence pattern in the sentence.
        match idx.plan(b"the") {
            CandidatePlan::Candidates(c) => assert_eq!(c.len(), 2),
            other => panic!("expected candidates, got {other:?}"),
        }
    }

    #[test]
    fn payload_round_trips_and_rejects_tamper() {
        let src: Vec<u8> = (0..4096u32).map(|i| (i * 31 + 7) as u8).collect();
        let idx = TrigramIndex::build(&src);
        let bytes = idx.encode();
        assert_eq!(TrigramIndex::decode(&bytes).unwrap(), idx);
        // The key count lives at offset 49..53; an absurd count is rejected.
        let mut bad = bytes.clone();
        bad[49..53].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(TrigramIndex::decode(&bad).is_err());
        // A truncated payload is rejected.
        assert!(TrigramIndex::decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn manifest_round_trips_and_detects_tamper() {
        let m = TrigramManifest {
            schema: TRIGRAM_SCHEMA,
            generation: 3,
            volume_uuid: [9u8; 16],
            inode: 7,
            inode_version: 2,
            root: 4096,
            source_logical_size: 2048,
            source_blake3: [1u8; 32],
            posting_encoding: PostingEncoding::DeltaLeb128.code(),
            trigram_count: 100,
            posting_count: 2000,
            sketch_bits: 1024,
            sketch: vec![0xAA; 128],
            payload_rel_path: ".or_bloom/trigram/7-v2-r4096-g3.tri".into(),
            payload_blake3: [2u8; 32],
            payload_bytes: 9000,
            manifest_blake3: [0u8; 32],
        }
        .sealed();
        let bytes = m.encode();
        assert_eq!(TrigramManifest::decode(&bytes).unwrap(), m);
        let mut bad = bytes.clone();
        bad[5] ^= 0x80;
        assert!(TrigramManifest::decode(&bad).is_err());
    }

    #[test]
    fn version_qualification_is_exact() {
        let m = TrigramManifest {
            schema: TRIGRAM_SCHEMA,
            generation: 1,
            volume_uuid: [0u8; 16],
            inode: 5,
            inode_version: 4,
            root: 1000,
            source_logical_size: 100,
            source_blake3: [0u8; 32],
            posting_encoding: 1,
            trigram_count: 1,
            posting_count: 1,
            sketch_bits: 0,
            sketch: Vec::new(),
            payload_rel_path: "x".into(),
            payload_blake3: [0u8; 32],
            payload_bytes: 1,
            manifest_blake3: [0u8; 32],
        };
        assert!(m.usable_for(5, 4, 1000, 100));
        assert!(!m.usable_for(5, 5, 1000, 100));
        assert!(!m.usable_for(5, 4, 1001, 100));
        assert!(!m.usable_for(6, 4, 1000, 100));
        assert!(!m.usable_for(5, 4, 1000, 101));
    }

    #[test]
    fn engine_builds_and_recovers() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TrigramStore::new(dir.path());
        let (engine, report) =
            TrigramEngine::start(store.clone(), [3u8; 16], TrigramConfig::default()).unwrap();
        assert_eq!(report.recovered_generations, 0);
        let src = b"alpha beta gamma delta alpha beta".to_vec();
        let outcome = engine.publish_now(TrigramJob {
            inode: 2,
            inode_version: 1,
            root: 4096,
            source: src.clone(),
        });
        assert_eq!(outcome.status, "published");
        assert!(engine.is_idle());
        let state = engine.state();
        let m = state.usable_for(2, 1, 4096, src.len() as u64).unwrap();
        let idx = store.load_index(&m).unwrap();
        assert_eq!(idx.logical_size(), src.len() as u64);
        // A rebuilt store recovers the same committed structure.
        let recovered = store.recover().unwrap();
        assert_eq!(recovered.generations.len(), 1);
        assert_eq!(recovered.newest_per_inode().len(), 1);
    }

    #[test]
    fn cancellation_leaves_no_committed_generation() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = TrigramStore::new(dir.path());
        let (engine, _) =
            TrigramEngine::start(store.clone(), [0u8; 16], TrigramConfig::default()).unwrap();
        let handle = engine
            .submit(TrigramJob {
                inode: 9,
                inode_version: 1,
                root: 1,
                source: b"cancel me please".to_vec(),
            })
            .unwrap();
        handle.cancel();
        let outcome = handle.wait(Duration::from_secs(5)).unwrap();
        assert_eq!(outcome.status, "canceled");
        assert!(engine.wait_idle(Duration::from_secs(5)));
        assert_eq!(store.recover().unwrap().generations.len(), 0);
        assert_eq!(engine.state().generation_count(), 0);
    }
}
