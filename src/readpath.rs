//! The planned, certified, measured read path over EKBLOOM manifested
//! structures (research §10.2 read selection, §16, §20 Ring R).
//!
//! A read request follows exactly the research ordering:
//!
//! ```text
//! logical inode -> committed inode version -> extent selection
//!   -> available certified manifestation -> fastest compatible path -> bytes
//! ```
//!
//! # What this module does and does not do
//!
//! OrFS's job (research §10) is to **store, generate, publish, select, and
//! safely access** EKBLOOM structures. EKBLOOM's job is to produce exact outputs
//! and certified operational transitions. This module therefore never
//! reimplements EKBLOOM's state machine: it only *drives* EKBLOOM's public
//! primitives ([`ekbloom::machine_by_id`], [`ekbloom::PathBloom`],
//! [`ekbloom::History`], [`ekbloom::CheckpointSet`],
//! [`ekbloom::bloom_global::GlobalBloom`], [`ekbloom::bloom_region::RegionTable`],
//! [`ekbloom::verify`]) and chooses between them by measurement.
//!
//! # Candidate paths
//!
//! For a compatible, certified generation the planner considers, per request:
//!
//! 1. **exact/path table** — a certified [`ekbloom::PathBloom`] (exact by
//!    construction),
//! 2. **full manifested state projection** — [`ekbloom::History`] state per
//!    position plus one machine reveal,
//! 3. **restart checkpoints** — [`ekbloom::CheckpointSet::restore`] plus bounded
//!    machine replay,
//! 4. **`D`-step transition bloom** — a universal [`GlobalBloom`] or a regional
//!    [`RegionTable`] stepped `D` symbols at a time,
//! 5. **the ordinary logical extent read** — the authoritative path
//!    ([`crate::namespace::Namespace::read_extent`]), always available.
//!
//! # Compatibility and certification on EVERY read
//!
//! Each read re-derives the object's committed version and root and requires
//! **exact** equality with the generation identity
//! ([`GenerationManifest::usable_for`](crate::manifestation::GenerationManifest::usable_for)),
//! plus the exact EKBLOOM engine version and full logical-extent coverage. A
//! structure that is absent, incomplete, corrupt, wrong-version, or
//! uncertified-for-domain is rejected and an alternative is used; the ultimate
//! alternative is the authoritative extent read. A manifested structure can
//! therefore never change the bytes a read returns.
//!
//! # Certification
//!
//! Certification is grounded in EKBLOOM's own exactness notions:
//!
//! * a body is loaded only after its payload BLAKE3 matches the committed
//!   manifest, [`ekbloom::reader::open_bytes`] accepts it, and its object
//!   identity/logical length/machine id agree with the manifest;
//! * [`ekbloom::verify`] recomputes core hash, authoritative decode, every
//!   history/checkpoint/bloom against the object's own positions, and the
//!   certificate receipts — a structure is **certified** iff its own check
//!   passes;
//! * a [`ekbloom::PathBloom`] is additionally certified only when EKBLOOM marks
//!   its shell `Certification::Certified`; history and checkpoints are exact by
//!   construction and certified by their passing check;
//! * a universal/regional `D`-step bloom is certified only when EKBLOOM's
//!   re-derived verdict is `Certification::Certified` (the **bloom key
//!   sufficiency law**). An `Unverified` bloom is **verified-on-use**: the
//!   planner compares it against the authoritative read and rejects it on any
//!   disagreement.
//!
//! # Selection by measurement
//!
//! The planner keeps an exponential-moving-average latency model per
//! (path, size class). That model is deliberately a **shared, aggregated
//! workload cost model**: it may inform *which mechanism* is worth trying, but it
//! never gates a correctness decision for one object.
//!
//! Per-object state — which candidates have been timed for a given object, and
//! which have failed for it — is keyed by the **full manifestation identity**
//! ([`ManifestIdentity`]: volume uuid, inode, inode version, committed root, and
//! generation). A rejected candidate for one inode can therefore never suppress
//! the same candidate for an unrelated inode, and calibration never leaks across
//! objects (Phase 18).
//!
//! Calibration is **bounded**: the first requests for an identity+class time the
//! candidates under a hard [`ReadPlannerConfig::calibration_budget_ns`] budget,
//! timing the authoritative read first so a correct baseline always exists. A
//! foreground read is never stalled to calibrate, and a `D`-step transition bloom
//! whose state would require an unbounded replay is refused outright, so a
//! manifestation can never add unbounded latency to a read (Phase 18).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, RwLock};

use ekbloom::bloom::{BloomKind, Certification, Outcome};
use ekbloom::bloom_global::GlobalBloom;
use ekbloom::bloom_path::PathBloom;
use ekbloom::bloom_region::RegionTable;
use ekbloom::checkpoint::CheckpointSet;
use ekbloom::{machine_by_id, EkbloomBody, Snapshot as EkSnapshot, VerificationReport};

use crate::error::{OrfsError, Result};
use crate::manifestation::{
    resolve_coverage, GenerationManifest, ManifestRegion, ManifestationState, EKBLOOM_VERSION,
};

/// The schema label of the read-path measurement surface.
pub const READPATH_SCHEMA: &str = "orfs.readpath.v1";

// ---------------------------------------------------------------------------
// Public request / result types
// ---------------------------------------------------------------------------

/// The kind of path that produced (or was asked to produce) a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReadPathKind {
    /// The ordinary authoritative logical extent read.
    LogicalExtent,
    /// A certified exact path bloom.
    PathBloom,
    /// A universal or regional `D`-step transition bloom.
    TransitionBloom,
    /// The full manifested state projection.
    History,
    /// A sparse/complete restart checkpoint.
    Checkpoint,
    /// An incremental generational overlay / flattened region table (Phase 22):
    /// unchanged regions reused from committed base generations, changed regions
    /// from the overlay's own payloads.
    Overlay,
}

impl ReadPathKind {
    /// Stable human-readable name used in evidence and diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            ReadPathKind::LogicalExtent => "logical-extent",
            ReadPathKind::PathBloom => "path-bloom",
            ReadPathKind::TransitionBloom => "transition-bloom",
            ReadPathKind::History => "history",
            ReadPathKind::Checkpoint => "checkpoint",
            ReadPathKind::Overlay => "overlay",
        }
    }

    /// Deterministic tie-break priority (lower is preferred on an equal cost).
    const fn priority(self) -> u8 {
        match self {
            ReadPathKind::Overlay => 0,
            ReadPathKind::PathBloom => 1,
            ReadPathKind::History => 2,
            ReadPathKind::Checkpoint => 3,
            ReadPathKind::TransitionBloom => 4,
            ReadPathKind::LogicalExtent => 5,
        }
    }
}

/// The **full identity** of one manifested generation.
///
/// Calibration and failure state are keyed by this, never by a globally-unique
/// generation number alone. Two structures can only share planner state when
/// every field agrees: the volume, the object (inode and its committed version),
/// the committed root the read is evaluated at, and the generation itself. A
/// rejected/failed candidate for one object can therefore never suppress the
/// same candidate for an unrelated object, and calibration never leaks across
/// objects (Phase 18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestIdentity {
    /// The volume the generation belongs to.
    pub volume_uuid: [u8; 16],
    /// The inode the generation manifests.
    pub inode: u64,
    /// The inode's committed version (I6).
    pub inode_version: u64,
    /// The committed root the generation was built at.
    pub root: u64,
    /// The generation number.
    pub generation: u64,
}

impl ManifestIdentity {
    /// The full identity of a manifest.
    pub fn of(manifest: &GenerationManifest) -> ManifestIdentity {
        ManifestIdentity {
            volume_uuid: manifest.volume_uuid,
            inode: manifest.inode,
            inode_version: manifest.inode_version,
            root: manifest.root,
            generation: manifest.generation,
        }
    }
}

/// A size class used to key the measured cost model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SizeClass {
    /// Zero-length request.
    Empty,
    /// A single byte.
    Byte,
    /// `2..=4096` bytes.
    Small,
    /// `4097..=65536` bytes.
    Medium,
    /// More than `65536` bytes.
    Large,
}

impl SizeClass {
    /// Stable name used in evidence.
    pub const fn name(self) -> &'static str {
        match self {
            SizeClass::Empty => "empty",
            SizeClass::Byte => "byte",
            SizeClass::Small => "small(<=4K)",
            SizeClass::Medium => "medium(<=64K)",
            SizeClass::Large => "large(>64K)",
        }
    }

    /// A representative effective length, used to seed the prior cost model.
    const fn representative_len(self) -> u64 {
        match self {
            SizeClass::Empty => 0,
            SizeClass::Byte => 1,
            SizeClass::Small => 2048,
            SizeClass::Medium => 16_384,
            SizeClass::Large => 262_144,
        }
    }
}

/// Classify an effective read length.
pub fn classify_length(len: u64) -> SizeClass {
    match len {
        0 => SizeClass::Empty,
        1 => SizeClass::Byte,
        2..=4096 => SizeClass::Small,
        4097..=65_536 => SizeClass::Medium,
        _ => SizeClass::Large,
    }
}

/// A fully-specified logical read request, with the identity a compatible
/// manifested structure must match exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadQuery {
    /// Inode identity.
    pub inode: u64,
    /// The inode's current committed version (I6).
    pub inode_version: u64,
    /// The authoritative committed root the read is evaluated at.
    pub root: u64,
    /// The inode's logical length in bytes.
    pub logical_len: u64,
    /// Logical byte offset.
    pub offset: u64,
    /// Requested length (clamped to the object by the authoritative read).
    pub length: u64,
}

/// The outcome of a planned read: the bytes plus the path that produced them.
#[derive(Debug, Clone)]
pub struct PlannedRead {
    /// The returned logical bytes (byte-identical to the authoritative read).
    pub bytes: Vec<u8>,
    /// The path that produced the bytes.
    pub path: ReadPathKind,
    /// The generation used, when a manifested structure served the read.
    pub generation: Option<u64>,
    /// The recorded profile of the generation, when applicable.
    pub profile: Option<String>,
    /// Whether the path was used without a per-read verification fallback.
    pub certified: bool,
    /// Why the authoritative path was used, when it was.
    pub fallback_reason: Option<String>,
}

impl PlannedRead {
    /// Construct an authoritative-path result. Public within the crate so the
    /// namespace can report the fallback path.
    pub(crate) fn fallback(bytes: Vec<u8>, reason: Option<String>) -> PlannedRead {
        PlannedRead {
            bytes,
            path: ReadPathKind::LogicalExtent,
            generation: None,
            profile: None,
            certified: false,
            fallback_reason: reason,
        }
    }
}

/// A measured per-(path, size-class) cost sample surface for evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct PathMeasurement {
    /// The path.
    pub path: ReadPathKind,
    /// The size class.
    pub class: SizeClass,
    /// The measured EWMA latency in nanoseconds.
    pub ewma_ns: f64,
    /// The number of recorded samples.
    pub samples: u64,
}

/// A directly measured latency for one candidate path (evidence surface).
#[derive(Debug, Clone, PartialEq)]
pub struct PathLatency {
    /// The path.
    pub path: ReadPathKind,
    /// Whether the path was certified (usable without per-read verification).
    pub certified: bool,
    /// The number of successful timed iterations.
    pub iterations: u32,
    /// The minimum observed latency in nanoseconds.
    pub min_ns: u128,
    /// The mean observed latency in nanoseconds.
    pub mean_ns: f64,
}

/// The explicit equivalence verdict for one candidate path's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathVerdict {
    /// The path.
    pub path: ReadPathKind,
    /// Whether the path was certified.
    pub certified: bool,
    /// Whether the path's bytes equal the authoritative extent read.
    pub equivalent: bool,
}

/// Planner configuration.
#[derive(Debug, Clone)]
pub struct ReadPlannerConfig {
    /// Refuse to materialise a payload larger than this (bytes). Beyond it the
    /// authoritative path is used rather than risking unbounded memory.
    pub max_payload_bytes: u64,
    /// Maximum number of parsed EKBLOOM bodies kept resident.
    pub cache_capacity: usize,
    /// Hard upper bound (nanoseconds) on the time the planner will spend
    /// *calibrating* candidate paths during a single foreground read. Once the
    /// budget is exhausted, candidates not yet timed keep their prior cost and
    /// the current request is served by the authoritative path. This guarantees
    /// the planner can never stall a foreground read to calibrate (Phase 18).
    pub calibration_budget_ns: u64,
}

impl Default for ReadPlannerConfig {
    fn default() -> ReadPlannerConfig {
        ReadPlannerConfig {
            max_payload_bytes: 512 * 1024 * 1024,
            cache_capacity: 64,
            calibration_budget_ns: 2_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Cost model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct EwmaCost {
    ns: f64,
    samples: u64,
}

#[derive(Debug, Default)]
struct CostModel {
    costs: HashMap<(ReadPathKind, SizeClass), EwmaCost>,
}

impl CostModel {
    /// A documented prior cost (nanoseconds), used only until real measurements
    /// exist. `fixed` is a per-request overhead; `per_byte` is the marginal cost.
    fn prior_ns(kind: ReadPathKind, class: SizeClass) -> f64 {
        let (fixed, per_byte) = match kind {
            ReadPathKind::LogicalExtent => (420.0, 24.0),
            ReadPathKind::PathBloom => (60.0, 9.0),
            ReadPathKind::TransitionBloom => (90.0, 11.0),
            ReadPathKind::History => (45.0, 7.0),
            ReadPathKind::Checkpoint => (70.0, 9.0),
            ReadPathKind::Overlay => (80.0, 10.0),
        };
        fixed + per_byte * class.representative_len() as f64
    }

    fn predict(&self, kind: ReadPathKind, class: SizeClass) -> f64 {
        self.costs
            .get(&(kind, class))
            .map(|c| c.ns)
            .unwrap_or_else(|| Self::prior_ns(kind, class))
    }

    fn record(&mut self, kind: ReadPathKind, class: SizeClass, measured_ns: f64) {
        const ALPHA: f64 = 0.3;
        let entry = self.costs.entry((kind, class)).or_insert(EwmaCost {
            ns: measured_ns,
            samples: 0,
        });
        entry.ns = if entry.samples == 0 {
            measured_ns
        } else {
            ALPHA * measured_ns + (1.0 - ALPHA) * entry.ns
        };
        entry.samples += 1;
    }

    fn measurements(&self) -> Vec<PathMeasurement> {
        let mut out: Vec<PathMeasurement> = self
            .costs
            .iter()
            .map(|(&(path, class), c)| PathMeasurement {
                path,
                class,
                ewma_ns: c.ns,
                samples: c.samples,
            })
            .collect();
        out.sort_by(|a, b| {
            a.class
                .name()
                .cmp(b.class.name())
                .then_with(|| a.path.priority().cmp(&b.path.priority()))
        });
        out
    }
}

// ---------------------------------------------------------------------------
// Loaded body + cache
// ---------------------------------------------------------------------------

/// A validated, verified EKBLOOM body together with the generation identity it
/// was loaded for. Manifested structures are parsed once here, so a read never
/// re-parses a bloom.
struct LoadedBody {
    body: EkbloomBody,
    report: VerificationReport,
    path_blooms: Vec<Option<PathBloom>>,
    global_blooms: Vec<Option<GlobalBloom>>,
    region_tables: Vec<Option<RegionTable>>,
    generation: u64,
    inode: u64,
    inode_version: u64,
    root: u64,
    logical_len: u64,
}

struct CacheEntry {
    generation: u64,
    manifest_blake3: [u8; 32],
    body: Arc<LoadedBody>,
}

/// A bounded, insertion-ordered body cache.
#[derive(Default)]
struct BodyCache {
    map: HashMap<u64, CacheEntry>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl BodyCache {
    fn get(&self, inode: u64, generation: u64, digest: &[u8; 32]) -> Option<Arc<LoadedBody>> {
        let e = self.map.get(&inode)?;
        if e.generation == generation && e.manifest_blake3 == *digest {
            Some(e.body.clone())
        } else {
            None
        }
    }

    fn insert(&mut self, inode: u64, entry: CacheEntry) {
        if self.capacity == 0 {
            return;
        }
        if self.map.contains_key(&inode) {
            self.order.retain(|&x| x != inode);
        }
        self.map.insert(inode, entry);
        self.order.push_back(inode);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

/// A cached, resolved region table for one overlay-backed generation.
struct CoverageEntry {
    generation: u64,
    digest: [u8; 32],
    table: Arc<Vec<ManifestRegion>>,
}

/// The bounded cache of parsed region payload bodies, keyed by payload path and
/// digest (Phase 22). A region payload is shared by every generation that reuses
/// it, so this cache is deliberately not keyed by the manifest identity.
#[derive(Default)]
struct RegionCache {
    map: HashMap<(String, [u8; 32]), Arc<EkbloomBody>>,
    order: VecDeque<(String, [u8; 32])>,
    capacity: usize,
}

impl RegionCache {
    fn get(&self, key: &(String, [u8; 32])) -> Option<Arc<EkbloomBody>> {
        self.map.get(key).cloned()
    }

    fn insert(&mut self, key: (String, [u8; 32]), body: Arc<EkbloomBody>) {
        if self.capacity == 0 {
            return;
        }
        if self.map.contains_key(&key) {
            self.order.retain(|k| k != &key);
        }
        self.order.push_back(key.clone());
        self.map.insert(key, body);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Candidates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Structure {
    Extent,
    Path { bloom_index: usize },
    History,
    Checkpoint { set_index: usize },
    Global { bloom_index: usize },
    Regional { bloom_index: usize },
}

#[derive(Debug, Clone, Copy)]
struct Candidate {
    kind: ReadPathKind,
    structure: Structure,
    /// Certified-and-compatible: usable without a per-read verification.
    certified: bool,
}

/// The maximum number of machine symbols the planner will replay
fn check_passed(report: &VerificationReport, name: &str) -> bool {
    report.checks.iter().any(|c| c.name == name && c.passed)
}

/// The maximum number of machine symbols the planner will replay from the
/// machine's initial state to reach a request position. A manifested structure
/// with no restart source (history or checkpoint) would otherwise require
/// replaying from the object's start — an O(offset) foreground read. Beyond this
/// bound the candidate is refused, so a manifestation can never cause unbounded
/// foreground read latency or rebuild amplification (Phase 18).
const MAX_REPLAY_SYMBOLS: u64 = 4096;

/// Whether the machine state at `offset` can be obtained without an unbounded
/// replay: a history covering the position, or a restart checkpoint whose
/// interval bounds the replay. Only then is a `D`-step transition bloom a
/// bounded-work candidate for a foreground read.
fn has_bounded_state_source(lb: &LoadedBody, offset: u64) -> bool {
    if let Some(h) = &lb.body.history {
        if h.logical_len == lb.body.logical_len && h.snapshot_at(offset).is_some() {
            return true;
        }
    }
    lb.body
        .checkpoints
        .iter()
        .any(|cp| cp.interval != 0 && cp.restart_point(offset).is_some())
}

/// Whether a manifested profile can provide a *bounded* read accelerator.
///
/// EKBLOOM's own speed ranking documents that `root`, universal and regional
/// `D`-step blooms do **not** accelerate the release corpus and fall back to
/// authoritative replay (their state at a large offset must be replayed from the
/// object's start). Loading and fully verifying such a body only to discover that
/// it cannot help would stall a foreground read for no benefit, so the planner
/// declines it up front. This is a bounded-work safety rule, not an acceleration
/// claim: the authoritative extent read remains available and correct (Phase 18).
fn profile_can_accelerate(profile_kind: u8) -> bool {
    // 0 = root, 4 = bloom(D), 5 = regional (see `ManifestationProfile::kind_code`).
    !matches!(profile_kind, 0 | 4 | 5)
}

/// Enumerate the compatible, structurally-usable candidates for a request.
///
/// The ordinary logical extent read is always a candidate, so the measured
/// selection can also decide that *no* manifested structure is worth using.
fn candidates(lb: &LoadedBody, q: &ReadQuery, eff_len: u64) -> Vec<Candidate> {
    let body = &lb.body;
    let report = &lb.report;
    let offset = q.offset;
    let end = offset + eff_len;
    let mut out = Vec::new();

    // (2) full manifested state projection.
    if let Some(h) = &body.history {
        if h.logical_len == body.logical_len
            && h.core_hash == body.core_hash
            && check_passed(report, "history")
        {
            out.push(Candidate {
                kind: ReadPathKind::History,
                structure: Structure::History,
                certified: true,
            });
        }
    }

    // (3) restart checkpoints.
    for (i, cp) in body.checkpoints.iter().enumerate() {
        if cp.interval == 0 || cp.restart_point(offset).is_none() {
            continue;
        }
        let name = format!("checkpoints[{i}] K={}", cp.interval);
        if check_passed(report, &name) {
            out.push(Candidate {
                kind: ReadPathKind::Checkpoint,
                structure: Structure::Checkpoint { set_index: i },
                certified: true,
            });
        }
    }

    // (1) exact/path table and (4) D-step transition blooms.
    for (i, shell) in body.blooms.iter().enumerate() {
        let name = format!("bloom[{i}]:{}", shell.kind.as_str());
        if !check_passed(report, &name) {
            continue;
        }
        match shell.kind {
            BloomKind::Path => {
                if shell.logical_len != body.logical_len {
                    continue;
                }
                let Some(pb) = lb.path_blooms[i].as_ref() else {
                    continue;
                };
                if pb.logical_len < end {
                    continue;
                }
                out.push(Candidate {
                    kind: ReadPathKind::PathBloom,
                    structure: Structure::Path { bloom_index: i },
                    certified: shell.status == Certification::Certified,
                });
            }
            BloomKind::Universal => {
                if lb.global_blooms[i].is_none() {
                    continue;
                }
                out.push(Candidate {
                    kind: ReadPathKind::TransitionBloom,
                    structure: Structure::Global { bloom_index: i },
                    certified: shell.status == Certification::Certified,
                });
            }
            BloomKind::Regional => {
                let Some(tbl) = lb.region_tables[i].as_ref() else {
                    continue;
                };
                if offset < tbl.logical_start
                    || offset >= tbl.logical_start.saturating_add(tbl.logical_len)
                {
                    continue;
                }
                out.push(Candidate {
                    kind: ReadPathKind::TransitionBloom,
                    structure: Structure::Regional { bloom_index: i },
                    certified: tbl.status == Certification::Certified,
                });
            }
            // Contextual blooms are not part of the documented OrFS read set.
            BloomKind::Contextual => {}
        }
    }

    // (5) the ordinary logical extent read (the authoritative path).
    out.push(Candidate {
        kind: ReadPathKind::LogicalExtent,
        structure: Structure::Extent,
        certified: true,
    });

    out
}

// ---------------------------------------------------------------------------
// Executors (EKBLOOM primitives only)
// ---------------------------------------------------------------------------

/// The machine state at logical position `pos`, from the best available source.
fn state_at(body: &EkbloomBody, pos: u64) -> Result<EkSnapshot> {
    if let Some(h) = &body.history {
        if h.logical_len == body.logical_len {
            if let Some(snap) = h.snapshot_at(pos) {
                return Ok(snap);
            }
        }
    }
    // Prefer the densest checkpoint that has a restart point for `pos`.
    let mut best: Option<&CheckpointSet> = None;
    for cp in &body.checkpoints {
        if cp.interval == 0 || cp.restart_point(pos).is_none() {
            continue;
        }
        if best.is_none_or(|b| cp.interval < b.interval) {
            best = Some(cp);
        }
    }
    if let Some(cp) = best {
        return Ok(cp.restore(&body.core, pos)?);
    }
    let machine = machine_by_id(body.machine_id).ok_or(OrfsError::Unsupported(format!(
        "no machine registered for id {}",
        body.machine_id
    )))?;
    machine.check_core(&body.core, body.logical_len)?;
    // No restart source: the only way to reach `pos` is to replay from the initial
    // state. Refuse an unbounded replay rather than let a manifestation cause an
    // O(pos) foreground read (Phase 18).
    if pos > MAX_REPLAY_SYMBOLS {
        return Err(OrfsError::Unsupported(format!(
            "no bounded state source for position {pos}: a from-scratch replay of {pos} \
             symbols exceeds the {MAX_REPLAY_SYMBOLS}-symbol bound"
        )));
    }
    let mut omega = machine.init(&body.core)?;
    let mut i = 0u64;
    while i < pos {
        machine.reveal(&body.core, &mut omega)?;
        i += 1;
    }
    Ok(omega)
}

fn read_path(lb: &LoadedBody, bloom_index: usize, offset: u64, end: u64) -> Result<Vec<u8>> {
    let bloom = lb.path_blooms[bloom_index]
        .as_ref()
        .ok_or_else(|| OrfsError::Corrupt("path bloom unavailable".into()))?;
    if bloom.logical_len < end {
        return Err(OrfsError::Corrupt(
            "path bloom does not cover the request".into(),
        ));
    }
    let mut out = Vec::with_capacity((end - offset) as usize);
    let mut pos = offset;
    while pos < end {
        out.push(bloom.symbol_at(pos)?);
        pos += 1;
    }
    Ok(out)
}

fn read_history(lb: &LoadedBody, offset: u64, end: u64) -> Result<Vec<u8>> {
    let history = lb
        .body
        .history
        .as_ref()
        .ok_or_else(|| OrfsError::Corrupt("history absent".into()))?;
    if history.logical_len != lb.body.logical_len {
        return Err(OrfsError::Corrupt(
            "history length disagrees with the body".into(),
        ));
    }
    let machine = machine_by_id(lb.body.machine_id)
        .ok_or(OrfsError::Unsupported("no machine registered".into()))?;
    let mut out = Vec::with_capacity((end - offset) as usize);
    let mut pos = offset;
    while pos < end {
        let mut omega = history
            .snapshot_at(pos)
            .ok_or_else(|| OrfsError::Corrupt("history does not cover the position".into()))?;
        out.push(machine.reveal(&lb.body.core, &mut omega)?);
        pos += 1;
    }
    Ok(out)
}

fn read_checkpoint(
    lb: &LoadedBody,
    set_index: usize,
    offset: u64,
    eff_len: u64,
) -> Result<Vec<u8>> {
    let cp = &lb.body.checkpoints[set_index];
    let machine = machine_by_id(lb.body.machine_id)
        .ok_or(OrfsError::Unsupported("no machine registered".into()))?;
    let mut omega = cp.restore(&lb.body.core, offset)?;
    let mut out = Vec::with_capacity(eff_len as usize);
    for _ in 0..eff_len {
        out.push(machine.reveal(&lb.body.core, &mut omega)?);
    }
    Ok(out)
}

fn read_global(lb: &LoadedBody, bloom_index: usize, offset: u64, end: u64) -> Result<Vec<u8>> {
    let bloom = lb.global_blooms[bloom_index]
        .as_ref()
        .ok_or_else(|| OrfsError::Corrupt("universal bloom unavailable".into()))?;
    let machine = machine_by_id(lb.body.machine_id)
        .ok_or(OrfsError::Unsupported("no machine registered".into()))?;
    let d = u64::from(bloom.depth);
    let mut out = Vec::with_capacity((end - offset) as usize);
    let mut omega = state_at(&lb.body, offset)?;
    let mut pos = offset;
    while d > 0 && pos + d <= end && pos + d <= lb.body.logical_len {
        let outcome: Outcome = bloom.step(omega.state)?;
        out.extend_from_slice(&outcome.symbols);
        omega = EkSnapshot::new(outcome.next_state, pos + d);
        pos += d;
    }
    // Tail (positions not covered by a full D-step window).
    while pos < end {
        out.push(machine.reveal(&lb.body.core, &mut omega)?);
        pos += 1;
    }
    Ok(out)
}

fn read_regional(lb: &LoadedBody, bloom_index: usize, offset: u64, end: u64) -> Result<Vec<u8>> {
    let table = lb.region_tables[bloom_index]
        .as_ref()
        .ok_or_else(|| OrfsError::Corrupt("regional bloom unavailable".into()))?;
    let region_end = table.logical_start.saturating_add(table.logical_len);
    if offset < table.logical_start || offset >= region_end {
        return Err(OrfsError::Corrupt(
            "request does not begin inside the region".into(),
        ));
    }
    let machine = machine_by_id(lb.body.machine_id)
        .ok_or(OrfsError::Unsupported("no machine registered".into()))?;
    let d = u64::from(table.depth);
    let mut out = Vec::with_capacity((end - offset) as usize);
    let mut omega = state_at(&lb.body, offset)?;
    let mut pos = offset;
    while d > 0 && pos + d <= end && pos + d <= region_end && pos + d <= lb.body.logical_len {
        let outcome = table.look(omega.state).ok_or_else(|| {
            OrfsError::Corrupt("regional bloom has no entry for a covered state".into())
        })?;
        out.extend_from_slice(&outcome.symbols);
        omega = EkSnapshot::new(outcome.next_state, pos + d);
        pos += d;
    }
    while pos < end {
        out.push(machine.reveal(&lb.body.core, &mut omega)?);
        pos += 1;
    }
    Ok(out)
}

/// The bytes a manifested structure reveals for the request. The ordinary extent
/// path is not represented here: it is the caller's authoritative read.
fn direct_bytes(
    structure: Structure,
    lb: &LoadedBody,
    q: &ReadQuery,
    eff_len: u64,
) -> Result<Vec<u8>> {
    let end = q.offset + eff_len;
    match structure {
        Structure::Path { bloom_index } => read_path(lb, bloom_index, q.offset, end),
        Structure::History => read_history(lb, q.offset, end),
        Structure::Checkpoint { set_index } => read_checkpoint(lb, set_index, q.offset, eff_len),
        Structure::Global { bloom_index } => read_global(lb, bloom_index, q.offset, end),
        Structure::Regional { bloom_index } => read_regional(lb, bloom_index, q.offset, end),
        Structure::Extent => Err(OrfsError::InvalidArgument(
            "the ordinary extent path is served by the caller, not a structure".into(),
        )),
    }
}

// ---------------------------------------------------------------------------
// The planner
// ---------------------------------------------------------------------------

/// The read planner: evaluates compatible certified structures and picks a valid
/// path by measurement, falling back to the authoritative extent read.
pub struct ReadPlanner {
    state: Arc<ManifestationState>,
    config: ReadPlannerConfig,
    model: RwLock<CostModel>,
    cache: Mutex<BodyCache>,
    /// (identity, size class, path) triples whose candidate has been timed. Keyed
    /// by the **full** identity, so no state leaks between objects.
    calibrated: RwLock<HashSet<(ManifestIdentity, SizeClass, ReadPathKind)>>,
    /// (identity, path) pairs proven unusable for that exact object.
    failed: RwLock<HashSet<(ManifestIdentity, ReadPathKind)>>,
    chosen: RwLock<HashMap<ReadPathKind, u64>>,
    /// Resolved region tables for overlay-backed generations.
    coverage: Mutex<HashMap<u64, CoverageEntry>>,
    /// Parsed region payload bodies, shared across generations.
    regions: Mutex<RegionCache>,
    /// Identities whose overlay bytes have been verified once against the
    /// authoritative read (so they are trusted thereafter).
    overlay_verified: RwLock<HashSet<ManifestIdentity>>,
}

impl ReadPlanner {
    /// Create a planner over a published-generation state.
    pub fn new(state: Arc<ManifestationState>, config: ReadPlannerConfig) -> ReadPlanner {
        let cache = BodyCache {
            capacity: config.cache_capacity,
            ..Default::default()
        };
        let regions = RegionCache {
            capacity: config.cache_capacity.max(1).saturating_mul(4),
            ..Default::default()
        };
        ReadPlanner {
            state,
            config,
            model: RwLock::new(CostModel::default()),
            cache: Mutex::new(cache),
            calibrated: RwLock::new(HashSet::new()),
            failed: RwLock::new(HashSet::new()),
            chosen: RwLock::new(HashMap::new()),
            coverage: Mutex::new(HashMap::new()),
            regions: Mutex::new(regions),
            overlay_verified: RwLock::new(HashSet::new()),
        }
    }

    /// The planner configuration.
    pub fn config(&self) -> &ReadPlannerConfig {
        &self.config
    }

    /// The measured per-(path, size-class) latency model, for evidence.
    pub fn measurements(&self) -> Vec<PathMeasurement> {
        self.model.read().measurements()
    }

    /// The number of reads served by each path since construction.
    pub fn chosen_counts(&self) -> Vec<(ReadPathKind, u64)> {
        let mut v: Vec<(ReadPathKind, u64)> =
            self.chosen.read().iter().map(|(k, c)| (*k, *c)).collect();
        v.sort_by_key(|(k, _)| k.priority());
        v
    }

    /// Forget the measured model, calibration set, failure set, and cached
    /// bodies (used by evidence runs that must observe a cold planner).
    pub fn reset(&self) {
        self.model.write().costs.clear();
        self.calibrated.write().clear();
        self.failed.write().clear();
        self.chosen.write().clear();
        self.coverage.lock().clear();
        self.region_cache_clear();
        self.overlay_verified.write().clear();
        let mut cache = self.cache.lock();
        cache.map.clear();
        cache.order.clear();
    }

    fn region_cache_clear(&self) {
        let mut c = self.regions.lock();
        c.map.clear();
        c.order.clear();
    }

    /// Measure each compatible candidate path for a request, independently of the
    /// cost model, and report the timings. Used for the performance evidence.
    pub fn measure_paths<F>(
        &self,
        q: &ReadQuery,
        auth: &mut F,
        iterations: u32,
    ) -> Result<Vec<PathLatency>>
    where
        F: FnMut(u64, u64) -> Result<Vec<u8>>,
    {
        let eff_len = q.logical_len.saturating_sub(q.offset).min(q.length);
        if eff_len == 0 {
            return Ok(Vec::new());
        }
        let manifest = self.state.latest_for(q.inode).ok_or_else(|| {
            OrfsError::InvalidArgument("no manifested generation for the inode".into())
        })?;
        manifest.usable_for(q.inode, q.inode_version, q.root)?;
        let loaded = self.load_body(&manifest)?;
        let cands = candidates(&loaded, q, eff_len);
        let mut out = Vec::new();
        let rounds = iterations.max(1);
        for c in &cands {
            let mut samples: Vec<u128> = Vec::with_capacity(rounds as usize);
            for _ in 0..rounds {
                let started = Instant::now();
                if self.execute(c, &loaded, q, eff_len, auth).is_ok() {
                    samples.push(started.elapsed().as_nanos());
                }
            }
            if samples.is_empty() {
                continue;
            }
            let min_ns = *samples.iter().min().unwrap_or(&0);
            let mean_ns = samples.iter().sum::<u128>() as f64 / samples.len() as f64;
            out.push(PathLatency {
                path: c.kind,
                certified: c.certified,
                iterations: samples.len() as u32,
                min_ns,
                mean_ns,
            });
        }
        Ok(out)
    }

    /// Evaluate a request, returning the bytes and the path that produced them.
    ///
    /// `auth` is the authoritative extent read; it is used for the ultimate
    /// fallback and to verify-on-use uncertified structures.
    pub fn read<F>(&self, q: &ReadQuery, mut auth: F) -> Result<PlannedRead>
    where
        F: FnMut(u64, u64) -> Result<Vec<u8>>,
    {
        let eff_len = q.logical_len.saturating_sub(q.offset).min(q.length);
        if eff_len == 0 {
            return Ok(PlannedRead::fallback(auth(q.offset, q.length)?, None));
        }

        // --- compatibility + version/root qualification on EVERY read ---
        let manifest = match self.state.latest_for(q.inode) {
            Some(m) => m,
            None => {
                return Ok(PlannedRead::fallback(
                    auth(q.offset, q.length)?,
                    Some("no manifested generation".into()),
                ))
            }
        };
        if let Err(e) = manifest.usable_for(q.inode, q.inode_version, q.root) {
            return Ok(PlannedRead::fallback(
                auth(q.offset, q.length)?,
                Some(e.to_string()),
            ));
        }
        if manifest.ekbloom_version != EKBLOOM_VERSION {
            return Ok(PlannedRead::fallback(
                auth(q.offset, q.length)?,
                Some(format!(
                    "ekbloom engine {} does not match {}",
                    manifest.ekbloom_version, EKBLOOM_VERSION
                )),
            ));
        }
        if manifest.logical_start != 0 || manifest.logical_end != q.logical_len {
            return Ok(PlannedRead::fallback(
                auth(q.offset, q.length)?,
                Some("manifested structure does not cover the logical extent".into()),
            ));
        }

        // --- incremental generational overlay (Phase 22) ---
        // A region-backed generation (overlay or flattened table) has no single
        // top-level body; it is resolved through its bounded region indirection,
        // reusing unchanged committed content from its base.
        if manifest.is_region_backed() {
            return self.read_region_backed(&manifest, q, eff_len, auth);
        }
        // A profile EKBLOOM documents as non-accelerating is not loaded at all:
        // loading + verifying it cannot change the bytes and would only add
        // unbounded foreground work (Phase 18).
        if !profile_can_accelerate(manifest.profile_kind) {
            return Ok(PlannedRead::fallback(
                auth(q.offset, q.length)?,
                Some(format!(
                    "manifested profile {} has no bounded read accelerator",
                    manifest.profile
                )),
            ));
        }

        // --- load + fully validate the manifested body ---
        let loaded = match self.load_body(&manifest) {
            Ok(l) => l,
            Err(e) => {
                return Ok(PlannedRead::fallback(
                    auth(q.offset, q.length)?,
                    Some(e.to_string()),
                ))
            }
        };

        // --- identity re-check on the loaded body (defence in depth) ---
        if loaded.inode != q.inode
            || loaded.inode_version != q.inode_version
            || loaded.root != q.root
            || loaded.logical_len != q.logical_len
        {
            return Ok(PlannedRead::fallback(
                auth(q.offset, q.length)?,
                Some("loaded structure identity does not match the request".into()),
            ));
        }

        let identity = ManifestIdentity::of(&manifest);
        let generation = loaded.generation;
        let class = classify_length(eff_len);

        // Drop candidates already proven unusable for this exact identity, and any
        // `D`-step transition bloom whose state at this offset cannot be obtained
        // within the replay bound. Keying by the *full* identity means a candidate
        // barred for one object never suppresses it for another (Phase 18).
        let cands: Vec<Candidate> = {
            let failed = self.failed.read();
            candidates(&loaded, q, eff_len)
                .into_iter()
                .filter(|c| !failed.contains(&(identity, c.kind)))
                .filter(|c| match c.structure {
                    Structure::Global { .. } | Structure::Regional { .. } => {
                        has_bounded_state_source(&loaded, q.offset)
                    }
                    _ => true,
                })
                .collect()
        };
        if cands.is_empty() {
            return Ok(PlannedRead::fallback(
                auth(q.offset, q.length)?,
                Some("no compatible certified structure".into()),
            ));
        }

        // --- bounded calibration (Phase 18) -----------------------------------
        // Time any candidate not yet timed for this identity+class. The
        // authoritative read is timed first (it is always correct and cheap), so
        // a valid baseline always exists; the loop then stops as soon as the
        // configured budget is exhausted. A foreground read is therefore never
        // stalled to calibrate, and no candidate predicted to be expensive is
        // forced through. Successful bytes are retained so the served candidate is
        // not executed twice.
        let budget = self.config.calibration_budget_ns;
        let pending: Vec<Candidate> = {
            let cal = self.calibrated.read();
            cands
                .iter()
                .filter(|c| !cal.contains(&(identity, class, c.kind)))
                .cloned()
                .collect()
        };
        let mut measured_bytes: HashMap<ReadPathKind, (Vec<u8>, bool)> = HashMap::new();
        if !pending.is_empty() {
            let mut order = pending;
            order.sort_by_key(|c| u8::from(c.kind != ReadPathKind::LogicalExtent));
            let started = Instant::now();
            for c in &order {
                if started.elapsed().as_nanos() as u64 > budget {
                    break;
                }
                let t = Instant::now();
                match self.execute(c, &loaded, q, eff_len, &mut auth) {
                    Ok(bytes) => {
                        let nanos = t.elapsed().as_nanos();
                        self.model.write().record(c.kind, class, nanos as f64);
                        self.calibrated.write().insert((identity, class, c.kind));
                        measured_bytes.insert(c.kind, (bytes, c.certified));
                    }
                    Err(_) => {
                        // A structure that cannot serve this object is barred for
                        // this identity; a read never retries it blindly.
                        self.failed.write().insert((identity, c.kind));
                    }
                }
            }
        }

        // --- select the cheapest calibrated candidate under the measured model --
        // Only candidates actually timed for this identity+class are eligible, so
        // an unmeasured (optimistic-prior) path can never be chosen blindly.
        let measured: Vec<Candidate> = {
            let cal = self.calibrated.read();
            cands
                .iter()
                .filter(|c| cal.contains(&(identity, class, c.kind)))
                .cloned()
                .collect()
        };
        let mut order: Vec<Candidate> = if measured.is_empty() {
            // No candidate for this object has been calibrated within the budget:
            // serve the authoritative path. Uncalibrated candidates are never
            // tried blindly — the documented selection guarantee is that only a
            // previously *measured* candidate may be selected. They are calibrated
            // by the bounded pass above on this or a later read.
            return Ok(PlannedRead::fallback(
                auth(q.offset, q.length)?,
                Some("no calibrated candidate for this object yet".into()),
            ));
        } else {
            measured
        };
        {
            let model = self.model.read();
            order.sort_by(|a, b| {
                model
                    .predict(a.kind, class)
                    .partial_cmp(&model.predict(b.kind, class))
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.certified.cmp(&a.certified))
                    .then_with(|| a.kind.priority().cmp(&b.kind.priority()))
            });
        }
        let mut last_err: Option<String> = None;
        for c in &order {
            // Reuse bytes already produced for this exact candidate during
            // calibration, so the authoritative fallback is executed once.
            let produced = match measured_bytes.remove(&c.kind) {
                // Bytes already produced (and accurately timed) by the calibration
                // pass: reuse them WITHOUT re-recording. Recording again here would
                // feed a near-zero "map lookup" duration into the cost model and
                // corrupt future path selection.
                Some((bytes, certified)) => {
                    debug_assert_eq!(certified, c.certified);
                    Ok(bytes)
                }
                // Not produced this call: execute AND time the execution. The timer
                // must wrap `execute`, never follow it — timing after execution
                // measured almost no work and poisoned the EWMA cost model.
                None => {
                    let t = Instant::now();
                    let r = self.execute(c, &loaded, q, eff_len, &mut auth);
                    let nanos = t.elapsed().as_nanos();
                    if r.is_ok() {
                        self.model.write().record(c.kind, class, nanos as f64);
                        self.calibrated.write().insert((identity, class, c.kind));
                    }
                    r
                }
            };
            match produced {
                Ok(bytes) => {
                    let reason = if c.kind == ReadPathKind::LogicalExtent {
                        last_err.clone()
                    } else {
                        None
                    };
                    return Ok(self.serve(
                        bytes,
                        c.kind,
                        generation,
                        &manifest,
                        c.certified,
                        reason,
                    ));
                }
                Err(e) => {
                    self.failed.write().insert((identity, c.kind));
                    last_err = Some(e.to_string());
                }
            }
        }
        Ok(PlannedRead::fallback(
            auth(q.offset, q.length)?,
            Some(last_err.unwrap_or_else(|| "no candidate path produced bytes".into())),
        ))
    }

    /// Execute each compatible candidate's structure and report whether its bytes
    /// equal the authoritative read. This is the explicit per-path equivalence
    /// check (research §10.2: a missing or invalid structure must never change the
    /// bytes).
    pub fn verify_paths<F>(&self, q: &ReadQuery, auth: &mut F) -> Result<Vec<PathVerdict>>
    where
        F: FnMut(u64, u64) -> Result<Vec<u8>>,
    {
        let eff_len = q.logical_len.saturating_sub(q.offset).min(q.length);
        let manifest = self.state.latest_for(q.inode).ok_or_else(|| {
            OrfsError::InvalidArgument("no manifested generation for the inode".into())
        })?;
        manifest.usable_for(q.inode, q.inode_version, q.root)?;
        if manifest.is_region_backed() {
            let expected = auth(q.offset, q.length)?;
            let equivalent = matches!(
                self.overlay_bytes(&manifest, q.offset, q.offset + eff_len),
                Ok(b) if b == expected
            );
            return Ok(vec![PathVerdict {
                path: ReadPathKind::Overlay,
                certified: true,
                equivalent,
            }]);
        }
        let loaded = self.load_body(&manifest)?;
        let expected = auth(q.offset, q.length)?;
        let mut out = Vec::new();
        for c in candidates(&loaded, q, eff_len) {
            let equivalent = match c.structure {
                Structure::Extent => true,
                other => matches!(direct_bytes(other, &loaded, q, eff_len), Ok(b) if b == expected),
            };
            out.push(PathVerdict {
                path: c.kind,
                certified: c.certified,
                equivalent,
            });
        }
        Ok(out)
    }

    fn serve(
        &self,
        bytes: Vec<u8>,
        path: ReadPathKind,
        generation: u64,
        manifest: &GenerationManifest,
        certified: bool,
        reason: Option<String>,
    ) -> PlannedRead {
        *self.chosen.write().entry(path).or_insert(0) += 1;
        if path == ReadPathKind::LogicalExtent {
            // The authoritative path was used. When `reason` is set, one or more
            // manifested candidates failed first (a fallback); otherwise the model
            // chose it because it measured fastest (a normal choice).
            let fallback = reason.is_some();
            return PlannedRead {
                bytes,
                path,
                generation: None,
                profile: None,
                certified: !fallback,
                fallback_reason: reason,
            };
        }
        PlannedRead {
            bytes,
            path,
            generation: Some(generation),
            profile: Some(manifest.profile.clone()),
            certified,
            fallback_reason: None,
        }
    }

    fn execute<F>(
        &self,
        c: &Candidate,
        lb: &LoadedBody,
        q: &ReadQuery,
        eff_len: u64,
        auth: &mut F,
    ) -> Result<Vec<u8>>
    where
        F: FnMut(u64, u64) -> Result<Vec<u8>>,
    {
        let direct = match c.structure {
            Structure::Extent => auth(q.offset, q.length)?,
            other => direct_bytes(other, lb, q, eff_len)?,
        };
        if direct.len() as u64 != eff_len {
            return Err(OrfsError::Corrupt(format!(
                "{} returned {} bytes, expected {}",
                c.kind.name(),
                direct.len(),
                eff_len
            )));
        }
        if c.certified {
            return Ok(direct);
        }
        // Uncertified-for-domain: verify-on-use against the authoritative read.
        let authoritative = auth(q.offset, q.length)?;
        if authoritative == direct {
            Ok(direct)
        } else {
            Err(OrfsError::Corrupt(format!(
                "uncertified {} disagreed with the authoritative read; rejected",
                c.kind.name()
            )))
        }
    }

    /// Resolve a region-backed (overlay / flattened) generation and serve the
    /// request (Phase 22). The first read for an identity is verified against the
    /// authoritative read; on success it is trusted, and on any disagreement the
    /// overlay is barred for that identity and the authoritative bytes are served,
    /// so an accelerated read is byte-identical with the authoritative one.
    fn read_region_backed<F>(
        &self,
        manifest: &GenerationManifest,
        q: &ReadQuery,
        eff_len: u64,
        mut auth: F,
    ) -> Result<PlannedRead>
    where
        F: FnMut(u64, u64) -> Result<Vec<u8>>,
    {
        let identity = ManifestIdentity::of(manifest);
        if self
            .failed
            .read()
            .contains(&(identity, ReadPathKind::Overlay))
        {
            return Ok(PlannedRead::fallback(
                auth(q.offset, q.length)?,
                Some("incremental overlay previously rejected for this version".into()),
            ));
        }
        let bytes = match self.overlay_bytes(manifest, q.offset, q.offset + eff_len) {
            Ok(b) => b,
            Err(e) => {
                return Ok(PlannedRead::fallback(
                    auth(q.offset, q.length)?,
                    Some(e.to_string()),
                ))
            }
        };
        if bytes.len() as u64 != eff_len {
            return Ok(PlannedRead::fallback(
                auth(q.offset, q.length)?,
                Some("incremental overlay returned the wrong length".into()),
            ));
        }
        let already = self.overlay_verified.read().contains(&identity);
        if !already {
            let authoritative = auth(q.offset, q.length)?;
            if authoritative != bytes {
                self.failed
                    .write()
                    .insert((identity, ReadPathKind::Overlay));
                return Ok(PlannedRead::fallback(
                    authoritative,
                    Some("incremental overlay disagreed with the authoritative read".into()),
                ));
            }
            self.overlay_verified.write().insert(identity);
        }
        *self
            .chosen
            .write()
            .entry(ReadPathKind::Overlay)
            .or_insert(0) += 1;
        Ok(PlannedRead {
            bytes,
            path: ReadPathKind::Overlay,
            generation: Some(manifest.generation),
            profile: Some(manifest.profile.clone()),
            certified: true,
            fallback_reason: None,
        })
    }

    /// The bytes a region-backed generation resolves for `[off, end)`: it splits
    /// the request across the (bounded) resolved region table, reading each region
    /// from its own committed payload.
    fn overlay_bytes(&self, manifest: &GenerationManifest, off: u64, end: u64) -> Result<Vec<u8>> {
        if end <= off {
            return Ok(Vec::new());
        }
        let table = self.coverage_for(manifest)?;
        let mut out = Vec::with_capacity((end - off) as usize);
        let mut pos = off;
        while pos < end {
            // Regions are disjoint and sorted, so the covering region is the
            // first whose end exceeds `pos` (Phase 22: bounded, O(log n) lookup).
            let idx = table.partition_point(|r| r.logical_end <= pos);
            let r = table
                .get(idx)
                .filter(|r| r.logical_start <= pos && pos < r.logical_end)
                .ok_or_else(|| {
                    OrfsError::Corrupt(format!("incremental coverage has a gap at {pos}"))
                })?;
            if !profile_can_accelerate(r.profile_kind)
                && r.logical_end.saturating_sub(r.logical_start) > MAX_REPLAY_SYMBOLS
            {
                return Err(OrfsError::Unsupported(
                    "incremental region would require an unbounded replay".into(),
                ));
            }
            let stop = end.min(r.logical_end);
            let body = self.region_body(r)?;
            let local = r.payload_offset + (pos - r.logical_start);
            let n = stop - pos;
            let bytes = ekbloom::read(
                &body,
                ekbloom::ReadRequest {
                    offset: local,
                    length: n,
                },
            )?;
            if bytes.len() as u64 != n {
                return Err(OrfsError::Corrupt(
                    "incremental region read returned the wrong length".into(),
                ));
            }
            out.extend_from_slice(&bytes);
            pos = stop;
        }
        Ok(out)
    }

    /// The (cached) complete region table for a region-backed generation.
    fn coverage_for(&self, manifest: &GenerationManifest) -> Result<Arc<Vec<ManifestRegion>>> {
        if let Some(e) = self.coverage.lock().get(&manifest.inode) {
            if e.generation == manifest.generation && e.digest == manifest.manifest_blake3 {
                return Ok(e.table.clone());
            }
        }
        let table = Arc::new(resolve_coverage(self.state.store(), manifest)?);
        self.coverage.lock().insert(
            manifest.inode,
            CoverageEntry {
                generation: manifest.generation,
                digest: manifest.manifest_blake3,
                table: table.clone(),
            },
        );
        Ok(table)
    }

    /// Load, validate, and fully verify one region payload body, with caching.
    fn region_body(&self, r: &ManifestRegion) -> Result<Arc<EkbloomBody>> {
        let key = (r.payload_rel_path.clone(), r.payload_blake3);
        if let Some(b) = self.regions.lock().get(&key) {
            return Ok(b);
        }
        let path = self.state.store().volume_root().join(&r.payload_rel_path);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(OrfsError::Corrupt(format!(
                    "incremental region payload is absent: {}",
                    r.payload_rel_path
                )))
            }
            Err(e) => return Err(e.into()),
        };
        if bytes.len() as u64 > self.config.max_payload_bytes {
            return Err(OrfsError::Unsupported(format!(
                "incremental region payload {} bytes exceeds the configured {} byte limit",
                bytes.len(),
                self.config.max_payload_bytes
            )));
        }
        if *blake3::hash(&bytes).as_bytes() != r.payload_blake3 {
            return Err(OrfsError::Corrupt(
                "incremental region payload BLAKE3 does not match the committed manifest".into(),
            ));
        }
        let body = ekbloom::reader::open_bytes(&bytes)?;
        if let Some(oid) = r.ekbloom_object_id {
            if body.object_id != oid {
                return Err(OrfsError::Corrupt(
                    "incremental region object identity does not match the manifest".into(),
                ));
            }
        }
        let report = ekbloom::verify(&body)?;
        if !check_passed(&report, "core_hash") || !check_passed(&report, "decode_length") {
            return Err(OrfsError::Corrupt(
                "incremental region body failed EKBLOOM verification".into(),
            ));
        }
        let body = Arc::new(body);
        self.regions.lock().insert(key, body.clone());
        Ok(body)
    }

    /// Load, validate, and fully verify a manifested body, with caching.
    fn load_body(&self, manifest: &GenerationManifest) -> Result<Arc<LoadedBody>> {
        if let Some(hit) = self.cache.lock().get(
            manifest.inode,
            manifest.generation,
            &manifest.manifest_blake3,
        ) {
            return Ok(hit);
        }
        let loaded = Arc::new(self.build_loaded_body(manifest)?);
        self.cache.lock().insert(
            manifest.inode,
            CacheEntry {
                generation: manifest.generation,
                manifest_blake3: manifest.manifest_blake3,
                body: loaded.clone(),
            },
        );
        Ok(loaded)
    }

    fn build_loaded_body(&self, manifest: &GenerationManifest) -> Result<LoadedBody> {
        let path = self
            .state
            .store()
            .volume_root()
            .join(&manifest.payload_rel_path);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(OrfsError::Corrupt(format!(
                    "manifested payload is absent: {}",
                    manifest.payload_rel_path
                )))
            }
            Err(e) => return Err(e.into()),
        };
        if bytes.len() as u64 > self.config.max_payload_bytes {
            return Err(OrfsError::Unsupported(format!(
                "manifested payload {} bytes exceeds the configured {} byte limit",
                bytes.len(),
                self.config.max_payload_bytes
            )));
        }
        // Integrity: the on-disk payload must match the committed digest.
        if *blake3::hash(&bytes).as_bytes() != manifest.payload_blake3 {
            return Err(OrfsError::Corrupt(
                "manifested payload BLAKE3 does not match the committed manifest".into(),
            ));
        }
        let body = ekbloom::reader::open_bytes(&bytes)?;
        if let Some(oid) = manifest.ekbloom_object_id {
            if body.object_id != oid {
                return Err(OrfsError::Corrupt(
                    "manifested object identity does not match the committed manifest".into(),
                ));
            }
        }
        if body.logical_len != manifest.logical_len() {
            return Err(OrfsError::Corrupt(
                "manifested logical length does not match the committed manifest".into(),
            ));
        }
        if body.machine_id != ekbloom::MACHINE_NL2 {
            return Err(OrfsError::Unsupported(format!(
                "manifested machine id {} is not the supported EKBLOOM machine",
                body.machine_id
            )));
        }
        // Certification: EKBLOOM recomputes everything against the object itself.
        let report = ekbloom::verify(&body)?;
        if !check_passed(&report, "core_hash") || !check_passed(&report, "decode_length") {
            return Err(OrfsError::Corrupt(
                "manifested body failed EKBLOOM core verification".into(),
            ));
        }
        // Parse each manifested structure exactly once.
        let path_blooms = body
            .blooms
            .iter()
            .map(|s| {
                if s.kind == BloomKind::Path {
                    PathBloom::from_shell(s).ok()
                } else {
                    None
                }
            })
            .collect();
        let global_blooms = body
            .blooms
            .iter()
            .map(|s| {
                if s.kind == BloomKind::Universal {
                    GlobalBloom::from_shell(s).ok()
                } else {
                    None
                }
            })
            .collect();
        let region_tables = body
            .blooms
            .iter()
            .map(|s| {
                if s.kind == BloomKind::Regional {
                    RegionTable::from_shell(s).ok()
                } else {
                    None
                }
            })
            .collect();
        Ok(LoadedBody {
            body,
            report,
            path_blooms,
            global_blooms,
            region_tables,
            generation: manifest.generation,
            inode: manifest.inode,
            inode_version: manifest.inode_version,
            root: manifest.root,
            logical_len: manifest.logical_len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_classes_are_ordered_and_disjoint() {
        assert_eq!(classify_length(0), SizeClass::Empty);
        assert_eq!(classify_length(1), SizeClass::Byte);
        assert_eq!(classify_length(2), SizeClass::Small);
        assert_eq!(classify_length(4096), SizeClass::Small);
        assert_eq!(classify_length(4097), SizeClass::Medium);
        assert_eq!(classify_length(65_536), SizeClass::Medium);
        assert_eq!(classify_length(65_537), SizeClass::Large);
    }

    #[test]
    fn measured_model_overrides_the_prior() {
        let mut m = CostModel::default();
        let prior = m.predict(ReadPathKind::History, SizeClass::Small);
        m.record(ReadPathKind::History, SizeClass::Small, 5.0);
        assert!((m.predict(ReadPathKind::History, SizeClass::Small) - 5.0).abs() < 1e-9);
        m.record(ReadPathKind::History, SizeClass::Small, 105.0);
        let after = m.predict(ReadPathKind::History, SizeClass::Small);
        assert!(after > 5.0 && after < 105.0, "ewma={after} prior={prior}");
    }

    fn identity(
        volume: u8,
        inode: u64,
        version: u64,
        root: u64,
        generation: u64,
    ) -> ManifestIdentity {
        ManifestIdentity {
            volume_uuid: [volume; 16],
            inode,
            inode_version: version,
            root,
            generation,
        }
    }

    /// Phase 18 — the read-planner isolation defect. Calibration and failure
    /// state must be keyed by the **full** manifestation identity, never by a
    /// generation number alone: a rejected/failed candidate for one object must
    /// not suppress the same candidate for an unrelated object, and calibration
    /// must not leak across objects. This test uses two identities that share a
    /// generation number and differ only in inode/root/version — exactly the
    /// collision an object-keyed-by-generation design would conflate.
    #[test]
    fn calibration_and_failure_state_are_keyed_by_full_identity() {
        let a = identity(1, 100, 3, 500, 7);
        let b = identity(1, 200, 3, 500, 7); // same generation, different inode
        let c = identity(1, 100, 4, 500, 7); // same generation, different version
        let d = identity(1, 100, 3, 501, 7); // same generation, different root
        let e = identity(2, 100, 3, 500, 7); // same generation, different volume

        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);

        let mut failed: HashSet<(ManifestIdentity, ReadPathKind)> = HashSet::new();
        failed.insert((a, ReadPathKind::PathBloom));
        assert!(failed.contains(&(a, ReadPathKind::PathBloom)));
        for other in [b, c, d, e] {
            assert!(
                !failed.contains(&(other, ReadPathKind::PathBloom)),
                "a failure for one object leaked onto {other:?}"
            );
        }

        let mut calibrated: HashSet<(ManifestIdentity, SizeClass, ReadPathKind)> = HashSet::new();
        calibrated.insert((a, SizeClass::Small, ReadPathKind::History));
        assert!(calibrated.contains(&(a, SizeClass::Small, ReadPathKind::History)));
        for other in [b, c, d, e] {
            assert!(!calibrated.contains(&(other, SizeClass::Small, ReadPathKind::History)));
        }
        // A different size class on the same object is also distinct.
        assert!(!calibrated.contains(&(a, SizeClass::Large, ReadPathKind::History)));
    }

    /// Phase 18 — the identity really is derived from the manifest's own fields,
    /// so two manifests that collide on generation but differ anywhere else are
    /// distinct keys.
    #[test]
    fn manifest_identity_is_derived_from_every_identity_field() {
        let base = |gen: u64, ino: u64, ver: u64, root: u64, uuid: [u8; 16]| GenerationManifest {
            generation: gen,
            volume_uuid: uuid,
            inode: ino,
            inode_version: ver,
            root,
            ..sample_manifest_stub()
        };
        let x = ManifestIdentity::of(&base(1, 1, 1, 1, [0; 16]));
        let y = ManifestIdentity::of(&base(1, 2, 1, 1, [0; 16]));
        assert_ne!(x, y);
    }

    /// A minimal `GenerationManifest` for identity tests. The read planner only
    /// reads the identity fields through `ManifestIdentity::of`, so the rest of
    /// the manifest is irrelevant here.
    fn sample_manifest_stub() -> GenerationManifest {
        GenerationManifest {
            schema: crate::manifestation::MANIFEST_SCHEMA,
            generation: 0,
            volume_uuid: [0; 16],
            inode: 0,
            inode_version: 0,
            root: 0,
            backend: String::new(),
            ekbloom_version: String::new(),
            ekbloom_format: String::new(),
            profile: String::new(),
            profile_kind: 0,
            logical_start: 0,
            logical_end: 0,
            physical_start: 0,
            physical_end: 0,
            interval: None,
            depth: None,
            region_bytes: None,
            certification: crate::manifestation::CertificationState::Built,
            certification_method: String::new(),
            payload_rel_path: String::new(),
            ekbloom_object_id: None,
            payload_blake3: [0; 32],
            visible_bytes: 0,
            physical_bytes: 0,
            concealed_bytes: 0,
            source_bytes: 0,
            components: Vec::new(),
            base_generation: None,
            base_manifest_blake3: None,
            overlay_depth: 0,
            regions: Vec::new(),
            manifest_blake3: [0; 32],
        }
    }
}
