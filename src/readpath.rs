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
//! # Selection by measurement: a precompiled per-object read plan
//!
//! The planner keeps an exponential-moving-average latency model per
//! (path, size class). Selection is **object-localized**: when the queried object
//! has its own measurement for a candidate, that measurement predicts the read;
//! only when it has none does selection fall back to the shared aggregate. Two
//! objects with different access characteristics therefore cannot bias each
//! other's choice. The model may inform *which* mechanism is worth trying, but it
//! never gates a correctness decision for one object.
//!
//! Planning is **precompiled**, not re-derived per request. When a generation's
//! body is loaded (its identity, version, and manifestation set determined) the
//! planner publishes an immutable [`ObjectPlan`] alongside it inside the cached
//! [`LoadedBody`]: the request-independent structure inventory (each structure
//! with its recomputed certification) computed once, and a per-[`SizeClass`]
//! **ranking** of the candidates actually measured for that class. A steady-state
//! certified read is then a bounded lookup + execute:
//!
//! ```text
//! classify the effective length -> look up the published ranking for that class
//!   -> execute the first candidate it names that covers the request -> bytes
//! ```
//!
//! No candidate vector is built, nothing is sorted, and no cost-model lock is
//! taken (the ranking is an immutable `Arc` behind a read lock; per-object failure
//! state is a single atomic byte, not a hash set). On any miss — no ranking yet,
//! an unavailable or failed candidate, an execution error — the authoritative
//! extent read serves the request: an **unmeasured** candidate is never selected.
//!
//! Learning is **off the steady state**. The first request for a given
//! `(identity, size class)` runs the bounded **calibration** pass (below); it is
//! the only point at which the measured model is written and a ranking is
//! published. Steady-state reads never mutate shared policy; the accumulated
//! observations of completed reads can be folded in through the explicit
//! [`ReadPlanner::record_observation`] learner seam (amortised, out of band).
//!
//! # Tail sensitivity
//!
//! The cost model is an EWMA **mean** per (path, size class), not a tail
//! statistic. A tail-sensitive estimate (say p99) would change *which* measured
//! path is preferred but could not change the bytes a read returns: selection is
//! correctness-neutral (the authoritative extent read is always a candidate, and
//! an uncertified manifested candidate is verified-on-use), and a measured-but-
//! slow candidate is simply ranked lower. Recording a quantile would add
//! per-candidate memory and an update to the model for no correctness gain, so the
//! mean is kept and the deterministic tie-break (certified first, then the fixed
//! path priority) resolves equal means. The tail is bounded independently: by the
//! calibration budget, by [`MAX_REPLAY_SYMBOLS`], and by the fact that a manifested
//! structure can never return different bytes.
//!
//! Per-object state is keyed by the **full manifestation identity**
//! ([`ManifestIdentity`]: volume uuid, inode, inode version, committed root, and
//! generation). A rejected candidate for one inode can therefore never suppress
//! the same candidate for an unrelated inode, and calibration never leaks across
//! objects (Phase 18). Only a candidate actually measured for the exact object is
//! ever eligible for selection, so an unmeasured (optimistic-prior) path can never
//! be chosen blindly.
//!
//! # Bounded planner state
//!
//! Every identity-keyed table the planner owns is explicitly bounded and retired
//! in insertion order (age eviction), so total planner state cannot grow with the
//! number of manifestations ever read:
//!
//! * a [`ObjectPlan`] lives inside its cached [`LoadedBody`], so it is bounded by
//!   `ReadPlannerConfig::cache_capacity` (the body cache retires old entries);
//! * the per-object selection models ([`ObjectCosts`]) and the region-overlay
//!   verification/failure ledger ([`IdentityLedger`]) are bounded by
//!   `ReadPlannerConfig::cache_capacity` and `ReadPlannerConfig::identity_capacity`
//!   respectively, and retire least-*recently-inserted* generations first.
//!
//! Retiring an entry can only ever turn a *measured* candidate back into an
//! *unmeasured* one, which already falls back to the authoritative path; it can
//! never cause a wrong selection. [`ReadPlanner::resident`] reports the resident
//! entries so the bound is observable (see `tests/read_path_planner.rs`).
//!
//! The authoritative fallback is deliberately lean: a request's authoritative read
//! is wrapped so it runs **at most once** (a fallback serves bytes a calibration
//! pass already produced rather than re-executing the read), and `'static` fallback
//! reasons are borrowed rather than allocated.
//!
//! Calibration is **bounded**: the first requests for an identity+class time the
//! candidates under a hard [`ReadPlannerConfig::calibration_budget_ns`] budget,
//! timing the authoritative read first so a correct baseline always exists. A
//! foreground read is never stalled to calibrate, and a `D`-step transition bloom
//! whose state would require an unbounded replay is refused outright, so a
//! manifestation can never add unbounded latency to a read (Phase 18).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
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

    /// A one-bit mask for this path, so per-object failure/measurement sets are a
    /// single atomic byte rather than a hash set on the read path.
    const fn bit(self) -> u8 {
        match self {
            ReadPathKind::LogicalExtent => 1 << 0,
            ReadPathKind::PathBloom => 1 << 1,
            ReadPathKind::TransitionBloom => 1 << 2,
            ReadPathKind::History => 1 << 3,
            ReadPathKind::Checkpoint => 1 << 4,
            ReadPathKind::Overlay => 1 << 5,
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
    /// The number of distinct size classes (the width of a per-class index).
    pub const COUNT: usize = 5;

    /// The dense index of this class in `0..COUNT`.
    pub const fn index(self) -> usize {
        match self {
            SizeClass::Empty => 0,
            SizeClass::Byte => 1,
            SizeClass::Small => 2,
            SizeClass::Medium => 3,
            SizeClass::Large => 4,
        }
    }

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
    /// Why the authoritative path was used, when it was. A `'static` reason is
    /// borrowed (the hot fallback path allocates nothing for it); only a
    /// dynamically built reason owns a string.
    pub fallback_reason: Option<Cow<'static, str>>,
}

impl PlannedRead {
    /// Construct an authoritative-path result. Public within the crate so the
    /// namespace can report the fallback path.
    pub(crate) fn fallback(bytes: Vec<u8>, reason: Option<String>) -> PlannedRead {
        PlannedRead::authoritative(bytes, reason.map(Cow::Owned))
    }

    /// Construct an authoritative-path result with a `'static` reason, which is
    /// borrowed rather than allocated.
    fn fallback_static(bytes: Vec<u8>, reason: Option<&'static str>) -> PlannedRead {
        PlannedRead::authoritative(bytes, reason.map(Cow::Borrowed))
    }

    fn authoritative(bytes: Vec<u8>, reason: Option<Cow<'static, str>>) -> PlannedRead {
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
    /// Maximum number of identity-keyed overlay/verification entries retained by
    /// the planner's [`IdentityLedger`] before the least-recently-inserted are
    /// retired. Together with `cache_capacity` this bounds all identity-keyed
    /// planner state.
    pub identity_capacity: usize,
}

impl Default for ReadPlannerConfig {
    fn default() -> ReadPlannerConfig {
        ReadPlannerConfig {
            max_payload_bytes: 512 * 1024 * 1024,
            cache_capacity: 64,
            calibration_budget_ns: 2_000_000,
            identity_capacity: 1024,
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

    /// The measured EWMA for `(kind, class)`, or `None` while no sample exists. The
    /// prior is not a measurement and must never be treated as one (the selection
    /// guarantee is that an unmeasured candidate is never selected).
    fn measured(&self, kind: ReadPathKind, class: SizeClass) -> Option<f64> {
        self.costs.get(&(kind, class)).map(|c| c.ns)
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

/// A bounded, per-object set of measured costs used for **selection**.
///
/// Selection predicts a read from the queried object's own measurements when it
/// has any, and only falls back to the shared aggregate when it does not. Two
/// objects with different access characteristics (for example a hot small-file
/// workload and a cold large-file workload that happen to share a size class)
/// therefore cannot bias each other's choice. The table is **bounded** and retires
/// the least-recently-*inserted* object once full (age eviction), so a long-lived
/// planner over many objects stays cheap. `predict` is a pure lookup that never
/// mutates the table, so it is safe to call while holding a shared lock (and is
/// never called from inside a sort comparator).
struct ObjectCosts {
    map: HashMap<ManifestIdentity, CostModel>,
    order: VecDeque<ManifestIdentity>,
    capacity: usize,
}

impl ObjectCosts {
    fn new(capacity: usize) -> ObjectCosts {
        ObjectCosts {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// The object's own measured cost for `(kind, class)`; `None` when the object
    /// has no such measurement (so the caller falls back to the shared aggregate).
    /// A pure read: it never updates recency, so callers may hold a shared lock.
    fn predict(&self, id: &ManifestIdentity, kind: ReadPathKind, class: SizeClass) -> Option<f64> {
        self.map.get(id).and_then(|m| m.measured(kind, class))
    }

    fn record(&mut self, id: ManifestIdentity, kind: ReadPathKind, class: SizeClass, ns: f64) {
        if self.capacity == 0 {
            return;
        }
        if !self.map.contains_key(&id) {
            // Age eviction: retire least-recently-inserted identities until there
            // is room. Inserting an already-present identity never reorders, so
            // this stays O(1) amortized (no linear `position` search).
            while self.order.len() >= self.capacity {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
            self.order.push_back(id);
            self.map.insert(id, CostModel::default());
        }
        if let Some(model) = self.map.get_mut(&id) {
            model.record(kind, class, ns);
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

/// The selection cost model: a shared aggregate plus a bounded per-object table.
///
/// Every measurement is recorded in the shared aggregate (which still backs the
/// performance-evidence surface), but *selection* consults the object-local table
/// first, so an object's own measurements decide its reads and unrelated objects
/// cannot cross-contaminate the choice.
struct SelectionModel {
    aggregate: CostModel,
    objects: ObjectCosts,
}

impl SelectionModel {
    fn new(object_capacity: usize) -> SelectionModel {
        SelectionModel {
            aggregate: CostModel::default(),
            objects: ObjectCosts::new(object_capacity),
        }
    }

    /// The predicted cost for one object's candidate. Uses the object's own
    /// measurement when it has one, else the shared aggregate (which itself falls
    /// back to the documented prior).
    fn predict(&self, id: &ManifestIdentity, kind: ReadPathKind, class: SizeClass) -> f64 {
        match self.objects.predict(id, kind, class) {
            Some(ns) => ns,
            None => self.aggregate.predict(kind, class),
        }
    }

    fn record(&mut self, id: ManifestIdentity, kind: ReadPathKind, class: SizeClass, ns: f64) {
        self.aggregate.record(kind, class, ns);
        self.objects.record(id, kind, class, ns);
    }

    fn measurements(&self) -> Vec<PathMeasurement> {
        self.aggregate.measurements()
    }

    fn clear(&mut self) {
        self.aggregate.costs.clear();
        self.objects.clear();
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
    /// The precompiled read plan published with this body (Phase 43): the
    /// request-independent structure inventory plus the per-class selection
    /// rankings the steady-state read looks up. Bounded by the body cache's
    /// capacity, since a retired body retires its plan with it.
    plan: ObjectPlan,
}

/// The precompiled, per-object read plan.
///
/// Built **once** when a body is loaded (its identity, version, and manifestation
/// set are then determined) and published inside the cached [`LoadedBody`]. The
/// steady-state read path performs no allocation and no sorting over it: it
/// classifies the request length, looks up the [`SizeClass`]'s published ranking,
/// and executes the first candidate that covers the request. All request-dependent
/// coverage checks ([`step_available`]) are cheap comparisons.
struct ObjectPlan {
    /// The certified, structurally-present, request-independent candidates. The
    /// authoritative extent is implicit and always appended by the planner.
    inventory: Vec<Candidate>,
    /// Per-size-class bitmask (see [`ReadPathKind::bit`]) of candidates already
    /// timed for this identity and class.
    measured: [AtomicU8; SizeClass::COUNT],
    /// Bitmask of candidates proven unusable for this identity.
    failed: AtomicU8,
    /// The published per-class ranking: the measured candidates, cheapest first.
    /// `None` until that class has been calibrated. An immutable `Arc`, so the hot
    /// path clones it under a shared lock and never mutates shared state.
    ranking: [RwLock<Option<Arc<Vec<Candidate>>>>; SizeClass::COUNT],
}

impl ObjectPlan {
    fn new(inventory: Vec<Candidate>) -> ObjectPlan {
        ObjectPlan {
            inventory,
            measured: std::array::from_fn(|_| AtomicU8::new(0)),
            failed: AtomicU8::new(0),
            ranking: std::array::from_fn(|_| RwLock::new(None)),
        }
    }

    fn is_failed(&self, kind: ReadPathKind) -> bool {
        self.failed.load(Ordering::Relaxed) & kind.bit() != 0
    }

    fn mark_failed(&self, kind: ReadPathKind) {
        self.failed.fetch_or(kind.bit(), Ordering::Relaxed);
    }

    fn measured_mask(&self, class: SizeClass) -> u8 {
        self.measured[class.index()].load(Ordering::Relaxed)
    }

    fn mark_measured(&self, class: SizeClass, kind: ReadPathKind) {
        self.measured[class.index()].fetch_or(kind.bit(), Ordering::Relaxed);
    }

    /// The published ranking for `class`, if that class has been calibrated.
    fn ranked(&self, class: SizeClass) -> Option<Arc<Vec<Candidate>>> {
        self.ranking[class.index()].read().clone()
    }

    fn publish_ranking(&self, class: SizeClass, ranking: Arc<Vec<Candidate>>) {
        *self.ranking[class.index()].write() = Some(ranking);
    }
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

    fn len(&self) -> usize {
        self.map.len()
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

/// A bounded, insertion-ordered set keyed by [`ManifestIdentity`].
///
/// This is the retirement policy for the planner's identity-keyed bookkeeping:
/// once `capacity` entries are resident, the least-recently-**inserted** are
/// retired (age eviction), so driving an unbounded number of distinct
/// manifestations/generations through the planner cannot grow its state without
/// bound. Retiring an entry only ever turns a *verified* identity back into an
/// *unverified* one, which re-verifies on next use; it can never cause a wrong
/// selection.
#[derive(Default)]
struct BoundedIdentitySet {
    set: HashSet<ManifestIdentity>,
    order: VecDeque<ManifestIdentity>,
    capacity: usize,
}

impl BoundedIdentitySet {
    fn new(capacity: usize) -> BoundedIdentitySet {
        BoundedIdentitySet {
            set: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn insert(&mut self, id: ManifestIdentity) {
        if self.capacity == 0 || self.set.contains(&id) {
            return;
        }
        self.set.insert(id);
        self.order.push_back(id);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
    }

    fn contains(&self, id: &ManifestIdentity) -> bool {
        self.set.contains(id)
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn clear(&mut self) {
        self.set.clear();
        self.order.clear();
    }
}

/// The bounded, identity-keyed ledger for region-overlay state (Phase 22): which
/// identities' overlay bytes have been verified against the authoritative read,
/// and which were proven unusable. Bounded by
/// [`ReadPlannerConfig::identity_capacity`]; see [`BoundedIdentitySet`].
#[derive(Default)]
struct IdentityLedger {
    overlay_verified: BoundedIdentitySet,
    overlay_failed: BoundedIdentitySet,
}

impl IdentityLedger {
    fn new(capacity: usize) -> IdentityLedger {
        IdentityLedger {
            overlay_verified: BoundedIdentitySet::new(capacity),
            overlay_failed: BoundedIdentitySet::new(capacity),
        }
    }

    fn clear(&mut self) {
        self.overlay_verified.clear();
        self.overlay_failed.clear();
    }
}

/// A bounded, insertion-ordered cache of resolved region tables, one per inode
/// (Phase 22). Retires least-recently-inserted inodes once full, so a long-lived
/// planner over many region-backed objects stays bounded.
#[derive(Default)]
struct CoverageCache {
    map: HashMap<u64, CoverageEntry>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl CoverageCache {
    fn get(
        &self,
        inode: u64,
        generation: u64,
        digest: &[u8; 32],
    ) -> Option<Arc<Vec<ManifestRegion>>> {
        let e = self.map.get(&inode)?;
        if e.generation == generation && e.digest == *digest {
            Some(e.table.clone())
        } else {
            None
        }
    }

    fn insert(&mut self, inode: u64, entry: CoverageEntry) {
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

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

/// Cumulative counters for the read planner, used by the lean-read court to
/// prove the steady state performs no planning work. All are monotonic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadPlannerStats {
    /// Number of per-object read plans built (once per body load).
    pub plan_builds: u64,
    /// Number of calibration passes that timed at least one candidate.
    pub calibrations: u64,
    /// Number of candidate rankings sorted (calibration only).
    pub selection_sorts: u64,
    /// Number of times the selection cost model's write lock was acquired.
    pub model_write_locks: u64,
    /// Number of reads served from a published ranking without planning work.
    pub hot_reads: u64,
}

#[derive(Default)]
struct StatsInner {
    plan_builds: AtomicU64,
    calibrations: AtomicU64,
    selection_sorts: AtomicU64,
    model_write_locks: AtomicU64,
    hot_reads: AtomicU64,
}

/// The resident (in-memory) planner state, with the capacity that bounds it. Used
/// by the aging court (`tests/read_path_planner.rs`) to measure the bound.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlannerResidency {
    /// Cached bodies resident (each carries one [`ObjectPlan`]).
    pub body_plans: usize,
    /// Per-object selection models resident.
    pub object_models: usize,
    /// Verified-overlay identities resident.
    pub overlay_verified: usize,
    /// Rejected-overlay identities resident.
    pub overlay_failed: usize,
    /// The body-cache capacity.
    pub body_capacity: usize,
    /// The per-object-model capacity.
    pub object_capacity: usize,
    /// The identity-ledger capacity.
    pub identity_capacity: usize,
}

impl PlannerResidency {
    /// The total number of identity-keyed entries resident across every bounded
    /// table.
    pub fn total(&self) -> usize {
        self.body_plans + self.object_models + self.overlay_verified + self.overlay_failed
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

/// Enumerate the **request-independent** certified structures present in a loaded
/// body. This is the object's read-plan inventory, built once per body load. It
/// deliberately excludes the authoritative extent (which the planner always
/// appends) and defers every request-dependent coverage decision to
/// [`step_available`].
fn build_inventory(
    body: &EkbloomBody,
    report: &VerificationReport,
    path_blooms: &[Option<PathBloom>],
    global_blooms: &[Option<GlobalBloom>],
    region_tables: &[Option<RegionTable>],
) -> Vec<Candidate> {
    let mut out = Vec::new();

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

    for (i, cp) in body.checkpoints.iter().enumerate() {
        if cp.interval == 0 {
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

    for (i, shell) in body.blooms.iter().enumerate() {
        let name = format!("bloom[{i}]:{}", shell.kind.as_str());
        if !check_passed(report, &name) {
            continue;
        }
        match shell.kind {
            BloomKind::Path => {
                if shell.logical_len != body.logical_len || path_blooms[i].is_none() {
                    continue;
                }
                out.push(Candidate {
                    kind: ReadPathKind::PathBloom,
                    structure: Structure::Path { bloom_index: i },
                    certified: shell.status == Certification::Certified,
                });
            }
            BloomKind::Universal => {
                if global_blooms[i].is_none() {
                    continue;
                }
                out.push(Candidate {
                    kind: ReadPathKind::TransitionBloom,
                    structure: Structure::Global { bloom_index: i },
                    certified: shell.status == Certification::Certified,
                });
            }
            BloomKind::Regional => {
                if region_tables[i].is_none() {
                    continue;
                }
                out.push(Candidate {
                    kind: ReadPathKind::TransitionBloom,
                    structure: Structure::Regional { bloom_index: i },
                    certified: shell.status == Certification::Certified,
                });
            }
            BloomKind::Contextual => {}
        }
    }

    out
}

/// Whether `structure` can serve this exact request (a cheap, allocation-free
/// coverage check). This is the only request-dependent filter on the hot path.
fn step_available(lb: &LoadedBody, q: &ReadQuery, eff_len: u64, structure: Structure) -> bool {
    let end = q.offset.saturating_add(eff_len);
    match structure {
        Structure::Extent | Structure::History => true,
        Structure::Checkpoint { set_index } => {
            let cp = &lb.body.checkpoints[set_index];
            cp.interval != 0 && cp.restart_point(q.offset).is_some()
        }
        Structure::Path { bloom_index } => lb.path_blooms[bloom_index]
            .as_ref()
            .is_some_and(|b| b.logical_len >= end),
        Structure::Global { .. } => has_bounded_state_source(lb, q.offset),
        Structure::Regional { bloom_index } => {
            let covers = lb.region_tables[bloom_index].as_ref().is_some_and(|t| {
                q.offset >= t.logical_start
                    && q.offset < t.logical_start.saturating_add(t.logical_len)
            });
            covers && has_bounded_state_source(lb, q.offset)
        }
    }
}

/// Whether every candidate that could serve this request for `class` has already
/// been measured (or proven unusable). When this holds and a ranking is published,
/// the steady-state read is a pure lookup + execute.
fn plan_is_complete(lb: &LoadedBody, q: &ReadQuery, eff_len: u64, class: SizeClass) -> bool {
    let plan = &lb.plan;
    let mask = plan.measured_mask(class) | plan.failed.load(Ordering::Relaxed);
    if mask & ReadPathKind::LogicalExtent.bit() == 0 {
        return false;
    }
    for s in &plan.inventory {
        if !step_available(lb, q, eff_len, s.structure) {
            continue;
        }
        if mask & s.kind.bit() == 0 {
            return false;
        }
    }
    true
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

/// The authoritative extent read for one request, evaluated **at most once**.
///
/// Within a single request the planner may need the authoritative bytes from
/// several places: the ordinary extent candidate, verify-on-use of an uncertified
/// structure, and the ultimate fallback. Wrapping the caller's closure here makes
/// that a structural guarantee: a fallback never re-executes a read a calibration
/// pass already produced, the closure is never invoked redundantly, and the
/// authoritative bytes are moved out (not cloned) for the result when possible.
struct Authoritative<'a, F> {
    auth: &'a mut F,
    cached: Option<Vec<u8>>,
    memoize: bool,
}

impl<'a, F> Authoritative<'a, F>
where
    F: FnMut(u64, u64) -> Result<Vec<u8>>,
{
    /// A memoizing wrapper for a foreground read.
    fn new(auth: &'a mut F) -> Authoritative<'a, F> {
        Authoritative {
            auth,
            cached: None,
            memoize: true,
        }
    }

    /// A pass-through wrapper that never memoizes; used where each iteration must
    /// execute the read afresh (direct per-path measurement).
    fn uncached(auth: &'a mut F) -> Authoritative<'a, F> {
        Authoritative {
            auth,
            cached: None,
            memoize: false,
        }
    }

    /// The authoritative bytes for `(offset, length)`, computed at most once and
    /// thereafter served from the cached copy.
    fn fetch(&mut self, offset: u64, length: u64) -> Result<Vec<u8>> {
        if !self.memoize {
            return (self.auth)(offset, length);
        }
        if let Some(bytes) = &self.cached {
            return Ok(bytes.clone());
        }
        let bytes = (self.auth)(offset, length)?;
        self.cached = Some(bytes.clone());
        Ok(bytes)
    }

    /// The authoritative bytes for the request, moving a cached copy out without
    /// cloning when one exists; otherwise executing the read once.
    fn take(&mut self, offset: u64, length: u64) -> Result<Vec<u8>> {
        match self.cached.take() {
            Some(bytes) => Ok(bytes),
            None => (self.auth)(offset, length),
        }
    }
}

/// The read planner: evaluates compatible certified structures and picks a valid
/// path by measurement, falling back to the authoritative extent read.
///
/// All identity-keyed state is bounded (see the module header): per-object plans
/// live in the body cache, per-object selection models in [`ObjectCosts`], and the
/// region-overlay ledger in [`IdentityLedger`]. The steady-state read consults the
/// per-object [`ObjectPlan`] only.
pub struct ReadPlanner {
    state: Arc<ManifestationState>,
    config: ReadPlannerConfig,
    model: RwLock<SelectionModel>,
    cache: Mutex<BodyCache>,
    /// The bounded identity ledger for region-overlay verification/failure state.
    ledger: RwLock<IdentityLedger>,
    chosen: RwLock<HashMap<ReadPathKind, u64>>,
    /// Resolved region tables for overlay-backed generations (bounded).
    coverage: Mutex<CoverageCache>,
    /// Parsed region payload bodies, shared across generations (bounded).
    regions: Mutex<RegionCache>,
    /// Cumulative planning-work counters (see [`ReadPlannerStats`]).
    stats: StatsInner,
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
        let coverage = CoverageCache {
            capacity: config.identity_capacity.max(1),
            ..Default::default()
        };
        let object_capacity = config.cache_capacity.max(1);
        let identity_capacity = config.identity_capacity;
        ReadPlanner {
            state,
            config,
            model: RwLock::new(SelectionModel::new(object_capacity)),
            cache: Mutex::new(cache),
            ledger: RwLock::new(IdentityLedger::new(identity_capacity)),
            chosen: RwLock::new(HashMap::new()),
            coverage: Mutex::new(coverage),
            regions: Mutex::new(regions),
            stats: StatsInner::default(),
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

    /// The cumulative planning-work counters. A steady-state certified read must
    /// leave `selection_sorts` and `model_write_locks` unchanged while advancing
    /// `hot_reads`.
    pub fn stats(&self) -> ReadPlannerStats {
        ReadPlannerStats {
            plan_builds: self.stats.plan_builds.load(Ordering::Relaxed),
            calibrations: self.stats.calibrations.load(Ordering::Relaxed),
            selection_sorts: self.stats.selection_sorts.load(Ordering::Relaxed),
            model_write_locks: self.stats.model_write_locks.load(Ordering::Relaxed),
            hot_reads: self.stats.hot_reads.load(Ordering::Relaxed),
        }
    }

    /// The resident planner state, with the capacity that bounds it. Every field
    /// is bounded by construction; the aging court asserts it (Phase 43).
    pub fn resident(&self) -> PlannerResidency {
        let ledger = self.ledger.read();
        PlannerResidency {
            body_plans: self.cache.lock().len(),
            object_models: self.model.read().objects.len(),
            overlay_verified: ledger.overlay_verified.len(),
            overlay_failed: ledger.overlay_failed.len(),
            body_capacity: self.config.cache_capacity,
            object_capacity: self.config.cache_capacity.max(1),
            identity_capacity: self.config.identity_capacity,
        }
    }

    /// Feed one completed read observation for `identity` into the planner's
    /// bounded per-identity policy state. This is the **learner seam**: the
    /// steady-state read path never mutates shared policy, so observations of
    /// completed reads can be folded in through here — from any thread and,
    /// because it is off the read path, without blocking readers on the foreground
    /// choice. Every table it touches is bounded, so driving an unbounded number of
    /// distinct identities through it cannot grow planner state (the aging court in
    /// `tests/read_path_planner.rs` does exactly that).
    pub fn record_observation(
        &self,
        identity: ManifestIdentity,
        class: SizeClass,
        kind: ReadPathKind,
        ns: f64,
    ) {
        {
            let mut model = self.model.write();
            self.stats.model_write_locks.fetch_add(1, Ordering::Relaxed);
            model.record(identity, kind, class, ns);
        }
        self.ledger.write().overlay_verified.insert(identity);
    }

    /// Forget the measured model, published plans (via the body cache), failure
    /// state, and cumulative counters (used by evidence runs that must observe a
    /// cold planner).
    pub fn reset(&self) {
        self.model.write().clear();
        self.ledger.write().clear();
        self.chosen.write().clear();
        self.coverage.lock().clear();
        self.region_cache_clear();
        self.stats.plan_builds.store(0, Ordering::Relaxed);
        self.stats.calibrations.store(0, Ordering::Relaxed);
        self.stats.selection_sorts.store(0, Ordering::Relaxed);
        self.stats.model_write_locks.store(0, Ordering::Relaxed);
        self.stats.hot_reads.store(0, Ordering::Relaxed);
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
        // Direct measurement must execute the read on every iteration, so this
        // wrapper is a pass-through that never memoizes.
        let mut auth = Authoritative::uncached(auth);
        for c in &cands {
            let mut samples: Vec<u128> = Vec::with_capacity(rounds as usize);
            for _ in 0..rounds {
                let started = Instant::now();
                if self.execute(c, &loaded, q, eff_len, &mut auth).is_ok() {
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
        // The authoritative read is executed at most once for this request, no
        // matter how many candidates or fallbacks consult it.
        let mut auth = Authoritative::new(&mut auth);
        let eff_len = q.logical_len.saturating_sub(q.offset).min(q.length);
        if eff_len == 0 {
            return Ok(PlannedRead::fallback(auth.take(q.offset, q.length)?, None));
        }

        // --- compatibility + version/root qualification on EVERY read ---
        let manifest = match self.state.latest_for(q.inode) {
            Some(m) => m,
            None => {
                return Ok(PlannedRead::fallback_static(
                    auth.take(q.offset, q.length)?,
                    Some("no manifested generation"),
                ))
            }
        };
        if let Err(e) = manifest.usable_for(q.inode, q.inode_version, q.root) {
            return Ok(PlannedRead::fallback(
                auth.take(q.offset, q.length)?,
                Some(e.to_string()),
            ));
        }
        if manifest.ekbloom_version != EKBLOOM_VERSION {
            return Ok(PlannedRead::fallback(
                auth.take(q.offset, q.length)?,
                Some(format!(
                    "ekbloom engine {} does not match {}",
                    manifest.ekbloom_version, EKBLOOM_VERSION
                )),
            ));
        }
        if manifest.logical_start != 0 || manifest.logical_end != q.logical_len {
            return Ok(PlannedRead::fallback_static(
                auth.take(q.offset, q.length)?,
                Some("manifested structure does not cover the logical extent"),
            ));
        }

        // --- incremental generational overlay (Phase 22) ---
        // A region-backed generation (overlay or flattened table) has no single
        // top-level body; it is resolved through its bounded region indirection,
        // reusing unchanged committed content from its base.
        if manifest.is_region_backed() {
            return self.read_region_backed(&manifest, q, eff_len, &mut auth);
        }
        // A profile EKBLOOM documents as non-accelerating is not loaded at all:
        // loading + verifying it cannot change the bytes and would only add
        // unbounded foreground work (Phase 18).
        if !profile_can_accelerate(manifest.profile_kind) {
            return Ok(PlannedRead::fallback(
                auth.take(q.offset, q.length)?,
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
                    auth.take(q.offset, q.length)?,
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
            return Ok(PlannedRead::fallback_static(
                auth.take(q.offset, q.length)?,
                Some("loaded structure identity does not match the request"),
            ));
        }

        let identity = ManifestIdentity::of(&manifest);
        let class = classify_length(eff_len);

        // --- steady state: a bounded lookup + execute --------------------------
        // Once every candidate that can serve this request has been measured for
        // the exact identity and size class, the published ranking is the whole
        // decision: classify the length, walk the ranking, execute the first
        // candidate that covers the request. No candidate vector is built, nothing
        // is sorted, and the cost model is not consulted (so no model lock is
        // taken). The ranking holds only measured candidates, so an unmeasured path
        // can never be selected.
        let mut produced: HashMap<ReadPathKind, (Vec<u8>, bool)> = HashMap::new();
        if plan_is_complete(&loaded, q, eff_len, class) {
            if let Some(ranked) = loaded.plan.ranked(class) {
                self.stats.hot_reads.fetch_add(1, Ordering::Relaxed);
                return self.serve_ranked(
                    &ranked,
                    &loaded,
                    q,
                    eff_len,
                    &manifest,
                    &mut auth,
                    &mut produced,
                );
            }
        }

        // --- first (or still-incomplete) read for this identity+class ----------
        // Calibrate the not-yet-timed candidates under the bounded budget, then
        // serve from the published ranking.
        self.calibrate_class(
            identity,
            &loaded,
            q,
            eff_len,
            class,
            &mut auth,
            &mut produced,
        );
        if let Some(ranked) = loaded.plan.ranked(class) {
            return self.serve_ranked(
                &ranked,
                &loaded,
                q,
                eff_len,
                &manifest,
                &mut auth,
                &mut produced,
            );
        }
        Ok(PlannedRead::fallback_static(
            auth.take(q.offset, q.length)?,
            Some("no calibrated candidate for this object yet"),
        ))
    }

    /// Calibrate `class` for `identity` under the bounded budget, record the
    /// timings into the object-local model, and publish the class's ranking.
    ///
    /// Only candidates that can serve this request and have not already been
    /// measured are timed, authoritative first, and the pass stops as soon as the
    /// budget is exhausted — so a foreground read is never stalled to calibrate
    /// (Phase 18). Successful bytes are retained in `produced` so the candidate the
    /// ranking then serves is not executed a second time. This is the **only**
    /// point on the read path that writes the measured model or sorts a ranking;
    /// the steady state never reaches it.
    #[allow(clippy::too_many_arguments)]
    fn calibrate_class<F>(
        &self,
        identity: ManifestIdentity,
        lb: &LoadedBody,
        q: &ReadQuery,
        eff_len: u64,
        class: SizeClass,
        auth: &mut Authoritative<'_, F>,
        produced: &mut HashMap<ReadPathKind, (Vec<u8>, bool)>,
    ) where
        F: FnMut(u64, u64) -> Result<Vec<u8>>,
    {
        let budget = self.config.calibration_budget_ns;
        if budget > 0 {
            let mask = lb.plan.measured_mask(class);
            let mut pending: Vec<Candidate> = lb
                .plan
                .inventory
                .iter()
                .copied()
                .filter(|c| !lb.plan.is_failed(c.kind))
                .filter(|c| step_available(lb, q, eff_len, c.structure))
                .filter(|c| mask & c.kind.bit() == 0)
                .collect();
            if mask & ReadPathKind::LogicalExtent.bit() == 0 {
                pending.push(Candidate {
                    kind: ReadPathKind::LogicalExtent,
                    structure: Structure::Extent,
                    certified: true,
                });
            }
            // The authoritative read is timed first, so a correct baseline always
            // exists even if the budget then stops the pass.
            pending.sort_by_key(|c| u8::from(c.kind != ReadPathKind::LogicalExtent));
            let started = Instant::now();
            let mut timed: Vec<(Candidate, f64, Vec<u8>)> = Vec::new();
            for c in &pending {
                if started.elapsed().as_nanos() as u64 > budget {
                    break;
                }
                let t = Instant::now();
                match self.execute(c, lb, q, eff_len, auth) {
                    Ok(bytes) => timed.push((*c, t.elapsed().as_nanos() as f64, bytes)),
                    Err(_) => {
                        // A structure that cannot serve this object is barred for
                        // this identity; a read never retries it blindly.
                        lb.plan.mark_failed(c.kind);
                    }
                }
            }
            if !timed.is_empty() {
                {
                    // One acquisition of the model lock for the whole pass.
                    let mut model = self.model.write();
                    self.stats.model_write_locks.fetch_add(1, Ordering::Relaxed);
                    for (c, ns, _) in &timed {
                        model.record(identity, c.kind, class, *ns);
                    }
                }
                self.stats.calibrations.fetch_add(1, Ordering::Relaxed);
                for (c, _, bytes) in timed {
                    lb.plan.mark_measured(class, c.kind);
                    produced.insert(c.kind, (bytes, c.certified));
                }
            }
        }

        // Publish the ranking from every kind measured for this class. An empty
        // measured set leaves the ranking unpublished, so the caller falls back to
        // the authoritative path (an unmeasured candidate is never selected).
        let mask = lb.plan.measured_mask(class);
        if mask != 0 {
            let ranked = self.rank_measured(identity, lb, class, mask);
            self.stats.selection_sorts.fetch_add(1, Ordering::Relaxed);
            lb.plan.publish_ranking(class, Arc::new(ranked));
        }
    }

    /// Order every candidate measured for `class` cheapest-first, from a single
    /// snapshot of the object-local model. The snapshot is taken under a shared
    /// lock and dropped before sorting, so no lock is held inside the comparator
    /// and `ObjectCosts::predict` is a pure lookup (Phase 43).
    fn rank_measured(
        &self,
        identity: ManifestIdentity,
        lb: &LoadedBody,
        class: SizeClass,
        mask: u8,
    ) -> Vec<Candidate> {
        let mut steps: Vec<Candidate> = lb
            .plan
            .inventory
            .iter()
            .copied()
            .filter(|c| mask & c.kind.bit() != 0)
            .collect();
        if mask & ReadPathKind::LogicalExtent.bit() != 0 {
            steps.push(Candidate {
                kind: ReadPathKind::LogicalExtent,
                structure: Structure::Extent,
                certified: true,
            });
        }
        let costs: Vec<f64> = {
            let model = self.model.read();
            steps
                .iter()
                .map(|c| model.predict(&identity, c.kind, class))
                .collect()
        };
        let mut order: Vec<usize> = (0..steps.len()).collect();
        order.sort_by(|&i, &j| {
            costs[i]
                .partial_cmp(&costs[j])
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| steps[j].certified.cmp(&steps[i].certified))
                .then_with(|| steps[i].kind.priority().cmp(&steps[j].kind.priority()))
        });
        order.into_iter().map(|i| steps[i]).collect()
    }

    /// Execute the ranked candidates for a request, cheapest first, skipping any
    /// the object has barred or that cannot cover the request, and reusing the
    /// bytes a calibration pass already produced. Any miss falls through to the
    /// authoritative path, so a manifested structure can never change the bytes.
    #[allow(clippy::too_many_arguments)]
    fn serve_ranked<F>(
        &self,
        ranked: &[Candidate],
        lb: &LoadedBody,
        q: &ReadQuery,
        eff_len: u64,
        manifest: &GenerationManifest,
        auth: &mut Authoritative<'_, F>,
        produced: &mut HashMap<ReadPathKind, (Vec<u8>, bool)>,
    ) -> Result<PlannedRead>
    where
        F: FnMut(u64, u64) -> Result<Vec<u8>>,
    {
        let mut last_err: Option<OrfsError> = None;
        for c in ranked {
            if lb.plan.is_failed(c.kind) || !step_available(lb, q, eff_len, c.structure) {
                continue;
            }
            let result = match produced.remove(&c.kind) {
                Some((bytes, certified)) => {
                    debug_assert_eq!(certified, c.certified);
                    Ok(bytes)
                }
                None => self.execute(c, lb, q, eff_len, auth),
            };
            match result {
                Ok(bytes) => {
                    // Only allocate a reason when it is actually propagated: a
                    // manifested candidate carries none, and the authoritative
                    // path carries one only if a manifested candidate failed first.
                    let reason = if c.kind == ReadPathKind::LogicalExtent {
                        last_err.as_ref().map(|e| Cow::Owned(e.to_string()))
                    } else {
                        None
                    };
                    return Ok(self.serve(
                        bytes,
                        c.kind,
                        lb.generation,
                        manifest,
                        c.certified,
                        reason,
                    ));
                }
                Err(e) => {
                    lb.plan.mark_failed(c.kind);
                    last_err = Some(e);
                }
            }
        }
        Ok(PlannedRead::fallback(
            auth.take(q.offset, q.length)?,
            Some(
                last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no candidate path produced bytes".to_string()),
            ),
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
        reason: Option<Cow<'static, str>>,
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
        auth: &mut Authoritative<'_, F>,
    ) -> Result<Vec<u8>>
    where
        F: FnMut(u64, u64) -> Result<Vec<u8>>,
    {
        let direct = match c.structure {
            Structure::Extent => auth.fetch(q.offset, q.length)?,
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
        let authoritative = auth.fetch(q.offset, q.length)?;
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
        auth: &mut Authoritative<'_, F>,
    ) -> Result<PlannedRead>
    where
        F: FnMut(u64, u64) -> Result<Vec<u8>>,
    {
        let identity = ManifestIdentity::of(manifest);
        if self.ledger.read().overlay_failed.contains(&identity) {
            return Ok(PlannedRead::fallback_static(
                auth.take(q.offset, q.length)?,
                Some("incremental overlay previously rejected for this version"),
            ));
        }
        let bytes = match self.overlay_bytes(manifest, q.offset, q.offset + eff_len) {
            Ok(b) => b,
            Err(e) => {
                return Ok(PlannedRead::fallback(
                    auth.take(q.offset, q.length)?,
                    Some(e.to_string()),
                ))
            }
        };
        if bytes.len() as u64 != eff_len {
            return Ok(PlannedRead::fallback_static(
                auth.take(q.offset, q.length)?,
                Some("incremental overlay returned the wrong length"),
            ));
        }
        let already = self.ledger.read().overlay_verified.contains(&identity);
        if !already {
            let authoritative = auth.take(q.offset, q.length)?;
            if authoritative != bytes {
                self.ledger.write().overlay_failed.insert(identity);
                return Ok(PlannedRead::fallback_static(
                    authoritative,
                    Some("incremental overlay disagreed with the authoritative read"),
                ));
            }
            self.ledger.write().overlay_verified.insert(identity);
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
        if let Some(table) = self.coverage.lock().get(
            manifest.inode,
            manifest.generation,
            &manifest.manifest_blake3,
        ) {
            return Ok(table);
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
        let path_blooms: Vec<Option<PathBloom>> = body
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
        let global_blooms: Vec<Option<GlobalBloom>> = body
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
        let region_tables: Vec<Option<RegionTable>> = body
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
        // Publish the precompiled, request-independent read plan with the body.
        let plan = ObjectPlan::new(build_inventory(
            &body,
            &report,
            &path_blooms,
            &global_blooms,
            &region_tables,
        ));
        self.stats.plan_builds.fetch_add(1, Ordering::Relaxed);
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
            plan,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

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

    /// Phase 34 — the authoritative read is executed **at most once** per request.
    /// The memoizing wrapper serves a cached copy on later consults (both for
    /// verification and for the ultimate fallback), so a fallback never re-runs a
    /// read a calibration pass already produced.
    #[test]
    fn authoritative_read_is_executed_at_most_once() {
        let calls = Cell::new(0u32);
        let mut closure = |off: u64, len: u64| -> Result<Vec<u8>> {
            calls.set(calls.get() + 1);
            Ok(vec![off as u8, len as u8])
        };
        let mut auth = Authoritative::new(&mut closure);
        assert_eq!(auth.fetch(3, 7).unwrap(), vec![3, 7]);
        assert_eq!(
            auth.fetch(3, 7).unwrap(),
            vec![3, 7],
            "a repeated consult must be served from the cache"
        );
        assert_eq!(
            auth.take(3, 7).unwrap(),
            vec![3, 7],
            "the cached copy is moved out, not cloned"
        );
        assert_eq!(
            calls.get(),
            1,
            "the authoritative read ran more than once for one request"
        );
        // Once the cache is drained, the next consult executes exactly once more.
        assert_eq!(auth.fetch(3, 7).unwrap(), vec![3, 7]);
        assert_eq!(calls.get(), 2);
    }

    /// The pass-through wrapper used by direct per-path measurement must **not**
    /// memoize: each timed iteration has to execute the read afresh.
    #[test]
    fn uncached_authoritative_read_always_executes() {
        let calls = Cell::new(0u32);
        let mut closure = |off: u64, len: u64| -> Result<Vec<u8>> {
            calls.set(calls.get() + 1);
            Ok(vec![off as u8, len as u8])
        };
        let mut auth = Authoritative::uncached(&mut closure);
        assert_eq!(auth.fetch(1, 1).unwrap(), vec![1, 1]);
        assert_eq!(auth.fetch(1, 1).unwrap(), vec![1, 1]);
        assert_eq!(
            calls.get(),
            2,
            "an uncached wrapper must re-execute every time"
        );
    }

    /// Phase 34 — selection is **object-localized**: an object's own measurements
    /// decide its choice, and an object that has none falls back to the shared
    /// aggregate rather than inheriting another object's private cost.
    #[test]
    fn object_localized_prediction_is_isolated_per_identity() {
        let a = identity(1, 100, 1, 10, 1);
        let b = identity(1, 200, 1, 20, 1);
        let c = identity(1, 300, 1, 30, 1); // never measured

        let mut model = SelectionModel::new(8);
        model.record(a, ReadPathKind::History, SizeClass::Small, 10.0);
        model.record(b, ReadPathKind::History, SizeClass::Small, 1_000.0);

        assert_eq!(
            model.predict(&a, ReadPathKind::History, SizeClass::Small),
            10.0
        );
        assert_eq!(
            model.predict(&b, ReadPathKind::History, SizeClass::Small),
            1_000.0
        );
        // The unmeasured object uses the shared aggregate (its EWMA over both
        // recordings), never either object's private cost.
        let aggregate = 0.3 * 1_000.0 + 0.7 * 10.0;
        let predicted = model.predict(&c, ReadPathKind::History, SizeClass::Small);
        assert!(
            (predicted - aggregate).abs() < 1e-9,
            "an unmeasured object must use the shared aggregate: {predicted} vs {aggregate}"
        );
        assert!(
            predicted > 10.0 && predicted < 1_000.0,
            "the shared aggregate must not equal either object's private measurement"
        );
    }

    /// The per-object table is bounded and retires the least-recently-*inserted*
    /// identity once full (age eviction), so a planner over many objects cannot
    /// grow without bound. `predict` is a pure lookup that never reorders.
    #[test]
    fn object_costs_are_bounded_and_retire_in_insertion_order() {
        let mut model = SelectionModel::new(2);
        let a = identity(1, 1, 1, 1, 1);
        let b = identity(1, 2, 1, 1, 1);
        let c = identity(1, 3, 1, 1, 1);
        model.record(a, ReadPathKind::History, SizeClass::Small, 1.0);
        model.record(b, ReadPathKind::History, SizeClass::Small, 2.0);
        assert_eq!(model.objects.len(), 2);
        // A third distinct identity retires the oldest (`a`); the table stays at
        // its capacity now and forever.
        model.record(c, ReadPathKind::History, SizeClass::Small, 3.0);
        assert_eq!(model.objects.len(), 2);
        assert_eq!(
            model.predict(&c, ReadPathKind::History, SizeClass::Small),
            3.0
        );
        assert_eq!(
            model.predict(&b, ReadPathKind::History, SizeClass::Small),
            2.0
        );
        // `a` was retired: predicting it now uses the shared aggregate, not its
        // own 1.0 ns measurement.
        let aggregate = 0.3 * 3.0 + 0.7 * (0.3 * 2.0 + 0.7 * 1.0);
        let retired = model.predict(&a, ReadPathKind::History, SizeClass::Small);
        assert!(
            (retired - aggregate).abs() < 1e-9,
            "the retired object must fall back to the aggregate: {retired} vs {aggregate}"
        );
        assert_ne!(retired, 1.0, "the retired object kept stale private state");
    }

    /// The bounded identity ledger retires least-recently-inserted identities once
    /// full, so driving many distinct identities through it stays bounded, and a
    /// retirement only turns a *verified* identity back into an *unverified* one.
    #[test]
    fn bounded_identity_set_retires_in_insertion_order() {
        let a = identity(1, 1, 1, 1, 1);
        let b = identity(1, 2, 1, 1, 1);
        let c = identity(1, 3, 1, 1, 1);
        let mut set = BoundedIdentitySet::new(2);
        set.insert(a);
        set.insert(b);
        set.insert(c);
        assert_eq!(set.len(), 2, "the ledger must stay at its capacity");
        assert!(!set.contains(&a), "the oldest identity must be retired");
        assert!(set.contains(&b) && set.contains(&c));
        // Re-inserting a resident identity is a no-op (no reordering, O(1)).
        set.insert(b);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&b));
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

    /// Phase 18 — planner bookkeeping must be keyed by the **full** manifestation
    /// identity, never by a generation number alone: a rejected/failed candidate
    /// for one object must not suppress the same candidate for an unrelated object,
    /// and calibration must not leak across objects. This test uses two identities
    /// that share a generation number and differ only in inode/root/version —
    /// exactly the collision an object-keyed-by-generation design would conflate.
    #[test]
    fn identity_keyed_bookkeeping_is_isolated_per_full_identity() {
        let a = identity(1, 100, 3, 500, 7);
        let b = identity(1, 200, 3, 500, 7); // same generation, different inode
        let c = identity(1, 100, 4, 500, 7); // same generation, different version
        let d = identity(1, 100, 3, 501, 7); // same generation, different root
        let e = identity(2, 100, 3, 500, 7); // same generation, different volume

        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);

        let mut set = BoundedIdentitySet::new(8);
        set.insert(a);
        assert!(set.contains(&a));
        for other in [b, c, d, e] {
            assert!(
                !set.contains(&other),
                "an entry for one object leaked onto {other:?}"
            );
        }
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
