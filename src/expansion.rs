//! The autonomous **concealed-expansion controller** (reviewer research §12).
//!
//! Research §12 asks the largest remaining question: rather than manifesting
//! structures by a fixed policy, can OrFS **observe** a read workload, **predict**
//! which additional manifested structure would most reduce work, **construct** it,
//! **verify** it, and publish a read decision — while never becoming
//! authoritative? The formal objective is
//!
//! ```text
//!   min_M   Σ_q w_q · T(q, M)      subject to   PhysicalBytes(M) ≤ B,
//!   Read(q, M) = Read_authority(q),
//!   (and the root / committed-history invariants)
//! ```
//!
//! # What this module is, and what it deliberately is not
//!
//! This module is a **bounded, honest first version**. It decides, per object and
//! under a manifested-space budget `B`, whether to build *no structure* or the
//! existing **direct-page atlas** (Phase 64, `Namespace::manifest_direct_page_atlas`)
//! — which today must ride an EKBLOOM generation, so the chosen "atlas program"
//! also constructs that prerequisite generation. It is a greedy knapsack over the
//! observed objects.
//!
//! Three separations keep the controller safe by construction:
//!
//! 1. **The prediction is pure and is never authoritative.** [`ExpansionController::plan`]
//!    is a pure function of *(observed workload, recorded costs, byte model)*. It
//!    estimates a per-object benefit from [`prior_cost_ns`](crate::readpath::prior_cost_ns)
//!    (the planner's own documented prior) or from **previously recorded** planner
//!    measurements ([`ExpansionCosts::record_measurements`]); it never reads
//!    committed history and never changes it. A wrong prediction can only waste
//!    bytes — it cannot change a byte a read returns.
//! 2. **Construction is off any read's critical path.** [`execute_plan`] builds
//!    the chosen programs between read phases, best-effort: a construction that
//!    fails is recorded and skipped. No read ever waits for the controller.
//! 3. **Selection remains the planner's, and it is measured.** After construction
//!    the ordinary [`ReadPlanner`](crate::readpath::ReadPlanner) owns every read:
//!    an unmeasured candidate is never selected, every manifested read is
//!    verified byte-identical to the authoritative read, and a structure that is
//!    absent, stale, tampered, non-verifying, or simply measured slower is ignored
//!    — the read falls back to the authoritative extent path. This module never
//!    weakens that invariant; it only decides *which* structures exist to be
//!    measured.
//!
//! # Recovery from a bad decision
//!
//! Because the atlas is verified against its committed BLAKE3 digest at load
//! ([`DirectPageState::load_payload`](crate::directpage::DirectPageState::load_payload)),
//! a deliberately bad decision — an atlas that is stale or tampered after it was
//! published — is *ignored*: the payload fails its digest, the `direct-image`
//! candidate is omitted, and reads return byte-exact authoritative bytes. The bad
//! decision costs only the wasted manifested bytes and construction time.
//! `tests/expansion_controller.rs` demonstrates exactly this.

use std::collections::{BTreeMap, HashMap};

use crate::directpage::ATLAS_ALIGN;
use crate::error::{OrfsError, Result};
use crate::manifestation::{ManifestationProfile, ManifestationStatus};
use crate::namespace::Namespace;
use crate::readpath::{
    classify_length, prior_cost_ns, PathMeasurement, ReadPathKind, ReadQuery, SizeClass,
};

/// The schema label of the expansion-controller evidence surface.
pub const EXPANSION_SCHEMA: &str = "orfs.performance.expansion-controller.v1";

/// Every size class, in the planner's canonical order.
const ALL_CLASSES: [SizeClass; SizeClass::COUNT] = [
    SizeClass::Empty,
    SizeClass::Byte,
    SizeClass::Small,
    SizeClass::Medium,
    SizeClass::Large,
];

// ---------------------------------------------------------------------------
// The observed workload
// ---------------------------------------------------------------------------

/// One aggregate observation: an object read `count` times with an effective read
/// length in a single size class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkloadRead {
    /// The object read.
    pub inode: u64,
    /// The object's committed version at the observation root.
    pub inode_version: u64,
    /// The committed root the workload ran against.
    pub root: u64,
    /// The object's committed logical length.
    pub logical_len: u64,
    /// The size class of the read.
    pub size_class: SizeClass,
    /// How many times this read occurred.
    pub count: u64,
}

/// An object as the controller sees it: its committed identity, its logical
/// length, and its per-size-class read counts over the workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkloadObject {
    /// The object.
    pub inode: u64,
    /// Committed version.
    pub inode_version: u64,
    /// Committed root.
    pub root: u64,
    /// Logical length in bytes.
    pub logical_len: u64,
    /// Total reads over every size class.
    pub total_reads: u64,
    /// Reads per size class (indexed by [`SizeClass::index`]).
    pub class_counts: [u64; SizeClass::COUNT],
}

impl WorkloadObject {
    /// The number of reads recorded for `class`.
    pub fn count(&self, class: SizeClass) -> u64 {
        self.class_counts[class.index()]
    }
}

/// The observed read workload over a committed root, aggregated per object and
/// size class. Objects are kept in first-seen order so a plan is deterministic.
#[derive(Debug, Clone, Default)]
pub struct ReadWorkload {
    objects: Vec<WorkloadObject>,
    index: BTreeMap<u64, usize>,
    total_reads: u64,
}

impl ReadWorkload {
    /// An empty workload.
    pub fn new() -> ReadWorkload {
        ReadWorkload::default()
    }

    /// Record `count` reads of `length` bytes from `inode` at `(version, root)`.
    /// The length is classified by the planner's own [`classify_length`].
    pub fn observe(
        &mut self,
        inode: u64,
        inode_version: u64,
        root: u64,
        logical_len: u64,
        length: u64,
        count: u64,
    ) {
        if count == 0 {
            return;
        }
        let class = classify_length(length);
        let pos = match self.index.get(&inode) {
            Some(&p) => p,
            None => {
                let p = self.objects.len();
                self.index.insert(inode, p);
                self.objects.push(WorkloadObject {
                    inode,
                    inode_version,
                    root,
                    logical_len,
                    total_reads: 0,
                    class_counts: [0; SizeClass::COUNT],
                });
                p
            }
        };
        let obj = &mut self.objects[pos];
        obj.total_reads += count;
        obj.class_counts[class.index()] += count;
        self.total_reads += count;
    }

    /// The observed objects, in first-seen order.
    pub fn objects(&self) -> &[WorkloadObject] {
        &self.objects
    }

    /// Total reads over every object and size class.
    pub fn total_reads(&self) -> u64 {
        self.total_reads
    }

    /// Whether nothing was observed.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Cost / byte estimates (measured or previously recorded; pure)
// ---------------------------------------------------------------------------

/// The controller's per-`(path, size class)` cost estimate. A **recorded**
/// measurement (from [`ReadPlanner::measurements`](crate::readpath::ReadPlanner::measurements))
/// overrides the planner's documented prior; where no measurement exists the
/// estimate is [`prior_cost_ns`]. It is deliberately read-only at planning time,
/// so `plan` is a pure function.
#[derive(Debug, Clone, Default)]
pub struct ExpansionCosts {
    measured: HashMap<(ReadPathKind, SizeClass), f64>,
}

impl ExpansionCosts {
    /// An empty cost table (every estimate falls back to the documented prior).
    pub fn new() -> ExpansionCosts {
        ExpansionCosts::default()
    }

    /// Record one measured `(path, size class)` latency in nanoseconds.
    pub fn record(&mut self, kind: ReadPathKind, class: SizeClass, ns: f64) {
        self.measured.insert((kind, class), ns);
    }

    /// Fold in a planner's measured cost-model surface (its EWMA per
    /// `(path, size class)`), so the estimate uses genuine measurements rather
    /// than the prior wherever they exist.
    pub fn record_measurements(&mut self, measurements: &[PathMeasurement]) {
        for m in measurements {
            self.record(m.path, m.class, m.ewma_ns);
        }
    }

    /// The recorded measurement for `(kind, class)`, if any.
    pub fn recorded(&self, kind: ReadPathKind, class: SizeClass) -> Option<f64> {
        self.measured.get(&(kind, class)).copied()
    }

    /// Whether `(kind, class)` has a recorded measurement.
    pub fn is_recorded(&self, kind: ReadPathKind, class: SizeClass) -> bool {
        self.measured.contains_key(&(kind, class))
    }

    /// The estimate for `(kind, class)`: the recorded measurement when present,
    /// otherwise the planner's documented prior.
    pub fn estimate(&self, kind: ReadPathKind, class: SizeClass) -> f64 {
        self.recorded(kind, class)
            .unwrap_or_else(|| prior_cost_ns(kind, class))
    }

    /// The number of recorded measurements.
    pub fn len(&self) -> usize {
        self.measured.len()
    }

    /// Whether no measurement has been recorded.
    pub fn is_empty(&self) -> bool {
        self.measured.is_empty()
    }
}

/// The manifested-space byte estimator. The atlas payload is exactly its
/// alignment header plus the logical bytes; the EKBLOOM generation's physical
/// bytes are estimated from a **measured** per-logical-byte ratio (the caller
/// records it from a real generation, e.g. `physical_bytes / logical_len`).
#[derive(Debug, Clone, Copy)]
pub struct ByteModel {
    /// Measured manifested-generation bytes per logical byte.
    pub generation_bytes_per_logical: f64,
    /// The atlas payload's fixed overhead (its alignment header), in bytes.
    pub atlas_overhead_bytes: u64,
}

impl ByteModel {
    /// A byte model from a measured generation ratio and the atlas alignment.
    pub fn new(generation_bytes_per_logical: f64, atlas_overhead_bytes: u64) -> ByteModel {
        ByteModel {
            generation_bytes_per_logical,
            atlas_overhead_bytes,
        }
    }

    /// A byte model using the direct-page atlas's real alignment header.
    pub fn with_atlas_align(generation_bytes_per_logical: f64) -> ByteModel {
        ByteModel::new(generation_bytes_per_logical, ATLAS_ALIGN)
    }

    /// The exact payload bytes of a direct-page atlas covering `logical_len`.
    pub fn atlas_payload_bytes(&self, logical_len: u64) -> u64 {
        self.atlas_overhead_bytes + logical_len
    }

    /// The estimated manifested physical bytes of a program for `logical_len`.
    pub fn program_bytes(&self, choice: ExpansionChoice, logical_len: u64) -> u64 {
        match choice {
            ExpansionChoice::None => 0,
            ExpansionChoice::Atlas => {
                let gen = (self.generation_bytes_per_logical * logical_len as f64).round() as u64;
                gen + self.atlas_payload_bytes(logical_len)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// A program the controller may choose for one object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpansionChoice {
    /// No derived structure: the object is read authoritatively.
    None,
    /// An EKBLOOM generation (today's prerequisite for any manifested candidate)
    /// plus a direct-page atlas.
    Atlas,
}

impl ExpansionChoice {
    /// A stable short name for evidence.
    pub const fn name(self) -> &'static str {
        match self {
            ExpansionChoice::None => "none",
            ExpansionChoice::Atlas => "atlas",
        }
    }
}

/// The controller's decision for one object.
#[derive(Debug, Clone)]
pub struct ExpansionDecision {
    /// The object.
    pub inode: u64,
    /// Committed version.
    pub inode_version: u64,
    /// Committed root.
    pub root: u64,
    /// Logical length in bytes.
    pub logical_len: u64,
    /// Total reads over the workload.
    pub total_reads: u64,
    /// The chosen program.
    pub choice: ExpansionChoice,
    /// The predicted aggregate read-time reduction (ns) if `Atlas` is chosen.
    pub predicted_benefit_ns: f64,
    /// The predicted manifested bytes of the `Atlas` program.
    pub predicted_bytes: u64,
    /// The predicted benefit per manifested byte.
    pub benefit_per_byte: f64,
}

impl ExpansionDecision {
    /// Whether a structure was chosen for this object.
    pub fn chosen(&self) -> bool {
        self.choice != ExpansionChoice::None
    }
}

/// The controller's chosen set under a manifested-space budget.
#[derive(Debug, Clone)]
pub struct ExpansionPlan {
    /// One decision per observed object, in workload order.
    pub decisions: Vec<ExpansionDecision>,
    /// The manifested-space budget the plan was made under.
    pub budget_bytes: u64,
    /// The predicted manifested bytes of the chosen programs.
    pub predicted_bytes: u64,
    /// The predicted aggregate read-time reduction of the chosen programs.
    pub predicted_benefit_ns: f64,
    /// The EKBLOOM generation profile the `Atlas` program constructs.
    pub profile: ManifestationProfile,
}

impl ExpansionPlan {
    /// The chosen decisions (those that build a structure).
    pub fn chosen(&self) -> impl Iterator<Item = &ExpansionDecision> {
        self.decisions.iter().filter(|d| d.chosen())
    }

    /// The inodes the plan chooses to manifest.
    pub fn chosen_inodes(&self) -> Vec<u64> {
        self.chosen().map(|d| d.inode).collect()
    }

    /// The number of chosen objects.
    pub fn chosen_count(&self) -> usize {
        self.chosen().count()
    }
}

/// Controller configuration.
#[derive(Debug, Clone)]
pub struct ExpansionConfig {
    /// The manifested-space budget `B` (physical bytes).
    pub budget_bytes: u64,
    /// The EKBLOOM generation profile the `Atlas` program constructs (the
    /// prerequisite the current planner requires for any manifested candidate).
    pub profile: ManifestationProfile,
}

impl ExpansionConfig {
    /// A configuration for a budget and a generation profile.
    pub fn new(budget_bytes: u64, profile: ManifestationProfile) -> ExpansionConfig {
        ExpansionConfig {
            budget_bytes,
            profile,
        }
    }
}

// ---------------------------------------------------------------------------
// The controller (pure prediction)
// ---------------------------------------------------------------------------

/// The autonomous controller: a pure predictor that decides which structures to
/// build under a budget. It holds no namespace handle and does no I/O, so its
/// decision is a pure function of the workload and its estimates — and can never
/// touch committed history.
pub struct ExpansionController {
    config: ExpansionConfig,
    costs: ExpansionCosts,
    bytes: ByteModel,
}

impl ExpansionController {
    /// A controller over a config, a cost table, and a byte model.
    pub fn new(
        config: ExpansionConfig,
        costs: ExpansionCosts,
        bytes: ByteModel,
    ) -> ExpansionController {
        ExpansionController {
            config,
            costs,
            bytes,
        }
    }

    /// The controller configuration.
    pub fn config(&self) -> &ExpansionConfig {
        &self.config
    }

    /// The cost table.
    pub fn costs(&self) -> &ExpansionCosts {
        &self.costs
    }

    /// The byte model.
    pub fn byte_model(&self) -> &ByteModel {
        &self.bytes
    }

    /// The predicted aggregate read-time reduction (nanoseconds) from choosing
    /// `Atlas` over `None` for one object:
    ///
    /// ```text
    ///   Σ_c count_c · max(0, estimate(LogicalExtent, c) − estimate(DirectImage, c))
    /// ```
    ///
    /// Pure: it consults only the recorded/prior cost table.
    pub fn predicted_benefit_ns(&self, obj: &WorkloadObject) -> f64 {
        let mut benefit = 0.0;
        for class in ALL_CLASSES {
            let n = obj.count(class) as f64;
            if n <= 0.0 {
                continue;
            }
            let auth = self.costs.estimate(ReadPathKind::LogicalExtent, class);
            let atlas = self.costs.estimate(ReadPathKind::DirectImage, class);
            benefit += n * (auth - atlas).max(0.0);
        }
        benefit
    }

    /// Decide, purely, which structures to build under the manifested-space
    /// budget. Objects are ranked by predicted benefit per manifested byte
    /// (descending, ties broken by inode for determinism) and taken greedily while
    /// the cumulative predicted bytes fit `B`. A non-positive predicted benefit is
    /// never chosen, so the plan never spends bytes on an object the estimate says
    /// cannot improve.
    pub fn plan(&self, workload: &ReadWorkload) -> ExpansionPlan {
        let n = workload.objects().len();
        let mut benefit = vec![0.0f64; n];
        let mut bytes = vec![0u64; n];
        let mut density = vec![0.0f64; n];
        for (i, obj) in workload.objects().iter().enumerate() {
            benefit[i] = self.predicted_benefit_ns(obj);
            bytes[i] = self
                .bytes
                .program_bytes(ExpansionChoice::Atlas, obj.logical_len);
            density[i] = if bytes[i] > 0 {
                benefit[i] / bytes[i] as f64
            } else {
                benefit[i]
            };
        }

        // Rank by density (descending), then by inode (ascending) for determinism.
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by(|&a, &b| {
            density[b]
                .partial_cmp(&density[a])
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    workload.objects()[a]
                        .inode
                        .cmp(&workload.objects()[b].inode)
                })
        });

        let mut chosen = vec![false; n];
        let mut spent = 0u64;
        let mut total_benefit = 0.0;
        for &i in &order {
            if benefit[i] <= 0.0 {
                continue;
            }
            let projected = spent + bytes[i];
            if projected <= self.config.budget_bytes {
                chosen[i] = true;
                spent = projected;
                total_benefit += benefit[i];
            }
        }

        let decisions = workload
            .objects()
            .iter()
            .enumerate()
            .map(|(i, obj)| ExpansionDecision {
                inode: obj.inode,
                inode_version: obj.inode_version,
                root: obj.root,
                logical_len: obj.logical_len,
                total_reads: obj.total_reads,
                choice: if chosen[i] {
                    ExpansionChoice::Atlas
                } else {
                    ExpansionChoice::None
                },
                predicted_benefit_ns: benefit[i],
                predicted_bytes: bytes[i],
                benefit_per_byte: density[i],
            })
            .collect();

        ExpansionPlan {
            decisions,
            budget_bytes: self.config.budget_bytes,
            predicted_bytes: spent,
            predicted_benefit_ns: total_benefit,
            profile: self.config.profile,
        }
    }
}

// ---------------------------------------------------------------------------
// The safe execution loop (best-effort construction + verification)
// ---------------------------------------------------------------------------

/// The outcome of executing a plan's decision for one object.
#[derive(Debug, Clone)]
pub struct ExpansionOutcome {
    /// The object.
    pub inode: u64,
    /// Committed version.
    pub inode_version: u64,
    /// Committed root.
    pub root: u64,
    /// Logical length in bytes.
    pub logical_len: u64,
    /// The chosen program.
    pub choice: ExpansionChoice,
    /// Whether every structure the program needs was built (published).
    pub built: bool,
    /// Whether the manifested read was verified byte-identical to the
    /// authoritative read. A program that is not verified is ignored by the
    /// planner, so it can cost bytes but never change a read's bytes.
    pub verified: bool,
    /// The published generation's physical bytes (`0` if none was built).
    pub generation_bytes: u64,
    /// The published atlas payload bytes (`0` if none was built).
    pub atlas_bytes: u64,
    /// Total manifested physical bytes for this object.
    pub manifested_bytes: u64,
    /// A human-readable detail (never fabricated: it reflects what happened).
    pub detail: String,
}

/// Execute a plan against a namespace whose manifestation and direct-page atlas
/// planes are already enabled: **best-effort** construction of each chosen
/// program (an EKBLOOM generation, then a direct-page atlas), followed by a
/// **byte-identity verification** of the manifested read against the
/// authoritative read. Construction happens here, in a deliberate planning phase
/// — never on a foreground read's critical path — and a failure is recorded and
/// skipped rather than propagated, so one object's failure cannot abort the rest.
///
/// The planner is *not* told what was built; it simply measures every published
/// structure on the next read and selects the cheapest it has measured, falling
/// back to the authoritative path. A program that failed to build, or that does
/// not verify, is therefore ignored — the recovery property this module promises.
pub fn execute_plan(ns: &Namespace, plan: &ExpansionPlan) -> Vec<ExpansionOutcome> {
    plan.chosen()
        .map(|d| execute_one(ns, d, plan.profile))
        .collect()
}

fn execute_one(
    ns: &Namespace,
    d: &ExpansionDecision,
    profile: ManifestationProfile,
) -> ExpansionOutcome {
    let mut outcome = ExpansionOutcome {
        inode: d.inode,
        inode_version: d.inode_version,
        root: d.root,
        logical_len: d.logical_len,
        choice: d.choice,
        built: false,
        verified: false,
        generation_bytes: 0,
        atlas_bytes: 0,
        manifested_bytes: 0,
        detail: String::new(),
    };
    if d.choice == ExpansionChoice::None {
        outcome.built = true;
        outcome.verified = true;
        outcome.detail = "no structure chosen".to_string();
        return outcome;
    }

    // 1. The EKBLOOM generation (the prerequisite for any manifested candidate).
    let generation = match ns.manifest_eligible(Some(d.inode), profile) {
        Ok(outcomes) => outcomes.into_iter().find(|o| o.inode == d.inode),
        Err(e) => {
            outcome.detail = format!("generation construction failed: {e}");
            return outcome;
        }
    };
    match generation {
        Some(o) if o.status == ManifestationStatus::Published => {
            outcome.generation_bytes = o.physical_bytes;
        }
        Some(o) => {
            outcome.detail = format!(
                "generation not published ({}): {}",
                o.status.name(),
                o.detail.unwrap_or_default()
            );
            return outcome;
        }
        None => {
            outcome.detail = "generation produced no outcome".to_string();
            return outcome;
        }
    }

    // 2. The direct-page atlas.
    match ns.manifest_direct_page_atlas(d.inode) {
        Ok(a) if a.published => outcome.atlas_bytes = a.payload_bytes,
        Ok(a) => {
            outcome.detail = format!("atlas not published: {}", a.detail);
            return outcome;
        }
        Err(e) => {
            outcome.detail = format!("atlas construction failed: {e}");
            return outcome;
        }
    }
    outcome.manifested_bytes = outcome.generation_bytes + outcome.atlas_bytes;
    outcome.built = true;

    // 3. Verify byte-identity against the authoritative read.
    match verify_atlas_identity(ns, d) {
        Ok(true) => {
            outcome.verified = true;
            outcome.detail = "built and verified byte-identical".to_string();
        }
        Ok(false) => {
            outcome.detail =
                "built but not verifiable as byte-identical; the planner ignores it".to_string();
        }
        Err(e) => {
            outcome.detail = format!("verification error: {e}");
        }
    }
    outcome
}

/// Whether the published atlas for `d` is enumerated by the planner as a
/// certified, byte-identical candidate for the exact identity.
fn verify_atlas_identity(ns: &Namespace, d: &ExpansionDecision) -> Result<bool> {
    let planner = ns
        .read_planner()
        .ok_or_else(|| OrfsError::InvalidArgument("no read planner is available".into()))?;
    let (size, version) = ns.inode_identity(d.inode)?;
    let q = ReadQuery {
        inode: d.inode,
        inode_version: version,
        root: d.root,
        logical_len: size,
        offset: 0,
        length: size,
    };
    let mut auth = |off: u64, len: u64| ns.read_extent(d.inode, d.root, off, len);
    let verdicts = planner.verify_paths(&q, &mut auth)?;
    Ok(verdicts
        .iter()
        .any(|v| v.path == ReadPathKind::DirectImage && v.certified && v.equivalent))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(inode: u64, logical_len: u64, counts: &[(SizeClass, u64)]) -> WorkloadObject {
        let mut class_counts = [0u64; SizeClass::COUNT];
        let mut total = 0;
        for &(c, n) in counts {
            class_counts[c.index()] += n;
            total += n;
        }
        WorkloadObject {
            inode,
            inode_version: 1,
            root: 100,
            logical_len,
            total_reads: total,
            class_counts,
        }
    }

    fn controller(budget: u64) -> ExpansionController {
        ExpansionController::new(
            ExpansionConfig::new(budget, ManifestationProfile::Path { depth: 8 }),
            ExpansionCosts::new(),
            ByteModel::with_atlas_align(2.5),
        )
    }

    #[test]
    fn budget_zero_chooses_nothing() {
        let mut wl = ReadWorkload::new();
        wl.observe(10, 1, 100, 65536, 16384, 32);
        let plan = controller(0).plan(&wl);
        assert_eq!(plan.chosen_count(), 0);
        assert_eq!(plan.predicted_bytes, 0);
    }

    #[test]
    fn a_larger_budget_never_chooses_less() {
        let mut wl = ReadWorkload::new();
        for i in 0..8u64 {
            wl.observe(
                10 + i,
                1,
                100,
                65536,
                16384,
                64 - i * 4, // decreasing read counts
            );
        }
        let mut prev = 0;
        for budget in [0, 262_144, 1_048_576, 4_194_304, u64::MAX] {
            let plan = controller(budget).plan(&wl);
            assert!(
                plan.chosen_count() >= prev,
                "budget {budget} chose fewer than a smaller budget"
            );
            assert!(
                plan.predicted_bytes <= budget,
                "budget {budget}: predicted {} bytes exceeds it",
                plan.predicted_bytes
            );
            prev = plan.chosen_count();
        }
    }

    #[test]
    fn the_plan_respects_the_byte_budget() {
        let mut wl = ReadWorkload::new();
        for i in 0..8u64 {
            wl.observe(10 + i, 1, 100, 65536, 16384, 16);
        }
        let budget = 500_000;
        let plan = controller(budget).plan(&wl);
        assert!(
            plan.predicted_bytes <= budget,
            "predicted {} exceeds budget {budget}",
            plan.predicted_bytes
        );
    }

    #[test]
    fn a_bigger_object_can_be_chosen_ahead_of_a_smaller_one() {
        // A big, hot object beats a small, cold one on density.
        let mut wl = ReadWorkload::new();
        wl.observe(1, 1, 100, 262_144, 131_072, 64);
        wl.observe(2, 1, 100, 16_384, 1, 1);
        let plan = controller(u64::MAX).plan(&wl);
        assert_eq!(plan.chosen_count(), 2);
        // Under a budget that fits only one, the hot object wins.
        let one = plan
            .decisions
            .iter()
            .find(|d| d.inode == 1)
            .unwrap()
            .predicted_bytes;
        let plan1 = controller(one).plan(&wl);
        assert_eq!(plan1.chosen_inodes(), vec![1]);
    }

    #[test]
    fn recorded_costs_override_the_prior() {
        let mut costs = ExpansionCosts::new();
        // Force the atlas to look TWICE as slow as the authoritative prior.
        let auth = prior_cost_ns(ReadPathKind::LogicalExtent, SizeClass::Medium);
        let atlas_prior = prior_cost_ns(ReadPathKind::DirectImage, SizeClass::Medium);
        costs.record(ReadPathKind::DirectImage, SizeClass::Medium, auth * 2.0);
        assert!(costs.is_recorded(ReadPathKind::DirectImage, SizeClass::Medium));
        assert_eq!(
            costs.estimate(ReadPathKind::DirectImage, SizeClass::Medium),
            auth * 2.0
        );
        // The unrecorded classes still fall back to the documented prior.
        assert_eq!(
            costs.estimate(ReadPathKind::DirectImage, SizeClass::Byte),
            prior_cost_ns(ReadPathKind::DirectImage, SizeClass::Byte)
        );
        assert!(atlas_prior < auth);
        let ctrl = ExpansionController::new(
            ExpansionConfig::new(u64::MAX, ManifestationProfile::Path { depth: 8 }),
            costs,
            ByteModel::with_atlas_align(2.5),
        );
        // A medium-only object now predicts a non-positive benefit.
        let o = obj(1, 65_536, &[(SizeClass::Medium, 16)]);
        assert!(ctrl.predicted_benefit_ns(&o) <= 0.0);
    }

    #[test]
    fn byte_model_counts_the_prerequisite_generation() {
        let bm = ByteModel::with_atlas_align(1.0);
        assert_eq!(bm.program_bytes(ExpansionChoice::None, 65536), 0);
        assert_eq!(bm.atlas_payload_bytes(65536), ATLAS_ALIGN + 65536);
        assert_eq!(
            bm.program_bytes(ExpansionChoice::Atlas, 65536),
            2 * 65536 + ATLAS_ALIGN
        );
    }
}
