//! Phase 80 **durability qualification beyond the model** — a failure-state model
//! with three distinguished classes, the extended fault matrix (in-flight
//! completions, metadata tearing, remount cycles, reordered writes, lost flushes),
//! and the commit-watermark **residual window** as an explicit, tested property.
//!
//! # The three failure classes
//!
//! The court runs *the same workload* under each [`FailureClass`] and checks that
//! the **acknowledged-durability contract** holds in all three while the
//! **unacknowledged tail** differs:
//!
//! | Class | Userspace buffers | OS page cache | Device write-back cache |
//! |---|---|---|---|
//! | `Process` | lost | **survives** | not relevant |
//! | `Kernel` | lost | lost | **survives** (writes may reorder) |
//! | `Storage` | lost | lost | **lost** (reorder/partial/torn per profile) |
//!
//! It also qualifies the **commit-watermark residual window** (`docs/LIMITATIONS.md`
//! §6, `docs/RECOVERY.md` §5): the loss of durable bytes *between the last
//! watermark and the committed root* is undetectable, and the court records that
//! as an explicit `residual_window` field rather than smoothing it over. A
//! watermark *ahead* of the surviving bytes is *detected* (the open is refused).
//!
//! # Honesty
//!
//! This is still a **simulated** device (`src/powerloss.rs`), not hardware. A
//! green run proves OrFS's recovery correct *relative to the model's assumed
//! device semantics*; it does not prove real-hardware durability. Real block-device
//! fault injection (`dm-flaky`/`dm-error`) is not usable here — the receipt records
//! the concrete `dm_probe` result. See `docs/DURABILITY.md`.

#![cfg(feature = "powerloss")]

mod support;

use std::path::Path;

use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::log::OpenMode;
use orfs::powerloss::{
    self, DeviceFaultKind, DeviceFaultRule, DeviceOp, FailureClass, PowerFailReport, SimConfig,
};
use orfs::record::RecordType;
use orfs::segment::segment_file_name;
use orfs::volume::Volume;

use serde_json::{json, Value};
use support::{build_transaction, init_volume, snapshot_segments, SegmentSnapshot};
use tempfile::TempDir;

/// A small segment size so a short workload rolls over at least once.
const SEG: u64 = 1024;
/// A large segment size so a short workload stays within one segment.
const SEG_LARGE: u64 = 1 << 20;

// ---------------------------------------------------------------------------
// Experiment machinery (shared shape with tests/power_loss.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Ack {
    tx: u64,
    root: u64,
    durable: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Invariants {
    recovered_root_is_transaction_boundary: bool,
    last_record_is_commit_or_genesis: bool,
    earlier_committed_roots_valid: bool,
    no_committed_record_rewritten: bool,
    committed_physical_bytes_unchanged: bool,
    next_transaction_commits_and_advances: bool,
}

impl Invariants {
    fn all_ok(&self) -> bool {
        self.recovered_root_is_transaction_boundary
            && self.last_record_is_commit_or_genesis
            && self.earlier_committed_roots_valid
            && self.no_committed_record_rewritten
            && self.committed_physical_bytes_unchanged
            && self.next_transaction_commits_and_advances
    }
}

#[derive(Debug, Clone, serde::Serialize)]
enum Recovery {
    Recovered {
        root: u64,
        invariants: Invariants,
        durable_watermark_root: Option<u64>,
    },
    Refused {
        error: String,
    },
}

impl Recovery {
    fn root(&self) -> Option<u64> {
        match self {
            Recovery::Recovered { root, .. } => Some(*root),
            Recovery::Refused { .. } => None,
        }
    }

    fn refused(&self) -> bool {
        matches!(self, Recovery::Refused { .. })
    }

    fn watermark_root(&self) -> Option<u64> {
        match self {
            Recovery::Recovered {
                durable_watermark_root,
                ..
            } => *durable_watermark_root,
            Recovery::Refused { .. } => None,
        }
    }
}

fn durable_roots(acks: &[Ack]) -> Vec<u64> {
    acks.iter().filter(|a| a.durable).map(|a| a.root).collect()
}

fn baseline(dir: &Path) -> (u64, Vec<u8>, Vec<SegmentSnapshot>) {
    let vol = Volume::open(dir, OpenMode::ReadOnly).expect("open baseline");
    (
        vol.log.committed_end_offset(),
        vol.log.read_committed_bytes().expect("baseline bytes"),
        snapshot_segments(&vol.log),
    )
}

/// Independently reopen the powered-down volume and check the §35 invariants.
fn recover(dir: &Path, baseline_bytes: &[u8], baseline_segments: &[SegmentSnapshot]) -> Recovery {
    let vol = match Volume::open(dir, OpenMode::ReadOnly) {
        Ok(v) => v,
        Err(e) => {
            return Recovery::Refused {
                error: e.to_string(),
            }
        }
    };
    let root = vol.log.committed_end_offset();
    let recovered_root_is_transaction_boundary = vol.log.is_boundary(root);
    let last_record_is_commit_or_genesis = vol
        .log
        .replay_upto(root)
        .ok()
        .and_then(|r| r.last().cloned())
        .map(|rec| {
            matches!(
                rec.known_type().expect("known type"),
                RecordType::TxCommit | RecordType::VolumeGenesis
            )
        })
        .unwrap_or(false);
    let earlier_committed_roots_valid = vol
        .log
        .boundaries()
        .iter()
        .all(|&b| b <= root && vol.log.is_boundary(b) && vol.log.replay_upto(b).is_ok());
    let now = vol.log.read_committed_bytes().unwrap_or_default();
    let no_committed_record_rewritten =
        now.len() >= baseline_bytes.len() && now[..baseline_bytes.len()] == *baseline_bytes;
    let log_dir = vol.log.dir().to_path_buf();
    let committed_physical_bytes_unchanged = baseline_segments.iter().all(|s| {
        let path = log_dir.join(segment_file_name(s.id).expect("segment name"));
        match std::fs::read(&path) {
            Ok(actual) => actual.len() >= s.bytes.len() && actual[..s.bytes.len()] == s.bytes[..],
            Err(_) => false,
        }
    });
    let durable_watermark_root = vol.log.durable_watermark().map(|w| w.committed_root);
    drop(vol);

    let next_transaction_commits_and_advances = match Volume::open(dir, OpenMode::ReadWrite) {
        Ok(mut vol) => {
            let out = {
                let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
                let tx = build_transaction(seq.peek_transaction_id(), 2);
                seq.commit(tx)
            };
            match out {
                Ok(o) => o.begin_offset == root && o.root > root && vol.log.is_boundary(o.root),
                Err(_) => false,
            }
        }
        Err(_) => false,
    };

    Recovery::Recovered {
        root,
        invariants: Invariants {
            recovered_root_is_transaction_boundary,
            last_record_is_commit_or_genesis,
            earlier_committed_roots_valid,
            no_committed_record_rewritten,
            committed_physical_bytes_unchanged,
            next_transaction_commits_and_advances,
        },
        durable_watermark_root,
    }
}

/// One fully classified experiment.
struct Row {
    mode: DurabilityMode,
    class: FailureClass,
    cfg: SimConfig,
    fail_after: u64,
    flush_at: u64,
    baseline_root: u64,
    acks: Vec<Ack>,
    in_flight_skip: Option<u64>,
    in_flight_failure: Option<String>,
    in_flight_errno: Option<i32>,
    /// The errno of a mutation attempted immediately after an in-flight failure
    /// (`None` = it succeeded; `EROFS` would mean the volume wrongly latched).
    subsequent_errno: Option<i32>,
    report: PowerFailReport,
    recovery: Recovery,
}

impl Row {
    fn root(&self) -> Option<u64> {
        self.recovery.root()
    }

    fn refused(&self) -> bool {
        self.recovery.refused()
    }

    fn max_durable(&self) -> Option<u64> {
        durable_roots(&self.acks).into_iter().max()
    }

    /// The recovered root is strictly short of a previously acknowledged-durable
    /// root (the recovered history is shorter than what was acknowledged).
    fn known_shorter(&self) -> bool {
        match (self.root(), self.max_durable()) {
            (Some(r), Some(d)) => r < d,
            _ => false,
        }
    }

    /// The surviving watermark certifies **more** committed history than the
    /// recovered root: recovery ignored or downgraded a certified boundary. This
    /// must never happen without an explicit refusal (the invariant of
    /// `docs/RECOVERY.md` §5).
    fn watermark_ahead(&self) -> bool {
        match (self.root(), self.recovery.watermark_root()) {
            (Some(root), Some(wm)) => wm > root,
            _ => false,
        }
    }

    /// `none` | `detected_refusal` | `undetectable_unwatermarked_tail`.
    ///
    /// The last is the documented **residual window**: acknowledged-durable bytes
    /// beyond the last persisted watermark were lost, the surviving watermark is
    /// at or behind the recovered root, and the loss is therefore undetectable by
    /// the watermark alone.
    fn residual_window(&self) -> &'static str {
        if self.refused() {
            "detected_refusal"
        } else if self.known_shorter() {
            "undetectable_unwatermarked_tail"
        } else {
            "none"
        }
    }

    /// Recovery returned a root **shorter than the watermark certifies** without
    /// refusing: the watermark was silently ignored. Must always be `false`.
    fn silent_shortening(&self) -> bool {
        !self.refused() && self.watermark_ahead()
    }

    /// Every acknowledged-durable mutation survives (the acknowledged contract).
    fn ack_durable_survived(&self) -> bool {
        match self.root() {
            Some(r) => durable_roots(&self.acks).iter().all(|&d| d <= r),
            // A refusal is a deliberate detection; it never loses data silently.
            None => true,
        }
    }

    /// Recovery selected the newest *valid* committed generation, never a partial
    /// one (recovered rows), or refused explicitly (never a silent selection).
    fn newest_valid_generation_selected(&self) -> bool {
        match &self.recovery {
            Recovery::Recovered { invariants, .. } => {
                invariants.recovered_root_is_transaction_boundary
                    && invariants.last_record_is_commit_or_genesis
            }
            Recovery::Refused { .. } => true,
        }
    }

    fn invariants_ok(&self) -> bool {
        match &self.recovery {
            Recovery::Recovered { invariants, .. } => invariants.all_ok(),
            Recovery::Refused { .. } => true,
        }
    }
}

fn row_json(r: &Row) -> Value {
    let acks = &r.acks;
    json!({
        "durability_mode": r.mode.name(),
        "failure_class": r.class.name(),
        "profile": r.cfg,
        "fail_after_transactions": r.fail_after,
        "flush_at": r.flush_at,
        "baseline_root": r.baseline_root,
        "acknowledged_transaction_ids": acks.iter().map(|a| a.tx).collect::<Vec<_>>(),
        "acknowledged_roots": acks.iter().map(|a| a.root).collect::<Vec<_>>(),
        "acknowledged_durable_roots": durable_roots(acks),
        "final_acknowledged_root": acks.last().map(|a| a.root),
        "recovered_root": r.root(),
        "refused": r.refused(),
        "newest_valid_generation_selected": r.newest_valid_generation_selected(),
        "silent_shortening": r.silent_shortening(),
        "acknowledged_data_survived": r.ack_durable_survived(),
        "residual_window": r.residual_window(),
        "watermark_ahead_of_recovered_root": r.watermark_ahead(),
        "invariants_ok": r.invariants_ok(),
        "retained_volatile_bytes": r.report.retained_volatile_bytes,
        "dropped_volatile_bytes": r.report.total_dropped_volatile_bytes,
        "torn_durable_bytes": r.report.total_torn_durable_bytes,
        "failure_class_of_report": r.report.failure_class.name(),
        "in_flight_skip": r.in_flight_skip,
        "in_flight_failure": r.in_flight_failure,
        "in_flight_errno": r.in_flight_errno,
        "after_in_flight_errno": r.subsequent_errno,
        "recovery": r.recovery,
        "power_fail_report": r.report,
    })
}

// ---------------------------------------------------------------------------
// Environment / provenance
// ---------------------------------------------------------------------------

fn manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn environment() -> Value {
    let digest = std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".into());
    let env = orfs::bench::Environment::capture(Some(digest));
    json!({
        "bench": serde_json::to_value(&env).unwrap_or(Value::Null),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "toolchain": std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".into()),
    })
}

fn git_commit() -> String {
    std::env::var("ORFS_GIT_COMMIT").unwrap_or_else(|_| "unknown".into())
}

/// The persisted device-mapper probe (from the elevated container), if present.
fn dm_probe() -> Value {
    if let Ok(path) = std::env::var("ORFS_DM_PROBE_JSON") {
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                return v;
            }
        }
    }
    json!({
        "ran": false,
        "status": "not-probed",
        "conclusion": "No dm-probe receipt was supplied (set ORFS_DM_PROBE_JSON); \
                       the elevated probe did not run in this container.",
    })
}

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

/// Honest storage profiles: the device honours `fsync`.
fn honest_profiles() -> Vec<(&'static str, SimConfig)> {
    vec![
        ("honest_barrier", SimConfig::honest(1)),
        ("honest_reordered", SimConfig::reordered(7)),
    ]
}

/// The extended fault matrix (Storage class): reordered writes, lost flushes,
/// metadata tearing, and the residual window.
fn fault_profiles() -> Vec<(&'static str, SimConfig)> {
    vec![
        ("partial_flush", SimConfig::partial(3)),
        ("reordered_partial_flush", SimConfig::reordered_partial(5)),
        ("torn_tail", SimConfig::tear(4)),
        ("lost_watermark", SimConfig::lost_watermark(17)),
        ("reorder_durable", SimConfig::reorder_durable(9)),
        ("torn_watermark", SimConfig::torn_watermark(2)),
        ("torn_directory_entry", SimConfig::torn_directory_entry(6)),
        ("tear_interior_metadata", SimConfig::tear_interior(8)),
        ("residual_window", SimConfig::residual_window(11)),
    ]
}

const MODES: [DurabilityMode; 3] = [
    DurabilityMode::Sync,
    DurabilityMode::Ordered,
    DurabilityMode::Batched { batch_size: 3 },
];

/// Run one experiment: initialise a volume, attach a device of `class` with `cfg`
/// and optional `rules`, commit `fail_after` transactions (with an explicit
/// `flush` after `flush_at` when non-zero), power-fail, then recover independently.
fn run_row(
    mode: DurabilityMode,
    class: FailureClass,
    cfg: SimConfig,
    seg: u64,
    fail_after: u64,
    flush_at: u64,
    rules: Vec<DeviceFaultRule>,
) -> Row {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().to_path_buf();
    drop(init_volume(&dir, seg));
    let (baseline_root, baseline_bytes, baseline_segments) = baseline(&dir);

    let log_dir = Volume::log_dir(&dir);
    let handle = powerloss::attach_with_class(&log_dir, cfg, class, rules).expect("attach device");

    let mut acks = Vec::new();
    let mut in_flight_failure = None;
    let mut in_flight_errno = None;
    let mut subsequent_errno = None;
    {
        let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("open workload volume");
        let mut seq = CommitSequencer::new(&mut vol, mode);
        for i in 0..fail_after {
            let tx = build_transaction(seq.peek_transaction_id(), 2);
            match seq.commit(tx) {
                Ok(out) => acks.push(Ack {
                    tx: out.transaction_id,
                    root: out.root,
                    durable: out.durable,
                }),
                Err(e) => {
                    in_flight_errno = Some(e.errno());
                    in_flight_failure = Some(e.to_string());
                    // A non-latching in-flight failure must leave the volume
                    // writable: a following mutation must not return EROFS.
                    let tx2 = build_transaction(seq.peek_transaction_id(), 2);
                    subsequent_errno = seq.commit(tx2).err().map(|e| e.errno());
                    break;
                }
            }
            if flush_at != 0 && i + 1 == flush_at {
                seq.flush().expect("explicit durability point");
            }
        }
    }

    let report = handle.power_fail().expect("power fail");
    let recovery = recover(&dir, &baseline_bytes, &baseline_segments);
    Row {
        mode,
        class,
        cfg,
        fail_after,
        flush_at,
        baseline_root,
        acks,
        in_flight_skip: None,
        in_flight_failure,
        in_flight_errno,
        subsequent_errno,
        report,
        recovery,
    }
}

/// As [`run_row`], but attaches the device *after* opening the volume (so the
/// open's own directory sync cannot consume the injected fault) and arms an
/// in-flight completion on the `skip`-th `sync`.
fn run_in_flight(mode: DurabilityMode, class: FailureClass, cfg: SimConfig, skip: u64) -> Row {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().to_path_buf();
    drop(init_volume(&dir, SEG_LARGE));
    let (baseline_root, baseline_bytes, baseline_segments) = baseline(&dir);

    let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("open workload volume");
    let log_dir = Volume::log_dir(&dir);
    let rules = vec![DeviceFaultRule::new(
        DeviceOp::Sync,
        DeviceFaultKind::InFlight,
        skip,
    )];
    let handle = powerloss::attach_with_class(&log_dir, cfg, class, rules).expect("attach device");

    let mut acks = Vec::new();
    let mut in_flight_failure = None;
    let mut in_flight_errno = None;
    let mut subsequent_errno = None;
    {
        let mut seq = CommitSequencer::new(&mut vol, mode);
        for _ in 0..6 {
            let tx = build_transaction(seq.peek_transaction_id(), 2);
            match seq.commit(tx) {
                Ok(out) => acks.push(Ack {
                    tx: out.transaction_id,
                    root: out.root,
                    durable: out.durable,
                }),
                Err(e) => {
                    in_flight_errno = Some(e.errno());
                    in_flight_failure = Some(e.to_string());
                    break;
                }
            }
            // `ordered`/`batched` do not sync per commit; force a durability
            // point so the in-flight rule can fire on a real `sync`.
            if mode != DurabilityMode::Sync {
                if let Err(e) = seq.flush() {
                    in_flight_errno = Some(e.errno());
                    in_flight_failure = Some(e.to_string());
                    break;
                }
            }
        }
        if in_flight_errno.is_some() {
            let tx2 = build_transaction(seq.peek_transaction_id(), 2);
            subsequent_errno = seq.commit(tx2).err().map(|e| e.errno());
        }
    }

    let report = handle.power_fail().expect("power fail");
    let recovery = recover(&dir, &baseline_bytes, &baseline_segments);
    Row {
        mode,
        class,
        cfg,
        fail_after: 6,
        flush_at: 0,
        baseline_root,
        acks,
        in_flight_skip: Some(skip),
        in_flight_failure,
        in_flight_errno,
        subsequent_errno,
        report,
        recovery,
    }
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

/// Whether a profile models a **contract-honouring** device: a flush that
/// actually promotes the cached writes (Barrier/Reordered) and, at power failure,
/// no damage to the durable image other than possibly the (atomic) watermark.
/// Under such a device every acknowledged-durable mutation must survive.
fn is_honouring(cfg: &SimConfig) -> bool {
    use orfs::powerloss::{DurableLoss, FlushMode};
    matches!(cfg.flush, FlushMode::Barrier | FlushMode::Reordered)
        && matches!(
            cfg.durable_loss,
            DurableLoss::None | DurableLoss::LostWatermark
        )
}

/// The general safety contract, which must hold for **every** row (honest or
/// contract-violating): recovery selects the newest valid generation, never
/// silently ignores the watermark, and satisfies the §35 invariants.
fn assert_safety(r: &Row, context: &str) {
    assert!(
        r.newest_valid_generation_selected(),
        "{context}: did not select the newest valid generation: {:?}",
        r.recovery
    );
    assert!(
        !r.silent_shortening(),
        "{context}: recovery returned a root shorter than the watermark certifies \
         without refusing: {:?}",
        r.recovery
    );
    if let Recovery::Recovered { invariants, .. } = &r.recovery {
        assert!(
            invariants.all_ok(),
            "{context}: a recovered row failed the §35 invariants: {invariants:?}"
        );
    }
}

/// The **acknowledged-durability contract**: every acknowledged-durable mutation
/// survives. Required under a contract-honouring device and for every failure
/// class. For a contract-violating profile, a loss is tolerated **only** when it
/// is classified as the documented residual window (or an explicit refusal).
fn assert_contract(r: &Row, context: &str) {
    assert_safety(r, context);
    if is_honouring(&r.cfg) {
        assert!(
            r.ack_durable_survived(),
            "{context}: an acknowledged-durable mutation was lost under a \
             contract-honouring device: {:?}",
            r.recovery
        );
        assert_eq!(
            r.residual_window(),
            "none",
            "{context}: a contract-honouring device must not lose acknowledged-durable data"
        );
    } else if !r.ack_durable_survived() {
        assert_ne!(
            r.residual_window(),
            "none",
            "{context}: a contract-violating device lost acknowledged-durable data \
             without it being the documented residual window: {:?}",
            r.recovery
        );
    }
}

// ---------------------------------------------------------------------------
// 1. The three failure classes: same guarantee, differing unacknowledged tail
// ---------------------------------------------------------------------------

#[test]
fn failure_classes_uphold_the_acknowledged_contract_with_differing_tails() {
    for &mode in &MODES {
        for fail_after in [4u64, 5] {
            // (class, retained_volatile_bytes, dropped_volatile_bytes, recovered_root)
            let mut seen = Vec::new();
            for &class in &FailureClass::ALL {
                let row = run_row(
                    mode,
                    class,
                    SimConfig::honest(1),
                    SEG,
                    fail_after,
                    0,
                    Vec::new(),
                );
                assert_contract(&row, &format!("{mode}/{class:?}"));
                assert!(
                    !row.refused(),
                    "{mode}/{class:?}: an honest profile refused: {:?}",
                    row.recovery
                );
                seen.push((
                    class,
                    row.report.retained_volatile_bytes,
                    row.report.total_dropped_volatile_bytes,
                    row.root(),
                ));
            }
            let get = |c: FailureClass| *seen.iter().find(|x| x.0 == c).expect("row");
            let storage = get(FailureClass::Storage);
            let kernel = get(FailureClass::Kernel);
            let process = get(FailureClass::Process);

            assert_eq!(storage.1, 0, "{mode}: Storage must retain nothing");
            assert_eq!(
                kernel.1, process.1,
                "{mode}: Process and Kernel retain alike"
            );
            if mode == DurabilityMode::Sync {
                // No un-flushed tail exists, so every class coincides.
                assert_eq!(storage.3, kernel.3);
                assert_eq!(kernel.3, process.3);
            } else {
                assert!(
                    kernel.1 > 0,
                    "{mode}: Kernel must retain the volatile tail (nothing was dropped)"
                );
                assert!(storage.2 > 0, "{mode}: Storage must drop the volatile tail");
                assert!(
                    storage.3 <= kernel.3 && kernel.3 == process.3,
                    "{mode}: retained-tail precedence violated: {storage:?} {kernel:?} {process:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Every acknowledged-durability mode: the whole fault matrix
// ---------------------------------------------------------------------------

#[test]
fn every_durability_mode_survives_the_fault_matrix() {
    for &mode in &MODES {
        for (_, cfg) in fault_profiles() {
            for fail_after in [4u64] {
                // (a) with an explicit durability point before the tail;
                // (b) without one (all acks unsynced for ordered/batched).
                for flush_at in [0u64, fail_after.saturating_sub(1)] {
                    let row = run_row(
                        mode,
                        FailureClass::Storage,
                        cfg,
                        SEG,
                        fail_after,
                        if mode == DurabilityMode::Sync {
                            0
                        } else {
                            flush_at
                        },
                        Vec::new(),
                    );
                    assert_contract(
                        &row,
                        &format!("{mode}/storage/{:?}/flush_at={flush_at}", cfg.durable_loss),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Delayed / in-flight completions
// ---------------------------------------------------------------------------

#[test]
fn an_in_flight_completion_is_never_treated_as_durable() {
    for &mode in &MODES {
        for skip in [0u64, 2] {
            for &class in &FailureClass::ALL {
                let row = run_in_flight(mode, class, SimConfig::honest(21), skip);
                // The commit that hit the in-flight completion failed with EAGAIN,
                // a transient (non-latching) outcome — it was never acknowledged.
                let errno = row
                    .in_flight_errno
                    .expect("an in-flight failure must be recorded");
                assert_eq!(
                    errno,
                    libc::EAGAIN,
                    "an in-flight completion must surface as EAGAIN (got {errno})"
                );
                assert_ne!(
                    row.subsequent_errno,
                    Some(libc::EROFS),
                    "an in-flight completion must not latch the volume read-only"
                );
                assert_contract(&row, &format!("in-flight/{mode}/{class:?}/skip={skip}"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Torn metadata specifically
// ---------------------------------------------------------------------------

#[test]
fn torn_metadata_is_detected_or_recovers_validly() {
    // (a) torn watermark: present-but-corrupt ⇒ must be detected (refused).
    let wm = run_row(
        DurabilityMode::Sync,
        FailureClass::Storage,
        SimConfig::torn_watermark(2),
        SEG,
        4,
        0,
        Vec::new(),
    );
    assert!(
        wm.refused(),
        "a torn watermark must be detected (open refused), never silently ignored: {:?}",
        wm.recovery
    );
    assert!(!wm.silent_shortening());

    // (b) torn directory entry, (c) torn interior framing metadata.
    for cfg in [
        SimConfig::torn_directory_entry(6),
        SimConfig::tear_interior(8),
    ] {
        for fail_after in [2u64, 4, 6] {
            let row = run_row(
                DurabilityMode::Sync,
                FailureClass::Storage,
                cfg,
                SEG,
                fail_after,
                0,
                Vec::new(),
            );
            assert!(
                !row.silent_shortening(),
                "torn metadata silently shortened history: {:?}",
                row.recovery
            );
            assert!(
                row.newest_valid_generation_selected(),
                "torn metadata left a partial generation selected: {:?}",
                row.recovery
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Repeated power loss with remount cycles
// ---------------------------------------------------------------------------

/// Run `cycles` power-fail → recover → continue → power-fail cycles over one
/// volume, asserting the §35 invariants after each cycle. Returns the per-cycle
/// recovered roots and whether every cycle was correct.
fn run_remount_cycles(
    mode: DurabilityMode,
    class: FailureClass,
    cfg: SimConfig,
    cycles: u32,
) -> (Vec<u64>, bool) {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().to_path_buf();
    drop(init_volume(&dir, SEG));
    let (_, mut baseline_bytes, mut baseline_segments) = baseline(&dir);

    let mut roots = Vec::new();
    let mut all_ok = true;
    for _ in 0..cycles {
        let log_dir = Volume::log_dir(&dir);
        let handle =
            powerloss::attach_with_class(&log_dir, cfg, class, Vec::new()).expect("attach");
        let mut acks = Vec::new();
        {
            let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("open cycle volume");
            let mut seq = CommitSequencer::new(&mut vol, mode);
            for _ in 0..3 {
                let tx = build_transaction(seq.peek_transaction_id(), 2);
                let out = seq.commit(tx).expect("cycle commit");
                acks.push(Ack {
                    tx: out.transaction_id,
                    root: out.root,
                    durable: out.durable,
                });
            }
        }
        handle.power_fail().expect("cycle power fail");
        let recovery = recover(&dir, &baseline_bytes, &baseline_segments);
        match &recovery {
            Recovery::Recovered {
                root, invariants, ..
            } => {
                all_ok &= invariants.all_ok();
                all_ok &= durable_roots(&acks).iter().all(|&d| d <= *root);
                roots.push(*root);
                // Re-baseline from the recovered state for the next cycle. (The
                // recovery step itself commits one fresh probe transaction.)
                let (_, bytes, segs) = baseline(&dir);
                baseline_bytes = bytes;
                baseline_segments = segs;
            }
            Recovery::Refused { .. } => {
                all_ok &= durable_roots(&acks).is_empty();
                roots.push(u64::MAX);
            }
        }
    }
    (roots, all_ok)
}

#[test]
fn repeated_power_loss_with_remounts_recovers_each_cycle() {
    for &class in &FailureClass::ALL {
        let (roots, ok) = run_remount_cycles(DurabilityMode::Sync, class, SimConfig::honest(1), 5);
        assert!(ok, "remount cycles diverged for {class:?}: roots {roots:?}");
        assert_eq!(roots.len(), 5);
        assert!(
            roots.windows(2).all(|w| w[0] <= w[1]),
            "a remount cycle withdrew committed history: {roots:?}"
        );
    }
    // Reordered writes and a lost flush across remounts.
    for cfg in [SimConfig::reordered(7), SimConfig::lost_watermark(17)] {
        let (roots, ok) = run_remount_cycles(DurabilityMode::Sync, FailureClass::Storage, cfg, 4);
        assert!(ok, "remount cycles diverged for {cfg:?}: roots {roots:?}");
        assert!(
            roots.windows(2).all(|w| w[0] <= w[1]),
            "a remount cycle withdrew committed history: {roots:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. The commit-watermark residual window, as an explicit property
// ---------------------------------------------------------------------------

#[test]
fn the_residual_window_is_an_explicit_property() {
    // `residual_window`: durable bytes that were never watermarked are lost while
    // the watermark stays behind. The loss is undetectable by construction, so
    // recovery proceeds to the surviving shorter root — recorded, not smoothed
    // over.
    let mut residual_losses = 0u32;
    for &mode in &[DurabilityMode::Sync, DurabilityMode::Ordered] {
        for fail_after in [3u64, 5, 7, 9] {
            let row = run_row(
                mode,
                FailureClass::Storage,
                SimConfig::residual_window(11),
                SEG,
                fail_after,
                0,
                Vec::new(),
            );
            // The watermark stays behind, so it can never *detect* the loss: the
            // outcome is either no loss at all, or an undetected (residual) loss.
            assert_ne!(
                row.residual_window(),
                "detected_refusal",
                "{mode}/{fail_after}: the watermark was behind and cannot refuse: {:?}",
                row.recovery
            );
            assert!(
                !row.silent_shortening(),
                "the residual window is documented, never an unclassified silent shortening"
            );
            assert!(row.newest_valid_generation_selected());
            if row.residual_window() == "undetectable_unwatermarked_tail" {
                residual_losses += 1;
            }
        }
    }
    assert!(
        residual_losses > 0,
        "the residual window profile must actually lose durable bytes at least once"
    );

    // Detection happens when the watermark is *ahead* of the surviving bytes.
    let mut detected = false;
    for seed in [4u64, 16, 64] {
        for fail_after in [3u64, 5, 7] {
            let row = run_row(
                DurabilityMode::Sync,
                FailureClass::Storage,
                SimConfig::tear(seed),
                SEG,
                fail_after,
                0,
                Vec::new(),
            );
            assert!(!row.silent_shortening());
            if row.refused() {
                detected = true;
            }
        }
    }
    assert!(
        detected,
        "a watermark ahead of the surviving bytes must be detected at least once"
    );
}

// ---------------------------------------------------------------------------
// 7. Machine-generated evidence (opt-in sweep)
// ---------------------------------------------------------------------------

/// The per-mode acknowledged-durability contract, as machine-readable rows.
fn per_mode_contract(runs: &[Row]) -> Value {
    let mut out = Vec::new();
    for &mode in &MODES {
        let rows: Vec<&Row> = runs.iter().filter(|r| r.mode == mode).collect();
        // The acknowledged contract holds when every contract-honouring row keeps
        // its acknowledged-durable data, every contract-violating loss is the
        // documented residual (or an explicit refusal), and the watermark is never
        // ignored.
        let all_ok = rows.iter().all(|r| {
            !r.silent_shortening()
                && (!is_honouring(&r.cfg) || r.ack_durable_survived())
                && (r.ack_durable_survived() || r.refused() || r.residual_window() != "none")
        });
        let (point, tail) = match mode {
            DurabilityMode::Sync => (
                "every commit (segment fsync + watermark write)",
                "nothing acknowledged may be lost",
            ),
            DurabilityMode::Ordered => (
                "an explicit flush / fsync",
                "ordered-but-unsynced mutations may be lost under Storage; they survive under Process/Kernel",
            ),
            DurabilityMode::Batched { .. } => (
                "every batch_size commits (amortised fsync)",
                "mutations within the current batch may be lost under Storage",
            ),
        };
        let residual = if rows
            .iter()
            .any(|r| r.residual_window() == "undetectable_unwatermarked_tail")
        {
            "undetectable_unwatermarked_tail"
        } else {
            "none"
        };
        out.push(json!({
            "mode": mode.name(),
            "acknowledged_durability_point": point,
            "may_be_lost_before_the_point": tail,
            "acknowledged_data_survives_all_classes": all_ok,
            "rows": rows.len(),
            "residual_window_seen": residual,
        }));
    }
    Value::Array(out)
}

fn build_matrix() -> Vec<Row> {
    let fail_afters: [u64; 4] = [2, 3, 5, 8];
    let mut rows = Vec::new();

    // Three classes × honest profiles.
    for &mode in &MODES {
        for (_, cfg) in honest_profiles() {
            for &fa in &fail_afters {
                for &class in &FailureClass::ALL {
                    rows.push(run_row(mode, class, cfg, SEG, fa, 0, Vec::new()));
                }
            }
        }
    }

    // Storage class × the extended fault matrix, with and without an explicit
    // durability point before the tail (ordered/batched).
    for &mode in &MODES {
        for (_, cfg) in fault_profiles() {
            for &fa in &fail_afters {
                let flush_choices: [u64; 2] = if mode == DurabilityMode::Sync {
                    [0, 0]
                } else {
                    [0, fa.saturating_sub(1)]
                };
                for flush_at in flush_choices {
                    rows.push(run_row(
                        mode,
                        FailureClass::Storage,
                        cfg,
                        SEG,
                        fa,
                        flush_at,
                        Vec::new(),
                    ));
                }
            }
        }
    }

    // In-flight completions.
    for &mode in &MODES {
        for skip in [0u64, 1, 2] {
            for &class in &FailureClass::ALL {
                rows.push(run_in_flight(mode, class, SimConfig::honest(21), skip));
            }
        }
    }
    rows
}

#[test]
fn write_durability_qualification_evidence() {
    if std::env::var("ORFS_DQ_SWEEP").is_err() {
        eprintln!("skip: set ORFS_DQ_SWEEP=1 (run scripts/container-durability-qualification.sh)");
        return;
    }

    let rows = build_matrix();

    // Every row must satisfy the contract; only then is the receipt written.
    for r in &rows {
        assert_contract(
            r,
            &format!(
                "sweep/{}/{}/{:?}",
                r.mode,
                r.class.name(),
                r.cfg.durable_loss
            ),
        );
    }

    let matrix: Vec<Value> = rows.iter().map(row_json).collect();
    let all_newest = rows.iter().all(|r| r.newest_valid_generation_selected());
    let any_silent = rows.iter().any(|r| r.silent_shortening());
    // The acknowledged contract: every contract-honouring device preserves
    // acknowledged-durable data, and every loss under a contract-violating device
    // is the documented residual window (or an explicit refusal).
    let all_ack = rows
        .iter()
        .all(|r| !is_honouring(&r.cfg) || r.ack_durable_survived());
    let unclassified_losses = rows
        .iter()
        .filter(|r| !r.ack_durable_survived() && r.residual_window() == "none" && !r.refused())
        .count();
    let detected_refusals = rows.iter().filter(|r| r.refused()).count();
    let residual_undetectable = rows
        .iter()
        .filter(|r| r.residual_window() == "undetectable_unwatermarked_tail")
        .count();
    let honouring_rows = rows.iter().filter(|r| is_honouring(&r.cfg)).count();

    // The explicit multi-cycle verdict, re-run for the receipt.
    let mut remount = Vec::new();
    for &class in &FailureClass::ALL {
        let (roots, ok) = run_remount_cycles(DurabilityMode::Sync, class, SimConfig::honest(1), 5);
        remount.push(json!({
            "failure_class": class.name(),
            "cycles": 5,
            "roots": roots,
            "all_ok": ok,
        }));
    }

    let evidence = json!({
        "schema": "orfs.recovery.durability-qualification.v1",
        "generated_by": "tests/durability_qualification.rs",
        "evidence_kind": "simulated durability qualification (NOT real hardware)",
        "commit": git_commit(),
        "environment": environment(),
        "failure_classes": [
            {
                "name": "process",
                "loses": ["userspace_buffers"],
                "retains": ["os_page_cache"],
                "assumptions": "A clean-ish process kill (SIGKILL/abort): only the process's own buffers are lost; every byte that completed a write syscall survives in the OS page cache. The strongest class (tests/crash_recovery.rs)."
            },
            {
                "name": "kernel",
                "loses": ["userspace_buffers", "os_page_cache"],
                "retains": ["device_write_back_cache"],
                "assumptions": "A kernel panic/reboot: userspace buffers and the OS page cache are lost; bytes the device already accepted survive because the device write-back cache is not lost; writes may be reordered."
            },
            {
                "name": "storage",
                "loses": ["userspace_buffers", "os_page_cache", "device_write_back_cache"],
                "retains": ["flushed_image"],
                "assumptions": "An un-clean storage power loss: only flushed bytes survive, and per the flush/durable-loss profile writes may be reordered, partially applied, or torn (src/powerloss.rs, Phases 17/23)."
            }
        ],
        "precedence": "retained(process) superset retained(kernel) superset retained(storage); the acknowledged-durability contract holds for every class while the unacknowledged tail differs",
        "durability_modes": MODES.iter().map(|m| m.name()).collect::<Vec<_>>(),
        "newest_valid_generation_selected": all_newest,
        "silent_shortening": any_silent,
        "acknowledged_data_survived_all": all_ack,
        "unclassified_durable_losses": unclassified_losses,
        "contract_honouring_rows": honouring_rows,
        "detected_refusals": detected_refusals,
        "residual_window_undetectable": residual_undetectable,
        "matrix_rows": matrix.len(),
        "remount_cycles": 5,
        "remount": remount,
        "per_mode_contract": per_mode_contract(&rows),
        "residual_property": {
            "detectable": "a commit watermark ahead of the surviving committed bytes (a lost/truncated trailing committed segment) is DETECTED: the open is refused, never silently shortened",
            "undetectable": "the loss of durable bytes between the last persisted watermark and the committed root is UNDETECTED by the watermark alone (the documented residual window; docs/LIMITATIONS.md 6, docs/RECOVERY.md 5)",
            "residual_window_seen": rows.iter().any(|r| r.residual_window() == "undetectable_unwatermarked_tail"),
            "can_be_strengthened": false,
            "reason": "The watermark is written AFTER the bytes it describes and is never allowed to rewrite committed history (non-withdrawal). Detecting the loss of those not-yet-watermarked bytes would require an additional synchronous metadata write on the acknowledgment path (changing the durability contract and cost) or rewriting committed bytes (forbidden). The gap is inherent to any scheme that cannot rewrite committed history, so it is recorded as an explicit property rather than claimed closed."
        },
        "dm_probe": dm_probe(),
        "model_assumptions": [
            "This is a deterministic, in-process simulated device (src/powerloss.rs), not hardware. A green run shows recovery correct relative to the model's assumed device semantics; it does not prove real-hardware durability.",
            "The distinguished failure classes differ only in which volatile layer is lost, and therefore in how many un-flushed bytes are retained: Process (page cache) >= Kernel (device cache) >= Storage (nothing).",
            "For OrFS, Process and Kernel retain the same bytes: the commit path has no acknowledged-but-unwritten userspace data, so the two coincide for the acknowledged contract; they differ only in that Kernel may reorder the retained writes.",
            "An in-flight completion (a sync that never completed) surfaces as OrfsError::InFlight (EAGAIN): transient, non-latching, never durable.",
            "Metadata tearing targets the watermark, a directory entry, and an interior framing sector of a committed segment -- not only a file's trailing sector.",
            "The generation manifest / catalogue lives outside the log directory and is therefore not modelled by the log-directory device; it is covered by the manifestation courts (Phases 42/78)."
        ],
        "matrix": matrix,
    });

    support::write_json(
        &manifest_dir().join("evidence/recovery/durability-qualification.json"),
        &evidence,
    );
    assert!(!any_silent, "the sweep observed a silent shortening");
    assert!(all_ack, "the sweep lost an acknowledged-durable mutation");
    assert_eq!(
        unclassified_losses, 0,
        "the sweep observed an unclassified durable loss"
    );
}
