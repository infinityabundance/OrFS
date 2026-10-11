//! Phase 17 **simulated power-loss court** (research §22 durability modes, §26
//! committed-root visibility, §37 crash/adversarial courts).
//!
//! The process-crash court (`tests/crash_recovery.rs`) kills the process, but the
//! OS page cache survives, so it cannot model lost write-back caches, reordering,
//! or torn sectors. This court runs a **whole OrFS volume on a deterministic,
//! simulated storage device** (`orfs::powerloss`) whose volatile write-back cache
//! is configurable, then triggers a simulated un-clean power failure and recovers
//! in an independent step.
//!
//! The device model is *simulated*, not real hardware; see `docs/POWERLOSS.md` and
//! the `model_assumptions` recorded in `evidence/recovery/power-loss.json`. A
//! green run proves OrFS's recovery is correct **relative to the model's assumed
//! device semantics**; it does not prove real-hardware durability.

#![cfg(feature = "powerloss")]

mod support;

use std::path::Path;

use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::log::OpenMode;
use orfs::powerloss::{self, DurableLoss, PowerFailReport, SimConfig};
use orfs::record::RecordType;
use orfs::segment::segment_file_name;
use orfs::volume::Volume;

use support::{build_transaction, init_volume, snapshot_segments, SegmentSnapshot};
use tempfile::TempDir;

/// Small segment size so a short workload rolls over at least once.
const SEG: u64 = 1024;
/// A large segment size so a short workload stays within one segment and the
/// durability semantics are not masked by rollover (which must flush the
/// departing segment).
const SEG_LARGE: u64 = 1 << 20;

// ---------------------------------------------------------------------------
// Experiment machinery
// ---------------------------------------------------------------------------

/// One acknowledged mutation: its id, the committed root it produced, and
/// whether OrFS acknowledged it as *durable* (an `fsync` completed).
#[derive(Debug, Clone)]
struct Ack {
    tx: u64,
    root: u64,
    durable: bool,
}

/// Machine-checkable post-power-failure invariants (research §35).
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

/// The independent recovery outcome.
#[derive(Debug, Clone, serde::Serialize)]
enum Recovery {
    Recovered {
        root: u64,
        invariants: Invariants,
        /// The committed root the surviving durable watermark certifies, if any.
        durable_watermark_root: Option<u64>,
    },
    Refused {
        error: String,
    },
}

impl Recovery {
    fn recovered_root(&self) -> Option<u64> {
        match self {
            Recovery::Recovered { root, .. } => Some(*root),
            Recovery::Refused { .. } => None,
        }
    }
}

struct Experiment {
    mode: DurabilityMode,
    cfg: SimConfig,
    fail_after: u64,
    baseline_root: u64,
    acks: Vec<Ack>,
    report: PowerFailReport,
    recovery: Recovery,
}

fn durable_roots(acks: &[Ack]) -> Vec<u64> {
    acks.iter().filter(|a| a.durable).map(|a| a.root).collect()
}

fn unsynced_roots(acks: &[Ack]) -> Vec<u64> {
    acks.iter().filter(|a| !a.durable).map(|a| a.root).collect()
}

/// Capture the committed state before any workload (the durable base image).
fn baseline(dir: &Path) -> (u64, Vec<u8>, Vec<SegmentSnapshot>) {
    let vol = Volume::open(dir, OpenMode::ReadOnly).expect("open baseline");
    (
        vol.log.committed_end_offset(),
        vol.log.read_committed_bytes().expect("baseline bytes"),
        snapshot_segments(&vol.log),
    )
}

/// Independently reopen the powered-down volume and check the §35 invariants.
///
/// `ReadOnly` is used for measurement (it never mutates the volume), then a
/// `ReadWrite` open commits one fresh transaction to prove progress.
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

/// Run one experiment: initialise a volume, attach the simulated device, commit
/// `fail_after` transactions, power-fail, then recover independently.
fn run_experiment(mode: DurabilityMode, cfg: SimConfig, seg: u64, fail_after: u64) -> Experiment {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().to_path_buf();
    drop(init_volume(&dir, seg));
    let (baseline_root, baseline_bytes, baseline_segments) = baseline(&dir);

    let log_dir = Volume::log_dir(&dir);
    let handle = powerloss::attach(&log_dir, cfg).expect("attach device");

    let acks = {
        let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("open workload volume");
        let mut seq = CommitSequencer::new(&mut vol, mode);
        let mut acks = Vec::new();
        for _ in 0..fail_after {
            let tx = build_transaction(seq.peek_transaction_id(), 2);
            let out = seq.commit(tx).expect("commit");
            acks.push(Ack {
                tx: out.transaction_id,
                root: out.root,
                durable: out.durable,
            });
        }
        acks
    };

    let report = handle.power_fail().expect("power fail");
    let recovery = recover(&dir, &baseline_bytes, &baseline_segments);
    Experiment {
        mode,
        cfg,
        fail_after,
        baseline_root,
        acks,
        report,
        recovery,
    }
}

fn volume_has_prefix(dir: &Path, baseline_bytes: &[u8]) -> bool {
    let vol = Volume::open(dir, OpenMode::ReadOnly).expect("open");
    let now = vol.log.read_committed_bytes().expect("bytes");
    now.len() >= baseline_bytes.len() && now[..baseline_bytes.len()] == *baseline_bytes
}

// ---------------------------------------------------------------------------
// 1. `sync`: every acknowledged-durable mutation survives
// ---------------------------------------------------------------------------

#[test]
fn sync_durable_acknowledgements_survive_power_loss() {
    for seed in [1u64, 7, 99] {
        for fail_after in [1u64, 2, 3, 5, 8] {
            let e = run_experiment(
                DurabilityMode::Sync,
                SimConfig::honest(seed),
                SEG,
                fail_after,
            );
            let Recovery::Recovered {
                root, invariants, ..
            } = e.recovery
            else {
                panic!(
                    "sync (seed {seed}, after {fail_after}) refused: {:?}",
                    e.recovery
                );
            };
            assert!(
                invariants.all_ok(),
                "sync invariants failed: {invariants:?}"
            );
            assert!(e.acks.iter().all(|a| a.durable), "sync ack not durable");
            assert_eq!(
                root,
                e.acks.last().expect("acks").root,
                "sync must survive every acknowledged-durable mutation"
            );
            for a in &e.acks {
                assert!(root >= a.root, "acknowledged root {} missing", a.root);
            }
            assert_eq!(e.report.total_dropped_volatile_bytes, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// 2. `ordered` / `batched`: unsynced acks may be lost, never corrupt
// ---------------------------------------------------------------------------

#[test]
fn ordered_acknowledgements_may_be_lost_but_committed_state_is_intact() {
    for fail_after in [2u64, 4, 6] {
        let e = run_experiment(
            DurabilityMode::Ordered,
            SimConfig::honest(5),
            SEG_LARGE,
            fail_after,
        );
        let Recovery::Recovered {
            root, invariants, ..
        } = e.recovery
        else {
            panic!("ordered refused: {:?}", e.recovery);
        };
        assert!(
            invariants.all_ok(),
            "ordered invariants failed: {invariants:?}"
        );
        assert!(
            e.acks.iter().all(|a| !a.durable),
            "ordered must not ack durable"
        );
        assert_eq!(
            root, e.baseline_root,
            "ordered must not expose unflushed data"
        );
        assert!(root < e.acks.last().expect("acks").root);
        assert!(durable_roots(&e.acks).is_empty());
        assert!(e.report.total_dropped_volatile_bytes > 0);
    }
}

#[test]
fn batched_acknowledgements_survive_up_to_the_last_sync_point() {
    let mode = DurabilityMode::Batched { batch_size: 3 };
    for fail_after in [3u64, 4, 5, 6, 7] {
        let e = run_experiment(mode, SimConfig::honest(11), SEG_LARGE, fail_after);
        let Recovery::Recovered {
            root, invariants, ..
        } = e.recovery
        else {
            panic!("batched refused: {:?}", e.recovery);
        };
        assert!(
            invariants.all_ok(),
            "batched invariants failed: {invariants:?}"
        );
        let expected = durable_roots(&e.acks).last().copied();
        match expected {
            Some(r) => assert_eq!(root, r, "batched must survive the last sync point"),
            None => assert_eq!(root, e.baseline_root),
        }
        for a in &e.acks {
            if a.durable {
                assert!(root >= a.root);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. The accepted contract, explicitly
// ---------------------------------------------------------------------------

/// Under `ordered`, a mutation acknowledged without a sync **may be absent** after
/// a power failure, but the committed state it extended stays intact and
/// consistent: a whole committed prefix, never a partial transaction.
#[test]
fn an_unsynced_ack_may_be_lost_but_never_corrupts_committed_state() {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().to_path_buf();
    drop(init_volume(&dir, SEG_LARGE));
    let (baseline_root, baseline_bytes, baseline_segments) = baseline(&dir);
    let log_dir = Volume::log_dir(&dir);
    let handle = powerloss::attach(&log_dir, SimConfig::honest(21)).expect("attach");

    let (acks, flush_root) = {
        let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("open");
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        let mut acks = Vec::new();
        for _ in 0..4 {
            let tx = build_transaction(seq.peek_transaction_id(), 2);
            let out = seq.commit(tx).expect("commit");
            acks.push(Ack {
                tx: out.transaction_id,
                root: out.root,
                durable: out.durable,
            });
        }
        let synced = seq.flush().expect("explicit flush");
        // Three more acked-but-unsynced mutations.
        for _ in 0..3 {
            let tx = build_transaction(seq.peek_transaction_id(), 2);
            let out = seq.commit(tx).expect("commit");
            acks.push(Ack {
                tx: out.transaction_id,
                root: out.root,
                durable: out.durable,
            });
        }
        (acks, synced.root)
    };

    handle.power_fail().expect("power fail");
    let recovery = recover(&dir, &baseline_bytes, &baseline_segments);
    let Recovery::Recovered {
        root, invariants, ..
    } = recovery
    else {
        panic!("refused: {recovery:?}");
    };
    assert!(invariants.all_ok(), "invariants failed: {invariants:?}");
    // The explicit fsync made everything up to the flush durable: it survives.
    assert_eq!(root, flush_root, "flushed data must survive");
    assert!(flush_root > baseline_root);
    // The memory-acked, unsynced mutations may be absent...
    let unsynced: Vec<u64> = acks
        .iter()
        .filter(|a| a.root > flush_root)
        .map(|a| a.root)
        .collect();
    assert_eq!(unsynced.len(), 3);
    assert!(unsynced.iter().all(|&r| r > root), "unsynced data appeared");
    // ...but they never corrupted anything: the recovered root is a boundary and
    // the committed prefix is intact.
    assert!(volume_has_prefix(&dir, &baseline_bytes));
}

// ---------------------------------------------------------------------------
// 4. Hostile profiles: partial / reordered flushes and torn durable bytes
// ---------------------------------------------------------------------------

#[test]
fn partial_and_reordered_flushes_recover_or_refuse_but_never_corrupt() {
    let profiles = [
        SimConfig::partial(3),
        SimConfig::reordered_partial(3),
        SimConfig::partial(8),
        SimConfig::reordered_partial(21),
    ];
    for cfg in profiles {
        for fail_after in [2u64, 4, 7] {
            let e = run_experiment(DurabilityMode::Sync, cfg, SEG, fail_after);
            match &e.recovery {
                Recovery::Recovered {
                    root, invariants, ..
                } => {
                    assert!(
                        invariants.all_ok(),
                        "partial/reordered invariants failed ({cfg:?}, after {fail_after}): {invariants:?}"
                    );
                    assert!(*root >= e.baseline_root, "history withdrew below baseline");
                }
                // A device that did not finish its flush may leave a torn interior
                // segment: recovery must *refuse*, never silently repair.
                Recovery::Refused { .. } => {}
            }
        }
    }
}

#[test]
fn torn_flushed_bytes_recover_or_refuse_consistently() {
    for seed in [4u64, 16, 64] {
        for fail_after in [1u64, 3, 6] {
            let e = run_experiment(DurabilityMode::Sync, SimConfig::tear(seed), SEG, fail_after);
            match &e.recovery {
                Recovery::Recovered {
                    root, invariants, ..
                } => {
                    assert!(
                        invariants.all_ok(),
                        "tear invariants failed (seed {seed}, after {fail_after}): {invariants:?}"
                    );
                    assert!(*root <= e.acks.last().expect("acks").root);
                }
                Recovery::Refused { .. } => {}
            }
            assert!(e.report.total_torn_durable_bytes > 0);
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Durability-watermark interaction
// ---------------------------------------------------------------------------

/// A power loss in the window between the segment `fsync` and the watermark
/// `fsync` leaves the watermark behind the durable bytes. The loss of those
/// not-yet-watermarked bytes is undetectable by construction (the documented
/// residual window), so recovery proceeds — to the durable committed root, which
/// here is the final root because the segment bytes themselves are durable.
#[test]
fn power_loss_between_segment_and_watermark_fsync_recovers_forward_consistently() {
    let e = run_experiment(DurabilityMode::Sync, SimConfig::lost_watermark(17), SEG, 5);
    let Recovery::Recovered {
        root,
        invariants,
        durable_watermark_root,
    } = e.recovery
    else {
        panic!("refused: {:?}", e.recovery);
    };
    assert!(invariants.all_ok(), "invariants failed: {invariants:?}");
    assert_eq!(root, e.acks.last().expect("acks").root);
    // The watermark never certifies more than survives: it is at or behind root.
    if let Some(wm) = durable_watermark_root {
        assert!(wm <= root, "watermark {wm} ahead of surviving root {root}");
    }
}

/// The complementary case: durable segment bytes are lost while the watermark
/// survives, so the watermark certifies *more* than the surviving bytes. OrFS
/// must detect this and refuse rather than silently recover a shorter history (or
/// recover to a valid earlier boundary when the loss is confined to the tail).
#[test]
fn a_watermark_ahead_of_surviving_bytes_is_refused_or_recovered_validly() {
    for seed in [2u64, 12, 40] {
        for fail_after in [2u64, 4, 6] {
            let e = run_experiment(DurabilityMode::Sync, SimConfig::tear(seed), SEG, fail_after);
            match &e.recovery {
                Recovery::Recovered {
                    root, invariants, ..
                } => {
                    assert!(invariants.all_ok(), "invariants failed: {invariants:?}");
                    assert!(*root <= e.acks.last().expect("acks").root);
                }
                Recovery::Refused { error } => {
                    assert!(
                        error.contains("watermark") || error.contains("corrupt"),
                        "refusal should name corruption/watermark: {error}"
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Logical content consistency across a power loss
// ---------------------------------------------------------------------------

#[test]
fn surviving_logical_content_is_consistent_after_power_loss() {
    use orfs::index::ROOT_INODE;
    use orfs::namespace::Namespace;

    let td = TempDir::new().expect("tempdir");
    let dir = td.path().to_path_buf();
    drop(init_volume(&dir, 2048));
    let log_dir = Volume::log_dir(&dir);
    let handle = powerloss::attach(&log_dir, SimConfig::honest(31)).expect("attach");

    let files: Vec<(Vec<u8>, Vec<u8>)> = (0..6u8)
        .map(|i| {
            let name = format!("f{i}").into_bytes();
            let data = vec![i.wrapping_mul(17).wrapping_add(3); 40 + i as usize];
            (name, data)
        })
        .collect();

    {
        let mut ns =
            Namespace::open(&dir, OpenMode::ReadWrite, DurabilityMode::Sync).expect("open ns");
        for (name, data) in &files {
            let ino = ns
                .create(ROOT_INODE, name, 0o644, 0, 0)
                .expect("create file");
            ns.write_at(ino, 0, data).expect("write file");
        }
        ns.sync().expect("sync namespace");
        assert_eq!(ns.root(), ns.volume().log.committed_end_offset());
    }

    handle.power_fail().expect("power fail");

    let ns = Namespace::open(&dir, OpenMode::ReadOnly, DurabilityMode::Sync).expect("reopen ns");
    let root = ns.root();
    assert!(ns.volume().log.is_boundary(root));
    // sync mode flushed everything: every file survives with byte-exact content,
    // and no partially written or inconsistent file is ever visible.
    for (name, data) in &files {
        let ino = ns
            .lookup(ROOT_INODE, name, root)
            .unwrap_or_else(|e| panic!("file {} missing: {e}", String::from_utf8_lossy(name)));
        let got = ns.read_at(ino, root, 0, data.len() as u32).expect("read");
        assert_eq!(
            got,
            *data,
            "file {} has inconsistent content after power loss",
            String::from_utf8_lossy(name)
        );
    }
}

// ---------------------------------------------------------------------------
// 7. Machine-generated evidence
// ---------------------------------------------------------------------------

fn experiment_json(e: &Experiment) -> serde_json::Value {
    let recovered_root = e.recovery.recovered_root();
    let surviving_durable = match recovered_root {
        Some(root) => durable_roots(&e.acks)
            .into_iter()
            .filter(|&r| r <= root)
            .count(),
        None => 0,
    };
    serde_json::json!({
        "durability_mode": e.mode.name(),
        "profile": e.cfg,
        "fail_after_transactions": e.fail_after,
        "baseline_root": e.baseline_root,
        "acknowledged_transaction_ids": e.acks.iter().map(|a| a.tx).collect::<Vec<_>>(),
        "acknowledged_durable_roots": durable_roots(&e.acks),
        "acknowledged_unsynced_roots": unsynced_roots(&e.acks),
        "final_acknowledged_root": e.acks.last().map(|a| a.root),
        "surviving_durable_mutations": surviving_durable,
        "recovery": e.recovery,
        "power_fail_report": e.report,
    })
}

#[test]
fn write_power_loss_evidence() {
    let mut matrix = Vec::new();

    // sync, honest: durable acks must all survive.
    for seed in [1u64, 2, 3] {
        for fail_after in [1u64, 3, 6] {
            matrix.push(experiment_json(&run_experiment(
                DurabilityMode::Sync,
                SimConfig::honest(seed),
                SEG,
                fail_after,
            )));
        }
    }
    // ordered / batched, honest: unsynced acks may be lost.
    for fail_after in [2u64, 4, 6] {
        matrix.push(experiment_json(&run_experiment(
            DurabilityMode::Ordered,
            SimConfig::honest(5),
            SEG_LARGE,
            fail_after,
        )));
    }
    let batched = DurabilityMode::Batched { batch_size: 3 };
    for fail_after in [3u64, 5, 7] {
        matrix.push(experiment_json(&run_experiment(
            batched,
            SimConfig::honest(11),
            SEG_LARGE,
            fail_after,
        )));
    }
    // Hostile profiles: partial / reordered / torn.
    for cfg in [SimConfig::partial(3), SimConfig::reordered_partial(3)] {
        for fail_after in [3u64, 6] {
            matrix.push(experiment_json(&run_experiment(
                DurabilityMode::Sync,
                cfg,
                SEG,
                fail_after,
            )));
        }
    }
    for seed in [4u64, 16] {
        matrix.push(experiment_json(&run_experiment(
            DurabilityMode::Sync,
            SimConfig::tear(seed),
            SEG,
            4,
        )));
    }
    // Watermark interaction.
    matrix.push(experiment_json(&run_experiment(
        DurabilityMode::Sync,
        SimConfig::lost_watermark(17),
        SEG,
        5,
    )));

    // A recovered entry must satisfy every invariant; a refusal is an explicit,
    // consistent *detection* (no silent repair) and is acceptable for hostile
    // profiles. The honest barrier profiles must never refuse.
    let recovered_entry_ok = |m: &serde_json::Value| -> bool {
        match m["recovery"].get("Recovered") {
            Some(rec) => rec
                .get("invariants")
                .and_then(|inv| inv.as_object())
                .map(|inv| inv.values().all(|v| v == &serde_json::Value::Bool(true)))
                .unwrap_or(false),
            None => true,
        }
    };
    let all_ok = matrix.iter().all(recovered_entry_ok);
    let honest_profiles_never_refuse = matrix
        .iter()
        .filter(|m| {
            let p = &m["profile"];
            p["flush"] == "barrier"
                && (p["durable_loss"] == "none" || p["durable_loss"] == "lost_watermark")
        })
        .all(|m| m["recovery"].get("Recovered").is_some());

    let evidence = serde_json::json!({
        "schema": "orfs.evidence.power-loss.v1",
        "generator": "tests/power_loss.rs",
        "evidence_kind": "simulated power-loss (NOT real hardware)",
        "device_model": {
            "kind": "deterministic in-process write-back cache with a configurable flush and power-fail",
            "flush_modes": ["barrier", "partial", "reordered_partial"],
            "durable_loss_modes": ["none", "tear_tail", "lost_watermark"],
            "assertion_policy": "barrier+none asserts ack survival; partial/reordered/torn assert safety only (recover-or-refuse, never corrupt)"
        },
        "model_assumptions": [
            "Writes are captured per log file in a volatile cache and written through to the real file so in-session reads are correct.",
            "Only a flush/fsync promotes cached writes to the durable image; its behaviour is configurable (barrier vs partial vs reordered-partial).",
            "A 'barrier' fsync is an honoured durability barrier: the profile under which a sync-mode acknowledgement must survive.",
            "'partial'/'reordered_partial'/'tear_tail' model hardware that violated its documented contract (or a power cut during the flush whose completion the caller never received); they assert safety, not ack survival.",
            "power_fail() discards every un-flushed cached write, optionally tears the trailing sector of the durable image, materialises the surviving image to the real directory, and detaches for an independent recovery.",
            "The commit watermark is modelled as atomic (all-or-nothing), matching its write-tmp/rename/fsync implementation.",
            "All randomness is seeded and consumed in a fixed order, so a run reproduces exactly.",
            "This does NOT prove real-hardware durability; it proves OrFS recovery is correct relative to these assumed device semantics."
        ],
        "all_invariants_ok": all_ok,
        "honest_profiles_never_refuse": honest_profiles_never_refuse,
        "matrix": matrix,
    });

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/recovery/power-loss.json");
    support::write_json(&path, &evidence);
    assert!(
        all_ok,
        "power-loss evidence contains a failed invariant verdict"
    );
    assert!(
        honest_profiles_never_refuse,
        "an honest (barrier) profile refused recovery"
    );
}

#[test]
fn tear_profile_reports_torn_bytes() {
    let e = run_experiment(DurabilityMode::Sync, SimConfig::tear(1), SEG, 3);
    assert_eq!(e.report.config.durable_loss, DurableLoss::TearTail);
    assert!(e.report.total_torn_durable_bytes > 0);
}
