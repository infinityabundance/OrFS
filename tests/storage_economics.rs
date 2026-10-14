//! **Phase 75 — the storage-economics court.**
//!
//! The point of this phase is to make *indefinite retention* predictable and
//! budgetable, never to reclaim authoritative history. Two claims are made
//! executable here:
//!
//! 1. **Separated accounting.** Every byte beneath a volume belongs to exactly one
//!    of four non-overlapping categories — permanent authoritative history,
//!    rebuildable manifestations, metadata, and temporary construction space — so
//!    the four totals sum to the observed on-disk total of the volume's own files.
//!    This mirrors the Kafka tiered-storage discipline (KIP-405): keep metadata
//!    strongly consistent and *separate* from the data tier, and make the derived
//!    tier idempotent and rebuildable.
//! 2. **A validated forecast.** Given a written-bytes rate and an overwrite ratio,
//!    the model predicts retained-authority growth and time-to-full. The crux is
//!    that an **overwrite still appends** (non-withdrawal), so retained growth
//!    tracks *written* bytes, not *live* bytes — exactly the amplification the
//!    endurance court (Phase 69) measured. The model is therefore *falsifiable*,
//!    and this court validates the prediction against the measured growth, with a
//!    stated tolerance.
//!
//! ## What it does
//!
//! A deterministic workload writes `initial_mib` MiB of **new** content, then
//! `overwrite_mib` MiB into **already-written** logical ranges (content-neutral:
//! the live content is byte-identical before and after). The workload is run in
//! two arms over the *same* history: **authoritative** (manifestation disabled)
//! and **manifested** (EKBLOOM enabled), so the accounting table shows the
//! rebuildable tier appearing without changing authority (the two arms' committed
//! roots are asserted identical).
//!
//! * Calibration: the new-content phase yields the framing amplification
//!   `phi = retained_authority_growth / logical_bytes_written` and
//!   `bytes_per_transaction`.
//! * Prediction: the overwrite phase's retained growth is predicted as
//!   `phi * logical_bytes_written` (equivalently `bytes_per_transaction * tx`).
//! * Validation: the measured growth must match the prediction within tolerance,
//!   while the **live** logical growth is zero — the naive live-bytes model is
//!   thereby falsified.
//!
//! ## Running it
//!
//! * `cargo test --test storage_economics` runs the always-on smoke.
//! * The full sweep is opt-in behind `ORFS_STORAGE_ECONOMICS=1` and writes
//!   `evidence/performance/storage-economics.json`. Run it (release,
//!   representative) via `scripts/container-storage-economics.sh`.

use std::path::{Path, PathBuf};
use std::time::Instant;

use orfs::capacity::{ForecastInputs, StorageAccounting};
use orfs::commit::DurabilityMode;
use orfs::log::OpenMode;
use orfs::manifestation::{ManifestationConfig, ManifestationProfile};
use orfs::namespace::Namespace;
use orfs::volume::Volume;
use tempfile::TempDir;

/// A fixed volume identity makes the authoritative history byte-reproducible, so
/// the two arms build the *same* history and their committed roots must agree.
const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x45, 0x01, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const CREATED: u64 = 1_700_000_000;
/// A small segment size so the authoritative log rolls over within the bounded
/// run (the default is 64 MiB).
const SEGMENT: u64 = 256 * 1024;
const MIB: u64 = 1024 * 1024;
/// The stated tolerance for the predicted-vs-measured retained growth.
const TOLERANCE: f64 = 0.05;

#[derive(Clone, Copy)]
struct Workload {
    /// Number of regular files.
    objects: usize,
    /// Initial logical size of each file, in MiB.
    object_mib: u64,
    /// Bytes per write transaction.
    write_len: u64,
    /// MiB written as **new** content (the calibration phase).
    initial_mib: u64,
    /// MiB written into **already-written** ranges (the validation phase).
    overwrite_mib: u64,
    /// Whether the manifested arm (EKBLOOM) is enabled.
    manifested: bool,
}

fn smoke_workload() -> Workload {
    Workload {
        objects: 2,
        object_mib: 1,
        write_len: 16 * 1024,
        initial_mib: 1,
        overwrite_mib: 1,
        manifested: true,
    }
}

fn sweep_workload() -> Workload {
    Workload {
        objects: 4,
        object_mib: 4,
        write_len: 64 * 1024,
        initial_mib: 8,
        overwrite_mib: 8,
        manifested: true,
    }
}

/// The deterministic logical content of every object. Every write in the court
/// writes a slice of exactly these bytes, so a rewrite is content-neutral.
fn content_at(offset: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|j| (((offset + j as u64) * 131 + 17) % 251) as u8)
        .collect()
}

/// The number of `write_len`-sized transactions a MiB count needs.
fn txns(mib: u64, write_len: u64) -> u64 {
    (mib * MIB) / write_len
}

struct ArmResult {
    /// The committed roots at the phase boundaries.
    root_start: u64,
    root_after_calibration: u64,
    root_after_overwrite: u64,
    /// Committed transaction counts at the phase boundaries.
    tx_start: u64,
    tx_after_calibration: u64,
    tx_after_overwrite: u64,
    /// Logical bytes written in each phase.
    written_calibration: u64,
    written_overwrite: u64,
    /// Live logical bytes before and after the overwrite phase (must be equal).
    live_before_overwrite: u64,
    live_after_overwrite: u64,
    /// The four-category accounting after the overwrite phase.
    accounting: StorageAccounting,
    /// The full economics report (accounting + forecast) after the run.
    economics: serde_json::Value,
    /// Verdicts at ok / warn / exhausted reserves.
    verdicts: (String, String, String),
    wall_micros: u128,
}

/// Build the deterministic history and run both phases. `manifested` selects the
/// manifested arm (plane enabled) or the authoritative baseline (plane disabled).
fn run_arm(dir: &Path, wl: &Workload) -> ArmResult {
    let start = Instant::now();
    let mut ns = Namespace::init_with_uuid(dir, SEGMENT, UUID, CREATED, DurabilityMode::Ordered)
        .expect("init namespace");
    let root_ino = ns.root_inode();

    let mut inodes = Vec::with_capacity(wl.objects);
    let mut sizes = Vec::with_capacity(wl.objects);
    for i in 0..wl.objects {
        let name = format!("obj{i}");
        let ino = ns
            .create(root_ino, name.as_bytes(), 0o644, 0, 0)
            .expect("create object");
        let mut off = 0;
        while off < wl.object_mib * MIB {
            let n = wl.write_len.min(wl.object_mib * MIB - off);
            ns.write_at(ino, off, &content_at(off, n as usize))
                .expect("initial write");
            off += n;
        }
        inodes.push(ino);
        sizes.push(wl.object_mib * MIB);
    }
    ns.sync().expect("sync initial content");

    if wl.manifested {
        ns.enable_manifestation(ManifestationConfig {
            workers: 1,
            queue_capacity: 32,
            synchronous: true,
            profile: ManifestationProfile::Full,
            max_source_bytes: 64 << 20,
        })
        .expect("enable manifestation");
    }

    let tx_start = ns.volume().log.transaction_count();
    let root_start = ns.root();
    let live_before_calibration = live_bytes(dir);

    // --- Calibration phase: new content (extend every object) ---------------
    let n_cal = txns(wl.initial_mib, wl.write_len);
    for i in 0..n_cal {
        let oi = (i as usize) % wl.objects;
        let off = sizes[oi];
        ns.write_at(inodes[oi], off, &content_at(off, wl.write_len as usize))
            .expect("calibration write");
        sizes[oi] += wl.write_len;
    }
    ns.sync().expect("sync calibration");
    if wl.manifested {
        ns.manifest_eligible(None, ManifestationProfile::Full)
            .expect("manifest calibration");
        ns.sync().expect("sync manifestation");
    }
    let tx_after_calibration = ns.volume().log.transaction_count();
    let root_after_calibration = ns.root();

    // --- Validation phase: overwrite already-written ranges ---------------
    // A deterministic misaligned-ish scatter: each write targets a slot inside an
    // existing object, so the live content set never grows.
    let live_before_overwrite = live_bytes(dir);
    assert_eq!(
        live_before_calibration + wl.initial_mib * MIB,
        live_before_overwrite,
        "the calibration phase must have added exactly its logical bytes"
    );
    let n_ovw = txns(wl.overwrite_mib, wl.write_len);
    for i in 0..n_ovw {
        let oi = (i as usize) % wl.objects;
        let slots = sizes[oi] / wl.write_len;
        let slot = (i.wrapping_mul(2_654_435_761)) % slots.max(1);
        let off = slot * wl.write_len;
        ns.write_at(inodes[oi], off, &content_at(off, wl.write_len as usize))
            .expect("overwrite write");
    }
    ns.sync().expect("sync overwrite");
    if wl.manifested {
        ns.manifest_eligible(None, ManifestationProfile::Full)
            .expect("manifest overwrite");
        ns.sync().expect("sync manifestation");
    }
    let tx_after_overwrite = ns.volume().log.transaction_count();
    let root_after_overwrite = ns.root();
    let live_after_overwrite = live_bytes(dir);

    // --- The report ---------------------------------------------------------
    let vol = Volume::open(dir, OpenMode::ReadOnly).expect("open volume read-only");
    let free = vol
        .capacity_status(Some(0))
        .free_bytes
        .expect("free space readable");

    // Operator illustration: a unit is one transaction, from the measured rates.
    let written_total = wl.initial_mib * MIB + wl.overwrite_mib * MIB;
    let amp = if written_total > 0 {
        (root_after_overwrite - root_start) as f64 / written_total as f64
    } else {
        1.0
    };
    let inputs = ForecastInputs {
        write_bytes_per_unit: wl.write_len,
        overwrite_ratio: if wl.initial_mib > 0 {
            wl.overwrite_mib as f64 / wl.initial_mib as f64
        } else {
            0.0
        },
        authority_amplification: amp,
        manifested_bytes_per_unit: 0,
        metadata_bytes_per_unit: 0,
        transactions_per_unit: 1,
    };
    let r_ok = vol.storage_economics(Some(0), inputs);
    let r_warn = vol.storage_economics(Some(free / 2 + free / 4), inputs);
    let r_exhausted = vol.storage_economics(Some(free + MIB), inputs);
    let accounting = r_ok.accounting.clone();
    let economics = serde_json::to_value(&r_ok).expect("serialize economics");

    ArmResult {
        root_start,
        root_after_calibration,
        root_after_overwrite,
        tx_start,
        tx_after_calibration,
        tx_after_overwrite,
        written_calibration: n_cal * wl.write_len,
        written_overwrite: n_ovw * wl.write_len,
        live_before_overwrite,
        live_after_overwrite,
        accounting,
        economics,
        verdicts: (
            verdict_name(r_ok.forecast.verdict),
            verdict_name(r_warn.forecast.verdict),
            verdict_name(r_exhausted.forecast.verdict),
        ),
        wall_micros: start.elapsed().as_micros(),
    }
}

fn verdict_name(v: orfs::capacity::CapacityVerdict) -> String {
    match v {
        orfs::capacity::CapacityVerdict::Ok => "ok",
        orfs::capacity::CapacityVerdict::Warn => "warn",
        orfs::capacity::CapacityVerdict::Exhausted => "exhausted",
    }
    .to_string()
}

/// The live logical bytes at the committed root (a separate read-only open).
fn live_bytes(dir: &Path) -> u64 {
    orfs::stats::account_volume(dir)
        .expect("account volume")
        .logical_live_bytes
}

/// The machine-checkable assessment of one run.
fn assess(wl: &Workload, a: &ArmResult) -> serde_json::Value {
    let cal_growth = a.root_after_calibration - a.root_start;
    let ovw_growth = a.root_after_overwrite - a.root_after_calibration;
    let cal_tx = a.tx_after_calibration - a.tx_start;
    let ovw_tx = a.tx_after_overwrite - a.tx_after_calibration;
    let phi = if a.written_calibration > 0 {
        cal_growth as f64 / a.written_calibration as f64
    } else {
        1.0
    };
    let bpt = if cal_tx > 0 {
        cal_growth as f64 / cal_tx as f64
    } else {
        0.0
    };
    // The prediction: retained authority growth tracks *written* bytes.
    let predicted = phi * a.written_overwrite as f64;
    let measured = ovw_growth as f64;
    let rel_err = if predicted > 0.0 {
        (measured - predicted).abs() / predicted
    } else {
        0.0
    };
    let within = rel_err <= TOLERANCE;
    let live_growth = a
        .live_after_overwrite
        .saturating_sub(a.live_before_overwrite);
    // The naive live-bytes model predicts ~0 growth; its error is total.
    let naive_predicted = 0.0_f64;
    let naive_rel_err = if measured > 0.0 {
        (measured - naive_predicted).abs() / measured
    } else {
        0.0
    };

    let acc = &a.accounting;
    serde_json::json!({
        "workload": {
            "objects": wl.objects,
            "object_mib": wl.object_mib,
            "write_len": wl.write_len,
            "initial_mib": wl.initial_mib,
            "overwrite_mib": wl.overwrite_mib,
            "manifested": wl.manifested,
            "logical_bytes_written": a.written_calibration + a.written_overwrite,
            "new_logical_bytes": a.written_calibration,
            "overwritten_logical_bytes": a.written_overwrite,
            "overwrite_ratio_rho": if a.written_calibration > 0 {
                a.written_overwrite as f64 / a.written_calibration as f64
            } else { 0.0 },
        },
        "accounting": {
            "permanent_authoritative": acc.permanent_authoritative,
            "rebuildable_manifestation": acc.rebuildable_manifestation,
            "metadata": acc.metadata,
            "temporary_construction": acc.temporary_construction,
            "total_bytes": acc.total_bytes,
            "observed_volume_bytes": acc.observed_volume_bytes,
            "categories_disjoint_and_complete": acc.categories_disjoint_and_complete,
            "transaction_count": acc.transaction_count,
            "bytes_per_transaction": acc.bytes_per_transaction,
            "overwrite_ratio": acc.overwrite_ratio,
        },
        "predicted_vs_actual": {
            "calibration": {
                "logical_bytes_written": a.written_calibration,
                "transactions": cal_tx,
                "authoritative_growth": cal_growth,
                "authority_amplification_phi": phi,
                "bytes_per_transaction": bpt,
            },
            "overwrite": {
                "logical_bytes_written": a.written_overwrite,
                "transactions": ovw_tx,
                "predicted_authority_growth": predicted,
                "measured_authority_growth": measured,
                "relative_error": rel_err,
                "tolerance": TOLERANCE,
                "within_tolerance": within,
                "live_logical_growth": live_growth,
                "naive_live_model_prediction": naive_predicted,
                "naive_live_model_relative_error": naive_rel_err,
            },
        },
        "forecast": a.economics["forecast"].clone(),
        "verdicts": {
            "ok_reserve_0": a.verdicts.0,
            "warn_reserve_3_4_free": a.verdicts.1,
            "exhausted_reserve_above_free": a.verdicts.2,
        },
        "assessment": {
            "categories_disjoint_and_complete": acc.categories_disjoint_and_complete,
            "authoritative_is_permanent": acc.permanent_authoritative.bytes > 0
                && !acc.permanent_authoritative.reclaimable,
            "overwrite_ratio_zero_live_growth": live_growth == 0,
            "overwrite_still_appends": measured > 0.0,
            "prediction_within_tolerance": within,
            "naive_live_model_is_wrong": naive_rel_err > 0.9,
            "verdict_degrades_ok_warn_exhausted":
                a.verdicts.0 == "ok" && a.verdicts.1 == "warn" && a.verdicts.2 == "exhausted",
            "manifested_adds_rebuildable_bytes":
                !wl.manifested || acc.rebuildable_manifestation.bytes > 0,
        },
        "wall_micros": a.wall_micros as u64,
    })
}

/// Build both arms (authoritative + manifested) over the identical history.
fn run_court(
    dir: &Path,
    wl: &Workload,
) -> (serde_json::Value, serde_json::Value, ArmResult, ArmResult) {
    let auth_dir = dir.join("authoritative");
    let man_dir = dir.join("manifested");
    std::fs::create_dir_all(&auth_dir).expect("auth dir");
    std::fs::create_dir_all(&man_dir).expect("man dir");

    let mut auth_wl = *wl;
    auth_wl.manifested = false;
    let authoritative = run_arm(&auth_dir, &auth_wl);
    let manifested = run_arm(&man_dir, wl);

    // The concealed plane must never change authority.
    assert_eq!(
        authoritative.root_after_overwrite, manifested.root_after_overwrite,
        "manifestation must not alter the committed history"
    );
    assert_eq!(
        authoritative.root_after_calibration, manifested.root_after_calibration,
        "manifestation must not alter the calibration history"
    );

    let a_assess = assess(&auth_wl, &authoritative);
    let m_assess = assess(wl, &manifested);

    // Non-overlap + summation, and the core falsifiable claims.
    assert!(
        authoritative.accounting.categories_disjoint_and_complete,
        "the four categories must partition the observed bytes: {a_assess}"
    );
    assert_eq!(
        authoritative.accounting.total_bytes,
        authoritative.accounting.observed_volume_bytes
    );
    assert!(
        a_assess["assessment"]["prediction_within_tolerance"] == serde_json::json!(true),
        "predicted-vs-actual must be within tolerance: {a_assess}"
    );
    assert!(
        a_assess["assessment"]["overwrite_still_appends"] == serde_json::json!(true),
        "an overwrite must still append: {a_assess}"
    );
    assert!(
        a_assess["assessment"]["naive_live_model_is_wrong"] == serde_json::json!(true),
        "the naive live-bytes model must be falsified: {a_assess}"
    );
    assert!(
        a_assess["assessment"]["verdict_degrades_ok_warn_exhausted"] == serde_json::json!(true),
        "the verdict must degrade ok -> warn -> exhausted: {a_assess}"
    );
    assert!(
        manifested.accounting.rebuildable_manifestation.bytes > 0,
        "the manifested arm must add rebuildable bytes: {m_assess}"
    );

    (a_assess, m_assess, authoritative, manifested)
}

#[test]
fn storage_economics_smoke() {
    let td = TempDir::new().unwrap();
    let wl = smoke_workload();
    let (a, m, auth, _man) = run_court(td.path(), &wl);

    // Recorded evidence is complete and self-consistent.
    assert!(
        a["accounting"]["permanent_authoritative"]["bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(a["workload"]["objects"], serde_json::json!(wl.objects));
    assert_eq!(
        a["accounting"]["total_bytes"].as_u64().unwrap(),
        a["accounting"]["observed_volume_bytes"].as_u64().unwrap()
    );
    // The authoritative arm has no rebuildable tier; the manifested arm does.
    assert_eq!(auth.accounting.rebuildable_manifestation.bytes, 0);
    assert!(
        m["accounting"]["rebuildable_manifestation"]["bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    // The forecast exposes usable, non-degenerate numbers.
    let f = &auth.economics["forecast"];
    assert!(f["retained_authority_bytes_per_unit"].as_u64().unwrap() > 0);
    assert!(f["units_to_full"].as_f64().unwrap() > 0.0);
    assert!(f["assumptions"].as_array().unwrap().len() >= 4);
}

#[test]
fn storage_economics_sweep() {
    if std::env::var("ORFS_STORAGE_ECONOMICS").as_deref() != Ok("1") {
        eprintln!(
            "storage_economics_sweep: skipped \
             (set ORFS_STORAGE_ECONOMICS=1 to run the full sweep)"
        );
        return;
    }
    let td = TempDir::new().unwrap();
    let wl = sweep_workload();
    let (a, m, _auth, man) = run_court(td.path(), &wl);

    let environment = serde_json::json!({
        "bench": serde_json::to_value(orfs::bench::Environment::capture(
            std::env::var("ORFS_IMAGE").ok()
        ))
        .unwrap_or(serde_json::Value::Null),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
    });

    let all_ok = [
        "categories_disjoint_and_complete",
        "authoritative_is_permanent",
        "overwrite_ratio_zero_live_growth",
        "overwrite_still_appends",
        "prediction_within_tolerance",
        "naive_live_model_is_wrong",
        "verdict_degrades_ok_warn_exhausted",
        "manifested_adds_rebuildable_bytes",
    ]
    .iter()
    .all(|k| a["assessment"][k] == serde_json::json!(true));

    let doc = serde_json::json!({
        "schema": "orfs.performance.storage-economics.v1",
        "generated_by": "tests/storage_economics.rs",
        "note": "Single-run, single-host, BOUNDED measurements. The four-category \
                 accounting is a single walk that classifies each file, so the four \
                 totals are disjoint by construction and are proved to sum to the \
                 independently measured on-disk total. The forecast is validated: a \
                 calibration phase measures the framing amplification phi, the \
                 prediction predicts the overwrite phase's retained growth as \
                 phi x written bytes, and the measured growth must match within the \
                 stated tolerance. The crux is that an overwrite still appends, so \
                 retained growth tracks written bytes, not live bytes (the naive \
                 live-bytes model is falsified). Absolute bytes are host/build \
                 dependent; the shape and the byte counts are the point.",
        "tolerance": TOLERANCE,
        "environment": environment,
        "arms": {
            "authoritative": {
                "manifestation": "disabled",
                "assessment": a,
            },
            "manifested": {
                "manifestation": "enabled (profile full, synchronous)",
                "assessment": m,
            },
        },
        "accounting_table": {
            "permanent_authoritative": man.accounting.permanent_authoritative.bytes,
            "rebuildable_manifestation": man.accounting.rebuildable_manifestation.bytes,
            "metadata": man.accounting.metadata.bytes,
            "temporary_construction": man.accounting.temporary_construction.bytes,
            "total_bytes": man.accounting.total_bytes,
            "observed_volume_bytes": man.accounting.observed_volume_bytes,
            "categories_disjoint_and_complete":
                man.accounting.categories_disjoint_and_complete,
            "transaction_count": man.accounting.transaction_count,
            "bytes_per_transaction": man.accounting.bytes_per_transaction,
            "overwrite_ratio": man.accounting.overwrite_ratio,
        },
        "all_ok": all_ok,
    });

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/performance/storage-economics.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("storage-economics evidence written to {}", path.display());

    assert!(all_ok, "storage-economics court: {doc}");
}
