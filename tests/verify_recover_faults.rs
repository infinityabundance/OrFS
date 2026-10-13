//! Phase 62 — **device-fault evidence: `verify --deep` + `recover`**.
//!
//! The reviewer's residual item was: *the ENOSPC / device-error path has
//! `tests/power_loss.rs`, but there is no court that injects a fault into a log
//! and then drives the **real `orfs` binary** (`orfs verify --deep`, `orfs
//! recover`) to show it detects the fault and recovers to a valid committed
//! boundary.*
//!
//! For each injected fault this court:
//!
//! 1. builds a known-good `Namespace` volume (real, semantically-valid typed
//!    records, so `verify --deep`'s namespace rebuild succeeds on the committed
//!    prefix) and records a known-good baseline;
//! 2. injects the fault — either by direct segment-byte damage (a torn write, a
//!    partially-persisted commit/tail, a duplicated write) or through the
//!    project's deterministic **simulated device** (`src/powerloss.rs`: a
//!    reordered write, a rejected/shortened write, a torn durable tail);
//! 3. runs the **real CLI binary** `orfs verify --deep` and asserts it *surfaces*
//!    the damage and — because it opens read-only — does **not** silently repair
//!    it (the tree is byte-identical afterwards);
//! 4. runs the **real CLI binary** `orfs recover`, then checks, directly on disk,
//!    that the recovered root is a committed boundary and every pre-fault
//!    committed byte `[0, R)` is intact (byte-exact, nothing invented, nothing
//!    rewritten), and that a refusal never touched anything.
//!
//! # The abandoned-tail shape (and one honest residual)
//!
//! OrFS's recovery is defined for a tail that occupies a **whole trailing
//! segment** (a torn/uncommitted write that rolled over into a fresh segment):
//! the segment is moved to `quarantine/` and the volume reopens cleanly. A torn
//! write that is also the *last* segment (`Inject::TrailingTorn`) and a
//! partially-persisted/uncommitted commit (`Inject::TrailingStray`) are covered
//! this way.
//!
//! A tail that begins **inside** the committed segment (`Inject::IntraSegmentTorn`)
//! is deliberately *retained in place* — `tests/log_model.rs` pins
//! "quarantined, not truncated". The CLI still reports the correct committed
//! boundary and leaves every committed byte intact, but a *later fresh open*
//! refuses the retained bytes ("a torn record in a non-final segment"). That is a
//! real residual; the row asserts all the safety properties and records the
//! refusal in a `residual` field rather than hiding it.
//!
//! # Device-mapper probe
//!
//! The court records whether *real* device-mapper fault targets (`dm-flaky` /
//! `dm-error`) are usable here; they are **not** (no `dmsetup` in the pinned
//! image, no `/dev/mapper/control`, `losetup --find --show <file>` fails). The
//! probe result is embedded with `ran: false` and the exact failing commands.
//! `scripts/container-fault-verify.sh` re-probes in an elevated container.
//!
//! Evidence: `evidence/recovery/fault-injection-verify-recover.json`, schema
//! `orfs.recovery.fault-injection-verify-recover.v1`. The always-on matrix is
//! small; `ORFS_FAULT_SWEEP=1` adds a heavier sweep under `runs.sweep`.

#![cfg(feature = "powerloss")]

mod support;

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use orfs::commit::DurabilityMode;
use orfs::index::ROOT_INODE;
use orfs::log::{scan_log, OpenMode};
use orfs::namespace::Namespace;
use orfs::powerloss::{self, DeviceFaultKind, DeviceFaultRule, DeviceOp, SimConfig};
use orfs::segment::{discover_segment_ids, segment_file_name};
use orfs::volume::Volume;

use serde_json::{json, Value};
use support::{payload, FIXED_CREATED, FIXED_UUID};
use tempfile::TempDir;

/// A large segment: a short workload stays in one segment.
const SEG_LARGE: u64 = 1 << 20;
/// A small segment: a short workload rolls over into several segments.
const SEG_ROLL: u64 = 2048;
/// Baseline mutations committed before any fault is injected.
const BASELINE_TXNS: u64 = 2;

// ---------------------------------------------------------------------------
// CLI driver
// ---------------------------------------------------------------------------

struct Cli {
    ok: bool,
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_cli(args: &[&OsStr]) -> Cli {
    let out = Command::new(env!("CARGO_BIN_EXE_orfs"))
        .args(args)
        .output()
        .expect("spawn the orfs CLI");
    Cli {
        ok: out.status.success(),
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// The parsed `orfs verify --deep` outcome.
struct VerifyDeep {
    cli_ok: bool,
    exit_code: Option<i32>,
    report_ok: bool,
    /// The damage was surfaced: a check failed, or a `tail` check named a
    /// non-empty tail. A clean report over untouched bytes is not "detected".
    detected: bool,
    tail_kind: Option<String>,
    tail_abandoned_bytes: Option<u64>,
    failing_checks: Vec<String>,
    error: Option<String>,
}

fn parse_abandoned_bytes(detail: &str) -> Option<u64> {
    let idx = detail.find(" bytes retained")?;
    let before = &detail[..idx];
    let start = before
        .rfind(|c: char| !c.is_ascii_digit())
        .map(|i| i + 1)
        .unwrap_or(0);
    before[start..].parse().ok()
}

fn run_verify_deep(dir: &Path) -> VerifyDeep {
    let cli = run_cli(&[
        OsStr::new("--json"),
        OsStr::new("verify"),
        OsStr::new("--deep"),
        dir.as_os_str(),
    ]);
    let json = serde_json::from_str::<Value>(&cli.stdout).ok();
    let mut report_ok = false;
    let mut tail_kind = None;
    let mut tail_abandoned_bytes = None;
    let mut failing_checks = Vec::new();
    if let Some(v) = &json {
        report_ok = v["ok"].as_bool().unwrap_or(false);
        if let Some(checks) = v["checks"].as_array() {
            for c in checks {
                let name = c["name"].as_str().unwrap_or("");
                let ok = c["ok"].as_bool().unwrap_or(true);
                let detail = c["detail"].as_str().unwrap_or("");
                if !ok {
                    failing_checks.push(name.to_string());
                }
                if name == "tail" && detail != "no torn or uncommitted tail" {
                    tail_kind = detail.split_whitespace().next().map(str::to_string);
                    tail_abandoned_bytes = parse_abandoned_bytes(detail);
                }
            }
        }
    }
    let detected = json.is_none() || !report_ok || tail_kind.is_some();
    VerifyDeep {
        cli_ok: cli.ok,
        exit_code: cli.code,
        report_ok,
        detected,
        tail_kind,
        tail_abandoned_bytes,
        failing_checks,
        error: (!cli.stderr.trim().is_empty()).then(|| cli.stderr.trim().to_string()),
    }
}

/// The parsed `orfs recover` outcome.
struct RecoverCli {
    cli_ok: bool,
    exit_code: Option<i32>,
    refused: bool,
    recovered_root: Option<u64>,
    committed_records: Option<u64>,
    quarantined: Option<bool>,
    tail_kind: Option<String>,
    tail_abandoned_bytes: Option<u64>,
    scan_error: Option<String>,
    error: Option<String>,
}

fn run_recover(dir: &Path) -> RecoverCli {
    let cli = run_cli(&[OsStr::new("--json"), OsStr::new("recover"), dir.as_os_str()]);
    let json = serde_json::from_str::<Value>(&cli.stdout).ok();
    let mut out = RecoverCli {
        cli_ok: cli.ok,
        exit_code: cli.code,
        refused: !cli.ok,
        recovered_root: None,
        committed_records: None,
        quarantined: None,
        tail_kind: None,
        tail_abandoned_bytes: None,
        scan_error: None,
        error: (!cli.stderr.trim().is_empty()).then(|| cli.stderr.trim().to_string()),
    };
    if let Some(v) = &json {
        if let Some(se) = v["scan_error"].as_str() {
            out.scan_error = Some(se.to_string());
            out.refused = true;
        }
        out.recovered_root = v["recovered_root"].as_u64();
        out.committed_records = v["committed_records"].as_u64();
        out.quarantined = v["quarantined"].as_bool();
        if !v["tail"].is_null() {
            out.tail_kind = v["tail"]["kind"].as_str().map(str::to_string);
            out.tail_abandoned_bytes = v["tail"]["abandoned_bytes"].as_u64();
        }
        if out.recovered_root.is_some() {
            out.refused = false;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Byte-level log helpers
// ---------------------------------------------------------------------------

/// Recursively capture every file under the volume (path -> bytes).
fn snapshot_tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(cur: &Path, root: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(rd) = std::fs::read_dir(cur) else {
            return;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.path());
        for e in entries {
            let p = e.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else if let Ok(bytes) = std::fs::read(&p) {
                out.push((p.strip_prefix(root).unwrap().to_path_buf(), bytes));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out
}

/// The committed record byte ranges: each record's start offset and its bytes.
/// OrFS names a segment by the *logical offset of its first byte*.
fn committed_records(dir: &Path) -> (Vec<u64>, Vec<u8>) {
    let vol = Volume::open(dir, OpenMode::ReadOnly).expect("open");
    let root = vol.log.committed_end_offset();
    let bytes = vol.log.read_committed_bytes().expect("committed bytes");
    let recs = vol.log.replay_upto(root).expect("replay");
    let mut starts = Vec::with_capacity(recs.len());
    let mut off = 0u64;
    for r in &recs {
        starts.push(off);
        off += r.header.total_len().expect("record length");
    }
    (starts, bytes)
}

/// The bytes of the last committed record.
fn last_committed_record_bytes(dir: &Path) -> Vec<u8> {
    let (starts, bytes) = committed_records(dir);
    let start = *starts.last().expect("a committed record") as usize;
    bytes[start..].to_vec()
}

/// The bytes of the last committed *data* record (the one before the final
/// `TX_COMMIT`), used to model a stray/duplicated persisted record.
fn last_data_record_bytes(dir: &Path) -> Vec<u8> {
    let (starts, bytes) = committed_records(dir);
    let idx = starts.len().saturating_sub(2);
    let start = starts[idx] as usize;
    let end = starts
        .get(idx + 1)
        .map(|s| *s as usize)
        .unwrap_or(bytes.len());
    bytes[start..end].to_vec()
}

fn append_to_newest(dir: &Path, bytes: &[u8]) {
    let log_dir = Volume::log_dir(dir);
    let ids = discover_segment_ids(&log_dir).expect("segment ids");
    let last = *ids.last().expect("a segment");
    let path = log_dir.join(segment_file_name(last).expect("segment name"));
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("open newest segment");
    f.write_all(bytes).expect("append bytes");
    f.sync_all().expect("sync appended bytes");
}

/// Write a fresh trailing segment (id == the committed root) containing `bytes`.
fn write_trailing_segment(dir: &Path, id: u64, bytes: &[u8]) {
    let log_dir = Volume::log_dir(dir);
    let path = log_dir.join(segment_file_name(id).expect("segment name"));
    assert!(!path.exists(), "a trailing segment already exists at {id}");
    std::fs::write(&path, bytes).expect("write trailing segment");
}

/// Read the first `upto` bytes of the concatenated segment files. Segment ids
/// are logical start offsets and OrFS segments are contiguous, so this is exactly
/// the committed prefix `[0, upto)` as it survives on disk — independent of any
/// reopen.
fn ondisk_committed_prefix(dir: &Path, upto: u64) -> Vec<u8> {
    let log_dir = Volume::log_dir(dir);
    let ids = discover_segment_ids(&log_dir).expect("segment ids");
    let mut out = Vec::new();
    for id in ids {
        if out.len() as u64 >= upto {
            break;
        }
        let path = log_dir.join(segment_file_name(id).expect("segment name"));
        let Ok(bytes) = std::fs::read(&path) else {
            break;
        };
        let take = (upto - out.len() as u64).min(bytes.len() as u64) as usize;
        out.extend_from_slice(&bytes[..take]);
    }
    out
}

fn try_reopen(dir: &Path) -> Result<u64, String> {
    match Volume::open(dir, OpenMode::ReadOnly) {
        Ok(vol) => Ok(vol.log.committed_end_offset()),
        Err(e) => Err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Workload preparation
// ---------------------------------------------------------------------------

/// Known-good state captured before any fault is injected.
struct PreFault {
    baseline_root: u64,
    /// Committed bytes `[0, baseline_root)` — the durable pre-workload base.
    baseline_bytes: Vec<u8>,
    prefault_root: u64,
    /// All committed bytes `[0, prefault_root)`.
    prefault_bytes: Vec<u8>,
    segment_count: usize,
}

/// A deterministic namespace mutation: create a file and write 32 bytes to it.
/// Each call commits real, semantically-valid typed records, so `verify --deep`'s
/// namespace rebuild (`Index::from_log`) succeeds on the committed prefix. A
/// synthetic record type/payload would be rejected there and mask the real fault.
fn mutate(ns: &mut Namespace, i: u64) {
    let name = format!("f{i}");
    let ino = ns
        .create(ROOT_INODE, name.as_bytes(), 0o644, 0, 0)
        .expect("create");
    ns.write_at(ino, 0, &payload(i, 0, 32)).expect("write");
}

fn prepare(dir: &Path, seg: u64, baseline: u64, extra: u64) -> PreFault {
    let mut ns =
        Namespace::init_with_uuid(dir, seg, FIXED_UUID, FIXED_CREATED, DurabilityMode::Sync)
            .expect("init namespace");
    for i in 1..=baseline {
        mutate(&mut ns, i);
    }
    ns.sync().expect("sync baseline");
    let baseline_root = ns.volume().log.committed_end_offset();
    for i in baseline + 1..=baseline + extra {
        mutate(&mut ns, i);
    }
    ns.sync().expect("sync workload");
    let prefault_root = ns.volume().log.committed_end_offset();
    let prefault_bytes = ns
        .volume()
        .log
        .read_committed_bytes()
        .expect("committed bytes");
    let segment_count = ns.volume().log.extents().len();
    drop(ns);
    PreFault {
        baseline_root,
        baseline_bytes: prefault_bytes[..baseline_root as usize].to_vec(),
        prefault_root,
        prefault_bytes,
        segment_count,
    }
}

// ---------------------------------------------------------------------------
// Injected-fault descriptions
// ---------------------------------------------------------------------------

enum Inject {
    /// A torn (half-written) record in a fresh **trailing segment**: a torn write
    /// that rolled over and never committed. Recovery moves the segment aside and
    /// the volume reopens cleanly.
    TrailingTorn,
    /// A stray, well-framed committed record in a fresh trailing segment: a
    /// partially-persisted commit/tail that never published a root.
    TrailingStray,
    /// A duplicated (re-written) committed record in a fresh trailing segment.
    TrailingDuplicate,
    /// A torn record appended to the **last committed segment** (an
    /// intra-segment tear). Retained in place by design; recorded as a residual.
    IntraSegmentTorn,
}

fn apply_injection(dir: &Path, pf: &PreFault, inject: &Inject) {
    match inject {
        Inject::TrailingTorn => {
            let rec = last_committed_record_bytes(dir);
            write_trailing_segment(dir, pf.prefault_root, &rec[..rec.len() / 2]);
        }
        Inject::TrailingStray => {
            let rec = last_data_record_bytes(dir);
            write_trailing_segment(dir, pf.prefault_root, &rec);
        }
        Inject::TrailingDuplicate => {
            let rec = last_committed_record_bytes(dir);
            write_trailing_segment(dir, pf.prefault_root, &rec);
        }
        Inject::IntraSegmentTorn => {
            let rec = last_committed_record_bytes(dir);
            append_to_newest(dir, &rec[..rec.len() / 2]);
        }
    }
}

/// A device-level fault (the simulated storage device).
struct DeviceFault {
    cfg: SimConfig,
    rules: Vec<DeviceFaultRule>,
    attempts: u64,
}

// ---------------------------------------------------------------------------
// Row construction
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The CLI must recover to a valid committed boundary.
    Recovered,
    /// Either is acceptable (a contract-violating device may refuse); safety is
    /// asserted in both cases.
    Either,
}

/// A tiny assertion accumulator.
struct Checks {
    ok: bool,
    failures: Vec<String>,
}

impl Checks {
    fn new() -> Self {
        Checks {
            ok: true,
            failures: Vec::new(),
        }
    }

    fn req(&mut self, cond: bool, msg: impl Into<String>) {
        if !cond {
            self.ok = false;
            self.failures.push(msg.into());
        }
    }
}

/// The reopen an injected fault is expected to allow.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExpectReopen {
    /// The volume must reopen cleanly at the recovered root.
    Clean,
    /// A fresh open is expected to refuse the retained intra-segment tail
    /// (recorded as an explicit residual, not as a failure).
    Residual,
    /// Not asserted; just recorded.
    Any,
}

/// Run one fault row end to end and return `(row_json, ok)`.
#[allow(clippy::too_many_arguments)]
fn row(
    id: &str,
    class: &str,
    topology: &str,
    fault: String,
    pf: &PreFault,
    prefix_bytes: &[u8],
    dir: &Path,
    expected_root: Option<u64>,
    expected_tail: Option<String>,
    expect_detected: Option<bool>,
    expect: Expect,
    expect_reopen: ExpectReopen,
) -> (Value, bool) {
    // --- verify --deep (must not repair) ---
    let before_verify = snapshot_tree(dir);
    let verify = run_verify_deep(dir);
    let after_verify = snapshot_tree(dir);
    let verify_repaired = before_verify != after_verify;

    // --- recover (must not silently repair) ---
    let before_recover = snapshot_tree(dir);
    let recover = run_recover(dir);
    let after_recover = snapshot_tree(dir);
    let refused_untouched = !recover.refused || before_recover == after_recover;

    // --- validation (independent of a reopen) ---
    let expected = expected_root.unwrap_or(pf.prefault_root);
    let upto = expected.min(prefix_bytes.len() as u64);
    let prefix_ok = ondisk_committed_prefix(dir, upto) == prefix_bytes[..upto as usize];
    let reopen = try_reopen(dir);

    let mut c = Checks::new();
    c.req(
        !verify_repaired,
        "verify --deep changed the tree (silent repair)",
    );
    if let Some(want) = expect_detected {
        c.req(
            verify.detected == want,
            format!("verify --deep detected={} expected={want}", verify.detected),
        );
    }
    c.req(refused_untouched, "a refused recover modified the tree");

    if recover.refused {
        c.req(
            expect != Expect::Recovered,
            "recover refused but a valid boundary was expected",
        );
    } else {
        c.req(
            recover.recovered_root == Some(expected),
            format!(
                "recover reported root {:?}, expected {expected}",
                recover.recovered_root
            ),
        );
        c.req(prefix_ok, "the on-disk committed prefix was not intact");
        match (&reopen, expect_reopen) {
            (Ok(root), ExpectReopen::Clean) => c.req(
                *root == expected,
                format!("reopen root {root} != recovered root {expected}"),
            ),
            (Err(_), ExpectReopen::Clean) => {
                c.req(false, "the volume did not reopen cleanly after recovery")
            }
            (Ok(_), ExpectReopen::Residual) => c.req(
                false,
                "expected the retained intra-segment tail to refuse a reopen",
            ),
            _ => {}
        }
    }

    let (reopen_ok, reopen_root, reopen_error) = match &reopen {
        Ok(r) => (true, Some(*r), None),
        Err(e) => (false, None, Some(e.clone())),
    };
    let residual = match (&reopen, expect_reopen) {
        (Err(e), ExpectReopen::Residual) => Some(format!(
            "a fresh read-only open refuses the tail retained in place inside the \
             committed segment (quarantined, not truncated, by design): {e}"
        )),
        (Err(e), _) if !recover.refused => Some(format!("a fresh open refused: {e}")),
        _ => None,
    };

    let ok = c.ok;
    let failures = c.failures;
    let row = json!({
        "id": id,
        "class": class,
        "topology": topology,
        "fault": fault,
        "prefault": {
            "baseline_root": pf.baseline_root,
            "prefault_committed_root": pf.prefault_root,
            "segment_count": pf.segment_count,
            "expected_recovered_root": expected_root,
            "expected_tail_kind": expected_tail,
        },
        "verify_deep": {
            "cli_ok": verify.cli_ok,
            "exit_code": verify.exit_code,
            "report_ok": verify.report_ok,
            "detected": verify.detected,
            "tail_kind": verify.tail_kind,
            "tail_abandoned_bytes": verify.tail_abandoned_bytes,
            "failing_checks": verify.failing_checks,
            "repaired": verify_repaired,
            "error": verify.error,
        },
        "recover": {
            "cli_ok": recover.cli_ok,
            "exit_code": recover.exit_code,
            "refused": recover.refused,
            "recovered_root": recover.recovered_root,
            "committed_records": recover.committed_records,
            "quarantined": recover.quarantined,
            "tail_kind": recover.tail_kind,
            "tail_abandoned_bytes": recover.tail_abandoned_bytes,
            "scan_error": recover.scan_error,
            "error": recover.error,
        },
        "reopen": {
            "ok": reopen_ok,
            "root": reopen_root,
            "error": reopen_error,
        },
        "residual": residual,
        "data_intact": !recover.refused && prefix_ok,
        "refused_untouched": refused_untouched,
        "ok": ok,
        "failures": failures,
    });
    (row, ok)
}

/// Run a direct byte-level injection row in its own temp volume.
#[allow(clippy::too_many_arguments)]
fn direct_row(
    id: &str,
    class: &str,
    topology: &str,
    seg: u64,
    extra: u64,
    inject: Inject,
    expect_reopen: ExpectReopen,
) -> (Value, bool) {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().to_path_buf();
    let pf = prepare(&dir, seg, BASELINE_TXNS, extra);
    let fault = match &inject {
        Inject::TrailingTorn => {
            "a torn (half-written) record in a fresh trailing segment (a torn write that rolled over and never committed)".to_string()
        }
        Inject::TrailingStray => {
            "a stray well-framed committed record in a fresh trailing segment (a partially-persisted commit/tail)".to_string()
        }
        Inject::TrailingDuplicate => {
            "a full duplicate of the last committed record in a fresh trailing segment (a duplicated write)".to_string()
        }
        Inject::IntraSegmentTorn => {
            "a torn (half-written) record appended to the last committed segment (an intra-segment tear, retained in place)".to_string()
        }
    };
    apply_injection(&dir, &pf, &inject);

    let (expected_root, expected_tail) = match scan_log(&Volume::log_dir(&dir)) {
        Ok(s) => (
            Some(s.committed_end_offset),
            s.tail.map(|t| format!("{:?}", t.kind)),
        ),
        Err(_) => (None, None),
    };
    let expect_detected = Some(expected_tail.is_some() || expected_root.is_none());
    row(
        id,
        class,
        topology,
        fault,
        &pf,
        &pf.prefault_bytes,
        &dir,
        expected_root,
        expected_tail,
        expect_detected,
        Expect::Recovered,
        expect_reopen,
    )
}

/// Run a device-fault row in its own temp volume.
#[allow(clippy::too_many_arguments)]
fn device_row(
    id: &str,
    class: &str,
    topology: &str,
    fault: String,
    seg: u64,
    dev: DeviceFault,
    expect_detected: Option<bool>,
    expect: Expect,
) -> (Value, bool) {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().to_path_buf();
    let pf = prepare(&dir, seg, BASELINE_TXNS, 0);

    // The device is attached *after* the baseline, so only the workload runs on
    // it.
    let log_dir = Volume::log_dir(&dir);
    let handle =
        powerloss::attach_with_faults(&log_dir, dev.cfg, dev.rules).expect("attach device");

    let mut acks: Vec<u64> = Vec::new();
    let mut failure_errno: Option<i32> = None;
    {
        let mut ns = Namespace::open(&dir, OpenMode::ReadWrite, DurabilityMode::Sync)
            .expect("open workload namespace");
        for i in 1..=dev.attempts {
            let name = format!("g{i}");
            match ns.create(ROOT_INODE, name.as_bytes(), 0o644, 0, 0) {
                Ok(ino) => {
                    acks.push(ns.volume().log.committed_end_offset());
                    if let Err(e) = ns.write_at(ino, 0, &payload(i, 0, 32)) {
                        failure_errno = Some(e.errno());
                        break;
                    }
                    acks.push(ns.volume().log.committed_end_offset());
                }
                Err(e) => {
                    failure_errno = Some(e.errno());
                    break;
                }
            }
        }
    }
    let report = handle.power_fail().expect("power fail");

    let expected_root = acks.last().copied().unwrap_or(pf.baseline_root);
    let (row_json, mut ok) = row(
        id,
        class,
        topology,
        fault.clone(),
        &pf,
        &pf.baseline_bytes,
        &dir,
        Some(expected_root),
        None,
        expect_detected,
        expect,
        ExpectReopen::Any,
    );
    let mut merged = row_json;
    merged["device"] = json!({
        "sim_config": dev.cfg,
        "failure_errno": failure_errno,
        "acknowledged_roots": acks,
        "power_fail_report": report,
    });
    if expect == Expect::Recovered {
        if let Some(r) = merged["recover"]["recovered_root"].as_u64() {
            for a in acks.iter() {
                if *a > r {
                    ok = false;
                    merged["failures"]
                        .as_array_mut()
                        .expect("failures")
                        .push(json!(format!("acknowledged root {a} lost (recovered {r})")));
                }
            }
        }
    }
    merged["ok"] = json!(ok);
    (merged, ok)
}

// ---------------------------------------------------------------------------
// The fault matrix
// ---------------------------------------------------------------------------

/// The always-on matrix (one deterministic injection per fault class).
#[allow(clippy::vec_init_then_push)]
fn default_matrix() -> Vec<(Value, bool)> {
    let mut rows = Vec::new();

    // (a) torn record mid-log — a whole trailing segment (reopenable)…
    rows.push(direct_row(
        "torn_record_segment_rollover",
        "a_torn_record_mid_log",
        "segment_rollover",
        SEG_ROLL,
        10,
        Inject::TrailingTorn,
        ExpectReopen::Clean,
    ));
    // …and an intra-segment tear (retained in place by design; residual recorded).
    rows.push(direct_row(
        "torn_record_mid_segment",
        "a_torn_record_mid_log",
        "mid_segment",
        SEG_LARGE,
        4,
        Inject::IntraSegmentTorn,
        ExpectReopen::Residual,
    ));

    // (b) partially-persisted commit/tail — a well-framed uncommitted record.
    rows.push(direct_row(
        "partial_commit_tail",
        "b_partially_persisted_commit_tail",
        "segment_rollover",
        SEG_ROLL,
        10,
        Inject::TrailingStray,
        ExpectReopen::Clean,
    ));
    // (c) duplicated write — a re-written persisted record.
    rows.push(direct_row(
        "duplicated_write_tail",
        "c_reordered_duplicated_write",
        "segment_rollover",
        SEG_ROLL,
        10,
        Inject::TrailingDuplicate,
        ExpectReopen::Clean,
    ));

    // (d) write error at a chosen record boundary (atomic refusal: nothing
    // partial survives, so there is nothing for `verify` to detect).
    for (name, kind, skip) in [
        (
            "write_error_enospc_record_boundary",
            DeviceFaultKind::NoSpace,
            4u64,
        ),
        (
            "write_error_eio_record_boundary",
            DeviceFaultKind::IoError,
            4,
        ),
    ] {
        rows.push(device_row(
            name,
            "d_write_error_at_record_boundary",
            "mid_segment",
            format!("simulated device rejects write #{skip} with {kind:?}"),
            SEG_LARGE,
            DeviceFault {
                cfg: SimConfig::honest(7),
                rules: vec![DeviceFaultRule::new(DeviceOp::Write, kind, skip)],
                attempts: 4,
            },
            Some(false),
            Expect::Recovered,
        ));
    }

    // (c) reordered write — an honoured barrier applied out of order (nothing lost).
    rows.push(device_row(
        "reordered_write_no_loss",
        "c_reordered_duplicated_write",
        "mid_segment",
        "simulated device honours the barrier but applies durable writes out of order (nothing lost)".to_string(),
        SEG_LARGE,
        DeviceFault {
            cfg: SimConfig::reordered(7),
            rules: Vec::new(),
            attempts: 4,
        },
        Some(false),
        Expect::Recovered,
    ));
    // (b) a torn durable tail (the watermark then certifies more than survives:
    // a refusal, never a silent shorter recovery).
    rows.push(device_row(
        "torn_durable_tail",
        "b_partially_persisted_commit_tail",
        "mid_segment",
        "simulated device tears the trailing sector of every flushed file at power failure"
            .to_string(),
        SEG_LARGE,
        DeviceFault {
            cfg: SimConfig::tear(7),
            rules: Vec::new(),
            attempts: 4,
        },
        Some(true),
        Expect::Either,
    ));
    // (c) a contract-violating device drops durable sector-aligned blocks.
    rows.push(device_row(
        "reordered_durable_blocks",
        "c_reordered_duplicated_write",
        "mid_segment",
        "simulated device drops durable sector-aligned blocks at power failure".to_string(),
        SEG_LARGE,
        DeviceFault {
            cfg: SimConfig::reorder_durable(7),
            rules: Vec::new(),
            attempts: 4,
        },
        None,
        Expect::Either,
    ));

    rows
}

/// The opt-in heavier sweep (`ORFS_FAULT_SWEEP=1`).
#[allow(clippy::vec_init_then_push)]
fn sweep_matrix() -> Vec<(Value, bool)> {
    let mut rows = Vec::new();

    for (id, inject, class, expect_reopen) in [
        (
            "sweep_torn_trailing_deep",
            Inject::TrailingTorn,
            "a_torn_record_mid_log",
            ExpectReopen::Clean,
        ),
        (
            "sweep_torn_intra_deep",
            Inject::IntraSegmentTorn,
            "a_torn_record_mid_log",
            ExpectReopen::Residual,
        ),
        (
            "sweep_stray_deep",
            Inject::TrailingStray,
            "b_partially_persisted_commit_tail",
            ExpectReopen::Clean,
        ),
        (
            "sweep_duplicate_deep",
            Inject::TrailingDuplicate,
            "c_reordered_duplicated_write",
            ExpectReopen::Clean,
        ),
    ] {
        rows.push(direct_row(
            id,
            class,
            "segment_rollover",
            SEG_ROLL,
            16,
            inject,
            expect_reopen,
        ));
    }

    for kind in [DeviceFaultKind::NoSpace, DeviceFaultKind::IoError] {
        for skip in 0..8u64 {
            let name = match kind {
                DeviceFaultKind::NoSpace => "nospc",
                _ => "eio",
            };
            rows.push(device_row(
                &format!("sweep_write_error_{name}_skip{skip}"),
                "d_write_error_at_record_boundary",
                "mid_segment",
                format!("simulated device rejects write #{skip} with {kind:?}"),
                SEG_LARGE,
                DeviceFault {
                    cfg: SimConfig::honest(7),
                    rules: vec![DeviceFaultRule::new(DeviceOp::Write, kind, skip)],
                    attempts: 6,
                },
                Some(false),
                Expect::Recovered,
            ));
        }
    }

    for (id, cfg) in [
        ("sweep_tear_3", SimConfig::tear(3)),
        ("sweep_tear_21", SimConfig::tear(21)),
        ("sweep_reorder_durable_3", SimConfig::reorder_durable(3)),
        ("sweep_reorder_durable_21", SimConfig::reorder_durable(21)),
    ] {
        let detected = id.contains("tear").then_some(true);
        rows.push(device_row(
            id,
            "c_reordered_duplicated_write",
            "mid_segment",
            format!("simulated device durable-loss profile for {id}"),
            SEG_LARGE,
            DeviceFault {
                cfg,
                rules: Vec::new(),
                attempts: 6,
            },
            detected,
            Expect::Either,
        ));
    }

    rows
}

// ---------------------------------------------------------------------------
// Device-mapper probe
// ---------------------------------------------------------------------------

fn shell(cmd: &str) -> (Option<i32>, String) {
    let out = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .unwrap_or_else(|e| panic!("spawn `sh -c {cmd}`: {e}"));
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code(), s.trim().to_string())
}

/// Attempt to build a real `dm-flaky` / `dm-error` target over a loop device and
/// record the outcome precisely (never faking success).
fn build_dm_probe(mode: &str) -> Value {
    let mut attempts = Vec::new();
    let mut blockers = Vec::new();

    let (c, o) = shell("command -v losetup");
    attempts.push(
        json!({"what": "locate the loop helper", "command": "command -v losetup",
        "exit": c, "observed": if o.is_empty() { "<absent>".to_string() } else { o.clone() }}),
    );
    if c != Some(0) {
        blockers.push("`losetup` is not installed".to_string());
    }

    let (c, o) = shell("command -v dmsetup");
    attempts.push(json!({"what": "locate the device-mapper helper", "command": "command -v dmsetup",
        "exit": c, "observed": if o.is_empty() { "<absent: the dmsetup package is not installed>".to_string() } else { o.clone() }}));
    if c != Some(0) {
        blockers.push(
            "the device-mapper userspace tool `dmsetup` is not installed in the pinned image"
                .to_string(),
        );
    }

    let (c, o) = shell("ls -l /dev/loop-control /dev/mapper/control");
    attempts.push(
        json!({"what": "device nodes", "command": "ls -l /dev/loop-control /dev/mapper/control",
        "exit": c, "observed": o.clone()}),
    );
    if o.contains("No such file or directory") {
        blockers.push(
            "the container exposes neither `/dev/loop-control` nor `/dev/mapper/control`"
                .to_string(),
        );
    }

    let (c, o) = shell(
        "dd if=/dev/zero of=/tmp/orfs-dmprobe.img bs=1M count=4 2>/dev/null; \
         losetup --find --show /tmp/orfs-dmprobe.img",
    );
    attempts.push(json!({"what": "attach a loop device over a backing file",
        "command": "losetup --find --show /tmp/orfs-dmprobe.img",
        "exit": c, "observed": o.clone()}));
    let loop_ok = c == Some(0) && !o.is_empty();
    if !loop_ok {
        blockers.push(format!("`losetup --find --show <file>` failed: {o}"));
    }

    let (c, o) = shell("dmsetup version");
    attempts.push(json!({"what": "query device-mapper", "command": "dmsetup version",
        "exit": c, "observed": if o.is_empty() { "<absent: dmsetup not installed>".to_string() } else { o.clone() }}));

    if loop_ok {
        let (c, o) = shell(
            "dmsetup create orfsprobe --table '0 8192 error' 2>&1; \
             dmsetup remove orfsprobe 2>/dev/null; losetup -d /tmp/orfs-dmprobe.img 2>/dev/null",
        );
        attempts.push(
            json!({"what": "create a dm-error target over the loop device",
            "command": "dmsetup create orfsprobe --table '0 8192 error'",
            "exit": c, "observed": o.clone()}),
        );
        if c != Some(0) {
            blockers.push(format!("`dmsetup create … error` failed: {o}"));
        }
    } else {
        let _ = shell("losetup -d /tmp/orfs-dmprobe.img 2>/dev/null");
    }

    let ran = loop_ok && blockers.is_empty();
    let blocker = if blockers.is_empty() {
        None
    } else {
        Some(blockers.join("; "))
    };
    json!({
        "ran": ran,
        "status": if ran { "usable" } else { "not-runnable-in-this-environment" },
        "probe_mode": mode,
        "attempts": attempts,
        "blockers": blockers,
        "blocker": blocker,
        "conclusion": if ran {
            "A dm-flaky/dm-error target could be created over a loop device.".to_string()
        } else {
            "Real device-mapper fault targets (dm-flaky / dm-error) are NOT usable here; the fault \
             matrix below uses the project's deterministic simulated device and direct segment-byte \
             injection instead. No dm-* result is fabricated."
                .to_string()
        },
    })
}

/// Read the elevated probe the runner produced, else run the default probe.
fn dm_probe() -> Value {
    if let Ok(path) = std::env::var("ORFS_DM_PROBE_JSON") {
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                return v;
            }
        }
    }
    build_dm_probe("default-container")
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

fn flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn evidence_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/recovery/fault-injection-verify-recover.json")
}

/// Read-modify-write one run's section into the receipt (preserving other runs).
fn merge_run(kind: &str, matrix: Vec<Value>, all_ok: bool, probe: &Value) {
    let mut doc: Value = std::fs::read_to_string(evidence_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .filter(|v: &Value| {
            v.get("schema").and_then(|s| s.as_str())
                == Some("orfs.recovery.fault-injection-verify-recover.v1")
        })
        .unwrap_or_else(|| {
            json!({
                "schema": "orfs.recovery.fault-injection-verify-recover.v1",
                "generator": "tests/verify_recover_faults.rs",
                "cli": "the real `orfs` binary: `orfs verify --deep` and `orfs recover`",
                "device_model": "the project's deterministic simulated device (src/powerloss.rs) and direct segment-byte injection",
                "dm_probe": null,
                "runs": {},
            })
        });
    doc["dm_probe"] = probe.clone();
    let count = matrix.len();
    doc["runs"][kind] = json!({
        "row_count": count,
        "all_ok": all_ok,
        "matrix": matrix,
    });
    let mut overall = true;
    if let Some(runs) = doc["runs"].as_object() {
        for r in runs.values() {
            overall &= r["all_ok"].as_bool().unwrap_or(false);
        }
    }
    doc["all_ok"] = json!(overall);
    support::write_json(&evidence_path(), &doc);
}

fn summarize(rows: &[(Value, bool)]) -> (Vec<Value>, bool) {
    let ok = rows.iter().all(|(_, ok)| *ok);
    (rows.iter().map(|(v, _)| v.clone()).collect(), ok)
}

fn first_failure(rows: &[(Value, bool)]) -> String {
    rows.iter()
        .find(|(_, ok)| !*ok)
        .map(|(v, _)| {
            format!(
                "{}: {}\nrow={}",
                v["id"].as_str().unwrap_or("?"),
                serde_json::to_string(&v["failures"]).unwrap_or_default(),
                serde_json::to_string_pretty(v).unwrap_or_default(),
            )
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The always-on court. With `ORFS_FAULT_SWEEP=1` it also runs the heavier sweep
/// and records it under `runs.sweep` (the smoke result stays under `runs.default`).
#[test]
fn verify_recover_after_injected_faults() {
    let probe = dm_probe();

    let default_rows = default_matrix();
    let (matrix, ok) = summarize(&default_rows);
    assert!(
        ok,
        "default fault matrix has a failing row: {}",
        first_failure(&default_rows)
    );
    merge_run("default", matrix, ok, &probe);

    if flag("ORFS_FAULT_SWEEP") {
        let sweep_rows = sweep_matrix();
        let (matrix, ok) = summarize(&sweep_rows);
        assert!(
            ok,
            "sweep fault matrix has a failing row: {}",
            first_failure(&sweep_rows)
        );
        merge_run("sweep", matrix, ok, &probe);
    }
}

/// Write the device-mapper probe receipt used by the runner
/// (`scripts/container-fault-verify.sh`), which re-runs this test inside an
/// elevated container. Writes to `$ORFS_DM_PROBE_OUT` when set (the elevated
/// run uses a dedicated path so a root-owned file cannot collide with the
/// ordinary suite), else `target/dm-probe.json`. Harmless in the ordinary suite.
#[test]
fn write_dm_probe_receipt() {
    let mode =
        std::env::var("ORFS_DM_PROBE_MODE").unwrap_or_else(|_| "default-container".to_string());
    let probe = build_dm_probe(&mode);
    let path = std::env::var("ORFS_DM_PROBE_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("target/dm-probe.json"));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("probe dir");
    }
    support::write_json(&path, &probe);
}
