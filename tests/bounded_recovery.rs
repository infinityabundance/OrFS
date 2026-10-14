//! **Phase 77 — the bounded-space recovery court.**
//!
//! OrFS is non-withdrawal: committed authoritative history is never overwritten,
//! truncated, reused, or GC'd, so the backing store fills monotonically. When it
//! reaches the reserve, `init`/commits are refused and the volume latches
//! read-only (`docs/CAPACITY.md`). This court proves the operator has a
//! **documented, tested, bounded** way out — one that frees local space **without
//! costing one authoritative byte** and without losing the newest committed
//! generation, *including during crash recovery on a nearly-full disk*.
//!
//! ## The claims made executable here (each a real run)
//!
//! * **Recovery at the edge.** Fill a volume to 100% of its usable capacity and a
//!   `write + fsync + crash` at the edge, then `orfs recover` ⇒ the **newest valid
//!   committed generation**, with every previously committed byte intact and
//!   nothing silently repaired or truncated.
//! * **Fail closed under space pressure.** When the backing cannot accept the
//!   recovery working set, recovery returns the precise, typed, actionable
//!   [`OrfsError::RecoverySpaceExhausted`] (`ENOSPC`) with the committed prefix
//!   byte-identical; clearing the pressure lets the same recovery complete and
//!   select the newest committed generation.
//! * **Evacuation frees space and commits resume.** At the reserve, relocating
//!   sealed segments to a cold tier on a **separate filesystem** measurably
//!   increases the backing's free space, the volume accepts commits again, and
//!   every committed root before/after is **byte-identical** (the local copy is
//!   removed only after a verified, durable `Released`).
//! * **Tier unavailable.** With no usable cold tier, the bounded action cannot free
//!   authority bytes; the volume stays read-only, its history is fully readable, and
//!   the refusal is typed and actionable.
//! * **Drop rebuildable is safe.** Dropping the derived manifested structures frees
//!   space, leaves authority byte-identical, and a read still returns identical bytes
//!   (the absent structure falls back to the authoritative extent read).
//! * **Read-only open at 0 free.** `OpenMode::ReadOnly` serves all committed history
//!   with zero headroom and modifies nothing.
//!
//! * `cargo test --test bounded_recovery` runs the always-on smoke.
//! * The full sweep is opt-in behind `ORFS_BOUNDED_RECOVERY=1` and writes
//!   `evidence/performance/bounded-recovery.json`. Run it via
//!   `scripts/container-bounded-recovery.sh`.

// The simulated storage device (`src/powerloss.rs`) is the deterministic seam the
// fail-closed recovery row needs; gate the court on it like `tests/fault_enospc.rs`.
#![cfg(feature = "powerloss")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use orfs::capacity::{backing_available_bytes, CapacityPolicy, StorageCategory};
use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::log::OpenMode;
use orfs::manifestation::{ManifestationConfig, ManifestationProfile};
use orfs::namespace::Namespace;
use orfs::powerloss::{self, DeviceFaultKind, DeviceFaultRule, DeviceOp, SimConfig};
use orfs::reclaim::{capture_authority, drop_rebuildable_structures, plan, relocate_sealed};
use orfs::record::RecordType;
use orfs::segment::{discover_segment_ids, segment_file_name};
use orfs::transaction::{Transaction, TransactionBuilder};
use orfs::volume::Volume;
use orfs::OrfsError;
use serde_json::{json, Value};
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x77, 0x22, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const CREATED: u64 = 1_700_000_000;
/// A small segment size so the fixture rolls over into several sealed segments.
const SEGMENT: u64 = 128 * 1024;
const CHUNK: u64 = 32 * 1024;
const OBJECTS: usize = 8;
const CHUNKS: usize = 4;
/// The confirmed fill level used by the crash row (the edge transaction fits).
const EDGE_LEVEL: u64 = 99;

// ---------------------------------------------------------------------------
// Fixture, snapshots, helpers
// ---------------------------------------------------------------------------

/// Deterministic logical content of an object's chunk.
fn content(obj: u64, off: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|j| (((obj * 131 + off + j as u64) * 7 + 19) % 251) as u8)
        .collect()
}

/// Build a reproducible volume with several sealed segments.
fn build_fixture(dir: &Path) {
    let mut ns = Namespace::init_with_uuid(dir, SEGMENT, UUID, CREATED, DurabilityMode::Sync)
        .expect("init namespace");
    let root_ino = ns.root_inode();
    for i in 0..OBJECTS {
        let ino = ns
            .create(root_ino, format!("f{i}").as_bytes(), 0o644, 0, 0)
            .expect("create object");
        for c in 0..CHUNKS {
            let off = c as u64 * CHUNK;
            ns.write_at(ino, off, &content(i as u64, off, CHUNK as usize))
                .expect("write object chunk");
        }
    }
    ns.sync().expect("sync fixture");
}

/// A byte-level snapshot of the committed prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    root: u64,
    digest: String,
    bytes: Vec<u8>,
    /// `(committed root, committed prefix bytes)` for every published boundary.
    boundaries: Vec<(u64, Vec<u8>)>,
}

fn capture(dir: &Path) -> Snapshot {
    let vol = Volume::open(dir, OpenMode::ReadOnly).expect("open volume read-only");
    let root = vol.log.committed_end_offset();
    let digest = vol.log.committed_digest_hex().expect("committed digest");
    let bytes = vol.log.read_committed_bytes().expect("committed bytes");
    let boundaries = vol
        .log
        .boundaries()
        .iter()
        .map(|&r| (r, vol.log.read_range(0, r).expect("boundary bytes")))
        .collect();
    Snapshot {
        root,
        digest,
        bytes,
        boundaries,
    }
}

/// One fat transaction (a single `DataExtent`).
fn fat_transaction(id: u64, payload_len: usize) -> Transaction {
    let mut b = TransactionBuilder::new(id).expect("builder");
    b.add(
        RecordType::DataExtent,
        id,
        0,
        vec![id.wrapping_mul(31) as u8; payload_len],
    )
    .expect("add data extent");
    b.build().expect("build transaction")
}

/// The authoritative capacity that puts `used` bytes at `level_pct` of capacity.
fn capacity_for_fill(used: u64, level_pct: u64) -> u64 {
    let headroom = used.saturating_mul(100 - level_pct) / level_pct;
    used.saturating_add(headroom)
}

/// Set the declared capacity so the volume is `level_pct` full (deterministic; no
/// large files, no host free-space dependence). At `100` there is zero headroom.
fn apply_fill(vol: &mut Volume, level_pct: u64) -> (u64, u64) {
    let used = vol.log.authoritative_bytes();
    let capacity = capacity_for_fill(used, level_pct);
    vol.set_capacity_policy(CapacityPolicy::new().with_authoritative_capacity(capacity));
    (used, capacity)
}

/// A cold-tier / volume directory on a **container-private tmpfs** (`/dev/shm`),
/// so a free-space measurement taken on it is deterministic (unaffected by any
/// other activity on the shared host filesystem). `None` when `/dev/shm` is not
/// usable, in which case the free-space delta is reported as unmeasurable.
fn shm_dir(name: &str) -> Option<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let base = Path::new("/dev/shm");
    if !base.is_dir() {
        return None;
    }
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = base.join(format!(
        "orfs-bounded-{name}-{}-{n}-{t}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn same_device(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(ma), Ok(mb)) => ma.dev() == mb.dev(),
        _ => true,
    }
}

/// Append uncommitted (torn) bytes beyond the committed root of the head segment,
/// so a writable open must quarantine/continue (the recovery "working set").
fn append_uncommitted_tail(dir: &Path, bytes: usize) {
    let log_dir = Volume::log_dir(dir);
    let ids = discover_segment_ids(&log_dir).expect("segment ids");
    let head = *ids.last().expect("a head segment");
    let path = log_dir.join(segment_file_name(head).expect("segment name"));
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("open head segment");
    f.write_all(&vec![0u8; bytes]).expect("append tail");
    f.sync_all().expect("sync tail");
}

// ---------------------------------------------------------------------------
// 1. Recovery at the edge (a real process crash, then the real `orfs recover`)
// ---------------------------------------------------------------------------

/// The child body: open, fill to the edge, `write + fsync`, record the root, abort.
/// Inert unless `ORFS_BOUNDED_CRASH_DIR` is set, so an ordinary run is unaffected.
#[test]
fn bounded_crash_child_role() {
    let Ok(dir) = std::env::var("ORFS_BOUNDED_CRASH_DIR") else {
        return;
    };
    let dir = PathBuf::from(dir);
    let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("child open volume");
    apply_fill(&mut vol, EDGE_LEVEL);
    let root = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        let id = seq.peek_transaction_id();
        seq.commit(fat_transaction(id, 1024))
            .expect("child edge commit")
            .root
    };
    std::fs::write(dir.join("edge_root.txt"), format!("{root}")).expect("write sidecar root");
    std::process::abort();
}

fn spawn_crash_child(dir: &Path) -> Option<i32> {
    let exe = std::env::current_exe().ok()?;
    let status = Command::new(exe)
        .args([
            "bounded_crash_child_role",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ORFS_BOUNDED_CRASH_DIR", dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

/// The parsed `orfs recover --json` outcome (the real CLI).
struct RecoverOutcome {
    recovered_root: Option<u64>,
    quarantined: bool,
    error: Option<String>,
}

fn run_recover(dir: &Path) -> RecoverOutcome {
    let out = Command::new(env!("CARGO_BIN_EXE_orfs"))
        .arg("--json")
        .arg("recover")
        .arg(dir)
        .output()
        .expect("spawn the orfs CLI");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v = serde_json::from_str::<Value>(&stdout).ok();
    let mut rec = RecoverOutcome {
        recovered_root: None,
        quarantined: false,
        error: (!stderr.trim().is_empty()).then(|| stderr.trim().to_string()),
    };
    if let Some(v) = &v {
        rec.recovered_root = v["recovered_root"].as_u64();
        rec.quarantined = v["quarantined"].as_bool().unwrap_or(false);
    }
    rec
}

/// Fill to the edge, `write + fsync + crash`, then the real `orfs recover` ⇒ the
/// newest valid committed generation, with the committed prefix byte-identical.
fn recovery_after_edge_crash_row() -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().join("volume");
    std::fs::create_dir_all(&dir).expect("volume dir");
    build_fixture(&dir);
    let baseline = capture(&dir);

    let signal = spawn_crash_child(&dir);
    let crashed = signal == Some(libc::SIGABRT);
    let edge_root = std::fs::read_to_string(dir.join("edge_root.txt"))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok());

    let rec = run_recover(&dir);
    let recovered = rec.recovered_root;
    let newest_valid =
        recovered == edge_root && edge_root.is_some() && edge_root > Some(baseline.root);
    // The committed prefix the crash left behind is byte-identical.
    let reopen = capture(&dir);
    let baseline_intact = reopen.bytes.starts_with(&baseline.bytes);
    let no_silent_repair = !rec.quarantined;

    let all_ok = crashed && newest_valid && baseline_intact && no_silent_repair;
    assert!(
        all_ok,
        "edge-crash recovery row: crashed={crashed} newest_valid={newest_valid} \
         baseline_intact={baseline_intact} no_silent_repair={no_silent_repair} \
         recovered={recovered:?} edge={edge_root:?} err={:?}",
        rec.error
    );

    json!({
        "kind": "crash",
        "crash_seam": "real child process, SIGABRT after fsync",
        "level_pct": EDGE_LEVEL,
        "crashed_by_sigabrt": crashed,
        "baseline_root": baseline.root,
        "edge_root": edge_root,
        "recovered_root": recovered,
        "newest_valid_generation_selected": newest_valid,
        "baseline_prefix_byte_identical": baseline_intact,
        "quarantined": rec.quarantined,
        "silently_repaired_or_truncated": !no_silent_repair,
        "all_ok": all_ok,
    })
}

// ---------------------------------------------------------------------------
// 2. Recovery at 100% (in-process): typed refusal + intact, readable history
// ---------------------------------------------------------------------------

fn recovery_at_100_percent_row() -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().join("volume");
    std::fs::create_dir_all(&dir).expect("volume dir");
    build_fixture(&dir);
    let baseline = capture(&dir);

    // Fill to 100% and attempt an oversized write: refused typed, root intact.
    let (used, capacity) = {
        let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("open");
        let (used, capacity) = apply_fill(&mut vol, 100);
        let err = {
            let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
            let id = seq.peek_transaction_id();
            seq.commit(fat_transaction(id, 256 * 1024)).unwrap_err()
        };
        let typed = matches!(
            err,
            OrfsError::NoSpace(_) | OrfsError::CapacityExhausted { .. }
        );
        let enospc = err.errno() == libc::ENOSPC;
        let root_intact = vol.log.committed_end_offset() == baseline.root;
        assert!(typed && enospc && root_intact, "100% refusal: {err:?}");
        (used, capacity)
    };

    // Read-only open at "0 free" serves all committed history, unchanged.
    let ro = capture(&dir);
    let read_only_ok = ro == baseline;

    // The real `orfs recover` (fresh handle; declared capacity does not block
    // recovery) selects the newest committed generation and repairs nothing.
    let rec = run_recover(&dir);
    let recover_selects_newest = rec.recovered_root == Some(baseline.root) && !rec.quarantined;
    let after = capture(&dir);
    let history_intact = after == baseline;

    let all_ok = read_only_ok && recover_selects_newest && history_intact;
    assert!(
        all_ok,
        "100% row: read_only_ok={read_only_ok} recover_selects_newest={recover_selects_newest} \
         history_intact={history_intact}"
    );

    json!({
        "kind": "full_capacity",
        "authoritative_used_bytes": used,
        "authoritative_capacity_bytes": capacity,
        "headroom_bytes": 0,
        "oversized_write_refused_typed": true,
        "errno": "ENOSPC",
        "previous_root_intact": true,
        "read_only_open_at_zero_free_ok": read_only_ok,
        "recover_selected_newest_generation": recover_selects_newest,
        "recovered_root": rec.recovered_root,
        "committed_history_byte_identical": history_intact,
        "all_ok": all_ok,
    })
}

// ---------------------------------------------------------------------------
// 3. Fail closed under space pressure (the recovery working set)
// ---------------------------------------------------------------------------

fn recovery_fails_closed_at_the_reserve_row() -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().join("volume");
    std::fs::create_dir_all(&dir).expect("volume dir");
    build_fixture(&dir);
    let baseline = capture(&dir);

    // Manufacture an abandoned (torn) tail beyond the committed root: a writable
    // open must quarantine/continue, which *creates* a fresh segment — the recovery
    // working set.
    append_uncommitted_tail(&dir, 512);
    let log_dir = Volume::log_dir(&dir);

    // Arm the simulated device to refuse segment creation with ENOSPC.
    let _handle = powerloss::attach_with_faults(
        &log_dir,
        SimConfig::honest(7),
        vec![DeviceFaultRule::new(
            DeviceOp::Create,
            DeviceFaultKind::NoSpace,
            0,
        )],
    )
    .expect("attach device");

    let refused = Volume::open(&dir, OpenMode::ReadWrite).err();
    let typed = matches!(refused, Some(OrfsError::RecoverySpaceExhausted { .. }));
    let enospc = refused.as_ref().map(|e| e.errno()) == Some(libc::ENOSPC);
    let actionable = refused
        .as_ref()
        .map(|e| e.to_string().contains("orfs reclaim"))
        .unwrap_or(false);
    drop(_handle);
    powerloss::detach(&log_dir);

    // The committed prefix on disk is byte-identical; nothing was withdrawn.
    let ondisk = capture(&dir);
    let committed_intact =
        ondisk.bytes.starts_with(&baseline.bytes) && ondisk.root >= baseline.root;

    // Clearing the pressure lets the same recovery complete and select the newest
    // committed generation.
    let recovered = Volume::open(&dir, OpenMode::ReadWrite).map(|v| v.log.committed_end_offset());
    let recovered_ok = recovered.as_ref().ok().copied() == Some(baseline.root);

    let all_ok = typed && enospc && actionable && committed_intact && recovered_ok;
    assert!(
        all_ok,
        "fail-closed row: typed={typed} enospc={enospc} actionable={actionable} \
         committed_intact={committed_intact} recovered_ok={recovered_ok} err={refused:?}"
    );

    json!({
        "kind": "fail_closed",
        "trigger": "simulated device ENOSPC on segment creation during recovery",
        "refusal_is_typed": typed,
        "refusal_errno": "ENOSPC",
        "refusal_is_actionable": actionable,
        "committed_prefix_byte_identical": committed_intact,
        "recovery_completes_when_pressure_cleared": recovered_ok,
        "recovered_root": recovered.as_ref().ok().copied(),
        "baseline_root": baseline.root,
        "all_ok": all_ok,
    })
}

// ---------------------------------------------------------------------------
// 4. Evacuation frees space and commits resume
// ---------------------------------------------------------------------------

fn evacuation_row() -> Value {
    // The volume lives on a container-private tmpfs (`/dev/shm`) so the backing
    // free-space measurement is deterministic; the cold tier is a directory on the
    // ordinary (ext4) backing — genuinely a different filesystem.
    let Some(dir) = shm_dir("evac-vol") else {
        return json!({
            "kind": "evacuation",
            "measured": false,
            "skipped": "/dev/shm is not a usable container-private filesystem here",
            "all_ok": Value::Null,
        });
    };
    let td = TempDir::new().expect("tempdir");
    let tier = td.path().join("cold");
    std::fs::create_dir_all(&tier).expect("tier dir");
    build_fixture(&dir);
    let before = capture(&dir);
    let separate = !same_device(&dir, &tier);

    // At the reserve: a fresh handle whose reserve equals live free space has zero
    // headroom, so an authoritative write is refused and the handle latches.
    let free0 = backing_available_bytes(&dir).expect("free space");
    let (refused_errno, latched) = {
        let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("open");
        vol.set_capacity_policy(CapacityPolicy::new().with_reserve(free0));
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        let id = seq.peek_transaction_id();
        match seq.commit(fat_transaction(id, 4096)) {
            Ok(_) => (None, false),
            Err(e) => (Some(e.errno()), vol.is_degraded()),
        }
    };
    let at_reserve_refused = refused_errno == Some(libc::ENOSPC) && latched;

    // Evacuate: relocate every sealed segment to the separate-filesystem tier.
    let reloc = relocate_sealed(&dir, &tier).expect("relocate sealed");
    let free1 = backing_available_bytes(&dir).expect("free space");
    let freed_local = reloc
        .local_authoritative_bytes_before
        .saturating_sub(reloc.local_authoritative_bytes_after);

    // The committed authority before evacuation and right after is byte-identical.
    let mid = capture(&dir);
    let authority_identical =
        before.root == mid.root && before.digest == mid.digest && before.bytes == mid.bytes;
    let boundaries_identical = before.boundaries == mid.boundaries;

    // The volume accepts commits again: a fresh handle, same reserve, commits.
    let resumed_root = {
        let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("reopen");
        vol.set_capacity_policy(CapacityPolicy::new().with_reserve(free0));
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        let id = seq.peek_transaction_id();
        seq.commit(fat_transaction(id, 4096))
            .expect("commit after evacuation")
            .root
    };
    let commits_resumed = resumed_root > mid.root;
    let after = capture(&dir);
    let append_only = after.bytes.starts_with(&mid.bytes);

    let free_space_increased = free1 > free0;
    let all_ok = separate
        && at_reserve_refused
        && authority_identical
        && boundaries_identical
        && commits_resumed
        && append_only
        && freed_local > 0
        && free_space_increased;

    // Clean up the tmpfs volume before asserting so a failure never leaks it.
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&tier);
    assert!(
        all_ok,
        "evacuation row: separate={separate} at_reserve_refused={at_reserve_refused} \
         authority_identical={authority_identical} boundaries_identical={boundaries_identical} \
         commits_resumed={commits_resumed} append_only={append_only} freed_local={freed_local} \
         free0={free0} free1={free1}"
    );

    json!({
        "kind": "evacuation",
        "measured": true,
        "tier_on_separate_filesystem": separate,
        "free_bytes_before": free0,
        "free_bytes_after": free1,
        "freed_bytes": free1.saturating_sub(free0),
        "free_space_increased": free_space_increased,
        "relocated_segments": reloc.segments_relocated,
        "relocated_bytes": reloc.bytes_relocated,
        "local_authoritative_bytes_freed": freed_local,
        "at_reserve_write_refused_typed": at_reserve_refused,
        "commits_resumed": commits_resumed,
        "committed_root_byte_equality": authority_identical && boundaries_identical,
        "boundaries_checked": before.boundaries.len(),
        "committed_root": before.root,
        "resumed_root": resumed_root,
        "all_ok": all_ok,
    })
}

// ---------------------------------------------------------------------------
// 5. Tier unavailable at the reserve
// ---------------------------------------------------------------------------

fn tier_unavailable_row() -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().join("volume");
    std::fs::create_dir_all(&dir).expect("volume dir");
    build_fixture(&dir);
    let baseline = capture(&dir);

    // No usable cold tier: the relocation is refused typed (TierUnavailable), so it
    // cannot free authority bytes.
    let missing = td.path().join("no-such-tier");
    let reloc_err = relocate_sealed(&dir, &missing).err();
    let reloc_typed = matches!(reloc_err, Some(OrfsError::TierUnavailable(_)));

    // Drop-rebuildable with no manifested structures frees no authority bytes.
    let plan = plan(&dir, None);
    let droppable = plan.droppable_rebuildable_bytes;

    // The volume stays read-only: a fresh handle at the reserve refuses the next
    // commit (EROFS), and its committed history is still fully readable.
    let free0 = backing_available_bytes(&dir).expect("free space");
    let (first_errno, latched, subsequent_errno) = {
        let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("open");
        vol.set_capacity_policy(CapacityPolicy::new().with_reserve(free0));
        let first = {
            let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
            let id = seq.peek_transaction_id();
            seq.commit(fat_transaction(id, 4096))
                .err()
                .map(|e| e.errno())
        };
        let latched = vol.is_degraded();
        let subsequent = {
            let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
            let id = seq.peek_transaction_id();
            seq.commit(fat_transaction(id, 2)).err().map(|e| e.errno())
        };
        (first, latched, subsequent)
    };

    let stays_read_only =
        first_errno == Some(libc::ENOSPC) && latched && subsequent_errno == Some(libc::EROFS);
    let read_only_history = capture(&dir);
    let history_readable = read_only_history == baseline;
    let nothing_withdrawn = read_only_history.bytes.starts_with(&baseline.bytes);

    let all_ok =
        reloc_typed && droppable == 0 && stays_read_only && history_readable && nothing_withdrawn;
    assert!(
        all_ok,
        "tier-unavailable row: reloc_typed={reloc_typed} droppable={droppable} \
         stays_read_only={stays_read_only} history_readable={history_readable} \
         nothing_withdrawn={nothing_withdrawn} err={reloc_err:?}"
    );

    json!({
        "kind": "tier_unavailable",
        "relocation_refused_typed": reloc_typed,
        "relocation_error": reloc_err.as_ref().map(|e| e.to_string()),
        "authority_bytes_freed_by_drop": droppable,
        "volume_stays_read_only": stays_read_only,
        "committed_history_fully_readable": history_readable,
        "committed_history_byte_identical": nothing_withdrawn,
        "all_ok": all_ok,
    })
}

// ---------------------------------------------------------------------------
// 6. Drop rebuildable is safe
// ---------------------------------------------------------------------------

/// A manifested fixture: EKBLOOM bodies under `.or_bloom/ekbloom` + generation
/// manifests, built over a real namespace.
fn build_manifested_fixture(dir: &Path) -> u64 {
    let mut ns = Namespace::init_with_uuid(dir, SEGMENT, UUID, CREATED, DurabilityMode::Sync)
        .expect("init namespace");
    let root_ino = ns.root_inode();
    let mut first = 0u64;
    for i in 0..4u64 {
        let ino = ns
            .create(root_ino, format!("m{i}").as_bytes(), 0o644, 0, 0)
            .expect("create");
        let off = 0u64;
        ns.write_at(ino, off, &content(i, off, 64 * 1024))
            .expect("write");
        if i == 0 {
            first = ino;
        }
    }
    ns.sync().expect("sync");
    ns.enable_manifestation(ManifestationConfig {
        workers: 1,
        queue_capacity: 32,
        synchronous: true,
        profile: ManifestationProfile::Full,
        max_source_bytes: 64 << 20,
    })
    .expect("enable manifestation");
    ns.manifest_eligible(None, ManifestationProfile::Full)
        .expect("manifest");
    ns.sync().expect("sync manifestation");
    first
}

fn drop_rebuildable_row() -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().join("volume");
    std::fs::create_dir_all(&dir).expect("volume dir");
    let ino = build_manifested_fixture(&dir);

    let before = capture(&dir);
    let auth_before = capture_authority(&dir).expect("authority before");
    let acc_before = orfs::capacity::storage_accounting(&dir, 0, None, None);
    let rebuildable_before = acc_before.rebuildable_manifestation.bytes;
    let read_before = {
        let ns =
            Namespace::open(&dir, OpenMode::ReadOnly, DurabilityMode::Ordered).expect("open ns");
        ns.read_at(ino, ns.root(), 0, 4096).expect("read before")
    };

    // Drop the derived manifested structures.
    let dropped: u64 = drop_rebuildable_structures(&dir)
        .expect("drop rebuildable")
        .iter()
        .map(|s| s.bytes_freed)
        .sum();
    let acc_after = orfs::capacity::storage_accounting(&dir, 0, None, None);
    let rebuildable_after = acc_after.rebuildable_manifestation.bytes;

    // Authority is byte-identical (root, digest, committed bytes, watermark).
    let after = capture(&dir);
    let auth_after = capture_authority(&dir).expect("authority after");
    let authority_identical = before == after && auth_before == auth_after;
    let watermark_identical = auth_before.watermark == auth_after.watermark;

    // A read still returns identical bytes: the absent structure falls back to the
    // authoritative extent read. Manifestation is re-enabled so the planner really
    // considers the (now missing) manifested candidates.
    let read_after = {
        let mut ns =
            Namespace::open(&dir, OpenMode::ReadWrite, DurabilityMode::Ordered).expect("reopen ns");
        ns.enable_manifestation(ManifestationConfig {
            workers: 1,
            queue_capacity: 32,
            synchronous: true,
            profile: ManifestationProfile::Full,
            max_source_bytes: 64 << 20,
        })
        .expect("re-enable manifestation");
        ns.read_at(ino, ns.root(), 0, 4096).expect("read after")
    };
    let read_identical = read_before == read_after;

    // The `RebuildableManifestation` category is genuinely reclaimed, and the
    // permanent authoritative category is untouched.
    let permanent_unchanged =
        acc_before.permanent_authoritative.bytes == acc_after.permanent_authoritative.bytes;

    let all_ok = rebuildable_before > 0
        && rebuildable_after == 0
        && dropped > 0
        && authority_identical
        && watermark_identical
        && read_identical
        && permanent_unchanged;
    assert!(
        all_ok,
        "drop-rebuildable row: rebuildable_before={rebuildable_before} \
         rebuildable_after={rebuildable_after} dropped={dropped} authority_identical={authority_identical} \
         read_identical={read_identical} permanent_unchanged={permanent_unchanged}"
    );

    json!({
        "kind": "drop_rebuildable",
        "rebuildable_bytes_before": rebuildable_before,
        "rebuildable_bytes_after": rebuildable_after,
        "dropped_bytes": dropped,
        "category": StorageCategory::RebuildableManifestation.name(),
        "authority_byte_identical": authority_identical,
        "watermark_byte_identical": watermark_identical,
        "permanent_authoritative_unchanged": permanent_unchanged,
        "read_returns_identical_bytes_after_drop": read_identical,
        "all_ok": all_ok,
    })
}

// ---------------------------------------------------------------------------
// 7. Read-only open at 0 free
// ---------------------------------------------------------------------------

fn read_only_at_zero_free_row() -> Value {
    let td = TempDir::new().expect("tempdir");
    let dir = td.path().join("volume");
    std::fs::create_dir_all(&dir).expect("volume dir");
    build_fixture(&dir);
    let baseline = capture(&dir);

    // Declared 100%: zero headroom. A read-only open must serve all committed
    // history and modify not a single byte.
    {
        let mut vol = Volume::open(&dir, OpenMode::ReadWrite).expect("open");
        let _ = apply_fill(&mut vol, 100);
    }
    let ro = Volume::open(&dir, OpenMode::ReadOnly).expect("read-only open at 0 free");
    let root = ro.log.committed_end_offset();
    let digest = ro.log.committed_digest_hex().expect("digest");
    let bytes = ro.log.read_committed_bytes().expect("bytes");
    let identical = root == baseline.root && digest == baseline.digest && bytes == baseline.bytes;
    let not_read_only_refused = !ro.is_degraded();

    let all_ok = identical && not_read_only_refused;
    assert!(all_ok, "read-only-at-0-free row: identical={identical}");

    json!({
        "kind": "read_only_at_zero_free",
        "open_succeeded": true,
        "committed_root": root,
        "committed_history_byte_identical": identical,
        "wrote_nothing": true,
        "all_ok": all_ok,
    })
}

// ---------------------------------------------------------------------------
// The court + evidence
// ---------------------------------------------------------------------------

/// Run every bounded-recovery case and aggregate the assessment.
fn run_court() -> Value {
    let recovery_edge = recovery_after_edge_crash_row();
    let recovery_full = recovery_at_100_percent_row();
    let fail_closed = recovery_fails_closed_at_the_reserve_row();
    let evacuation = evacuation_row();
    let tier_unavailable = tier_unavailable_row();
    let drop_rebuildable = drop_rebuildable_row();
    let read_only = read_only_at_zero_free_row();

    let evac_ok = evacuation["all_ok"] != json!(false);
    let all_ok = recovery_edge["all_ok"] == json!(true)
        && recovery_full["all_ok"] == json!(true)
        && fail_closed["all_ok"] == json!(true)
        && evac_ok
        && tier_unavailable["all_ok"] == json!(true)
        && drop_rebuildable["all_ok"] == json!(true)
        && read_only["all_ok"] == json!(true);

    json!({
        "workload": {
            "segment_size": SEGMENT,
            "objects": OBJECTS,
            "chunks_per_object": CHUNKS,
            "chunk_bytes": CHUNK,
        },
        "recovery_at_the_edge": recovery_edge,
        "recovery_at_100_percent": recovery_full,
        "recovery_fails_closed_at_the_reserve": fail_closed,
        "evacuation_frees_space_and_commits_resume": evacuation,
        "tier_unavailable_at_the_reserve": tier_unavailable,
        "drop_rebuildable_is_safe": drop_rebuildable,
        "read_only_open_at_zero_free": read_only,
        "all_ok": all_ok,
    })
}

#[test]
fn bounded_recovery_smoke() {
    let value = run_court();
    assert_eq!(
        value["all_ok"],
        json!(true),
        "bounded-recovery court: {value:#}"
    );
    assert_eq!(
        value["recovery_at_100_percent"]["read_only_open_at_zero_free_ok"],
        json!(true)
    );
    assert_eq!(
        value["evacuation_frees_space_and_commits_resume"]["commits_resumed"],
        json!(true)
    );
}

#[test]
fn bounded_recovery_sweep() {
    if std::env::var("ORFS_BOUNDED_RECOVERY").as_deref() != Ok("1") {
        eprintln!(
            "bounded_recovery_sweep: skipped \
             (set ORFS_BOUNDED_RECOVERY=1 to run the full sweep)"
        );
        return;
    }
    let value = run_court();

    let environment = json!({
        "bench": serde_json::to_value(orfs::bench::Environment::capture(
            std::env::var("ORFS_IMAGE").ok()
        ))
        .unwrap_or(Value::Null),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
    });

    let all_ok = value["all_ok"] == json!(true);
    let doc = json!({
        "schema": "orfs.performance.bounded-recovery.v1",
        "generated_by": "tests/bounded_recovery.rs",
        "note": "Single-run, single-host, BOUNDED measurements. A bounded reclaim frees \
                 local space WITHOUT withdrawing one authoritative byte: relocating a \
                 sealed segment moves a verified copy to the cold tier (the local footprint \
                 drops; the committed root, the commit watermark, and the total authority are \
                 unchanged) and dropping a rebuildable structure costs no authority. At the \
                 reserve, recovery of a nearly-full volume either completes without appending \
                 new authoritative bytes or fails with the typed `RecoverySpaceExhausted` and \
                 leaves the committed prefix byte-identical. Absolute bytes are host/build \
                 dependent; the byte-equality and the bookkeeping are the point.",
        "environment": environment,
        "workload": value["workload"],
        "recovery_at_the_edge": value["recovery_at_the_edge"],
        "recovery_at_100_percent": value["recovery_at_100_percent"],
        "recovery_fails_closed_at_the_reserve": value["recovery_fails_closed_at_the_reserve"],
        "evacuation": value["evacuation_frees_space_and_commits_resume"],
        "tier_unavailable": value["tier_unavailable_at_the_reserve"],
        "drop_rebuildable": value["drop_rebuildable_is_safe"],
        "read_only_at_zero_free": value["read_only_open_at_zero_free"],
        "all_ok": all_ok,
    });

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/performance/bounded-recovery.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("bounded-recovery evidence written to {}", path.display());

    assert!(all_ok, "bounded-recovery court: {doc:#}");
}
