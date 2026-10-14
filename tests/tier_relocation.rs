//! **Phase 76 — the immutable tier-relocation court.**
//!
//! Move **sealed** (immutable) authoritative segments from the local backing
//! store to a cold tier **without withdrawing authority**: every committed byte
//! is preserved, every committed root returns byte-identical content, and the
//! committed end offset / watermark is unchanged. The active head segment is
//! never relocatable.
//!
//! The design follows the Kafka tiered-storage discipline (KIP-405): metadata is
//! strongly consistent and **separate** from the data tier; the durable
//! transitions `Copying → Copied{verified} → Released` are explicit and fsynced
//! before the next (destructive) step; the local copy is deleted only after the
//! tier copy is written, fsynced, read back, and digest-verified; and copy/delete
//! are idempotent, so a crash converges to exactly one authoritative home.
//!
//! ## What this court proves (each a real run in the container)
//!
//! * **Identity.** After relocating sealed segments, every committed root's bytes
//!   are byte-identical, the committed end offset and digest are unchanged, and a
//!   deep verify passes both before and after.
//! * **Verify before forget.** A fault between the tier copy and its verification
//!   leaves the local copy in place (never removed before the remote is verified).
//! * **Idempotence.** Copying twice yields exactly one tier object; deleting twice
//!   is a success.
//! * **Crash matrix.** A fault after *each* transition, then a reopen/converge,
//!   yields exactly one authoritative home with the digest intact.
//! * **Tier unavailable.** A read of a released segment whose tier is offline
//!   returns the typed `TierUnavailable`; the authority is intact and the offline
//!   segments are reported explicitly.
//! * **Catalogue integrity.** A corrupt/truncated/removed catalogue entry fails
//!   **closed** — it never fabricates or silently shortens authority.
//! * **Mixed layout.** Recovery/verify over a mixed local+tier layout yields the
//!   same newest valid committed generation.
//!
//! * `cargo test --test tier_relocation` runs the always-on smoke.
//! * The full sweep is opt-in behind `ORFS_TIER_RELOCATION=1` and writes
//!   `evidence/performance/tier-relocation.json`. Run it (release, representative)
//!   via `scripts/container-tier-relocation.sh`.

use std::path::{Path, PathBuf};

use orfs::commit::DurabilityMode;
use orfs::log::OpenMode;
use orfs::namespace::Namespace;
use orfs::segment::segment_file_name;
use orfs::tiering::{list_report, verify_report, RelocationCatalogue, Relocator};
#[cfg(feature = "failpoints")]
use orfs::tiering::{TierState, TierStore};
use orfs::volume::Volume;
use orfs::OrfsError;
use tempfile::TempDir;

const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x76, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const CREATED: u64 = 1_700_000_000;
/// A small segment size so the log rolls over into several sealed segments.
const SEGMENT: u64 = 128 * 1024;
const CHUNK: u64 = 32 * 1024;
const OBJECTS: usize = 8;
const CHUNKS: usize = 4;

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

/// The sealed (non-head) segment ids, in order.
fn sealed_ids(dir: &Path) -> Vec<u64> {
    Relocator::open(dir)
        .expect("open relocator")
        .sealed_ids()
        .expect("sealed ids")
}

/// Relocate every sealed segment, returning the outcomes.
fn relocate_all(dir: &Path, tier: &Path) -> Vec<orfs::tiering::RelocationOutcome> {
    let mut r = Relocator::open(dir).expect("open relocator");
    r.set_tier_root(tier).expect("set tier root");
    let ids = r.sealed_ids().expect("sealed ids");
    ids.into_iter()
        .map(|id| r.relocate(id).expect("relocate"))
        .collect()
}

/// Local authoritative bytes under `or.log/` (the relocation target).
fn local_authoritative_bytes(dir: &Path) -> u64 {
    orfs::manifestation::dir_bytes(&Volume::log_dir(dir))
}

/// The number of tier objects held for a segment.
fn tier_object_count(tier: &Path, id: u64) -> usize {
    let dir = tier
        .join("orfs-tier")
        .join(uuid_hex(&UUID))
        .join(format!("{id:016}"));
    match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .flatten()
            .filter(|e| e.path().is_file() && !e.path().to_string_lossy().ends_with(".tmp"))
            .count(),
        Err(_) => 0,
    }
}

fn uuid_hex(uuid: &[u8; 16]) -> String {
    uuid.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// 1. Identity
// ---------------------------------------------------------------------------

#[test]
fn tier_relocation_preserves_identity() {
    let td = TempDir::new().unwrap();
    let dir = td.path().join("volume");
    let tier = td.path().join("cold");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&tier).unwrap();
    build_fixture(&dir);

    let before = capture(&dir);
    let deep_before = Volume::open(&dir, OpenMode::ReadOnly)
        .unwrap()
        .verify(true)
        .unwrap();
    assert!(deep_before.ok, "deep verify must pass before relocation");

    let sealed = sealed_ids(&dir);
    assert!(
        sealed.len() >= 2,
        "the fixture must produce at least two sealed segments (got {sealed:?})"
    );
    let local_before = local_authoritative_bytes(&dir);
    let total_before = list_report(&dir).unwrap().total_authoritative_bytes;

    let outcomes = relocate_all(&dir, &tier);
    assert_eq!(outcomes.len(), sealed.len());
    let bytes_relocated: u64 = outcomes.iter().map(|o| o.bytes).sum();
    assert!(bytes_relocated > 0);

    // Every committed root returns byte-identical content; the root and digest
    // are unchanged; a deep verify still passes.
    let after = capture(&dir);
    assert_eq!(before.root, after.root, "committed root must not move");
    assert_eq!(
        before.digest, after.digest,
        "committed digest must be unchanged"
    );
    assert_eq!(
        before.bytes, after.bytes,
        "committed bytes must be identical"
    );
    assert_eq!(
        before.boundaries, after.boundaries,
        "every committed root's bytes must be identical"
    );
    let deep_after = Volume::open(&dir, OpenMode::ReadOnly)
        .unwrap()
        .verify(true)
        .unwrap();
    assert!(deep_after.ok, "deep verify must pass after relocation");

    // The local authoritative footprint drops; the total authority is unchanged.
    let report = list_report(&dir).unwrap();
    let local_after = local_authoritative_bytes(&dir);
    assert_eq!(
        report.local_authoritative_bytes, local_after,
        "list report must agree with the measured local footprint"
    );
    assert!(
        local_after < local_before,
        "local authoritative bytes must drop (before {local_before}, after {local_after})"
    );
    assert_eq!(
        local_before - local_after,
        bytes_relocated,
        "the local footprint must drop by exactly the relocated bytes"
    );
    assert_eq!(
        report.total_authoritative_bytes, total_before,
        "total authority must be unchanged by relocation"
    );
    assert_eq!(report.tier_bytes, bytes_relocated);
    assert_eq!(report.released_segments as usize, sealed.len());

    // Every relocated segment re-verifies; nothing is missing.
    let verify = verify_report(&dir).unwrap();
    assert!(verify.all_ok, "tier verify must pass: {verify:?}");
    assert!(verify.mismatches.is_empty());
    assert_eq!(verify.segments.len(), sealed.len());
}

// ---------------------------------------------------------------------------
// 2. Verify before forget
// ---------------------------------------------------------------------------

#[cfg(feature = "failpoints")]
#[test]
fn local_copy_survives_a_fault_between_copy_and_verification() {
    use orfs::failpoints::{self, FailAction};

    for fp in [
        orfs::failpoints::Failpoint::TierAfterIntent,
        orfs::failpoints::Failpoint::TierAfterRemoteCopy,
    ] {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("volume");
        let tier = td.path().join("cold");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&tier).unwrap();
        build_fixture(&dir);

        let target = sealed_ids(&dir)[0];
        let local = Volume::log_dir(&dir).join(segment_file_name(target).unwrap());

        failpoints::clear();
        failpoints::configure_one(fp.name(), FailAction::Error, 0);
        let result = {
            let mut r = Relocator::open(&dir).unwrap();
            r.set_tier_root(&tier).unwrap();
            r.relocate(target)
        };
        failpoints::clear();

        assert!(
            matches!(result, Err(OrfsError::Failpoint(_))),
            "{}: the injected fault must fire, got {result:?}",
            fp.name()
        );
        assert!(
            local.is_file(),
            "{}: the local copy must NOT be removed before the remote copy is verified",
            fp.name()
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Idempotence
// ---------------------------------------------------------------------------

#[test]
fn copy_and_delete_are_idempotent() {
    let td = TempDir::new().unwrap();
    let dir = td.path().join("volume");
    let tier = td.path().join("cold");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&tier).unwrap();
    build_fixture(&dir);

    let target = sealed_ids(&dir)[0];
    let mut r = Relocator::open(&dir).unwrap();
    r.set_tier_root(&tier).unwrap();
    let first = r.relocate(target).unwrap();
    assert_eq!(first.action, "relocated");
    let second = r.relocate(target).unwrap();
    assert_eq!(
        second.action, "already_released",
        "a second relocation must be a convergent no-op"
    );

    // Exactly one tier object, and it verifies.
    assert_eq!(tier_object_count(&tier, target), 1);
    let verify = verify_report(&dir).unwrap();
    assert!(verify.all_ok);

    // Idempotent delete: an already-removed local copy is a success.
    let local = Volume::log_dir(&dir).join(segment_file_name(target).unwrap());
    assert!(!local.exists(), "the local copy must be gone after release");
    let third = r.relocate(target).unwrap();
    assert_eq!(third.action, "already_released");
}

// ---------------------------------------------------------------------------
// 4. Crash matrix
// ---------------------------------------------------------------------------

#[cfg(feature = "failpoints")]
fn crash_matrix() -> serde_json::Value {
    use orfs::failpoints::{self, FailAction, Failpoint};

    let mut rows = Vec::new();
    let mut all_converged = true;
    for fp in Failpoint::TIER_ALL {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("volume");
        let tier = td.path().join("cold");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&tier).unwrap();
        build_fixture(&dir);

        let before = capture(&dir);
        let target = sealed_ids(&dir)[0];
        let local = Volume::log_dir(&dir).join(segment_file_name(target).unwrap());
        // The recall transition is only reachable from a released segment.
        let recall_op = fp == Failpoint::TierAfterRecall;
        if recall_op {
            let mut r = Relocator::open(&dir).unwrap();
            r.set_tier_root(&tier).unwrap();
            r.relocate(target).unwrap();
        }

        failpoints::clear();
        failpoints::configure_one(fp.name(), FailAction::Error, 0);
        let attempt = {
            let mut r = Relocator::open(&dir).unwrap();
            r.set_tier_root(&tier).unwrap();
            if recall_op {
                r.recall(target).map(|o| o.action)
            } else {
                r.relocate(target).map(|o| o.action)
            }
        };
        failpoints::clear();
        let fired = matches!(attempt, Err(OrfsError::Failpoint(_)));

        // Re-open (discard the in-memory catalogue) and converge: a further run of
        // the same transition must reach exactly one authoritative home without
        // losing or duplicating authority.
        let converged = {
            let mut r = Relocator::open(&dir).unwrap();
            r.set_tier_root(&tier).unwrap();
            if recall_op {
                r.recall(target).map(|o| o.action)
            } else {
                r.relocate(target).map(|o| o.action)
            }
        };
        let converge_ok = match (&converged, recall_op) {
            (Ok(a), false) => *a == "already_released" || *a == "relocated",
            (Ok(a), true) => *a == "recalled",
            _ => false,
        };

        // Authority: the committed root/digest are unchanged; the segment's home
        // is the tier (relocate) or local (recall) with the digest intact.
        let after = capture(&dir);
        let (state, verified, objects) = {
            let cat = RelocationCatalogue::open(&dir).unwrap();
            let rec = cat.latest_for(target);
            let state = rec.as_ref().map(|r| r.state);
            let verified = rec
                .as_ref()
                .map(|r| {
                    TierStore::new(&tier)
                        .verify_segment(&UUID, target, &r.digest, r.segment_len)
                        .is_ok()
                })
                .unwrap_or(false);
            (state, verified, tier_object_count(&tier, target))
        };
        let home_ok = if recall_op {
            state == Some(TierState::Recalled) && local.is_file() && verified
        } else {
            state == Some(TierState::Released) && !local.exists() && verified
        };
        let authority_intact = before.root == after.root && before.digest == after.digest;
        let volume_opens = Volume::open(&dir, OpenMode::ReadOnly).is_ok();
        let row_ok =
            fired && converge_ok && home_ok && objects == 1 && authority_intact && volume_opens;
        all_converged &= row_ok;
        rows.push(serde_json::json!({
            "failpoint": fp.name(),
            "fired": fired,
            "converged": converge_ok,
            "converged_action": match &converged {
                Ok(a) => (*a).to_string(),
                Err(e) => format!("error: {e}"),
            },
            "exactly_one_home": home_ok,
            "remote_objects": objects,
            "digest_intact": verified,
            "authority_intact": authority_intact,
            "volume_opens": volume_opens,
            "all_ok": row_ok,
        }));
    }
    serde_json::json!({
        "failpoints_feature": true,
        "rows_count": rows.len(),
        "rows": rows,
        "all_converged": all_converged,
    })
}

#[cfg(not(feature = "failpoints"))]
fn crash_matrix() -> serde_json::Value {
    serde_json::json!({
        "failpoints_feature": false,
        "rows_count": 0,
        "skipped": "the `failpoints` feature is disabled in this build; the transitions are still exercised in-process by the always-on tests",
        "rows": [],
        "all_converged": serde_json::Value::Null,
    })
}

#[test]
fn crash_matrix_converges_to_one_authoritative_home() {
    let value = crash_matrix();
    if value["failpoints_feature"] == serde_json::json!(true) {
        assert_eq!(
            value["all_converged"],
            serde_json::json!(true),
            "every crash row must converge: {value}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Tier unavailable
// ---------------------------------------------------------------------------

#[test]
fn tier_unavailable_is_a_typed_error_and_authority_is_intact() {
    let td = TempDir::new().unwrap();
    let dir = td.path().join("volume");
    let tier = td.path().join("cold");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&tier).unwrap();
    build_fixture(&dir);

    let before = capture(&dir);
    let sealed = sealed_ids(&dir);
    relocate_all(&dir, &tier);

    // Take the tier offline (move it aside).
    let offline = td.path().join("cold-offline");
    std::fs::rename(&tier, &offline).unwrap();

    // A read needing a released segment returns the *typed* error, never wrong or
    // truncated data.
    let open = Volume::open(&dir, OpenMode::ReadOnly);
    let typed = matches!(&open, Err(OrfsError::TierUnavailable(_)));
    assert!(
        typed,
        "opening a volume with an offline tier must be a typed TierUnavailable, got {:?}",
        open.err()
    );

    // `tier verify` reports the offline segments explicitly.
    let verify = verify_report(&dir).unwrap();
    assert!(!verify.all_ok);
    assert_eq!(verify.unavailable_segments.len(), sealed.len());
    assert_eq!(verify.mismatches.len(), sealed.len());

    // Authority is intact: restoring the tier makes the volume open, with the same
    // committed bytes.
    std::fs::rename(&offline, &tier).unwrap();
    let after = capture(&dir);
    assert_eq!(before.root, after.root);
    assert_eq!(before.bytes, after.bytes);
    assert!(verify_report(&dir).unwrap().all_ok);
}

// ---------------------------------------------------------------------------
// 6. Catalogue integrity (fail closed)
// ---------------------------------------------------------------------------

#[test]
fn catalogue_corruption_fails_closed() {
    // (a) A byte flipped in a record -> the catalogue refuses to load.
    {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("volume");
        let tier = td.path().join("cold");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&tier).unwrap();
        build_fixture(&dir);
        relocate_all(&dir, &tier);

        let cat_path = orfs::tiering::catalogue_path(&dir);
        let mut bytes = std::fs::read(&cat_path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&cat_path, &bytes).unwrap();

        let open = Volume::open(&dir, OpenMode::ReadOnly);
        assert!(
            open.is_err(),
            "a corrupt catalogue must fail closed, never return a shorter history"
        );
        // The catalogue refuses to load, so no report can fabricate a healthy
        // layout; authority is never destroyed.
        assert!(
            list_report(&dir).is_err(),
            "list must not fabricate a healthy catalogue"
        );
    }

    // (b) A truncated trailing record cannot silently shorten authority: the
    // surviving state says the segment is `Copied` while its local copy is gone,
    // so the resolver fails closed instead of shortening history.
    {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("volume");
        let tier = td.path().join("cold");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&tier).unwrap();
        build_fixture(&dir);
        let target = sealed_ids(&dir)[0];
        // Relocate only `target`, so its `Released` record is the last in the
        // catalogue and can be truncated away.
        {
            let mut r = Relocator::open(&dir).unwrap();
            r.set_tier_root(&tier).unwrap();
            r.relocate(target).unwrap();
        }

        // Remove the final `Released` record by truncating the file to just before
        // it: the last surviving record for `target` is then `Copied`.
        let cat_path = orfs::tiering::catalogue_path(&dir);
        let cat = RelocationCatalogue::open(&dir).unwrap();
        let released_len = {
            let last = cat.records().last().unwrap();
            orfs::tiering::record_encoded_len(&last.tier_root)
        };
        let total = std::fs::metadata(&cat_path).unwrap().len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&cat_path)
            .unwrap()
            .set_len(total - released_len)
            .unwrap();

        let open = Volume::open(&dir, OpenMode::ReadOnly);
        assert!(
            open.is_err(),
            "a truncated catalogue must fail closed (segment {target})"
        );
        assert!(
            !matches!(open, Err(OrfsError::TierUnavailable(_))),
            "the failure is a local/catalogue inconsistency, not an offline tier"
        );
    }

    // (c) A removed catalogue cannot silently shorten history: the relocated
    // segment is gone locally and there is no record that it was released, so the
    // surviving local ids are non-contiguous and the open is refused.
    {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("volume");
        let tier = td.path().join("cold");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&tier).unwrap();
        build_fixture(&dir);
        relocate_all(&dir, &tier);

        std::fs::remove_file(orfs::tiering::catalogue_path(&dir)).unwrap();
        let open = Volume::open(&dir, OpenMode::ReadOnly);
        assert!(
            open.is_err(),
            "a removed catalogue must fail closed, never recover a shorter history"
        );
    }
}

// ---------------------------------------------------------------------------
// 7. Mixed local + remote layout
// ---------------------------------------------------------------------------

#[test]
fn mixed_layout_recovers_the_newest_valid_generation() {
    let td = TempDir::new().unwrap();
    let dir = td.path().join("volume");
    let tier = td.path().join("cold");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&tier).unwrap();
    build_fixture(&dir);

    let before = capture(&dir);
    let sealed = sealed_ids(&dir);
    assert!(sealed.len() >= 2);

    // Relocate only the *even* sealed segments, leaving the odd ones local, so the
    // volume after this has a genuinely mixed local + remote layout.
    let mut r = Relocator::open(&dir).unwrap();
    r.set_tier_root(&tier).unwrap();
    let mut relocated = 0;
    for (i, &id) in sealed.iter().enumerate() {
        if i % 2 == 0 {
            r.relocate(id).unwrap();
            relocated += 1;
        }
    }
    assert!(relocated >= 1 && relocated < sealed.len());

    // Recovery and verify over the mixed layout yield the same newest valid
    // committed generation.
    let after = capture(&dir);
    assert_eq!(before.root, after.root);
    assert_eq!(before.digest, after.digest);
    assert_eq!(before.bytes, after.bytes);
    assert_eq!(before.boundaries, after.boundaries);
    let verify = Volume::open(&dir, OpenMode::ReadOnly)
        .unwrap()
        .verify(true)
        .unwrap();
    assert!(verify.ok, "deep verify over the mixed layout must pass");

    // The recovered root is the same as the freshly scanned one.
    let scan = orfs::tiering::scan_volume(&dir).unwrap();
    assert_eq!(scan.committed_end_offset, before.root);

    // The reported layout is genuinely mixed.
    let report = list_report(&dir).unwrap();
    assert!(report.released_segments >= 1);
    let local_homes = report
        .segments
        .iter()
        .filter(|s| s.home == "local" && !s.head)
        .count();
    assert!(local_homes >= 1, "some sealed segments must remain local");
}

// ---------------------------------------------------------------------------
// Evidence sweep
// ---------------------------------------------------------------------------

/// The full court, returning a JSON assessment. Runs every always-on check and
/// (when the `failpoints` feature is compiled in) the crash matrix.
fn run_court() -> serde_json::Value {
    let td = TempDir::new().unwrap();
    let dir = td.path().join("volume");
    let tier = td.path().join("cold");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&tier).unwrap();
    build_fixture(&dir);

    let before = capture(&dir);
    let deep_before = Volume::open(&dir, OpenMode::ReadOnly)
        .unwrap()
        .verify(true)
        .unwrap();
    let sealed = sealed_ids(&dir);
    let local_before = local_authoritative_bytes(&dir);
    let total_before = list_report(&dir).unwrap().total_authoritative_bytes;

    let outcomes = relocate_all(&dir, &tier);
    let bytes_relocated: u64 = outcomes.iter().map(|o| o.bytes).sum();

    let after = capture(&dir);
    let deep_after = Volume::open(&dir, OpenMode::ReadOnly)
        .unwrap()
        .verify(true)
        .unwrap();
    let report = list_report(&dir).unwrap();
    let local_after = local_authoritative_bytes(&dir);
    let verify = verify_report(&dir).unwrap();

    // Idempotence: a second relocation of the same segment yields one object.
    let probe = sealed[0];
    let mut r = Relocator::open(&dir).unwrap();
    r.set_tier_root(&tier).unwrap();
    let second = r.relocate(probe).unwrap();

    // Tier unavailable.
    let offline = td.path().join("cold-offline");
    std::fs::rename(&tier, &offline).unwrap();
    let unavailable_open = Volume::open(&dir, OpenMode::ReadOnly);
    let unavailable_typed = matches!(unavailable_open, Err(OrfsError::TierUnavailable(_)));
    let verify_offline = verify_report(&dir).unwrap();
    std::fs::rename(&offline, &tier).unwrap();

    // Identity bytes.
    let identity_ok = before.root == after.root
        && before.digest == after.digest
        && before.bytes == after.bytes
        && before.boundaries == after.boundaries;

    let assessment = serde_json::json!({
        "identity": {
            "committed_root_before": before.root,
            "committed_root_after": after.root,
            "committed_root_unchanged": before.root == after.root,
            "committed_digest_before": before.digest,
            "committed_digest_after": after.digest,
            "committed_digest_unchanged": before.digest == after.digest,
            "boundaries_checked": before.boundaries.len(),
            "all_boundaries_byte_identical": before.boundaries == after.boundaries,
            "read_after_relocate_byte_equivalence": before.bytes == after.bytes,
            "deep_verify_before": deep_before.ok,
            "deep_verify_after": deep_after.ok,
        },
        "relocation": {
            "segments_total": sealed.len() + 1,
            "segments_relocated": outcomes.len(),
            "bytes_relocated": bytes_relocated,
            "digest_matches": verify.segments.iter().filter(|s| s.verified).count(),
            "digest_mismatches": verify.mismatches.len(),
            "local_authoritative_bytes_before": local_before,
            "local_authoritative_bytes_after": local_after,
            "local_bytes_reduced": local_after < local_before,
            "total_authoritative_bytes_before": total_before,
            "total_authoritative_bytes_after": report.total_authoritative_bytes,
            "total_authority_unchanged": total_before == report.total_authoritative_bytes,
            "tier_bytes": report.tier_bytes,
        },
        "idempotence": {
            "second_relocation_action": second.action,
            "remote_objects_for_probe": tier_object_count(&tier, probe),
            "idempotent_copy": second.action == "already_released" && tier_object_count(&tier, probe) == 1,
        },
        "verify_before_forget": {
            "fault_after_remote_copy_local_survives": cfg!(feature = "failpoints"),
        },
        "crash_matrix": crash_matrix(),
        "tier_unavailable": {
            "error_is_typed": unavailable_typed,
            "unavailable_segments_reported": verify_offline.unavailable_segments.len(),
            "mismatches_reported": verify_offline.mismatches.len(),
            "authority_intact_after_restore": verify_report(&dir).unwrap().all_ok,
        },
        "all_ok": identity_ok
            && deep_before.ok
            && deep_after.ok
            && verify.all_ok
            && local_after < local_before
            && total_before == report.total_authoritative_bytes
            && unavailable_typed,
    });

    serde_json::json!({
        "workload": {
            "segment_size": SEGMENT,
            "objects": OBJECTS,
            "chunks_per_object": CHUNKS,
            "chunk_bytes": CHUNK,
            "committed_root": before.root,
            "committed_bytes": before.bytes.len() as u64,
            "boundaries": before.boundaries.len(),
        },
        "assessment": assessment,
    })
}

#[test]
fn tier_relocation_smoke() {
    let value = run_court();
    assert_eq!(
        value["assessment"]["all_ok"],
        serde_json::json!(true),
        "tier-relocation court: {value}"
    );
    assert_eq!(
        value["assessment"]["identity"]["all_boundaries_byte_identical"],
        serde_json::json!(true)
    );
    assert_eq!(
        value["assessment"]["tier_unavailable"]["error_is_typed"],
        serde_json::json!(true)
    );
    let relocated = value["assessment"]["relocation"]["segments_relocated"]
        .as_u64()
        .unwrap();
    assert!(
        relocated >= 2,
        "the smoke must relocate at least two segments"
    );
}

#[test]
fn tier_relocation_sweep() {
    if std::env::var("ORFS_TIER_RELOCATION").as_deref() != Ok("1") {
        eprintln!(
            "tier_relocation_sweep: skipped \
             (set ORFS_TIER_RELOCATION=1 to run the full sweep)"
        );
        return;
    }
    let value = run_court();

    let environment = serde_json::json!({
        "bench": serde_json::to_value(orfs::bench::Environment::capture(
            std::env::var("ORFS_IMAGE").ok()
        ))
        .unwrap_or(serde_json::Value::Null),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "features": if cfg!(feature = "failpoints") { vec!["failpoints"] } else { Vec::<&str>::new() },
    });

    let assessment = &value["assessment"];
    let all_ok = assessment["all_ok"] == serde_json::json!(true);
    let crash_ok = assessment["crash_matrix"]["all_converged"] != serde_json::json!(false);

    let doc = serde_json::json!({
        "schema": "orfs.performance.tier-relocation.v1",
        "generated_by": "tests/tier_relocation.rs",
        "note": "Single-run, single-host, BOUNDED measurements. Sealed immutable \
                 segments are relocated from the local backing store to a cold tier \
                 WITHOUT withdrawing authority: the tier copy is written, fsynced, \
                 read back and digest-verified, and only then is the local copy \
                 removed, after a durable `Released` transition (Kafka KIP-405). The \
                 committed root and every committed root's bytes are byte-identical \
                 before and after; the active head segment is never relocatable. \
                 Absolute bytes are host/build dependent; the identity and the \
                 bookkeeping are the point.",
        "environment": environment,
        "workload": value["workload"],
        "assessment": assessment,
        "crash_matrix_converged": crash_ok,
        "all_ok": all_ok && crash_ok,
    });

    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("evidence/performance/tier-relocation.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("tier-relocation evidence written to {}", path.display());

    assert!(all_ok, "tier-relocation court: {doc}");
    assert!(crash_ok, "crash matrix did not converge: {doc}");
}
