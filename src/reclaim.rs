//! **Phase 77 — a bounded-space recovery path for an almost-full volume.**
//!
//! OrFS is non-withdrawal: committed authoritative history is never overwritten,
//! truncated, reused, or garbage-collected, so the backing store fills
//! monotonically and, at the reserve, `init`/commits are refused and the volume
//! latches read-only (`docs/CAPACITY.md`). This module is the operator's **bounded**
//! way out: a documented, tested set of actions that free local space **without
//! costing one authoritative byte** and without losing the newest committed
//! generation.
//!
//! Three actions, in the recommended order:
//!
//! 1. **Relocate sealed segments** ([`relocate_sealed`]) — the Phase-76 machinery
//!    moves a *verified* copy of each sealed (immutable, non-head) segment to the
//!    cold tier and removes the local copy only after a durable `Released`
//!    transition. The local footprint drops by exactly the relocated bytes; the
//!    committed root, the commit watermark, and the *total* authority are
//!    unchanged. This is the Kafka tiered-storage discipline (KIP-405): freeing
//!    local space by relocating verified copies is the sanctioned way to survive a
//!    full local tier while retaining authority.
//! 2. **Drop rebuildable manifestations** ([`drop_rebuildable_structures`]) —
//!    EKBLOOM bodies, the trigram index, the global search directory, direct-page
//!    atlases, the suffix/image accelerators, and kernel-passthrough images are all
//!    *derived*: dropping them costs no authoritative byte and they rebuild on
//!    demand (an absent structure falls back to the authoritative extent read;
//!    `docs/EKBLOOM-INTEGRATION.md`).
//! 3. **Drop derived metadata** ([`drop_derived_metadata_structures`]) — the
//!    `index/` accelerators (the committed-root directory, checkpoints, and
//!    published snapshots). Also derived: a later open falls back to a full log
//!    scan (`docs/RECOVERY.md` §8.1).
//!
//! # The safety invariant
//!
//! After every action, [`apply`] re-captures the committed authority and asserts it
//! is **byte-identical**: the committed root, its BLAKE3 digest, the committed
//! prefix bytes, and the durable commit watermark are unchanged. That equality —
//! not a summary — is what makes the action safe, and a violation is a hard error.
//!
//! Nothing here ever touches the active head segment or a single byte under
//! `or.log/`; `volume.meta`, the generation manifests/catalogue, and the relocation
//! catalogue are likewise never removed (they are strongly-consistent metadata).

use std::path::{Path, PathBuf};

use crate::capacity::{backing_available_bytes, reclaimable, CapacityVerdict, Reclaimable};
use crate::error::{OrfsError, Result};
use crate::log::OpenMode;
use crate::tiering::{RelocationOutcome, Relocator};
use crate::volume::Volume;

/// The concealed subdirectories whose contents are rebuildable manifestations.
/// Deliberately excludes `manifests/` (the generation manifests + catalogue +
/// `HEAD`, strongly-consistent metadata) and `tiering/` (the relocation
/// catalogue, load-bearing for resolving released segments).
pub const REBUILDABLE_BLOOM_SUBDIRS: [&str; 6] = [
    "ekbloom",
    "trigram",
    "suffix",
    "image",
    "directory",
    "atlas",
];

/// Kernel-passthrough images: derived copies of committed history.
pub const PASSTHROUGH_DIR: &str = ".or_passthrough";

/// A byte-level snapshot of the committed authority, used to prove an action
/// changed no authoritative byte (Phase 77).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    /// The committed end offset (root `R`).
    pub committed_root: u64,
    /// BLAKE3 of the committed prefix (lowercase hex).
    pub committed_digest: String,
    /// The committed prefix bytes.
    pub committed_bytes: Vec<u8>,
    /// The durable commit watermark, when present.
    pub watermark: Option<crate::watermark::Watermark>,
}

/// Capture the committed authority of a volume read-only. Fails if the volume
/// cannot be opened (for example a relocated segment whose cold tier is offline):
/// a caller must then treat authority as **unverifiable**, never as unchanged.
pub fn capture_authority(volume_root: &Path) -> Result<AuthoritySnapshot> {
    let vol = Volume::open(volume_root, OpenMode::ReadOnly)?;
    Ok(AuthoritySnapshot {
        committed_root: vol.log.committed_end_offset(),
        committed_digest: vol.log.committed_digest_hex()?,
        committed_bytes: vol.log.read_committed_bytes()?,
        watermark: vol.log.durable_watermark(),
    })
}

/// The outcome of one dropped area.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DropSummary {
    /// The area removed, relative to the volume root (e.g. `.or_bloom/ekbloom`).
    pub area: String,
    /// Bytes freed (measured before/after).
    pub bytes_freed: u64,
    /// Files removed.
    pub files_removed: u64,
}

/// The outcome of relocating every sealed segment.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RelocateSummary {
    /// The cold-tier root the segments were moved to.
    pub tier_root: String,
    /// Segments relocated (or converged).
    pub segments_relocated: u64,
    /// Bytes reported by the relocation outcomes.
    pub bytes_relocated: u64,
    /// The per-segment outcomes.
    pub outcomes: Vec<RelocationOutcome>,
    /// The local authoritative footprint (`or.log/`) before the relocation.
    pub local_authoritative_bytes_before: u64,
    /// The local authoritative footprint after the relocation.
    pub local_authoritative_bytes_after: u64,
}

/// The complete outcome of a bounded reclaim (`orfs reclaim --apply`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReclaimOutcome {
    /// The volume root.
    pub volume: String,
    /// The actions performed, in order.
    pub actions: Vec<String>,
    /// Live backing free space before the actions, when readable.
    pub free_bytes_before: Option<u64>,
    /// Live backing free space after the actions, when readable.
    pub free_bytes_after: Option<u64>,
    /// The measured free-space increase (`after - before`, saturating).
    pub freed_bytes: u64,
    /// The local authoritative footprint (`or.log/`) before the actions.
    pub local_authoritative_bytes_before: u64,
    /// The local authoritative footprint after the actions.
    pub local_authoritative_bytes_after: u64,
    /// Bytes relocated to the cold tier.
    pub relocated_bytes: u64,
    /// Rebuildable manifestation bytes dropped.
    pub dropped_rebuildable_bytes: u64,
    /// Derived metadata bytes dropped.
    pub dropped_derived_metadata_bytes: u64,
    /// The committed root before the actions.
    pub committed_root_before: u64,
    /// The committed root after the actions.
    pub committed_root_after: u64,
    /// Whether the committed root is byte-identical (unchanged).
    pub committed_root_unchanged: bool,
    /// Whether the committed digest is byte-identical.
    pub committed_digest_unchanged: bool,
    /// Whether the committed prefix bytes are byte-identical.
    pub committed_bytes_unchanged: bool,
    /// Whether the durable commit watermark is byte-identical.
    pub watermark_unchanged: bool,
    /// Whether the committed authority was re-captured and proved unchanged.
    pub authority_checked: bool,
    /// Whether the committed authority is unchanged (the safety invariant).
    pub authority_unchanged: bool,
}

/// The reclaimable-space plan for a volume (what a bounded action *would* free).
pub fn plan(volume_root: &Path, reserve_override: Option<u64>) -> Reclaimable {
    // Reuse the capacity verdict for the recommendation. The reserve only affects
    // the recommendation, never the measured byte totals.
    let status = Volume::open(volume_root, OpenMode::ReadOnly)
        .ok()
        .map(|v| v.capacity_status(reserve_override));
    let verdict = status
        .as_ref()
        .map(|s| s.verdict)
        .unwrap_or(CapacityVerdict::Warn);
    reclaimable(volume_root, verdict)
}

/// The local authoritative footprint under `or.log/` (the relocation target).
pub fn local_authoritative_bytes(volume_root: &Path) -> u64 {
    crate::manifestation::dir_bytes(&Volume::log_dir(volume_root))
}

/// Relocate every sealed (immutable, non-head) segment to `tier_root` using the
/// Phase-76 machinery (`docs/TIERING.md`). The active head is never relocatable;
/// an unusable tier root is refused with the typed [`OrfsError::TierUnavailable`].
pub fn relocate_sealed(volume_root: &Path, tier_root: &Path) -> Result<RelocateSummary> {
    let before = local_authoritative_bytes(volume_root);
    let mut relocator = Relocator::open(volume_root)?;
    relocator.set_tier_root(tier_root)?;
    let ids = relocator.sealed_ids()?;
    let mut outcomes = Vec::new();
    let mut bytes_relocated = 0u64;
    for id in ids {
        let outcome = relocator.relocate(id)?;
        bytes_relocated = bytes_relocated.saturating_add(outcome.bytes);
        outcomes.push(outcome);
    }
    let after = local_authoritative_bytes(volume_root);
    Ok(RelocateSummary {
        tier_root: tier_root.display().to_string(),
        segments_relocated: outcomes.len() as u64,
        bytes_relocated,
        outcomes,
        local_authoritative_bytes_before: before,
        local_authoritative_bytes_after: after,
    })
}

/// Drop the rebuildable manifestation structures. Never touches `or.log/`,
/// `index/`, `volume.meta`, the generation manifests/catalogue, or the relocation
/// catalogue.
pub fn drop_rebuildable_structures(volume_root: &Path) -> Result<Vec<DropSummary>> {
    let mut out = Vec::new();
    let bloom = volume_root.join(crate::manifestation::BLOOM_DIR);
    for sub in REBUILDABLE_BLOOM_SUBDIRS {
        let dir = bloom.join(sub);
        out.push(remove_area(
            &dir,
            &format!("{}/{sub}", crate::manifestation::BLOOM_DIR),
        )?);
    }
    out.push(remove_area(
        &volume_root.join(PASSTHROUGH_DIR),
        PASSTHROUGH_DIR,
    )?);
    Ok(out)
}

/// Drop the derived metadata accelerators under `index/` (the committed-root
/// directory, checkpoints, and published snapshots). A later open rebuilds them by
/// scanning the log (`docs/RECOVERY.md` §8.1).
pub fn drop_derived_metadata_structures(volume_root: &Path) -> Result<Vec<DropSummary>> {
    Ok(vec![remove_area(&volume_root.join("index"), "index")?])
}

/// Remove every regular file beneath `dir` (and the now-empty subdirectories),
/// keeping the top directory itself. Returns the measured bytes freed.
///
/// The caller has already restricted `dir` to a derived area (`or.log/` and the
/// authoritative files are never passed here).
fn remove_area(dir: &Path, label: &str) -> Result<DropSummary> {
    let bytes_before = crate::manifestation::dir_bytes(dir);
    let mut files_removed = 0u64;
    if dir.is_dir() {
        let mut stack = vec![dir.to_path_buf()];
        let mut subdirs: Vec<PathBuf> = Vec::new();
        while let Some(cur) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&cur) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else { continue };
                let path = entry.path();
                if ft.is_dir() {
                    subdirs.push(path.clone());
                    stack.push(path);
                } else if ft.is_file() {
                    std::fs::remove_file(&path)?;
                    files_removed += 1;
                }
            }
        }
        // Deepest first, so a directory is empty before removal is attempted.
        subdirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        for d in subdirs {
            let _ = std::fs::remove_dir(&d);
        }
    }
    // Keep the area present, matching the layout `orfs init` creates.
    std::fs::create_dir_all(dir)?;
    let bytes_after = crate::manifestation::dir_bytes(dir);
    Ok(DropSummary {
        area: label.to_string(),
        bytes_freed: bytes_before.saturating_sub(bytes_after),
        files_removed,
    })
}

/// Apply the bounded reclaim and prove the committed authority unchanged.
///
/// Order: relocate sealed (when `tier_root` is given) → drop rebuildable
/// manifestations → drop derived metadata. Afterwards the committed authority is
/// re-captured and asserted **byte-identical** (root, digest, committed bytes,
/// watermark); a difference is a hard error, never a silent success. The active
/// head and every authoritative byte are never touched.
pub fn apply(
    volume_root: &Path,
    tier_root: Option<&Path>,
    drop_rebuildable: bool,
    drop_derived_metadata: bool,
) -> Result<ReclaimOutcome> {
    let before = capture_authority(volume_root).ok();
    let free_before = backing_available_bytes(volume_root);
    let local_before = local_authoritative_bytes(volume_root);

    let mut actions = Vec::new();
    let mut relocated_bytes = 0u64;
    let mut dropped_rebuildable_bytes = 0u64;
    let mut dropped_derived_metadata_bytes = 0u64;

    if let Some(tier) = tier_root {
        let summary = relocate_sealed(volume_root, tier)?;
        relocated_bytes = summary.bytes_relocated;
        actions.push(format!(
            "relocate_sealed:{} segment(s), {} byte(s)",
            summary.segments_relocated, summary.bytes_relocated
        ));
    }
    if drop_rebuildable {
        let summaries = drop_rebuildable_structures(volume_root)?;
        dropped_rebuildable_bytes = summaries.iter().map(|s| s.bytes_freed).sum();
        actions.push(format!(
            "drop_rebuildable:{dropped_rebuildable_bytes} byte(s)"
        ));
    }
    if drop_derived_metadata {
        let summaries = drop_derived_metadata_structures(volume_root)?;
        dropped_derived_metadata_bytes = summaries.iter().map(|s| s.bytes_freed).sum();
        actions.push(format!(
            "drop_derived_metadata:{dropped_derived_metadata_bytes} byte(s)"
        ));
    }

    let free_after = backing_available_bytes(volume_root);
    let local_after = local_authoritative_bytes(volume_root);
    let after = capture_authority(volume_root).ok();

    let freed_bytes = match (free_before, free_after) {
        (Some(b), Some(a)) => a.saturating_sub(b),
        _ => 0,
    };
    let (
        authority_checked,
        committed_root_unchanged,
        committed_digest_unchanged,
        committed_bytes_unchanged,
        watermark_unchanged,
    ) = match (&before, &after) {
        (Some(b), Some(a)) => (
            true,
            b.committed_root == a.committed_root,
            b.committed_digest == a.committed_digest,
            b.committed_bytes == a.committed_bytes,
            b.watermark == a.watermark,
        ),
        // Authority could not be re-captured (a relocated segment's tier is
        // offline). The actions performed still never touch `or.log/` — proved
        // by the local footprint being unchanged for a drop-only reclaim — but
        // the byte-exact invariant is *unverified*, and is reported as such.
        _ => (false, false, false, false, false),
    };
    // A drop-only reclaim must leave the authoritative footprint byte-count intact.
    let drop_only_ok = tier_root.is_some() || local_after == local_before;
    let authority_unchanged = authority_checked
        && committed_root_unchanged
        && committed_digest_unchanged
        && committed_bytes_unchanged
        && watermark_unchanged;
    if authority_checked && !authority_unchanged {
        return Err(OrfsError::Corrupt(
            "bounded reclaim changed authoritative history; refusing (this must be impossible)"
                .to_string(),
        ));
    }
    if !drop_only_ok {
        return Err(OrfsError::Corrupt(
            "bounded reclaim changed the local authoritative footprint without relocating; refusing"
                .to_string(),
        ));
    }

    Ok(ReclaimOutcome {
        volume: volume_root.display().to_string(),
        actions,
        free_bytes_before: free_before,
        free_bytes_after: free_after,
        freed_bytes,
        local_authoritative_bytes_before: local_before,
        local_authoritative_bytes_after: local_after,
        relocated_bytes,
        dropped_rebuildable_bytes,
        dropped_derived_metadata_bytes,
        committed_root_before: before.as_ref().map(|b| b.committed_root).unwrap_or(0),
        committed_root_after: after.as_ref().map(|a| a.committed_root).unwrap_or(0),
        committed_root_unchanged,
        committed_digest_unchanged,
        committed_bytes_unchanged,
        watermark_unchanged,
        authority_checked,
        authority_unchanged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::DurabilityMode;
    use crate::namespace::Namespace;
    use tempfile::TempDir;

    const UUID: [u8; 16] = [
        0x4F, 0x72, 0x46, 0x53, 0x77, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];
    const CREATED: u64 = 1_700_000_000;
    const SEGMENT: u64 = 64 * 1024;

    fn build(dir: &Path) {
        let mut ns = Namespace::init_with_uuid(dir, SEGMENT, UUID, CREATED, DurabilityMode::Sync)
            .expect("init namespace");
        let root = ns.root_inode();
        for i in 0..6 {
            let ino = ns
                .create(root, format!("f{i}").as_bytes(), 0o644, 0, 0)
                .expect("create");
            ns.write_at(ino, 0, &vec![i as u8; 16 * 1024])
                .expect("write");
        }
        ns.sync().expect("sync");
    }

    #[test]
    fn plan_reports_only_derived_bytes_and_never_authority() {
        let td = TempDir::new().unwrap();
        build(td.path());
        let plan = plan(td.path(), None);
        // A freshly built manifested-free volume has no rebuildable bytes, and the
        // head is never counted as relocatable.
        assert_eq!(plan.droppable_rebuildable_bytes, 0);
        assert!(
            plan.relocatable_sealed_bytes > 0,
            "the fixture must produce sealed segments"
        );
        assert!(plan.reclaimable_bytes >= plan.relocatable_sealed_bytes);
    }

    #[test]
    fn dropping_rebuildable_leaves_authority_identical() {
        let td = TempDir::new().unwrap();
        build(td.path());
        let before = capture_authority(td.path()).expect("capture");
        let outcome = apply(td.path(), None, true, true).expect("apply");
        assert!(outcome.authority_unchanged, "{outcome:?}");
        assert!(outcome.committed_root_unchanged);
        assert_eq!(
            outcome.local_authoritative_bytes_after,
            outcome.local_authoritative_bytes_before
        );
        let after = capture_authority(td.path()).expect("recapture");
        assert_eq!(before, after);
    }
}
