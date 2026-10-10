//! Physical accounting (research §33).
//!
//! OrFS deliberately spends manifested space to maximise speed, and committed
//! history is never withdrawn, so the physical footprint is a first-class,
//! *honest* quantity. This module separates the logical view from the physical
//! reality and reports both:
//!
//! * **logical** — current live file bytes and object counts, from the namespace
//!   index (what `readdir`/`stat` reveal);
//! * **physical** — the authoritative log (`M_log`), the EKBLOOM manifested
//!   structures (`M_ekbloom`), the rebuildable indexes and other search
//!   structures (`M_indexes`), the replay accelerators (`M_checkpoints`), and
//!   everything else (`M_other`), plus the actual backing capacity.
//!
//! A concealed structure may be absent from ordinary `readdir`; it must **not**
//! be absent from administrative accounting. The totals are measured from the
//! bytes on disk; nothing is assumed and no capacity is ever reported as
//! unlimited.

use std::collections::BTreeMap;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::error::Result;
use crate::index::Index;
use crate::inode::InodeType;
use crate::log::OpenMode;
use crate::manifestation::{self, BLOOM_DIR};
use crate::volume::{Volume, BLOOM_SUBDIRS};

/// A truthful backing-capacity reading (from `statvfs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct BackingCapacity {
    /// Total backing device bytes.
    pub total_bytes: u64,
    /// Free bytes available to an unprivileged writer.
    pub available_bytes: u64,
    /// Preferred block size in bytes.
    pub block_size: u64,
}

/// The full physical-vs-logical accounting of one volume (research §33).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PhysicalAccounting {
    /// The backing directory.
    pub volume: String,
    /// The volume UUID, when the path is a volume.
    pub uuid: Option<String>,
    /// The committed root the logical figures reflect.
    pub committed_root: u64,

    // -- logical (what the namespace reveals) --
    /// Live logical file bytes (sum of regular-file sizes at the committed root).
    pub logical_live_bytes: u64,
    /// Live regular-file count.
    pub logical_file_count: u64,
    /// Live directory count.
    pub logical_directory_count: u64,
    /// Live symbolic-link count.
    pub logical_symlink_count: u64,
    /// Live inode count.
    pub logical_inode_count: u64,

    // -- physical categories (research §33) --
    /// `M_log`: bytes under `or.log/` (including retained, non-canonical tails).
    pub m_log: u64,
    /// Canonical committed bytes of the authoritative log.
    pub authoritative_canonical_bytes: u64,
    /// `M_ekbloom`: bytes under `.or_bloom/ekbloom/`.
    pub m_ekbloom: u64,
    /// `M_indexes`: rebuildable namespace/search structures (`index/` + the
    /// `trigram`/`suffix`/`image`/`directory` families).
    pub m_indexes: u64,
    /// `M_checkpoints`: replay accelerators. Index checkpoints are records inside
    /// the authoritative log, so their bytes are counted in `M_log`; this figure
    /// is the separate on-disk replay-accelerator area (zero today).
    pub m_checkpoints: u64,
    /// `M_other`: generation manifests and residual backing-root files.
    pub m_other: u64,
    /// `M_total`: the sum of the five categories above (no double counting).
    pub m_total: u64,

    // -- supporting detail --
    /// Physical bytes under `.or_bloom/` (payloads + manifests).
    pub bloom_total_bytes: u64,
    /// Per-`BLOOM_SUBDIRS` byte breakdown.
    pub bloom_subdir_bytes: BTreeMap<String, u64>,
    /// Bytes under `index/`.
    pub index_bytes: u64,
    /// Bytes under `.or_bloom/manifests/` (generation manifests + `HEAD`).
    pub generation_manifest_bytes: u64,
    /// Physical authoritative tail bytes retained but not canonical.
    pub uncommitted_tail_bytes: u64,

    // -- manifestation summary --
    /// Number of committed manifestations (newest per inode).
    pub manifested_generations: u64,
    /// Number of distinct inodes with at least one committed manifestation.
    pub manifested_inodes: u64,
    /// Total committed manifested payload bytes (equals `m_ekbloom` today).
    pub manifested_bytes: u64,

    // -- capacity (never unlimited) --
    /// Backing device capacity, when readable.
    pub capacity: Option<BackingCapacity>,
    /// Physical overhead over the live logical bytes (`m_total - logical_live`).
    pub physical_overhead_bytes: u64,
}

impl PhysicalAccounting {
    /// A one-line human summary.
    pub fn describe(&self) -> String {
        format!(
            "logical {} byte(s) in {} file(s); physical {} byte(s) \
             (M_log {}, M_ekbloom {}, M_indexes {}, M_checkpoints {}, M_other {})",
            self.logical_live_bytes,
            self.logical_file_count,
            self.m_total,
            self.m_log,
            self.m_ekbloom,
            self.m_indexes,
            self.m_checkpoints,
            self.m_other,
        )
    }
}

/// Read the backing capacity for a path with `statvfs` (truthful, never
/// unlimited).
pub fn backing_capacity(path: &Path) -> Option<BackingCapacity> {
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c` is a valid NUL-terminated path; `st` is a valid, aligned,
    // fully-owned buffer that `statvfs` initialises. No pointer is retained.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return None;
    }
    let frsize = if st.f_frsize == 0 {
        st.f_bsize as u64
    } else {
        st.f_frsize as u64
    };
    let block_size = if st.f_bsize == 0 {
        1
    } else {
        st.f_bsize as u64
    };
    Some(BackingCapacity {
        total_bytes: (st.f_blocks as u64).saturating_mul(frsize),
        available_bytes: (st.f_bavail as u64).saturating_mul(frsize),
        block_size,
    })
}

/// Account a volume backing directory (opens the committed index read-only).
pub fn account_volume(dir: &Path) -> Result<PhysicalAccounting> {
    let volume = Volume::open(dir, OpenMode::ReadOnly)?;
    let index = Index::from_log(&volume.log, volume.log.committed_end_offset())?;
    account_with_index(dir, Some(&volume), &index)
}

/// Account a path that may or may not be an OrFS volume. A non-volume path
/// reports only capacity and file-system byte counts.
pub fn account_path(dir: &Path) -> Result<PhysicalAccounting> {
    if dir.join("volume.meta").exists() {
        account_volume(dir)
    } else {
        let mut acc = empty_account(dir)?;
        acc.capacity = backing_capacity(dir);
        Ok(acc)
    }
}

fn empty_account(dir: &Path) -> Result<PhysicalAccounting> {
    Ok(PhysicalAccounting {
        volume: dir.display().to_string(),
        uuid: None,
        committed_root: 0,
        logical_live_bytes: 0,
        logical_file_count: 0,
        logical_directory_count: 0,
        logical_symlink_count: 0,
        logical_inode_count: 0,
        m_log: 0,
        authoritative_canonical_bytes: 0,
        m_ekbloom: 0,
        m_indexes: 0,
        m_checkpoints: 0,
        m_other: 0,
        m_total: 0,
        bloom_total_bytes: 0,
        bloom_subdir_bytes: BTreeMap::new(),
        index_bytes: 0,
        generation_manifest_bytes: 0,
        uncommitted_tail_bytes: 0,
        manifested_generations: 0,
        manifested_inodes: 0,
        manifested_bytes: 0,
        capacity: backing_capacity(dir),
        physical_overhead_bytes: 0,
    })
}

fn account_with_index(
    dir: &Path,
    volume: Option<&Volume>,
    index: &Index,
) -> Result<PhysicalAccounting> {
    let mut acc = empty_account(dir)?;

    if let Some(v) = volume {
        acc.uuid = Some(v.meta.uuid_string());
        acc.committed_root = v.log.committed_end_offset();
        acc.authoritative_canonical_bytes = v.log.canonical_bytes();
        acc.uncommitted_tail_bytes = v.log.tail().map(|t| t.abandoned_bytes).unwrap_or(0);
    }

    // Logical figures from the committed namespace index.
    for id in index.inode_ids() {
        let Some(inode) = index.inode(id) else {
            continue;
        };
        acc.logical_inode_count += 1;
        match inode.kind {
            InodeType::File => {
                acc.logical_file_count += 1;
                acc.logical_live_bytes = acc.logical_live_bytes.saturating_add(inode.size);
            }
            InodeType::Directory => acc.logical_directory_count += 1,
            InodeType::Symlink => acc.logical_symlink_count += 1,
        }
    }

    // Physical categories, measured from disk.
    let log_dir = dir.join("or.log");
    acc.m_log = manifestation::dir_bytes(&log_dir);

    let bloom_root = dir.join(BLOOM_DIR);
    let mut subdirs = BTreeMap::new();
    for name in BLOOM_SUBDIRS {
        subdirs.insert(
            name.to_string(),
            manifestation::dir_bytes(&bloom_root.join(name)),
        );
    }
    acc.bloom_subdir_bytes = subdirs.clone();
    acc.m_ekbloom = *subdirs.get("ekbloom").unwrap_or(&0);
    let other_accel: u64 = ["trigram", "suffix", "image", "directory"]
        .iter()
        .map(|k| *subdirs.get(*k).unwrap_or(&0))
        .sum();

    acc.index_bytes = manifestation::dir_bytes(&dir.join("index"));
    acc.generation_manifest_bytes = *subdirs.get("manifests").unwrap_or(&0);
    acc.bloom_total_bytes = manifestation::dir_bytes(&bloom_root);

    // `M_other`: generation manifests plus everything at the backing root that
    // is not a known area (`volume.meta` and any residual file). Together the
    // five categories partition every byte beneath the backing directory, so
    // `m_total` equals the measured on-disk total exactly.
    let root_total = manifestation::dir_bytes(dir);
    let residue_outside = root_total
        .saturating_sub(acc.m_log)
        .saturating_sub(acc.bloom_total_bytes)
        .saturating_sub(acc.index_bytes);
    // Bytes directly under `.or_bloom/` that are not in a known subdirectory.
    let residual_bloom = acc
        .bloom_total_bytes
        .saturating_sub(acc.m_ekbloom)
        .saturating_sub(other_accel)
        .saturating_sub(acc.generation_manifest_bytes);
    acc.m_other = residue_outside
        .saturating_add(acc.generation_manifest_bytes)
        .saturating_add(residual_bloom);

    acc.m_indexes = acc.index_bytes.saturating_add(other_accel);
    // Index checkpoints are authoritative records inside `or.log` today, so the
    // separate replay-accelerator area is empty (documented, not fabricated).
    acc.m_checkpoints = 0;
    acc.m_total = acc
        .m_log
        .saturating_add(acc.m_ekbloom)
        .saturating_add(acc.m_indexes)
        .saturating_add(acc.m_checkpoints)
        .saturating_add(acc.m_other);

    acc.physical_overhead_bytes = acc.m_total.saturating_sub(acc.logical_live_bytes);

    // Manifestation summary (counts only; bytes are the measured m_ekbloom).
    let store = manifestation::GenerationStore::new(dir);
    if let Ok(recovery) = store.recover() {
        acc.manifested_generations = recovery.generations.len() as u64;
        acc.manifested_inodes = recovery.newest_per_inode().len() as u64;
    }
    acc.manifested_bytes = acc.m_ekbloom;

    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::DurabilityMode;
    use crate::namespace::Namespace;
    use tempfile::TempDir;

    #[test]
    fn accounts_logical_and_physical_separately() {
        let dir = TempDir::new().unwrap();
        let mut ns = Namespace::init(dir.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
        let root = ns.root_inode();
        let f = ns.create(root, b"a", 0o644, 0, 0).unwrap();
        ns.write_at(f, 0, &vec![7u8; 4096]).unwrap();
        ns.sync().unwrap();

        let acc = account_volume(dir.path()).unwrap();
        assert_eq!(acc.logical_file_count, 1);
        assert_eq!(acc.logical_live_bytes, 4096);
        assert!(acc.m_log > 0);
        assert_eq!(acc.m_ekbloom, 0);
        assert_eq!(acc.m_total, acc.m_log + acc.m_indexes + acc.m_other);
        assert!(acc.capacity.is_some());
        assert!(acc.capacity.unwrap().total_bytes > 0);
    }
}
