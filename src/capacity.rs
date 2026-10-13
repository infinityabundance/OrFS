//! Volume capacity policy and authoritative-space governance (research **I8**
//! *physical capacity is finite*, §30 *capacity, statfs, and the visible void*,
//! §31 *storage exhaustion and non-withdrawal*).
//!
//! OrFS is append-only: it never releases authoritative history, so its physical
//! footprint grows monotonically. That does **not** make the backing device
//! infinite (I8). When the backing store cannot accept another authoritative
//! record, OrFS must apply a declared policy and return the appropriate error
//! (ENOSPC) — never claim success (I7), never silently reclaim committed history.
//!
//! # The two spaces
//!
//! * **Authoritative space** — the committed record stream (`or.log/`) and its
//!   completeness witness (`commit.watermark`). Running out of *this* space fails
//!   a mutation with [`OrfsError::NoSpace`] (errno `ENOSPC`) and latches the volume
//!   into a degraded, read-only state ([`OrfsError::ReadOnly`], errno `EROFS`).
//! * **Optional (manifestation) space** — EKBLOOM payloads and generation
//!   manifests. Running out of *this* space must **never** fail an authoritative
//!   operation: optional construction is throttled and skipped instead.
//!
//! # Early detection
//!
//! A transaction needs more than its payload: a `TX_BEGIN` record, the data
//! records, and a `TX_COMMIT` record, each framed with a 60-byte header and a
//! 16-byte footer. Admission therefore uses the transaction's **whole framed
//! size**, not just the payload, so ENOSPC is returned *before* the first byte of
//! the transaction is written rather than mid-record.
//!
//! # Non-withdrawal
//!
//! The governor only ever *refuses* growth; it never truncates, reclaims, or
//! rewrites committed bytes. Exhaustion is an orderly read-only transition, not a
//! reclamation.

use std::path::Path;

use serde::Serialize;

use crate::error::{OrfsError, Result};

/// The configured capacity policy for a volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct CapacityPolicy {
    /// Minimum bytes that must remain free before an authoritative allocation is
    /// admitted. A floor that keeps the backing from filling completely (so the
    /// device, the filesystem, and any metadata can still make progress).
    pub reserve_bytes: u64,
    /// Soft threshold: above this total physical usage, optional (manifestation)
    /// construction is throttled. Authoritative writes are never refused by the
    /// soft quota.
    pub soft_quota_bytes: Option<u64>,
    /// Hard threshold: authoritative growth is refused above this total. Reaching
    /// it is an orderly read-only transition, never a reclamation.
    pub hard_quota_bytes: Option<u64>,
    /// An explicit bound on authoritative history bytes. When `None` the bound is
    /// derived from the backing device's currently-available space plus the bytes
    /// already in use (so the reserve is always honoured against the real device).
    /// Tests set an explicit small bound for determinism.
    pub authoritative_capacity_bytes: Option<u64>,
}

impl CapacityPolicy {
    /// A policy with no explicit bound (the reserve is derived from the device).
    pub const fn new() -> Self {
        CapacityPolicy {
            reserve_bytes: 0,
            soft_quota_bytes: None,
            hard_quota_bytes: None,
            authoritative_capacity_bytes: None,
        }
    }

    /// Override the authoritative reserve.
    pub const fn with_reserve(mut self, bytes: u64) -> Self {
        self.reserve_bytes = bytes;
        self
    }

    /// Set the optional-manifestation soft quota.
    pub const fn with_soft_quota(mut self, bytes: u64) -> Self {
        self.soft_quota_bytes = Some(bytes);
        self
    }

    /// Set the authoritative hard quota.
    pub const fn with_hard_quota(mut self, bytes: u64) -> Self {
        self.hard_quota_bytes = Some(bytes);
        self
    }

    /// Set an explicit authoritative capacity bound.
    pub const fn with_authoritative_capacity(mut self, bytes: u64) -> Self {
        self.authoritative_capacity_bytes = Some(bytes);
        self
    }
}

/// A truthful, machine-readable capacity reading for a volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapacityReport {
    pub policy: CapacityPolicy,
    /// Authoritative history bytes currently in use.
    pub authoritative_used_bytes: u64,
    /// The effective authoritative capacity, if bounded.
    pub authoritative_capacity_bytes: Option<u64>,
    /// Authoritative bytes still admissible before the reserve is breached.
    pub authoritative_headroom_bytes: Option<u64>,
    /// Optional (manifestation) bytes currently in use, as last reported.
    pub optional_used_bytes: u64,
    /// Whether optional construction is currently throttled.
    pub optional_throttled: bool,
    /// Whether the volume has latched into degraded/read-only mode.
    pub degraded: bool,
    /// Why the volume degraded, when it has.
    pub degraded_reason: Option<String>,
}

/// The verdict of a capacity inspection against a reserve: enough headroom
/// (`ok`), close to the reserve (`warn`), or no headroom left (`exhausted`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CapacityVerdict {
    /// Comfortably above the reserve.
    Ok,
    /// Headroom is below the reserve, or below one projected transaction.
    Warn,
    /// No headroom above the reserve: the volume is at (or below) its reserve.
    Exhausted,
}

impl CapacityVerdict {
    /// Classify `free` backing bytes against `reserve` and a projected
    /// per-transaction growth. `exhausted` means there is no headroom above the
    /// reserve — the point at which the guard's refusal becomes a read-only
    /// transition. `warn` means the headroom is thinner than the reserve itself
    /// (or than a single projected transaction).
    pub fn classify(free: u64, reserve: u64, bytes_per_transaction: Option<u64>) -> Self {
        let headroom = free.saturating_sub(reserve);
        if headroom == 0 {
            CapacityVerdict::Exhausted
        } else if headroom < reserve || bytes_per_transaction.is_some_and(|b| headroom < b) {
            CapacityVerdict::Warn
        } else {
            CapacityVerdict::Ok
        }
    }
}

/// The backing filesystem holding a volume's directory, read from `statvfs`
/// plus the mount identity from `/proc/self/mountinfo` (Phase 68).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BackingSpace {
    /// Bytes available to an unprivileged writer (`f_bavail * f_frsize`).
    pub available_bytes: u64,
    /// Free bytes including the filesystem's root reserve (`f_bfree * f_frsize`).
    pub free_bytes: u64,
    /// Total filesystem size (`f_blocks * f_frsize`).
    pub total_bytes: u64,
    /// The mount point of the backing filesystem, when it can be identified.
    pub mount_point: Option<String>,
    /// The backing device / source, when it can be identified.
    pub device: Option<String>,
    /// The backing filesystem type, when it can be identified.
    pub filesystem: Option<String>,
}

/// A truthful, machine-readable capacity inspection for an operator
/// (`orfs doctor --capacity`, Phase 68). It ties together the retained
/// authoritative footprint, the live backing free space, the projected growth,
/// and a verdict against the configured reserve.
#[derive(Debug, Clone, Serialize)]
pub struct CapacityStatus {
    /// The volume directory.
    pub volume: String,
    /// The verdict against the reserve.
    pub verdict: CapacityVerdict,
    /// The reserve in force (the `--reserve` override, else the policy reserve).
    pub reserve_bytes: u64,
    /// Live backing free space (to an unprivileged writer), when readable.
    pub free_bytes: Option<u64>,
    /// Free bytes above the reserve (`free - reserve`), when readable.
    pub headroom_bytes: Option<u64>,
    /// Retained authoritative physical bytes (the committed segment files plus
    /// the durable commit watermark).
    pub physical_bytes: u64,
    /// The authoritative logical frontier (committed end offset).
    pub authoritative_bytes: u64,
    /// The number of log segments.
    pub segment_count: usize,
    /// Committed transactions, excluding genesis.
    pub transaction_count: u64,
    /// Projected bytes written per committed transaction (sampled from history).
    pub bytes_per_transaction: Option<u64>,
    /// Estimated committed transactions that still fit above the reserve.
    pub estimated_transactions_remaining: Option<u64>,
    /// The backing mount point, when identified.
    pub mount_point: Option<String>,
    /// The backing device / source, when identified.
    pub device: Option<String>,
    /// The backing filesystem type, when identified.
    pub filesystem: Option<String>,
    /// Whether the volume has latched read-only.
    pub degraded: bool,
    /// Why the volume degraded, when it has.
    pub degraded_reason: Option<String>,
    /// The capacity policy in force.
    pub policy: CapacityPolicy,
}

/// The capacity governor: admission control for authoritative growth and a
/// throttle for optional construction.
///
/// It holds the policy and a one-way degraded latch. The caller supplies the
/// current usage at each check, so the governor never has to walk the tree.
#[derive(Debug, Clone)]
pub struct CapacityGovernor {
    policy: CapacityPolicy,
    /// The effective authoritative capacity (policy value, or backing-derived).
    capacity: Option<u64>,
    /// Optional (manifestation) bytes, as last reported by the owner.
    optional_used: u64,
    /// One-way degraded latch.
    degraded: Option<String>,
    /// Whether optional construction is currently throttled.
    optional_throttled: bool,
}

impl Default for CapacityGovernor {
    fn default() -> Self {
        CapacityGovernor::new(CapacityPolicy::default())
    }
}

impl CapacityGovernor {
    /// Build a governor for `policy`. When the policy does not bound capacity
    /// explicitly, [`Self::resolve_from_backing`] derives it from the device.
    pub fn new(policy: CapacityPolicy) -> Self {
        CapacityGovernor {
            capacity: policy.authoritative_capacity_bytes,
            policy,
            optional_used: 0,
            degraded: None,
            optional_throttled: false,
        }
    }

    /// The policy in force.
    pub fn policy(&self) -> CapacityPolicy {
        self.policy
    }

    /// Replace the policy. The degraded latch is never cleared here (a degraded
    /// volume must be reopened to become writable again); use [`Self::reset`] when
    /// a fresh handle is constructed.
    pub fn set_policy(&mut self, policy: CapacityPolicy) {
        self.policy = policy;
        self.capacity = policy.authoritative_capacity_bytes;
    }

    /// Clear the latch and optional throttle (a fresh handle over a reopened
    /// volume).
    pub fn reset(&mut self) {
        self.degraded = None;
        self.optional_throttled = false;
        self.optional_used = 0;
    }

    /// Resolve a `None` capacity from the backing device's current free space plus
    /// `used`, so the configured reserve is honoured against the real device.
    /// No-op when the policy already bounds capacity or the device is unreadable.
    pub fn resolve_from_backing(&mut self, dir: &Path, used: u64) {
        if self.policy.authoritative_capacity_bytes.is_none() {
            if let Some(free) = backing_available_bytes(dir) {
                self.capacity = Some(free.saturating_add(used));
            }
        }
    }

    /// The effective authoritative capacity, if bounded.
    pub fn capacity_bytes(&self) -> Option<u64> {
        self.capacity
    }

    /// Whether the volume has latched into degraded/read-only mode.
    pub fn is_degraded(&self) -> bool {
        self.degraded.is_some()
    }

    /// Why the volume degraded, when it has.
    pub fn degraded_reason(&self) -> Option<&str> {
        self.degraded.as_deref()
    }

    /// Whether optional construction is currently throttled.
    pub fn optional_throttled(&self) -> bool {
        self.optional_throttled
    }

    /// The optional (manifestation) bytes as last reported by the owner.
    pub fn optional_used_bytes(&self) -> u64 {
        self.optional_used
    }

    /// Latch the volume degraded. Idempotent: the first reason wins.
    pub fn degrade(&mut self, reason: impl Into<String>) {
        if self.degraded.is_none() {
            self.degraded = Some(reason.into());
        }
    }

    /// Admit `needed` authoritative bytes when the authoritative history already
    /// occupies `used`. Returns:
    ///
    /// * `Err(ReadOnly)` when the volume has already degraded — mutations are
    ///   refused with `EROFS` rather than accepted onto an unreliable store;
    /// * `Err(NoSpace)` when the allocation would breach the hard quota or eat into
    ///   the reserve; the volume is latched degraded at the same time;
    /// * `Ok(())` otherwise.
    pub fn check_authoritative(&mut self, used: u64, needed: u64) -> Result<()> {
        if let Some(reason) = &self.degraded {
            return Err(OrfsError::ReadOnly(format!("volume degraded: {reason}")));
        }
        let projected = used
            .saturating_add(self.optional_used)
            .saturating_add(needed);
        // The *explicit* authoritative bound (a declared volume size) is a hard
        // ceiling: crossing it is an orderly read-only transition. A
        // device-derived capacity (see [`Self::resolve_from_backing`]) is only a
        // snapshot used for optional throttling and reporting — the **live**
        // backing-space guard ([`crate::log::Log::ensure_capacity`]) owns the
        // device, so a volume near a shrinking/filled device gets a predictable
        // [`OrfsError::CapacityExhausted`] instead of a spurious latch.
        if let Some(cap) = self.policy.authoritative_capacity_bytes {
            let limit = cap.saturating_sub(self.policy.reserve_bytes);
            if projected > limit {
                let msg = format!(
                    "authoritative capacity exhausted: {projected} byte(s) needed but only {limit} \
                     admissible (capacity {cap}, reserve {}, optional in use {})",
                    self.policy.reserve_bytes, self.optional_used
                );
                self.degrade(msg.clone());
                return Err(OrfsError::NoSpace(msg));
            }
        }
        if let Some(hard) = self.policy.hard_quota_bytes {
            if projected > hard {
                let msg = format!(
                    "authoritative hard quota exceeded: {projected} byte(s) needed, quota {hard}"
                );
                self.degrade(msg.clone());
                return Err(OrfsError::NoSpace(msg));
            }
        }
        Ok(())
    }

    /// Record the current optional (manifestation) usage.
    pub fn note_optional_used(&mut self, bytes: u64) {
        self.optional_used = bytes;
    }

    /// Whether optional construction should proceed. Updates the throttle flag.
    ///
    /// Optional space is the *first* thing sacrificed: it is throttled as soon as
    /// total usage would reach the soft quota or the authoritative reserve, so
    /// optional construction is stopped **before** it can starve authoritative
    /// commits (research §31).
    pub fn optional_allowed(&mut self, authoritative_used: u64, optional_used: u64) -> bool {
        self.optional_used = optional_used;
        if self.degraded.is_some() {
            self.optional_throttled = true;
            return false;
        }
        let total = authoritative_used.saturating_add(optional_used);
        let mut allowed = true;
        if let Some(soft) = self.policy.soft_quota_bytes {
            if total >= soft {
                allowed = false;
            }
        }
        if let Some(cap) = self.capacity {
            let ceiling = cap.saturating_sub(self.policy.reserve_bytes);
            if total >= ceiling {
                allowed = false;
            }
        }
        self.optional_throttled = !allowed;
        allowed
    }

    /// Build a truthful report for the given usage.
    pub fn report(&self, authoritative_used: u64, optional_used: u64) -> CapacityReport {
        let headroom = self.capacity.map(|cap| {
            cap.saturating_sub(self.policy.reserve_bytes)
                .saturating_sub(authoritative_used)
                .saturating_sub(optional_used)
        });
        CapacityReport {
            policy: self.policy,
            authoritative_used_bytes: authoritative_used,
            authoritative_capacity_bytes: self.capacity,
            authoritative_headroom_bytes: headroom,
            optional_used_bytes: optional_used,
            optional_throttled: self.optional_throttled,
            degraded: self.is_degraded(),
            degraded_reason: self.degraded.clone(),
        }
    }
}

/// Read `statvfs` for `dir`, or `None` when it cannot be read.
fn statvfs(dir: &Path) -> Option<libc::statvfs> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c` is a valid NUL-terminated path; `st` is a valid, aligned,
    // fully-owned buffer that `statvfs` initialises. No pointer is retained.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return None;
    }
    Some(st)
}

/// The filesystem fragment size `statvfs` reports (falling back to `f_bsize`).
fn filesystem_block_size(st: &libc::statvfs) -> u64 {
    if st.f_frsize == 0 {
        st.f_bsize
    } else {
        st.f_frsize
    }
}

/// The bytes available to an unprivileged writer on the filesystem holding
/// `dir` (via `statvfs`), or `None` when it cannot be read.
pub fn backing_available_bytes(dir: &Path) -> Option<u64> {
    let st = statvfs(dir)?;
    Some(st.f_bavail.saturating_mul(filesystem_block_size(&st)))
}

/// The bytes available to an unprivileged writer on the filesystem that will
/// hold `dir`, walking up to the nearest existing ancestor when `dir` does not
/// exist yet (used by `init` before it creates anything).
pub fn backing_available_nearest(dir: &Path) -> Option<u64> {
    if let Some(free) = dir.ancestors().find_map(backing_available_bytes) {
        return Some(free);
    }
    // A relative path whose ancestors are all relative (e.g. `vol`): fall back
    // to the current directory so `init` still measures the real filesystem.
    std::env::current_dir()
        .ok()
        .and_then(|cwd| cwd.ancestors().find_map(backing_available_bytes))
}

/// Refuse to create a volume whose **initial reservation** (`initial_bytes`, the
/// framed genesis record, plus `reserve_bytes`) cannot fit in the backing free
/// space of the filesystem that will hold `dir` (Phase 68). The nearest existing
/// ancestor is measured, so the check runs before any directory is created. When
/// the filesystem cannot be measured the check is skipped — the OS `ENOSPC`
/// remains the ultimate backstop.
pub fn check_reservation(dir: &Path, initial_bytes: u64, reserve_bytes: u64) -> Result<()> {
    if let Some(available) = backing_available_nearest(dir) {
        let required = initial_bytes.saturating_add(reserve_bytes);
        if required > available {
            return Err(OrfsError::CapacityExhausted {
                needed: required,
                admissible: available,
            });
        }
    }
    Ok(())
}

/// The backing filesystem's free space and mount identity for `dir`.
pub fn backing_space(dir: &Path) -> Option<BackingSpace> {
    let st = statvfs(dir)?;
    let frsize = filesystem_block_size(&st);
    let (mount_point, device, filesystem) = mount_identity(dir);
    Some(BackingSpace {
        available_bytes: st.f_bavail.saturating_mul(frsize),
        free_bytes: st.f_bfree.saturating_mul(frsize),
        total_bytes: st.f_blocks.saturating_mul(frsize),
        mount_point,
        device,
        filesystem,
    })
}

/// The mount point, device, and filesystem type of the filesystem holding
/// `dir`, resolved from the inode's `st_dev` and `/proc/self/mountinfo`.
/// Returns `(None, None, None)` when it cannot be identified.
fn mount_identity(dir: &Path) -> (Option<String>, Option<String>, Option<String>) {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(dir) else {
        return (None, None, None);
    };
    let majmin = format!("{}:{}", libc::major(meta.dev()), libc::minor(meta.dev()));
    let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return (None, None, None);
    };
    for line in text.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        // Fields: 0 mount id, 1 parent id, 2 major:minor, 3 root, 4 mount point,
        // ... optional fields ..., a `-` separator, then fstype and source.
        if fields.len() < 6 || fields[2] != majmin {
            continue;
        }
        let mount_point = Some(unescape_mountinfo(fields[4]));
        let sep = fields.iter().position(|f| *f == "-");
        let (filesystem, device) = match sep {
            Some(i) => (
                fields.get(i + 1).map(|s| s.to_string()),
                fields.get(i + 2).map(|s| unescape_mountinfo(s)),
            ),
            None => (None, None),
        };
        return (mount_point, device, filesystem);
    }
    (None, None, None)
}

/// Decode the octal escapes `mountinfo` uses for space, tab, newline, and
/// backslash in a field.
fn unescape_mountinfo(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_defaults_to_unbounded_and_admits() {
        let mut g = CapacityGovernor::default();
        assert!(g.check_authoritative(0, 1 << 40).is_ok());
        assert!(!g.is_degraded());
        assert!(g.optional_allowed(0, 0));
    }

    #[test]
    fn hard_capacity_refuses_then_latches_read_only() {
        let mut g = CapacityGovernor::new(CapacityPolicy::new().with_authoritative_capacity(1000));
        assert!(g.check_authoritative(0, 900).is_ok());
        let err = g.check_authoritative(900, 200).unwrap_err();
        assert!(matches!(err, OrfsError::NoSpace(_)));
        assert!(g.is_degraded());
        // Every subsequent mutation is refused with EROFS, never accepted.
        let err = g.check_authoritative(900, 1).unwrap_err();
        assert!(matches!(err, OrfsError::ReadOnly(_)));
        assert_eq!(err.errno(), libc::EROFS);
    }

    #[test]
    fn reserve_is_honoured() {
        let mut g = CapacityGovernor::new(
            CapacityPolicy::new()
                .with_authoritative_capacity(1000)
                .with_reserve(200),
        );
        // Only 800 bytes are admissible; 801 breaches the reserve.
        assert!(g.check_authoritative(0, 800).is_ok());
        let mut g = CapacityGovernor::new(
            CapacityPolicy::new()
                .with_authoritative_capacity(1000)
                .with_reserve(200),
        );
        assert!(matches!(
            g.check_authoritative(0, 801).unwrap_err(),
            OrfsError::NoSpace(_)
        ));
    }

    #[test]
    fn hard_quota_is_independent_of_capacity() {
        let mut g = CapacityGovernor::new(CapacityPolicy::new().with_hard_quota(500));
        assert!(g.check_authoritative(0, 500).is_ok());
        assert!(matches!(
            g.check_authoritative(0, 501).unwrap_err(),
            OrfsError::NoSpace(_)
        ));
    }

    #[test]
    fn optional_is_throttled_before_authoritative_is_endangered() {
        let mut g = CapacityGovernor::new(
            CapacityPolicy::new()
                .with_authoritative_capacity(1000)
                .with_reserve(100),
        );
        // Optional + authoritative well below the reserve ceiling: allowed.
        assert!(g.optional_allowed(600, 100));
        assert!(!g.optional_throttled());
        // Total reaches the ceiling (900): throttle optional. Authoritative
        // admission still has the remaining headroom once optional is counted.
        assert!(!g.optional_allowed(850, 100));
        assert!(g.optional_throttled());
        assert!(g.check_authoritative(600, 190).is_ok());
        // And refuses once the optional bytes plus the request break the reserve.
        assert!(matches!(
            g.check_authoritative(600, 250).unwrap_err(),
            OrfsError::NoSpace(_)
        ));
    }

    #[test]
    fn soft_quota_throttles_optional_but_not_authoritative() {
        let mut g = CapacityGovernor::new(CapacityPolicy::new().with_soft_quota(500));
        assert!(!g.optional_allowed(400, 100));
        // The soft quota never refuses an authoritative write.
        assert!(g.check_authoritative(400, 100).is_ok());
    }

    #[test]
    fn degraded_volume_forbids_optional_construction() {
        let mut g = CapacityGovernor::new(CapacityPolicy::new().with_authoritative_capacity(10));
        let _ = g.check_authoritative(0, 11);
        assert!(g.is_degraded());
        assert!(!g.optional_allowed(0, 0));
    }

    #[test]
    fn report_exposes_headroom_and_reason() {
        let mut g = CapacityGovernor::new(
            CapacityPolicy::new()
                .with_authoritative_capacity(1000)
                .with_reserve(100),
        );
        let r = g.report(200, 0);
        assert_eq!(r.authoritative_headroom_bytes, Some(700));
        assert!(!r.degraded);
        let _ = g.check_authoritative(0, 10_000);
        let r = g.report(0, 0);
        assert!(r.degraded);
        assert!(r.degraded_reason.is_some());
    }
}
