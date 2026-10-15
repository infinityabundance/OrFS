//! Reusable fault-injection points (research §34 "Fault-injection court").
//!
//! The authoritative commit path is instrumented with named [`Failpoint`]s. The
//! system is **compiled out by default** and enabled with the `failpoints`
//! Cargo feature:
//!
//! ```sh
//! cargo test --features failpoints
//! ```
//!
//! When the feature is disabled, [`check`] is an `#[inline]` no-op and none of
//! the runtime control state exists — there is no cost and no way for a
//! production build to trip a failpoint.
//!
//! # Runtime control
//!
//! Control is **thread-local**, so independent tests (which `cargo test` runs on
//! separate threads) never interfere. A thread is configured either from the
//! environment or programmatically:
//!
//! * `ORFS_FAILPOINT` — comma/whitespace separated failpoint names to arm.
//! * `ORFS_FAILPOINT_ACTION` — `abort` (default) or `error`.
//! * `ORFS_FAILPOINT_SKIP` — number of firings to allow before the armed action
//!   takes effect (default `0`).
//!
//! Programmatic control (used by in-process tests) is
//! [`configure`] / [`clear`], with a spec of the form
//! `name=action[:skip];name2=action`.
//!
//! # Semantics of the two actions
//!
//! * **`error`** — [`check`] returns [`OrfsError::Failpoint`]. The write path
//!   unwinds through its normal error handling and the caller must discard (drop
//!   or reopen) the log: a failpoint deliberately leaves the in-memory log state
//!   inconsistent with the physical bytes.
//! * **`abort`** — the process is terminated immediately with `SIGABRT`
//!   (`std::process::abort`). This is the action used by
//!   `tests/crash_recovery.rs` to simulate a genuine process crash: no destructor
//!   runs, no buffer is flushed, and the on-disk bytes are exactly those written
//!   before the failpoint.
//!
//! Neither action models storage-device reordering or device-cache loss. See
//! `docs/TRANSACTIONS.md` §"Process crash is not power loss".

use crate::error::Result;

/// A named injection point on the authoritative write path.
///
/// The first ten variants correspond exactly to `research/OrFS.md` §34
/// items 1–10; `DuringDirectorySync` is the extra directory-synchronization
/// point (item 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failpoint {
    /// 1. Before the first append-position reservation of a transaction.
    BeforeReservation,
    /// 2. After an append position has been reserved but before any byte of the
    ///    reserved record is written.
    AfterReservation,
    /// 3. During a record write: roughly half of the record's bytes are on disk
    ///    (a torn record).
    DuringRecordWrite,
    /// 4. After a data record is fully written but the transaction is not yet
    ///    committed (some records, no `TX_COMMIT`).
    AfterPartialRecordWrite,
    /// 5. After all data records, immediately before the `TX_COMMIT` record.
    BeforeCommit,
    /// 6. During the `TX_COMMIT` record write (a torn commit record).
    DuringCommitRecordWrite,
    /// 7. After the `TX_COMMIT` record is fully written, before it is published
    ///    in memory.
    AfterCommitCompletion,
    /// 8. Immediately before the in-memory committed root is published.
    BeforePublication,
    /// 9. After publication but before the required synchronization completes.
    AfterPublicationBeforeSync,
    /// 10. At the start of physical segment rollover.
    DuringSegmentRollover,
    /// 11. During a directory `fsync` (segment-directory durability).
    DuringDirectorySync,
    /// 18. The **shared durability barrier** itself: the log-level `flush`/`fsync`
    ///     hook (`Log::sync`) that the mount-level group-commit coordinator issues
    ///     once per batch (Phase 88). Distinct from
    ///     [`Failpoint::AfterPublicationBeforeSync`] (which fires on the
    ///     commit-sequencer path *before* it calls that hook) so a test can fail
    ///     the barrier **after** every member has been published and observe that
    ///     the members are refused, not acknowledged. Kept **out** of
    ///     [`Failpoint::ALL`] so the §34 crash matrix (which arms every
    ///     [`Failpoint::ALL`] item) is unaffected.
    DurabilityBarrier,
    /// 12. Tier relocation (Phase 76): after the durable `Copying` intent record,
    ///     before the cold-tier copy is written.
    TierAfterIntent,
    /// 13. Tier relocation: after the cold-tier copy is written and fsynced,
    ///     before it is read back and digest-verified.
    TierAfterRemoteCopy,
    /// 14. Tier relocation: after the `Copied{verified}` transition is durable,
    ///     before `Released`.
    TierAfterVerified,
    /// 15. Tier relocation: after the `Released` transition is durable, before
    ///     the local copy is (idempotently) deleted.
    TierAfterReleased,
    /// 16. Tier relocation: after the local copy is deleted and the log directory
    ///     fsynced.
    TierAfterLocalDelete,
    /// 17. Tier recall: after a recalled local copy is restored and verified,
    ///     before the `Recalled` transition is recorded.
    TierAfterRecall,
}

impl Failpoint {
    /// Every failpoint, in injection order.
    pub const ALL: [Failpoint; 11] = [
        Failpoint::BeforeReservation,
        Failpoint::AfterReservation,
        Failpoint::DuringRecordWrite,
        Failpoint::AfterPartialRecordWrite,
        Failpoint::BeforeCommit,
        Failpoint::DuringCommitRecordWrite,
        Failpoint::AfterCommitCompletion,
        Failpoint::BeforePublication,
        Failpoint::AfterPublicationBeforeSync,
        Failpoint::DuringSegmentRollover,
        Failpoint::DuringDirectorySync,
    ];

    /// The tier-relocation transitions (Phase 76, items 12–17). Kept *separate*
    /// from [`Failpoint::ALL`] so the §34 crash matrix (which arms every
    /// [`Failpoint::ALL`] item on the commit path and requires each to fire) is
    /// unaffected by relocation failpoints that only fire in
    /// [`crate::tiering`]. `from_name` searches both.
    pub const TIER_ALL: [Failpoint; 6] = [
        Failpoint::TierAfterIntent,
        Failpoint::TierAfterRemoteCopy,
        Failpoint::TierAfterVerified,
        Failpoint::TierAfterReleased,
        Failpoint::TierAfterLocalDelete,
        Failpoint::TierAfterRecall,
    ];

    /// The mount-level **durability-barrier** failpoints (Phase 88). Kept separate
    /// from [`Failpoint::ALL`] for the same reason as [`Failpoint::TIER_ALL`]: they
    /// are armed only by the group-commit durability court, never by the §34
    /// commit-path crash matrix.
    pub const BARRIER_ALL: [Failpoint; 1] = [Failpoint::DurabilityBarrier];

    /// The stable snake-case name used in `ORFS_FAILPOINT` and evidence.
    pub const fn name(self) -> &'static str {
        match self {
            Failpoint::BeforeReservation => "before_reservation",
            Failpoint::AfterReservation => "after_reservation",
            Failpoint::DuringRecordWrite => "during_record_write",
            Failpoint::AfterPartialRecordWrite => "after_partial_record_write",
            Failpoint::BeforeCommit => "before_commit",
            Failpoint::DuringCommitRecordWrite => "during_commit_record_write",
            Failpoint::AfterCommitCompletion => "after_commit_completion",
            Failpoint::BeforePublication => "before_publication",
            Failpoint::AfterPublicationBeforeSync => "after_publication_before_sync",
            Failpoint::DuringSegmentRollover => "during_segment_rollover",
            Failpoint::DuringDirectorySync => "during_directory_sync",
            Failpoint::DurabilityBarrier => "durability_barrier",
            Failpoint::TierAfterIntent => "tier_after_intent",
            Failpoint::TierAfterRemoteCopy => "tier_after_remote_copy",
            Failpoint::TierAfterVerified => "tier_after_verified",
            Failpoint::TierAfterReleased => "tier_after_released",
            Failpoint::TierAfterLocalDelete => "tier_after_local_delete",
            Failpoint::TierAfterRecall => "tier_after_recall",
        }
    }

    /// Parse a failpoint from its stable name (the §34 set, the tier relocation
    /// transitions, or the mount-level durability barrier).
    pub fn from_name(name: &str) -> Option<Failpoint> {
        Failpoint::ALL
            .into_iter()
            .chain(Failpoint::TIER_ALL)
            .chain(Failpoint::BARRIER_ALL)
            .find(|f| f.name() == name)
    }
}

impl std::fmt::Display for Failpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// What happens when an armed failpoint fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailAction {
    /// Return [`OrfsError::Failpoint`] from the injection point.
    Error,
    /// Terminate the process with `SIGABRT`.
    Abort,
}

impl FailAction {
    fn parse(s: &str) -> Option<FailAction> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" | "err" => Some(FailAction::Error),
            "abort" | "panic" | "crash" => Some(FailAction::Abort),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Enabled implementation
// ---------------------------------------------------------------------------

/// Whether this build has failpoints compiled in.
#[inline]
pub const fn enabled() -> bool {
    cfg!(feature = "failpoints")
}

/// Arm `name` with `action` for the current thread; the action takes effect on
/// the `skip`th and subsequent firings (0 = immediately).
pub fn configure_one(name: &str, action: FailAction, skip: u64) {
    #[cfg(feature = "failpoints")]
    imp::configure_one(name, action, skip);
    #[cfg(not(feature = "failpoints"))]
    {
        let _ = (name, action, skip);
    }
}

/// Configure the current thread from a spec of the form
/// `name=action[:skip];name2=action`. Invalid entries are ignored. Any previous
/// configuration and firing counters on this thread are cleared first.
pub fn configure(spec: &str) {
    clear();
    for entry in spec.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, rest) = match entry.split_once('=') {
            Some((n, r)) => (n.trim(), r.trim()),
            None => (entry, "error"),
        };
        let (action_str, skip) = match rest.split_once(':') {
            Some((a, s)) => (a.trim(), s.trim().parse::<u64>().unwrap_or(0)),
            None => (rest, 0),
        };
        if let Some(action) = FailAction::parse(action_str) {
            configure_one(name, action, skip);
        }
    }
}

/// Forget this thread's failpoint configuration and counters. The next
/// [`check`] re-seeds from the environment.
pub fn clear() {
    #[cfg(feature = "failpoints")]
    imp::clear();
}

/// Whether `fp` is armed on this thread (regardless of its skip counter).
///
/// Used by the commit path to avoid paying for torn-write machinery unless a
/// test has actually requested it. Always `false` when the feature is disabled.
#[cfg(feature = "failpoints")]
#[inline]
pub fn armed(fp: Failpoint) -> bool {
    imp::is_armed(fp)
}

/// Whether `fp` is armed (disabled build: always `false`).
#[cfg(not(feature = "failpoints"))]
#[inline]
pub fn armed(_fp: Failpoint) -> bool {
    false
}

/// Consult a failpoint. Returns `Ok(())` unless the failpoint is armed and its
/// skip counter is exhausted, in which case the configured action is taken.
///
/// When the `failpoints` feature is disabled this is a compile-time no-op.
#[cfg(feature = "failpoints")]
#[inline]
pub fn check(fp: Failpoint) -> Result<()> {
    match imp::observe(fp) {
        None => Ok(()),
        Some(FailAction::Error) => Err(crate::error::OrfsError::Failpoint(fp.name())),
        Some(FailAction::Abort) => {
            // Terminate without unwinding: this is a process crash, not a panic.
            std::process::abort();
        }
    }
}

/// Consult a failpoint (disabled build: always `Ok`).
#[cfg(not(feature = "failpoints"))]
#[inline]
pub fn check(_fp: Failpoint) -> Result<()> {
    Ok(())
}

#[cfg(feature = "failpoints")]
mod imp {
    use super::{FailAction, Failpoint};
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct State {
        seeded: bool,
        spec: HashMap<Failpoint, (FailAction, u64)>,
        hits: HashMap<Failpoint, u64>,
    }

    thread_local! {
        static STATE: RefCell<State> = RefCell::new(State::default());
    }

    fn seed_from_env(state: &mut State) {
        let names = std::env::var("ORFS_FAILPOINT").unwrap_or_default();
        if names.trim().is_empty() {
            return;
        }
        let action = std::env::var("ORFS_FAILPOINT_ACTION")
            .ok()
            .and_then(|s| FailAction::parse(&s))
            .unwrap_or(FailAction::Abort);
        let skip = std::env::var("ORFS_FAILPOINT_SKIP")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        for name in names.split([',', ' ', '\t', '\n']) {
            if let Some(fp) = Failpoint::from_name(name.trim()) {
                state.spec.insert(fp, (action, skip));
            }
        }
    }

    /// Decide whether `fp` fires now, advancing its counter when it does not.
    pub(super) fn observe(fp: Failpoint) -> Option<FailAction> {
        STATE.with(|cell| {
            let mut state = cell.borrow_mut();
            if !state.seeded {
                seed_from_env(&mut state);
                state.seeded = true;
            }
            let (action, skip) = *state.spec.get(&fp)?;
            let hits = state.hits.entry(fp).or_insert(0);
            if *hits >= skip {
                Some(action)
            } else {
                *hits += 1;
                None
            }
        })
    }

    pub(super) fn configure_one(name: &str, action: FailAction, skip: u64) {
        if let Some(fp) = Failpoint::from_name(name.trim()) {
            STATE.with(|cell| {
                let mut state = cell.borrow_mut();
                // Any programmatic configuration disables env re-seeding.
                state.seeded = true;
                state.spec.insert(fp, (action, skip));
                state.hits.remove(&fp);
            });
        }
    }

    pub(super) fn clear() {
        STATE.with(|cell| {
            let mut state = cell.borrow_mut();
            *state = State::default();
        });
    }

    /// Whether `fp` would be considered on this thread once seeded.
    pub(super) fn is_armed(fp: Failpoint) -> bool {
        STATE.with(|cell| {
            let mut state = cell.borrow_mut();
            if !state.seeded {
                seed_from_env(&mut state);
                state.seeded = true;
            }
            state.spec.contains_key(&fp)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_are_unique() {
        for fp in Failpoint::ALL {
            assert_eq!(Failpoint::from_name(fp.name()), Some(fp));
        }
        let mut names: Vec<&str> = Failpoint::ALL.iter().map(|f| f.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Failpoint::ALL.len());
    }

    #[cfg(not(feature = "failpoints"))]
    #[test]
    fn disabled_build_is_a_no_op() {
        // With no feature, check never fires regardless of configuration.
        clear();
        configure("before_commit=error");
        assert!(check(Failpoint::BeforeCommit).is_ok());
    }

    #[cfg(feature = "failpoints")]
    #[test]
    fn error_action_fires_after_skip() {
        clear();
        configure("before_commit=error:2");
        assert!(check(Failpoint::BeforeCommit).is_ok());
        assert!(check(Failpoint::BeforeCommit).is_ok());
        let err = check(Failpoint::BeforeCommit).unwrap_err();
        assert!(matches!(
            err,
            crate::error::OrfsError::Failpoint("before_commit")
        ));
        // An unarmed failpoint never fires.
        assert!(check(Failpoint::BeforeReservation).is_ok());
    }

    #[cfg(feature = "failpoints")]
    #[test]
    fn configure_is_thread_local() {
        clear();
        configure("before_commit=error");
        let handle = std::thread::spawn(|| check(Failpoint::BeforeCommit).is_ok());
        // The other thread is unconfigured, so it does not fire.
        assert!(handle.join().unwrap());
        assert!(check(Failpoint::BeforeCommit).is_err());
    }
}
