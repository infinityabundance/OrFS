//! Phase 70: bounded **Loom models** of the concurrent-immutable-read-view
//! protocol (Phase 19) and the group-commit coordinator's admission/fence
//! (Phase 32/46). See `docs/CONCURRENCY.md` §10.
//!
//! `#![cfg(loom)]`: this court compiles to an empty test binary in a normal
//! build, so the default `cargo test` count is unaffected and no normal build
//! compiles `loom`. Run it with `sh scripts/container-loom.sh`
//! (`RUSTFLAGS="--cfg loom" cargo test --test loom_concurrency`).
//!
//! The models are deliberately tiny so the state space stays bounded and the
//! court finishes quickly. The search is additionally bounded by a preemption
//! limit, a permutation cap and a wall-clock cap; `ORFS_LOOM_FULL=1` relaxes all
//! three, and the per-axis `ORFS_LOOM_{READERS,PUBLISHES,LOADS,SUBMITTERS,JOBS}`
//! variables override individual model sizes.

#![cfg(loom)]

use std::time::Duration;

use loom::sync::Arc;
use loom::thread;

use orfs::sync_model::{FrozenView, GcEvent, GroupCommitModel, ReadViewCell, SubmitOutcome};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

fn full() -> bool {
    std::env::var("ORFS_LOOM_FULL").as_deref() == Ok("1")
}

/// Run a bounded Loom model. The default is intentionally small so the court
/// finishes quickly; `ORFS_LOOM_FULL=1` relaxes the caps for a longer search.
fn check<F>(f: F)
where
    F: Fn() + Sync + Send + 'static,
{
    let mut builder = loom::model::Builder::new();
    // Honour the caps every iteration rather than every 20 000th.
    builder.checkpoint_interval = 1;
    builder.preemption_bound = if full() { None } else { Some(2) };
    // No permutation cap by default: with a preemption bound of 2 the search is
    // exhaustive (it completed in ~7 s locally) and stays well inside the time
    // cap. `ORFS_LOOM_FULL=1` lifts the preemption bound and the time cap for a
    // longer, unbounded-preemption search.
    builder.max_permutations = None;
    builder.max_duration = Some(Duration::from_secs(if full() { 600 } else { 60 }));
    builder.check(f);
}

/// **Invariants.** N readers clone the current immutable view out of the shared
/// cell (the only lock they hold is the short read-lock around the `Arc` clone)
/// while one writer publishes successive complete roots. Every loaded view must
/// be internally consistent — a whole committed version, never a partial one —
/// and the threads must not deadlock.
#[test]
fn read_views_are_never_observed_partial_and_do_not_deadlock() {
    let readers = env_usize("ORFS_LOOM_READERS", if full() { 3 } else { 2 });
    let publishes = env_usize("ORFS_LOOM_PUBLISHES", if full() { 3 } else { 2 });
    let loads = env_usize("ORFS_LOOM_LOADS", if full() { 4 } else { 2 });

    check(move || {
        let cell = Arc::new(ReadViewCell::new(FrozenView::build(0)));
        let writer = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                for k in 1..=publishes as u64 {
                    cell.publish(FrozenView::build(k));
                }
            })
        };
        let mut readers_handles = Vec::new();
        for _ in 0..readers {
            let cell = Arc::clone(&cell);
            readers_handles.push(thread::spawn(move || {
                for _ in 0..loads {
                    // Clone the view out (the only moment the publication lock is
                    // held), then read with no publication lock held.
                    let view = cell.load();
                    assert!(
                        view.is_consistent(),
                        "reader observed a torn/partial view: {view:?}"
                    );
                    let n = cell.read_bytes(&view);
                    assert_eq!(n, view.rows.len());
                }
            }));
        }
        for h in readers_handles {
            h.join().unwrap();
        }
        writer.join().unwrap();
        // The last published root is the one left installed.
        assert_eq!(cell.load().root, publishes as u64);
    });
}

/// **Invariants.** Many submitters race to admit jobs into the bounded
/// coordinator while one worker drains batches, runs them under the core lock,
/// issues one shared durability barrier, and only then acknowledges each member.
/// I7 must hold under every explored interleaving: a member is never
/// acknowledged before a barrier covering its bytes completed; batched jobs are
/// written in submission order; refused submissions are served on the direct
/// path (never dropped); and no thread deadlocks.
#[test]
fn group_commit_never_acks_before_the_covering_barrier() {
    let submitters = env_usize("ORFS_LOOM_SUBMITTERS", 2);
    let jobs_each = env_usize("ORFS_LOOM_JOBS", if full() { 3 } else { 2 });

    check(move || {
        // Batch bound 2, admission capacity 2 (QUEUE_SLACK = 2 in the real code
        // would be 4; 2 forces refusals into the direct path, which the model
        // covers).
        let gc = Arc::new(GroupCommitModel::new(2, 2));
        let worker = {
            let gc = Arc::clone(&gc);
            thread::spawn(move || loop {
                if !gc.run_batch() {
                    break;
                }
            })
        };
        let mut handles = Vec::new();
        for _ in 0..submitters {
            let gc = Arc::clone(&gc);
            handles.push(thread::spawn(move || {
                for job in 0..jobs_each as u64 {
                    match gc.submit(job) {
                        SubmitOutcome::Acked { barrier_ok, .. } => {
                            assert!(barrier_ok, "job {job} acked with a failed barrier")
                        }
                        // Refused: the caller runs it on the direct path.
                        SubmitOutcome::Refused { job } => gc.direct_path(job),
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        gc.shutdown();
        worker.join().unwrap();

        // The coordinator did real work, or the assertions below prove nothing.
        assert!(gc.barriers() >= 1, "no batched barrier ran");
        assert!(gc.barrier_through() >= 1, "no job was covered by a barrier");
        // I7 and ordering, over the whole happens-before ledger.
        assert!(
            gc.ack_never_precedes_covering_barrier(),
            "an acknowledgment preceded its durability barrier"
        );
        assert!(
            gc.writes_in_submission_order(),
            "batched jobs were not written in submission order"
        );
        // No job is lost and none is acked twice: every submitted job is
        // accounted for exactly once, batched or on the direct path.
        let ledger = gc.ledger();
        let acked_batch = ledger
            .iter()
            .filter(|e| matches!(e, GcEvent::AckedBatch(_)))
            .count();
        let refused = ledger
            .iter()
            .filter(|e| matches!(e, GcEvent::Refused(_)))
            .count();
        assert_eq!(
            acked_batch + gc.direct_serves() as usize,
            submitters * jobs_each,
            "every submitted job must be acknowledged exactly once"
        );
        assert_eq!(
            refused,
            gc.direct_serves() as usize,
            "every refused submission must be served on the direct path"
        );
    });
}
