//! Bounded **Loom models** of the two synchronization protocols on which Phase
//! 19 (concurrent immutable read views) and Phase 46 (the group-commit
//! coordinator) rest.
//!
//! The real types cannot be loom-instrumented without a large refactor —
//! `ReadCell` is a `parking_lot::RwLock`, the commit sequencer is serialised by
//! Rust borrow-checking (`&mut Volume`) rather than by a lock, and both paths
//! perform real `pread`/`fsync` I/O — so, as the directive's explicit fallback
//! allows, this module re-expresses the **minimal synchronization protocol**:
//! the same lock order and the same state machine, compiled with
//! configuration-selected primitives (`loom::sync` under `--cfg loom`,
//! `std::sync` otherwise). It **mirrors** the real code; it does not instrument
//! it. See `docs/CONCURRENCY.md` §10 for the precise coverage boundary.
//!
//! The module is compiled only for the model: under `--cfg loom` (the Loom
//! build, `scripts/container-loom.sh`) and under `cfg(test)` (so the ordinary
//! test and clippy builds still compile and lint it). A normal production build
//! carries none of it.

#[cfg(loom)]
use loom::sync::{Arc, Condvar, Mutex, RwLock};
#[cfg(not(loom))]
use std::sync::{Arc, Condvar, Mutex, RwLock};

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// (a) Concurrent immutable read views (Phase 19)
// ---------------------------------------------------------------------------

/// A complete, frozen read view: the unit a reader observes.
///
/// It mirrors the fields `ReadState` captures at the commit boundary (`root`
/// plus the frozen index and the log locator). `sealed` is set only once the
/// whole view is built, so a publication that filled a live view in place
/// (`publish-then-mutate`) would be detectable — the model builds first, then
/// publishes, exactly as `Namespace::publish_read_state` does.
#[derive(Debug)]
pub struct FrozenView {
    /// The committed root this view reflects.
    pub root: u64,
    /// The view payload. Row `i` must equal `root`; a torn publication would
    /// expose a row written for a different root.
    pub rows: Vec<u8>,
    /// `true` only when the view is fully constructed.
    pub sealed: bool,
}

impl FrozenView {
    /// Build a complete view for `root`. Everything is finalised *before* it is
    /// handed to [`ReadViewCell::publish`].
    pub fn build(root: u64) -> FrozenView {
        let rows = vec![root as u8; root as usize];
        FrozenView {
            root,
            rows,
            sealed: true,
        }
    }

    /// The reader's consistency check: the view is sealed and internally
    /// consistent, so it can only be a whole committed version, never a partial
    /// or mixed one.
    pub fn is_consistent(&self) -> bool {
        self.sealed && self.rows.iter().all(|&b| b == self.root as u8)
    }
}

/// The publication protocol of `ReadCell = Arc<parking_lot::RwLock<Arc<dyn
/// CoreRead>>>` (`src/namespace.rs`).
pub struct ReadViewCell {
    view: RwLock<Arc<FrozenView>>,
    /// The shared segment-handle cache (mirrors `ReadState::log`'s
    /// `Arc<Mutex<SegmentCache>>`). It is taken only briefly and never while the
    /// publication lock is held.
    cache: Mutex<u64>,
}

impl ReadViewCell {
    /// Publish an initial complete view before the cell is shared.
    pub fn new(initial: FrozenView) -> ReadViewCell {
        ReadViewCell {
            view: RwLock::new(Arc::new(initial)),
            cache: Mutex::new(0),
        }
    }

    /// A writer installs a new complete view at the commit boundary: build it,
    /// then swap the pointer under the write lock. The write lock is held only
    /// for the store (mirrors `*self.read_pub.write() = state;`).
    pub fn publish(&self, next: FrozenView) {
        let next = Arc::new(next);
        *self.view.write().unwrap() = next;
    }

    /// A reader clones the current `Arc` out under the read lock and drops the
    /// guard (mirrors `self.read_pub.read().clone()`): nothing else is done
    /// while the publication lock is held.
    pub fn load(&self) -> Arc<FrozenView> {
        self.view.read().unwrap().clone()
    }

    /// The section mirroring `ReadState::read_at`: use the already-cloned view
    /// and take the shared cache lock briefly. **No** publication lock is held
    /// here — that is the whole point of the model.
    pub fn read_bytes(&self, view: &FrozenView) -> usize {
        let mut hits = self.cache.lock().unwrap();
        *hits += 1;
        view.rows.len()
    }
}

// ---------------------------------------------------------------------------
// (b) The group-commit coordinator's admission-and-fence state machine
//    (Phase 32/46, `src/group_commit.rs`)
// ---------------------------------------------------------------------------

/// The outcome of a submission, mirroring `BatchCoordinator::try_admit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Admitted into the coordinator and acknowledged **only after** the shared
    /// durability barrier that covered this job's bytes completed.
    Acked { seq: u64, barrier_ok: bool },
    /// Refused because the bounded queue was full: the caller serves it on the
    /// direct path (under the core lock, with its own barrier). Never dropped.
    Refused { job: u64 },
}

/// An ordered, happens-before ledger the model's assertions scan. Every event is
/// appended under the coordinator's state lock, so the recorded order is a total
/// order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcEvent {
    /// A submission was refused by bounded admission.
    Refused(u64),
    /// A batched job's bytes were written under the core lock.
    Wrote(u64),
    /// The shared barrier completed, covering every job sequence `<= this`.
    Barrier(u64),
    /// A batched member was acknowledged (recorded after [`GcEvent::Barrier`]).
    AckedBatch(u64),
    /// A direct-path job issued its own barrier.
    DirectBarrier(u64),
    /// A direct-path job was acknowledged (recorded after its own barrier).
    AckedDirect(u64),
}

struct GcShared {
    state: Mutex<GcState>,
    /// The worker waits here for queued work (mirrors the bounded channel's
    /// blocking `recv`).
    work: Condvar,
    /// A submitter waits here for its acknowledgment (mirrors the caller
    /// blocking on its reply receiver).
    ack_ready: Condvar,
    /// The "core" lock: the coordinator runs the batch and the shared barrier
    /// under it, exactly as `run_loop` holds `inner.core` across
    /// `execute_batch`.
    core: Mutex<GcCore>,
}

struct GcState {
    capacity: usize,
    limit: usize,
    next_seq: u64,
    queued: VecDeque<u64>,
    acks: Vec<(u64, bool)>,
    shutdown: bool,
    events: Vec<GcEvent>,
}

struct GcCore {
    barrier_through: u64,
    barriers: u64,
    direct_serves: u64,
}

/// The group-commit coordinator's admission-and-fence state machine.
pub struct GroupCommitModel {
    shared: Arc<GcShared>,
}

impl GroupCommitModel {
    /// `limit` is the batch bound; the bounded-admission capacity is
    /// `limit × QUEUE_SLACK` in the real code (`QUEUE_SLACK = 2`), passed here
    /// explicitly so the court can force refusals.
    pub fn new(limit: usize, capacity: usize) -> GroupCommitModel {
        GroupCommitModel {
            shared: Arc::new(GcShared {
                state: Mutex::new(GcState {
                    capacity: capacity.max(1),
                    limit: limit.max(1),
                    next_seq: 0,
                    queued: VecDeque::new(),
                    acks: Vec::new(),
                    shutdown: false,
                    events: Vec::new(),
                }),
                work: Condvar::new(),
                ack_ready: Condvar::new(),
                core: Mutex::new(GcCore {
                    barrier_through: 0,
                    barriers: 0,
                    direct_serves: 0,
                }),
            }),
        }
    }

    /// Non-blocking bounded admission (`try_admit`). On success the caller
    /// blocks for its own acknowledgment; on refusal it is handed its job back
    /// unchanged for the direct path.
    pub fn submit(&self, job: u64) -> SubmitOutcome {
        let mut st = self.shared.state.lock().unwrap();
        if st.queued.len() >= st.capacity {
            st.events.push(GcEvent::Refused(job));
            return SubmitOutcome::Refused { job };
        }
        let seq = st.next_seq;
        st.next_seq += 1;
        st.queued.push_back(seq);
        self.shared.work.notify_one();
        // Block for the acknowledgment. The check and the wait hold the same
        // state lock, so an acknowledgment inserted between them cannot be
        // missed (the Phase-61 lost-wakeup discipline).
        loop {
            if let Some(pos) = st.acks.iter().position(|(s, _)| *s == seq) {
                let (_, ok) = st.acks.swap_remove(pos);
                return SubmitOutcome::Acked {
                    seq,
                    barrier_ok: ok,
                };
            }
            st = self.shared.ack_ready.wait(st).unwrap();
        }
    }

    /// Run at most one batch. Blocks until work is available or the coordinator
    /// is shut down; returns `false` once shut down with nothing queued.
    pub fn run_batch(&self) -> bool {
        let mut st = self.shared.state.lock().unwrap();
        while st.queued.is_empty() && !st.shutdown {
            st = self.shared.work.wait(st).unwrap();
        }
        if st.queued.is_empty() {
            return false;
        }
        let n = st.queued.len().min(st.limit);
        let batch: Vec<u64> = st.queued.drain(..n).collect();
        drop(st);

        let last = *batch.last().expect("non-empty batch");
        // Execute and barrier under the core lock (mirrors `run_loop`:
        // `let mut core = inner.core.lock(); execute_batch(&mut *core, batch, …)`).
        let mut core = self.shared.core.lock().unwrap();
        core.barrier_through = core.barrier_through.max(last);
        core.barriers += 1;
        // Record the write / barrier / ack events in protocol order, under the
        // state lock (lock order: core → state, as `execute_batch` sends its
        // replies while the core lock is still held).
        let mut st = self.shared.state.lock().unwrap();
        for seq in &batch {
            st.events.push(GcEvent::Wrote(*seq));
        }
        st.events.push(GcEvent::Barrier(last));
        for seq in batch {
            st.acks.push((seq, true));
            st.events.push(GcEvent::AckedBatch(seq));
        }
        self.shared.ack_ready.notify_all();
        drop(st);
        drop(core);
        true
    }

    /// Serve a refused job on the direct path: under the core lock, with its own
    /// durability barrier (mirrors the caller of `try_admit` running the job
    /// itself when admission is refused).
    pub fn direct_path(&self, job: u64) {
        let mut core = self.shared.core.lock().unwrap();
        core.direct_serves += 1;
        let mut st = self.shared.state.lock().unwrap();
        st.events.push(GcEvent::DirectBarrier(job));
        st.events.push(GcEvent::AckedDirect(job));
        drop(st);
        drop(core);
    }

    /// Stop the worker: its blocking receive returns and the worker loop exits.
    pub fn shutdown(&self) {
        let mut st = self.shared.state.lock().unwrap();
        st.shutdown = true;
        drop(st);
        self.shared.work.notify_all();
    }

    /// The happens-before ledger (a copy), for the model's assertions.
    pub fn ledger(&self) -> Vec<GcEvent> {
        self.shared.state.lock().unwrap().events.clone()
    }

    /// The number of shared barriers the coordinator issued.
    pub fn barriers(&self) -> u64 {
        self.shared.core.lock().unwrap().barriers
    }

    /// The number of direct-path serves (refused admissions run by the caller).
    pub fn direct_serves(&self) -> u64 {
        self.shared.core.lock().unwrap().direct_serves
    }

    /// The highest job sequence covered by a completed barrier.
    pub fn barrier_through(&self) -> u64 {
        self.shared.core.lock().unwrap().barrier_through
    }

    /// **Invariant (I7).** No acknowledgment precedes a durability barrier that
    /// covers the acknowledged job's bytes. A batched member must follow a
    /// [`GcEvent::Barrier`] covering its sequence; a direct member must follow
    /// its own [`GcEvent::DirectBarrier`].
    pub fn ack_never_precedes_covering_barrier(&self) -> bool {
        let mut batch_durable = 0u64;
        let mut direct_durable = 0u64;
        for ev in self.ledger() {
            match ev {
                GcEvent::Barrier(t) => batch_durable = batch_durable.max(t),
                GcEvent::DirectBarrier(j) => direct_durable = direct_durable.max(j),
                GcEvent::AckedBatch(s) if s > batch_durable => return false,
                GcEvent::AckedDirect(j) if j > direct_durable => return false,
                _ => {}
            }
        }
        true
    }

    /// **Invariant (ordering).** Batched jobs are written in submission order.
    pub fn writes_in_submission_order(&self) -> bool {
        let mut prev: Option<u64> = None;
        for ev in self.ledger() {
            if let GcEvent::Wrote(seq) = ev {
                if let Some(p) = prev {
                    if seq <= p {
                        return false;
                    }
                }
                prev = Some(seq);
            }
        }
        true
    }
}
