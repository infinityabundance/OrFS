//! End-to-end group-commit coordinator through the transports (Phases 32/39).
//!
//! The engine-level ordered group commit (Phase 31, [`crate::commit`]) amortises
//! **one** durability barrier over many transactions. Before Phase 32 the FUSE
//! adapters serialised every mutating request through `Mutex<Core>` and issued a
//! per-request `fsync`, so that win was invisible through a mount.
//!
//! This coordinator makes the win observable end-to-end without disturbing the
//! delicate per-transaction record-offset logic:
//!
//! * Mutating requests are submitted here instead of taking the core lock
//!   directly. A background thread drains a batch of concurrently-arrived jobs
//!   and runs them **sequentially**, in submission order, against the core — so
//!   authoritative order, per-transaction atomicity and the existing `Plan`
//!   offset prediction are all preserved untouched.
//! * For a `sync` mount the batch runs with the durability temporarily lowered to
//!   `ordered` (so no per-job `fsync`), then a **single** `fsync` covers the whole
//!   batch before any caller is acknowledged. Each caller is acknowledged only
//!   after that barrier, so the `sync` contract (I7) is fully preserved; the
//!   expensive barrier is amortised exactly as the review (§6) describes.
//! * For `ordered`/`batched` mounts the jobs run with their normal durability and
//!   no extra barrier is added — no semantic change and no fabricated win. There
//!   is consequently *nothing to amortise*, so the adaptive policy never waits for
//!   such a mount.
//!
//! # Adaptive coalescing (this phase)
//!
//! A **fixed** linger (the original 300 µs [`FIXED_LINGER`]) is wrong across the
//! traffic range: when a backlog already exists the wait is pointless, and when
//! traffic is sparse it cannot manufacture concurrency — it only adds latency.
//! The adaptive policy instead decides, from observable state, whether to commit
//! immediately or briefly accumulate:
//!
//! ```text
//! t_wait = min(t_batch_opportunity, t_remaining_latency_budget)
//! ```
//!
//! where `t_batch_opportunity` is the opportunity window `min(barrier_cost,
//! latency_objective)`: the wait is bounded by the barrier it would amortise and
//! by the latency objective — which bounds the *linger the coordinator adds*, not
//! the load-induced queueing delay (see [`coalesce_wait`]). The concrete rule
//! lives in [`coalesce_wait`] and is a pure function of [`CoalesceInputs`] so it
//! is deterministically testable. Waiting is undertaken **only** when coalescing
//! is worthwhile: when contention is already evident (the batch holds more than
//! one member, a ready backlog exists, or the oldest member has waited past the
//! objective), or when another arrival is expected within the window
//! (`rate × window ≥ 1`); a strictly sequential writer is therefore never delayed.
//! While the predictor is still uncertain (no arrival rate yet, or the barrier not
//! yet measured) the rule keeps a **conservative fallback to the historical
//! [`FIXED_LINGER`]**, capped by the objective, so it never adds unbounded
//! latency.
//!
//! # Bounded admission (this phase)
//!
//! The submission channel is a **bounded** `sync_channel` holding at most
//! `batch_limit × QUEUE_SLACK` waiting jobs. Admission is non-blocking
//! ([`BatchCoordinator::try_admit`]): a submission that finds the queue full is
//! handed back and served on the **direct path** by the caller, under the same
//! core lock, with its normal durability (so an over-capacity caller still gets a
//! per-request `fsync` under `sync` — I7 is untouched, never a silent drop and
//! never a false success). This caps queueing delay and yields a predictable
//! latency-vs-throughput envelope instead of unbounded batching.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{
    channel, sync_channel, Receiver, Sender, SyncSender, TryRecvError, TrySendError,
};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use crate::commit::DurabilityMode;
use crate::error::{OrfsError, Result};
use crate::fuse::Inner;
use crate::namespace::OrfsCore;

/// A single mutation to run against the core, yielding an `i64` (unit ops yield
/// `0`, id-returning ops yield the id).
pub(crate) type Job<C> = Box<dyn FnOnce(&mut C) -> Result<i64> + Send>;

/// A submitted mutation: the job, the channel its acknowledgment is returned on,
/// and the instant it was enqueued (so the coordinator can account for how long
/// the oldest member has already waited).
struct Envelope<C> {
    job: Job<C>,
    reply: Sender<Result<i64>>,
    enqueued: Instant,
}

/// How the per-mount coordinator decides how long to wait for a cohort to
/// assemble before taking the durability barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupCommitLinger {
    /// The historical behaviour: always wait [`FIXED_LINGER`] when a batch is not
    /// yet full, regardless of traffic. Retained only as the fixed arm of the
    /// adaptive court.
    Fixed,
    /// Deadline-aware: wait `min(t_batch_opportunity, latency_objective)`, where
    /// the opportunity is bounded by the barrier the wait would amortise and by
    /// the objective. The wait is taken only when contention is evident (a
    /// multi-member batch, a ready backlog, or an oldest member that has waited
    /// past the objective) or an arrival is expected inside the window; a full
    /// batch and a mount with no shared barrier commit immediately, and a
    /// strictly sequential writer is never delayed.
    #[default]
    Adaptive,
}

/// The blind linger the coordinator used before adaptive coalescing: a fixed
/// 300 µs wait for a cohort to assemble, whatever the traffic.
pub(crate) const FIXED_LINGER: Duration = Duration::from_micros(300);

/// The maximum extra latency the adaptive coordinator will add to a mutation in
/// order to coalesce it with a cohort (the latency objective). It bounds the
/// **linger only**, never a request's load-induced queueing delay.
pub(crate) const LATENCY_BUDGET: Duration = Duration::from_micros(250);

/// The bounded-admission capacity, in jobs, expressed as a multiple of the batch
/// limit. Two batches' worth of slack lets a full cohort be drained while the
/// next accumulates, without letting the queue grow without bound.
const QUEUE_SLACK: usize = 2;

/// How many recent arrivals feed the arrival-rate estimate.
const RATE_WINDOW: usize = 64;

/// EWMA weight applied to the newest barrier-cost sample.
const BARRIER_EWMA_ALPHA: f64 = 0.3;

/// Observable state that drives the coalescing decision. Every field is a plain
/// value, so [`coalesce_wait`] is a pure function and deterministically testable.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CoalesceInputs {
    /// Jobs already collected into the batch being assembled.
    pub batch_len: usize,
    /// The batch bound (`--group-commit-batch N`).
    pub limit: usize,
    /// Jobs already waiting in the bounded queue *right now* (a ready backlog).
    pub backlog: usize,
    /// Estimated arrival rate, in jobs/second (`0.0` when not yet known).
    pub arrival_rate: f64,
    /// Whether this mount issues a shared durability barrier at all (`sync`).
    /// `ordered`/`batched` mounts issue none, so there is nothing to amortise and
    /// the policy never waits for them.
    pub barrier_expected: bool,
    /// Predicted cost of the durability barrier, in seconds (`0` when the mount
    /// issues no shared barrier — `ordered`/`batched` — or none observed yet).
    pub barrier_cost: Duration,
    /// How long the oldest member of this batch has already waited. When this
    /// exceeds the objective it is used as evidence of persistent contention.
    pub oldest_wait: Duration,
    /// The latency objective (maximum extra wait the coordinator will add).
    pub budget: Duration,
}

/// The adaptive coalescing rule.
///
/// Returns how long the coordinator should keep accumulating before committing.
/// It is `Duration::ZERO` when accumulating cannot help at all:
///
/// * the batch is already full (`batch_len >= limit`);
/// * the mount issues no shared barrier (`!barrier_expected`), so there is
///   nothing to amortise (`ordered`/`batched`); or
/// * no contention is evident and no arrival is expected inside the window (the
///   sparse/sequential regime).
///
/// Otherwise the wait is the **opportunity window**
/// `t_batch_opportunity = min(barrier_cost, latency_objective)` — bounded by the
/// barrier the wait would amortise and by the objective — and it is taken only
/// when coalescing is actually worthwhile:
///
/// * **contention is evident** — the batch already holds more than one member, a
///   ready backlog exists, or the oldest member has already waited past the
///   objective (which proves a persistent queue) — so waiting the window builds a
///   larger batch and removes further barriers; or
/// * **a lone member so far** — wait the window only if another arrival is
///   expected inside it (`rate × window ≥ 1`), so a strictly sequential writer is
///   never delayed.
///
/// The wait is therefore `min(t_batch_opportunity, latency_objective)` whenever it
/// is taken, and never more.
///
/// **The objective bounds the *linger*, not the total latency.** A saturated mount
/// already imposes a large load-induced queueing delay on every request; if the
/// objective were spent by that delay, the rule would suppress coalescing exactly
/// when it pays most (which would then raise queueing further). The coordinator
/// therefore bounds only the extra latency *it* adds, and uses the oldest
/// member's wait as evidence of contention rather than as a budget to subtract.
///
/// **Conservative fallback.** While the predictor is still uncertain — no
/// arrival-rate estimate yet (fewer than two arrivals observed), or the barrier
/// has not been measured — the rule falls back to the historical fixed linger
/// ([`FIXED_LINGER`]), capped by the objective, so an as-yet-uncalibrated mount
/// coalesces exactly as it did before and the wait can never exceed the objective.
pub(crate) fn coalesce_wait(i: &CoalesceInputs) -> Duration {
    if i.batch_len >= i.limit {
        return Duration::ZERO;
    }
    if !i.barrier_expected {
        return Duration::ZERO;
    }
    let rate_known = i.arrival_rate.is_finite() && i.arrival_rate > 0.0;
    if !rate_known || i.barrier_cost.is_zero() {
        // The predictor is uncertain: behave like the historical fixed linger,
        // bounded by the latency objective.
        return FIXED_LINGER.min(i.budget);
    }
    // Bounded by the barrier the wait would amortise and by the objective.
    let window = i.barrier_cost.min(i.budget);
    let contended = i.batch_len >= 2 || i.backlog > 0 || i.oldest_wait > i.budget;
    let expected = i.arrival_rate * window.as_secs_f64() >= 1.0;
    if contended || expected {
        window
    } else {
        Duration::ZERO
    }
}

/// A snapshot of the coordinator's instrumentation, for `stats`, evidence and a
/// court. All counters are cumulative since the mount started except
/// `queue_depth` (the instant the snapshot was taken).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GroupCommitStats {
    /// The bounded-admission capacity (maximum waiting jobs).
    pub capacity: u64,
    /// The configured batch bound.
    pub batch_limit: u64,
    /// Submissions admitted to the coordinator.
    pub admissions: u64,
    /// Submissions refused admission and served on the direct path (overload).
    pub direct_fallbacks: u64,
    /// Batches executed.
    pub batches: u64,
    /// Shared durability barriers actually issued (a subset of `batches`; only
    /// `sync` mounts issue them, and only when a member succeeded).
    pub barriers: u64,
    /// Jobs executed through the coordinator.
    pub jobs_committed: u64,
    /// The largest batch observed.
    pub max_batch_size: u64,
    /// Batch-size distribution: `histogram[k]` is how many batches had size `k`
    /// (index 0 is unused; the length is `batch_limit + 1`).
    pub batch_size_histogram: Vec<u64>,
    /// Queue depth at the instant of the snapshot.
    pub queue_depth: u64,
    /// The largest queue depth observed (bounded by `capacity`).
    pub max_queue_depth: u64,
    /// Total time spent lingering for cohorts, in microseconds.
    pub linger_waited_us_total: u64,
    /// The longest single linger observed, in microseconds.
    pub linger_waited_us_max: u64,
    /// Mean measured barrier duration, in microseconds.
    pub mean_barrier_us: f64,
}

/// Lock-free counters shared between the worker thread and the mount.
pub(crate) struct GcCounters {
    limit: u64,
    capacity: u64,
    admissions: AtomicU64,
    direct_fallbacks: AtomicU64,
    batches: AtomicU64,
    barriers: AtomicU64,
    barrier_ns_sum: AtomicU64,
    jobs: AtomicU64,
    max_batch: AtomicU64,
    queue_depth: AtomicU64,
    max_queue_depth: AtomicU64,
    linger_ns_sum: AtomicU64,
    linger_ns_max: AtomicU64,
    batch_hist: Mutex<Vec<u64>>,
}

impl GcCounters {
    fn new(limit: usize, capacity: usize) -> Self {
        GcCounters {
            limit: limit as u64,
            capacity: capacity as u64,
            admissions: AtomicU64::new(0),
            direct_fallbacks: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            barriers: AtomicU64::new(0),
            barrier_ns_sum: AtomicU64::new(0),
            jobs: AtomicU64::new(0),
            max_batch: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
            max_queue_depth: AtomicU64::new(0),
            linger_ns_sum: AtomicU64::new(0),
            linger_ns_max: AtomicU64::new(0),
            batch_hist: Mutex::new(vec![0u64; limit + 1]),
        }
    }

    /// Count a submission attempt *before* the job is offered to the channel.
    /// Incrementing first (and rolling back on refusal, [`Self::record_fallback`])
    /// means a concurrent receive can never decrement below the true occupancy, so
    /// the depth cannot drift upward; it may transiently over-count by the number
    /// of submitters currently between this increment and their send, which is
    /// bounded by the number of concurrent callers.
    fn on_submit_attempt(&self) {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    /// The job was accepted by the channel.
    fn record_admission(&self) {
        self.admissions.fetch_add(1, Ordering::Relaxed);
        let depth = self.queue_depth.load(Ordering::Relaxed);
        self.max_queue_depth.fetch_max(depth, Ordering::Relaxed);
    }

    /// The job was refused (overload); roll its attempted admission back.
    fn record_fallback(&self) {
        self.direct_fallbacks.fetch_add(1, Ordering::Relaxed);
        self.decrement_depth();
    }

    // `fetch_update` is deprecated in favour of `try_update`, but `try_update` is
    // newer than this crate's MSRV, so the saturating decrement keeps it.
    #[allow(deprecated)]
    fn decrement_depth(&self) {
        let _ = self
            .queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |d| d.checked_sub(1));
    }

    fn on_receive(&self) {
        self.decrement_depth();
    }

    fn queue_depth(&self) -> usize {
        self.queue_depth.load(Ordering::Relaxed) as usize
    }

    fn record_batch(&self, size: u64, waited: Duration) {
        self.batches.fetch_add(1, Ordering::Relaxed);
        self.jobs.fetch_add(size, Ordering::Relaxed);
        self.max_batch.fetch_max(size, Ordering::Relaxed);
        let ns = waited.as_nanos() as u64;
        self.linger_ns_sum.fetch_add(ns, Ordering::Relaxed);
        self.linger_ns_max.fetch_max(ns, Ordering::Relaxed);
        if let Ok(mut hist) = self.batch_hist.lock() {
            if let Some(slot) = hist.get_mut(size as usize) {
                *slot += 1;
            }
        }
    }

    fn record_barrier(&self, issued: bool, dur: Duration) {
        if issued {
            self.barriers.fetch_add(1, Ordering::Relaxed);
            self.barrier_ns_sum
                .fetch_add(dur.as_nanos() as u64, Ordering::Relaxed);
        }
    }

    /// Take a consistent-enough snapshot for instrumentation and evidence.
    pub(crate) fn snapshot(&self) -> GroupCommitStats {
        let barriers = self.barriers.load(Ordering::Relaxed);
        let barrier_ns_sum = self.barrier_ns_sum.load(Ordering::Relaxed);
        GroupCommitStats {
            capacity: self.capacity,
            batch_limit: self.limit,
            admissions: self.admissions.load(Ordering::Relaxed),
            direct_fallbacks: self.direct_fallbacks.load(Ordering::Relaxed),
            batches: self.batches.load(Ordering::Relaxed),
            barriers,
            jobs_committed: self.jobs.load(Ordering::Relaxed),
            max_batch_size: self.max_batch.load(Ordering::Relaxed),
            batch_size_histogram: self
                .batch_hist
                .lock()
                .map(|h| h.clone())
                .unwrap_or_default(),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            max_queue_depth: self.max_queue_depth.load(Ordering::Relaxed),
            linger_waited_us_total: self.linger_ns_sum.load(Ordering::Relaxed) / 1000,
            linger_waited_us_max: self.linger_ns_max.load(Ordering::Relaxed) / 1000,
            mean_barrier_us: if barriers > 0 {
                barrier_ns_sum as f64 / barriers as f64 / 1000.0
            } else {
                0.0
            },
        }
    }
}

/// The per-mount group-commit coordinator. Cheap to clone through an `Arc`; it
/// holds the bounded submission channel and the shared counters.
pub(crate) struct BatchCoordinator<C: OrfsCore + Send + 'static> {
    tx: SyncSender<Envelope<C>>,
    counters: Arc<GcCounters>,
    /// Whether this mount issues a shared durability barrier at all (`sync`).
    /// `ordered`/`batched` mounts have no barrier to amortise, so a barrier
    /// submission is refused and the caller syncs directly.
    coalesces: bool,
}

impl<C: OrfsCore + Send + 'static> BatchCoordinator<C> {
    /// Start the coordinator for `inner`, draining at most `limit` jobs per
    /// batch with the given linger policy. The worker holds only a [`Weak`]
    /// handle, so the mount can drop normally: once the last strong `Arc<Inner>`
    /// goes away the worker exits.
    pub(crate) fn start(
        inner: &Arc<Inner<C>>,
        limit: usize,
        linger: GroupCommitLinger,
    ) -> Arc<Self> {
        let limit = limit.max(1);
        let capacity = (limit * QUEUE_SLACK).max(1);
        let (tx, rx) = sync_channel::<Envelope<C>>(capacity);
        let counters = Arc::new(GcCounters::new(limit, capacity));
        let worker_counters = Arc::clone(&counters);
        // Whether this mount issues a shared durability barrier. Read from the
        // core's authoritative mode here, while the core is still exclusively
        // owned (the worker has not started), so the coalescing policy knows
        // whether there is a barrier to amortise at all.
        let coalesces = inner.core.lock().durability() == DurabilityMode::Sync;
        let weak = Arc::downgrade(inner);
        let _ = std::thread::Builder::new()
            .name("orfs-group-commit".to_string())
            .spawn(move || run_loop(rx, weak, limit, worker_counters, linger, coalesces));
        Arc::new(BatchCoordinator {
            tx,
            counters,
            coalesces,
        })
    }

    /// Attempt a bounded admission. On success the caller waits on the returned
    /// receiver for its own durability-conditioned acknowledgment. On refusal the
    /// job is handed back **unchanged** so the caller can run it on the direct
    /// path — never silently dropped, never a false success.
    pub(crate) fn try_admit(
        &self,
        job: Job<C>,
    ) -> std::result::Result<Receiver<Result<i64>>, Job<C>> {
        let (reply_tx, reply_rx) = channel::<Result<i64>>();
        let envelope = Envelope {
            job,
            reply: reply_tx,
            enqueued: Instant::now(),
        };
        // Count the attempt before offering it, so a concurrent receive cannot be
        // clamped at zero and inflate the depth (see `on_submit_attempt`).
        self.counters.on_submit_attempt();
        match self.tx.try_send(envelope) {
            Ok(()) => {
                self.counters.record_admission();
                Ok(reply_rx)
            }
            Err(TrySendError::Full(env)) | Err(TrySendError::Disconnected(env)) => {
                self.counters.record_fallback();
                Err(env.job)
            }
        }
    }

    /// Submit a **durability barrier** into the current batch (Phase 88).
    ///
    /// This is the coalescing path for an explicit `fsync(2)`: the barrier is a
    /// batch member that performs no work of its own, so the batch executes it as
    /// a no-op and the batch's one shared `sync` (issued after every member,
    /// including this one) is what acknowledges it. Because the channel is FIFO
    /// and batches run in submission order, that barrier covers every mutation
    /// submitted before this call — so concurrently-arrived `fsync(2)` requests
    /// (and the writes they cover) share one barrier instead of each paying its
    /// own. Semantically identical to the direct `sync` on the refusal path.
    ///
    /// Returns `Err(())` when this mount has no shared barrier to amortise
    /// (`ordered`/`batched`) or the queue is full/closed, so the caller syncs
    /// directly under the core lock — never a false success, never a silent drop.
    pub(crate) fn try_admit_barrier(&self) -> std::result::Result<Receiver<Result<i64>>, ()> {
        if !self.coalesces {
            return Err(());
        }
        let (reply_tx, reply_rx) = channel::<Result<i64>>();
        let envelope = Envelope {
            job: Box::new(|_core: &mut C| Ok(0)),
            reply: reply_tx,
            enqueued: Instant::now(),
        };
        self.counters.on_submit_attempt();
        match self.tx.try_send(envelope) {
            Ok(()) => {
                self.counters.record_admission();
                Ok(reply_rx)
            }
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.counters.record_fallback();
                Err(())
            }
        }
    }

    /// The shared instrumentation cell (so the mount can expose it).
    pub(crate) fn counters(&self) -> Arc<GcCounters> {
        Arc::clone(&self.counters)
    }

    /// A snapshot of the instrumentation (used by the coordinator's own court).
    #[cfg(test)]
    pub(crate) fn stats(&self) -> GroupCommitStats {
        self.counters.snapshot()
    }

    /// Construct a worker-less coordinator for tests of the bounded-admission
    /// policy (the receiver is leaked so senders never observe a disconnection).
    #[cfg(test)]
    fn for_test(limit: usize, capacity: usize) -> Self {
        let (tx, rx) = sync_channel::<Envelope<C>>(capacity);
        std::mem::forget(rx);
        BatchCoordinator {
            tx,
            counters: Arc::new(GcCounters::new(limit, capacity)),
            coalesces: true,
        }
    }
}

/// A windowed arrival-rate estimate: `(n-1) / span` over the last
/// [`RATE_WINDOW`] arrivals, using the instants the jobs were enqueued.
struct ArrivalRate {
    window: VecDeque<Instant>,
}

impl ArrivalRate {
    fn new() -> Self {
        ArrivalRate {
            window: VecDeque::with_capacity(RATE_WINDOW),
        }
    }

    fn observe(&mut self, at: Instant) {
        if self.window.len() >= RATE_WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(at);
    }

    fn rate(&self) -> f64 {
        let n = self.window.len();
        if n < 2 {
            return 0.0;
        }
        let first = *self.window.front().expect("non-empty window");
        let last = *self.window.back().expect("non-empty window");
        let span = last.saturating_duration_since(first).as_secs_f64();
        if span <= 0.0 {
            return 0.0;
        }
        (n - 1) as f64 / span
    }
}

fn ewma(old: Duration, new: Duration) -> Duration {
    let o = old.as_secs_f64();
    let n = new.as_secs_f64();
    Duration::from_secs_f64((o + BARRIER_EWMA_ALPHA * (n - o)).max(0.0))
}

fn run_loop<C: OrfsCore + Send + 'static>(
    rx: Receiver<Envelope<C>>,
    weak: Weak<Inner<C>>,
    limit: usize,
    counters: Arc<GcCounters>,
    linger: GroupCommitLinger,
    coalesces: bool,
) {
    let mut arrivals = ArrivalRate::new();
    let mut barrier_cost = Duration::ZERO;
    loop {
        let first = match rx.recv() {
            Ok(v) => v,
            Err(_) => break, // every sender dropped: mount is gone.
        };
        counters.on_receive();
        arrivals.observe(first.enqueued);
        let mut batch = Vec::with_capacity(limit);
        batch.push(first);
        // Non-blocking drain: take everything already waiting, up to the limit.
        // This is what lets concurrently-submitted mutations share one barrier.
        while batch.len() < limit {
            match rx.try_recv() {
                Ok(v) => {
                    counters.on_receive();
                    arrivals.observe(v.enqueued);
                    batch.push(v);
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
        // Decide how long (if at all) to wait for a cohort to join this batch.
        let oldest_wait = batch[0].enqueued.elapsed();
        let t_wait = match linger {
            GroupCommitLinger::Fixed => FIXED_LINGER,
            GroupCommitLinger::Adaptive => coalesce_wait(&CoalesceInputs {
                batch_len: batch.len(),
                limit,
                backlog: counters.queue_depth(),
                arrival_rate: arrivals.rate(),
                barrier_expected: coalesces,
                barrier_cost,
                oldest_wait,
                budget: LATENCY_BUDGET,
            }),
        };
        let waited = wait_for_cohort(&rx, &mut batch, limit, t_wait, &counters, &mut arrivals);
        counters.record_batch(batch.len() as u64, waited);

        let Some(inner) = weak.upgrade() else {
            break;
        };
        let mut core = inner.core.lock();
        let measured = execute_batch(&mut *core, batch, &counters);
        drop(core);
        if !measured.is_zero() {
            barrier_cost = if barrier_cost.is_zero() {
                measured
            } else {
                ewma(barrier_cost, measured)
            };
        }
    }
}

/// Accumulate jobs for up to `t_wait`, returning the time actually spent waiting.
fn wait_for_cohort<C: OrfsCore + Send + 'static>(
    rx: &Receiver<Envelope<C>>,
    batch: &mut Vec<Envelope<C>>,
    limit: usize,
    t_wait: Duration,
    counters: &GcCounters,
    arrivals: &mut ArrivalRate,
) -> Duration {
    if t_wait.is_zero() {
        return Duration::ZERO;
    }
    let start = Instant::now();
    let deadline = start + t_wait;
    while batch.len() < limit {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok(v) => {
                counters.on_receive();
                arrivals.observe(v.enqueued);
                batch.push(v);
            }
            Err(_) => break,
        }
    }
    start.elapsed()
}

/// Run one batch against the core: sequential execution (order/atomicity
/// preserved) with the durability barrier coalesced for `sync` mounts. Returns
/// the measured barrier duration (zero when no barrier was issued).
fn execute_batch<C: OrfsCore>(
    core: &mut C,
    batch: Vec<Envelope<C>>,
    counters: &GcCounters,
) -> Duration {
    let mode = core.durability();
    let coalesce = mode == DurabilityMode::Sync;
    if coalesce {
        core.set_durability(DurabilityMode::Ordered);
    }
    let mut results: Vec<(Result<i64>, Sender<Result<i64>>)> = Vec::with_capacity(batch.len());
    for env in batch {
        let r = (env.job)(core);
        results.push((r, env.reply));
    }
    if coalesce {
        core.set_durability(mode);
    }
    // One shared barrier, issued only after every member's bytes are written and
    // only if some member succeeded; only then is any caller acknowledged.
    let any_ok = results.iter().any(|(r, _)| r.is_ok());
    if !(coalesce && any_ok) {
        counters.record_barrier(false, Duration::ZERO);
        for (r, reply) in results {
            let _ = reply.send(ack_outcome(r, true));
        }
        return Duration::ZERO;
    }
    let t = Instant::now();
    let ok = core.sync().is_ok();
    let elapsed = t.elapsed();
    counters.record_barrier(true, elapsed);
    for (r, reply) in results {
        let _ = reply.send(ack_outcome(r, ok));
    }
    elapsed
}

/// The acknowledgment rule (I7): a caller is acknowledged only once a durable
/// operation covering *its own* bytes has completed. A mutation whose bytes were
/// published but whose covering barrier failed is reported as `EIO`, never
/// success; a mutation that failed on its own reports its own error.
fn ack_outcome(r: Result<i64>, barrier_ok: bool) -> Result<i64> {
    match (r, barrier_ok) {
        (Ok(v), true) => Ok(v),
        (Ok(_), false) => Err(OrfsError::Io(io::Error::from_raw_os_error(libc::EIO))),
        (Err(e), _) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode::InodeStat;
    use crate::namespace::{ReadCell, RenameMode, SetAttr};

    fn inputs(
        batch_len: usize,
        backlog: usize,
        arrival_rate: f64,
        barrier_cost: Duration,
        oldest_wait: Duration,
    ) -> CoalesceInputs {
        CoalesceInputs {
            batch_len,
            limit: 64,
            backlog,
            arrival_rate,
            barrier_expected: true,
            barrier_cost,
            oldest_wait,
            budget: LATENCY_BUDGET,
        }
    }

    #[test]
    fn coalesce_never_waits_for_a_full_batch() {
        let i = inputs(64, 0, 10_000.0, Duration::from_millis(3), Duration::ZERO);
        assert_eq!(coalesce_wait(&i), Duration::ZERO);
    }

    #[test]
    fn coalesce_waits_when_a_backlog_exists() {
        // A ready backlog is evidence of concurrency: waiting the window builds a
        // larger batch (fewer barriers), bounded by the objective.
        let i = inputs(1, 3, 10_000.0, Duration::from_millis(3), Duration::ZERO);
        assert_eq!(coalesce_wait(&i), LATENCY_BUDGET);
    }

    #[test]
    fn coalesce_never_waits_when_sparse() {
        // ~333 submissions/s against a 3 ms barrier: fewer than one arrival is
        // expected inside the 250 µs window, so waiting cannot coalesce anything.
        let i = inputs(1, 0, 333.0, Duration::from_millis(3), Duration::ZERO);
        assert_eq!(coalesce_wait(&i), Duration::ZERO);
    }

    #[test]
    fn coalesce_does_not_delay_a_sequential_writer() {
        // A strictly sequential writer (~143 sync commits/s) presents a lone
        // member with no backlog and no expected arrival in the window: no wait.
        let i = inputs(1, 0, 143.0, Duration::from_millis(3), Duration::ZERO);
        assert_eq!(coalesce_wait(&i), Duration::ZERO);
    }

    #[test]
    fn coalesce_waits_the_window_when_concurrency_is_evident() {
        // A second member already proves concurrency even at a low arrival rate.
        let i = inputs(2, 0, 143.0, Duration::from_millis(3), Duration::ZERO);
        assert_eq!(coalesce_wait(&i), LATENCY_BUDGET);
    }

    #[test]
    fn coalesce_never_waits_for_a_mount_without_a_shared_barrier() {
        // ordered/batched mounts issue no shared barrier: nothing to amortise, so
        // even dense traffic must not be delayed.
        let mut i = inputs(1, 0, 1_000_000.0, Duration::from_micros(20), Duration::ZERO);
        i.barrier_expected = false;
        assert_eq!(coalesce_wait(&i), Duration::ZERO);
    }

    #[test]
    fn coalesce_falls_back_to_a_bounded_linger_when_the_rate_is_unknown() {
        // Warm-up (fewer than two arrivals): the predictor is uncertain, so the
        // rule behaves like the historical fixed linger, capped by the objective.
        let i = inputs(1, 0, 0.0, Duration::from_millis(3), Duration::ZERO);
        assert_eq!(coalesce_wait(&i), LATENCY_BUDGET);
    }

    #[test]
    fn coalesce_falls_back_to_a_bounded_linger_before_the_barrier_is_measured() {
        // Sync mount with a known arrival rate but no barrier measured yet.
        let i = inputs(1, 0, 8_000.0, Duration::ZERO, Duration::ZERO);
        assert_eq!(coalesce_wait(&i), LATENCY_BUDGET);
    }

    #[test]
    fn coalesce_fallback_is_capped_by_the_objective() {
        // The conservative fallback never exceeds the latency objective.
        let i = inputs(2, 0, 0.0, Duration::from_millis(3), Duration::ZERO);
        assert_eq!(coalesce_wait(&i), LATENCY_BUDGET);
    }

    #[test]
    fn coalesce_waits_the_window_when_an_arrival_is_expected() {
        // 8 000 submissions/s: two arrivals are expected inside the 250 µs window
        // (which the 3 ms barrier does not shorten), so the window is taken.
        let i = inputs(1, 0, 8_000.0, Duration::from_millis(3), Duration::ZERO);
        assert_eq!(coalesce_wait(&i), LATENCY_BUDGET);
    }

    #[test]
    fn coalesce_window_is_capped_by_the_objective() {
        // A 3 ms barrier with a 250 µs objective and contention present: the
        // objective, not the barrier, caps the window.
        let i = inputs(2, 0, 5_000.0, Duration::from_millis(3), Duration::ZERO);
        assert_eq!(coalesce_wait(&i), LATENCY_BUDGET);
    }

    #[test]
    fn coalesce_is_capped_by_the_barrier_cost() {
        // Very dense traffic against a tiny barrier: waiting longer than the
        // barrier that would be saved is pointless, so the barrier caps the wait.
        for rate in [1_000_000.0, 5_000_000.0, 50_000_000.0] {
            let i = inputs(1, 0, rate, Duration::from_micros(20), Duration::ZERO);
            assert!(
                coalesce_wait(&i) <= Duration::from_micros(20),
                "barrier cap violated at rate {rate}"
            );
        }
    }

    #[test]
    fn coalesce_never_exceeds_the_budget() {
        for rate in [1_000.0, 10_000.0, 1_000_000.0] {
            let i = inputs(1, 0, rate, Duration::from_millis(9), Duration::ZERO);
            assert!(coalesce_wait(&i) <= LATENCY_BUDGET);
        }
    }

    #[test]
    fn coalesce_waits_when_the_oldest_member_proves_contention() {
        // A lone member whose oldest wait already exceeds the objective proves a
        // persistent queue, so the coordinator invests its bounded window.
        let i = inputs(
            1,
            0,
            143.0,
            Duration::from_millis(3),
            LATENCY_BUDGET + Duration::from_micros(1),
        );
        assert_eq!(coalesce_wait(&i), LATENCY_BUDGET);
    }

    // -- Bounded admission ---------------------------------------------------

    #[test]
    fn admission_is_refused_once_the_queue_is_full() {
        let coord = BatchCoordinator::<crate::namespace::Namespace>::for_test(4, 3);
        assert!(coord.try_admit(Box::new(|_c: &mut _| Ok(0))).is_ok());
        assert!(coord.try_admit(Box::new(|_c: &mut _| Ok(0))).is_ok());
        assert!(coord.try_admit(Box::new(|_c: &mut _| Ok(0))).is_ok());
        // The fourth submission finds the queue full and is handed back.
        assert!(coord.try_admit(Box::new(|_c: &mut _| Ok(0))).is_err());
        let s = coord.stats();
        assert_eq!(s.admissions, 3);
        assert_eq!(s.direct_fallbacks, 1);
        // The refused attempt briefly counts one over capacity before it is rolled
        // back, so the high-water mark is the attempt, not the buffered occupancy.
        assert!(s.max_queue_depth <= s.capacity + 1);
        assert_eq!(s.capacity, 3);
    }

    #[test]
    fn a_refused_job_is_handed_back_intact_for_the_direct_path() {
        let coord = BatchCoordinator::<MockCore>::for_test(1, 1);
        assert!(coord.try_admit(Box::new(|_c: &mut MockCore| Ok(1))).is_ok());
        // The second submission finds the one-slot queue full.
        let refused = coord
            .try_admit(Box::new(|_c: &mut MockCore| Ok(42)))
            .expect_err("the queue is full");
        // The job is returned unchanged and can be served on the direct path
        // (never dropped, never a false success).
        let mut core = MockCore::new(true, Arc::new(Mutex::new(Vec::new())));
        assert_eq!(refused(&mut core).unwrap(), 42);
        let s = coord.stats();
        assert_eq!(s.admissions, 1);
        assert_eq!(s.direct_fallbacks, 1);
        assert!(s.max_queue_depth <= s.capacity);
    }

    // -- Acknowledgment / ordering under an injected barrier failure ---------

    /// A minimal core: only the three methods the coordinator's batch path uses
    /// are real; the rest are placeholders (never reached).
    struct MockCore {
        mode: DurabilityMode,
        sync_ok: bool,
        syncs: Vec<DurabilityMode>,
        _log: Arc<Mutex<Vec<i64>>>,
    }

    impl MockCore {
        fn new(sync_ok: bool, log: Arc<Mutex<Vec<i64>>>) -> Self {
            MockCore {
                mode: DurabilityMode::Sync,
                sync_ok,
                syncs: Vec::new(),
                _log: log,
            }
        }
    }

    impl OrfsCore for MockCore {
        fn durability(&self) -> DurabilityMode {
            self.mode
        }
        fn set_durability(&mut self, mode: DurabilityMode) {
            self.mode = mode;
        }
        fn sync(&mut self) -> Result<()> {
            self.syncs.push(self.mode);
            if self.sync_ok {
                Ok(())
            } else {
                Err(OrfsError::Io(io::Error::from_raw_os_error(libc::EIO)))
            }
        }
        fn root(&self) -> u64 {
            unimplemented!()
        }
        fn parent_of(&self, _inode: u64) -> Option<u64> {
            unimplemented!()
        }
        fn lookup(&self, _parent: u64, _name: &[u8], _root: u64) -> Result<u64> {
            unimplemented!()
        }
        fn getattr(&self, _inode: u64, _root: u64) -> Result<InodeStat> {
            unimplemented!()
        }
        fn setattr(&mut self, _inode: u64, _attrs: &SetAttr) -> Result<()> {
            unimplemented!()
        }
        fn read_at(&self, _inode: u64, _root: u64, _offset: u64, _length: u32) -> Result<Vec<u8>> {
            unimplemented!()
        }
        fn write_at(&mut self, _inode: u64, _offset: u64, _data: &[u8]) -> Result<u32> {
            unimplemented!()
        }
        fn write_at_killpriv(
            &mut self,
            _inode: u64,
            _offset: u64,
            _data: &[u8],
            _kill_setid: bool,
        ) -> Result<u32> {
            unimplemented!()
        }
        fn zero_range(&mut self, _inode: u64, _offset: u64, _len: u64) -> Result<()> {
            unimplemented!()
        }
        fn seek_data_hole(
            &self,
            _inode: u64,
            _root: u64,
            _offset: u64,
            _hole: bool,
        ) -> Result<Option<u64>> {
            unimplemented!()
        }
        fn create(
            &mut self,
            _parent: u64,
            _name: &[u8],
            _mode: u32,
            _uid: u32,
            _gid: u32,
        ) -> Result<u64> {
            unimplemented!()
        }
        fn mkdir(
            &mut self,
            _parent: u64,
            _name: &[u8],
            _mode: u32,
            _uid: u32,
            _gid: u32,
        ) -> Result<u64> {
            unimplemented!()
        }
        fn unlink(&mut self, _parent: u64, _name: &[u8]) -> Result<()> {
            unimplemented!()
        }
        fn rmdir(&mut self, _parent: u64, _name: &[u8]) -> Result<()> {
            unimplemented!()
        }
        fn rename(
            &mut self,
            _old_parent: u64,
            _old_name: &[u8],
            _new_parent: u64,
            _new_name: &[u8],
            _mode: RenameMode,
        ) -> Result<()> {
            unimplemented!()
        }
        fn link(&mut self, _inode: u64, _new_parent: u64, _new_name: &[u8]) -> Result<()> {
            unimplemented!()
        }
        fn symlink(
            &mut self,
            _parent: u64,
            _name: &[u8],
            _target: &[u8],
            _uid: u32,
            _gid: u32,
        ) -> Result<u64> {
            unimplemented!()
        }
        fn readlink(&self, _inode: u64, _root: u64) -> Result<Vec<u8>> {
            unimplemented!()
        }
        fn getxattr(&self, _inode: u64, _name: &[u8], _root: u64) -> Result<Vec<u8>> {
            unimplemented!()
        }
        fn setxattr(
            &mut self,
            _inode: u64,
            _name: &[u8],
            _value: &[u8],
            _create: bool,
        ) -> Result<()> {
            unimplemented!()
        }
        fn listxattr(&self, _inode: u64, _root: u64) -> Result<Vec<Vec<u8>>> {
            unimplemented!()
        }
        fn removexattr(&mut self, _inode: u64, _name: &[u8]) -> Result<()> {
            unimplemented!()
        }
        fn readdir(&self, _parent: u64, _root: u64) -> Result<Vec<(Vec<u8>, u64)>> {
            unimplemented!()
        }
        fn read_view_cell(&self) -> ReadCell {
            unimplemented!()
        }
    }

    fn envelope<C>(
        job: impl FnOnce(&mut C) -> Result<i64> + Send + 'static,
    ) -> (Envelope<C>, Receiver<Result<i64>>) {
        let (tx, rx) = channel();
        (
            Envelope {
                job: Box::new(job),
                reply: tx,
                enqueued: Instant::now(),
            },
            rx,
        )
    }

    #[test]
    fn batch_runs_in_submission_order_sequentially() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut core = MockCore::new(true, Arc::clone(&log));
        let counters = GcCounters::new(8, 16);
        let mut batch = Vec::new();
        let mut replies = Vec::new();
        for id in [10i64, 20, 30, 40] {
            let log2 = Arc::clone(&log);
            let (env, rx) = envelope::<MockCore>(move |_c| {
                log2.lock().unwrap().push(id);
                Ok(id)
            });
            batch.push(env);
            replies.push(rx);
        }
        let barrier = execute_batch(&mut core, batch, &counters);
        assert!(!barrier.is_zero(), "a sync batch issues one barrier");
        assert_eq!(*log.lock().unwrap(), vec![10, 20, 30, 40]);
        for (i, rx) in replies.into_iter().enumerate() {
            assert_eq!(
                rx.recv().unwrap().unwrap(),
                *(log.lock().unwrap()).get(i).unwrap()
            );
        }
        let s = counters.snapshot();
        assert_eq!(s.batches, 0, "record_batch is done by the worker loop");
        assert_eq!(s.barriers, 1);
        assert!(s.mean_barrier_us > 0.0);
    }

    #[test]
    fn barrier_failure_yields_eio_for_every_successful_member() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut core = MockCore::new(false, Arc::clone(&log));
        let counters = GcCounters::new(8, 16);
        let mut batch = Vec::new();
        let mut replies = Vec::new();
        for id in [1i64, 2, 3] {
            let (env, rx) = envelope::<MockCore>(move |_c| Ok(id));
            batch.push(env);
            replies.push(rx);
        }
        execute_batch(&mut core, batch, &counters);
        for rx in replies {
            let out = rx.recv().unwrap();
            match out {
                Err(OrfsError::Io(e)) => {
                    assert_eq!(
                        e.raw_os_error(),
                        Some(libc::EIO),
                        "must be EIO, not success"
                    )
                }
                other => panic!("published-but-unsynced member was acked: {other:?}"),
            }
        }
        assert_eq!(core.syncs, vec![DurabilityMode::Sync]);
        assert_eq!(counters.snapshot().barriers, 1);
    }

    #[test]
    fn a_job_error_propagates_while_others_still_get_the_barrier_verdict() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut core = MockCore::new(false, Arc::clone(&log));
        let counters = GcCounters::new(8, 16);
        let mut batch = Vec::new();
        let mut replies = Vec::new();
        let (ok_env, ok_rx) = envelope::<MockCore>(|_c| Ok(7));
        let (bad_env, bad_rx) = envelope::<MockCore>(|_c| Err(OrfsError::NotFound));
        batch.push(ok_env);
        batch.push(bad_env);
        replies.push(ok_rx);
        replies.push(bad_rx);
        execute_batch(&mut core, batch, &counters);
        // The successful member's bytes were published but the covering barrier
        // failed: it must see EIO (not success).
        match replies[0].recv().unwrap() {
            Err(OrfsError::Io(e)) => assert_eq!(e.raw_os_error(), Some(libc::EIO)),
            other => panic!("expected EIO, got {other:?}"),
        }
        // The failed member reports its own error.
        assert!(matches!(
            replies[1].recv().unwrap(),
            Err(OrfsError::NotFound)
        ));
    }

    #[test]
    fn ordered_mount_issues_no_barrier() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut core = MockCore::new(true, Arc::clone(&log));
        core.mode = DurabilityMode::Ordered;
        let counters = GcCounters::new(8, 16);
        let (env, rx) = envelope::<MockCore>(|_c| Ok(1));
        let barrier = execute_batch(&mut core, vec![env], &counters);
        assert!(barrier.is_zero());
        assert!(rx.recv().unwrap().is_ok());
        assert!(core.syncs.is_empty());
        assert_eq!(counters.snapshot().barriers, 0);
    }
}
