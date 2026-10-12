//! End-to-end group-commit coordinator through the transports (Phase 32).
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
//!   directly. A background thread drains a bounded batch of concurrently-arrived
//!   jobs and runs them **sequentially**, in submission order, against the core —
//!   so authoritative order, per-transaction atomicity and the existing `Plan`
//!   offset prediction are all preserved untouched.
//! * For a `sync` mount the batch runs with the durability temporarily lowered to
//!   `ordered` (so no per-job `fsync`), then a **single** `fsync` covers the whole
//!   batch before any caller is acknowledged. Each caller is acknowledged only
//!   after that barrier, so the `sync` contract (I7) is fully preserved; the
//!   expensive barrier is amortised exactly as the review (§6) describes.
//! * For `ordered`/`batched` mounts the jobs run with their normal durability and
//!   no extra barrier is added — no semantic change and no fabricated win.

use std::io;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use crate::commit::DurabilityMode;
use crate::error::{OrfsError, Result};
use crate::fuse::Inner;
use crate::namespace::OrfsCore;

/// A single mutation to run against the core, yielding an `i64` (unit ops yield
/// `0`, id-returning ops yield the id).
pub(crate) type Job<C> = Box<dyn FnOnce(&mut C) -> Result<i64> + Send>;

type Envelope<C> = (Job<C>, Sender<Result<i64>>);

/// The per-mount group-commit coordinator. Cheap to clone through an `Arc`; it
/// holds only the submission channel.
pub(crate) struct BatchCoordinator<C: OrfsCore + Send + 'static> {
    tx: Sender<Envelope<C>>,
}

impl<C: OrfsCore + Send + 'static> BatchCoordinator<C> {
    /// Start the coordinator for `inner`, draining at most `limit` jobs per
    /// batch. The worker holds only a [`Weak`] handle, so the mount can drop
    /// normally: once the last strong `Arc<Inner>` goes away the worker exits.
    pub(crate) fn start(inner: &Arc<Inner<C>>, limit: usize) -> Arc<Self> {
        let limit = limit.max(1);
        let (tx, rx) = channel::<Envelope<C>>();
        let weak = Arc::downgrade(inner);
        let _ = std::thread::Builder::new()
            .name("orfs-group-commit".to_string())
            .spawn(move || run_loop(rx, weak, limit));
        Arc::new(BatchCoordinator { tx })
    }

    /// Submit a job and block until its batch has been committed and its
    /// durability condition satisfied.
    pub(crate) fn submit(&self, job: Job<C>) -> Result<i64> {
        let (reply_tx, reply_rx) = channel::<Result<i64>>();
        self.tx.send((job, reply_tx)).map_err(|_| {
            OrfsError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "group-commit coordinator is not running",
            ))
        })?;
        reply_rx.recv().map_err(|_| {
            OrfsError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "group-commit reply dropped",
            ))
        })?
    }
}

fn run_loop<C: OrfsCore + Send + 'static>(
    rx: Receiver<Envelope<C>>,
    weak: Weak<Inner<C>>,
    limit: usize,
) {
    loop {
        let first = match rx.recv() {
            Ok(v) => v,
            Err(_) => break, // every sender dropped: mount is gone.
        };
        let mut batch = Vec::with_capacity(limit);
        batch.push(first);
        // Drain whatever else has already arrived, up to the batch limit. This
        // is what lets concurrently-submitted mutations share one barrier.
        while batch.len() < limit {
            match rx.try_recv() {
                Ok(v) => batch.push(v),
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
        // Bounded linger: give concurrent submissions a brief window to join this
        // batch before we take the durability barrier. Without it a leader that
        // grabs the barrier the instant it sees one job pays a full `fsync` for a
        // batch of one. The wait is bounded (never unbounded latency), and the
        // barrier it saves costs far more than the linger.
        const LINGER: Duration = Duration::from_micros(300);
        let deadline = Instant::now() + LINGER;
        while batch.len() < limit {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            match rx.recv_timeout(deadline - now) {
                Ok(v) => batch.push(v),
                Err(_) => break,
            }
        }
        let Some(inner) = weak.upgrade() else {
            break;
        };
        execute_batch(&inner, batch);
    }
}

/// Run one batch: sequential execution (order/atomicity preserved) with the
/// durability barrier coalesced for `sync` mounts.
fn execute_batch<C: OrfsCore + Send + 'static>(inner: &Arc<Inner<C>>, batch: Vec<Envelope<C>>) {
    let mut core = inner.core.lock();
    let mode = core.durability();
    let coalesce = mode == DurabilityMode::Sync;
    if coalesce {
        core.set_durability(DurabilityMode::Ordered);
    }
    let mut results: Vec<(Result<i64>, Sender<Result<i64>>)> = Vec::with_capacity(batch.len());
    for (job, reply) in batch {
        let r = job(&mut core);
        results.push((r, reply));
    }
    if coalesce {
        core.set_durability(mode);
    }
    // One shared barrier, issued only after every member's bytes are written;
    // only then is any caller acknowledged.
    let any_ok = results.iter().any(|(r, _)| r.is_ok());
    let sync_ok = if coalesce && any_ok {
        core.sync().is_ok()
    } else {
        true
    };
    drop(core);

    for (r, reply) in results {
        let out = match (r, sync_ok) {
            (Ok(v), true) => Ok(v),
            // The batch's data was published but the covering barrier failed: the
            // caller must NOT be told it succeeded (I7).
            (Ok(_), false) => Err(OrfsError::Io(io::Error::from_raw_os_error(libc::EIO))),
            (Err(e), _) => Err(e),
        };
        let _ = reply.send(out);
    }
}
