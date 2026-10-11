//! Registered-buffer / buffer-pool management with strict lifetime tracking
//! (research §20, Ring W; the Phase 5 directive's buffer-lifetime rule).
//!
//! `io_uring` performs I/O *asynchronously*: the kernel may read from — or write
//! into — a buffer after the submission call has returned, and it may keep
//! accessing it until the corresponding completion is posted. A buffer must
//! therefore remain allocated, at a stable address, and untouched by anyone else
//! for the whole time an operation can still reference it. Cancellation is **not**
//! proof that a buffer is immediately safe to release: a canceled request may
//! still be observed by the kernel after the cancel is issued.
//!
//! This module makes that lifetime rule explicit and machine-checked:
//!
//! * [`BufferPool`] owns a fixed set of page-aligned buffers. Each buffer may be
//!   *pinned* by exactly one [`Pin`] at a time.
//! * A [`Pin`] borrows the pool, so the pool **cannot be dropped** while any pin
//!   exists (the borrow checker enforces this — no runtime check can be skipped).
//! * A pin tracks an *operation count*: [`Pin::begin_op`] increments the pool's
//!   in-flight count and returns an [`OpId`]; [`Pin::end_op`] releases it. The
//!   buffer is thus "pinned while schedulable or in-flight".
//! * [`BufferPool::try_release`] refuses to release while any buffer is pinned or
//!   in flight, so an explicit release can never race a completion.
//!
//! # Safety invariants
//!
//! 1. An [`AlignedBuffer`] is exclusively owned; its address never changes for
//!    the buffer's whole lifetime (the allocation is never reallocated or moved).
//! 2. A buffer referenced by a submitted operation is kept pinned until *after*
//!    its completion has been collected (the engine's synchronous submit-and-wait
//!    guarantees this; see `crate::uring`). Cancellation drains completions before
//!    the pin is released.
//! 3. Buffers are page-aligned and zero-initialised, which satisfies
//!    `io_uring_register_buffers` alignment expectations when the engine chooses
//!    to register them.

use std::alloc::{alloc_zeroed, dealloc, handle_alloc_error, Layout};
use std::cell::{Cell, RefCell, RefMut};

/// Default page alignment for pooled buffers.
pub const DEFAULT_ALIGN: usize = 4096;

/// A unique operation identity allocated by a [`Pin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpId(pub u64);

/// Why a pool refused to be released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseError {
    /// One or more buffers are still pinned.
    #[error("{0} buffer(s) still pinned")]
    Pinned(usize),
    /// One or more pinned buffers still have operations in flight.
    #[error("{0} operation(s) still in flight")]
    InFlight(usize),
}

/// An owned, page-aligned, zero-initialised byte buffer at a stable address.
///
/// # Safety
///
/// The pointer is produced by a single `alloc_zeroed` and freed exactly once, in
/// [`Drop`]. `len` and `layout` are consistent for the whole lifetime, so the
/// slice accessors are sound. The type is `Send` because ownership (and hence
/// the exclusive right to touch the buffer) can be transferred between threads;
/// it is not `Sync`.
pub struct AlignedBuffer {
    ptr: *mut u8,
    len: usize,
    layout: Layout,
}

// SAFETY: `AlignedBuffer` owns its allocation outright. Sending it transfers that
// exclusive ownership; no thread retains a reference to the old location, and the
// buffer is only ever accessed through `&self`/`&mut self`. `*mut u8` is otherwise
// `!Send` only because raw pointers may alias across threads, which cannot happen
// here.
unsafe impl Send for AlignedBuffer {}

impl AlignedBuffer {
    /// Allocate a zeroed buffer of `len` bytes aligned to `align` (a power of two).
    pub fn new(len: usize, align: usize) -> AlignedBuffer {
        assert!(len > 0, "buffer length must be non-zero");
        assert!(align.is_power_of_two(), "alignment must be a power of two");
        let layout = Layout::from_size_align(len, align).expect("valid buffer layout");
        // SAFETY: `len > 0`, so the layout has non-zero size; the returned pointer
        // is checked for null and the layout is retained for a matching `dealloc`.
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            handle_alloc_error(layout);
        }
        AlignedBuffer { ptr, len, layout }
    }

    /// The buffer length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the buffer is empty (never true for pooled buffers).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// A shared view of the buffer.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is valid for `len` bytes for `self`'s lifetime and is not
        // aliased mutably while `&self` is held.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// A mutable view of the buffer. Requires `&mut self`, so no other view exists.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, and `&mut self` guarantees exclusivity.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// The base address of the allocation.
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`layout` came from `alloc_zeroed` with this exact layout,
        // and `Drop` runs at most once.
        unsafe { dealloc(self.ptr, self.layout) }
    }
}

/// One pool slot: the buffer plus its pin state.
struct Slot {
    buf: RefCell<AlignedBuffer>,
    in_use: Cell<bool>,
    /// The buffer's `iovec`, captured once at construction. Because the
    /// allocation address is stable, this stays valid for the pool's lifetime
    /// and lets [`BufferPool::iovecs`] avoid borrowing a pinned buffer.
    iov: libc::iovec,
}

/// A fixed pool of page-aligned buffers with strict pin / in-flight tracking.
pub struct BufferPool {
    slots: Vec<Slot>,
    buffer_size: usize,
    align: usize,
    pinned: Cell<usize>,
    in_flight: Cell<usize>,
    next_op: Cell<u64>,
}

// SAFETY: the pool owns every buffer outright. The `iovec` fields are raw
// pointers into those same allocations; moving the pool between threads moves
// that exclusive ownership with it, and no thread retains a reference to the old
// location. Nothing in the pool aliases memory it does not own.
unsafe impl Send for BufferPool {}

impl BufferPool {
    /// Create a pool of `count` buffers, each `buffer_size` bytes, page-aligned.
    pub fn new(count: usize, buffer_size: usize) -> BufferPool {
        Self::with_align(count, buffer_size, DEFAULT_ALIGN)
    }

    /// Create a pool with an explicit alignment.
    pub fn with_align(count: usize, buffer_size: usize, align: usize) -> BufferPool {
        assert!(count > 0, "pool must contain at least one buffer");
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            let buf = AlignedBuffer::new(buffer_size, align);
            let iov = libc::iovec {
                iov_base: buf.as_ptr().cast(),
                iov_len: buf.len(),
            };
            slots.push(Slot {
                buf: RefCell::new(buf),
                in_use: Cell::new(false),
                iov,
            });
        }
        BufferPool {
            slots,
            buffer_size,
            align,
            pinned: Cell::new(0),
            in_flight: Cell::new(0),
            next_op: Cell::new(0),
        }
    }

    /// Number of buffers in the pool.
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Size of each buffer in bytes.
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Alignment of each buffer in bytes.
    pub fn align(&self) -> usize {
        self.align
    }

    /// Number of buffers currently pinned.
    pub fn pinned(&self) -> usize {
        self.pinned.get()
    }

    /// Number of operations currently in flight across all pins.
    pub fn in_flight(&self) -> usize {
        self.in_flight.get()
    }

    /// Number of free (pinnable) buffers.
    pub fn available(&self) -> usize {
        self.slots.iter().filter(|s| !s.in_use.get()).count()
    }

    /// Pin a free buffer, or `None` when the pool is exhausted.
    ///
    /// The returned [`Pin`] borrows the pool, so the pool cannot be dropped while
    /// the pin is alive.
    pub fn pin(&self) -> Option<Pin<'_>> {
        for (index, slot) in self.slots.iter().enumerate() {
            if !slot.in_use.get() {
                slot.in_use.set(true);
                self.pinned.set(self.pinned.get() + 1);
                let stage = slot.buf.borrow_mut();
                return Some(Pin {
                    pool: self,
                    index,
                    stage,
                    op: Cell::new(None),
                });
            }
        }
        None
    }

    /// Borrow the raw base addresses and lengths of every buffer, as `iovec`s,
    /// for `io_uring_register_buffers`.
    ///
    /// The addresses are stable for the pool's lifetime, so a caller may register
    /// them once. Registration is only valid while the pool outlives the ring's
    /// use of them; the engine unregisters before dropping the pool.
    pub fn iovecs(&self) -> Vec<libc::iovec> {
        self.slots.iter().map(|s| s.iov).collect()
    }

    /// Build the two-element `iovec` array that a FUSE-over-`io_uring`
    /// `REGISTER` command imports from `sqe->addr`: `iov[0]` is the request
    /// header, `iov[1]` the payload buffer.
    ///
    /// This is the same pin discipline as [`BufferPool::iovecs`], specialised to
    /// the ring transport: both buffers must stay allocated, at a stable address,
    /// and untouched by anyone else for as long as the kernel keeps the entry
    /// registered — deregistration is *not* implied by cancelling an operation,
    /// so the entry's whole lifetime is the pin window. The array is boxed so its
    /// own address is stable across moves of the owning struct, which is what lets
    /// the caller hand the kernel a pointer once at registration time.
    pub fn register_iovecs(
        header: &AlignedBuffer,
        payload: &AlignedBuffer,
    ) -> Box<[libc::iovec; 2]> {
        Box::new([
            libc::iovec {
                iov_base: header.as_ptr().cast(),
                iov_len: header.len(),
            },
            libc::iovec {
                iov_base: payload.as_ptr().cast(),
                iov_len: payload.len(),
            },
        ])
    }

    /// Attempt to release (`true`) or report why the pool is still busy.
    ///
    /// A pool is releasable only when nothing is pinned and nothing is in flight.
    /// This is the runtime half of the lifetime rule; the borrow checker provides
    /// the compile-time half (a live [`Pin`] prevents the pool from being dropped).
    pub fn try_release(&self) -> Result<(), ReleaseError> {
        if self.in_flight.get() > 0 {
            return Err(ReleaseError::InFlight(self.in_flight.get()));
        }
        if self.pinned.get() > 0 {
            return Err(ReleaseError::Pinned(self.pinned.get()));
        }
        Ok(())
    }
}

/// An exclusive pin on one pooled buffer.
///
/// While a `Pin` exists the buffer is not schedulable by any other `Pin`, and the
/// pool cannot be dropped. [`Pin::begin_op`]/[`Pin::end_op`] bracket each use of
/// the buffer by an `io_uring` operation.
pub struct Pin<'a> {
    pool: &'a BufferPool,
    index: usize,
    stage: RefMut<'a, AlignedBuffer>,
    op: Cell<Option<OpId>>,
}

impl<'a> Pin<'a> {
    /// The pool slot index (also the registered-buffer index).
    pub fn index(&self) -> usize {
        self.index
    }

    /// The buffer capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.stage.len()
    }

    /// A mutable view of the pinned buffer, for staging bytes to submit.
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        self.stage.as_mut_slice()
    }

    /// A shared view of the pinned buffer.
    pub fn buffer(&self) -> &[u8] {
        self.stage.as_slice()
    }

    /// The base address handed to `io_uring`. Valid until this pin is released.
    pub fn as_ptr(&self) -> *mut u8 {
        self.stage.as_ptr()
    }

    /// Mark that an operation referencing this buffer has been submitted.
    ///
    /// Panics if this pin already has an operation in flight; call [`Pin::end_op`]
    /// first. Returns the [`OpId`] the caller must pass to `io_uring`'s
    /// `user_data` so the completion can be matched.
    pub fn begin_op(&mut self) -> OpId {
        assert!(
            self.op.get().is_none(),
            "buffer pin already has an operation in flight"
        );
        let id = OpId(self.pool.next_op.get());
        self.pool.next_op.set(id.0 + 1);
        self.op.set(Some(id));
        self.pool.in_flight.set(self.pool.in_flight.get() + 1);
        id
    }

    /// Mark that the operation returned by the last [`Pin::begin_op`] has
    /// completed and its completion has been collected.
    pub fn end_op(&mut self) {
        if self.op.replace(None).is_some() {
            self.pool.in_flight.set(self.pool.in_flight.get() - 1);
        }
    }

    /// The currently in-flight operation, if any.
    pub fn in_flight_op(&self) -> Option<OpId> {
        self.op.get()
    }
}

impl Drop for Pin<'_> {
    fn drop(&mut self) {
        // A pin must not be released while one of its operations is in flight: the
        // kernel could still touch the buffer. This is a programming error, caught
        // in debug builds; in release we still repair the accounting so the pool is
        // not left permanently un-releasable.
        if self.op.replace(None).is_some() {
            self.pool
                .in_flight
                .set(self.pool.in_flight.get().saturating_sub(1));
            debug_assert!(
                false,
                "Pin dropped while an io_uring operation was still in flight"
            );
        }
        self.pool
            .pinned
            .set(self.pool.pinned.get().saturating_sub(1));
        self.pool.slots[self.index].in_use.set(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_are_exclusive_and_reusable() {
        let pool = BufferPool::new(2, 4096);
        assert_eq!(pool.capacity(), 2);
        let a = pool.pin().expect("first pin");
        let b = pool.pin().expect("second pin");
        assert!(pool.pin().is_none(), "pool must be exhausted");
        assert_eq!(pool.available(), 0);
        drop(a);
        assert_eq!(pool.pinned(), 1);
        let _c = pool.pin().expect("reusable after release");
        drop(b);
        assert_eq!(pool.pinned(), 1);
    }

    #[test]
    fn release_is_refused_while_pinned_or_in_flight() {
        let pool = BufferPool::new(1, 4096);
        assert!(pool.try_release().is_ok());
        let mut pin = pool.pin().unwrap();
        assert_eq!(pool.try_release(), Err(ReleaseError::Pinned(1)));

        let _op = pin.begin_op();
        assert_eq!(pool.in_flight(), 1);
        assert_eq!(pool.try_release(), Err(ReleaseError::InFlight(1)));
        assert_eq!(pin.in_flight_op().map(|o| o.0), Some(0));

        pin.end_op();
        assert_eq!(pool.in_flight(), 0);
        assert_eq!(pool.try_release(), Err(ReleaseError::Pinned(1)));

        drop(pin);
        assert!(pool.try_release().is_ok());
    }

    #[test]
    fn op_ids_are_unique_and_monotonic() {
        let pool = BufferPool::new(2, 4096);
        let mut a = pool.pin().unwrap();
        let mut b = pool.pin().unwrap();
        let a0 = a.begin_op();
        a.end_op();
        let b0 = b.begin_op();
        b.end_op();
        let a1 = a.begin_op();
        assert!(a1.0 > a0.0 && b0.0 > a0.0 && a1.0 > b0.0);
        a.end_op();
    }

    #[test]
    fn buffers_are_page_aligned_and_zeroed() {
        let pool = BufferPool::new(1, 8192);
        let pin = pool.pin().unwrap();
        assert_eq!(pin.as_ptr() as usize % DEFAULT_ALIGN, 0);
        assert!(pin.buffer().iter().all(|&b| b == 0));
        let iov = pool.iovecs();
        assert_eq!(iov.len(), 1);
        assert_eq!(iov[0].iov_len, 8192);
    }

    /// **Invariant (b): a registered buffer is releasable only after every
    /// referencing completion has been reaped.** Cancelling an operation is not a
    /// completion, so an op counts as in flight until `end_op` (i.e. until its CQE
    /// was collected) *and* its pin has been dropped.
    #[test]
    fn registered_buffers_are_released_only_after_every_completion_is_reaped() {
        let pool = BufferPool::new(2, 8192);
        let mut a = pool.pin().expect("pin a");
        let mut b = pool.pin().expect("pin b");
        let _oa = a.begin_op();
        let _ob = b.begin_op();
        assert_eq!(pool.in_flight(), 2);
        assert_eq!(pool.try_release(), Err(ReleaseError::InFlight(2)));
        // Reap only the first CQE: the buffer is still not releasable.
        a.end_op();
        assert_eq!(pool.in_flight(), 1);
        assert_eq!(pool.try_release(), Err(ReleaseError::InFlight(1)));
        // Reap the second; now it is the still-live pins that block release.
        b.end_op();
        assert_eq!(pool.in_flight(), 0);
        assert_eq!(pool.try_release(), Err(ReleaseError::Pinned(2)));
        drop(a);
        drop(b);
        assert!(
            pool.try_release().is_ok(),
            "release is allowed only once nothing is pinned or in flight"
        );
    }

    /// **Invariant (buffer lifetime): an `AlignedBuffer`'s address is stable
    /// across an ownership move between threads.** The kernel may retain a pointer
    /// into the buffer for an operation's whole lifetime, so transferring the buffer
    /// to another thread (the `unsafe impl Send`) must not relocate it.
    #[test]
    fn aligned_buffer_address_is_stable_when_ownership_moves_between_threads() {
        let buf = AlignedBuffer::new(8192, DEFAULT_ALIGN);
        let addr = buf.as_ptr() as usize;
        let buf = std::thread::spawn(move || buf).join().expect("worker");
        assert_eq!(buf.as_ptr() as usize, addr, "address must not change");
        assert!(buf.as_slice().iter().all(|&b| b == 0));
    }
}
