//! Traditional `/dev/fuse` transport (research §13–§16, §26–§29, §33).
//!
//! This module is **Plane D**: it adapts the transport-neutral [`OrfsCore`] to the
//! Linux FUSE kernel protocol through the `fuser` crate (typed 0.18 API). It owns
//! no filesystem semantics of its own beyond POSIX bookkeeping the kernel
//! requires from every FUSE filesystem (open handles, directory iteration
//! cookies, lookup accounting, permission checks, errno mapping).
//!
//! Design rules encoded here:
//!
//! * **Inode identity ≠ handle identity.** An inode id is stable for the life of
//!   the volume and never reused; a *file handle* is a short-lived correlation id
//!   for one open file description. `unlink` removes a name, never an inode, so an
//!   already-open handle keeps working (research §15, §26.1).
//! * **Conservative, write-through caching.** Attributes and entries are cached
//!   for a short, controlled TTL; a small `direct_io`/readahead surface is exposed.
//!   The writeback cache is deliberately **not** negotiated (see
//!   `docs/FUSE-SEMANTICS.md`): it would move writes into the kernel page cache
//!   and destroy per-operation transaction visibility.
//! * **`flush` is not a durability barrier; `fsync` is.** Every mutating reply is
//!   already durable according to the selected [`DurabilityMode`]; `flush` merely
//!   releases handle state.
//! * **No silent capability.** Unsupported operations return the exact documented
//!   errno rather than a wrong success.

use std::collections::HashMap;
use std::ffi::{CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    AccessFlags, BackgroundSession, Config, CopyFileRangeFlags, Errno, FileAttr, FileHandle,
    FileType as FuseFileType, Filesystem, FopenFlags, Generation, INodeNo, InitFlags, KernelConfig,
    LockOwner, MountOption, Notifier, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyLock, ReplyLseek, ReplyOpen,
    ReplyStatfs, ReplyWrite, ReplyXattr, Request, Session, SessionACL, TimeOrNow, WriteFlags,
};
use parking_lot::Mutex;

use crate::commit::DurabilityMode;
use crate::error::{OrfsError, Result};
use crate::fuse_uring::{self, FuseUringNegotiation, FuseUringReport, TransportProfile};
use crate::inode::{has_permission_grouped, InodeStat, InodeType, Timespec};
use crate::log::OpenMode;
use crate::manifestation::ManifestationProfile;
use crate::namespace::{CoreRead, Namespace, OrfsCore, ReadCell, RenameMode, SetAttr};
use crate::snapshot::Snapshot;

/// The FUSE root inode (`FUSE_ROOT_ID`), shared with the namespace engine.
pub const ROOT_INODE: u64 = 1;
/// Fixed inode generation. OrFS never reuses an inode id, so the generation is
/// always 1 (research §26.2).
pub(crate) const GENERATION: Generation = Generation(1);
/// Reported `st_blksize` / `statfs` block size.
const BLOCK_SIZE: u32 = 4096;
/// Maximum filename length reported by `statfs`.
const NAME_MAX: u32 = 255;
/// Upper bound on one `copy_file_range` chunk, to bound per-call memory.
const COPY_CHUNK: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Which backing-I/O engine a mount *requested*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackingIo {
    /// Synchronous positional `pread`/`pwrite` + `fsync`.
    Sync,
    /// `io_uring` backing rings (Ring W + Ring R). Whether it actually engages is
    /// reported truthfully by [`OrfsMount::backing_io_used`] and
    /// [`crate::uring::UringReport`]; if unavailable at runtime, OrFS falls back
    /// to [`BackingIo::Sync`].
    Uring,
}

impl BackingIo {
    /// Parse the `--backing-io` value.
    pub fn parse(s: &str) -> Result<BackingIo> {
        match s.trim().to_ascii_lowercase().as_str() {
            "sync" => Ok(BackingIo::Sync),
            "uring" => Ok(BackingIo::Uring),
            other => Err(OrfsError::InvalidArgument(format!(
                "unknown backing-io {other:?} (expected sync|uring)"
            ))),
        }
    }
}

/// Which FUSE transport a mount *requested* (research §18; directive §16.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Traditional `/dev/fuse` request transport. Combined with the backing
    /// engine this is profile F0 (sync) or F1 (io_uring).
    Fuse,
    /// Request FUSE-over-`io_uring` (profile F2). Negotiated at runtime; falls
    /// back cleanly to F1/F0 when the kernel or privilege model does not permit
    /// it, without changing filesystem contents.
    FuseUring,
}

impl Transport {
    /// Parse the `--transport` value.
    pub fn parse(s: &str) -> Result<Transport> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fuse" => Ok(Transport::Fuse),
            "fuse-uring" | "fuse_uring" | "fuse-over-io-uring" => Ok(Transport::FuseUring),
            other => Err(OrfsError::InvalidArgument(format!(
                "unknown transport {other:?} (expected fuse|fuse-uring)"
            ))),
        }
    }

    /// The requested transport profile name, before negotiation.
    pub fn requested_name(&self) -> &'static str {
        match self {
            Transport::Fuse => "fuse",
            Transport::FuseUring => "fuse-uring",
        }
    }

    /// Whether the caller asked for the advanced (F2) transport.
    pub fn requests_uring_fuse(&self) -> bool {
        matches!(self, Transport::FuseUring)
    }
}

/// How the native F2 session services its ring queues (Phase 26).
///
/// The kernel registers one entry per CPU queue; every request delivered into an
/// entry must be dispatched and then re-armed with `COMMIT_AND_FETCH`. This
/// chooses *where* that dispatch runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum F2Servicing {
    /// One session loop services every queue inline, on the thread that owns the
    /// ring (the Phase 15..25 behaviour). Lowest overhead and lowest latency for
    /// a single in-flight request; no cross-thread handoff.
    Single,
    /// A bounded worker pool dispatches requests off the session thread. It is
    /// split into a *latency* lane (metadata and small reads) and a *bulk* lane
    /// (large reads and writes) so a small metadata op never queues behind a
    /// large read. The session thread alone owns the ring and submits
    /// `COMMIT_AND_FETCH` (the kernel delivers URING_CMD completions as task-work
    /// to the submitting task).
    Pool { fast: usize, bulk: usize },
}

impl F2Servicing {
    /// Parse the `--f2-servicing` value.
    pub fn parse(s: &str) -> Result<F2Servicing> {
        match s.trim().to_ascii_lowercase().as_str() {
            "single" | "loop" => Ok(F2Servicing::Single),
            "pool" => Ok(F2Servicing::pool_default()),
            other => Err(OrfsError::InvalidArgument(format!(
                "unknown f2-servicing {other:?} (expected single|pool)"
            ))),
        }
    }

    /// The measured-default worker-pool split (see `docs/FUSE_URING.md` §6.2).
    pub fn pool_default() -> F2Servicing {
        F2Servicing::Pool { fast: 2, bulk: 6 }
    }

    /// A one-line description for diagnostics and evidence.
    pub fn describe(&self) -> String {
        match self {
            F2Servicing::Single => "single-loop".to_string(),
            F2Servicing::Pool { fast, bulk } => format!("pool(fast={fast},bulk={bulk})"),
        }
    }
}

/// How `statfs` reports free space (research §30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatfsMode {
    /// Report the backing filesystem's real capacity (the honest default).
    PhysicalSafe,
    /// Report the "visible void" conceptual illusion (`U64_MAX` blocks).
    LogicalPlenum,
}

/// Mount-time cache and transport configuration.
///
/// The defaults are the conservative *write-through* profile: both TTLs are one
/// second, direct I/O is off, and readahead is 128 KiB. Every field is surfaced
/// on the `orfs mount` command line.
#[derive(Debug, Clone, Copy)]
pub struct MountOptions {
    /// Durability profile for every committed mutation.
    pub durability: DurabilityMode,
    /// Enable the end-to-end group-commit coordinator (Phase 32). Off by default;
    /// when on, concurrently-arrived mutations executed under `sync` share one
    /// durability barrier (Phase 31's amortisation), observed through the mount.
    pub group_commit: bool,
    /// Maximum number of concurrently-arrived mutations coalesced into one batch.
    pub group_commit_batch: usize,
    /// Mount read-only.
    pub read_only: bool,
    /// Requested FUSE transport (`fuse` = F0/F1, `fuse-uring` = attempt F2).
    pub transport: Transport,
    /// Request the `io_uring` backing engine (falls back to sync if unavailable).
    pub backing_io: BackingIo,
    /// Opt in to FUSE-over-`io_uring` zero-copy. Requires the F2 transport, a
    /// buffer pool, and `CAP_SYS_ADMIN`; never required for ordinary mounts.
    pub zero_copy: bool,
    /// Ask the kernel for `FOPEN_DIRECT_IO` on every open (bypass page cache).
    pub direct_io: bool,
    /// Kernel readahead in kibibytes (0 keeps the kernel default).
    pub readahead_kb: u32,
    /// Maximum size of a single kernel write in kibibytes.
    pub max_write_kb: u32,
    /// Attribute cache TTL.
    pub attr_ttl: Duration,
    /// Directory-entry cache TTL.
    pub entry_ttl: Duration,
    /// Delegate permission checks to the kernel (`default_permissions`).
    pub default_permissions: bool,
    /// Allow access by other users (`allow_other`).
    pub allow_other: bool,
    /// Unmount automatically when the daemon exits (implies an ACL other than
    /// owner; set automatically when `allow_other` is requested).
    pub auto_unmount: bool,
    /// How `statfs` accounts capacity.
    pub statfs: StatfsMode,
    /// Request kernel FUSE **passthrough** for immutable snapshot reads
    /// (Phase 21). Only engageable on the native F2 session (which owns the
    /// `/dev/fuse` descriptor) and only for read-only historical views; when it
    /// cannot engage, reads fall back to the daemon with identical bytes.
    pub passthrough: bool,
    /// Enable concealed manifestation for eligible objects with this profile
    /// (`None` disables the plane entirely; the default).
    pub manifest: Option<ManifestationProfile>,
    /// Wait for the optional manifestation before acknowledging a write.
    pub manifest_sync: bool,
    /// Manifestation worker threads (`0` selects the CPU count).
    pub manifest_workers: usize,
    /// Minimum backing bytes to keep free for authoritative writes (the
    /// capacity reserve; Phase 23, research §31). `0` leaves the device-derived
    /// default in place.
    pub capacity_reserve_bytes: u64,
    /// F2 queue-servicing topology (single session loop vs bounded worker pool).
    /// Ignored unless the mount engages the native F2 transport.
    pub f2_servicing: F2Servicing,
    /// Reserve a dedicated CPU set for the F2 session/worker threads (leaves the
    /// remaining CPUs for background manifestation). No effect on F0/F1.
    pub f2_affinity: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        MountOptions {
            durability: DurabilityMode::Ordered,
            group_commit: false,
            group_commit_batch: 64,
            read_only: false,
            transport: Transport::Fuse,
            backing_io: BackingIo::Sync,
            zero_copy: false,
            direct_io: false,
            readahead_kb: 128,
            max_write_kb: 128,
            attr_ttl: Duration::from_secs(1),
            entry_ttl: Duration::from_secs(1),
            default_permissions: false,
            allow_other: false,
            auto_unmount: false,
            statfs: StatfsMode::PhysicalSafe,
            passthrough: false,
            manifest: None,
            manifest_sync: false,
            manifest_workers: 0,
            capacity_reserve_bytes: 0,
            f2_servicing: F2Servicing::Single,
            f2_affinity: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Handle and lookup bookkeeping
// ---------------------------------------------------------------------------

/// One directory entry as captured at `opendir`/`create` time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirEntryView {
    pub(crate) name: Vec<u8>,
    pub(crate) ino: u64,
    pub(crate) kind: FuseFileType,
}

/// A single open file or directory handle.
#[derive(Debug)]
pub(crate) struct Handle {
    pub(crate) ino: u64,
    pub(crate) is_dir: bool,
    /// The raw open flags (file handles only).
    pub(crate) flags: i32,
    /// The immutable directory listing captured at `opendir` (dir handles only).
    pub(crate) dir: Option<Vec<DirEntryView>>,
    /// The version-qualified passthrough backing image this file handle is
    /// pinned to (native F2 sessions only). Released on `RELEASE`.
    pub(crate) backing: Option<PathBuf>,
}

/// The per-mount handle table. Handle ids are distinct from inode ids.
#[derive(Debug, Default)]
struct HandleTable {
    next: u64,
    map: HashMap<u64, Handle>,
}

impl HandleTable {
    fn insert(&mut self, handle: Handle) -> u64 {
        self.next += 1;
        let id = self.next;
        self.map.insert(id, handle);
        id
    }

    fn get(&self, id: u64) -> Option<&Handle> {
        self.map.get(&id)
    }

    fn remove(&mut self, id: u64) -> Option<Handle> {
        self.map.remove(&id)
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

/// Tracks kernel lookup references per inode (research §26.2).
///
/// OrFS inode ids are stable and never recycled, so this table is bookkeeping
/// rather than a lifetime mechanism: it lets us assert that every reference the
/// kernel acquires through `lookup`/`create`/`mkdir`/`symlink`/`link`/
/// `readdirplus` is eventually released by exactly one `forget`.
#[derive(Debug, Default)]
struct LookupTable {
    counts: HashMap<u64, u64>,
    acquired: u64,
    forgotten: u64,
}

impl LookupTable {
    fn acquire(&mut self, ino: u64) {
        *self.counts.entry(ino).or_insert(0) += 1;
        self.acquired += 1;
    }

    /// Release `n` references. Returns the outstanding count.
    fn forget(&mut self, ino: u64, n: u64) -> u64 {
        let current = self.counts.get(&ino).copied().unwrap_or(0);
        let released = current.min(n);
        self.forgotten += released;
        let remaining = current - released;
        if remaining == 0 {
            self.counts.remove(&ino);
        } else {
            self.counts.insert(ino, remaining);
        }
        remaining
    }

    fn outstanding(&self, ino: u64) -> u64 {
        self.counts.get(&ino).copied().unwrap_or(0)
    }

    #[allow(dead_code)]
    fn tracked_inodes(&self) -> usize {
        self.counts.len()
    }
}

/// Coarse operation counters, exposed for tests and evidence.
#[derive(Debug, Default, Clone)]
pub struct Metrics {
    pub lookups: u64,
    pub forgets: u64,
    pub opens: u64,
    pub releases: u64,
    pub opendirs: u64,
    pub releasedirs: u64,
    pub reads: u64,
    pub writes: u64,
    pub byte_reads: u64,
    pub byte_writes: u64,
    pub fsyncs: u64,
    pub create: u64,
    pub mkdir: u64,
    pub unlink: u64,
    pub rmdir: u64,
    pub rename: u64,
    pub link: u64,
    pub symlink: u64,
    pub setattr: u64,
    pub open_handles: u64,
}

// ---------------------------------------------------------------------------
// The adaptor
// ---------------------------------------------------------------------------

pub(crate) struct Inner<C: OrfsCore + Send + 'static> {
    pub(crate) core: Mutex<C>,
    /// The current immutable read view (Phase 19). Readers clone the `Arc` out of
    /// this short-lived cell and then serve the request with **no lock held across
    /// physical I/O**. It is the *same* cell the core publishes into at each commit
    /// boundary, so it is always current without the FUSE layer taking the core
    /// lock.
    read: ReadCell,
    handles: Mutex<HandleTable>,
    lookups: Mutex<LookupTable>,
    pub(crate) metrics: Arc<Mutex<Metrics>>,
    pub(crate) backing: PathBuf,
    pub(crate) root_inode: u64,
    /// End-to-end group-commit coordinator (Phase 32). When present, mutating
    /// requests are submitted here instead of taking the core lock directly, so
    /// concurrently-arrived mutations share one durability barrier under `sync`.
    coordinator: Option<Arc<crate::group_commit::BatchCoordinator<C>>>,
}

impl<C: OrfsCore + Send + 'static> Inner<C> {
    /// Clone the current immutable read view (a cheap `Arc` bump, no I/O).
    pub(crate) fn read_view(&self) -> Arc<dyn CoreRead> {
        self.read.read().clone()
    }

    /// Run `f` against the core. With a group-commit coordinator active the job
    /// is submitted to it (so it can share a batch's durability barrier);
    /// otherwise it runs directly under the core lock. Either way the mutation
    /// executes against the single authoritative core with its order preserved.
    pub(crate) fn mutate<F>(&self, f: F) -> Result<i64>
    where
        F: FnOnce(&mut C) -> Result<i64> + Send + 'static,
    {
        match &self.coordinator {
            Some(coord) => coord.submit(Box::new(f)),
            None => {
                let mut core = self.core.lock();
                f(&mut core)
            }
        }
    }

    /// A shared handle to the operation counters, so a mount can report the
    /// number of requests that reached the daemon regardless of transport.
    pub(crate) fn metrics_cell(&self) -> Arc<Mutex<Metrics>> {
        Arc::clone(&self.metrics)
    }

    pub(crate) fn stat(&self, view: &dyn CoreRead, ino: u64) -> Result<InodeStat> {
        view.getattr(ino, view.root())
    }

    /// Build the immutable listing of `dir` used to answer `readdir`/
    /// `readdirplus` for its whole lifetime.
    ///
    /// Mutation-consistency policy (documented in `docs/FUSE-SEMANTICS.md`):
    /// a directory stream observes the directory as of `opendir`; concurrent
    /// mutations are not reflected until the directory is reopened. This makes
    /// the iteration cookies stable and makes a partially consumed listing
    /// resumable, which is the strongest guarantee a FUSE filesystem can offer
    /// without per-directory versioning.
    pub(crate) fn build_dir_listing(
        &self,
        view: &dyn CoreRead,
        dir: u64,
    ) -> Result<Vec<DirEntryView>> {
        let root = view.root();
        let ino = view.getattr(dir, root)?;
        if ino.kind != InodeType::Directory {
            return Err(OrfsError::NotADirectory);
        }
        let mut out = Vec::new();
        out.push(DirEntryView {
            name: b".".to_vec(),
            ino: dir,
            kind: FuseFileType::Directory,
        });
        let parent = view.parent_of(dir).unwrap_or(ROOT_INODE);
        out.push(DirEntryView {
            name: b"..".to_vec(),
            ino: parent,
            kind: FuseFileType::Directory,
        });
        for (name, child) in view.readdir(dir, root)? {
            let kind = match view.getattr(child, root) {
                Ok(st) => fuse_kind(st.kind),
                Err(_) => continue,
            };
            out.push(DirEntryView {
                name,
                ino: child,
                kind,
            });
        }
        Ok(out)
    }

    pub(crate) fn register_file(&self, ino: u64, flags: i32) -> u64 {
        self.handles.lock().insert(Handle {
            ino,
            is_dir: false,
            flags,
            dir: None,
            backing: None,
        })
    }

    pub(crate) fn register_dir(&self, ino: u64, listing: Vec<DirEntryView>) -> u64 {
        let mut table = self.handles.lock();
        table.insert(Handle {
            ino,
            is_dir: true,
            flags: 0,
            dir: Some(listing),
            backing: None,
        })
    }

    /// Pin a passthrough backing image to an open file handle so `RELEASE` can
    /// release the kernel registration. A no-op if the handle already vanished.
    pub(crate) fn set_handle_backing(&self, id: u64, path: PathBuf) {
        if let Some(h) = self.handles.lock().map.get_mut(&id) {
            h.backing = Some(path);
        }
    }

    pub(crate) fn handle(&self, id: u64) -> Option<Handle> {
        self.handles.lock().get(id).map(|h| Handle {
            ino: h.ino,
            is_dir: h.is_dir,
            flags: h.flags,
            dir: h.dir.clone(),
            backing: h.backing.clone(),
        })
    }

    pub(crate) fn remove_handle(&self, id: u64) -> Option<Handle> {
        self.handles.lock().remove(id)
    }

    pub(crate) fn record_lookup(&self, ino: u64) {
        self.lookups.lock().acquire(ino);
    }

    pub(crate) fn record_forget(&self, ino: u64, n: u64) {
        self.lookups.lock().forget(ino, n);
    }
}

/// A shared cell holding the kernel notifier once the session is attached.
type NotifierCell = Arc<Mutex<Option<Notifier>>>;

/// A cache-invalidation request handed to the background notifier thread.
enum NotifyMsg {
    InvalEntry { parent: u64, name: Vec<u8> },
    InvalInode { ino: u64 },
}

/// A mounted OrFS filesystem (transport adaptor + mount state).
pub struct OrfsFuse<C: OrfsCore + Send + 'static> {
    pub(crate) inner: Arc<Inner<C>>,
    notifier: NotifierCell,
    notify_tx: std::sync::mpsc::Sender<NotifyMsg>,
    pub(crate) options: MountOptions,
    /// Filled during the FUSE `INIT` handshake with the live FUSE-over-
    /// `io_uring` negotiation result (the only authoritative statement of
    /// whether the kernel would enable `io_uring` on this connection).
    negotiation: Arc<Mutex<FuseUringNegotiation>>,
}

impl<C: OrfsCore + Send + 'static> OrfsFuse<C> {
    pub(crate) fn new(core: C, backing: PathBuf, options: MountOptions) -> OrfsFuse<C> {
        // The core owns the publication cell; the adaptor shares it so it never
        // has to take the core lock just to obtain the current read view.
        let read = core.read_view_cell();
        let mut inner = Arc::new(Inner {
            core: Mutex::new(core),
            read,
            handles: Mutex::new(HandleTable::default()),
            lookups: Mutex::new(LookupTable::default()),
            metrics: Arc::new(Mutex::new(Metrics::default())),
            backing,
            root_inode: ROOT_INODE,
            coordinator: None,
        });
        // Start the end-to-end group-commit coordinator (Phase 32) when opted in.
        // `BatchCoordinator::start` only takes a *weak* handle to `inner`, so the
        // strong count stays 1 here and `get_mut` succeeds; if it ever did not, we
        // simply fall back to the direct (per-request) path.
        if options.group_commit {
            let coord =
                crate::group_commit::BatchCoordinator::start(&inner, options.group_commit_batch);
            if let Some(slot) = Arc::get_mut(&mut inner) {
                slot.coordinator = Some(coord);
            }
        }
        let notifier: NotifierCell = Arc::new(Mutex::new(None));
        // Cache invalidation runs on its own thread. Sending a FUSE notify from
        // inside a request handler can deadlock the kernel: the notify path
        // (`fuse_reverse_inval_entry`) takes locks that a concurrent syscall may
        // hold while it waits for *this* handler to reply. Running notifications
        // off the request thread keeps that request thread free to answer, so
        // the lock is always released (research §27).
        let (notify_tx, notify_rx) = std::sync::mpsc::channel::<NotifyMsg>();
        let worker_notifier = notifier.clone();
        let _ = std::thread::Builder::new()
            .name("orfs-notify".to_string())
            .spawn(move || {
                while let Ok(msg) = notify_rx.recv() {
                    let n = match worker_notifier.lock().as_ref() {
                        Some(n) => n.clone(),
                        None => continue,
                    };
                    match msg {
                        NotifyMsg::InvalEntry { parent, name } => {
                            let _ = n.inval_entry(INodeNo(parent), OsStr::from_bytes(&name));
                        }
                        NotifyMsg::InvalInode { ino } => {
                            let _ = n.inval_inode(INodeNo(ino), 0, 0);
                        }
                    }
                }
            });
        OrfsFuse {
            inner,
            notifier,
            notify_tx,
            options,
            negotiation: Arc::new(Mutex::new(FuseUringNegotiation::not_requested())),
        }
    }

    /// Clone the current immutable read view (a cheap `Arc` bump; no core lock).
    pub(crate) fn read_view(&self) -> Arc<dyn CoreRead> {
        self.inner.read_view()
    }

    /// The shared cell the `INIT` negotiation writes and the mount reports from.
    pub(crate) fn negotiation_cell(&self) -> Arc<Mutex<FuseUringNegotiation>> {
        Arc::clone(&self.negotiation)
    }

    /// Record a FUSE-over-`io_uring` negotiation result computed by the native
    /// F2 session (which performs the same `INIT` handshake itself).
    pub(crate) fn record_negotiation(&self, neg: FuseUringNegotiation) {
        eprintln!("orfs: {}", neg.describe());
        *self.negotiation.lock() = neg;
    }

    /// A snapshot of the operation counters.
    pub fn metrics(&self) -> Metrics {
        self.inner.metrics.lock().clone()
    }

    /// A shared handle to the operation counters, so the mount can expose the
    /// daemon-request count for every transport (F0/F1/F2).
    pub(crate) fn metrics_cell(&self) -> Arc<Mutex<Metrics>> {
        self.inner.metrics_cell()
    }

    /// The number of outstanding kernel lookup references for `ino`.
    pub fn outstanding_lookups(&self, ino: u64) -> u64 {
        self.inner.lookups.lock().outstanding(ino)
    }

    /// The number of open file/directory handles.
    pub fn open_handles(&self) -> usize {
        self.inner.handles.lock().len()
    }

    /// Enqueue an entry-cache invalidation (non-blocking; performed off-thread).
    fn invalidate_entry(&self, parent: u64, name: &[u8]) {
        let _ = self.notify_tx.send(NotifyMsg::InvalEntry {
            parent,
            name: name.to_vec(),
        });
    }

    /// Enqueue an inode-cache invalidation (non-blocking; performed off-thread).
    fn invalidate_inode(&self, ino: u64) {
        let _ = self.notify_tx.send(NotifyMsg::InvalInode { ino });
    }

    fn ensure_writable(&self) -> Result<()> {
        if self.options.read_only {
            Err(OrfsError::ReadOnly("mounted read-only".into()))
        } else {
            Ok(())
        }
    }

    /// Perform the live FUSE-over-`io_uring` negotiation during `INIT`.
    ///
    /// The kernel sets `FUSE_OVER_IO_URING` in the `INIT` flags **only** when
    /// `fuse_uring_enabled()` is true (`fs/fuse/inode.c`), so the presence (or
    /// absence) of that capability bit is the authoritative runtime answer, not a
    /// guess. The result is recorded truthfully: `engaged` stays `false` unless a
    /// native ring is actually driven for this mount.
    fn negotiate_fuse_uring(&self, config: &mut KernelConfig) {
        if self.options.transport != Transport::FuseUring {
            *self.negotiation.lock() = FuseUringNegotiation::not_requested();
            return;
        }
        let caps = config.capabilities();
        let kernel_offered = caps.contains(InitFlags::FUSE_OVER_IO_URING);
        let kernel_offered_bufpool = caps.bits() & fuse_uring::FUSE_HAS_IO_URING_BUFPOOL != 0;
        let v = config.kernel_abi();
        // Echo the capability back to the kernel when it was offered. On a host
        // where `fuse.enable_uring` is off the kernel never offers it, so this
        // returns `false` and nothing is claimed.
        let accepted = if kernel_offered {
            config
                .add_capabilities(InitFlags::FUSE_OVER_IO_URING)
                .is_ok()
        } else {
            false
        };
        let reason = if !kernel_offered {
            Some(format!(
                "kernel did not offer FUSE_OVER_IO_URING at INIT (FUSE ABI {}.{}); it \
                 gates this on the fuse.enable_uring module parameter, which is off on \
                 this host, so FUSE requests continue over /dev/fuse",
                v.0, v.1
            ))
        } else {
            Some(
                "FUSE_OVER_IO_URING was negotiated, but this build uses the fuser crate \
                 for the session and fuser 0.18 does not expose the /dev/fuse file \
                 descriptor, so a native ring cannot be attached (see docs/FUSE_URING.md)"
                    .to_string(),
            )
        };
        let neg = FuseUringNegotiation {
            kernel_offered,
            kernel_offered_bufpool,
            kernel_abi: Some((v.0, v.1)),
            accepted,
            engaged: false,
            reason,
            cap_sys_admin: crate::fuse_uring::has_cap_sys_admin(),
            num_queues: 0,
        };
        eprintln!("orfs: {}", neg.describe());
        *self.negotiation.lock() = neg;
    }
}

// ---------------------------------------------------------------------------
// Conversions and checks
// ---------------------------------------------------------------------------

fn errno(e: &OrfsError) -> Errno {
    Errno::from_i32(e.errno())
}

fn fuse_kind(kind: InodeType) -> FuseFileType {
    match kind {
        InodeType::File => FuseFileType::RegularFile,
        InodeType::Directory => FuseFileType::Directory,
        InodeType::Symlink => FuseFileType::Symlink,
    }
}

fn ts_to_system(ts: Timespec) -> SystemTime {
    if ts.secs >= 0 {
        UNIX_EPOCH + Duration::new(ts.secs as u64, ts.nanos.min(999_999_999))
    } else {
        UNIX_EPOCH - Duration::new((-ts.secs) as u64, ts.nanos.min(999_999_999))
    }
}

fn system_to_ts(t: SystemTime) -> Timespec {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => Timespec::new(d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            if d.subsec_nanos() == 0 {
                Timespec::new(-(d.as_secs() as i64), 0)
            } else {
                Timespec::new(-(d.as_secs() as i64) - 1, 1_000_000_000 - d.subsec_nanos())
            }
        }
    }
}

fn time_or_now(t: TimeOrNow) -> Timespec {
    match t {
        TimeOrNow::SpecificTime(st) => system_to_ts(st),
        TimeOrNow::Now => system_to_ts(SystemTime::now()),
    }
}

pub(crate) fn file_attr(st: &InodeStat) -> FileAttr {
    FileAttr {
        ino: INodeNo(st.id),
        size: st.size,
        blocks: st.blocks,
        atime: ts_to_system(st.atime),
        mtime: ts_to_system(st.mtime),
        ctime: ts_to_system(st.ctime),
        crtime: ts_to_system(st.ctime),
        kind: fuse_kind(st.kind),
        perm: (st.mode & 0o7777) as u16,
        // Report the true link count, including 0 for an unlinked file that is
        // still open (POSIX). A named inode always has nlink >= 1, so lookup and
        // readdirplus never hand the kernel a zero link count.
        nlink: st.nlink,
        uid: st.uid,
        gid: st.gid,
        rdev: 0,
        blksize: BLOCK_SIZE,
        flags: 0,
    }
}

// ---------------------------------------------------------------------------
// The Filesystem implementation
// ---------------------------------------------------------------------------

impl<C: OrfsCore + Send + 'static> Filesystem for OrfsFuse<C> {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> io::Result<()> {
        // Only request capabilities this build actually honours. OrFS serves
        // readdirplus, async reads, big writes and max-pages. It does NOT request
        // the writeback cache, POSIX locks, or flock (see docs/FUSE-SEMANTICS.md).
        let want = InitFlags::FUSE_DO_READDIRPLUS
            | InitFlags::FUSE_READDIRPLUS_AUTO
            | InitFlags::FUSE_ASYNC_READ
            | InitFlags::FUSE_BIG_WRITES
            | InitFlags::FUSE_MAX_PAGES
            | InitFlags::FUSE_ASYNC_DIO
            // Delegate suid/sgid clearing on write to the daemon instead of the
            // kernel's mode-clearing SETATTR, which the ownership rule refuses
            // (docs/FUSE-SEMANTICS.md §5.2). The V2 form additionally carries
            // FUSE_WRITE_KILL_SUIDGID on the write so the daemon clears exactly
            // when the kernel would.
            | InitFlags::FUSE_HANDLE_KILLPRIV
            | InitFlags::FUSE_HANDLE_KILLPRIV_V2;
        let supported = config.capabilities() & want;
        let _ = config.add_capabilities(supported);

        let _ = config.set_max_write(self.options.max_write_kb.saturating_mul(1024).max(4096));
        if self.options.readahead_kb > 0 {
            let _ = config.set_max_readahead(self.options.readahead_kb.saturating_mul(1024));
        }
        let _ = config.set_time_granularity(Duration::from_nanos(1));

        self.negotiate_fuse_uring(config);
        Ok(())
    }

    fn destroy(&mut self) {
        // Best-effort durability flush on unmount. Errors cannot be reported to
        // the kernel here; they are logged.
        let mut core = self.inner.core.lock();
        if let Err(e) = core.sync() {
            tracing::warn!("orfs: destroy flush failed: {e}");
        }
    }

    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name = name.as_bytes();
        let view = self.read_view();
        let root = view.root();
        let directory = match view.getattr(parent.0, root) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        if directory.kind != InodeType::Directory {
            return reply.error(Errno::ENOTDIR);
        }
        if !has_permission_grouped(
            req.uid(),
            req.gid(),
            &caller_groups(req.pid()),
            &directory,
            0o1,
        ) {
            return reply.error(Errno::EACCES);
        }
        let resolved = if name == b"." {
            Ok(parent.0)
        } else if name == b".." {
            Ok(view.parent_of(parent.0).unwrap_or(self.inner.root_inode))
        } else {
            view.lookup(parent.0, name, root)
        };
        let ino = match resolved {
            Ok(i) => i,
            Err(e) => return reply.error(errno(&e)),
        };
        let st = match view.getattr(ino, root) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        self.inner.record_lookup(ino);
        self.inner.metrics.lock().lookups += 1;
        let attr = file_attr(&st);
        reply.entry_with_ttls(
            &self.options.attr_ttl,
            &self.options.entry_ttl,
            &attr,
            GENERATION,
        );
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.inner.record_forget(ino.0, nlookup);
        self.inner.metrics.lock().forgets += 1;
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let view = self.read_view();
        match self.inner.stat(view.as_ref(), ino.0) {
            Ok(st) => reply.attr(&self.options.attr_ttl, &file_attr(&st)),
            Err(e) => reply.error(errno(&e)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        // Truncation through an already-open writable descriptor carries write
        // access from `open`; do not re-check the inode's write permission
        // (Linux `ftruncate` never does). A path-based truncate still checks.
        let writable_fh = fh
            .and_then(|h| self.inner.handle(h.0))
            .is_some_and(|h| !h.is_dir && (h.flags & libc::O_ACCMODE) != libc::O_RDONLY);
        // The permission model reads the authoritative inode, and the change must
        // be decided against the same state it commits against, so the whole check
        // + mutate runs inside one job under the core lock. That also lets a
        // truncate share a group-commit batch's durability barrier.
        let ino_raw = ino.0;
        let actor_uid = req.uid();
        let actor_gid = req.gid();
        let actor_pid = req.pid();
        let groups = caller_groups(actor_pid);
        let is_root = actor_uid == 0;
        let res = self.inner.mutate(move |core| {
            let root = core.root();
            let st = core.getattr(ino_raw, root)?;
            let owner_or_root = is_root || actor_uid == st.uid;
            let meta_change = mode.is_some() || uid.is_some() || gid.is_some();
            let time_change = atime.is_some() || mtime.is_some();
            // Linux `ATTR_TOUCH` (an explicit `utimensat`/`utimes` with `times == NULL`
            // or both fields `UTIME_NOW`) is the one time update a *non-owner* may
            // perform, provided it has write permission. Every other time form (a
            // specific time, or one field omitted) is `ATTR_TIMES_SET`, which
            // requires ownership. Because the mount does not use
            // `default_permissions`, the kernel delegates this check to the daemon.
            let touch_like = !meta_change
                && matches!(&atime, Some(TimeOrNow::Now))
                && matches!(&mtime, Some(TimeOrNow::Now));
            if touch_like {
                if !owner_or_root
                    && !has_permission_grouped(actor_uid, actor_gid, &groups, &st, 0o2)
                {
                    return Err(OrfsError::PermissionDenied);
                }
            } else if (meta_change || time_change) && !owner_or_root {
                // chmod/chown/utimes with an explicit value require ownership or root.
                return Err(OrfsError::NotPermitted);
            }
            // Changing the *owner* (uid) requires root (Linux `CAP_CHOWN`).
            let uid_changes = uid.is_some_and(|u| u != st.uid);
            if uid_changes && !is_root {
                return Err(OrfsError::NotPermitted);
            }
            // A non-root owner may move a file into a group it belongs to — its
            // effective group or a supplementary group — and only root may do more.
            // Membership is read from the kernel's own `/proc/<pid>/status`.
            let gid_changes = gid.is_some_and(|g| g != st.gid);
            if gid_changes && !is_root {
                let target = gid.unwrap_or(st.gid);
                if !owner_or_root || !caller_in_group(actor_pid, actor_gid, target) {
                    return Err(OrfsError::NotPermitted);
                }
            }
            if size.is_some()
                && !writable_fh
                && !has_permission_grouped(actor_uid, actor_gid, &groups, &st, 0o2)
            {
                return Err(OrfsError::PermissionDenied);
            }
            // Linux clears S_ISUID/S_ISGID when a caller without CAP_FSETID truncates
            // (FATTR_KILL_SUIDGID, which the high-level API does not surface, so we
            // approximate CAP_FSETID as uid 0). The resize and the clearing share one
            // authoritative transaction.
            let mut effective_mode = mode;
            if size.is_some() && !is_root {
                let cleared = st.mode & !(libc::S_ISUID | libc::S_ISGID);
                if cleared != st.mode {
                    effective_mode =
                        Some(effective_mode.unwrap_or(st.mode) & !(libc::S_ISUID | libc::S_ISGID));
                }
            }
            let attrs = SetAttr {
                mode: effective_mode,
                uid,
                gid,
                atime: atime.map(time_or_now),
                mtime: mtime.map(time_or_now),
                size,
            };
            core.setattr(ino_raw, &attrs)?;
            Ok(0)
        });
        if let Err(e) = res {
            return reply.error(errno(&e));
        }
        // The committed state is visible through the published read view once the
        // job (and, under grouping, its covering barrier) has returned.
        let view = self.read_view();
        let updated = match view.getattr(ino.0, view.root()) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        self.inner.metrics.lock().setattr += 1;
        self.invalidate_inode(ino.0);
        reply.attr(&self.options.attr_ttl, &file_attr(&updated));
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let view = self.read_view();
        let root = view.root();
        match view.readlink(ino.0, root) {
            Ok(target) => reply.data(&target),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn mknod(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        // Only regular files, directories and symlinks are representable. Any
        // other node type is rejected explicitly (research §14).
        let fmt = mode & libc::S_IFMT;
        let kind = match fmt {
            0 | libc::S_IFREG => InodeType::File,
            libc::S_IFDIR => InodeType::Directory,
            _ => return reply.error(Errno::EOPNOTSUPP),
        };
        let is_dir = kind == InodeType::Directory;
        let uid = req.uid();
        let gid = req.gid();
        let groups = caller_groups(req.pid());
        let parent_ino = parent.0;
        let name_bytes = name.as_bytes().to_vec();
        let perm = mode & 0o7777;
        let res = self.inner.mutate(move |core| {
            check_create_uid(&*core, uid, gid, &groups, parent_ino, 0o2 | 0o1)?;
            let ino = match kind {
                InodeType::File => core.create(parent_ino, &name_bytes, perm, uid, gid)?,
                InodeType::Directory => core.mkdir(parent_ino, &name_bytes, perm, uid, gid)?,
                _ => unreachable!(),
            };
            Ok(ino as i64)
        });
        let ino = match res {
            Ok(i) => i as u64,
            Err(e) => return reply.error(errno(&e)),
        };
        let view = self.read_view();
        let st = match view.getattr(ino, view.root()) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        self.inner.metrics.lock().create += 1;
        if is_dir {
            self.inner.metrics.lock().mkdir += 1;
        }
        self.inner.record_lookup(ino);
        self.invalidate_entry(parent.0, name.as_bytes());
        reply.entry_with_ttls(
            &self.options.attr_ttl,
            &self.options.entry_ttl,
            &file_attr(&st),
            GENERATION,
        );
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        let uid = req.uid();
        let gid = req.gid();
        let groups = caller_groups(req.pid());
        let parent_ino = parent.0;
        let name_bytes = name.as_bytes().to_vec();
        let perm = mode & 0o7777;
        let res = self.inner.mutate(move |core| {
            check_create_uid(&*core, uid, gid, &groups, parent_ino, 0o2 | 0o1)?;
            let ino = core.mkdir(parent_ino, &name_bytes, perm, uid, gid)?;
            Ok(ino as i64)
        });
        let ino = match res {
            Ok(i) => i as u64,
            Err(e) => return reply.error(errno(&e)),
        };
        let view = self.read_view();
        let st = match view.getattr(ino, view.root()) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        self.inner.metrics.lock().mkdir += 1;
        self.inner.record_lookup(ino);
        self.invalidate_entry(parent.0, name.as_bytes());
        reply.entry_with_ttls(
            &self.options.attr_ttl,
            &self.options.entry_ttl,
            &file_attr(&st),
            GENERATION,
        );
    }

    fn unlink(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        let uid = req.uid();
        let gid = req.gid();
        let groups = caller_groups(req.pid());
        let parent_ino = parent.0;
        let name_bytes = name.as_bytes().to_vec();
        let res = self.inner.mutate(move |core| {
            let root = core.root();
            check_dir_write_uid(&*core, uid, gid, &groups, parent_ino, 0o2 | 0o1)?;
            // Sticky-bit handling: in a sticky directory only the owner of the
            // entry (or a privileged caller) may remove it.
            if let Ok(dir) = core.getattr(parent_ino, root) {
                if dir.mode & libc::S_ISVTX != 0 && uid != 0 {
                    let child = core.lookup(parent_ino, &name_bytes, root)?;
                    if let Ok(st) = core.getattr(child, root) {
                        if st.uid != uid && dir.uid != uid {
                            return Err(OrfsError::NotPermitted);
                        }
                    }
                }
            }
            core.unlink(parent_ino, &name_bytes)?;
            Ok(0)
        });
        match res {
            Ok(_) => {
                self.inner.metrics.lock().unlink += 1;
                self.invalidate_entry(parent.0, name.as_bytes());
                reply.ok();
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn rmdir(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        let uid = req.uid();
        let gid = req.gid();
        let groups = caller_groups(req.pid());
        let parent_ino = parent.0;
        let name_bytes = name.as_bytes().to_vec();
        let res = self.inner.mutate(move |core| {
            let root = core.root();
            check_dir_write_uid(&*core, uid, gid, &groups, parent_ino, 0o2 | 0o1)?;
            // Sticky-bit handling (same rule as `unlink`): in a sticky directory only
            // the owner of the entry to be removed — or the owner of the sticky
            // directory, or root — may remove it. POSIX applies this to `rmdir` too.
            if let Ok(dir) = core.getattr(parent_ino, root) {
                if dir.mode & libc::S_ISVTX != 0 && uid != 0 {
                    let child = core.lookup(parent_ino, &name_bytes, root)?;
                    if let Ok(st) = core.getattr(child, root) {
                        if st.uid != uid && dir.uid != uid {
                            return Err(OrfsError::NotPermitted);
                        }
                    }
                }
            }
            core.rmdir(parent_ino, &name_bytes)?;
            Ok(0)
        });
        match res {
            Ok(_) => {
                self.inner.metrics.lock().rmdir += 1;
                self.invalidate_entry(parent.0, name.as_bytes());
                reply.ok();
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn symlink(
        &self,
        req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        let uid = req.uid();
        let gid = req.gid();
        let groups = caller_groups(req.pid());
        let parent_ino = parent.0;
        let link_bytes = link_name.as_bytes().to_vec();
        let target_bytes = target.as_os_str().as_bytes().to_vec();
        let res = self.inner.mutate(move |core| {
            check_create_uid(&*core, uid, gid, &groups, parent_ino, 0o2 | 0o1)?;
            let ino = core.symlink(parent_ino, &link_bytes, &target_bytes, uid, gid)?;
            Ok(ino as i64)
        });
        let ino = match res {
            Ok(i) => i as u64,
            Err(e) => return reply.error(errno(&e)),
        };
        let view = self.read_view();
        let st = match view.getattr(ino, view.root()) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        self.inner.metrics.lock().symlink += 1;
        self.inner.record_lookup(ino);
        self.invalidate_entry(parent.0, link_name.as_bytes());
        reply.entry_with_ttls(
            &self.options.attr_ttl,
            &self.options.entry_ttl,
            &file_attr(&st),
            GENERATION,
        );
    }

    fn rename(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        let bits = flags.bits();
        let mode = if bits == 0 {
            RenameMode::Ordinary
        } else if bits == libc::RENAME_NOREPLACE {
            RenameMode::NoReplace
        } else if bits == libc::RENAME_EXCHANGE {
            RenameMode::Exchange
        } else if bits & libc::RENAME_WHITEOUT != 0 {
            return reply.error(Errno::EOPNOTSUPP);
        } else {
            return reply.error(Errno::EINVAL);
        };
        let actor_uid = req.uid();
        let actor_gid = req.gid();
        let groups = caller_groups(req.pid());
        let parent_raw = parent.0;
        let newparent_raw = newparent.0;
        let old_name = name.as_bytes().to_vec();
        let new_name = newname.as_bytes().to_vec();
        let res = self.inner.mutate(move |core| {
            check_dir_write_uid(core, actor_uid, actor_gid, &groups, parent_raw, 0o2 | 0o1)?;
            check_dir_write_uid(
                core,
                actor_uid,
                actor_gid,
                &groups,
                newparent_raw,
                0o2 | 0o1,
            )?;
            core.rename(parent_raw, &old_name, newparent_raw, &new_name, mode)?;
            Ok(0)
        });
        match res {
            Ok(_) => {
                self.inner.metrics.lock().rename += 1;
                self.invalidate_entry(parent.0, name.as_bytes());
                self.invalidate_entry(newparent.0, newname.as_bytes());
                reply.ok();
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn link(
        &self,
        req: &Request,
        ino: INodeNo,
        newparent: INodeNo,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        let actor_uid = req.uid();
        let actor_gid = req.gid();
        let groups = caller_groups(req.pid());
        let old_ino = ino.0;
        let newparent_raw = newparent.0;
        let new_name = newname.as_bytes().to_vec();
        let res = self.inner.mutate(move |core| {
            check_dir_write_uid(
                core,
                actor_uid,
                actor_gid,
                &groups,
                newparent_raw,
                0o2 | 0o1,
            )?;
            core.link(old_ino, newparent_raw, &new_name)?;
            Ok(0)
        });
        if let Err(e) = res {
            return reply.error(errno(&e));
        }
        let view = self.read_view();
        let st = match view.getattr(ino.0, view.root()) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        self.inner.metrics.lock().link += 1;
        self.inner.record_lookup(ino.0);
        self.invalidate_entry(newparent.0, newname.as_bytes());
        reply.entry_with_ttls(
            &self.options.attr_ttl,
            &self.options.entry_ttl,
            &file_attr(&st),
            GENERATION,
        );
    }

    fn open(&self, req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let view = self.read_view();
        let root = view.root();
        let st = match view.getattr(ino.0, root) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        if st.kind == InodeType::Directory {
            return reply.error(Errno::EISDIR);
        }
        let access = flags.acc_mode();
        let mask = acc_mask(access);
        if !has_permission_grouped(req.uid(), req.gid(), &caller_groups(req.pid()), &st, mask) {
            return reply.error(Errno::EACCES);
        }
        if self.options.read_only && mask & 0o2 != 0 {
            return reply.error(Errno::EROFS);
        }
        if flags.0 & libc::O_TRUNC != 0 && mask & 0o2 != 0 {
            let attrs = SetAttr {
                size: Some(0),
                ..Default::default()
            };
            // A truncating open is the only mutating part; route it through the
            // coordinator so it can share a batch's durability barrier. A plain
            // open (the common case) is served from the immutable view with no
            // writer lock.
            let ino_raw = ino.0;
            if let Err(e) = self.inner.mutate(move |core| {
                core.setattr(ino_raw, &attrs)?;
                Ok(0)
            }) {
                return reply.error(errno(&e));
            }
        }
        let fh = self.inner.register_file(ino.0, flags.0);
        let mut m = self.inner.metrics.lock();
        m.opens += 1;
        m.open_handles += 1;
        drop(m);
        let fopen = self.fopen_flags();
        reply.opened(FileHandle(fh), fopen);
    }

    fn read(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let handle = match self.inner.handle(fh.0) {
            Some(h) if !h.is_dir => h,
            _ => return reply.error(Errno::EBADF),
        };
        let view = self.read_view();
        let root = view.root();
        let st = match view.getattr(ino.0, root) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        if !has_permission_grouped(req.uid(), req.gid(), &caller_groups(req.pid()), &st, 0o4) {
            return reply.error(Errno::EACCES);
        }
        let _ = handle;
        match view.read_at(ino.0, root, offset, size) {
            Ok(data) => {
                let mut m = self.inner.metrics.lock();
                m.reads += 1;
                m.byte_reads += data.len() as u64;
                drop(m);
                reply.data(&data);
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        write_flags: fuser::WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        let handle = match self.inner.handle(fh.0) {
            Some(h) if !h.is_dir => h,
            _ => return reply.error(Errno::EBADF),
        };
        // Everything that depends on the authoritative state — the permission
        // check, the O_APPEND end-of-file and the killpriv decision — is resolved
        // *inside* the job, under the core lock, so it observes the same state the
        // write commits against. Routing through `Inner::mutate` lets a write
        // share a group-commit batch's durability barrier; concurrency therefore
        // never resolves a stale append offset or a stale owner/mode.
        let ino_raw = ino.0;
        let uid = req.uid();
        let gid = req.gid();
        let groups = caller_groups(req.pid());
        let append = handle.flags & libc::O_APPEND != 0;
        // The kernel's precise signal (FUSE_HANDLE_KILLPRIV(_V2)). The non-owner
        // fallback is applied inside the job against the authoritative mode.
        let kill_flag = write_flags.contains(WriteFlags::FUSE_WRITE_KILL_SUIDGID);
        // The payload is owned by the kernel for the duration of this call; the
        // job outlives the call, so it must own its bytes.
        let data = data.to_vec();
        let res = self.inner.mutate(move |core| {
            let root = core.root();
            let st = core.getattr(ino_raw, root)?;
            if !has_permission_grouped(uid, gid, &groups, &st, 0o2) {
                return Err(OrfsError::PermissionDenied);
            }
            // O_APPEND: honour the authoritative end-of-file rather than the
            // possibly-stale offset the kernel supplied.
            let effective = if append { st.size } else { offset };
            let kill_setid = kill_flag
                || (uid != 0 && uid != st.uid && st.mode & (libc::S_ISUID | libc::S_ISGID) != 0);
            let n = core.write_at_killpriv(ino_raw, effective, &data, kill_setid)?;
            Ok(n as i64)
        });
        match res {
            Ok(n) => {
                let mut m = self.inner.metrics.lock();
                m.writes += 1;
                m.byte_writes += n as u64;
                drop(m);
                self.invalidate_inode(ino.0);
                reply.written(n as u32);
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        // NOT a durability barrier: every mutation already committed through the
        // sequencer before it was acknowledged. There is nothing buffered to
        // report here (research §14).
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let removed = self.inner.remove_handle(fh.0);
        let mut m = self.inner.metrics.lock();
        m.releases += 1;
        if removed.is_some() {
            m.open_handles = m.open_handles.saturating_sub(1);
        }
        drop(m);
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        if let Err(e) = self.ensure_writable() {
            // fsync on a read-only mount needs no durability work.
            let _ = e;
        }
        let mut core = self.inner.core.lock();
        match core.sync() {
            Ok(()) => {
                drop(core);
                self.inner.metrics.lock().fsyncs += 1;
                reply.ok();
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn opendir(&self, req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        let view = self.read_view();
        let root = view.root();
        let st = match view.getattr(ino.0, root) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        if st.kind != InodeType::Directory {
            return reply.error(Errno::ENOTDIR);
        }
        if !has_permission_grouped(
            req.uid(),
            req.gid(),
            &caller_groups(req.pid()),
            &st,
            0o4 | 0o1,
        ) {
            return reply.error(Errno::EACCES);
        }
        let listing = match self.inner.build_dir_listing(view.as_ref(), ino.0) {
            Ok(l) => l,
            Err(e) => return reply.error(errno(&e)),
        };
        let fh = self.inner.register_dir(ino.0, listing);
        let mut m = self.inner.metrics.lock();
        m.opendirs += 1;
        m.open_handles += 1;
        drop(m);
        reply.opened(FileHandle(fh), FopenFlags::FOPEN_CACHE_DIR);
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let handle = match self.inner.handle(fh.0) {
            Some(h) if h.is_dir => h,
            _ => return reply.error(Errno::EBADF),
        };
        let entries = match handle.dir {
            Some(e) => e,
            None => return reply.error(Errno::EBADF),
        };
        let start = offset as usize;
        for (idx, entry) in entries.iter().enumerate().skip(start) {
            // Cookie is the index of the *next* entry.
            if reply.add(
                INodeNo(entry.ino),
                (idx + 1) as u64,
                entry.kind,
                OsStr::from_bytes(&entry.name),
            ) {
                break;
            }
        }
        let _ = ino;
        reply.ok();
    }

    fn readdirplus(
        &self,
        _req: &Request,
        ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectoryPlus,
    ) {
        let handle = match self.inner.handle(fh.0) {
            Some(h) if h.is_dir => h,
            _ => return reply.error(Errno::EBADF),
        };
        let entries = match handle.dir {
            Some(e) => e,
            None => return reply.error(Errno::EBADF),
        };
        let view = self.read_view();
        let root = view.root();
        let start = offset as usize;
        let mut acquired: Vec<u64> = Vec::new();
        for (idx, entry) in entries.iter().enumerate().skip(start) {
            let st = match view.getattr(entry.ino, root) {
                Ok(st) => st,
                Err(_) => continue,
            };
            if reply.add(
                INodeNo(entry.ino),
                (idx + 1) as u64,
                OsStr::from_bytes(&entry.name),
                &self.options.attr_ttl,
                &file_attr(&st),
                GENERATION,
            ) {
                break;
            }
            acquired.push(entry.ino);
        }
        // Each readdirplus entry we hand back takes a kernel lookup reference.
        for ino in acquired {
            self.inner.record_lookup(ino);
        }
        let _ = ino;
        reply.ok();
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        let removed = self.inner.remove_handle(fh.0);
        let mut m = self.inner.metrics.lock();
        m.releasedirs += 1;
        if removed.is_some() {
            m.open_handles = m.open_handles.saturating_sub(1);
        }
        drop(m);
        reply.ok();
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let mut core = self.inner.core.lock();
        match core.sync() {
            Ok(()) => {
                drop(core);
                self.inner.metrics.lock().fsyncs += 1;
                reply.ok();
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let stats = match self.options.statfs {
            StatfsMode::LogicalPlenum => StatfsValues {
                blocks: u64::MAX,
                bfree: u64::MAX,
                bavail: u64::MAX,
                files: u64::MAX,
                ffree: u64::MAX,
                bsize: BLOCK_SIZE,
            },
            StatfsMode::PhysicalSafe => match statvfs(&self.inner.backing) {
                Some(s) => s,
                None => return reply.error(Errno::EIO),
            },
        };
        reply.statfs(
            stats.blocks,
            stats.bfree,
            stats.bavail,
            stats.files,
            stats.ffree,
            stats.bsize,
            NAME_MAX,
            stats.bsize,
        );
    }

    fn setxattr(
        &self,
        req: &Request,
        ino: INodeNo,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        if position != 0 {
            return reply.error(Errno::EINVAL);
        }
        if flags & libc::XATTR_CREATE != 0 && flags & libc::XATTR_REPLACE != 0 {
            return reply.error(Errno::EINVAL);
        }
        let actor_uid = req.uid();
        let actor_gid = req.gid();
        let groups = caller_groups(req.pid());
        let ino_raw = ino.0;
        let name_bytes = name.as_bytes().to_vec();
        let value = value.to_vec();
        let create = flags & libc::XATTR_CREATE != 0;
        let replace = flags & libc::XATTR_REPLACE != 0;
        let res = self.inner.mutate(move |core| {
            let root = core.root();
            let st = core.getattr(ino_raw, root)?;
            if !has_permission_grouped(actor_uid, actor_gid, &groups, &st, 0o2) {
                return Err(OrfsError::PermissionDenied);
            }
            let present = core.getxattr(ino_raw, &name_bytes, root).is_ok();
            if replace && !present {
                return Err(OrfsError::NoData);
            }
            core.setxattr(ino_raw, &name_bytes, &value, create)?;
            Ok(0)
        });
        match res {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn getxattr(&self, req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: ReplyXattr) {
        let view = self.read_view();
        let root = view.root();
        // Access rule: reading an attribute requires read permission on the
        // inode, symmetric with reading its contents. No namespace (including
        // `security.*`/`trusted.*`) bypasses this check.
        let st = match view.getattr(ino.0, root) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        if !has_permission_grouped(req.uid(), req.gid(), &caller_groups(req.pid()), &st, 0o4) {
            return reply.error(Errno::EACCES);
        }
        match view.getxattr(ino.0, name.as_bytes(), root) {
            Ok(value) => {
                if size == 0 {
                    reply.size(value.len() as u32);
                } else if value.len() as u32 > size {
                    reply.error(Errno::ERANGE);
                } else {
                    reply.data(&value);
                }
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn listxattr(&self, req: &Request, ino: INodeNo, size: u32, reply: ReplyXattr) {
        let view = self.read_view();
        let root = view.root();
        let st = match view.getattr(ino.0, root) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        if !has_permission_grouped(req.uid(), req.gid(), &caller_groups(req.pid()), &st, 0o4) {
            return reply.error(Errno::EACCES);
        }
        match view.listxattr(ino.0, root) {
            Ok(names) => {
                let mut buf = Vec::new();
                for n in &names {
                    buf.extend_from_slice(n);
                    buf.push(0);
                }
                if size == 0 {
                    reply.size(buf.len() as u32);
                } else if buf.len() as u32 > size {
                    reply.error(Errno::ERANGE);
                } else {
                    reply.data(&buf);
                }
            }
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn removexattr(&self, req: &Request, ino: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        let actor_uid = req.uid();
        let actor_gid = req.gid();
        let groups = caller_groups(req.pid());
        let ino_raw = ino.0;
        let name_bytes = name.as_bytes().to_vec();
        let res = self.inner.mutate(move |core| {
            let root = core.root();
            let st = core.getattr(ino_raw, root)?;
            if !has_permission_grouped(actor_uid, actor_gid, &groups, &st, 0o2) {
                return Err(OrfsError::PermissionDenied);
            }
            core.removexattr(ino_raw, &name_bytes)?;
            Ok(0)
        });
        match res {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn access(&self, req: &Request, ino: INodeNo, mask: AccessFlags, reply: ReplyEmpty) {
        let view = self.read_view();
        let root = view.root();
        let st = match view.getattr(ino.0, root) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        let bits = mask.bits() as u32;
        if bits == 0 {
            return reply.ok();
        }
        if has_permission_grouped(
            req.uid(),
            req.gid(),
            &caller_groups(req.pid()),
            &st,
            bits & 0o7,
        ) {
            reply.ok();
        } else {
            reply.error(Errno::EACCES);
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        let uid = req.uid();
        let gid = req.gid();
        let groups = caller_groups(req.pid());
        let parent_ino = parent.0;
        let name_bytes = name.as_bytes().to_vec();
        let perm = mode & 0o7777;
        let res = self.inner.mutate(move |core| {
            check_create_uid(&*core, uid, gid, &groups, parent_ino, 0o2 | 0o1)?;
            let ino = core.create(parent_ino, &name_bytes, perm, uid, gid)?;
            Ok(ino as i64)
        });
        let ino = match res {
            Ok(i) => i as u64,
            Err(e) => return reply.error(errno(&e)),
        };
        let view = self.read_view();
        let st = match view.getattr(ino, view.root()) {
            Ok(st) => st,
            Err(e) => return reply.error(errno(&e)),
        };
        let fh = self.inner.register_file(ino, flags);
        let mut m = self.inner.metrics.lock();
        m.create += 1;
        m.open_handles += 1;
        drop(m);
        self.inner.record_lookup(ino);
        self.invalidate_entry(parent.0, name.as_bytes());
        reply.created(
            &self.options.attr_ttl,
            &file_attr(&st),
            GENERATION,
            FileHandle(fh),
            self.fopen_flags(),
        );
    }

    fn getlk(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        reply: ReplyLock,
    ) {
        // Declared limitation: OrFS does not negotiate FUSE_POSIX_LOCKS. The
        // documented ENOSYS reply instructs the kernel to service record locks
        // with its own local lock manager, which is correct for a single-node
        // mount. See docs/FUSE-SEMANTICS.md §Locking.
        reply.error(Errno::ENOSYS);
    }

    #[allow(clippy::too_many_arguments)]
    fn setlk(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        _start: u64,
        _end: u64,
        _typ: i32,
        _pid: u32,
        _sleep: bool,
        reply: ReplyEmpty,
    ) {
        // See `getlk`. FLOCK is likewise delegated to the kernel (OrFS does not
        // negotiate FUSE_FLOCK_LOCKS).
        reply.error(Errno::ENOSYS);
    }

    fn fallocate(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        let ino_raw = ino.0;
        let res = self.inner.mutate(move |core| {
            let root = core.root();
            let st = core.getattr(ino_raw, root)?;
            if st.kind != InodeType::File {
                return Err(OrfsError::IsADirectory);
            }
            let keep = mode & libc::FALLOC_FL_KEEP_SIZE != 0;
            let punch = mode & libc::FALLOC_FL_PUNCH_HOLE != 0;
            let zero = mode & libc::FALLOC_FL_ZERO_RANGE != 0;
            let collapse = mode & libc::FALLOC_FL_COLLAPSE_RANGE != 0;
            let insert = mode & libc::FALLOC_FL_INSERT_RANGE != 0;
            let unshare = mode & libc::FALLOC_FL_UNSHARE_RANGE != 0;
            if collapse || insert || unshare {
                Err(OrfsError::Unsupported(
                    "fallocate collapse/insert/unshare range".into(),
                ))
            } else if punch {
                // PUNCH_HOLE must be combined with KEEP_SIZE.
                if !keep {
                    Err(OrfsError::InvalidArgument(
                        "FALLOC_FL_PUNCH_HOLE requires FALLOC_FL_KEEP_SIZE".into(),
                    ))
                } else {
                    core.zero_range(ino_raw, offset, length)
                }
            } else if zero {
                core.zero_range(ino_raw, offset, length)
            } else if keep {
                // Plain allocation without a size change: a sparse file is already
                // "allocated" logically, so this is a no-op.
                Ok(())
            } else {
                let end = offset.checked_add(length).ok_or(OrfsError::Overflow {
                    what: "fallocate range",
                })?;
                if end > st.size {
                    core.setattr(
                        ino_raw,
                        &SetAttr {
                            size: Some(end),
                            ..Default::default()
                        },
                    )
                } else {
                    Ok(())
                }
            }?;
            Ok(0)
        });
        match res {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(errno(&e)),
        }
    }

    fn lseek(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        let hole = match whence {
            libc::SEEK_DATA => false,
            libc::SEEK_HOLE => true,
            // SEEK_SET/CUR/END are resolved entirely in the kernel before a
            // FUSE request is generated.
            _ => return reply.error(Errno::EINVAL),
        };
        if offset < 0 {
            return reply.error(Errno::EINVAL);
        }
        let view = self.read_view();
        let root = view.root();
        match view.seek_data_hole(ino.0, root, offset as u64, hole) {
            Ok(Some(pos)) => reply.offset(pos as i64),
            Ok(None) => reply.error(Errno::ENXIO),
            Err(e) => reply.error(errno(&e)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn copy_file_range(
        &self,
        _req: &Request,
        ino_in: INodeNo,
        _fh_in: FileHandle,
        offset_in: u64,
        ino_out: INodeNo,
        _fh_out: FileHandle,
        offset_out: u64,
        len: u64,
        flags: CopyFileRangeFlags,
        reply: ReplyWrite,
    ) {
        if let Err(e) = self.ensure_writable() {
            return reply.error(errno(&e));
        }
        if flags.bits() != 0 {
            return reply.error(Errno::EINVAL);
        }
        if len == 0 {
            return reply.written(0);
        }
        let chunk = len.min(COPY_CHUNK);
        let in_raw = ino_in.0;
        let out_raw = ino_out.0;
        let res = self.inner.mutate(move |core| {
            let root = core.root();
            let data = core.read_at(in_raw, root, offset_in, chunk as u32)?;
            if data.is_empty() {
                return Ok(0);
            }
            let n = core.write_at(out_raw, offset_out, &data)?;
            Ok(n as i64)
        });
        match res {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(errno(&e)),
        }
    }
}

impl<C: OrfsCore + Send + 'static> OrfsFuse<C> {
    /// Conservative write-through: no page cache is retained across opens; the
    /// kernel still caches within a single open. `direct_io` bypasses the page
    /// cache entirely.
    pub(crate) fn fopen_flags(&self) -> FopenFlags {
        if self.options.direct_io {
            FopenFlags::FOPEN_DIRECT_IO
        } else {
            FopenFlags::empty()
        }
    }
}

// ---------------------------------------------------------------------------
// Permission helpers
// ---------------------------------------------------------------------------

fn acc_mask(mode: fuser::OpenAccMode) -> u32 {
    match mode {
        fuser::OpenAccMode::O_RDONLY => 0o4,
        fuser::OpenAccMode::O_WRONLY => 0o2,
        fuser::OpenAccMode::O_RDWR => 0o4 | 0o2,
    }
}

/// Whether the process that issued the FUSE request (identified by `pid`) is a
/// member of `target_gid`, through its effective group or a supplementary group.
///
/// A FUSE request carries only the caller's fsuid/fsgid, never its supplementary
/// groups, so the daemon reads them from the kernel's own
/// `/proc/<pid>/status` `Groups:` line — the same set Linux's `chgrp_ok`
/// consults. The requesting process is blocked in the FUSE call, so its `/proc`
/// entry is stable. A missing or unreadable entry yields `false` (deny), which
/// is conservative: it can refuse a permitted `chgrp` but never fabricate one.
pub(crate) fn caller_in_group(pid: u32, egid: u32, target_gid: u32) -> bool {
    egid == target_gid || caller_groups(pid).contains(&target_gid)
}

/// The requesting process's supplementary groups (`/proc/<pid>/status` `Groups:`).
///
/// Used to classify POSIX access with full group membership (`in_group_p`), so a
/// caller whose only access is via a supplementary group is granted the group
/// class. A missing/unreadable entry yields an empty set: the caller is then
/// classified by its effective ids alone.
pub(crate) fn caller_groups(pid: u32) -> Vec<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Groups:"))
                .map(str::to_owned)
        })
        .map(|groups| {
            groups
                .split_whitespace()
                .filter_map(|g| g.parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn check_create_uid<C: OrfsCore>(
    core: &C,
    uid: u32,
    gid: u32,
    groups: &[u32],
    parent: u64,
    mask: u32,
) -> Result<()> {
    check_dir_write_uid(core, uid, gid, groups, parent, mask)
}

pub(crate) fn check_dir_write_uid<C: OrfsCore>(
    core: &C,
    uid: u32,
    gid: u32,
    groups: &[u32],
    parent: u64,
    mask: u32,
) -> Result<()> {
    let st = core.getattr(parent, core.root())?;
    if st.kind != InodeType::Directory {
        return Err(OrfsError::NotADirectory);
    }
    if !has_permission_grouped(uid, gid, groups, &st, mask) {
        return Err(OrfsError::PermissionDenied);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// statfs
// ---------------------------------------------------------------------------

struct StatfsValues {
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    bsize: u32,
}

fn statvfs(path: &Path) -> Option<StatfsValues> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a valid, aligned,
    // fully-owned buffer that `statvfs` initialises. No pointer is retained.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return None;
    }
    Some(StatfsValues {
        blocks: st.f_blocks as u64,
        bfree: st.f_bfree as u64,
        bavail: st.f_bavail as u64,
        files: st.f_files as u64,
        ffree: st.f_ffree as u64,
        bsize: if st.f_bsize == 0 {
            BLOCK_SIZE
        } else {
            st.f_bsize as u32
        },
    })
}

// ---------------------------------------------------------------------------
// Mount / unmount
// ---------------------------------------------------------------------------

/// The live request-handling session behind a mount: either the classical
/// `fuser`-managed `/dev/fuse` session (F0/F1) or the native F2 session.
enum MountSession {
    Fuser(BackgroundSession),
    Native(crate::fuse_native::NativeMount),
}

/// A live mounted OrFS volume.
pub struct OrfsMount {
    session: MountSession,
    notifier: NotifierCell,
    /// The requested FUSE transport.
    transport_requested: Transport,
    /// The backing-I/O engine actually in use (never lies about `Uring`).
    pub backing_io_used: BackingIo,
    /// The durability profile in force.
    pub durability: DurabilityMode,
    /// The live FUSE-over-`io_uring` negotiation result from `INIT`.
    negotiation: Arc<Mutex<FuseUringNegotiation>>,
    /// The shared daemon-operation counters. Present for every transport, so the
    /// number of requests that actually reached the daemon can be compared with
    /// the application-level syscall count.
    daemon_metrics: Arc<Mutex<Metrics>>,
}

impl OrfsMount {
    /// Unmount and wait for the request loop to end.
    pub fn unmount(self) -> io::Result<()> {
        match self.session {
            MountSession::Fuser(s) => s.umount_and_join(),
            MountSession::Native(n) => n.unmount(),
        }
    }

    /// Wait for the session to end (for example after an external unmount).
    pub fn join(self) -> io::Result<()> {
        match self.session {
            MountSession::Fuser(s) => s.join(),
            MountSession::Native(n) => n.join(),
        }
    }

    /// A notifier for explicit kernel cache invalidation. `None` for a native F2
    /// mount: the `fuser` `Notifier` is not available off a `fuser` session.
    pub fn notifier(&self) -> Option<Notifier> {
        self.notifier.lock().clone()
    }

    /// The transport the caller requested.
    pub fn transport_requested(&self) -> Transport {
        self.transport_requested
    }

    /// The transport profile **actually in force** (F0/F1/F2).
    ///
    /// F2 is reported only when a real FUSE-over-`io_uring` ring negotiated and
    /// engaged; backing `io_uring` on its own is F1, never F2.
    pub fn transport_used(&self) -> TransportProfile {
        let neg = self.negotiation.lock();
        fuse_uring::classify(
            self.transport_requested.requests_uring_fuse(),
            self.backing_io_used == BackingIo::Uring,
            Some(&neg),
        )
    }

    /// A one-line description of the transport in force, including the fallback
    /// reason when F2 was requested but is not active.
    pub fn transport_description(&self) -> String {
        let used = self.transport_used();
        let base = used.describe(self.backing_io_used == BackingIo::Uring);
        if self.transport_requested.requests_uring_fuse() && used != TransportProfile::F2 {
            let neg = self.negotiation.lock();
            format!("{base}; F2 unavailable: {}", neg.describe())
        } else {
            base
        }
    }

    /// A snapshot of the daemon-operation counters: how many requests of each
    /// kind actually reached the daemon, for every transport. This is the
    /// daemon-side counter against which the application-level syscall count is
    /// compared in the performance court.
    pub fn daemon_metrics(&self) -> Metrics {
        self.daemon_metrics.lock().clone()
    }

    /// The live FUSE-over-`io_uring` negotiation result.
    pub fn fuse_uring_negotiation(&self) -> FuseUringNegotiation {
        self.negotiation.lock().clone()
    }

    /// F2 session counters, present only when this mount is the native
    /// FUSE-over-`io_uring` session (proof the ring carried requests).
    pub fn f2_stats(&self) -> Option<crate::fuse_native::NativeStats> {
        match &self.session {
            MountSession::Native(n) => Some(n.stats()),
            MountSession::Fuser(_) => None,
        }
    }

    /// F2 environment facts, present only for a native F2 mount.
    pub fn f2_environment(&self) -> Option<crate::fuse_native::NativeEnvironment> {
        match &self.session {
            MountSession::Native(n) => Some(n.environment()),
            MountSession::Fuser(_) => None,
        }
    }

    /// A full report of FUSE-over-`io_uring` availability for this mount.
    pub fn fuse_uring_report(&self) -> FuseUringReport {
        let discovery = fuse_uring::Discovery::probe();
        let preconditions = discovery.preconditions();
        let negotiation = Some(self.fuse_uring_negotiation());
        FuseUringReport {
            discovery,
            preconditions,
            negotiation,
        }
    }
}

fn build_core(
    backing: &Path,
    opts: &MountOptions,
) -> Result<(Namespace, crate::uring::UringReport)> {
    let mode = if opts.read_only {
        OpenMode::ReadOnly
    } else {
        OpenMode::ReadWrite
    };
    let mut core = Namespace::open(backing, mode, opts.durability)?;
    // Phase 23: a configured authoritative reserve bounds growth so a full
    // backing returns ENOSPC before it fills the device (research §30, §31).
    if opts.capacity_reserve_bytes > 0 {
        core.set_capacity_policy(
            crate::capacity::CapacityPolicy::new().with_reserve(opts.capacity_reserve_bytes),
        );
    }
    let report = if opts.backing_io == BackingIo::Uring {
        let cfg = crate::uring::UringConfig {
            enabled: true,
            ..Default::default()
        };
        core.enable_backing_io(&cfg)
    } else {
        crate::uring::UringReport::disabled()
    };
    if let Some(profile) = opts.manifest {
        let cfg = crate::manifestation::ManifestationConfig {
            workers: opts.manifest_workers,
            synchronous: opts.manifest_sync,
            profile,
            ..Default::default()
        };
        let rep = core.enable_manifestation(cfg)?;
        eprintln!(
            "orfs: manifestation enabled (profile {}, backend {}, {} worker(s), queue {}; \
             recovered {} generation(s), {} rejected)",
            rep.profile,
            rep.backend,
            rep.workers,
            rep.queue_capacity,
            rep.recovered_generations,
            rep.recovered_rejected,
        );
    }
    Ok((core, report))
}

fn build_config(opts: &MountOptions) -> Config {
    let mut config = Config::default();
    // Serve FUSE requests from several threads so concurrent readers can actually
    // run in parallel. Combined with the immutable read view (Phase 19) a read no
    // longer serialises the whole filesystem behind the core lock. The `fuser`
    // read-dispatch loop itself is concurrent when `n_threads > 1`.
    config.n_threads = Some(
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1),
    );
    let mut options = vec![
        MountOption::FSName("orfs".to_string()),
        MountOption::Subtype("orfs".to_string()),
    ];
    if opts.read_only {
        options.push(MountOption::RO);
    } else {
        options.push(MountOption::RW);
    }
    if opts.default_permissions {
        options.push(MountOption::DefaultPermissions);
    }
    if opts.allow_other || opts.auto_unmount {
        options.push(MountOption::AutoUnmount);
    }
    config.mount_options = options;
    config.acl = if opts.allow_other {
        SessionACL::All
    } else if opts.auto_unmount {
        SessionACL::RootAndOwner
    } else {
        SessionACL::Owner
    };
    config
}

fn attach<C: OrfsCore + Send + 'static>(
    fs: OrfsFuse<C>,
    mountpoint: &Path,
    config: &Config,
) -> Result<(Session<OrfsFuse<C>>, NotifierCell)> {
    let notifier = fs.notifier.clone();
    let session = Session::new(fs, mountpoint, config)?;
    *notifier.lock() = Some(session.notifier());
    Ok((session, notifier))
}

/// Mount an existing OrFS backing volume in the background.
///
/// When `--transport fuse-uring` is requested, the native F2 session is tried
/// first; if it cannot engage for any reason, the exact reason is reported and
/// the classical `/dev/fuse` transport is used instead, with byte-identical
/// filesystem contents.
pub fn spawn(backing: &Path, mountpoint: &Path, opts: &MountOptions) -> Result<OrfsMount> {
    if opts.transport.requests_uring_fuse() {
        match crate::fuse_native::prepare(mountpoint, opts) {
            Ok(prepared) => {
                let (core, report) = build_core(backing, opts)?;
                let backing_io_used = if report.engaged {
                    BackingIo::Uring
                } else {
                    BackingIo::Sync
                };
                match prepared.launch(core, backing.to_path_buf()) {
                    Ok(native) => {
                        let negotiation = native.negotiation_cell();
                        let daemon_metrics = native.metrics_cell();
                        return Ok(OrfsMount {
                            session: MountSession::Native(native),
                            notifier: Arc::new(Mutex::new(None)),
                            transport_requested: opts.transport,
                            backing_io_used,
                            durability: opts.durability,
                            negotiation,
                            daemon_metrics,
                        });
                    }
                    Err(e) => eprintln!(
                        "orfs: warning: native F2 session failed to start ({e}); \
                         falling back to the classical /dev/fuse transport"
                    ),
                }
            }
            Err(reason) => eprintln!(
                "orfs: F2 not engaged ({reason}); falling back to the classical \
                 /dev/fuse transport"
            ),
        }
    }
    let (core, report) = build_core(backing, opts)?;
    let backing_io_used = if report.engaged {
        BackingIo::Uring
    } else {
        BackingIo::Sync
    };
    let fs = OrfsFuse::new(core, backing.to_path_buf(), *opts);
    let negotiation = fs.negotiation_cell();
    let daemon_metrics = fs.metrics_cell();
    let config = build_config(opts);
    let (session, notifier) = attach(fs, mountpoint, &config)?;
    let session = session.spawn()?;
    Ok(OrfsMount {
        session: MountSession::Fuser(session),
        notifier,
        transport_requested: opts.transport,
        backing_io_used,
        durability: opts.durability,
        negotiation,
        daemon_metrics,
    })
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static WATCH_STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    // Async-signal-safe: only an atomic store.
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Install SIGINT/SIGTERM handlers that flip [`INTERRUPTED`].
///
/// SAFETY: the handler performs only a single atomic store and returns, which is
/// async-signal-safe. `libc::signal` is used only to install that handler.
fn install_signal_handlers() {
    let handler = on_signal as extern "C" fn(libc::c_int);
    unsafe {
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handler as libc::sighandler_t);
    }
}

/// Mount and run in the foreground until unmounted (external `orfs unmount`, a
/// signal, or an error).
pub fn run(backing: &Path, mountpoint: &Path, opts: &MountOptions) -> Result<()> {
    if opts.transport.requests_uring_fuse() {
        match crate::fuse_native::prepare(mountpoint, opts) {
            Ok(prepared) => {
                let (core, report) = build_core(backing, opts)?;
                eprintln!("orfs: {}", report.describe());
                match prepared.launch(core, backing.to_path_buf()) {
                    Ok(native) => return run_native_foreground(native, mountpoint),
                    Err(e) => eprintln!(
                        "orfs: warning: native F2 session failed to start ({e}); \
                         falling back to the classical /dev/fuse transport"
                    ),
                }
            }
            Err(reason) => eprintln!(
                "orfs: F2 not engaged ({reason}); falling back to the classical \
                 /dev/fuse transport"
            ),
        }
    }
    let (core, report) = build_core(backing, opts)?;
    eprintln!("orfs: {}", report.describe());
    let fs = OrfsFuse::new(core, backing.to_path_buf(), *opts);
    let config = build_config(opts);
    run_session(fs, mountpoint, &config)
}

/// Run a native F2 session in the foreground until externally unmounted or
/// interrupted, mirroring [`run_session`]'s signal handling.
fn run_native_foreground(native: crate::fuse_native::NativeMount, mountpoint: &Path) -> Result<()> {
    INTERRUPTED.store(false, Ordering::SeqCst);
    WATCH_STOP.store(false, Ordering::SeqCst);
    install_signal_handlers();
    let stop = native.stop_cell();
    let mnt = mountpoint.to_path_buf();
    let watcher = std::thread::Builder::new()
        .name("orfs-signal".to_string())
        .spawn(move || {
            while !WATCH_STOP.load(Ordering::SeqCst) && !INTERRUPTED.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(50));
            }
            if INTERRUPTED.load(Ordering::SeqCst) {
                let _ = unmount(&mnt);
                stop.store(true, Ordering::SeqCst);
            }
        })
        .map_err(OrfsError::Io)?;
    let result = native.join();
    WATCH_STOP.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    result.map_err(OrfsError::Io)
}

/// Mount a historical snapshot **read-only** and run in the foreground.
///
/// The mount serves the namespace exactly as of `root`: every read is answered
/// from the prefix `L[0:root]`, and every mutation returns `EROFS` because the
/// snapshot core is read-only *and* the kernel mount is flagged read-only
/// (research §7.4, §14).
pub fn run_snapshot(
    backing: &Path,
    mountpoint: &Path,
    root: u64,
    opts: &MountOptions,
) -> Result<()> {
    let opts = MountOptions {
        read_only: true,
        ..*opts
    };
    let snap = Snapshot::open_dir(backing, root)?;
    eprintln!(
        "orfs: snapshot mount of {} at root {root} (read-only; pinned for the mount lifetime)",
        snap.identity()
    );
    // Prefer the native F2 session when passthrough was requested: only a session
    // that owns the `/dev/fuse` descriptor can register backing files. If it
    // cannot engage for any reason, fall back to the classical transport with
    // byte-identical reads (never a silent capability claim).
    if opts.passthrough {
        // The native F2 session is the only transport that owns `/dev/fuse`;
        // request it explicitly for the passthrough attempt.
        let native_opts = MountOptions {
            transport: Transport::FuseUring,
            ..opts
        };
        match crate::fuse_native::prepare(mountpoint, &native_opts) {
            Ok(prepared) => match prepared.launch(snap, backing.to_path_buf()) {
                Ok(native) => return run_native_foreground(native, mountpoint),
                Err(e) => eprintln!(
                    "orfs: warning: native passthrough session failed to start ({e}); \
                     falling back to the classical /dev/fuse transport"
                ),
            },
            Err(reason) => eprintln!(
                "orfs: native passthrough session not engaged ({reason}); \
                 falling back to the classical /dev/fuse transport"
            ),
        }
    }
    let snap = Snapshot::open_dir(backing, root)?;
    let fs = OrfsFuse::new(snap, backing.to_path_buf(), opts);
    let config = build_config(&opts);
    run_session(fs, mountpoint, &config)
}

/// Mount a historical snapshot read-only on the **native** F2 session with
/// kernel FUSE passthrough enabled, in the background.
///
/// Unlike [`spawn_snapshot`], this never silently falls back: if the native
/// session (the only transport that owns `/dev/fuse`, and therefore the only one
/// that can register backing files) cannot engage, it returns an error. The
/// passthrough court uses this so a green run proves real kernel engagement.
pub fn spawn_snapshot_native(
    backing: &Path,
    mountpoint: &Path,
    root: u64,
    opts: &MountOptions,
) -> Result<OrfsMount> {
    let opts = MountOptions {
        read_only: true,
        transport: Transport::FuseUring,
        ..*opts
    };
    let snap = Snapshot::open_dir(backing, root)?;
    let prepared = crate::fuse_native::prepare(mountpoint, &opts).map_err(|e| {
        OrfsError::Unsupported(format!("native F2 snapshot mount did not engage: {e}"))
    })?;
    let native = prepared.launch(snap, backing.to_path_buf()).map_err(|e| {
        OrfsError::Unsupported(format!("native F2 snapshot session did not start: {e}"))
    })?;
    let negotiation = native.negotiation_cell();
    let daemon_metrics = native.metrics_cell();
    Ok(OrfsMount {
        session: MountSession::Native(native),
        notifier: Arc::new(Mutex::new(None)),
        transport_requested: opts.transport,
        backing_io_used: BackingIo::Sync,
        durability: opts.durability,
        negotiation,
        daemon_metrics,
    })
}

/// Mount a historical snapshot read-only in the background (tests/embedding).
pub fn spawn_snapshot(
    backing: &Path,
    mountpoint: &Path,
    root: u64,
    opts: &MountOptions,
) -> Result<OrfsMount> {
    let opts = MountOptions {
        read_only: true,
        ..*opts
    };
    let snap = Snapshot::open_dir(backing, root)?;
    let fs = OrfsFuse::new(snap, backing.to_path_buf(), opts);
    let daemon_metrics = fs.metrics_cell();
    let config = build_config(&opts);
    let (session, notifier) = attach(fs, mountpoint, &config)?;
    let session = session.spawn()?;
    Ok(OrfsMount {
        session: MountSession::Fuser(session),
        notifier,
        transport_requested: Transport::Fuse,
        backing_io_used: BackingIo::Sync,
        durability: opts.durability,
        negotiation: Arc::new(Mutex::new(FuseUringNegotiation::not_requested())),
        daemon_metrics,
    })
}

/// Run a constructed filesystem session until unmounted or interrupted.
fn run_session<C: OrfsCore + Send + 'static>(
    fs: OrfsFuse<C>,
    mountpoint: &Path,
    config: &Config,
) -> Result<()> {
    let (mut session, _notifier) = attach(fs, mountpoint, config)?;

    INTERRUPTED.store(false, Ordering::SeqCst);
    WATCH_STOP.store(false, Ordering::SeqCst);
    install_signal_handlers();
    let mut unmounter = session.unmount_callable();
    let watcher = std::thread::Builder::new()
        .name("orfs-signal".to_string())
        .spawn(move || {
            while !WATCH_STOP.load(Ordering::SeqCst) && !INTERRUPTED.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(50));
            }
            if INTERRUPTED.load(Ordering::SeqCst) {
                let _ = unmounter.unmount();
            }
        })
        .map_err(OrfsError::Io)?;

    let result = session.run();
    WATCH_STOP.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    result.map_err(OrfsError::Io)
}

/// Unmount the FUSE filesystem at `mountpoint`.
///
/// Prefers the setuid `fusermount3` helper (works unprivileged); falls back to a
/// direct `umount2(MNT_DETACH)`, which needs `CAP_SYS_ADMIN`.
pub fn unmount(mountpoint: &Path) -> Result<()> {
    if let Ok(status) = Command::new("fusermount3")
        .arg("-u")
        .arg(mountpoint)
        .status()
    {
        if status.success() {
            return Ok(());
        }
    }
    if let Ok(status) = Command::new("fusermount")
        .arg("-u")
        .arg(mountpoint)
        .status()
    {
        if status.success() {
            return Ok(());
        }
    }
    // Last resort: lazy unmount via the mount syscall.
    if let Ok(c) = CString::new(mountpoint.as_os_str().as_bytes()) {
        // SAFETY: `c` is a valid NUL-terminated path; `umount2` performs a lazy
        // detach and retains no pointer.
        let rc = unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        return Err(OrfsError::Io(io::Error::new(
            err.kind(),
            format!("failed to unmount {}: {err}", mountpoint.display()),
        )));
    }
    Err(OrfsError::InvalidArgument(
        "mount path is not a valid C string".into(),
    ))
}

// ---------------------------------------------------------------------------
// Tests (bookkeeping, cookies, permissions, seek)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inode::has_permission;

    fn options() -> MountOptions {
        MountOptions::default()
    }

    #[test]
    fn lookup_table_counts_acquisitions_and_forgets() {
        let mut t = LookupTable::default();
        t.acquire(2);
        t.acquire(2);
        t.acquire(3);
        assert_eq!(t.outstanding(2), 2);
        assert_eq!(t.outstanding(3), 1);
        assert_eq!(t.forget(2, 1), 1);
        assert_eq!(t.forget(2, 5), 0);
        assert_eq!(t.outstanding(2), 0);
        assert_eq!(t.tracked_inodes(), 1);
    }

    #[test]
    fn handle_table_ids_are_distinct_from_inodes() {
        let mut t = HandleTable::default();
        let a = t.insert(Handle {
            ino: 1,
            is_dir: false,
            flags: libc::O_RDONLY,
            dir: None,
            backing: None,
        });
        let b = t.insert(Handle {
            ino: 2,
            is_dir: true,
            flags: 0,
            dir: Some(vec![]),
            backing: None,
        });
        assert_ne!(a, b);
        assert_eq!(t.get(a).unwrap().ino, 1);
        assert!(t.get(b).unwrap().is_dir);
        assert!(t.remove(a).is_some());
        assert!(t.get(a).is_none());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn dir_cookies_are_stable_indexes() {
        let listing = [
            DirEntryView {
                name: b".".to_vec(),
                ino: 1,
                kind: FuseFileType::Directory,
            },
            DirEntryView {
                name: b"..".to_vec(),
                ino: 1,
                kind: FuseFileType::Directory,
            },
            DirEntryView {
                name: b"a".to_vec(),
                ino: 2,
                kind: FuseFileType::RegularFile,
            },
        ];
        // Cookie convention: entry i is returned with offset i+1.
        assert_eq!(listing[0].name, b".");
        assert_eq!(listing[1].name, b"..");
        assert_eq!(listing[2].ino, 2);
    }

    #[test]
    fn permission_model_is_class_based() {
        let st = InodeStat {
            id: 5,
            kind: InodeType::File,
            mode: 0o640,
            uid: 1000,
            gid: 100,
            nlink: 1,
            size: 0,
            atime: Timespec::ZERO,
            mtime: Timespec::ZERO,
            ctime: Timespec::ZERO,
            version: 1,
            blocks: 0,
        };
        assert!(has_permission(1000, 999, &st, 0o4)); // owner read
        assert!(has_permission(1000, 999, &st, 0o2)); // owner write
        assert!(!has_permission(1000, 999, &st, 0o1)); // owner no exec
        assert!(has_permission(2000, 100, &st, 0o4)); // group read
        assert!(!has_permission(2000, 100, &st, 0o2)); // group no write
        assert!(!has_permission(2000, 200, &st, 0o4)); // other none
        assert!(has_permission(0, 0, &st, 0o2)); // root write bypass
                                                 // Supplementary-group membership grants the group class (Linux in_group_p).
        assert!(crate::inode::has_permission_grouped(
            2000,
            2000,
            &[100],
            &st,
            0o4
        ));
        assert!(!crate::inode::has_permission_grouped(
            2000,
            2000,
            &[100],
            &st,
            0o2
        ));
        assert!(!crate::inode::has_permission_grouped(
            2000,
            2000,
            &[999],
            &st,
            0o4
        ));
        assert!(crate::inode::perm_class_groups(2000, 2000, &[100], &st) == 3);
    }

    #[test]
    fn options_default_is_write_through() {
        let o = options();
        assert_eq!(o.attr_ttl, Duration::from_secs(1));
        assert_eq!(o.entry_ttl, Duration::from_secs(1));
        assert!(!o.direct_io);
        assert_eq!(o.statfs, StatfsMode::PhysicalSafe);
    }
}
