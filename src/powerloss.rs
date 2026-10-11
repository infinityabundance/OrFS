//! A **controlled, deterministic, simulated storage-device model** for
//! power-loss(-like) durability evidence (Phase 17).
//!
//! # Why this exists
//!
//! The process-crash court (`tests/crash_recovery.rs`) terminates the process
//! with `SIGABRT` mid-write. That is a genuine test of OrFS's *own* logic — no
//! destructor runs and all in-memory state is gone — but the operating system's
//! page cache survives a process kill, so every byte that reached a `write`
//! syscall is still present. A process kill therefore does **not** model
//! storage-device write-back caches, reordering, torn sectors, or the loss of
//! acknowledged-but-not-flushed data. This module adds a stronger, explicitly
//! *simulated* device with those failure modes, so OrFS can be asked what
//! survives an *un-clean* power loss rather than only a clean process crash.
//!
//! # What is simulated (and what is not)
//!
//! This is a **software model**, not real hardware. It lives entirely in the
//! process and is driven by the log's own `write`/`fsync` calls:
//!
//! * Every write to a log file is captured into a per-file **volatile cache**
//!   (in addition to being written through to the real file so ordinary
//!   in-session reads observe the latest bytes).
//! * An `fsync`/flush is the only durability point that moves cached writes
//!   into the **durable image**. Its behaviour is configurable ([`FlushMode`]):
//!   a completing `fsync` may be an honoured barrier, or it may promote only
//!   some sectors (a flush that did not finish — the device's cache did not
//!   fully drain).
//! * [`SimDevice::power_fail`] discards every un-flushed cached write and, per
//!   [`DurableLoss`], may additionally tear the trailing sector of the durable
//!   image (a flushed sector lost on an unclean power-down). It then
//!   **materialises** the surviving durable image to the real log directory and
//!   detaches, so an independent recovery step can open the volume exactly as a
//!   fresh process would.
//!
//! ## Assumptions (stated precisely)
//!
//! 1. Writes are modelled at byte granularity inside file-sized images; sector
//!    granularity (`sector`) is used only to decide *which* bytes a partial
//!    flush persists and *how much* a torn tail loses.
//! 2. A completed `fsync` under [`FlushMode::Barrier`] is an honoured durability
//!    barrier. This models a device whose documented `fsync` contract holds; it
//!    is the profile under which a `sync`-mode acknowledgement is expected to
//!    survive.
//! 3. Under [`FlushMode::Partial`]/[`FlushMode::ReorderedPartial`] and
//!    [`DurableLoss::TearTail`], the device may lose already-`fsync`ed bytes.
//!    That models **hardware that violated its documented contract** (or a power
//!    cut *during* the flush whose completion the caller never received).
//!    Assertions for those profiles are therefore restricted to *safety* (no
//!    corruption, no partial transaction, recovery to a valid boundary or an
//!    explicit refusal) — never to "the ack must survive".
//! 4. Directory-entry durability is modelled coarsely: a file created during a
//!    session is durable only once a directory `fsync` is observed; OrFS fsyncs
//!    the segment directory immediately after creating a segment, so created
//!    segments are durable.
//! 5. All randomness is derived from a single seeded [`Rng`] and consumed in a
//!    fixed (sorted-key) order, so a given seed reproduces a run exactly.
//!
//! ## What it does **not** prove
//!
//! A green run here does **not** prove real-hardware durability. It shows that
//! OrFS's recovery is correct *relative to this model's assumed device
//! semantics*, and that its commit protocol never exposes a partially applied
//! transaction or withdraws committed history under those semantics. Real
//! devices, filesystems, and their caches differ; only an instrumented power-loss
//! rig can test real hardware. See `docs/POWERLOSS.md`.
//!
//! # Non-withdrawal
//!
//! The model never rewrites committed bytes: the durable image is built by
//! applying only *promoted* writes to the durable image in issue order, and a
//! power failure only ever *drops* not-yet-durable bytes (or tears the trailing
//! edge of the durable image). It can make history *shorter*, never different.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::error::{OrfsError, Result};
use crate::watermark::{Watermark, WATERMARK_FILE, WATERMARK_LEN};

/// Default modelled sector size in bytes.
pub const DEFAULT_SECTOR: u64 = 512;

/// How a completed `fsync`/flush interacts with the volatile cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlushMode {
    /// An honoured barrier: every cached write becomes durable.
    Barrier,
    /// Only a seeded subset of the cached sectors becomes durable; the rest
    /// stay cached and are lost at power failure (a flush that did not finish).
    Partial,
    /// As [`FlushMode::Partial`], but the promoted subset is selected in a
    /// shuffled order (models write reordering across the flush).
    ReorderedPartial,
}

/// An optional additional failure applied to the *already-durable* image at
/// power failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableLoss {
    /// The durable image survives exactly as flushed.
    None,
    /// At power failure, tear (truncate) the trailing sector of every flushed
    /// file: a flushed sector lost on an unclean power-down.
    TearTail,
    /// At power failure, lose the commit watermark (a power cut in the window
    /// between the segment `fsync` and the watermark `fsync`) while the flushed
    /// segment bytes survive: exercises the residual window (`docs/RECOVERY.md` §5).
    LostWatermark,
}

/// The deterministic configuration of a simulated device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SimConfig {
    /// Seed for every randomised decision.
    pub seed: u64,
    /// Modelled sector size.
    pub sector: u64,
    /// Flush semantics.
    pub flush: FlushMode,
    /// Extra durable-image damage at power failure.
    pub durable_loss: DurableLoss,
}

impl SimConfig {
    /// A device whose `fsync` is an honoured barrier and which loses only
    /// un-flushed cached writes. The profile under which `sync` acknowledgements
    /// are expected to survive.
    pub const fn honest(seed: u64) -> Self {
        Self {
            seed,
            sector: DEFAULT_SECTOR,
            flush: FlushMode::Barrier,
            durable_loss: DurableLoss::None,
        }
    }

    /// A device whose `fsync` promotes only some sectors: models a flush that
    /// did not complete.
    pub const fn partial(seed: u64) -> Self {
        Self {
            seed,
            sector: DEFAULT_SECTOR,
            flush: FlushMode::Partial,
            durable_loss: DurableLoss::None,
        }
    }

    /// As [`SimConfig::partial`] but with the promoted sectors chosen in a
    /// shuffled order.
    pub const fn reordered_partial(seed: u64) -> Self {
        Self {
            seed,
            sector: DEFAULT_SECTOR,
            flush: FlushMode::ReorderedPartial,
            durable_loss: DurableLoss::None,
        }
    }

    /// An honoured barrier, but with the trailing sector of each flushed file
    /// torn at power failure.
    pub const fn tear(seed: u64) -> Self {
        Self {
            seed,
            sector: DEFAULT_SECTOR,
            flush: FlushMode::Barrier,
            durable_loss: DurableLoss::TearTail,
        }
    }

    /// An honoured barrier for segment bytes, but the commit watermark is lost at
    /// power failure (a power cut between the segment `fsync` and the watermark
    /// `fsync`).
    pub const fn lost_watermark(seed: u64) -> Self {
        Self {
            seed,
            sector: DEFAULT_SECTOR,
            flush: FlushMode::Barrier,
            durable_loss: DurableLoss::LostWatermark,
        }
    }

    /// Override the modelled sector size.
    pub const fn with_sector(mut self, sector: u64) -> Self {
        self.sector = sector;
        self
    }
}

/// A deterministic SplitMix64 generator (small, dependency-free, reproducible).
#[derive(Debug, Clone, Copy)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// In-place Fisher–Yates shuffle.
    fn shuffle<T>(&mut self, items: &mut [T]) {
        if items.len() < 2 {
            return;
        }
        for i in (1..items.len()).rev() {
            let j = (self.next_u64() % (i as u64 + 1)) as usize;
            items.swap(i, j);
        }
    }
}

/// One cached (not yet durable) write.
#[derive(Debug, Clone)]
struct WriteOp {
    offset: u64,
    bytes: Vec<u8>,
}

/// The modelled state of one file.
#[derive(Debug, Clone)]
struct FileModel {
    /// Bytes durable at the moment the device was attached.
    #[allow(dead_code)]
    base: Vec<u8>,
    /// The durable image (base plus every promoted write, in issue order).
    durable: Vec<u8>,
    /// Writes still sitting in the volatile cache, in issue order.
    pending: Vec<WriteOp>,
    /// Whether the file was created during this session.
    created: bool,
    /// Whether a directory `fsync` has made its existence durable.
    dir_synced: bool,
}

impl FileModel {
    fn from_existing(bytes: Vec<u8>) -> Self {
        FileModel {
            base: bytes.clone(),
            durable: bytes,
            pending: Vec::new(),
            created: false,
            dir_synced: true,
        }
    }
}

/// Overwrite `content` with `bytes` at `offset`, extending with zeros as needed.
fn apply(content: &mut Vec<u8>, offset: u64, bytes: &[u8]) {
    let off = offset as usize;
    if content.len() < off {
        content.resize(off, 0);
    }
    let end = off + bytes.len();
    if content.len() < end {
        content.resize(end, 0);
    }
    content[off..end].copy_from_slice(bytes);
}

/// Per-file outcome of a simulated power failure.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FileLoss {
    /// File name relative to the log directory.
    pub name: String,
    /// Durable length after the failure.
    pub durable_len: u64,
    /// Volatile (un-flushed) bytes discarded.
    pub dropped_volatile_bytes: u64,
    /// Durable bytes torn off the trailing edge.
    pub torn_durable_bytes: u64,
    /// Whether the file remains present after the failure.
    pub present: bool,
}

/// Machine-readable outcome of a simulated power failure.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PowerFailReport {
    /// The configuration this device was run with.
    pub config: SimConfig,
    /// Per-file outcomes, ordered by name.
    pub files: Vec<FileLoss>,
    /// Total volatile bytes discarded across all files.
    pub total_dropped_volatile_bytes: u64,
    /// Total durable bytes torn off across all files.
    pub total_torn_durable_bytes: u64,
    /// Number of cached writes discarded.
    pub dropped_writes: u64,
}

/// The simulated device. Owns an in-memory image of every file in one log
/// directory; the real files are written through so in-session reads work.
#[derive(Debug)]
pub struct SimDevice {
    dir: PathBuf,
    cfg: SimConfig,
    rng: Rng,
    files: BTreeMap<String, FileModel>,
}

impl SimDevice {
    /// Load the current contents of `dir` into a fresh device image.
    fn load(dir: &Path, cfg: SimConfig) -> Result<SimDevice> {
        let mut files = BTreeMap::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            if !ft.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let bytes = std::fs::read(entry.path())?;
            files.insert(name.to_string(), FileModel::from_existing(bytes));
        }
        Ok(SimDevice {
            dir: dir.to_path_buf(),
            cfg,
            rng: Rng::new(cfg.seed),
            files,
        })
    }

    /// The device's configuration.
    pub fn config(&self) -> SimConfig {
        self.cfg
    }

    /// Register a file created during the session (idempotent).
    pub fn record_create(&mut self, name: &str) {
        self.files
            .entry(name.to_string())
            .or_insert_with(|| FileModel {
                base: Vec::new(),
                durable: Vec::new(),
                pending: Vec::new(),
                created: true,
                dir_synced: false,
            });
    }

    /// Record (and, via write-through, already persist) a cached write.
    pub fn record_write(&mut self, name: &str, offset: u64, bytes: &[u8]) {
        let fm = self
            .files
            .entry(name.to_string())
            .or_insert_with(|| FileModel {
                base: Vec::new(),
                durable: Vec::new(),
                pending: Vec::new(),
                created: true,
                dir_synced: false,
            });
        fm.pending.push(WriteOp {
            offset,
            bytes: bytes.to_vec(),
        });
    }

    /// Forget a file (for example one moved into `quarantine/`): its bytes are
    /// retained elsewhere, so the model must not resurrect it at power failure.
    pub fn record_remove(&mut self, name: &str) {
        self.files.remove(name);
    }

    /// A durability point for one file: promote cached writes to the durable
    /// image according to [`SimConfig::flush`].
    pub fn flush(&mut self, name: &str) {
        let cfg = self.cfg;
        // Copy the (Copy) generator out so the borrow of `self.files` is disjoint.
        let mut rng = self.rng;
        let Some(fm) = self.files.get_mut(name) else {
            return;
        };
        match cfg.flush {
            FlushMode::Barrier => {
                for op in fm.pending.drain(..) {
                    apply(&mut fm.durable, op.offset, &op.bytes);
                }
            }
            FlushMode::Partial | FlushMode::ReorderedPartial => {
                let mut pending = std::mem::take(&mut fm.pending);
                if cfg.flush == FlushMode::ReorderedPartial {
                    rng.shuffle(&mut pending);
                }
                let mut kept = Vec::new();
                for op in pending {
                    let op_end = op.offset + op.bytes.len() as u64;
                    let mut cur = op.offset;
                    while cur < op_end {
                        let sec_end = (cur / cfg.sector + 1) * cfg.sector;
                        let piece_end = op_end.min(sec_end);
                        let lo = (cur - op.offset) as usize;
                        let hi = (piece_end - op.offset) as usize;
                        if rng.next_u64() & 1 == 0 {
                            apply(&mut fm.durable, cur, &op.bytes[lo..hi]);
                        } else {
                            kept.push(WriteOp {
                                offset: cur,
                                bytes: op.bytes[lo..hi].to_vec(),
                            });
                        }
                        cur = piece_end;
                    }
                }
                fm.pending = kept;
            }
        }
        self.rng = rng;
    }

    /// A directory `fsync`: every file currently present has a durable name.
    pub fn sync_dir(&mut self) {
        for fm in self.files.values_mut() {
            fm.dir_synced = true;
        }
    }

    /// Model the atomic `write-tmp → rename → fsync` of a commit watermark as a
    /// single durable file write, plus a write-through so a same-session read is
    /// consistent.
    pub fn write_watermark(&mut self, wm: &Watermark) -> Result<()> {
        let encoded = wm.encode();
        self.record_create(WATERMARK_FILE);
        self.record_write(WATERMARK_FILE, 0, &encoded);
        self.flush(WATERMARK_FILE);
        self.sync_dir();
        // Write-through: keep the on-disk file consistent for any same-session
        // reader (the real file is overwritten from the durable image at power
        // failure if the write was not made durable).
        let path = self.dir.join(WATERMARK_FILE);
        std::fs::write(&path, encoded)?;
        Ok(())
    }

    /// Reconstruct the durable image of one file at power failure, returning its
    /// content, the number of durable bytes torn off, and whether it remains.
    fn reconstruct(&self, name: &str, fm: &FileModel) -> (Vec<u8>, u64, bool) {
        let present = !(fm.created && !fm.dir_synced);
        // The commit watermark is written with an atomic `write-tmp → rename`, so
        // the model treats it as all-or-nothing: it is either a complete
        // watermark or the previous one (never a torn one).
        if name == WATERMARK_FILE {
            let content = if self.cfg.durable_loss == DurableLoss::LostWatermark {
                fm.base.clone()
            } else if fm.durable.len() == WATERMARK_LEN {
                fm.durable.clone()
            } else {
                fm.base.clone()
            };
            let present = present && !content.is_empty();
            return (content, 0, present);
        }
        let mut content = fm.durable.clone();
        let mut torn = 0u64;
        if self.cfg.durable_loss == DurableLoss::TearTail && !content.is_empty() {
            let sector = self.cfg.sector.max(1) as usize;
            let rem = content.len() % sector;
            let new_len = if rem == 0 {
                content.len().saturating_sub(sector)
            } else {
                content.len() - rem
            };
            torn = (content.len() - new_len) as u64;
            content.truncate(new_len);
        }
        (content, torn, present)
    }

    /// Discard every un-flushed cached write, apply configured durable damage,
    /// materialise the surviving image to the real directory, and report.
    pub fn power_fail(&mut self) -> Result<PowerFailReport> {
        let mut files = Vec::with_capacity(self.files.len());
        let mut total_dropped = 0u64;
        let mut total_torn = 0u64;
        let mut dropped_writes = 0u64;
        for (name, fm) in &self.files {
            let dropped: u64 = fm.pending.iter().map(|o| o.bytes.len() as u64).sum();
            let dropped_n = fm.pending.len() as u64;
            let (content, torn, present) = self.reconstruct(name, fm);
            total_dropped += dropped;
            total_torn += torn;
            dropped_writes += dropped_n;
            files.push((name.clone(), content, dropped, torn, present));
        }

        for (name, content, _, _, present) in &files {
            let path = self.dir.join(name);
            if !present {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
                continue;
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, content)?;
        }

        let file_losses = files
            .into_iter()
            .map(|(name, content, dropped, torn, present)| FileLoss {
                name,
                durable_len: content.len() as u64,
                dropped_volatile_bytes: dropped,
                torn_durable_bytes: torn,
                present,
            })
            .collect();

        Ok(PowerFailReport {
            config: self.cfg,
            files: file_losses,
            total_dropped_volatile_bytes: total_dropped,
            total_torn_durable_bytes: total_torn,
            dropped_writes,
        })
    }

    /// A clean shutdown: promote every cached write and materialise (no damage).
    pub fn clean_close(&mut self) -> Result<()> {
        let names: Vec<String> = self.files.keys().cloned().collect();
        for name in names {
            if let Some(fm) = self.files.get_mut(&name) {
                for op in fm.pending.drain(..) {
                    apply(&mut fm.durable, op.offset, &op.bytes);
                }
            }
        }
        // A clean shutdown persists directory entries as well as cached bytes.
        self.sync_dir();
        let mut files = Vec::new();
        for (name, fm) in &self.files {
            files.push((
                name.clone(),
                fm.durable.clone(),
                !(fm.created && !fm.dir_synced),
            ));
        }
        for (name, content, present) in &files {
            let path = self.dir.join(name);
            if !present {
                let _ = std::fs::remove_file(&path);
            } else {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&path, content)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Thread-local registry & seam helpers
// ---------------------------------------------------------------------------

thread_local! {
    static DEVICES: std::cell::RefCell<BTreeMap<PathBuf, Arc<Mutex<SimDevice>>>> =
        const { std::cell::RefCell::new(BTreeMap::new()) };
}

/// An attached simulated device: a handle that can trigger the power failure.
pub struct PowerLossHandle {
    dir: PathBuf,
    config: SimConfig,
}

impl PowerLossHandle {
    /// The modelled log directory.
    pub fn log_dir(&self) -> &Path {
        &self.dir
    }

    /// The device configuration.
    pub fn config(&self) -> SimConfig {
        self.config
    }

    /// Trigger the un-clean power failure: discard un-flushed writes, apply
    /// configured durable damage, materialise the surviving image to the real
    /// directory, and detach so an independent recovery step can open it.
    pub fn power_fail(&self) -> Result<PowerFailReport> {
        let dev = lookup(&self.dir).ok_or_else(|| {
            OrfsError::InvalidArgument("power-fail on a device that is not attached".to_string())
        })?;
        let report = {
            let mut guard = dev.lock().expect("sim device mutex");
            guard.power_fail()?
        };
        detach(&self.dir);
        Ok(report)
    }
}

impl Drop for PowerLossHandle {
    fn drop(&mut self) {
        // If the test ends without an explicit power failure, close the device
        // cleanly (flush everything) so the real directory is left consistent.
        if let Some(dev) = lookup(&self.dir) {
            {
                let mut guard = dev.lock().expect("sim device mutex");
                let _ = guard.clean_close();
            }
            detach(&self.dir);
        }
    }
}

/// Attach a simulated device to `log_dir`, loading its current contents as the
/// durable base image. All subsequent log I/O in this directory on this thread
/// is captured by the device until [`PowerLossHandle::power_fail`] (or the
/// handle's drop) detaches it.
pub fn attach(log_dir: &Path, cfg: SimConfig) -> Result<PowerLossHandle> {
    let dev = SimDevice::load(log_dir, cfg)?;
    let arc = Arc::new(Mutex::new(dev));
    DEVICES.with(|m| {
        m.borrow_mut().insert(log_dir.to_path_buf(), arc);
    });
    Ok(PowerLossHandle {
        dir: log_dir.to_path_buf(),
        config: cfg,
    })
}

/// Detach any device attached to `log_dir` on this thread.
pub fn detach(log_dir: &Path) {
    DEVICES.with(|m| {
        m.borrow_mut().remove(log_dir);
    });
}

/// Whether a device is attached to `log_dir` on this thread.
pub fn attached(log_dir: &Path) -> bool {
    DEVICES.with(|m| m.borrow().contains_key(log_dir))
}

/// Look up the device attached to `log_dir` on this thread, if any.
pub fn lookup(log_dir: &Path) -> Option<Arc<Mutex<SimDevice>>> {
    DEVICES.with(|m| m.borrow().get(log_dir).cloned())
}

/// Record a file creation. No-op when no device is attached.
#[inline]
pub fn record_create(dir: &Path, name: &str) {
    if let Some(dev) = lookup(dir) {
        dev.lock().expect("sim device mutex").record_create(name);
    }
}

/// Record a cached write. No-op when no device is attached.
#[inline]
pub fn record_write(dir: &Path, name: &str, offset: u64, bytes: &[u8]) {
    if let Some(dev) = lookup(dir) {
        dev.lock()
            .expect("sim device mutex")
            .record_write(name, offset, bytes);
    }
}

/// A durability point for one file. No-op when no device is attached.
#[inline]
pub fn flush_file(dir: &Path, name: &str) {
    if let Some(dev) = lookup(dir) {
        dev.lock().expect("sim device mutex").flush(name);
    }
}

/// A directory `fsync`. Returns `true` when a device handled it.
#[inline]
pub fn sync_dir(dir: &Path) -> bool {
    if let Some(dev) = lookup(dir) {
        dev.lock().expect("sim device mutex").sync_dir();
        true
    } else {
        false
    }
}

/// Forget a file moved outside the modelled set (e.g. into `quarantine/`).
#[inline]
pub fn record_remove(dir: &Path, name: &str) {
    if let Some(dev) = lookup(dir) {
        dev.lock().expect("sim device mutex").record_remove(name);
    }
}

/// Model an atomic commit-watermark write. Returns `None` when no device is
/// attached (the caller then performs the real `write-tmp → rename → fsync`), or
/// `Some(result)` when the simulated device handled it.
#[inline]
pub fn write_watermark(dir: &Path, wm: &Watermark) -> Option<Result<()>> {
    lookup(dir).map(|dev| dev.lock().expect("sim device mutex").write_watermark(wm))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev_with(files: &[(&str, Vec<u8>)], cfg: SimConfig) -> (tempfile::TempDir, SimDevice) {
        let td = tempfile::TempDir::new().unwrap();
        for (name, bytes) in files {
            std::fs::write(td.path().join(name), bytes).unwrap();
        }
        let dev = SimDevice::load(td.path(), cfg).unwrap();
        (td, dev)
    }

    #[test]
    fn barrier_flush_makes_cached_writes_durable() {
        let (td, mut dev) = dev_with(&[("seg", vec![0; 8])], SimConfig::honest(1));
        dev.record_write("seg", 0, b"hello");
        dev.flush("seg");
        let report = dev.power_fail().unwrap();
        assert_eq!(report.total_dropped_volatile_bytes, 0);
        let bytes = std::fs::read(td.path().join("seg")).unwrap();
        assert_eq!(&bytes[..5], b"hello");
        assert_eq!(report.files.len(), 1);
    }

    #[test]
    fn unflushed_writes_are_lost_and_durable_bytes_survive() {
        let (td, mut dev) = dev_with(&[("seg", b"abcd".to_vec())], SimConfig::honest(2));
        dev.record_write("seg", 4, b"EFGH");
        // Not flushed: must be dropped.
        let report = dev.power_fail().unwrap();
        assert_eq!(report.total_dropped_volatile_bytes, 4);
        assert_eq!(report.dropped_writes, 1);
        let bytes = std::fs::read(td.path().join("seg")).unwrap();
        assert_eq!(bytes, b"abcd");
    }

    #[test]
    fn clean_close_promotes_everything() {
        let (td, mut dev) = dev_with(&[("seg", Vec::new())], SimConfig::honest(3));
        dev.record_create("new");
        dev.record_write("new", 0, b"xyz");
        dev.record_write("seg", 0, b"abc");
        dev.clean_close().unwrap();
        assert_eq!(std::fs::read(td.path().join("new")).unwrap(), b"xyz");
        assert_eq!(std::fs::read(td.path().join("seg")).unwrap(), b"abc");
    }

    #[test]
    fn undurable_created_file_is_removed_at_power_failure() {
        let (_td, mut dev) = dev_with(&[], SimConfig::honest(4));
        dev.record_create("ghost");
        dev.record_write("ghost", 0, b"data");
        // No sync_dir call, so its directory entry was never durable.
        let report = dev.power_fail().unwrap();
        assert!(!report.files[0].present);
    }

    #[test]
    fn reordered_partial_flush_is_deterministic() {
        let run = |seed: u64| {
            let (_td, mut dev) = dev_with(&[], SimConfig::reordered_partial(seed));
            dev.record_create("seg");
            dev.record_write("seg", 0, &vec![0xAB; 4096]);
            dev.flush("seg");
            dev.power_fail().unwrap()
        };
        let a = run(42);
        let b = run(42);
        let c = run(43);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap(),
            "same seed must reproduce"
        );
        // A different seed is extremely unlikely to match byte-for-byte.
        assert_ne!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&c).unwrap()
        );
    }

    #[test]
    fn tear_tail_shortens_the_durable_image() {
        // 700 bytes durable, sector 512: the trailing partial sector is torn.
        let (td, mut dev) = dev_with(&[("seg", vec![7u8; 700])], SimConfig::tear(5));
        let report = dev.power_fail().unwrap();
        assert_eq!(report.total_torn_durable_bytes, 188);
        assert_eq!(std::fs::read(td.path().join("seg")).unwrap().len(), 512);
    }

    #[test]
    fn non_withdrawal_durable_bytes_are_never_rewritten() {
        let (td, mut dev) = dev_with(&[("seg", b"BASE".to_vec())], SimConfig::partial(9));
        dev.record_write("seg", 0, b"base");
        dev.flush("seg");
        dev.record_write("seg", 4, b"tail");
        dev.power_fail().unwrap();
        let bytes = std::fs::read(td.path().join("seg")).unwrap();
        // The durable prefix can only have been extended in place, never
        // changed to something else.
        assert!(bytes.starts_with(b"base") || bytes.starts_with(b"BASE"));
    }

    #[test]
    fn watermark_is_modelled_as_a_durable_file() {
        let (_td, mut dev) = dev_with(&[], SimConfig::honest(11));
        let wm = Watermark {
            committed_root: 128,
            segment_id: 0,
            segment_valid_len: 128,
        };
        dev.write_watermark(&wm).unwrap();
        assert_eq!(dev.files.get(WATERMARK_FILE).unwrap().durable, wm.encode());
    }
}
