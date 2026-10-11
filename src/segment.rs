//! Immutable physical segments and canonical logical-offset location (§4).
//!
//! `or.log` is a *logical* append-only byte stream. It is realized physically as
//! an ordered set of immutable segment files named `NNNNNNNNNNNNNNNN.seg`
//! (decimal, zero-padded to 16 digits). A segment's numeric id is the **first
//! logical byte offset it covers**, so for any canonical logical offset `L`
//! within a segment of id `S` the physical offset is `L - S`.
//!
//! A record never straddles two segments (the writer rolls over before writing,
//! never mid-record), which keeps the mapping single-valued and total.
//!
//! Segments are append-only. A committed physical byte is never rewritten or
//! removed (Law I). When a segment ends in a torn or abandoned tail, the
//! segment is *retained* and the writer continues in a fresh segment whose id
//! continues the canonical logical stream (see `log.rs`).

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use crate::error::{OrfsError, Result};

/// Suffix shared by every segment file.
pub const SEGMENT_SUFFIX: &str = ".seg";

/// Number of decimal digits in a segment file name.
pub const SEGMENT_NAME_DIGITS: usize = 16;

/// Largest logical offset representable in a 16-digit segment name.
pub const MAX_SEGMENT_ID: u64 = 9_999_999_999_999_999;

/// Format a segment file name for an id.
pub fn segment_file_name(id: u64) -> Result<String> {
    if id > MAX_SEGMENT_ID {
        return Err(OrfsError::Unsupported(format!(
            "segment id {id} exceeds the 16-digit segment naming space"
        )));
    }
    Ok(format!(
        "{id:0width$}{SEGMENT_SUFFIX}",
        width = SEGMENT_NAME_DIGITS
    ))
}

/// Parse a segment file name, returning its id. Non-segment names yield `None`.
pub fn parse_segment_name(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(SEGMENT_SUFFIX)?;
    if stem.len() != SEGMENT_NAME_DIGITS || !stem.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    stem.parse::<u64>().ok()
}

/// The canonical logical range physically covered by one segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct SegmentExtent {
    /// Logical offset of the first byte of this segment.
    pub id: u64,
    /// Number of *canonical* (well-framed) bytes in this segment. This may be
    /// smaller than the physical file length when an abandoned tail has been
    /// retained.
    pub valid_len: u64,
}

impl SegmentExtent {
    /// Exclusive logical end of the canonical bytes in this segment.
    pub fn end(&self) -> u64 {
        self.id + self.valid_len
    }
}

/// Discover segment ids directly inside `dir`, sorted ascending.
///
/// Non-segment entries (including a `quarantine/` directory) are ignored.
pub fn discover_segment_ids(dir: &Path) -> Result<Vec<u64>> {
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(id) = parse_segment_name(name) {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    for pair in ids.windows(2) {
        if pair[0] == pair[1] {
            return Err(OrfsError::Corrupt(format!(
                "duplicate segment id {} in {}",
                pair[0],
                dir.display()
            )));
        }
    }
    Ok(ids)
}

/// An open immutable segment file.
#[derive(Debug)]
pub struct Segment {
    id: u64,
    dir: PathBuf,
    name: String,
    path: PathBuf,
    file: File,
    len: u64,
}

impl Segment {
    /// Create a new, empty segment. Fails if the file already exists.
    pub fn create(dir: &Path, id: u64) -> Result<Segment> {
        let name = segment_file_name(id)?;
        if let Some(err) = crate::powerloss::device_create(dir, &name) {
            return Err(err);
        }
        let path = dir.join(&name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        // The simulated power-loss layer records creation so a directory-entry
        // loss can be modelled; a no-op when no device is attached.
        crate::powerloss::record_create(dir, &name);
        Ok(Segment {
            id,
            dir: dir.to_path_buf(),
            name,
            path,
            file,
            len: 0,
        })
    }

    /// Open an existing segment for reading and appending.
    pub fn open(dir: &Path, id: u64) -> Result<Segment> {
        let name = segment_file_name(id)?;
        let path = dir.join(&name);
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        let len = file.metadata()?.len();
        Ok(Segment {
            id,
            dir: dir.to_path_buf(),
            name,
            path,
            file,
            len,
        })
    }

    /// The segment's logical id (== first logical byte offset it covers).
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Path of the segment file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Physical length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the segment is physically empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append `buf` at the current physical end, returning the start offset.
    pub fn append(&mut self, buf: &[u8]) -> Result<u64> {
        let offset = self.len;
        self.write_at(offset, buf)?;
        self.len += buf.len() as u64;
        Ok(offset)
    }

    /// Write `buf` at `offset`. The caller must ensure the range is within the
    /// append frontier; committed bytes are never rewritten by this layer.
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        // A simulated device may reject (ENOSPC/EIO) or shorten the write. When it
        // does, only the accepted prefix is persisted, and the error is returned so
        // the authoritative path refuses the mutation rather than acknowledging it.
        if let Some(fault) =
            crate::powerloss::device_write(&self.dir, &self.name, offset, buf.len() as u64)
        {
            let n = (fault.written as usize).min(buf.len());
            if n > 0 {
                self.file
                    .write_all_at(&buf[..n], offset)
                    .map_err(map_store_err)?;
                crate::powerloss::record_write(&self.dir, &self.name, offset, &buf[..n]);
            }
            return Err(fault.error);
        }
        self.file.write_all_at(buf, offset).map_err(map_store_err)?;
        // Capture the write in the simulated device's volatile cache (write-through
        // to `self.file` keeps ordinary in-session reads correct). No-op without a
        // device.
        crate::powerloss::record_write(&self.dir, &self.name, offset, buf);
        Ok(())
    }

    /// Read exactly `buf.len()` bytes at `offset`, or fail.
    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let n = self.file.read_at(&mut buf[done..], offset + done as u64)?;
            if n == 0 {
                return Err(OrfsError::Corrupt(format!(
                    "unexpected end of segment {} at physical offset {}",
                    self.id,
                    offset + done as u64
                )));
            }
            done += n;
        }
        Ok(())
    }

    /// Flush and fsync the segment file.
    pub fn sync(&self) -> Result<()> {
        if let Some(err) = crate::powerloss::device_sync(&self.dir, &self.name) {
            return Err(err);
        }
        self.file.sync_all().map_err(map_store_err)?;
        // The device's durability point: promote cached writes per its model.
        crate::powerloss::flush_file(&self.dir, &self.name);
        Ok(())
    }

    /// The underlying file descriptor, for `io_uring` submission.
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// A read-only, open segment used by the log reader.
pub(crate) struct ReadAt {
    file: File,
    id: u64,
}

impl ReadAt {
    pub(crate) fn open(dir: &Path, id: u64) -> Result<ReadAt> {
        let path = dir.join(segment_file_name(id)?);
        Ok(ReadAt {
            file: File::open(path)?,
            id,
        })
    }

    /// Physical length in bytes.
    pub(crate) fn len(&self) -> Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    pub(crate) fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let mut done = 0usize;
        while done < buf.len() {
            let n = self.file.read_at(&mut buf[done..], offset + done as u64)?;
            if n == 0 {
                return Err(OrfsError::Corrupt(format!(
                    "unexpected end of segment {} at physical offset {}",
                    self.id,
                    offset + done as u64
                )));
            }
            done += n;
        }
        Ok(())
    }

    /// The underlying file descriptor, for `io_uring` submission.
    pub(crate) fn raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

/// Maps canonical logical byte offsets to `(segment id, physical offset)`.
///
/// Extents must be contiguous and start at logical offset 0; [`Self::from_extents`]
/// enforces this.
#[derive(Debug, Clone, Default)]
pub struct SegmentLocator {
    extents: Vec<SegmentExtent>,
}

impl SegmentLocator {
    /// Build a validated locator. Extents must be non-empty, ordered, start at
    /// logical offset 0, and abut exactly (no gaps or overlaps).
    pub fn from_extents(extents: Vec<SegmentExtent>) -> Result<SegmentLocator> {
        let mut prev_end: Option<u64> = None;
        for e in &extents {
            match prev_end {
                None => {
                    if e.id != 0 {
                        return Err(OrfsError::Corrupt(format!(
                            "first segment id {} is not 0",
                            e.id
                        )));
                    }
                }
                Some(pe) => {
                    if e.id != pe {
                        return Err(OrfsError::Corrupt(format!(
                            "segment id {} does not continue from {}",
                            e.id, pe
                        )));
                    }
                }
            }
            prev_end = Some(e.end());
        }
        Ok(SegmentLocator { extents })
    }

    /// Push an extent (used only when constructing a fresh writer).
    pub fn push(&mut self, extent: SegmentExtent) {
        self.extents.push(extent);
    }

    /// The extents in canonical order.
    pub fn extents(&self) -> &[SegmentExtent] {
        &self.extents
    }

    /// The exclusive end of the last canonical extent.
    pub fn total_len(&self) -> u64 {
        self.extents.last().map(|e| e.end()).unwrap_or(0)
    }

    /// Locate a logical offset, returning `(segment id, physical offset)`.
    pub fn locate(&self, offset: u64) -> Option<(u64, u64)> {
        self.locate_extent(offset).map(|(e, phys)| (e.id, phys))
    }

    /// Locate a logical offset, returning the covering [`SegmentExtent`] and the
    /// physical offset within it. One binary search and no second lookup: callers
    /// that also need the extent (its `valid_len`) must use this instead of
    /// [`Self::locate`] followed by [`Self::extent_of`] — which would otherwise
    /// repeat the search.
    pub fn locate_extent(&self, offset: u64) -> Option<(SegmentExtent, u64)> {
        let idx = self.extents.partition_point(|e| e.id <= offset);
        if idx == 0 {
            return None;
        }
        let e = self.extents[idx - 1];
        if offset < e.end() {
            Some((e, offset - e.id))
        } else {
            None
        }
    }

    /// The extent with the given segment id, if present.
    pub fn extent_of(&self, id: u64) -> Option<SegmentExtent> {
        self.extents.iter().find(|e| e.id == id).copied()
    }

    /// Update the canonical valid length of the last extent.
    pub fn set_last_valid_len(&mut self, valid_len: u64) {
        if let Some(last) = self.extents.last_mut() {
            last.valid_len = valid_len;
        }
    }
}

/// Fsync a directory so that newly created/renamed entries are durable.
pub(crate) fn fsync_dir(dir: &Path) -> Result<()> {
    crate::failpoints::check(crate::failpoints::Failpoint::DuringDirectorySync)?;
    if let Some(err) = crate::powerloss::device_dir_sync(dir) {
        return Err(err);
    }
    // A simulated device models directory durability itself; when one is attached
    // to this directory it handles the sync and the real fsync is skipped.
    if crate::powerloss::sync_dir(dir) {
        return Ok(());
    }
    match File::open(dir) {
        Ok(f) => {
            f.sync_all().map_err(map_store_err)?;
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Map an OS error to a semantically meaningful OrFS error: an out-of-space error
/// becomes [`OrfsError::NoSpace`] (so the authoritative path can recognise and
/// latch a capacity exhaustion), everything else stays an `Io` error.
pub(crate) fn map_store_err(e: io::Error) -> OrfsError {
    if e.raw_os_error() == Some(libc::ENOSPC) {
        OrfsError::NoSpace(e.to_string())
    } else {
        OrfsError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_names_round_trip() {
        for id in [0u64, 1, 42, 1_000_000, MAX_SEGMENT_ID] {
            let name = segment_file_name(id).unwrap();
            assert_eq!(name.len(), SEGMENT_NAME_DIGITS + SEGMENT_SUFFIX.len());
            assert_eq!(parse_segment_name(&name), Some(id));
        }
    }

    #[test]
    fn non_segment_names_are_ignored() {
        assert_eq!(parse_segment_name("quarantine"), None);
        assert_eq!(parse_segment_name("0.seg"), None);
        assert_eq!(parse_segment_name("00000000000000000.seg"), None);
        assert_eq!(parse_segment_name("000000000000000a.seg"), None);
        assert_eq!(parse_segment_name("0000000000000000.seg.bak"), None);
    }

    #[test]
    fn locator_maps_offsets_across_segments() {
        let loc = SegmentLocator::from_extents(vec![
            SegmentExtent {
                id: 0,
                valid_len: 10,
            },
            SegmentExtent {
                id: 10,
                valid_len: 5,
            },
        ])
        .unwrap();
        assert_eq!(loc.locate(0), Some((0, 0)));
        assert_eq!(loc.locate(9), Some((0, 9)));
        assert_eq!(loc.locate(10), Some((10, 0)));
        assert_eq!(loc.locate(14), Some((10, 4)));
        assert_eq!(loc.locate(15), None);
        assert_eq!(loc.total_len(), 15);
        // `locate_extent` returns the same answer *plus* the covering extent, from
        // a single search.
        assert_eq!(loc.locate_extent(12), Some((loc.extent_of(10).unwrap(), 2)));
    }

    #[test]
    fn locator_rejects_gaps() {
        let err = SegmentLocator::from_extents(vec![
            SegmentExtent {
                id: 0,
                valid_len: 10,
            },
            SegmentExtent {
                id: 11,
                valid_len: 5,
            },
        ]);
        assert!(err.is_err());
    }

    #[test]
    fn locator_rejects_nonzero_first_id() {
        let err = SegmentLocator::from_extents(vec![SegmentExtent {
            id: 4,
            valid_len: 5,
        }]);
        assert!(err.is_err());
    }
}
