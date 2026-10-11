//! Logical extent map built from `DATA_EXTENT`, `DATA_ZERO_RANGE`, and
//! `FILE_RESIZE` (research §7, §7.1–§7.3).
//!
//! A file's *logical* bytes are reconstructed from an ordered map of immutable
//! extents. A write never rewrites historical storage: it appends a new
//! `DATA_EXTENT` record whose bytes live permanently in the log, and the map
//! simply references the new bytes for the affected logical range. Overwritten
//! bytes remain in the log (Law I, research §7).
//!
//! The map always covers exactly `[0, size)` with disjoint extents: any range
//! that was never written (a sparse hole) or was exposed by a grow is
//! represented by an explicit zero extent, so a read is a straight walk with no
//! ambiguity.
//!
//! Semantics implemented here (mirrored exactly by the reference model in
//! `tests/namespace_model.rs`):
//!
//! * writes at offset zero, in the middle, at EOF, and **beyond EOF** (the gap
//!   is zero-filled — POSIX zero-fill);
//! * overlapping writes (last writer wins for the overlapped bytes);
//! * sparse files (unwritten holes read as zeros);
//! * partial writes;
//! * truncate **shrink** (drops the visible map beyond the new size but never
//!   reclaims log bytes) and truncate **extend** (zero-fills the newly exposed
//!   region, so old truncated bytes are never resurrected — research §7.2).

use crate::error::{OrfsError, Result};
use crate::persistent::PMap;
use crate::record::{get_u32, get_u64, put_u32, put_u64};

// ---------------------------------------------------------------------------
// Payload magics and lengths
// ---------------------------------------------------------------------------

/// `DATA_EXTENT` magic; LE bytes spell `DEX1`.
pub const DATA_EXTENT_MAGIC: u32 = 0x3158_4544;
/// `DATA_ZERO_RANGE` magic; LE bytes spell `DZR1`.
pub const DATA_ZERO_RANGE_MAGIC: u32 = 0x3152_5A44;
/// `FILE_RESIZE` magic; LE bytes spell `FRS1`.
pub const FILE_RESIZE_MAGIC: u32 = 0x3153_5246;

/// Fixed length of a `DATA_ZERO_RANGE` payload.
pub const DATA_ZERO_RANGE_PAYLOAD_LEN: usize = 24;
/// Fixed length of a `FILE_RESIZE` payload.
pub const FILE_RESIZE_PAYLOAD_LEN: usize = 16;

fn check_fixed(buf: &[u8], magic: u32, len: usize, what: &str) -> Result<()> {
    if buf.len() != len {
        return Err(OrfsError::Corrupt(format!(
            "{what} payload is {} bytes, expected {len}",
            buf.len()
        )));
    }
    if get_u32(buf, 0) != magic {
        return Err(OrfsError::Corrupt(format!("{what} payload bad magic")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Extent map
// ---------------------------------------------------------------------------

/// The source of a data extent's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtentKind {
    /// Immutable bytes stored in the log at the given **absolute logical
    /// offset**. The bytes are never rewritten or freed.
    Data { data_offset: u64 },
    /// A logically-zero range (a hole, or the zero-fill of a grow).
    Zero,
}

/// Shift a data extent's base offset right by `delta` logical bytes.
fn shift_kind(kind: ExtentKind, delta: u64) -> ExtentKind {
    match kind {
        ExtentKind::Data { data_offset } => ExtentKind::Data {
            data_offset: data_offset + delta,
        },
        ExtentKind::Zero => ExtentKind::Zero,
    }
}

/// One maximal logical extent `[start, start + len)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub start: u64,
    pub len: u64,
    pub kind: ExtentKind,
}

impl Extent {
    pub fn end(&self) -> u64 {
        self.start + self.len
    }
}

/// One piece of a read plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadPiece {
    /// Read `len` bytes from the log at `logical_offset`.
    Data { logical_offset: u64, len: u64 },
    /// Emit `len` zero bytes.
    Zero { len: u64 },
}

/// The current logical extent map of a file.
///
/// Invariant: the extents are ordered by `start`, disjoint, and cover exactly
/// `[0, size)` with no gaps and no overlaps.
///
/// # Structural sharing (Phase 27)
///
/// The map is a persistent [`PMap`] keyed by `start`, so cloning it (as happens
/// once per `Inode` clone on the publish path) is a single `Arc` bump and never
/// deep-copies the extent list. Mutations path-copy only the `O(log E)` nodes on
/// the affected range and splice just the overlapping extents, so write latency
/// is bounded by `O(log E + k)` rather than the whole file's fragmentation. The
/// representation is a pure performance change: the observable extent sequence
/// is identical to the previous ordered `Vec`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtentMap {
    size: u64,
    extents: PMap<u64, Extent>,
}

impl ExtentMap {
    /// The current logical size in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The extent list (ordered, disjoint, covering `[0, size)`).
    ///
    /// Materialised as an owned, ordered `Vec`; callers that only need to walk
    /// the map in order (a snapshot encode, a count) pay `O(E)` here. The hot
    /// read path uses [`Self::plan_read`], which is `O(log E + k)`.
    pub fn extents(&self) -> Vec<Extent> {
        self.extents.values().copied().collect()
    }

    /// Overwrite `[start, end)` with `kind`, extending the size as required and
    /// zero-filling any gap before `start`.
    ///
    /// The input invariant is that `extents` is sorted by `start`; this method
    /// therefore performs a **single linear merge** (O(E)) instead of draining,
    /// appending, and re-sorting (O(E log E)). Semantics are unchanged: the new
    /// extent is the last writer over `[start, end)` and every surviving fragment
    /// preserves its own base offset.
    fn overlay(&mut self, start: u64, end: u64, kind: ExtentKind) {
        debug_assert!(start <= end);
        if end == start {
            return;
        }
        let target_size = self.size.max(end);
        let mut map = std::mem::take(&mut self.extents);

        // Collect, in ascending key order, every extent that intersects
        // `[start, end)` plus a straddling predecessor. Extents are disjoint and
        // contiguous, so this is a short run (typically one or two entries).
        let mut affected: Vec<u64> = Vec::new();
        let pred = map.predecessor(&start).map(|(k, _)| *k);
        let mut next = if let Some(s) = pred {
            if map.get(&s).map(|e| e.end() > start).unwrap_or(false) {
                affected.push(s);
                map.successor_strict(&s).map(|(k, _)| *k)
            } else {
                map.successor(&start).map(|(k, _)| *k)
            }
        } else {
            map.successor(&start).map(|(k, _)| *k)
        };
        while let Some(s) = next {
            if s >= end {
                break;
            }
            affected.push(s);
            next = map.successor_strict(&s).map(|(k, _)| *k);
        }

        // Build the replacement fragments.
        let mut inserts: Vec<(u64, Extent)> = Vec::with_capacity(affected.len() + 2);
        if let Some(&s) = affected.first() {
            let e = *map.get(&s).expect("affected extent present");
            if s < start {
                inserts.push((
                    s,
                    Extent {
                        start: s,
                        len: start - s,
                        kind: e.kind,
                    },
                ));
            }
        }
        // A write beyond EOF zero-fills the gap `[size, start)`.
        if start > self.size {
            inserts.push((
                self.size,
                Extent {
                    start: self.size,
                    len: start - self.size,
                    kind: ExtentKind::Zero,
                },
            ));
        }
        inserts.push((
            start,
            Extent {
                start,
                len: end - start,
                kind,
            },
        ));
        // The right remainder of an extent straddling `end`.
        if let Some(&s) = affected.last() {
            let e = *map.get(&s).expect("affected extent present");
            if e.end() > end {
                inserts.push((
                    end,
                    Extent {
                        start: end,
                        len: e.end() - end,
                        kind: shift_kind(e.kind, end - e.start),
                    },
                ));
            }
        }

        for s in &affected {
            map = map.remove(s);
        }
        for (s, e) in inserts {
            map = map.insert(s, e);
        }
        self.extents = map;
        self.size = target_size;
    }

    /// Apply a data write: the immutable bytes live at `data_offset` in the log.
    pub fn write(&mut self, offset: u64, len: u64, data_offset: u64) {
        if len == 0 {
            return;
        }
        self.overlay(offset, offset + len, ExtentKind::Data { data_offset });
    }

    /// Apply an explicit zero range (hole punch or zero-fill).
    pub fn zero(&mut self, offset: u64, len: u64) {
        if len == 0 {
            return;
        }
        self.overlay(offset, offset + len, ExtentKind::Zero);
    }

    /// Apply a size change. Shrinking hides bytes beyond the new size (they are
    /// retained in the log but no longer referenced); growing zero-fills the
    /// newly exposed region so that truncated bytes are never resurrected.
    pub fn resize(&mut self, new_size: u64) {
        if new_size >= self.size {
            if new_size > self.size {
                self.overlay(self.size, new_size, ExtentKind::Zero);
            }
            return;
        }
        if new_size == 0 {
            self.extents = PMap::new();
            self.size = 0;
            return;
        }
        let mut map = std::mem::take(&mut self.extents);
        match map.predecessor(&(new_size - 1)).map(|(k, _)| *k) {
            Some(c) => {
                let e = *map.get(&c).expect("covering extent present");
                if e.end() > new_size {
                    map = map.remove(&c);
                    map = map.insert(
                        c,
                        Extent {
                            start: c,
                            len: new_size - c,
                            kind: e.kind,
                        },
                    );
                }
                // Drop every extent that starts at or beyond the new size.
                let mut k = map.successor_strict(&c).map(|(kk, _)| *kk);
                while let Some(s) = k {
                    map = map.remove(&s);
                    k = map.successor_strict(&s).map(|(kk, _)| *kk);
                }
                self.extents = map;
                self.size = new_size;
            }
            None => {
                // No extent covers `[0, new_size)` (only possible for an empty
                // map); everything is hidden.
                self.extents = PMap::new();
                self.size = new_size;
            }
        }
    }

    /// Plan a read of `[offset, offset + length)`, clamped to the current size.
    ///
    /// The returned pieces are ordered and confined to the file; the caller
    /// fetches `Data` pieces from the log and materialises `Zero` pieces.
    pub fn plan_read(&self, offset: u64, length: u64) -> Vec<ReadPiece> {
        let end = offset.saturating_add(length).min(self.size);
        let mut out = Vec::new();
        if offset >= end {
            return out;
        }
        // The extent covering `offset` has the largest key `<= offset` (coverage
        // is contiguous from zero). Only the k intersecting extents are then
        // visited → O(log E + k).
        let mut k = self.extents.predecessor(&offset).map(|(s, _)| *s);
        while let Some(s) = k {
            if s >= end {
                break;
            }
            let e = *self.extents.get(&s).expect("extent present");
            let (es, ee) = (e.start, e.end());
            let rs = es.max(offset);
            let re = ee.min(end);
            let len = re - rs;
            match e.kind {
                ExtentKind::Data { data_offset } => out.push(ReadPiece::Data {
                    logical_offset: data_offset + (rs - es),
                    len,
                }),
                ExtentKind::Zero => out.push(ReadPiece::Zero { len }),
            }
            if ee >= end {
                break;
            }
            k = self.extents.successor_strict(&s).map(|(kk, _)| *kk);
        }
        out
    }

    /// The number of extents a [`Self::plan_read`] visits for `[offset, offset +
    /// length)`. This is the honest *work* metric for a read (independent of
    /// wall-clock noise): with the binary-search plan it is `O(log E + k)` and
    /// does not grow with unrelated fragmentation elsewhere in the file. A
    /// read-only diagnostic (Phase 18 evidence).
    pub fn plan_read_work(&self, offset: u64, length: u64) -> usize {
        let end = offset.saturating_add(length).min(self.size);
        if offset >= end {
            return 0;
        }
        let mut count = 0usize;
        let mut k = self.extents.predecessor(&offset).map(|(s, _)| *s);
        while let Some(s) = k {
            if s >= end {
                break;
            }
            count += 1;
            let ee = self.extents.get(&s).expect("extent present").end();
            if ee >= end {
                break;
            }
            k = self.extents.successor_strict(&s).map(|(kk, _)| *kk);
        }
        count
    }
}

// ---------------------------------------------------------------------------
// DATA_EXTENT
// ---------------------------------------------------------------------------

/// Payload of `DATA_EXTENT` (variable): `offset` is the logical file position
/// and the trailing bytes are the immutable stored data. The data's absolute
/// log offset is the record's offset plus the header and this fixed prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataExtentPayload {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Byte offset of the data field inside an encoded `DATA_EXTENT` payload.
pub const DATA_EXTENT_DATA_OFFSET: usize = 20;

impl DataExtentPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(DATA_EXTENT_DATA_OFFSET + self.data.len() + 4);
        b.extend_from_slice(&DATA_EXTENT_MAGIC.to_le_bytes());
        b.extend_from_slice(&self.offset.to_le_bytes());
        b.extend_from_slice(&(self.data.len() as u64).to_le_bytes());
        b.extend_from_slice(&self.data);
        let check = crc32c::crc32c(&b);
        b.extend_from_slice(&check.to_le_bytes());
        b
    }

    pub fn decode(buf: &[u8]) -> Result<DataExtentPayload> {
        if buf.len() < DATA_EXTENT_DATA_OFFSET + 4 || get_u32(buf, 0) != DATA_EXTENT_MAGIC {
            return Err(OrfsError::Corrupt("DATA_EXTENT payload bad magic".into()));
        }
        let stored = get_u32(buf, buf.len() - 4);
        if stored != crc32c::crc32c(&buf[..buf.len() - 4]) {
            return Err(OrfsError::Corrupt(
                "DATA_EXTENT payload checksum mismatch".into(),
            ));
        }
        let data_len = get_u64(buf, 12) as usize;
        let start = DATA_EXTENT_DATA_OFFSET;
        let end = start.checked_add(data_len).ok_or(OrfsError::Overflow {
            what: "DATA_EXTENT data length",
        })?;
        // Checked add: a hostile `data_len` must not overflow (or panic in a
        // debug build) when the trailing CRC length is folded in.
        let framed = end.checked_add(4).ok_or(OrfsError::Overflow {
            what: "DATA_EXTENT framed length",
        })?;
        if framed != buf.len() {
            return Err(OrfsError::Corrupt(
                "DATA_EXTENT payload length disagreement".into(),
            ));
        }
        Ok(DataExtentPayload {
            offset: get_u64(buf, 4),
            data: buf[start..end].to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// DATA_ZERO_RANGE
// ---------------------------------------------------------------------------

/// Payload of `DATA_ZERO_RANGE` (fixed 24 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataZeroRangePayload {
    pub offset: u64,
    pub len: u64,
}

impl DataZeroRangePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; DATA_ZERO_RANGE_PAYLOAD_LEN];
        put_u32(&mut b, 0, DATA_ZERO_RANGE_MAGIC);
        put_u64(&mut b, 4, self.offset);
        put_u64(&mut b, 12, self.len);
        let check = crc32c::crc32c(&b[..20]);
        put_u32(&mut b, 20, check);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<DataZeroRangePayload> {
        check_fixed(
            buf,
            DATA_ZERO_RANGE_MAGIC,
            DATA_ZERO_RANGE_PAYLOAD_LEN,
            "DATA_ZERO_RANGE",
        )?;
        if get_u32(buf, 20) != crc32c::crc32c(&buf[..20]) {
            return Err(OrfsError::Corrupt(
                "DATA_ZERO_RANGE payload checksum mismatch".into(),
            ));
        }
        Ok(DataZeroRangePayload {
            offset: get_u64(buf, 4),
            len: get_u64(buf, 12),
        })
    }
}

// ---------------------------------------------------------------------------
// FILE_RESIZE
// ---------------------------------------------------------------------------

/// Payload of `FILE_RESIZE` (fixed 16 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileResizePayload {
    pub new_size: u64,
}

impl FileResizePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; FILE_RESIZE_PAYLOAD_LEN];
        put_u32(&mut b, 0, FILE_RESIZE_MAGIC);
        put_u64(&mut b, 4, self.new_size);
        let check = crc32c::crc32c(&b[..12]);
        put_u32(&mut b, 12, check);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<FileResizePayload> {
        check_fixed(
            buf,
            FILE_RESIZE_MAGIC,
            FILE_RESIZE_PAYLOAD_LEN,
            "FILE_RESIZE",
        )?;
        if get_u32(buf, 12) != crc32c::crc32c(&buf[..12]) {
            return Err(OrfsError::Corrupt(
                "FILE_RESIZE payload checksum mismatch".into(),
            ));
        }
        Ok(FileResizePayload {
            new_size: get_u64(buf, 4),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_round_trip() {
        let d = DataExtentPayload {
            offset: 4096,
            data: b"hello".to_vec(),
        };
        assert_eq!(DataExtentPayload::decode(&d.encode()).unwrap(), d);
        let z = DataZeroRangePayload { offset: 1, len: 5 };
        assert_eq!(DataZeroRangePayload::decode(&z.encode()).unwrap(), z);
        let r = FileResizePayload { new_size: 9 };
        assert_eq!(FileResizePayload::decode(&r.encode()).unwrap(), r);
    }

    fn ranges(m: &ExtentMap) -> Vec<(u64, u64, ExtentKind)> {
        m.extents()
            .iter()
            .map(|e| (e.start, e.len, e.kind))
            .collect()
    }

    #[test]
    fn write_beyond_eof_zero_fills_the_gap() {
        let mut m = ExtentMap::default();
        m.write(10, 3, 100);
        assert_eq!(m.size(), 13);
        assert_eq!(
            ranges(&m),
            vec![
                (0, 10, ExtentKind::Zero),
                (10, 3, ExtentKind::Data { data_offset: 100 }),
            ]
        );
    }

    #[test]
    fn overlapping_write_replaces_only_the_overlap() {
        let mut m = ExtentMap::default();
        m.write(0, 8, 0);
        m.write(3, 2, 8);
        assert_eq!(m.size(), 8);
        assert_eq!(
            ranges(&m),
            vec![
                (0, 3, ExtentKind::Data { data_offset: 0 }),
                (3, 2, ExtentKind::Data { data_offset: 8 }),
                (5, 3, ExtentKind::Data { data_offset: 5 }),
            ]
        );
        // The surviving tail keeps its own base offset; a read resolves it.
        assert_eq!(
            m.plan_read(5, 3),
            vec![ReadPiece::Data {
                logical_offset: 5,
                len: 3
            }]
        );
    }

    #[test]
    fn resize_shrink_then_grow_does_not_resurrect_bytes() {
        let mut m = ExtentMap::default();
        m.write(0, 8, 0); // A A A A A A A A
        m.resize(3);
        assert_eq!(m.size(), 3);
        m.resize(8);
        assert_eq!(m.size(), 8);
        assert_eq!(
            ranges(&m),
            vec![
                (0, 3, ExtentKind::Data { data_offset: 0 }),
                (3, 5, ExtentKind::Zero),
            ]
        );
    }

    #[test]
    fn plan_read_clamps_and_splits() {
        let mut m = ExtentMap::default();
        m.write(0, 4, 0);
        m.zero(4, 4);
        m.write(8, 4, 4);
        assert_eq!(
            m.plan_read(2, 8),
            vec![
                ReadPiece::Data {
                    logical_offset: 2,
                    len: 2
                },
                ReadPiece::Zero { len: 4 },
                ReadPiece::Data {
                    logical_offset: 4,
                    len: 2
                },
            ]
        );
        // Clamped to size (12).
        assert_eq!(m.plan_read(10, 100).len(), 1);
        assert_eq!(m.plan_read(12, 1), vec![]);
    }

    /// Build a synthetic map of `n` 4 KiB `Data` extents by directly seeding the
    /// persistent spine (so constructing 100k extents is `O(n log n)`, and the
    /// per-extent `overlay` is bypassed).
    fn fragmented(n: u64) -> ExtentMap {
        let mut extents = PMap::new();
        for i in 0..n {
            extents = extents.insert(
                i * 4096,
                Extent {
                    start: i * 4096,
                    len: 4096,
                    kind: ExtentKind::Data {
                        data_offset: i * 4096,
                    },
                },
            );
        }
        ExtentMap {
            extents,
            size: n * 4096,
        }
    }

    /// A naive `extents`-linear reference plan, used to prove the binary-search
    /// plan is byte-identical.
    fn plan_read_reference(m: &ExtentMap, offset: u64, length: u64) -> Vec<ReadPiece> {
        let end = offset.saturating_add(length).min(m.size);
        let mut out = Vec::new();
        if offset >= end {
            return out;
        }
        for e in m.extents() {
            let (es, ee) = (e.start, e.end());
            if ee <= offset {
                continue;
            }
            if es >= end {
                break;
            }
            let rs = es.max(offset);
            let re = ee.min(end);
            let len = re - rs;
            match e.kind {
                ExtentKind::Data { data_offset } => out.push(ReadPiece::Data {
                    logical_offset: data_offset + (rs - es),
                    len,
                }),
                ExtentKind::Zero => out.push(ReadPiece::Zero { len }),
            }
        }
        out
    }

    /// Phase 18: reads must not scan the whole extent map. The work of a
    /// single-byte or 4 KiB read stays ~constant (and byte-identical in result)
    /// as *unrelated* fragmentation grows from 10 to 100,000 extents.
    #[test]
    fn read_work_is_independent_of_unrelated_fragmentation() {
        let small = fragmented(10);
        let large = fragmented(100_000);
        // Read near the far end of the file, so a forward scan from the start
        // would have to walk almost every extent.
        let off = large.size() / 2;

        for length in [1u64, 4096] {
            let ws = small.plan_read_work(0, length);
            let wl = large.plan_read_work(off, length);
            // Binary search + k intersecting extents: a tiny constant, far below
            // the number of extents a linear scan would visit. A 4 KiB read over
            // 4 KiB extents intersects at most two.
            assert!(ws <= 2, "small-map read visited {ws} extents");
            assert!(wl <= 2, "large-map read visited {wl} extents");
            // The work must not grow with total fragmentation.
            assert_eq!(ws, wl, "read work grew with fragmentation");
            // Result identity: the binary-search plan equals the linear reference.
            assert_eq!(
                large.plan_read(off, length),
                plan_read_reference(&large, off, length)
            );
            assert_eq!(
                small.plan_read(0, length),
                plan_read_reference(&small, 0, length)
            );
        }

        // The work a linear scan *would* have done, for the evidence ledger.
        let linear = large
            .extents()
            .iter()
            .take_while(|e| e.end() <= off)
            .count();
        assert!(
            linear > 40_000,
            "expected the fixture to be genuinely fragmented (linear ~{linear})"
        );
    }

    /// Phase 18: the rewritten single-pass `overlay` preserves exactly the old
    /// last-writer-wins / overwrite semantics, checked against a per-byte
    /// reference model over a randomized write/zero/resize schedule.
    #[test]
    fn overlay_matches_a_reference_byte_model() {
        let mut m = ExtentMap::default();
        // Per-byte absolute log offset; `None` is a zero byte.
        let mut reference: Vec<Option<u64>> = Vec::new();
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 33
        };
        for _ in 0..3_000 {
            match next() % 3 {
                0 => {
                    let start = next() % 512;
                    let len = 1 + next() % 64;
                    let data_offset = next() % 100_000;
                    m.write(start, len, data_offset);
                    let end = (start + len) as usize;
                    if reference.len() < end {
                        reference.resize(end, None);
                    }
                    for b in start..start + len {
                        reference[b as usize] = Some(data_offset + (b - start));
                    }
                }
                1 => {
                    let start = next() % 512;
                    let len = 1 + next() % 64;
                    m.zero(start, len);
                    let end = (start + len) as usize;
                    if reference.len() < end {
                        reference.resize(end, None);
                    }
                    for b in start..start + len {
                        reference[b as usize] = None;
                    }
                }
                _ => {
                    let new_size = next() % 1024;
                    m.resize(new_size);
                    reference.resize(new_size as usize, None);
                }
            }
            assert_eq!(m.size(), reference.len() as u64);
            let mut covered = 0u64;
            for e in m.extents() {
                assert_eq!(e.start, covered, "extents must be ordered and contiguous");
                covered = e.end();
                match e.kind {
                    ExtentKind::Data { data_offset } => {
                        for b in e.start..e.end() {
                            assert_eq!(reference[b as usize], Some(data_offset + (b - e.start)));
                        }
                    }
                    ExtentKind::Zero => {
                        for b in e.start..e.end() {
                            assert_eq!(reference[b as usize], None);
                        }
                    }
                }
            }
            assert_eq!(covered, m.size());
        }
    }
}
