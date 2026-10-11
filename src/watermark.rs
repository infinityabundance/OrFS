//! The durable commit watermark: a completeness witness for the committed prefix
//! (research §23 *recovery*, §35 *recovery and historical invariants*; the
//! directive's requirement that recovery never silently skips corrupted committed
//! history).
//!
//! # The problem this solves
//!
//! `or.log` is realized as an ordered set of immutable segment files. If the
//! **trailing** committed segment(s) are physically removed or truncated
//! *outside* OrFS, the surviving segments still form a contiguous, self-valid
//! chain. A pure segment scan cannot distinguish "a legitimately shorter log"
//! from "a log whose newest committed segment disappeared": it reconstructs the
//! most recent *surviving* boundary and reports a strictly earlier root. That
//! silent reduction is exactly what §23 forbids.
//!
//! # The witness
//!
//! Every time the committed prefix is made durable, the log records a small
//! **watermark**: the committed root `R` and the physical coordinate
//! `(segment_id, segment_valid_len)` of the byte just before `R`, together with
//! a CRC32C. The file is updated with an atomic `write-tmp → rename → fsync`, so
//! a reader always observes either the previous or the next complete watermark,
//! never a torn one.
//!
//! On open, recovery validates the watermark against the scanned committed root.
//! If the watermark is **ahead** of the bytes that physically survive, a
//! committed segment has been lost or truncated, and the open is **refused**
//! rather than silently recovering a shorter history.
//!
//! # Non-withdrawal
//!
//! The watermark is *added metadata*: it is never part of the authoritative
//! record stream, it is written only after the bytes it describes, and it never
//! causes a committed byte to be rewritten. It is written at durability points
//! (`sync`/`flush`/batch-sync), after the segment is fsynced, so it can never
//! claim more durable history than the backing store actually holds. A missing
//! watermark (a legacy volume) is reported as *unvalidated*, not as an error.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::error::{OrfsError, Result};
use crate::segment::fsync_dir;

/// File name of the watermark inside the log directory.
pub const WATERMARK_FILE: &str = "commit.watermark";

/// Little-endian magic spelling `ORFW`.
pub const WATERMARK_MAGIC: u32 = 0x5746_524F;

/// Fixed encoded length in bytes.
pub const WATERMARK_LEN: usize = 36;

/// A durable completeness witness for the committed prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Watermark {
    /// The committed root `R` the watermark certifies.
    pub committed_root: u64,
    /// Segment id that physically holds the committed frontier.
    pub segment_id: u64,
    /// Number of committed bytes within that segment.
    pub segment_valid_len: u64,
}

impl Watermark {
    /// The physical end coordinate of the committed prefix
    /// (`segment_id + segment_valid_len`).
    pub fn physical_end(&self) -> u64 {
        self.segment_id.saturating_add(self.segment_valid_len)
    }

    /// Encode to exactly [`WATERMARK_LEN`] bytes.
    pub fn encode(&self) -> [u8; WATERMARK_LEN] {
        let mut b = [0u8; WATERMARK_LEN];
        b[0..4].copy_from_slice(&WATERMARK_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&crate::FORMAT_VERSION.to_le_bytes());
        // b[6..8] reserved
        b[8..16].copy_from_slice(&self.committed_root.to_le_bytes());
        b[16..24].copy_from_slice(&self.segment_id.to_le_bytes());
        b[24..32].copy_from_slice(&self.segment_valid_len.to_le_bytes());
        let crc = crc32c::crc32c(&b[..32]);
        b[32..36].copy_from_slice(&crc.to_le_bytes());
        b
    }

    /// Decode and validate a watermark.
    pub fn decode(buf: &[u8]) -> Result<Watermark> {
        if buf.len() < WATERMARK_LEN {
            return Err(OrfsError::Corrupt(format!(
                "commit watermark is {} bytes, expected {WATERMARK_LEN}",
                buf.len()
            )));
        }
        let stored = u32::from_le_bytes(buf[32..36].try_into().expect("4 bytes"));
        let computed = crc32c::crc32c(&buf[..32]);
        if stored != computed {
            return Err(OrfsError::Corrupt(
                "commit watermark checksum mismatch".to_string(),
            ));
        }
        let magic = u32::from_le_bytes(buf[0..4].try_into().expect("4 bytes"));
        if magic != WATERMARK_MAGIC {
            return Err(OrfsError::Corrupt(format!(
                "commit watermark bad magic 0x{magic:08X}"
            )));
        }
        let version = u16::from_le_bytes(buf[4..6].try_into().expect("2 bytes"));
        if version != crate::FORMAT_VERSION {
            return Err(OrfsError::Compatibility(format!(
                "commit watermark format version {version} (this build supports {})",
                crate::FORMAT_VERSION
            )));
        }
        Ok(Watermark {
            committed_root: u64::from_le_bytes(buf[8..16].try_into().expect("8 bytes")),
            segment_id: u64::from_le_bytes(buf[16..24].try_into().expect("8 bytes")),
            segment_valid_len: u64::from_le_bytes(buf[24..32].try_into().expect("8 bytes")),
        })
    }

    /// Path of the watermark for a log directory.
    pub fn path(dir: &Path) -> std::path::PathBuf {
        dir.join(WATERMARK_FILE)
    }

    /// Read the watermark, if present. A missing file is `Ok(None)` (a legacy
    /// volume); a present-but-corrupt file is an error (never silently ignored).
    pub fn read(dir: &Path) -> Result<Option<Watermark>> {
        match std::fs::read(Self::path(dir)) {
            Ok(bytes) => Ok(Some(Watermark::decode(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Durably persist the watermark atomically (temp file, fsync, rename,
    /// directory fsync).
    pub fn write(dir: &Path, wm: &Watermark) -> Result<()> {
        // Under the simulated power-loss layer the atomic temp-write → rename →
        // directory-fsync is modelled as one durable file write, so the watermark
        // can be lost or kept exactly as the device's flush semantics dictate.
        if let Some(result) = crate::powerloss::write_watermark(dir, wm) {
            return result;
        }
        let path = Self::path(dir);
        let tmp = dir.join("commit.watermark.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&wm.encode())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        fsync_dir(dir)?;
        Ok(())
    }
}

/// Validate the watermark against the recovered committed root.
///
/// Returns the watermark when present and consistent. Errors when the watermark
/// certifies committed history that the surviving segments do not cover — a
/// missing or truncated trailing committed segment (research §23, §35).
pub fn validate(dir: &Path, committed_root: u64) -> Result<Option<Watermark>> {
    let Some(wm) = Watermark::read(dir)? else {
        return Ok(None);
    };
    if wm.committed_root > committed_root {
        return Err(OrfsError::Corrupt(format!(
            "commit watermark certifies a committed root of {} but only {committed_root} \
             byte(s) of committed history survive (segment {} valid length {}): a trailing \
             committed segment is missing or truncated",
            wm.committed_root, wm.segment_id, wm.segment_valid_len
        )));
    }
    Ok(Some(wm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_detects_tamper() {
        let wm = Watermark {
            committed_root: 4096,
            segment_id: 0,
            segment_valid_len: 4096,
        };
        let bytes = wm.encode();
        assert_eq!(Watermark::decode(&bytes).unwrap(), wm);

        let mut bad = bytes;
        bad[8] ^= 0xFF;
        assert!(Watermark::decode(&bad).is_err());

        let mut wrong_len = bytes.to_vec();
        wrong_len.pop();
        assert!(Watermark::decode(&wrong_len).is_err());
    }

    #[test]
    fn read_write_and_validate() {
        let td = tempfile::TempDir::new().unwrap();
        let dir = td.path();
        assert_eq!(Watermark::read(dir).unwrap(), None);

        let wm = Watermark {
            committed_root: 100,
            segment_id: 64,
            segment_valid_len: 36,
        };
        assert_eq!(wm.physical_end(), 100);
        Watermark::write(dir, &wm).unwrap();
        assert_eq!(Watermark::read(dir).unwrap(), Some(wm));

        // A surviving committed root at or beyond the watermark is accepted.
        assert_eq!(validate(dir, 100).unwrap(), Some(wm));
        assert_eq!(validate(dir, 200).unwrap(), Some(wm));
        // A shorter surviving root is refused: committed history is missing.
        assert!(validate(dir, 99).is_err());
    }
}
