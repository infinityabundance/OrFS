//! **Phase 76 — immutable tier relocation.**
//!
//! Move **sealed** (immutable) authoritative segments from the local backing
//! store to a cheaper *cold tier* without withdrawing authority: the committed
//! history is never overwritten, truncated, renumbered, or GC'd — only the
//! physical *location* of a sealed segment's bytes changes. The active head
//! segment is never relocatable.
//!
//! The design adopts the Apache Kafka tiered-storage discipline (KIP-405)
//! deliberately:
//!
//! * **Metadata is strongly consistent and separate from the data tier.** The
//!   relocation catalogue is an append-only, immutable record of state
//!   transitions; it lives in the *Metadata* storage category
//!   (`src/capacity.rs::classify_storage`) and never holds segment payload bytes.
//! * **Explicit durable transitions.** Each segment has a state machine
//!   `Local → Copying{intent} → Copied{verified} → Released`, plus an operator
//!   `Recalled` path back to `Local`. Every transition is fsynced before the next
//!   (destructive) step.
//! * **Verify before forgetting.** A segment's local copy is deleted *only* after
//!   the tier copy is written, fsynced, read back, and digest-verified, and after
//!   `Released` is durable.
//! * **Idempotent copy and delete.** The tier target is content-addressed by
//!   `(volume uuid, segment id, digest)`, so a re-run after a crash converges. A
//!   delete of an already-removed local copy is a success.
//!
//! # Identity
//!
//! A root is a *position*, never a hash (§2, I2). Relocation preserves the
//! segment's identity and every committed byte: the tier copy is the local
//! file's exact bytes, and the log layer reads it through a [`SegmentSource`]
//! with no change to logical offsets, committed roots, or the watermark.
//!
//! # Failure model
//!
//! * **Process crash** — a re-run of `relocate` converges (idempotent copy and
//!   delete). The failpoints at each transition exercise this.
//! * **Tier unavailable** — reads of a `Released` segment return the typed
//!   [`OrfsError::TierUnavailable`]; the open is refused rather than silently
//!   recovering a shorter history.
//! * **Tier corruption** — a digest mismatch or a missing remote copy returns
//!   [`OrfsError::TierCorrupt`]; authority is never fabricated or destroyed.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{OrfsError, Result};
use crate::failpoints::{self, Failpoint};
use crate::log::{scan_log_with, LogScan};
use crate::segment::{
    discover_segment_ids, fsync_dir, segment_file_name, LocalSegments, SegmentSource,
    SharedSegmentSource, SEGMENT_SUFFIX,
};
use crate::volume::Volume;

/// Subdirectory of `.or_bloom/` that holds the relocation catalogue. The
/// classifier (`src/capacity.rs::classify_storage`) treats `.or_bloom/<x>` as
/// **Metadata** unless `<x>` is one of the rebuildable manifestation areas, so
/// the catalogue is accounted as metadata — strongly consistent, separate from
/// the data tier. Asserted by a unit test.
pub const TIERING_DIR: &str = "tiering";

/// The append-only relocation catalogue file name.
pub const CATALOGUE_FILE: &str = "relocations.cat";

/// Little-endian magic spelling `ORFL`.
pub const CATALOGUE_MAGIC: u32 = 0x4C46_524F;

/// Catalogue record format version.
pub const CATALOGUE_VERSION: u16 = 1;

/// Bytes of a catalogue record before the variable-length tier-root string.
const RECORD_PREFIX_LEN: usize = 4 + 2 + 1 + 2 + 8 + 16 + 8 + 8 + 32;

/// Maximum length of the stored tier-root identifier.
const MAX_TIER_ROOT_LEN: usize = 1024;

/// Suffix of an in-progress tier or recall object (staged before an atomic
/// rename).
const STAGING_SUFFIX: &str = ".tmp";

/// The durable relocation state of one segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TierState {
    /// The authoritative home is the local segment file (initial state).
    Local,
    /// An intent to relocate has been durably recorded; the tier copy may be
    /// partial. The local copy is still the authoritative home.
    Copying,
    /// The tier copy is written, fsynced, read back, and digest-verified. The
    /// local copy is still present and authoritative.
    Copied,
    /// Relocation is complete: the tier copy is the authoritative home and the
    /// local copy has been (or is being) removed idempotently.
    Released,
    /// The operator has recalled a released segment back to the local store. The
    /// local copy is authoritative again.
    Recalled,
}

impl TierState {
    /// The stable numeric code stored on disk.
    const fn code(self) -> u8 {
        match self {
            TierState::Local => 0,
            TierState::Copying => 1,
            TierState::Copied => 2,
            TierState::Released => 3,
            TierState::Recalled => 4,
        }
    }

    fn from_code(code: u8) -> Result<TierState> {
        match code {
            0 => Ok(TierState::Local),
            1 => Ok(TierState::Copying),
            2 => Ok(TierState::Copied),
            3 => Ok(TierState::Released),
            4 => Ok(TierState::Recalled),
            other => Err(OrfsError::Corrupt(format!(
                "relocation catalogue has unknown state code {other}"
            ))),
        }
    }

    /// The stable machine name (matches the `serde` spelling).
    pub const fn name(self) -> &'static str {
        match self {
            TierState::Local => "local",
            TierState::Copying => "copying",
            TierState::Copied => "copied",
            TierState::Released => "released",
            TierState::Recalled => "recalled",
        }
    }

    /// Whether the authoritative home is the tier copy.
    pub const fn home_is_tier(self) -> bool {
        matches!(self, TierState::Released)
    }
}

/// One durable relocation state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationRecord {
    /// Monotonic sequence number (assigned on append).
    pub seq: u64,
    /// The volume the segment belongs to (scopes the position §2, I2).
    pub volume_uuid: [u8; 16],
    /// The immutable segment id (its first logical byte offset).
    pub segment_id: u64,
    /// The segment file's physical length in bytes.
    pub segment_len: u64,
    /// The segment file's BLAKE3 content digest.
    pub digest: [u8; 32],
    /// The tier root identifier (the cold tier's filesystem path).
    pub tier_root: String,
    /// The state this transition establishes.
    pub state: TierState,
}

impl RelocationRecord {
    /// The digest as lowercase hexadecimal.
    pub fn digest_hex(&self) -> String {
        hex32(&self.digest)
    }

    /// Encode this record.
    fn encode(&self) -> Result<Vec<u8>> {
        if self.tier_root.len() > MAX_TIER_ROOT_LEN {
            return Err(OrfsError::InvalidArgument(format!(
                "tier root identifier is {} bytes, exceeding {MAX_TIER_ROOT_LEN}",
                self.tier_root.len()
            )));
        }
        let tier_len = self.tier_root.len() as u16;
        let mut b = Vec::with_capacity(RECORD_PREFIX_LEN + self.tier_root.len() + 4);
        b.extend_from_slice(&CATALOGUE_MAGIC.to_le_bytes());
        b.extend_from_slice(&CATALOGUE_VERSION.to_le_bytes());
        b.push(self.state.code());
        b.extend_from_slice(&tier_len.to_le_bytes());
        b.extend_from_slice(&self.seq.to_le_bytes());
        b.extend_from_slice(&self.volume_uuid);
        b.extend_from_slice(&self.segment_id.to_le_bytes());
        b.extend_from_slice(&self.segment_len.to_le_bytes());
        b.extend_from_slice(&self.digest);
        b.extend_from_slice(self.tier_root.as_bytes());
        let crc = crc32c::crc32c(&b);
        b.extend_from_slice(&crc.to_le_bytes());
        Ok(b)
    }

    /// Decode one record from `buf` (which must be exactly one record).
    fn decode(buf: &[u8]) -> Result<RelocationRecord> {
        if buf.len() < RECORD_PREFIX_LEN + 4 {
            return Err(OrfsError::Corrupt(
                "relocation catalogue record is truncated".to_string(),
            ));
        }
        let stored_crc = u32::from_le_bytes(
            buf[buf.len() - 4..]
                .try_into()
                .expect("4 crc bytes at the end"),
        );
        let computed = crc32c::crc32c(&buf[..buf.len() - 4]);
        if stored_crc != computed {
            return Err(OrfsError::Corrupt(
                "relocation catalogue record checksum mismatch".to_string(),
            ));
        }
        let magic = u32::from_le_bytes(buf[0..4].try_into().expect("4 bytes"));
        if magic != CATALOGUE_MAGIC {
            return Err(OrfsError::Corrupt(format!(
                "relocation catalogue record bad magic 0x{magic:08X}"
            )));
        }
        let version = u16::from_le_bytes(buf[4..6].try_into().expect("2 bytes"));
        if version != CATALOGUE_VERSION {
            return Err(OrfsError::Compatibility(format!(
                "relocation catalogue version {version} (this build supports {CATALOGUE_VERSION})"
            )));
        }
        let state = TierState::from_code(buf[6])?;
        let tier_len = u16::from_le_bytes(buf[7..9].try_into().expect("2 bytes")) as usize;
        let expected = RECORD_PREFIX_LEN + tier_len + 4;
        if buf.len() != expected {
            return Err(OrfsError::Corrupt(format!(
                "relocation catalogue record length {} != expected {expected}",
                buf.len()
            )));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[17..33]);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&buf[49..81]);
        let tier_root = String::from_utf8(buf[81..81 + tier_len].to_vec()).map_err(|_| {
            OrfsError::Corrupt("relocation catalogue tier root is not valid UTF-8".to_string())
        })?;
        Ok(RelocationRecord {
            seq: u64::from_le_bytes(buf[9..17].try_into().expect("8 bytes")),
            volume_uuid: uuid,
            segment_id: u64::from_le_bytes(buf[33..41].try_into().expect("8 bytes")),
            segment_len: u64::from_le_bytes(buf[41..49].try_into().expect("8 bytes")),
            digest,
            tier_root,
            state,
        })
    }
}

/// Lowercase hex of a 32-byte digest.
pub fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The encoded length in bytes of a catalogue record carrying `tier_root`.
pub fn record_encoded_len(tier_root: &str) -> u64 {
    (RECORD_PREFIX_LEN + tier_root.len() + 4) as u64
}

/// The path of the relocation catalogue for a volume root.
pub fn catalogue_path(volume_root: &Path) -> PathBuf {
    volume_root
        .join(".or_bloom")
        .join(TIERING_DIR)
        .join(CATALOGUE_FILE)
}

/// The append-only, immutable relocation catalogue.
///
/// Records are only ever appended; a committed record is never modified or
/// removed. A physically torn *trailing* record (a crash mid-append, which was
/// therefore never made durable) is ignored on read and truncated on the next
/// append — exactly the log layer's retained-tail discipline. Any other
/// corruption is a hard, fail-closed error: the catalogue never fabricates or
/// destroys authority.
pub struct RelocationCatalogue {
    path: PathBuf,
    records: Vec<RelocationRecord>,
    valid_len: u64,
    next_seq: u64,
}

impl RelocationCatalogue {
    /// Open (or create-on-first-append) the catalogue for a volume root.
    pub fn open(volume_root: &Path) -> Result<RelocationCatalogue> {
        let path = catalogue_path(volume_root);
        let (records, valid_len) = read_catalogue(&path)?;
        let next_seq = records.iter().map(|r| r.seq).max().map_or(0, |s| s + 1);
        Ok(RelocationCatalogue {
            path,
            records,
            valid_len,
            next_seq,
        })
    }

    /// The raw records in append order.
    pub fn records(&self) -> &[RelocationRecord] {
        &self.records
    }

    /// Whether the catalogue holds no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The latest record for every segment id (a fold of the append-only log).
    pub fn latest(&self) -> BTreeMap<u64, RelocationRecord> {
        let mut map: BTreeMap<u64, RelocationRecord> = BTreeMap::new();
        for r in &self.records {
            map.insert(r.segment_id, r.clone());
        }
        map
    }

    /// The latest record for one segment, if any.
    pub fn latest_for(&self, id: u64) -> Option<RelocationRecord> {
        self.records
            .iter()
            .rev()
            .find(|r| r.segment_id == id)
            .cloned()
    }

    /// Append one durable transition. The record's `seq` is assigned here.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &mut self,
        volume_uuid: [u8; 16],
        segment_id: u64,
        segment_len: u64,
        digest: [u8; 32],
        tier_root: &str,
        state: TierState,
    ) -> Result<u64> {
        let seq = self.next_seq;
        let rec = RelocationRecord {
            seq,
            volume_uuid,
            segment_id,
            segment_len,
            digest,
            tier_root: tier_root.to_string(),
            state,
        };
        let bytes = rec.encode()?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)?;
        // Drop a torn trailing record (never a durable transition) before
        // appending, so the file is exactly the durable record sequence.
        let actual = f.metadata()?.len();
        if actual > self.valid_len {
            f.set_len(self.valid_len)?;
        }
        f.seek(SeekFrom::Start(self.valid_len))?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        if let Some(parent) = self.path.parent() {
            fsync_dir(parent)?;
        }
        self.valid_len += bytes.len() as u64;
        self.next_seq = seq + 1;
        self.records.push(rec);
        Ok(seq)
    }
}

/// Read every durable record, returning `(records, valid_len)`. A physically
/// short trailing record is ignored; every other fault is a hard error.
fn read_catalogue(path: &Path) -> Result<(Vec<RelocationRecord>, u64)> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(e) => return Err(e.into()),
    };
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let mut records = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        if buf.len() - pos < RECORD_PREFIX_LEN {
            // A torn trailing record: no complete durable transition.
            break;
        }
        let tier_len =
            u16::from_le_bytes(buf[pos + 7..pos + 9].try_into().expect("2 bytes")) as usize;
        let total = RECORD_PREFIX_LEN + tier_len + 4;
        if buf.len() - pos < total {
            // A torn trailing record (its payload is incomplete).
            break;
        }
        let rec = RelocationRecord::decode(&buf[pos..pos + total])?;
        records.push(rec);
        pos += total;
    }
    Ok((records, pos as u64))
}

/// A content-addressed cold tier rooted at a filesystem directory.
///
/// Objects are addressed by `(volume uuid, segment id, digest)`:
/// `<root>/orfs-tier/<uuid>/<segment id>/<digest>.seg`. Because the digest is
/// part of the path, a re-copy after a crash is idempotent.
#[derive(Debug, Clone)]
pub struct TierStore {
    root: PathBuf,
}

impl TierStore {
    /// A store rooted at `root`.
    pub fn new(root: &Path) -> TierStore {
        TierStore {
            root: root.to_path_buf(),
        }
    }

    /// The tier root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The per-volume directory for a volume uuid.
    pub fn volume_dir(&self, uuid: &[u8; 16]) -> PathBuf {
        self.root.join("orfs-tier").join(uuid_hex(uuid))
    }

    /// The content-addressed object path for one segment.
    pub fn object_path(&self, uuid: &[u8; 16], segment_id: u64, digest_hex: &str) -> PathBuf {
        self.volume_dir(uuid)
            .join(format!("{segment_id:016}"))
            .join(format!("{digest_hex}{SEGMENT_SUFFIX}"))
    }

    /// Write `src` as the tier object for `(uuid, segment_id, digest)`.
    ///
    /// Idempotent: an existing object with the requested digest is verified and
    /// reused; otherwise the source is streamed to a staging file, fsynced, read
    /// back and digest-verified, then atomically renamed.
    pub fn put_segment(
        &self,
        uuid: &[u8; 16],
        segment_id: u64,
        digest: &[u8; 32],
        src: &Path,
    ) -> Result<u64> {
        let digest_hex = hex32(digest);
        let target = self.object_path(uuid, segment_id, &digest_hex);
        let dir = target.parent().expect("object path has a parent");
        if dir.is_dir() && target.is_file() {
            // Idempotent re-copy: the name is content-addressed, so verify the
            // existing bytes match before trusting them.
            let (existing_digest, existing_len) = hash_file(&target)?;
            if &existing_digest == digest {
                return Ok(existing_len);
            }
            return Err(OrfsError::TierCorrupt(format!(
                "tier object {} holds digest {} but {} was expected",
                target.display(),
                hex32(&existing_digest),
                digest_hex
            )));
        }
        std::fs::create_dir_all(dir)?;
        let staging = dir.join(format!("{digest_hex}{SEGMENT_SUFFIX}{STAGING_SUFFIX}"));
        // Stream the source to the staging file, fsync it, then read it back.
        let (written_digest, written_len) = copy_and_hash(src, &staging)?;
        if &written_digest != digest {
            let _ = std::fs::remove_file(&staging);
            return Err(OrfsError::TierCorrupt(format!(
                "copying segment {segment_id} produced digest {} but {} was expected",
                hex32(&written_digest),
                digest_hex
            )));
        }
        std::fs::rename(&staging, &target)?;
        fsync_dir(dir)?;
        Ok(written_len)
    }

    /// Re-verify a tier object's digest and length.
    pub fn verify_segment(
        &self,
        uuid: &[u8; 16],
        segment_id: u64,
        digest: &[u8; 32],
        expect_len: u64,
    ) -> Result<()> {
        self.require_available()?;
        let path = self.object_path(uuid, segment_id, &hex32(digest));
        if !path.is_file() {
            return Err(OrfsError::TierCorrupt(format!(
                "tier object {} is missing",
                path.display()
            )));
        }
        let (got_digest, got_len) = hash_file(&path)?;
        if &got_digest != digest {
            return Err(OrfsError::TierCorrupt(format!(
                "tier object {} digest {} != expected {}",
                path.display(),
                hex32(&got_digest),
                hex32(digest)
            )));
        }
        if expect_len != 0 && got_len != expect_len {
            return Err(OrfsError::TierCorrupt(format!(
                "tier object {} length {got_len} != expected {expect_len}",
                path.display()
            )));
        }
        Ok(())
    }

    /// Recall a tier object to `dst` (the local segment path), verified.
    pub fn recall_segment(
        &self,
        uuid: &[u8; 16],
        segment_id: u64,
        digest: &[u8; 32],
        dst: &Path,
    ) -> Result<u64> {
        self.require_available()?;
        let src = self.object_path(uuid, segment_id, &hex32(digest));
        if !src.is_file() {
            return Err(OrfsError::TierCorrupt(format!(
                "tier object {} is missing",
                src.display()
            )));
        }
        if dst.is_file() {
            // Idempotent recall: the local copy already exists. Verify it matches.
            let (dst_digest, dst_len) = hash_file(dst)?;
            if &dst_digest == digest {
                return Ok(dst_len);
            }
            return Err(OrfsError::TierCorrupt(format!(
                "local segment {} holds digest {} but {} was expected",
                dst.display(),
                hex32(&dst_digest),
                hex32(digest)
            )));
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let staging = dst.with_extension("seg.tmp");
        let (written_digest, written_len) = copy_and_hash(&src, &staging)?;
        if &written_digest != digest {
            let _ = std::fs::remove_file(&staging);
            return Err(OrfsError::TierCorrupt(format!(
                "recalling segment {segment_id} produced digest {} but {} was expected",
                hex32(&written_digest),
                hex32(digest)
            )));
        }
        std::fs::rename(&staging, dst)?;
        if let Some(parent) = dst.parent() {
            fsync_dir(parent)?;
        }
        Ok(written_len)
    }

    /// Whether the tier root is reachable (exists and is a directory).
    pub fn require_available(&self) -> Result<()> {
        if self.root.is_dir() {
            Ok(())
        } else {
            Err(OrfsError::TierUnavailable(format!(
                "tier root {} does not exist or is not a directory",
                self.root.display()
            )))
        }
    }
}

fn uuid_hex(uuid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in uuid {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Stream `src` into `dst`, fsyncing it, and return `(digest, len)` of the bytes
/// written. Reads the staging file back so a short write is caught here, not
/// later.
fn copy_and_hash(src: &Path, dst: &Path) -> Result<([u8; 32], u64)> {
    let mut input = File::open(src)?;
    let mut output = File::create(dst)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        output.write_all(&buf[..n])?;
        len += n as u64;
    }
    output.sync_all()?;
    drop(output);
    // Read back what was persisted and hash independently.
    let (read_digest, read_len) = hash_file(dst)?;
    if read_len != len || read_digest != *hasher.finalize().as_bytes() {
        return Err(OrfsError::TierCorrupt(format!(
            "staging file {} does not match the bytes written",
            dst.display()
        )));
    }
    Ok((read_digest, read_len))
}

/// Hash a file's full contents with BLAKE3, returning `(digest, len)`.
fn hash_file(path: &Path) -> Result<([u8; 32], u64)> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    let mut len = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        len += n as u64;
    }
    Ok((*hasher.finalize().as_bytes(), len))
}

/// A [`SegmentSource`] that resolves a sealed segment from the cold tier when it
/// has been `Released`, transparently to the log layer.
pub struct TieredSegments {
    log_dir: PathBuf,
    uuid: [u8; 16],
    latest: BTreeMap<u64, RelocationRecord>,
}

impl TieredSegments {
    /// Build a tier-aware source for a volume.
    pub fn for_volume(volume_root: &Path, uuid: [u8; 16]) -> Result<TieredSegments> {
        let catalogue = RelocationCatalogue::open(volume_root)?;
        Ok(TieredSegments {
            log_dir: Volume::log_dir(volume_root),
            uuid,
            latest: catalogue.latest(),
        })
    }

    /// The latest relocation record for a segment, if any.
    pub fn latest_for(&self, id: u64) -> Option<&RelocationRecord> {
        self.latest.get(&id)
    }
}

impl SegmentSource for TieredSegments {
    fn resolve_path(&self, id: u64) -> Result<PathBuf> {
        let local = self.log_dir.join(segment_file_name(id)?);
        if local.is_file() {
            // The local copy is byte-identical to the tier copy (relocation moves
            // a copy), so it is preferred whenever present.
            return Ok(local);
        }
        match self.latest.get(&id) {
            Some(rec) if rec.state == TierState::Released => {
                let store = TierStore::new(Path::new(&rec.tier_root));
                store.require_available()?;
                let path = store.object_path(&self.uuid, id, &rec.digest_hex());
                if path.is_file() {
                    Ok(path)
                } else {
                    Err(OrfsError::TierCorrupt(format!(
                        "segment {id} is released to tier {} but its object {} is missing",
                        rec.tier_root,
                        path.display()
                    )))
                }
            }
            Some(rec) => Err(OrfsError::Corrupt(format!(
                "relocation catalogue says segment {id} is `{}` but its local copy is missing",
                rec.state.name()
            ))),
            None => Err(OrfsError::Corrupt(format!(
                "segment {id} has no local file and no relocation catalogue entry \
                 (a committed segment is missing)"
            ))),
        }
    }

    fn discover(&self) -> Result<Vec<u64>> {
        let mut ids = discover_segment_ids(&self.log_dir)?;
        for (&id, rec) in &self.latest {
            if rec.state == TierState::Released {
                ids.push(id);
            }
        }
        ids.sort_unstable();
        ids.dedup();
        Ok(ids)
    }
}

/// The segment source for a volume: tier-aware when a catalogue exists, exactly
/// the local source otherwise. Used by [`crate::volume::Volume::open`] so
/// relocation is transparent to every caller.
pub fn segment_source(volume_root: &Path, uuid: [u8; 16]) -> Result<SharedSegmentSource> {
    Ok(Arc::new(TieredSegments::for_volume(volume_root, uuid)?))
}

/// A tier-aware scan of a volume's log (equivalent to
/// [`crate::log::scan_log`] over the un-relocated volume).
pub fn scan_volume(volume_root: &Path) -> Result<LogScan> {
    let meta = Volume::read_meta(volume_root)?;
    let source = TieredSegments::for_volume(volume_root, meta.uuid)?;
    scan_log_with(&source)
}

/// A local-only segment source (exported for tests and callers that have no
/// catalogue).
pub fn local_source(log_dir: &Path) -> SharedSegmentSource {
    Arc::new(LocalSegments::new(log_dir))
}

/// The outcome of one relocation or recall step.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RelocationOutcome {
    /// The segment id.
    pub segment_id: u64,
    /// What the step did: `relocated`, `already_released`, `recalled`, or
    /// `already_local`.
    pub action: &'static str,
    /// The segment's physical length in bytes.
    pub bytes: u64,
    /// The segment's content digest (lowercase hex).
    pub digest: String,
    /// The authoritative home after the step (`local` or `tier`).
    pub home: &'static str,
}

/// The relocation driver: performs the durable state machine for one volume.
pub struct Relocator {
    volume_root: PathBuf,
    log_dir: PathBuf,
    uuid: [u8; 16],
    head_id: u64,
    tier_root: Option<String>,
    catalogue: RelocationCatalogue,
}

impl Relocator {
    /// Open a relocator for a volume (read-only analysis of the log; the volume
    /// is not mounted).
    pub fn open(volume_root: &Path) -> Result<Relocator> {
        let meta = Volume::read_meta(volume_root)?;
        let scan = scan_volume(volume_root)?;
        let head_id = scan
            .extents
            .last()
            .map(|e| e.id)
            .ok_or_else(|| OrfsError::Corrupt("volume log has no segments".to_string()))?;
        let catalogue = RelocationCatalogue::open(volume_root)?;
        Ok(Relocator {
            volume_root: volume_root.to_path_buf(),
            log_dir: Volume::log_dir(volume_root),
            uuid: meta.uuid,
            head_id,
            tier_root: None,
            catalogue,
        })
    }

    /// The sealed segment ids (every canonical segment except the active head).
    pub fn sealed_ids(&self) -> Result<Vec<u64>> {
        let scan = scan_volume(&self.volume_root)?;
        Ok(scan
            .extents
            .iter()
            .map(|e| e.id)
            .filter(|&id| id != self.head_id)
            .collect())
    }

    /// Relocate one sealed segment. Idempotent and convergent: a repeated call,
    /// or a call after a crash at any transition, reaches exactly one
    /// authoritative home with the digest intact.
    pub fn relocate(&mut self, id: u64) -> Result<RelocationOutcome> {
        if id == self.head_id {
            return Err(OrfsError::InvalidArgument(format!(
                "segment {id} is the active head segment and is never relocatable"
            )));
        }
        let local = self.log_dir.join(segment_file_name(id)?);
        let existing = self.catalogue.latest_for(id);

        match existing.as_ref().map(|r| r.state) {
            Some(TierState::Released) => {
                let rec = existing.expect("released record present");
                let store = TierStore::new(Path::new(&rec.tier_root));
                store.verify_segment(&self.uuid, id, &rec.digest, rec.segment_len)?;
                // Complete an interrupted delete (idempotent).
                remove_if_present(&local)?;
                return Ok(RelocationOutcome {
                    segment_id: id,
                    action: "already_released",
                    bytes: rec.segment_len,
                    digest: rec.digest_hex(),
                    home: "tier",
                });
            }
            Some(TierState::Copied) | Some(TierState::Copying) => {
                // Resume: trust the durable intent's digest/length.
                let rec = existing.expect("resumable record present");
                self.complete_relocation(id, &local, rec.segment_len, rec.digest, &rec.tier_root)?;
                return Ok(RelocationOutcome {
                    segment_id: id,
                    action: "relocated",
                    bytes: rec.segment_len,
                    digest: rec.digest_hex(),
                    home: "tier",
                });
            }
            Some(TierState::Local) | Some(TierState::Recalled) | None => {}
        }

        // Fresh relocation: hashing the local file is the source of the digest.
        if !local.is_file() {
            return Err(OrfsError::Corrupt(format!(
                "segment {id} has no local file to relocate"
            )));
        }
        let (digest, len) = hash_file(&local)?;
        let tier_root = self.tier_root_string()?;
        self.complete_relocation(id, &local, len, digest, &tier_root)?;
        Ok(RelocationOutcome {
            segment_id: id,
            action: "relocated",
            bytes: len,
            digest: hex32(&digest),
            home: "tier",
        })
    }

    /// Run the durable `Copying → Copied → Released → delete` transitions for one
    /// segment. Every transition is fsynced before the next (destructive) step,
    /// and the local copy is deleted only after `Released` is durable.
    fn complete_relocation(
        &mut self,
        id: u64,
        local: &Path,
        len: u64,
        digest: [u8; 32],
        tier_root: &str,
    ) -> Result<()> {
        let state = self.catalogue.latest_for(id).map(|r| r.state);
        // 1. Record the intent (durable) if not already recorded.
        if !matches!(state, Some(TierState::Copying) | Some(TierState::Copied)) {
            self.catalogue
                .append(self.uuid, id, len, digest, tier_root, TierState::Copying)?;
        }
        failpoints::check(Failpoint::TierAfterIntent)?;

        // 2. Write + fsync the tier copy (idempotent, content-addressed).
        let store = TierStore::new(Path::new(tier_root));
        store.require_available()?;
        if !local.is_file() {
            return Err(OrfsError::Corrupt(format!(
                "segment {id} local copy vanished before its tier copy was verified"
            )));
        }
        store.put_segment(&self.uuid, id, &digest, local)?;
        failpoints::check(Failpoint::TierAfterRemoteCopy)?;

        // 3. Read back and digest-verify the tier copy, then record `Copied`.
        store.verify_segment(&self.uuid, id, &digest, len)?;
        self.catalogue
            .append(self.uuid, id, len, digest, tier_root, TierState::Copied)?;
        failpoints::check(Failpoint::TierAfterVerified)?;

        // 4. Record `Released` durably, *then* delete the local copy (idempotent).
        self.catalogue
            .append(self.uuid, id, len, digest, tier_root, TierState::Released)?;
        failpoints::check(Failpoint::TierAfterReleased)?;
        remove_if_present(local)?;
        fsync_dir(&self.log_dir)?;
        failpoints::check(Failpoint::TierAfterLocalDelete)?;
        Ok(())
    }

    /// Recall a released segment back to the local store, verified, and return it
    /// to `Local`.
    pub fn recall(&mut self, id: u64) -> Result<RelocationOutcome> {
        let record = self.catalogue.latest_for(id);
        let local = self.log_dir.join(segment_file_name(id)?);
        match record {
            Some(rec) if rec.state == TierState::Released => {
                let store = TierStore::new(Path::new(&rec.tier_root));
                let len = store.recall_segment(&self.uuid, id, &rec.digest, &local)?;
                failpoints::check(Failpoint::TierAfterRecall)?;
                self.catalogue.append(
                    self.uuid,
                    id,
                    len,
                    rec.digest,
                    &rec.tier_root,
                    TierState::Recalled,
                )?;
                Ok(RelocationOutcome {
                    segment_id: id,
                    action: "recalled",
                    bytes: len,
                    digest: rec.digest_hex(),
                    home: "local",
                })
            }
            _ => Ok(RelocationOutcome {
                segment_id: id,
                action: "already_local",
                bytes: 0,
                digest: record.as_ref().map(|r| r.digest_hex()).unwrap_or_default(),
                home: "local",
            }),
        }
    }

    /// The tier-root string for a new relocation, from [`Relocator::set_tier_root`].
    fn tier_root_string(&self) -> Result<String> {
        self.tier_root.clone().ok_or_else(|| {
            OrfsError::InvalidArgument(
                "no tier root set: call set_tier_root before relocating".to_string(),
            )
        })
    }

    /// The destination tier root.
    pub fn set_tier_root(&mut self, root: &Path) -> Result<()> {
        let canonical = std::fs::canonicalize(root).map_err(|e| {
            OrfsError::TierUnavailable(format!("tier root {} is not usable: {e}", root.display()))
        })?;
        self.tier_root = Some(canonical.to_string_lossy().into_owned());
        Ok(())
    }

    /// The active head segment id.
    pub fn head_id(&self) -> u64 {
        self.head_id
    }

    /// The segment ids currently released to the cold tier.
    pub fn released_ids(&self) -> Vec<u64> {
        self.catalogue
            .latest()
            .into_iter()
            .filter(|(_, r)| r.state == TierState::Released)
            .map(|(id, _)| id)
            .collect()
    }

    /// The catalogue (for reporting).
    pub fn catalogue(&self) -> &RelocationCatalogue {
        &self.catalogue
    }
}

fn remove_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// A per-segment relocation row for `orfs tier list`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TierSegmentRow {
    /// The segment id.
    pub segment_id: u64,
    /// The durable state name (`local` when there is no catalogue entry).
    pub state: String,
    /// The content digest (lowercase hex); empty when never relocated.
    pub digest: String,
    /// The authoritative home (`local` or `tier`).
    pub home: String,
    /// The segment's physical length in bytes.
    pub bytes: u64,
    /// Whether this is the active head segment (never relocatable).
    pub head: bool,
    /// The tier root this segment is released to, when released.
    pub tier_root: Option<String>,
}

/// The `orfs tier list` report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TierListReport {
    /// The volume root.
    pub volume: String,
    /// The volume uuid string.
    pub uuid: String,
    /// The active head segment id.
    pub head_segment: u64,
    /// Per-segment rows, ascending by segment id.
    pub segments: Vec<TierSegmentRow>,
    /// Local authoritative bytes under `or.log/` (the relocation *target*).
    pub local_authoritative_bytes: u64,
    /// Tier bytes held for this volume's released segments.
    pub tier_bytes: u64,
    /// Total authoritative bytes (local + tier): unchanged by relocation.
    pub total_authoritative_bytes: u64,
    /// Number of released segments.
    pub released_segments: u64,
    /// The tier roots referenced by the catalogue.
    pub tier_roots: Vec<String>,
}

/// Build the `orfs tier list` report for a volume.
pub fn list_report(volume_root: &Path) -> Result<TierListReport> {
    let meta = Volume::read_meta(volume_root)?;
    let source = TieredSegments::for_volume(volume_root, meta.uuid)?;
    let scan = scan_log_with(&source)?;
    let head_id = scan.extents.last().map(|e| e.id).unwrap_or(0);
    let log_dir = Volume::log_dir(volume_root);
    let local_authoritative_bytes = crate::manifestation::dir_bytes(&log_dir);

    let mut rows = Vec::new();
    let mut tier_bytes = 0u64;
    let mut total = 0u64;
    let mut released = 0u64;
    let mut tier_roots: Vec<String> = Vec::new();
    for e in &scan.extents {
        let record = source.latest_for(e.id).cloned();
        let (state, digest, home, tier_root, bytes) = match record {
            Some(rec) => {
                let bytes = rec.segment_len;
                if rec.state == TierState::Released {
                    released += 1;
                    tier_bytes = tier_bytes.saturating_add(bytes);
                    if !tier_roots.contains(&rec.tier_root) {
                        tier_roots.push(rec.tier_root.clone());
                    }
                }
                (
                    rec.state.name().to_string(),
                    rec.digest_hex(),
                    if rec.state.home_is_tier() {
                        "tier".to_string()
                    } else {
                        "local".to_string()
                    },
                    Some(rec.tier_root),
                    bytes,
                )
            }
            None => {
                let bytes = segment_physical_len(&log_dir, e.id);
                (
                    "local".to_string(),
                    String::new(),
                    "local".to_string(),
                    None,
                    bytes,
                )
            }
        };
        total = total.saturating_add(bytes);
        rows.push(TierSegmentRow {
            segment_id: e.id,
            state,
            digest,
            home,
            bytes,
            head: e.id == head_id,
            tier_root,
        });
    }
    Ok(TierListReport {
        volume: volume_root.display().to_string(),
        uuid: meta.uuid_string(),
        head_segment: head_id,
        segments: rows,
        local_authoritative_bytes,
        tier_bytes,
        total_authoritative_bytes: total,
        released_segments: released,
        tier_roots,
    })
}

fn segment_physical_len(log_dir: &Path, id: u64) -> u64 {
    segment_file_name(id)
        .ok()
        .and_then(|name| std::fs::metadata(log_dir.join(name)).ok())
        .map(|m| m.len())
        .unwrap_or(0)
}

/// One row of the `orfs tier verify` report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TierVerifyRow {
    /// The segment id.
    pub segment_id: u64,
    /// The durable state name.
    pub state: String,
    /// The recorded digest (lowercase hex).
    pub digest: String,
    /// Whether the tier copy was re-verified against its recorded digest.
    pub verified: bool,
    /// A human-readable detail (the failure reason when not verified).
    pub detail: String,
}

/// The `orfs tier verify` report: re-verify every relocated segment's digest.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TierVerifyReport {
    /// The volume root.
    pub volume: String,
    /// Per-relocated-segment rows.
    pub segments: Vec<TierVerifyRow>,
    /// Segments whose tier copy is missing/corrupt or whose tier is unreachable.
    pub mismatches: Vec<u64>,
    /// Segments whose tier is unreachable (a subset indicator).
    pub unavailable_segments: Vec<u64>,
    /// Every relocated segment verified.
    pub all_ok: bool,
}

/// Re-verify every relocated segment's tier copy for a volume.
pub fn verify_report(volume_root: &Path) -> Result<TierVerifyReport> {
    let meta = Volume::read_meta(volume_root)?;
    let catalogue = RelocationCatalogue::open(volume_root)?;
    let latest = catalogue.latest();
    let mut segments = Vec::new();
    let mut mismatches = Vec::new();
    let mut unavailable = Vec::new();
    for (id, rec) in &latest {
        if rec.state != TierState::Released {
            continue;
        }
        let store = TierStore::new(Path::new(&rec.tier_root));
        match store.verify_segment(&meta.uuid, *id, &rec.digest, rec.segment_len) {
            Ok(()) => segments.push(TierVerifyRow {
                segment_id: *id,
                state: rec.state.name().to_string(),
                digest: rec.digest_hex(),
                verified: true,
                detail: "digest and length match".to_string(),
            }),
            Err(e) => {
                let mut row = TierVerifyRow {
                    segment_id: *id,
                    state: rec.state.name().to_string(),
                    digest: rec.digest_hex(),
                    verified: false,
                    detail: e.to_string(),
                };
                if matches!(e, OrfsError::TierUnavailable(_)) {
                    unavailable.push(*id);
                    row.detail = format!("tier unavailable: {e}");
                }
                mismatches.push(*id);
                segments.push(row);
            }
        }
    }
    let all_ok = mismatches.is_empty();
    Ok(TierVerifyReport {
        volume: volume_root.display().to_string(),
        segments,
        mismatches,
        unavailable_segments: unavailable,
        all_ok,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_codes_round_trip() {
        for state in [
            TierState::Local,
            TierState::Copying,
            TierState::Copied,
            TierState::Released,
            TierState::Recalled,
        ] {
            assert_eq!(TierState::from_code(state.code()).unwrap(), state);
        }
        assert!(TierState::from_code(99).is_err());
    }

    #[test]
    fn record_round_trips_and_detects_tamper() {
        let rec = RelocationRecord {
            seq: 7,
            volume_uuid: [0xAB; 16],
            segment_id: 4096,
            segment_len: 123456,
            digest: [0xCD; 32],
            tier_root: "/mnt/cold/tier".to_string(),
            state: TierState::Released,
        };
        let bytes = rec.encode().unwrap();
        assert_eq!(RelocationRecord::decode(&bytes).unwrap(), rec);

        let mut bad = bytes.clone();
        bad[20] ^= 0xFF;
        assert!(RelocationRecord::decode(&bad).is_err());
    }

    #[test]
    fn catalogue_is_append_only_and_folds_latest() {
        let td = tempfile::TempDir::new().unwrap();
        let root = td.path();
        let mut cat = RelocationCatalogue::open(root).unwrap();
        assert!(cat.is_empty());
        cat.append([1; 16], 0, 100, [2; 32], "/cold", TierState::Copying)
            .unwrap();
        cat.append([1; 16], 0, 100, [2; 32], "/cold", TierState::Copied)
            .unwrap();
        cat.append([1; 16], 0, 100, [2; 32], "/cold", TierState::Released)
            .unwrap();

        // Re-open: the fold yields the latest state; earlier records are intact.
        let reopened = RelocationCatalogue::open(root).unwrap();
        assert_eq!(reopened.records().len(), 3);
        assert_eq!(reopened.latest_for(0).unwrap().state, TierState::Released);
    }

    #[test]
    fn torn_trailing_record_is_ignored_and_never_a_transition() {
        let td = tempfile::TempDir::new().unwrap();
        let root = td.path();
        {
            let mut cat = RelocationCatalogue::open(root).unwrap();
            cat.append([1; 16], 5, 64, [3; 32], "/cold", TierState::Copying)
                .unwrap();
        }
        // Append a partial (torn) record.
        let path = catalogue_path(root);
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&[0u8; RECORD_PREFIX_LEN - 3]).unwrap();
            f.sync_all().unwrap();
        }
        let reopened = RelocationCatalogue::open(root).unwrap();
        // The torn tail is ignored: exactly the one durable record survives.
        assert_eq!(reopened.records().len(), 1);
        assert_eq!(reopened.latest_for(5).unwrap().state, TierState::Copying);

        // A subsequent append truncates the torn tail and appends cleanly.
        let mut cat = RelocationCatalogue::open(root).unwrap();
        cat.append([1; 16], 5, 64, [3; 32], "/cold", TierState::Released)
            .unwrap();
        let final_cat = RelocationCatalogue::open(root).unwrap();
        assert_eq!(final_cat.records().len(), 2);
        assert_eq!(final_cat.latest_for(5).unwrap().state, TierState::Released);
    }

    #[test]
    fn catalogue_lives_in_the_metadata_category() {
        // `.or_bloom/tiering/relocations.cat` must classify as Metadata so the
        // capacity accounting attributes it to the strongly-consistent metadata
        // tier, separate from the authoritative data tier.
        let rel = Path::new(".or_bloom")
            .join(TIERING_DIR)
            .join(CATALOGUE_FILE);
        assert_eq!(
            crate::capacity::classify_storage(&rel),
            crate::capacity::StorageCategory::Metadata
        );
    }
}
