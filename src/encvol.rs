//! The **opt-in encrypted volume**: a real OrFS volume whose authoritative
//! segment bytes are made unreadable without the operator's key, by a
//! **length-preserving, per-segment sealed keystream** applied at the existing
//! [`crate::segment::Segment`] I/O seam (Phase 85; Phase 86 wires the mount).
//!
//! # The construction, and why it is length preserving
//!
//! Phase 85 sealed the store in *frames* (seal-then-length-prefix), which
//! inserted per-frame overhead: a record's **logical** offset no longer equalled
//! its **physical** offset inside a segment, so the namespace / scan / watermark
//! path could not resolve an encrypted volume and `orfs mount` refused. Phase 86
//! removes that obstruction:
//!
//! ```text
//!   ciphertext[i] = plaintext[i] XOR stream(key(epoch), segment_id, i)
//! ```
//!
//! [`crate::keyring::apply_positional_stream`] is a **random-access** BLAKE3-XOF
//! keystream indexed by `(epoch data key, segment id, block index)`, so the
//! ciphertext of a segment is exactly as long as its plaintext. Because the data
//! area is length preserving, *every* offset computation above the `Segment` seam
//! (the `SegmentLocator`, `scan_log`, the commit watermark, tiering, the
//! namespace/index, FUSE) is **unchanged** and works on an encrypted volume
//! exactly as it does on an unencrypted one.
//!
//! Integrity is then provided **without spending a byte of the data area**:
//!
//! * a **per-segment keyed BLAKE3 MAC** over the segment's *ciphertext*, held in
//!   a **sealed authentication table** (`crypto.segments`) in the volume's
//!   **metadata tier** — never in the authoritative data area, never in the log's
//!   plaintext framing;
//! * the table is sealed under the **master key** (`Keyring::seal_meta`), so it is
//!   unreadable without the key file and carries no key material;
//! * it binds each segment to the **epoch** that seals it, which is what makes
//!   an epoch key destruction render that segment's content inaccessible.
//!
//! See `docs/ERASURE.md` §5 for the exact trade-off (what tamper is detected,
//! **when**, and what it costs).
//!
//! # Wire format (encrypted volume)
//!
//! ```text
//!   <volume>/crypto.meta            plaintext identity (schema + CRC32C); no key bytes
//!   <volume>/crypto.segments        the sealed authentication table (master-key sealed)
//!   <volume>/or.log/NNNN…seg        the real OrFS log, keystream-sealed per segment
//!   <operator>/<key-file>           master key + wrapped epoch keys (never in the volume)
//! ```
//!
//! The encrypted volume *is* a normal OrFS volume underneath: it carries a real
//! `VOLUME_GENESIS` record and a real record stream, so `orfs mount --key-file`
//! serves it through the ordinary FUSE path. It carries `crypto.meta` instead of
//! `volume.meta`, so the unencrypted path is **byte-for-byte unchanged** — nothing
//! in this module runs unless an operator opts in with `--key-file`.
//!
//! # Epochs and segments
//!
//! A segment is sealed under exactly **one** epoch: its epoch is fixed when the
//! segment is created (in the sealed table). `orfs key rotate` therefore rotates
//! the keyring *and* forces a segment boundary, so subsequent writes are sealed
//! under the new epoch. Destroying an epoch key makes every segment bound to that
//! epoch — including a **relocated tier copy** of its ciphertext — fail closed
//! with [`OrfsError::KeyDestroyed`], while no byte is rewritten.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::{OrfsError, Result};
use crate::keyring::{self, Key, Keyring, TAG_LEN};
use crate::log::{Log, OpenMode, RootPins};
use crate::record::{Record, RecordType};
use crate::segment::{segment_file_name, LocalSegments, SharedSegmentSource};
use crate::volume::{genesis_payload, Volume, VolumeMeta, VOLUME_MAGIC};

/// Little-endian magic spelling `ORFE` (OrFS Encrypted) — the identity file's
/// schema tag prefix.
pub const CRYPTO_META_SCHEMA: &str = "orfs.crypto-meta.v1";
/// The `crypto.meta` file name.
pub const CRYPTO_META_FILE: &str = "crypto.meta";
/// The sealed authentication table's file name (metadata tier).
pub const CRYPTO_SEGMENTS_FILE: &str = "crypto.segments";
/// Schema tag of the sealed authentication table's payload.
pub const CRYPTO_SEGMENTS_SCHEMA: &str = "orfs.crypto-segments.v1";
/// The encrypted store's format version (distinct from the plaintext log's).
///
/// `2` is the Phase-86 **offset-preserving** construction; `1` was the Phase-85
/// framed seal, which is refused with a typed error rather than misread.
pub const CRYPTO_FORMAT_VERSION: u16 = 2;

/// The plaintext identity of an encrypted volume. Carries **no key material**.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoMeta {
    /// Lowercase hex volume UUID (matches the keyring's binding).
    pub volume_uuid: String,
    /// Segment size policy, in bytes.
    pub segment_size: u64,
    /// Creation time (unix seconds).
    pub created_at_unix_secs: u64,
    /// Encrypted-store format version.
    pub crypto_format_version: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct CryptoMetaFile {
    schema: String,
    crc32c: String,
    meta: CryptoMeta,
}

fn encode_meta(meta: &CryptoMeta) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(meta)
        .map_err(|e| OrfsError::Corrupt(format!("cannot serialize crypto.meta: {e}")))?;
    let file = CryptoMetaFile {
        schema: CRYPTO_META_SCHEMA.to_string(),
        crc32c: format!("{:08x}", crc32c::crc32c(&payload)),
        meta: meta.clone(),
    };
    serde_json::to_vec_pretty(&file)
        .map_err(|e| OrfsError::Corrupt(format!("cannot serialize crypto.meta: {e}")))
}

fn decode_meta(bytes: &[u8]) -> Result<CryptoMeta> {
    let file: CryptoMetaFile = serde_json::from_slice(bytes)
        .map_err(|e| OrfsError::Corrupt(format!("crypto.meta is not valid JSON: {e}")))?;
    if file.schema != CRYPTO_META_SCHEMA {
        return Err(OrfsError::Compatibility(format!(
            "crypto.meta schema {} (this build supports {CRYPTO_META_SCHEMA})",
            file.schema
        )));
    }
    let payload = serde_json::to_vec(&file.meta)
        .map_err(|e| OrfsError::Corrupt(format!("cannot re-serialize crypto.meta: {e}")))?;
    let want = u32::from_str_radix(file.crc32c.trim(), 16)
        .map_err(|_| OrfsError::Corrupt("crypto.meta checksum is not hex".into()))?;
    if crc32c::crc32c(&payload) != want {
        return Err(OrfsError::Corrupt(
            "crypto.meta checksum mismatch (the identity is corrupt)".to_string(),
        ));
    }
    if file.meta.crypto_format_version > CRYPTO_FORMAT_VERSION {
        return Err(OrfsError::Compatibility(format!(
            "encrypted volume format version {} (this build supports up to {CRYPTO_FORMAT_VERSION})",
            file.meta.crypto_format_version
        )));
    }
    if file.meta.crypto_format_version < 2 {
        return Err(OrfsError::Compatibility(format!(
            "encrypted volume format version {} is the retired Phase-85 framed seal; \
             recreate the volume with this build (docs/ERASURE.md §5)",
            file.meta.crypto_format_version
        )));
    }
    Ok(file.meta)
}

/// Whether `dir` is an encrypted volume (carries `crypto.meta`).
pub fn is_encrypted_volume(dir: &Path) -> bool {
    dir.join(CRYPTO_META_FILE).is_file()
}

/// Read and validate an encrypted volume's plaintext identity. Carries no key
/// material, so it needs no key: it is enough to discover that a volume is
/// encrypted and to check a key file's UUID binding.
pub fn read_crypto_meta(dir: &Path) -> Result<CryptoMeta> {
    decode_meta(&std::fs::read(dir.join(CRYPTO_META_FILE))?)
}

// ---------------------------------------------------------------------------
// The sealed authentication table (metadata tier)
// ---------------------------------------------------------------------------

/// One segment's record in the sealed authentication table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentEntry {
    /// The epoch whose data key seals this segment.
    pub epoch: u64,
    /// The authenticated ciphertext prefix length, in bytes.
    pub authenticated_len: u64,
    /// Lowercase hex keyed-BLAKE3 MAC over that prefix.
    pub mac: String,
}

/// The sealed per-segment table: epoch binding plus the authenticating MAC.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SegmentTable {
    /// Segment id → entry, ascending.
    pub segments: BTreeMap<u64, SegmentEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SegmentTableFile {
    schema: String,
    table: SegmentTable,
}

#[derive(Debug, Clone)]
struct RunningTagState {
    /// The seeded hasher over the segment's contiguous ciphertext prefix, when
    /// the prefix is known to have been consumed in order from offset 0.
    hasher: Option<blake3::Hasher>,
    /// Bytes of the segment's ciphertext consumed into `hasher` from offset 0.
    len: u64,
}

/// The per-segment seal: the epoch key, the positional keystream, and the
/// authenticating MAC.
///
/// Shared (`Arc`) by the writer's [`Segment`] handles and every read-only
/// [`crate::segment::ReadAt`] over the same volume, so the writer and all
/// concurrent readers use one table and one verified-segment set.
pub struct SegmentCipher {
    /// The volume root (metadata tier: `crypto.segments` lives here).
    root_dir: PathBuf,
    /// The authoritative log directory (`or.log`).
    log_dir: PathBuf,
    /// The identity the table is bound to (for the sealing AAD).
    volume_uuid: String,
    inner: RwLock<CipherInner>,
}

struct CipherInner {
    keyring: Keyring,
    table: SegmentTable,
    /// Running MAC state per segment (dropped on a gap or a rewrite).
    live: BTreeMap<u64, RunningTagState>,
    /// Unwrapped epoch data keys, memoised for the session.
    keys: BTreeMap<u64, Key>,
    /// Segment ids whose recorded MAC has been verified in this session.
    verified: BTreeMap<u64, ()>,
}

impl std::fmt::Debug for SegmentCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SegmentCipher(<sealed>)")
    }
}

impl SegmentCipher {
    fn new(keyring: Keyring, root_dir: &Path, log_dir: &Path, volume_uuid: &str) -> SegmentCipher {
        SegmentCipher {
            root_dir: root_dir.to_path_buf(),
            log_dir: log_dir.to_path_buf(),
            volume_uuid: volume_uuid.to_string(),
            inner: RwLock::new(CipherInner {
                keyring,
                table: SegmentTable::default(),
                live: BTreeMap::new(),
                keys: BTreeMap::new(),
                verified: BTreeMap::new(),
            }),
        }
    }

    /// The table path inside the metadata tier.
    fn table_path(&self) -> PathBuf {
        self.root_dir.join(CRYPTO_SEGMENTS_FILE)
    }

    /// Load the sealed table from the metadata tier.
    fn load_table(&self) -> Result<SegmentTable> {
        let path = self.table_path();
        if !path.is_file() {
            return Err(OrfsError::Corrupt(format!(
                "{} has no sealed authentication table ({CRYPTO_SEGMENTS_FILE})",
                self.root_dir.display()
            )));
        }
        let blob = std::fs::read(&path)?;
        let plain = {
            let inner = self.inner.read();
            inner
                .keyring
                .open_meta(self.volume_uuid.as_bytes(), &blob)?
        };
        let file: SegmentTableFile = serde_json::from_slice(&plain).map_err(|e| {
            OrfsError::Corrupt(format!(
                "sealed authentication table is not valid JSON: {e}"
            ))
        })?;
        if file.schema != CRYPTO_SEGMENTS_SCHEMA {
            return Err(OrfsError::Compatibility(format!(
                "authentication-table schema {} (this build supports {CRYPTO_SEGMENTS_SCHEMA})",
                file.schema
            )));
        }
        Ok(file.table)
    }

    /// Install a freshly loaded table.
    fn set_table(&self, table: SegmentTable) {
        self.inner.write().table = table;
    }

    /// The recorded entry for `id`, if any.
    pub fn entry(&self, id: u64) -> Option<SegmentEntry> {
        self.inner.read().table.segments.get(&id).cloned()
    }

    /// The epoch that seals segment `id`. Fails closed when the segment has no
    /// record (it is not part of this volume).
    pub fn epoch_of(&self, id: u64) -> Result<u64> {
        self.entry(id)
            .map(|e| e.epoch)
            .ok_or_else(|| self.no_record(id))
    }

    fn no_record(&self, id: u64) -> OrfsError {
        OrfsError::CryptoAuthFailed(format!(
            "segment {id} has no authentication record in {CRYPTO_SEGMENTS_FILE} \
             (it is not a segment of this encrypted volume)"
        ))
    }

    /// The authenticated ciphertext prefix length recorded for `id` (`0` when the
    /// segment is unknown, which makes every byte of it an unauthenticated tail).
    pub fn authenticated_len(&self, id: u64) -> u64 {
        self.inner
            .read()
            .table
            .segments
            .get(&id)
            .map(|e| e.authenticated_len)
            .unwrap_or(0)
    }

    /// The data key that seals segment `id`.
    fn segment_key(&self, id: u64) -> Result<Key> {
        let epoch = self.epoch_of(id)?;
        self.epoch_key(epoch)
    }

    /// The data key for `epoch`, memoised for the session. **Fails closed** on a
    /// destroyed or unknown epoch — never a fabricated key.
    fn epoch_key(&self, epoch: u64) -> Result<Key> {
        if let Some(k) = self.inner.read().keys.get(&epoch) {
            return Ok(k.clone());
        }
        let mut inner = self.inner.write();
        if let Some(k) = inner.keys.get(&epoch) {
            return Ok(k.clone());
        }
        let key = inner.keyring.epoch_key(epoch)?;
        inner.keys.insert(epoch, key.clone());
        Ok(key)
    }

    /// Register a **newly created** segment under the keyring's active epoch and
    /// make the record durable before the segment receives a byte.
    pub fn register(&self, id: u64) -> Result<()> {
        let mut inner = self.inner.write();
        let epoch = inner.keyring.active_epoch();
        let key = match inner.keyring.epoch_key(epoch) {
            Ok(k) => k,
            Err(e) => return Err(self.explain_key_error(epoch, e)),
        };
        let mac = hex32(&keyring::segment_tag(&key, id, 0, &[]));
        inner.table.segments.insert(
            id,
            SegmentEntry {
                epoch,
                authenticated_len: 0,
                mac,
            },
        );
        inner.live.insert(
            id,
            RunningTagState {
                hasher: None,
                len: 0,
            },
        );
        inner.verified.remove(&id);
        self.persist_locked(&inner)
    }

    /// XOR the positional keystream for `(id, offset)` into `buf`.
    pub fn seal(&self, id: u64, offset: u64, buf: &mut [u8]) -> Result<()> {
        let key = self.segment_key(id)?;
        keyring::apply_positional_stream(&key, &id.to_le_bytes(), offset, buf);
        Ok(())
    }

    /// Undo [`SegmentCipher::seal`].
    pub fn unseal(&self, id: u64, offset: u64, buf: &mut [u8]) -> Result<()> {
        let key = self.segment_key(id)?;
        keyring::apply_positional_stream(&key, &id.to_le_bytes(), offset, buf);
        Ok(())
    }

    /// Note ciphertext written at `offset` so the running segment MAC can be
    /// finalised cheaply at the next durability point.
    ///
    /// The running hash is only kept when the writes arrive contiguously from
    /// offset 0; a gap or a rewrite drops it, and [`SegmentCipher::seal_point`]
    /// then recomputes the tag from the bytes on disk. That keeps the fast path
    /// fast without ever relying on a hash that does not describe the file.
    pub fn note_write(&self, id: u64, offset: u64, ciphertext: &[u8]) {
        let seed = self.segment_key(id).ok();
        let mut inner = self.inner.write();
        match inner.live.get_mut(&id) {
            Some(state) => {
                if state.hasher.is_some() && state.len == offset {
                    if let Some(h) = state.hasher.as_mut() {
                        h.update(ciphertext);
                    }
                    state.len = offset + ciphertext.len() as u64;
                } else {
                    state.hasher = None;
                }
            }
            None => {
                let mut state = RunningTagState {
                    hasher: None,
                    len: 0,
                };
                if offset == 0 {
                    if let Some(key) = seed {
                        let mut h = keyring::segment_tag_hasher(&key, id);
                        h.update(ciphertext);
                        state.hasher = Some(h);
                        state.len = ciphertext.len() as u64;
                    }
                }
                inner.live.insert(id, state);
            }
        }
    }

    /// Advance segment `id`'s authenticated prefix to `len` and make the sealed
    /// table durable. This is the **only** point at which the store claims bytes
    /// are authenticated, and it is called after the data's own `fsync`.
    pub fn seal_point(&self, id: u64, len: u64) -> Result<()> {
        let mut inner = self.inner.write();
        let epoch = match inner.table.segments.get(&id) {
            Some(e) => e.epoch,
            None => return Err(self.no_record(id)),
        };
        if let Some(e) = inner.table.segments.get(&id) {
            if len < e.authenticated_len {
                return Err(OrfsError::Corrupt(format!(
                    "refusing to shrink segment {id}'s authenticated length \
                     ({} -> {len}): committed bytes are never withdrawn",
                    e.authenticated_len
                )));
            }
        }
        let key = match inner.keyring.epoch_key(epoch) {
            Ok(k) => k,
            Err(e) => return Err(self.explain_key_error(epoch, e)),
        };
        let incremental = inner
            .live
            .get(&id)
            .and_then(|s| s.hasher.clone().map(|h| (h, s.len)))
            .filter(|(_, hashed)| *hashed == len);
        let tag = match incremental {
            Some((mut h, _)) => {
                h.update(&len.to_le_bytes());
                *h.finalize().as_bytes()
            }
            None => self.tag_from_disk(id, len, &key)?,
        };
        self.store_tag(&mut inner, id, len, tag)
    }

    fn store_tag(
        &self,
        inner: &mut CipherInner,
        id: u64,
        len: u64,
        mac: [u8; TAG_LEN],
    ) -> Result<()> {
        let entry = inner
            .table
            .segments
            .get_mut(&id)
            .ok_or_else(|| self.no_record(id))?;
        entry.authenticated_len = len;
        entry.mac = hex32(&mac);
        self.persist_locked(inner)
    }

    /// The segment's MAC, recomputed from the ciphertext on disk.
    fn tag_from_disk(&self, id: u64, len: u64, key: &Key) -> Result<[u8; TAG_LEN]> {
        use std::os::unix::fs::FileExt;
        let path = self.log_dir.join(segment_file_name(id)?);
        let file = std::fs::File::open(&path)?;
        let physical = file.metadata()?.len();
        if len > physical {
            return Err(OrfsError::Corrupt(format!(
                "segment {id} authenticated length {len} exceeds its physical length {physical}"
            )));
        }
        let mut h = keyring::segment_tag_hasher(key, id);
        let mut remaining = len;
        let mut offset = 0u64;
        let mut buf = vec![0u8; 256 * 1024];
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            file.read_exact_at(&mut buf[..want], offset)?;
            h.update(&buf[..want]);
            offset += want as u64;
            remaining -= want as u64;
        }
        h.update(&len.to_le_bytes());
        Ok(*h.finalize().as_bytes())
    }

    /// Verify a segment's recorded MAC against the bytes at `path` (which may be
    /// a **relocated tier copy**: the bytes are the same ciphertext).
    pub fn verify_segment(&self, path: &Path, id: u64) -> Result<()> {
        let entry = self.entry(id).ok_or_else(|| self.no_record(id))?;
        let key = self.epoch_key(entry.epoch)?;
        let blob = std::fs::read(path)?;
        if entry.authenticated_len > blob.len() as u64 {
            return Err(OrfsError::Corrupt(format!(
                "segment {id} records {} authenticated bytes but only {} are present",
                entry.authenticated_len,
                blob.len()
            )));
        }
        let len = entry.authenticated_len;
        let want = hex32(&keyring::segment_tag(&key, id, len, &blob[..len as usize]));
        if !keyring::tags_equal(want.as_bytes(), entry.mac.as_bytes()) {
            return Err(OrfsError::CryptoAuthFailed(format!(
                "segment {id} failed authentication: its ciphertext does not match the \
                 MAC recorded in {CRYPTO_SEGMENTS_FILE} (tampered or corrupt bytes)"
            )));
        }
        self.inner.write().verified.insert(id, ());
        Ok(())
    }

    /// The recorded MACs of every segment, ascending (read-only inspection).
    pub fn table_entries(&self) -> Vec<(u64, SegmentEntry)> {
        self.inner
            .read()
            .table
            .segments
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// The epochs present in the table, ascending.
    pub fn table_epochs(&self) -> Vec<u64> {
        let mut out: Vec<u64> = self
            .inner
            .read()
            .table
            .segments
            .values()
            .map(|e| e.epoch)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Rotate the keyring. The *next* segment created will be sealed under the new
    /// epoch; existing segments keep the epoch they were created with.
    pub fn rotate(&self, now_unix_secs: u64) -> Result<u64> {
        let mut inner = self.inner.write();
        let epoch = inner.keyring.rotate(now_unix_secs)?;
        inner.keys.clear();
        Ok(epoch)
    }

    /// Destroy an epoch's data key (**crypto-erasure**). Never touches a byte.
    pub fn destroy_epoch(&self, epoch: u64, now_unix_secs: u64) -> Result<()> {
        let mut inner = self.inner.write();
        inner.keyring.destroy_epoch(epoch, now_unix_secs)?;
        inner.keys.remove(&epoch);
        Ok(())
    }

    /// The live epochs.
    pub fn live_epochs(&self) -> Vec<u64> {
        self.inner.read().keyring.live_epochs()
    }

    /// The destroyed epochs.
    pub fn destroyed_epochs(&self) -> Vec<u64> {
        self.inner.read().keyring.destroyed_epochs()
    }

    /// The active epoch.
    pub fn active_epoch(&self) -> u64 {
        self.inner.read().keyring.active_epoch()
    }

    /// Every epoch record (ordinal, live, created-at), for inspection.
    pub fn epoch_records(&self) -> Vec<crate::keyring::EpochRecord> {
        self.inner.read().keyring.epochs().to_vec()
    }

    /// Persist the sealed table atomically (tmp + rename + directory fsync).
    fn persist_locked(&self, inner: &CipherInner) -> Result<()> {
        let file = SegmentTableFile {
            schema: CRYPTO_SEGMENTS_SCHEMA.to_string(),
            table: inner.table.clone(),
        };
        let plain = serde_json::to_vec(&file)
            .map_err(|e| OrfsError::Corrupt(format!("cannot serialize segment table: {e}")))?;
        let blob = inner
            .keyring
            .seal_meta(self.volume_uuid.as_bytes(), &plain)?;
        let path = self.table_path();
        let tmp = self.root_dir.join(format!("{CRYPTO_SEGMENTS_FILE}.tmp"));
        std::fs::write(&tmp, &blob)?;
        std::fs::rename(&tmp, &path)?;
        crate::segment::fsync_dir(&self.root_dir)?;
        Ok(())
    }

    /// Explain a key-lookup failure in terms of the epoch it blocks.
    fn explain_key_error(&self, epoch: u64, e: OrfsError) -> OrfsError {
        match e {
            OrfsError::KeyDestroyed(_) => OrfsError::KeyDestroyed(epoch),
            other => other,
        }
    }
}

fn hex32(bytes: &[u8; TAG_LEN]) -> String {
    let mut s = String::with_capacity(TAG_LEN * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Verification reports
// ---------------------------------------------------------------------------

/// One segment's state, as reported by `verify`/`list`.
#[derive(Debug, Clone, Serialize)]
pub struct SegmentInfo {
    /// Segment id (== its first logical offset).
    pub id: u64,
    /// The epoch whose key seals it.
    pub epoch: u64,
    /// Authenticated ciphertext prefix length.
    pub authenticated_len: u64,
    /// Physical file length.
    pub physical_len: u64,
    /// `readable`, `epoch-key-destroyed`, `unauthenticated`, or `unrecorded`.
    pub state: &'static str,
}

/// The committed-log summary of an encrypted volume, when it can be assembled.
#[derive(Debug, Clone, Serialize)]
pub struct LogSummary {
    /// The committed root offset.
    pub committed_root: u64,
    /// Committed record count.
    pub records: u64,
    /// Canonical byte length.
    pub bytes: u64,
    /// Segment count in the locator.
    pub segments: u64,
}

/// A verification report for an encrypted volume.
#[derive(Debug, Clone, Serialize)]
pub struct CryptVerify {
    /// Number of segments discovered physically.
    pub segments: u64,
    /// Segments whose ciphertext authenticated and whose epoch key is live.
    pub readable: u64,
    /// Segments that cannot be read because their epoch key was destroyed.
    pub unreadable_destroyed: Vec<u64>,
    /// Segments that failed authentication (tampered/corrupt bytes).
    pub unauthenticated: Vec<u64>,
    /// Segments with no record in the sealed table.
    pub unrecorded: Vec<u64>,
    /// Whether the store is in its *intended* state.
    pub ok: bool,
    /// Per-segment detail.
    pub detail: Vec<SegmentInfo>,
    /// The committed-log summary, when the encrypted volume could be assembled.
    pub log: Option<LogSummary>,
    /// Why the log could not be assembled, when it could not.
    pub log_error: Option<String>,
}

/// A relocated encrypted store: the ciphertext copies of its segments.
#[derive(Debug, Clone, Serialize)]
pub struct Relocation {
    /// The tier root the ciphertext was copied into.
    pub tier_root: String,
    /// BLAKE3 digest (hex) of the relocated ciphertext — equal to the source's.
    pub digest: String,
    /// Number of bytes relocated.
    pub bytes: u64,
    /// The segment ids relocated.
    pub segments: Vec<u64>,
    /// The relocated file names, ascending.
    pub files: Vec<String>,
}

// ---------------------------------------------------------------------------
// The encrypted volume
// ---------------------------------------------------------------------------

/// An opened, opt-in encrypted volume.
pub struct EncryptedVolume {
    root_dir: PathBuf,
    meta: CryptoMeta,
    cipher: Arc<SegmentCipher>,
    /// The number of attempts made to verify the segment table.
    integrity_verified: bool,
}

impl EncryptedVolume {
    /// The sealed-store directory inside a volume.
    pub fn log_dir(dir: &Path) -> PathBuf {
        dir.join("or.log")
    }

    /// The `crypto.meta` path inside a volume.
    pub fn meta_path(dir: &Path) -> PathBuf {
        dir.join(CRYPTO_META_FILE)
    }

    /// The sealed authentication table's path inside a volume.
    pub fn segments_path(dir: &Path) -> PathBuf {
        dir.join(CRYPTO_SEGMENTS_FILE)
    }

    /// Create a fresh encrypted volume, generating the keyring at `key_path`.
    ///
    /// `key_path` is the **operator-supplied** location of the key file. It must
    /// be outside the volume's authoritative area; the key file is created with
    /// mode 0600.
    pub fn init(
        dir: &Path,
        key_path: &Path,
        segment_size: u64,
        uuid: [u8; 16],
        created_at_unix_secs: u64,
    ) -> Result<EncryptedVolume> {
        Self::init_with_reserve(dir, key_path, segment_size, uuid, created_at_unix_secs, 0)
    }

    /// [`EncryptedVolume::init`] with the Phase-68 **reserve** policy: refuse to
    /// create the volume unless the backing filesystem can hold the genesis record
    /// plus `reserve_bytes` kept free, and carry the reserve into the volume's
    /// capacity governor.
    pub fn init_with_reserve(
        dir: &Path,
        key_path: &Path,
        segment_size: u64,
        uuid: [u8; 16],
        created_at_unix_secs: u64,
        reserve_bytes: u64,
    ) -> Result<EncryptedVolume> {
        if segment_size == 0 {
            return Err(OrfsError::InvalidArgument(
                "segment size must be non-zero".to_string(),
            ));
        }
        if Self::meta_path(dir).exists() {
            return Err(OrfsError::AlreadyExists);
        }
        if dir.join("volume.meta").exists() {
            return Err(OrfsError::AlreadyExists);
        }
        let uuid_hex = uuid_hex(&uuid);

        // The authoritative content first: an encrypted volume *is* an OrFS
        // volume, so its genesis is a real `VOLUME_GENESIS` record and its segment
        // is a real segment — sealed length-preservingly.
        let genesis = Record::new(
            RecordType::VolumeGenesis,
            0,
            0,
            0,
            0,
            0,
            genesis_payload(&uuid, segment_size),
        )?;
        let initial_bytes = genesis.encode()?.len() as u64;
        crate::capacity::check_reservation(dir, initial_bytes, reserve_bytes)?;

        let keyring = Keyring::create(key_path, &uuid_hex, created_at_unix_secs)?;
        let log_dir = Self::log_dir(dir);
        std::fs::create_dir_all(&log_dir)?;
        std::fs::create_dir_all(dir.join("index"))?;
        let cipher = Arc::new(SegmentCipher::new(keyring, dir, &log_dir, &uuid_hex));
        // The sealed table must exist before the first segment is registered.
        cipher.persist_locked(&cipher.inner.read())?;

        let mut log = Log::create_with_cipher(&log_dir, segment_size, Some(cipher.clone()))?;
        if reserve_bytes > 0 {
            log.set_capacity_policy(
                crate::capacity::CapacityPolicy::new().with_reserve(reserve_bytes),
            );
        }
        log.append(genesis)?;
        log.sync()?;

        let meta = CryptoMeta {
            volume_uuid: uuid_hex,
            segment_size,
            created_at_unix_secs,
            crypto_format_version: CRYPTO_FORMAT_VERSION,
        };
        std::fs::write(Self::meta_path(dir), encode_meta(&meta)?)?;
        crate::segment::fsync_dir(dir)?;
        Ok(EncryptedVolume {
            root_dir: dir.to_path_buf(),
            meta,
            cipher,
            integrity_verified: true,
        })
    }

    /// Open an existing encrypted volume, requiring the key file **and**
    /// verifying every segment's authentication record.
    ///
    /// **Fails closed**: without the key (missing file, wrong volume, unknown
    /// epoch) or with any tampered segment the open returns a typed error and
    /// serves no data.
    pub fn open(dir: &Path, key_path: &Path) -> Result<EncryptedVolume> {
        let vol = Self::open_unverified(dir, key_path)?;
        vol.verify_all_segments()?;
        Ok(EncryptedVolume {
            integrity_verified: true,
            ..vol
        })
    }

    /// Open an existing encrypted volume **without** verifying every segment's
    /// authentication record.
    ///
    /// This is the honest operator surface for `orfs crypt verify`/`list` and for
    /// `orfs verify`/`recover` after a deliberate epoch destruction: they must be
    /// able to report *which* segments are cryptographically inaccessible rather
    /// than refuse to open at all. It still requires a valid, volume-bound key
    /// file, and it never fabricates plaintext. Mounting and reading always use
    /// [`EncryptedVolume::open`] (or `open_volume`, which re-verifies) instead.
    pub fn open_unverified(dir: &Path, key_path: &Path) -> Result<EncryptedVolume> {
        let meta = decode_meta(&std::fs::read(Self::meta_path(dir))?)?;
        let keyring = Keyring::load(key_path)?;
        if keyring.volume_uuid() != meta.volume_uuid {
            return Err(OrfsError::KeyUnavailable(format!(
                "key file is bound to volume {} but the volume is {}",
                keyring.volume_uuid(),
                meta.volume_uuid
            )));
        }
        let log_dir = Self::log_dir(dir);
        let cipher = Arc::new(SegmentCipher::new(
            keyring,
            dir,
            &log_dir,
            &meta.volume_uuid,
        ));
        let table = cipher.load_table()?;
        cipher.set_table(table);
        let vol = EncryptedVolume {
            root_dir: dir.to_path_buf(),
            meta,
            cipher,
            integrity_verified: false,
        };
        // The volume must at least have a segment to be a volume.
        if vol.physical_segment_ids()?.is_empty() {
            return Err(OrfsError::Corrupt(
                "encrypted volume has no segments (not a volume)".to_string(),
            ));
        }
        Ok(vol)
    }

    /// The volume's UUID (hex).
    pub fn uuid_hex(&self) -> &str {
        &self.meta.volume_uuid
    }

    /// The volume root directory.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// The segment size policy.
    pub fn segment_size(&self) -> u64 {
        self.meta.segment_size
    }

    /// The active epoch.
    pub fn active_epoch(&self) -> u64 {
        self.cipher.active_epoch()
    }

    /// The live epochs.
    pub fn live_epochs(&self) -> Vec<u64> {
        self.cipher.live_epochs()
    }

    /// The destroyed epochs.
    pub fn destroyed_epochs(&self) -> Vec<u64> {
        self.cipher.destroyed_epochs()
    }

    /// Every epoch record.
    pub fn epoch_records(&self) -> Vec<crate::keyring::EpochRecord> {
        self.cipher.epoch_records()
    }

    /// Whether `open` verified every segment's authentication record.
    pub fn integrity_verified(&self) -> bool {
        self.integrity_verified
    }

    /// The shared seal (used by the tier-read path).
    pub fn cipher(&self) -> &Arc<SegmentCipher> {
        &self.cipher
    }

    /// The segment ids physically present in the log directory, ascending.
    pub fn physical_segment_ids(&self) -> Result<Vec<u64>> {
        crate::segment::discover_segment_ids(&Self::log_dir(&self.root_dir))
    }

    /// The number of segments in the store.
    pub fn segment_count(&self) -> Result<u64> {
        Ok(self.physical_segment_ids()?.len() as u64)
    }

    /// Total physical (ciphertext) bytes in the authoritative area.
    pub fn physical_len(&self) -> Result<u64> {
        let dir = Self::log_dir(&self.root_dir);
        let mut total = 0u64;
        for id in self.physical_segment_ids()? {
            let path = dir.join(segment_file_name(id)?);
            total = total.saturating_add(std::fs::metadata(path).map(|m| m.len()).unwrap_or(0));
        }
        Ok(total)
    }

    /// Total *authenticated* ciphertext bytes (the prefix the table vouches for).
    pub fn authenticated_len(&self) -> u64 {
        self.cipher
            .table_entries()
            .iter()
            .map(|(_, e)| e.authenticated_len)
            .sum()
    }

    /// Verify every physically present segment against its sealed record.
    fn verify_all_segments(&self) -> Result<()> {
        let dir = Self::log_dir(&self.root_dir);
        for id in self.physical_segment_ids()? {
            let path = dir.join(segment_file_name(id)?);
            self.cipher.verify_segment(&path, id)?;
        }
        Ok(())
    }

    /// Open the encrypted volume as the **real OrFS volume**, resolving the log
    /// through the length-preserving seal.
    ///
    /// This is the integration point the namespace/index/read path and the FUSE
    /// mount use: because sealing preserves length, every offset computation above
    /// the `Segment` seam is unchanged. Fails closed on any authentication
    /// failure, a destroyed epoch key, or an absent key.
    pub fn open_volume(&self, mode: OpenMode) -> Result<Volume> {
        let log_dir = Self::log_dir(&self.root_dir);
        let source: SharedSegmentSource = Arc::new(LocalSegments::new(&log_dir));
        let log = Log::open_resolved_with_cipher(
            &log_dir,
            self.meta.segment_size,
            mode,
            RootPins::new(),
            source,
            Some(self.cipher.clone()),
        )?;
        let log_format_version = Volume::read_log_format_version(&log)?;
        let meta = VolumeMeta {
            magic: VOLUME_MAGIC,
            format_version: crate::FORMAT_VERSION,
            reserved: 0,
            uuid: uuid_from_hex(&self.meta.volume_uuid)?,
            created_at_unix_secs: self.meta.created_at_unix_secs,
            segment_size: self.meta.segment_size,
            meta_check: 0,
        };
        Ok(Volume {
            root_dir: self.root_dir.clone(),
            meta,
            log_format_version,
            log,
        })
    }

    /// Rotate to a new epoch: the keyring gains a new active epoch **and** the log
    /// is rolled over to a fresh segment, so subsequent writes are sealed under
    /// the new epoch while existing segments keep theirs.
    pub fn rotate(&mut self, now_unix_secs: u64) -> Result<u64> {
        let epoch = self.cipher.rotate(now_unix_secs)?;
        // Force the boundary. Offline (the volume is not mounted) and crash-safe:
        // the keyring rotation is already durable, and if the boundary fails the
        // next rotation simply advances again — no content is altered.
        let mut vol = self.open_volume(OpenMode::ReadWrite)?;
        vol.log.rollover_now()?;
        vol.log.sync()?;
        Ok(epoch)
    }

    /// Destroy an epoch's data key (crypto-erasure). Never touches a ciphertext
    /// byte.
    pub fn destroy_epoch(&mut self, epoch: u64, now_unix_secs: u64) -> Result<()> {
        self.cipher.destroy_epoch(epoch, now_unix_secs)
    }

    /// Verify the store: which segments authenticate, which are cryptographically
    /// inaccessible, and (when possible) the assembled committed log. Never
    /// fabricates plaintext.
    pub fn verify(&self) -> Result<CryptVerify> {
        let dir = Self::log_dir(&self.root_dir);
        let destroyed = self.destroyed_epochs();
        let mut detail = Vec::new();
        let mut readable = 0u64;
        let mut unreadable_destroyed = Vec::new();
        let mut unauthenticated = Vec::new();
        let mut unrecorded = Vec::new();
        for id in self.physical_segment_ids()? {
            let path = dir.join(segment_file_name(id)?);
            let physical_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let Some(entry) = self.cipher.entry(id) else {
                unrecorded.push(id);
                detail.push(SegmentInfo {
                    id,
                    epoch: 0,
                    authenticated_len: 0,
                    physical_len,
                    state: "unrecorded",
                });
                continue;
            };
            let state = match self.cipher.verify_segment(&path, id) {
                Ok(()) => {
                    readable += 1;
                    "readable"
                }
                Err(OrfsError::KeyDestroyed(_)) => {
                    unreadable_destroyed.push(id);
                    "epoch-key-destroyed"
                }
                Err(_) => {
                    unauthenticated.push(id);
                    "unauthenticated"
                }
            };
            detail.push(SegmentInfo {
                id,
                epoch: entry.epoch,
                authenticated_len: entry.authenticated_len,
                physical_len,
                state,
            });
        }
        let every_accounted_for = unauthenticated.is_empty()
            && unrecorded.is_empty()
            && unreadable_destroyed.iter().all(|id| {
                self.cipher
                    .entry(*id)
                    .map(|e| destroyed.contains(&e.epoch))
                    .unwrap_or(false)
            });
        let (log, log_error) = match self.open_volume(OpenMode::ReadOnly) {
            Ok(v) => (
                Some(LogSummary {
                    committed_root: v.log.committed_end_offset(),
                    records: v.log.committed_record_count(),
                    bytes: v.log.canonical_bytes(),
                    segments: v.log.extents().len() as u64,
                }),
                None,
            ),
            Err(e) => (None, Some(e.to_string())),
        };
        Ok(CryptVerify {
            segments: detail.len() as u64,
            readable,
            unreadable_destroyed,
            unauthenticated,
            unrecorded,
            ok: every_accounted_for,
            detail,
            log,
            log_error,
        })
    }

    /// BLAKE3 digest (hex) of the whole sealed store: every segment's ciphertext,
    /// in segment-id order, each prefixed by its id.
    pub fn ciphertext_digest(&self) -> Result<String> {
        let dir = Self::log_dir(&self.root_dir);
        let mut h = blake3::Hasher::new();
        for id in self.physical_segment_ids()? {
            h.update(&id.to_le_bytes());
            h.update(&std::fs::read(dir.join(segment_file_name(id)?))?);
        }
        Ok(h.finalize().to_hex().to_string())
    }

    /// The per-segment ciphertext digests, ascending.
    pub fn segment_digests(&self) -> Result<Vec<(u64, String)>> {
        let dir = Self::log_dir(&self.root_dir);
        let mut out = Vec::new();
        for id in self.physical_segment_ids()? {
            let bytes = std::fs::read(dir.join(segment_file_name(id)?))?;
            out.push((id, blake3::hash(&bytes).to_hex().to_string()));
        }
        Ok(out)
    }

    /// Relocate the sealed segments (their **ciphertext**) to a cold tier, copying
    /// the bytes verbatim and recording per-file digests. A tier copy is
    /// ciphertext, so destroying the epoch key renders it inaccessible too.
    pub fn relocate(&self, tier_root: &Path) -> Result<Relocation> {
        std::fs::create_dir_all(tier_root)?;
        let dir = Self::log_dir(&self.root_dir);
        let mut files = Vec::new();
        let mut segments = Vec::new();
        let mut bytes = 0u64;
        let mut whole = blake3::Hasher::new();
        for id in self.physical_segment_ids()? {
            let name = segment_file_name(id)?;
            let raw = std::fs::read(dir.join(&name))?;
            std::fs::write(tier_root.join(&name), &raw)?;
            let digest = blake3::hash(&raw).to_hex().to_string();
            std::fs::write(
                tier_root.join(format!("{name}.blake3")),
                format!("{digest}\n"),
            )?;
            whole.update(&id.to_le_bytes());
            whole.update(&raw);
            bytes += raw.len() as u64;
            files.push(name);
            segments.push(id);
        }
        crate::segment::fsync_dir(tier_root)?;
        Ok(Relocation {
            tier_root: tier_root.display().to_string(),
            digest: whole.finalize().to_hex().to_string(),
            bytes,
            segments,
            files,
        })
    }
}

/// Verify a **relocated** sealed segment (a ciphertext copy under a tier root)
/// against the source volume's sealed table, then return its plaintext.
///
/// This is the tier-read path: it resolves the segment bytes from the tier copy
/// and opens them under the segment's epoch key. A destroyed epoch key fails
/// closed here exactly as it does for the primary store.
pub fn read_relocated_segment(
    cipher: &SegmentCipher,
    tier_root: &Path,
    id: u64,
) -> Result<Vec<u8>> {
    let path = tier_root.join(segment_file_name(id)?);
    cipher.verify_segment(&path, id)?;
    let mut bytes = std::fs::read(&path)?;
    let len = std::cmp::min(bytes.len() as u64, cipher.authenticated_len(id));
    bytes.truncate(len as usize);
    cipher.unseal(id, 0, &mut bytes)?;
    Ok(bytes)
}

/// The BLAKE3 digest (hex) of a relocated encrypted store — equal to the
/// source's [`EncryptedVolume::ciphertext_digest`].
pub fn relocated_digest(cipher: &SegmentCipher, tier_root: &Path) -> Result<String> {
    let mut ids: Vec<u64> = Vec::new();
    for entry in std::fs::read_dir(tier_root)? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(id) = crate::segment::parse_segment_name(name) {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    let mut h = blake3::Hasher::new();
    for id in ids {
        h.update(&id.to_le_bytes());
        h.update(&std::fs::read(tier_root.join(segment_file_name(id)?))?);
    }
    let _ = cipher;
    Ok(h.finalize().to_hex().to_string())
}

fn uuid_hex(uuid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    for (i, b) in uuid.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn uuid_from_hex(hex: &str) -> Result<[u8; 16]> {
    let clean: String = hex.chars().filter(|c| *c != '-').collect();
    if clean.len() != 32 {
        return Err(OrfsError::Corrupt(format!(
            "volume UUID {hex} is not 32 hex digits"
        )));
    }
    let b = clean.as_bytes();
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = (b[2 * i] as char)
            .to_digit(16)
            .ok_or_else(|| OrfsError::Corrupt("volume UUID is not hex".to_string()))?;
        let lo = (b[2 * i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| OrfsError::Corrupt("volume UUID is not hex".to_string()))?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

/// Generate a fresh random UUID for an encrypted volume.
pub fn random_uuid() -> Result<[u8; 16]> {
    use std::io::Read;
    let mut uuid = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut uuid)?;
    // RFC 4122 v4 shape, matching the plaintext volume identity.
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    Ok(uuid)
}

/// The current unix time in seconds.
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A cipher over a fresh directory with the keyring written to `key.json`.
    fn cipher_in(dir: &Path, uuid: &str) -> Arc<SegmentCipher> {
        let kr = Keyring::create(&dir.join("key.json"), uuid, 1_000).unwrap();
        std::fs::create_dir_all(dir.join("or.log")).unwrap();
        Arc::new(SegmentCipher::new(kr, dir, &dir.join("or.log"), uuid))
    }

    /// The seal is a **length-preserving, random-access** keystream: transforming
    /// an arbitrary window on its own is byte-identical to transforming the whole
    /// buffer, and ciphertext length equals plaintext length. This is exactly the
    /// property that lets every offset computation above the `Segment` seam be
    /// unchanged on an encrypted volume.
    #[test]
    fn positional_seal_is_length_preserving_and_random_access() {
        let td = TempDir::new().unwrap();
        let c = cipher_in(td.path(), "u");
        c.register(7).unwrap();
        let plain: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8).collect();

        let mut whole = plain.clone();
        c.seal(7, 0, &mut whole).unwrap();

        let mut win = plain.clone();
        for (off, len) in [(0u64, 300usize), (300, 500), (800, 1200)] {
            let mut chunk = win[off as usize..off as usize + len].to_vec();
            c.seal(7, off, &mut chunk).unwrap();
            win[off as usize..off as usize + len].copy_from_slice(&chunk);
        }
        assert_eq!(whole, win, "the positional keystream is random access");
        assert_eq!(whole.len(), plain.len(), "the seal is length preserving");
        assert_ne!(whole, plain, "the seal actually transforms the bytes");

        let mut back = whole.clone();
        c.unseal(7, 0, &mut back).unwrap();
        assert_eq!(back, plain, "unseal restores the plaintext exactly");
    }

    /// A segment's authenticated prefix advances at the durability point and is
    /// **never** shrunk (committed bytes are never withdrawn).
    #[test]
    fn seal_point_authenticates_and_never_shrinks() {
        let td = TempDir::new().unwrap();
        let c = cipher_in(td.path(), "u");
        let log = td.path().join("or.log");
        let seg = crate::segment::Segment::create_with_cipher(&log, 0, Some(c.clone())).unwrap();
        let body: Vec<u8> = (0..1024u32).map(|i| (i % 97) as u8).collect();
        seg.write_at(0, &body).unwrap();
        seg.sync().unwrap();

        assert_eq!(c.authenticated_len(0), body.len() as u64);
        let path = log.join(segment_file_name(0).unwrap());
        c.verify_segment(&path, 0).unwrap();

        // Shrinking the authenticated prefix is refused.
        match c.seal_point(0, body.len() as u64 - 1) {
            Err(OrfsError::Corrupt(_)) => {}
            other => panic!("shrinking the authenticated prefix must be refused: {other:?}"),
        }
    }

    /// A destroyed epoch key renders the segment's bytes **cryptographically
    /// inaccessible** and fails closed — never a fabricated key, never plaintext.
    #[test]
    fn destroyed_epoch_fails_closed() {
        let td = TempDir::new().unwrap();
        let c = cipher_in(td.path(), "u");
        let log = td.path().join("or.log");
        let seg = crate::segment::Segment::create_with_cipher(&log, 0, Some(c.clone())).unwrap();
        seg.write_at(0, b"secret").unwrap();
        seg.sync().unwrap();

        // Rotate first (an active epoch is never destroyable), then destroy it.
        assert_eq!(c.rotate(1_500).unwrap(), 1);
        c.destroy_epoch(0, 2_000).unwrap();

        let path = log.join(segment_file_name(0).unwrap());
        match c.verify_segment(&path, 0) {
            Err(OrfsError::KeyDestroyed(0)) => {}
            other => panic!("a destroyed epoch key must fail the check closed: {other:?}"),
        }
        let mut buf = vec![0u8; 6];
        match c.unseal(0, 0, &mut buf) {
            Err(OrfsError::KeyDestroyed(0)) => {}
            other => panic!("unsealing a destroyed epoch must fail closed: {other:?}"),
        }
    }
}
