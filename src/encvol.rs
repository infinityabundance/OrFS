//! The **opt-in encrypted volume**: a real, self-contained authoritative store
//! whose segment bytes are sealed under the `src/keyring.rs` epoch keys, applied
//! at the existing [`crate::segment::Segment`] I/O seam (Phase 85,
//! `docs/ERASURE.md`).
//!
//! # What is wired, and what is not
//!
//! An **encrypted volume** is a *distinct volume kind*, selected at `orfs init`
//! with `--key-file`. It is not the default volume and it does not touch the
//! default (unencrypted) on-disk format: an encrypted volume carries
//! `crypto.meta` and no `volume.meta`, while an ordinary volume carries
//! `volume.meta` and no `crypto.meta`. Nothing in this module runs unless a
//! caller opts in, so the unencrypted path is byte-for-byte unchanged.
//!
//! * **Wired (and tested end to end, `tests/crypto_erasure.rs`):** encrypted
//!   volume create / open / append / read, epoch rotation, epoch-key destruction
//!   with the typed fail-closed error, verification, and relocation of the
//!   *ciphertext* to a cold tier (which crypto-erasure therefore also covers,
//!   because a tier copy is ciphertext).
//! * **Not wired:** mounting an encrypted volume through FUSE. `orfs mount` on a
//!   directory that carries `crypto.meta` refuses with a typed, honest error
//!   rather than mounting a plaintext projection. Wiring an encrypted mount needs
//!   the whole namespace/read path to resolve through this store (logical ≠
//!   physical offsets once frames are sealed), which is a separate phase; it is
//!   stated plainly in `docs/ERASURE.md` and `docs/RETENTION.md` rather than
//!   half-built.
//!
//! # Wire format (encrypted volume)
//!
//! ```text
//!   <volume>/crypto.meta        plaintext identity (schema + CRC32C), no key bytes
//!   <volume>/or.log/00000000000000000000.seg   the sealed authoritative store
//!   <operator>/<key-file>       master key + wrapped epoch keys (never in the volume)
//!
//!   FRAME := MAGIC(4) | FRAME_VERSION(2) | epoch(8) | SEALED
//!   SEALED := version(1) | nonce(24) | le64(ct_len) | ct(ct_len) | tag(32)   (src/keyring.rs)
//! ```
//!
//! The associated data authenticated with `SEALED` is the fixed frame header
//! `MAGIC ‖ FRAME_VERSION ‖ epoch`, so a frame's epoch binding is authenticated
//! and an epoch swap is rejected. The encrypted store writes through
//! [`crate::segment::Segment::append`], so it uses the same segment file layout
//! and the same `write_at`/`read_exact_at` seam the authoritative log uses; the
//! bytes on disk, however, are ciphertext.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{OrfsError, Result};
use crate::keyring::{self, Keyring, NONCE_LEN, SEALED_OVERHEAD, TAG_LEN};
use crate::segment::{segment_file_name, Segment};

/// Little-endian magic spelling `ORFE` (OrFS Encrypted).
pub const FRAME_MAGIC: u32 = 0x4546_524F;
/// Version byte of the frame wrapper.
pub const FRAME_VERSION: u16 = 1;
/// Fixed frame header length: magic + version + epoch.
pub const FRAME_HEADER_LEN: usize = 4 + 2 + 8;
/// Length of a `crypto.meta` file's schema tag.
pub const CRYPTO_META_SCHEMA: &str = "orfs.crypto-meta.v1";
/// The `crypto.meta` file name.
pub const CRYPTO_META_FILE: &str = "crypto.meta";
/// The encrypted store's format version (distinct from the plaintext log's).
pub const CRYPTO_FORMAT_VERSION: u16 = 1;
/// Domain prefix of the sealed genesis payload.
const GENESIS_LABEL: &[u8] = b"orfs.crypt.genesis.v1";

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

/// The sealed authoritative store: append-only frames written through the
/// [`Segment`] seam.
struct SealedLog {
    seg: Segment,
    /// Physical/logical end offset of the last complete frame.
    end: u64,
    /// Number of frames appended (used for nonce derivation).
    frames: u64,
}

impl SealedLog {
    fn create(dir: &Path) -> Result<SealedLog> {
        let seg = Segment::create(dir, 0)?;
        crate::segment::fsync_dir(dir)?;
        Ok(SealedLog {
            seg,
            end: 0,
            frames: 0,
        })
    }

    fn open(dir: &Path) -> Result<SealedLog> {
        let seg = Segment::open(dir, 0)?;
        let mut log = SealedLog {
            seg,
            end: 0,
            frames: 0,
        };
        // Walk the frame chain so `end` is the offset of the last complete frame
        // and `frames` counts them.
        let mut off = 0u64;
        let physical = log.seg.len();
        while off < physical {
            let total = log.frame_len_at(off)?;
            let next = off.checked_add(total).ok_or(OrfsError::Overflow {
                what: "sealed frame end",
            })?;
            if next > physical {
                return Err(OrfsError::Corrupt(format!(
                    "sealed frame at offset {off} extends past the segment length {physical}"
                )));
            }
            off = next;
            log.frames += 1;
        }
        if off != physical {
            return Err(OrfsError::Corrupt(
                "sealed store has a trailing partial frame".to_string(),
            ));
        }
        log.end = off;
        Ok(log)
    }

    fn len(&self) -> u64 {
        self.end
    }

    fn frame_count(&self) -> u64 {
        self.frames
    }

    /// Total encoded length of the frame starting at `offset`.
    fn frame_len_at(&self, offset: u64) -> Result<u64> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        self.seg.read_exact_at(offset, &mut header)?;
        let magic = u32::from_le_bytes(header[0..4].try_into().expect("4 bytes"));
        if magic != FRAME_MAGIC {
            return Err(OrfsError::Corrupt(format!(
                "sealed frame at offset {offset} has bad magic 0x{magic:08X}"
            )));
        }
        let version = u16::from_le_bytes(header[4..6].try_into().expect("2 bytes"));
        if version != FRAME_VERSION {
            return Err(OrfsError::Compatibility(format!(
                "sealed frame version {version} (this build supports {FRAME_VERSION})"
            )));
        }
        // Read the sealed blob's own header (version ‖ nonce ‖ ct_len).
        let mut sealed_header = [0u8; 1 + NONCE_LEN + 8];
        self.seg
            .read_exact_at(offset + FRAME_HEADER_LEN as u64, &mut sealed_header)?;
        if sealed_header[0] != keyring::SEALED_VERSION {
            return Err(OrfsError::Compatibility(format!(
                "sealed blob version {} (this build supports {})",
                sealed_header[0],
                keyring::SEALED_VERSION
            )));
        }
        let ct_len_at = 1 + NONCE_LEN;
        let ct_len = u64::from_le_bytes(
            sealed_header[ct_len_at..ct_len_at + 8]
                .try_into()
                .expect("8 bytes"),
        );
        let total = (FRAME_HEADER_LEN as u64)
            .checked_add(SEALED_OVERHEAD as u64)
            .and_then(|n| n.checked_add(ct_len))
            .ok_or(OrfsError::Overflow {
                what: "sealed frame length",
            })?;
        Ok(total)
    }

    /// Read the whole encoded frame at `offset`.
    fn read_frame(&self, offset: u64) -> Result<Vec<u8>> {
        let total = self.frame_len_at(offset)?;
        let total_usize = usize::try_from(total).map_err(|_| OrfsError::Overflow {
            what: "sealed frame length",
        })?;
        let mut buf = vec![0u8; total_usize];
        self.seg.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }

    /// Append a frame and return its start offset.
    fn append_frame(&mut self, epoch: u64, sealed: &[u8]) -> Result<u64> {
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + sealed.len());
        frame.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
        frame.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        frame.extend_from_slice(&epoch.to_le_bytes());
        frame.extend_from_slice(sealed);
        let offset = self.seg.append(&frame)?;
        self.end = offset
            .checked_add(frame.len() as u64)
            .ok_or(OrfsError::Overflow {
                what: "sealed store end",
            })?;
        self.frames += 1;
        Ok(offset)
    }

    fn sync(&self) -> Result<()> {
        self.seg.sync()
    }

    fn path(&self) -> &Path {
        self.seg.path()
    }
}

/// The authenticated data of a frame: its fixed header.
fn frame_aad(epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FRAME_HEADER_LEN);
    aad.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
    aad.extend_from_slice(&FRAME_VERSION.to_le_bytes());
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

/// A deterministic, unique nonce for a frame within an epoch: the frame ordinal
/// plus a domain byte. Frames are append-only and never rewritten, so an ordinal
/// is never reused within its epoch key.
fn frame_nonce(ordinal: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[0..8].copy_from_slice(&ordinal.to_le_bytes());
    nonce[16] = 0x0F; // domain byte: the sealed log (not key wrapping)
    nonce
}

/// The decoded plaintext of one frame together with its epoch.
#[derive(Debug, Clone, Serialize)]
pub struct FrameInfo {
    /// Frame start offset (logical == physical for the single-segment store).
    pub offset: u64,
    /// Total encoded frame length in bytes.
    pub total_len: u64,
    /// The epoch the frame is sealed under.
    pub epoch: u64,
    /// Plaintext length, when the epoch key is available.
    pub plaintext_len: Option<u64>,
}

/// A verification report for an encrypted volume.
#[derive(Debug, Clone, Serialize)]
pub struct CryptVerify {
    /// Number of frames in the store.
    pub frames: u64,
    /// Frames whose plaintext was opened.
    pub readable: u64,
    /// Frames that cannot be opened because their epoch key was destroyed.
    pub unreadable_destroyed: Vec<u64>,
    /// Whether the whole store verified.
    pub ok: bool,
    /// Per-frame detail.
    pub detail: Vec<FrameInfo>,
}

/// A relocated sealed segment (a ciphertext copy of the authoritative store).
#[derive(Debug, Clone, Serialize)]
pub struct Relocation {
    /// The relocated file's path under the tier root.
    pub path: String,
    /// BLAKE3 digest (hex) of the relocated ciphertext, equal to the source's.
    pub digest: String,
    /// Number of bytes relocated.
    pub bytes: u64,
}

/// An opened, opt-in encrypted volume.
pub struct EncryptedVolume {
    root_dir: PathBuf,
    meta: CryptoMeta,
    keyring: Keyring,
    log: SealedLog,
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
        let keyring = Keyring::create(key_path, &uuid_hex, created_at_unix_secs)?;

        let meta = CryptoMeta {
            volume_uuid: uuid_hex,
            segment_size,
            created_at_unix_secs,
            crypto_format_version: CRYPTO_FORMAT_VERSION,
        };
        let log_dir = Self::log_dir(dir);
        std::fs::create_dir_all(&log_dir)?;
        let mut log = SealedLog::create(&log_dir)?;

        // The genesis frame is itself sealed, so an encrypted volume opened
        // without its key is indistinguishable from opaque bytes.
        let genesis = genesis_plaintext(&uuid, segment_size, created_at_unix_secs);
        let epoch = keyring.active_epoch();
        let sealed =
            keyring.seal_with_epoch(epoch, &frame_nonce(0), &frame_aad(epoch), &genesis)?;
        log.append_frame(epoch, &sealed)?;
        log.sync()?;

        std::fs::write(Self::meta_path(dir), encode_meta(&meta)?)?;
        crate::segment::fsync_dir(dir)?;
        Ok(EncryptedVolume {
            root_dir: dir.to_path_buf(),
            meta,
            keyring,
            log,
        })
    }

    /// Open an existing encrypted volume, requiring the key file.
    ///
    /// **Fails closed**: without the key (missing file, wrong volume, or a
    /// destroyed epoch-0 key) the open returns a typed error and serves no data.
    pub fn open(dir: &Path, key_path: &Path) -> Result<EncryptedVolume> {
        Self::open_impl(dir, key_path, true)
    }

    /// Open an existing encrypted volume **without** requiring the sealed genesis
    /// frame to be readable.
    ///
    /// This is the honest operator surface for `orfs crypt verify`/`crypt list`
    /// after a deliberate epoch destruction: it lets the store report which frames
    /// remain readable and which are cryptographically inaccessible, instead of
    /// refusing to open at all. It still requires a valid, volume-bound key file;
    /// no plaintext is fabricated.
    pub fn open_unverified(dir: &Path, key_path: &Path) -> Result<EncryptedVolume> {
        Self::open_impl(dir, key_path, false)
    }

    fn open_impl(dir: &Path, key_path: &Path, verify_genesis: bool) -> Result<EncryptedVolume> {
        let meta = decode_meta(&std::fs::read(Self::meta_path(dir))?)?;
        let keyring = Keyring::load(key_path)?;
        if keyring.volume_uuid() != meta.volume_uuid {
            return Err(OrfsError::KeyUnavailable(format!(
                "key file is bound to volume {} but the volume is {}",
                keyring.volume_uuid(),
                meta.volume_uuid
            )));
        }
        let log = SealedLog::open(&Self::log_dir(dir))?;
        if log.frame_count() == 0 {
            return Err(OrfsError::Corrupt(
                "encrypted volume has no frames (not a volume)".to_string(),
            ));
        }
        let vol = EncryptedVolume {
            root_dir: dir.to_path_buf(),
            meta,
            keyring,
            log,
        };
        if !verify_genesis {
            return Ok(vol);
        }
        // Opening the genesis frame proves the key is correct and available.
        let genesis = vol.read_at(0)?;
        let (uuid, segment_size, created) = parse_genesis(&genesis)?;
        if uuid_hex(&uuid) != vol.meta.volume_uuid
            || segment_size != vol.meta.segment_size
            || created != vol.meta.created_at_unix_secs
        {
            return Err(OrfsError::Corrupt(
                "sealed genesis identity disagrees with crypto.meta".to_string(),
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

    /// The keyring.
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// The active epoch.
    pub fn active_epoch(&self) -> u64 {
        self.keyring.active_epoch()
    }

    /// The number of sealed frames (including the genesis frame).
    pub fn frame_count(&self) -> u64 {
        self.log.frame_count()
    }

    /// The physical length of the sealed store in bytes (all ciphertext).
    pub fn physical_len(&self) -> u64 {
        self.log.len()
    }

    /// Append `plaintext` as a new sealed frame under the active epoch. Returns
    /// the frame's offset.
    pub fn append(&mut self, plaintext: &[u8]) -> Result<u64> {
        let epoch = self.keyring.active_epoch();
        let ordinal = self.log.frame_count();
        let nonce = frame_nonce(ordinal);
        let sealed = self
            .keyring
            .seal_with_epoch(epoch, &nonce, &frame_aad(epoch), plaintext)?;
        self.log.append_frame(epoch, &sealed)
    }

    /// Read and open the frame at `offset`. Fails closed when the frame's epoch
    /// key is destroyed or unavailable.
    pub fn read_at(&self, offset: u64) -> Result<Vec<u8>> {
        let frame = self.log.read_frame(offset)?;
        if frame.len() < FRAME_HEADER_LEN {
            return Err(OrfsError::Corrupt("sealed frame is truncated".to_string()));
        }
        let epoch = u64::from_le_bytes(frame[6..14].try_into().expect("8 bytes"));
        let sealed = &frame[FRAME_HEADER_LEN..];
        self.keyring
            .open_with_epoch(epoch, &frame_aad(epoch), sealed)
    }

    /// The offset of every frame in the store.
    pub fn frame_offsets(&self) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        let mut off = 0u64;
        while off < self.log.len() {
            out.push(off);
            let total = self.log.frame_len_at(off)?;
            off = off.checked_add(total).ok_or(OrfsError::Overflow {
                what: "sealed frame end",
            })?;
        }
        Ok(out)
    }

    /// Rotate to a new epoch; subsequent appends are sealed under it.
    pub fn rotate(&mut self, now_unix_secs: u64) -> Result<u64> {
        self.keyring.rotate(now_unix_secs)
    }

    /// Destroy an epoch's data key (crypto-erasure). Never touches a ciphertext
    /// byte.
    pub fn destroy_epoch(&mut self, epoch: u64, now_unix_secs: u64) -> Result<()> {
        self.keyring.destroy_epoch(epoch, now_unix_secs)
    }

    /// Flush the sealed store to the backing store.
    pub fn sync(&self) -> Result<()> {
        self.log.sync()
    }

    /// Verify the sealed store: how many frames open, and which epochs are
    /// destroyed. Never fabricates plaintext.
    pub fn verify(&self) -> Result<CryptVerify> {
        let destroyed = self.keyring.destroyed_epochs();
        let mut readable = 0u64;
        let mut unreadable_destroyed = Vec::new();
        let mut detail = Vec::new();
        let mut off = 0u64;
        let end = self.log.len();
        while off < end {
            let total = self.log.frame_len_at(off)?;
            let frame = self.log.read_frame(off)?;
            let epoch = u64::from_le_bytes(frame[6..14].try_into().expect("8 bytes"));
            let sealed = &frame[FRAME_HEADER_LEN..];
            let plaintext_len = match self
                .keyring
                .open_with_epoch(epoch, &frame_aad(epoch), sealed)
            {
                Ok(pt) => {
                    readable += 1;
                    Some(pt.len() as u64)
                }
                Err(OrfsError::KeyDestroyed(_)) => {
                    if !unreadable_destroyed.contains(&off) {
                        unreadable_destroyed.push(off);
                    }
                    None
                }
                Err(e) => return Err(e),
            };
            detail.push(FrameInfo {
                offset: off,
                total_len: total,
                epoch,
                plaintext_len,
            });
            off = off.checked_add(total).ok_or(OrfsError::Overflow {
                what: "sealed frame end",
            })?;
        }
        let every_frame_accounted_for = detail
            .iter()
            .all(|f| f.plaintext_len.is_some() || destroyed.contains(&f.epoch));
        Ok(CryptVerify {
            frames: detail.len() as u64,
            readable,
            unreadable_destroyed,
            // The store is "ok" when every frame either opens or belongs to a
            // deliberately destroyed epoch: that is the *intended* state. A frame
            // unreadable for any other reason is a real failure.
            ok: every_frame_accounted_for,
            detail,
        })
    }

    /// BLAKE3 digest (hex) of the whole sealed store (the ciphertext).
    pub fn ciphertext_digest(&self) -> Result<String> {
        let bytes = std::fs::read(self.log.path())?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    /// Relocate the sealed segment (its **ciphertext**) to a cold tier, copying
    /// the bytes verbatim and recording the digest. A tier copy is ciphertext, so
    /// destroying the epoch key renders it inaccessible too.
    pub fn relocate(&self, tier_root: &Path) -> Result<Relocation> {
        std::fs::create_dir_all(tier_root)?;
        let src = self.log.path();
        let bytes = std::fs::read(src)?;
        let name = segment_file_name(0)?;
        let dst = tier_root.join(&name);
        std::fs::write(&dst, &bytes)?;
        let digest = blake3::hash(&bytes).to_hex().to_string();
        std::fs::write(
            tier_root.join(format!("{name}.blake3")),
            format!("{digest}\n"),
        )?;
        crate::segment::fsync_dir(tier_root)?;
        Ok(Relocation {
            path: dst.display().to_string(),
            digest,
            bytes: bytes.len() as u64,
        })
    }
}

/// Read and open a single frame from a *relocated* sealed store (a ciphertext
/// copy under a tier root), given the keyring.
///
/// This is the tier-read path: it resolves the frame bytes from the tier copy and
/// opens them under the epoch key. A destroyed epoch key fails closed here
/// exactly as it does for the primary store.
pub fn read_relocated_frame(tier_root: &Path, offset: u64, keyring: &Keyring) -> Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let path = tier_root.join(segment_file_name(0)?);
    let file = std::fs::File::open(&path)?;
    let mut header = [0u8; FRAME_HEADER_LEN];
    file.read_exact_at(&mut header, offset)?;
    let magic = u32::from_le_bytes(header[0..4].try_into().expect("4 bytes"));
    if magic != FRAME_MAGIC {
        return Err(OrfsError::TierCorrupt(format!(
            "relocated frame at offset {offset} has bad magic 0x{magic:08X}"
        )));
    }
    let epoch = u64::from_le_bytes(header[6..14].try_into().expect("8 bytes"));
    let mut sealed_header = [0u8; 1 + NONCE_LEN + 8];
    file.read_exact_at(&mut sealed_header, offset + FRAME_HEADER_LEN as u64)?;
    let ct_len_at = 1 + NONCE_LEN;
    let ct_len = u64::from_le_bytes(
        sealed_header[ct_len_at..ct_len_at + 8]
            .try_into()
            .expect("8 bytes"),
    );
    let total = (FRAME_HEADER_LEN as u64)
        .checked_add(SEALED_OVERHEAD as u64)
        .and_then(|n| n.checked_add(ct_len))
        .ok_or(OrfsError::Overflow {
            what: "relocated frame length",
        })?;
    let total = usize::try_from(total).map_err(|_| OrfsError::Overflow {
        what: "relocated frame length",
    })?;
    let mut buf = vec![0u8; total];
    file.read_exact_at(&mut buf, offset)?;
    let sealed = &buf[FRAME_HEADER_LEN..];
    keyring.open_with_epoch(epoch, &frame_aad(epoch), sealed)
}

/// The BLAKE3 digest (hex) of a relocated store — equal to the source's.
pub fn relocated_digest(tier_root: &Path) -> Result<String> {
    let path = tier_root.join(segment_file_name(0)?);
    let bytes = std::fs::read(&path)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// The sealed genesis payload.
fn genesis_plaintext(uuid: &[u8; 16], segment_size: u64, created_at_unix_secs: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(GENESIS_LABEL.len() + 16 + 16);
    out.extend_from_slice(GENESIS_LABEL);
    out.extend_from_slice(uuid);
    out.extend_from_slice(&segment_size.to_le_bytes());
    out.extend_from_slice(&created_at_unix_secs.to_le_bytes());
    out
}

fn parse_genesis(bytes: &[u8]) -> Result<([u8; 16], u64, u64)> {
    let want = GENESIS_LABEL.len() + 16 + 16;
    if bytes.len() != want || !bytes.starts_with(GENESIS_LABEL) {
        return Err(OrfsError::Corrupt(
            "sealed genesis payload has the wrong shape".to_string(),
        ));
    }
    let at = GENESIS_LABEL.len();
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes[at..at + 16]);
    let segment_size = u64::from_le_bytes(bytes[at + 16..at + 24].try_into().expect("8 bytes"));
    let created = u64::from_le_bytes(bytes[at + 24..at + 32].try_into().expect("8 bytes"));
    Ok((uuid, segment_size, created))
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

/// The total length of the fixed frame trailer (tag), exposed for tests that
/// locate the tag inside a frame.
pub const FRAME_TRAILER_LEN: usize = TAG_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const UUID: [u8; 16] = [
        0x4F, 0x72, 0x46, 0x53, 0x85, 0x00, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];

    fn init(dir: &Path, key: &Path) -> EncryptedVolume {
        EncryptedVolume::init(dir, key, 1 << 20, UUID, 1_700_000_000).unwrap()
    }

    #[test]
    fn round_trip_and_open_without_key_fails_closed() {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("vol");
        let key = td.path().join("orfs.keys");
        let mut vol = init(&dir, &key);
        let off = vol.append(b"hello sealed world").unwrap();
        vol.sync().unwrap();

        // Reopen with the key: content identical.
        let vol2 = EncryptedVolume::open(&dir, &key).unwrap();
        assert_eq!(vol2.read_at(off).unwrap(), b"hello sealed world");
        vol2.read_at(0).unwrap();

        // Without a key file at all: typed KeyUnavailable, no data.
        let missing = td.path().join("nope.keys");
        assert!(matches!(
            EncryptedVolume::open(&dir, &missing),
            Err(OrfsError::KeyUnavailable(_)) | Err(OrfsError::Io(_))
        ));
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("vol");
        let key = td.path().join("orfs.keys");
        let mut vol = init(&dir, &key);
        let marker = b"CANARY_PLAINTEXT_MARKER";
        vol.append(marker).unwrap();
        vol.sync().unwrap();

        let raw = sealed_bytes(&dir);
        assert!(
            !keyring::contains_bytes(&raw, marker),
            "plaintext must not appear in the sealed store"
        );
    }

    /// The raw bytes of the volume's sealed store.
    fn sealed_bytes(dir: &Path) -> Vec<u8> {
        let name = segment_file_name(0).unwrap();
        std::fs::read(EncryptedVolume::log_dir(dir).join(name)).unwrap()
    }

    #[test]
    fn destroyed_epoch_makes_content_inaccessible_but_bytes_unchanged() {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("vol");
        let key = td.path().join("orfs.keys");
        let mut vol = init(&dir, &key);
        let off_old = vol.append(b"epoch-0 secret").unwrap();
        let e1 = vol.rotate(1_700_000_100).unwrap();
        assert_eq!(e1, 1);
        let off_new = vol.append(b"epoch-1 content").unwrap();
        vol.sync().unwrap();

        let before = vol.ciphertext_digest().unwrap();
        let bytes_before = sealed_bytes(&dir);

        vol.destroy_epoch(0, 1_700_000_200).unwrap();

        // The epoch-0 frame now fails closed with the typed error.
        match vol.read_at(off_old) {
            Err(OrfsError::KeyDestroyed(0)) => {}
            other => panic!("expected KeyDestroyed(0), got {other:?}"),
        }
        // The epoch-1 frame is unaffected.
        assert_eq!(vol.read_at(off_new).unwrap(), b"epoch-1 content");

        // No ciphertext byte changed: the digest is identical.
        assert_eq!(vol.ciphertext_digest().unwrap(), before);
        assert_eq!(sealed_bytes(&dir), bytes_before);
    }

    #[test]
    fn relocation_copies_ciphertext_and_erasure_covers_it() {
        let td = TempDir::new().unwrap();
        let dir = td.path().join("vol");
        let tier = td.path().join("cold");
        let key = td.path().join("orfs.keys");
        let mut vol = init(&dir, &key);
        let off = vol.append(b"relocated secret").unwrap();
        vol.sync().unwrap();

        let rel = vol.relocate(&tier).unwrap();
        assert_eq!(rel.digest, vol.ciphertext_digest().unwrap());
        assert_eq!(
            read_relocated_frame(&tier, off, vol.keyring()).unwrap(),
            b"relocated secret"
        );

        // Destroy epoch 0: the tier copy is now inaccessible too, unchanged.
        vol.rotate(1_700_000_150).unwrap();
        let tier_digest_before = relocated_digest(&tier).unwrap();
        vol.destroy_epoch(0, 1_700_000_200).unwrap();
        match read_relocated_frame(&tier, off, vol.keyring()) {
            Err(OrfsError::KeyDestroyed(0)) => {}
            other => panic!("expected KeyDestroyed(0) from the tier copy, got {other:?}"),
        }
        assert_eq!(relocated_digest(&tier).unwrap(), tier_digest_before);
    }
}
