//! Volume identity and initialisation (§4).
//!
//! A volume directory contains:
//!
//! ```text
//! backup/
//! ├── volume.meta         fixed-size, checksummed volume identity
//! ├── or.log/             immutable authoritative segments
//! ├── index/              rebuildable namespace index snapshots
//! └── .or_bloom/          concealed acceleration structures (EKBLOOM &c.)
//!     ├── ekbloom/ trigram/ suffix/ image/ directory/ manifests/
//! ```
//!
//! `volume.meta` carries the volume UUID, format version, creation time, and the
//! segment-size policy. The authoritative content lives in `or.log`; the other
//! directories are rebuildable and never authoritative.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::capacity::{CapacityPolicy, CapacityReport};
use crate::error::{OrfsError, Result};
use crate::log::{scan_log, Log, OpenMode};
use crate::record::{
    get_u16, get_u32, get_u64, put_u16, put_u32, put_u64, Record, RecordType, TypeClass,
};
use crate::segment::fsync_dir;

/// `volume.meta` magic. Little-endian bytes on disk spell `ORFV`.
pub const VOLUME_MAGIC: u32 = 0x5646_524F;

/// Fixed `volume.meta` length in bytes.
pub const VOLUME_META_LEN: usize = 44;

/// Length of the **legacy** (log format version `0`) genesis payload: the
/// volume UUID followed by the segment size. A genesis of exactly this length
/// predates the `format_version` field and must be read as version `0`.
pub const LEGACY_GENESIS_PAYLOAD_LEN: usize = 24;

/// Length of the current genesis payload: UUID + segment size + `format_version`.
pub const GENESIS_PAYLOAD_LEN: usize = 26;

/// The concealed acceleration subdirectories created by `orfs init`.
pub const BLOOM_SUBDIRS: [&str; 6] = [
    "ekbloom",
    "trigram",
    "suffix",
    "image",
    "directory",
    "manifests",
];

/// Fixed-size volume identity record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeMeta {
    pub magic: u32,
    pub format_version: u16,
    /// Reserved for future use; written as zero.
    pub reserved: u16,
    pub uuid: [u8; 16],
    pub created_at_unix_secs: u64,
    pub segment_size: u64,
    pub meta_check: u32,
}

impl VolumeMeta {
    /// Serialize to exactly [`VOLUME_META_LEN`] bytes.
    pub fn encode(&self) -> [u8; VOLUME_META_LEN] {
        let mut b = [0u8; VOLUME_META_LEN];
        put_u32(&mut b, 0, self.magic);
        put_u16(&mut b, 4, self.format_version);
        put_u16(&mut b, 6, self.reserved);
        b[8..24].copy_from_slice(&self.uuid);
        put_u64(&mut b, 24, self.created_at_unix_secs);
        put_u64(&mut b, 32, self.segment_size);
        let check = crc32c::crc32c(&b[..40]);
        put_u32(&mut b, 40, check);
        b
    }

    /// Decode and validate.
    pub fn decode(buf: &[u8]) -> Result<VolumeMeta> {
        if buf.len() < VOLUME_META_LEN {
            return Err(OrfsError::Corrupt(format!(
                "volume.meta is {} bytes, expected {VOLUME_META_LEN}",
                buf.len()
            )));
        }
        let stored = get_u32(buf, 40);
        let computed = crc32c::crc32c(&buf[..40]);
        if stored != computed {
            return Err(OrfsError::Corrupt(
                "volume.meta checksum mismatch".to_string(),
            ));
        }
        let magic = get_u32(buf, 0);
        if magic != VOLUME_MAGIC {
            return Err(OrfsError::Corrupt(format!(
                "volume.meta bad magic 0x{magic:08X}"
            )));
        }
        let format_version = get_u16(buf, 4);
        // Accept any known version <= this build's, never rejecting an older one;
        // refuse an unknown *higher* version with the typed error.
        if format_version > crate::FORMAT_VERSION {
            return Err(OrfsError::UnsupportedFormatVersion {
                found: format_version,
                supported: crate::FORMAT_VERSION,
            });
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buf[8..24]);
        let segment_size = get_u64(buf, 32);
        if segment_size == 0 {
            return Err(OrfsError::Corrupt(
                "volume.meta has a zero segment size".to_string(),
            ));
        }
        Ok(VolumeMeta {
            magic,
            format_version,
            reserved: get_u16(buf, 6),
            uuid,
            created_at_unix_secs: get_u64(buf, 24),
            segment_size,
            meta_check: stored,
        })
    }

    /// Canonical UUID string (`8-4-4-4-12`).
    pub fn uuid_string(&self) -> String {
        uuid_string(&self.uuid)
    }
}

fn uuid_string(b: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn finalize_uuid(mut b: [u8; 16]) -> [u8; 16] {
    // Set RFC 4122 version 4 and variant bits.
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    b
}

fn random_uuid() -> [u8; 16] {
    let mut b = [0u8; 16];
    if let Ok(mut f) = File::open("/dev/urandom") {
        if f.read_exact(&mut b).is_ok() {
            return finalize_uuid(b);
        }
    }
    // Deterministic-from-entropy fallback; never used when /dev/urandom exists.
    let mut hasher = blake3::Hasher::new();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    hasher.update(&nanos.to_le_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(b"orfs-volume-uuid");
    let out = hasher.finalize();
    b.copy_from_slice(&out.as_bytes()[..16]);
    finalize_uuid(b)
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The parsed genesis (volume-identity) payload.
///
/// The first 24 bytes are the layout every legacy genesis shares — the volume
/// UUID and the segment-size policy — so the two-byte `format_version` is a
/// strict suffix and a legacy reader (or a reader that predates the field) can
/// still read the shared prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisIdentity {
    pub uuid: [u8; 16],
    pub segment_size: u64,
    /// The authoritative-log format version. `0` = legacy (the field was
    /// absent). See [`crate::LOG_FORMAT_VERSION`].
    pub format_version: u16,
}

/// The genesis payload written for a **new** volume: the volume UUID, the
/// segment-size policy, and the current [`crate::LOG_FORMAT_VERSION`].
pub fn genesis_payload(uuid: &[u8; 16], segment_size: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(GENESIS_PAYLOAD_LEN);
    v.extend_from_slice(uuid);
    v.extend_from_slice(&segment_size.to_le_bytes());
    v.extend_from_slice(&crate::LOG_FORMAT_VERSION.to_le_bytes());
    v
}

/// Parse a genesis payload.
///
/// A payload of exactly [`LEGACY_GENESIS_PAYLOAD_LEN`] bytes carries no version
/// field and is read as version `0`. A longer payload carries a little-endian
/// `u16` version at offset [`LEGACY_GENESIS_PAYLOAD_LEN`]. Every known version
/// `<= crate::LOG_FORMAT_VERSION` is accepted (an older version is **never**
/// rejected); an unknown **higher** version is refused with
/// [`OrfsError::UnsupportedFormatVersion`].
pub fn parse_genesis_payload(payload: &[u8]) -> Result<GenesisIdentity> {
    if payload.len() < LEGACY_GENESIS_PAYLOAD_LEN {
        return Err(OrfsError::Corrupt(format!(
            "genesis payload is {} bytes, expected at least {LEGACY_GENESIS_PAYLOAD_LEN}",
            payload.len()
        )));
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&payload[..16]);
    let segment_size = get_u64(payload, 16);
    let format_version = if payload.len() == LEGACY_GENESIS_PAYLOAD_LEN {
        // Legacy: the version field is absent, so the value is inferred as 0.
        0
    } else if payload.len() >= GENESIS_PAYLOAD_LEN {
        get_u16(payload, LEGACY_GENESIS_PAYLOAD_LEN)
    } else {
        return Err(OrfsError::Corrupt(format!(
            "genesis payload length {} is neither legacy ({LEGACY_GENESIS_PAYLOAD_LEN}) \
             nor versioned (>= {GENESIS_PAYLOAD_LEN})",
            payload.len()
        )));
    };
    if format_version > crate::LOG_FORMAT_VERSION {
        return Err(OrfsError::UnsupportedFormatVersion {
            found: format_version,
            supported: crate::LOG_FORMAT_VERSION,
        });
    }
    Ok(GenesisIdentity {
        uuid,
        segment_size,
        format_version,
    })
}

/// An opened volume: identity plus the authoritative log.
pub struct Volume {
    pub root_dir: PathBuf,
    pub meta: VolumeMeta,
    /// The authoritative-log format version read from (or written into) the
    /// genesis record. `0` = legacy; see [`crate::LOG_FORMAT_VERSION`].
    pub log_format_version: u16,
    pub log: Log,
}

impl Volume {
    /// `volume.meta` path for a volume directory.
    pub fn meta_path(dir: &Path) -> PathBuf {
        dir.join("volume.meta")
    }

    /// `or.log` directory for a volume directory.
    pub fn log_dir(dir: &Path) -> PathBuf {
        dir.join("or.log")
    }

    /// Read and validate the volume identity.
    pub fn read_meta(dir: &Path) -> Result<VolumeMeta> {
        let bytes = std::fs::read(Self::meta_path(dir))?;
        VolumeMeta::decode(&bytes)
    }

    /// Initialize a new volume with a fresh UUID and a genesis record.
    pub fn init(dir: &Path, segment_size: u64) -> Result<Volume> {
        Self::init_with_uuid(dir, segment_size, random_uuid(), now_unix_secs())
    }

    /// Initialize a new volume with an explicit identity. Used by tests and
    /// evidence generation to produce reproducible volumes.
    pub fn init_with_uuid(
        dir: &Path,
        segment_size: u64,
        uuid: [u8; 16],
        created_at_unix_secs: u64,
    ) -> Result<Volume> {
        if segment_size == 0 {
            return Err(OrfsError::InvalidArgument(
                "segment size must be non-zero".to_string(),
            ));
        }
        let meta_path = Self::meta_path(dir);
        if meta_path.exists() {
            return Err(OrfsError::AlreadyExists);
        }
        let log_dir = Self::log_dir(dir);
        std::fs::create_dir_all(&log_dir)?;
        std::fs::create_dir_all(dir.join("index"))?;
        let bloom = dir.join(".or_bloom");
        for sub in BLOOM_SUBDIRS {
            std::fs::create_dir_all(bloom.join(sub))?;
        }

        // Authoritative content first: a crash before volume.meta leaves an
        // orphan log that is not a volume, never a volume without a log.
        let mut log = Log::create(&log_dir, segment_size)?;
        let genesis = Record::new(
            RecordType::VolumeGenesis,
            0,
            0,
            0,
            0,
            0,
            genesis_payload(&uuid, segment_size),
        )?;
        log.append(genesis)?;
        log.sync()?;

        let meta = VolumeMeta {
            magic: VOLUME_MAGIC,
            format_version: crate::FORMAT_VERSION,
            reserved: 0,
            uuid,
            created_at_unix_secs,
            segment_size,
            meta_check: 0,
        };
        write_meta(dir, &meta)?;
        fsync_dir(dir)?;

        Ok(Volume {
            root_dir: dir.to_path_buf(),
            meta,
            log_format_version: crate::LOG_FORMAT_VERSION,
            log,
        })
    }

    /// Open an existing volume.
    pub fn open(dir: &Path, mode: OpenMode) -> Result<Volume> {
        let meta = Self::read_meta(dir)?;
        let log = Log::open(&Self::log_dir(dir), meta.segment_size, mode)?;
        // Decide compatibility from the authoritative log itself. An unknown
        // *higher* log format version is refused here, so a future-format volume
        // is never interpreted on a guess (no silent repair; `docs/RECOVERY.md`).
        let log_format_version = Self::read_log_format_version(&log)?;
        Ok(Volume {
            root_dir: dir.to_path_buf(),
            meta,
            log_format_version,
            log,
        })
    }

    /// Read and validate the authoritative-log format version from the first
    /// committed record (the genesis). Returns `0` (legacy) when the genesis
    /// carries no version field, and refuses an unknown higher version.
    fn read_log_format_version(log: &Log) -> Result<u16> {
        if log.committed_end_offset() == 0 {
            // No committed genesis (an orphan log, not yet a volume): there is no
            // version to read. Report the current version; the missing-genesis
            // condition is `verify`'s explicit concern.
            return Ok(crate::LOG_FORMAT_VERSION);
        }
        let genesis_root = log
            .boundaries()
            .first()
            .copied()
            .ok_or_else(|| OrfsError::Corrupt("committed log has no boundary".to_string()))?;
        let records = log.replay_upto(genesis_root)?;
        let genesis = records
            .first()
            .ok_or_else(|| OrfsError::Corrupt("committed log has no genesis record".to_string()))?;
        if !matches!(
            genesis.header.classify_type().map_err(OrfsError::from)?,
            TypeClass::Known(RecordType::VolumeGenesis)
        ) {
            return Err(OrfsError::Corrupt(
                "first committed record is not VOLUME_GENESIS".to_string(),
            ));
        }
        Ok(parse_genesis_payload(&genesis.payload)?.format_version)
    }

    /// Flush and fsync the authoritative log.
    pub fn sync(&mut self) -> Result<()> {
        self.log.sync()
    }

    /// Replace the volume's capacity policy (Phase 23; research §30, §31). An
    /// implicit capacity bound is re-derived from the backing device.
    pub fn set_capacity_policy(&mut self, policy: CapacityPolicy) {
        self.log.set_capacity_policy(policy);
    }

    /// A truthful capacity report for this volume.
    pub fn capacity_report(&self) -> CapacityReport {
        self.log.capacity_report()
    }

    /// Whether the volume has latched into degraded/read-only mode.
    pub fn is_degraded(&self) -> bool {
        self.log.is_degraded()
    }

    /// Attempt to engage the io_uring backing engine on the authoritative log
    /// (research §17 Domain A). Returns a truthful report of what engaged.
    pub fn enable_backing_io(
        &mut self,
        cfg: &crate::uring::UringConfig,
    ) -> crate::uring::UringReport {
        self.log.enable_uring(cfg)
    }

    /// Verify the volume's authoritative structure. `deep` additionally
    /// revalidates every committed record.
    pub fn verify(&self, deep: bool) -> Result<VerifyReport> {
        let mut checks = Vec::new();
        checks.push(VerifyCheck::ok(
            "volume_meta",
            format!(
                "uuid={} segment_size={} created_at={}",
                self.meta.uuid_string(),
                self.meta.segment_size,
                self.meta.created_at_unix_secs
            ),
        ));

        let root = self.log.committed_end_offset();
        let records = self.log.replay_upto(root)?;
        let first = records
            .first()
            .ok_or_else(|| OrfsError::Corrupt("no committed records".to_string()))?;
        let genesis_ok = matches!(
            first.header.classify_type().map_err(OrfsError::from)?,
            TypeClass::Known(RecordType::VolumeGenesis)
        );
        checks.push(VerifyCheck {
            name: "volume_genesis".to_string(),
            ok: genesis_ok,
            detail: if genesis_ok {
                "first committed record is VOLUME_GENESIS".to_string()
            } else {
                "first committed record is not VOLUME_GENESIS".to_string()
            },
        });
        if genesis_ok {
            let id = parse_genesis_payload(&first.payload)?;
            let ok = id.uuid == self.meta.uuid && id.segment_size == self.meta.segment_size;
            checks.push(VerifyCheck {
                name: "genesis_matches_meta".to_string(),
                ok,
                detail: format!(
                    "genesis uuid={} segment_size={}",
                    uuid_string(&id.uuid),
                    id.segment_size
                ),
            });
            // The authoritative-log format version is carried by the genesis, so
            // a reader decides compatibility from the log itself. `0` = legacy.
            checks.push(VerifyCheck::ok(
                "log_format_version",
                format!(
                    "genesis log format version {} (legacy=0, this build supports up to {})",
                    id.format_version,
                    crate::LOG_FORMAT_VERSION
                ),
            ));
        }

        checks.push(VerifyCheck {
            name: "committed_root_is_boundary".to_string(),
            ok: self.log.is_boundary(root),
            detail: format!("root R={root}"),
        });

        // The durable commit watermark certifies the committed prefix; if it
        // certifies more history than survives, a trailing committed segment is
        // missing (the open would already have refused, but report it too).
        checks.push(
            match crate::watermark::Watermark::read(&Volume::log_dir(&self.root_dir)) {
                Ok(Some(wm)) => VerifyCheck {
                    name: "commit_watermark".to_string(),
                    ok: wm.committed_root <= root,
                    detail: format!(
                        "committed_root={} segment={} valid_len={} physical_end={}",
                        wm.committed_root,
                        wm.segment_id,
                        wm.segment_valid_len,
                        wm.physical_end(),
                    ),
                },
                Ok(None) => VerifyCheck::ok(
                    "commit_watermark",
                    "absent (legacy volume; completeness unvalidated by the watermark)".to_string(),
                ),
                Err(e) => VerifyCheck {
                    name: "commit_watermark".to_string(),
                    ok: false,
                    detail: e.to_string(),
                },
            },
        );

        let contiguous = self.log.extents().windows(2).all(|w| w[0].end() == w[1].id);
        checks.push(VerifyCheck {
            name: "segment_continuity".to_string(),
            ok: contiguous,
            detail: format!("{} segment(s)", self.log.extents().len()),
        });

        checks.push(match self.log.tail() {
            Some(t) => VerifyCheck::ok(
                "tail",
                format!(
                    "{:?} tail at offset {} ({} bytes retained, not canonical)",
                    t.kind, t.boundary_offset, t.abandoned_bytes
                ),
            ),
            None => VerifyCheck::ok("tail", "no torn or uncommitted tail".to_string()),
        });

        if deep {
            checks.push(VerifyCheck::ok(
                "deep_replay_checksums",
                format!("{} committed records, CRC32C verified", records.len()),
            ));
            // Typed-bracket validation: every committed `TX_BEGIN`/`TX_COMMIT`
            // pair must certify exactly its actual bracketed records. An
            // inconsistent bracket is a hard error, never silently skipped.
            checks.push(match crate::log::validate_committed_brackets(&records) {
                Ok(n) => VerifyCheck::ok(
                    "transaction_brackets",
                    format!(
                        "{n} committed transactions: typed payloads and bracket checksums validated"
                    ),
                ),
                Err(e) => VerifyCheck {
                    name: "transaction_brackets".to_string(),
                    ok: false,
                    detail: e.to_string(),
                },
            });
            let mut offset = 0u64;
            let mut prev_ok = true;
            let mut prev_detail = "all previous_inode_offset values point backward".to_string();
            for r in &records {
                if r.header.previous_inode_offset != 0 && r.header.previous_inode_offset >= offset {
                    prev_ok = false;
                    prev_detail = format!(
                        "record at offset {offset} has forward previous_inode_offset {}",
                        r.header.previous_inode_offset
                    );
                    break;
                }
                offset = offset
                    .checked_add(r.header.total_len().map_err(OrfsError::from)?)
                    .ok_or(OrfsError::Overflow {
                        what: "verify offset",
                    })?;
            }
            checks.push(VerifyCheck {
                name: "previous_inode_offsets_backward".to_string(),
                ok: prev_ok,
                detail: prev_detail,
            });
            checks.push(VerifyCheck {
                name: "committed_record_count".to_string(),
                ok: records.len() as u64 == self.log.committed_record_count(),
                detail: format!(
                    "{} records (log reports {})",
                    records.len(),
                    self.log.committed_record_count()
                ),
            });
        }

        let ok = checks.iter().all(|c| c.ok);
        Ok(VerifyReport { checks, ok })
    }
}

fn write_meta(dir: &Path, meta: &VolumeMeta) -> Result<()> {
    let path = Volume::meta_path(dir);
    let tmp = dir.join("volume.meta.tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&meta.encode())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    fsync_dir(dir)?;
    Ok(())
}

/// A single verification check.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

impl VerifyCheck {
    fn ok(name: &str, detail: String) -> VerifyCheck {
        VerifyCheck {
            name: name.to_string(),
            ok: true,
            detail,
        }
    }
}

/// The outcome of verifying a volume.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub checks: Vec<VerifyCheck>,
}

/// Convenience: scan a volume's log directory read-only (no open).
pub fn scan_volume_log(dir: &Path) -> Result<crate::log::LogScan> {
    scan_log(&Volume::log_dir(dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_round_trips() {
        let meta = VolumeMeta {
            magic: VOLUME_MAGIC,
            format_version: crate::FORMAT_VERSION,
            reserved: 0,
            uuid: finalize_uuid([7u8; 16]),
            created_at_unix_secs: 1_700_000_000,
            segment_size: 4096,
            meta_check: 0,
        };
        let bytes = meta.encode();
        assert_eq!(bytes.len(), VOLUME_META_LEN);
        let decoded = VolumeMeta::decode(&bytes).unwrap();
        assert_eq!(decoded.uuid, meta.uuid);
        assert_eq!(decoded.segment_size, 4096);
        assert_eq!(decoded.created_at_unix_secs, 1_700_000_000);
    }

    #[test]
    fn meta_corruption_is_detected() {
        let meta = VolumeMeta {
            magic: VOLUME_MAGIC,
            format_version: crate::FORMAT_VERSION,
            reserved: 0,
            uuid: [1u8; 16],
            created_at_unix_secs: 1,
            segment_size: 4096,
            meta_check: 0,
        };
        let mut bytes = meta.encode();
        bytes[10] ^= 0xFF;
        assert!(VolumeMeta::decode(&bytes).is_err());
    }

    #[test]
    fn uuid_string_is_canonical_shape() {
        let s = uuid_string(&finalize_uuid([0u8; 16]));
        assert_eq!(s.len(), 36);
        assert_eq!(s.matches('-').count(), 4);
        // Version nibble is 4.
        assert_eq!(&s[14..15], "4");
    }
}
