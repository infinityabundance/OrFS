//! Authoritative physical record format (design specification §5).
//!
//! Every authoritative byte on disk is part of a framed record:
//!
//! ```text
//! RECORD HEADER   (60 bytes, fixed)
//! PAYLOAD         (payload_length bytes)
//! RECORD FOOTER   (16 bytes, fixed)
//! ```
//!
//! All multi-byte fields are little-endian. Fields are written and read
//! **explicitly, field by field**; no Rust struct is ever cast over untrusted
//! bytes. Checksums are CRC32C.
//!
//! ## Non-withdrawal and framing
//!
//! The header carries `header_check` (CRC32C over the first 56 header bytes)
//! and the footer carries `record_check` (CRC32C over header + payload) plus a
//! fixed `end_marker`. Together these let a reader distinguish a *complete*
//! record from a *torn* one without relying on file length. A record whose
//! framing cannot be validated is reported as [`DecodeError::Incomplete`]; a
//! reader must treat that as an abandoned physical tail, never as data to be
//! reinterpreted by rewriting earlier bytes.

use std::fmt;

use crate::error::{OrfsError, Result};

// ---------------------------------------------------------------------------
// Envelope constants and fixed field offsets
// ---------------------------------------------------------------------------

/// Record magic. Little-endian bytes on disk spell `ORFS`.
pub const RECORD_MAGIC: u32 = 0x5346_524F;

/// Footer end marker. Little-endian bytes on disk spell `END!`.
pub const FOOTER_END_MARKER: u32 = 0x2144_4E45;

/// Fixed header length in bytes (§5.1).
pub const HEADER_LEN: usize = 60;

/// Fixed footer length in bytes (§5.1).
pub const FOOTER_LEN: usize = 16;

/// Upper bound on a payload, enforced *before* a payload buffer is allocated
/// when reading untrusted records (specification §32, bounded allocation).
pub const MAX_PAYLOAD_LEN: u64 = 64 * 1024 * 1024; // 64 MiB

/// Bit 15 of a record type code marks the type *optional*: a reader that does
/// not understand such a record may skip it. A type code with bit 15 clear and
/// no known meaning is *mandatory* and must stop the reader.
pub const OPTIONAL_TYPE_BIT: u16 = 0x8000;

/// No record flags are defined in format version 1; the field is reserved.
pub const FLAG_NONE: u32 = 0;

// Header field offsets (bytes from the start of the record).
pub const HDR_OFF_MAGIC: usize = 0;
pub const HDR_OFF_FORMAT_VERSION: usize = 4;
pub const HDR_OFF_RECORD_TYPE: usize = 6;
pub const HDR_OFF_HEADER_LENGTH: usize = 8;
pub const HDR_OFF_PAYLOAD_LENGTH: usize = 12;
pub const HDR_OFF_SEQUENCE_NUMBER: usize = 20;
pub const HDR_OFF_TRANSACTION_ID: usize = 28;
pub const HDR_OFF_INODE_ID: usize = 36;
pub const HDR_OFF_PREVIOUS_INODE_OFFSET: usize = 44;
pub const HDR_OFF_FLAGS: usize = 52;
pub const HDR_OFF_HEADER_CHECK: usize = 56;

// Footer field offsets (bytes from the start of the footer).
pub const FTR_OFF_TOTAL_LENGTH: usize = 0;
pub const FTR_OFF_RECORD_CHECK: usize = 8;
pub const FTR_OFF_END_MARKER: usize = 12;

// ---------------------------------------------------------------------------
// Little-endian field access (explicit; never a struct cast)
// ---------------------------------------------------------------------------

pub(crate) fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

pub(crate) fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

pub(crate) fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

pub(crate) fn get_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

pub(crate) fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub(crate) fn get_u64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

// ---------------------------------------------------------------------------
// Decode errors
// ---------------------------------------------------------------------------

/// A framing-level decode failure. This is deliberately finer-grained than
/// [`OrfsError`] so that recovery can tell an *abandoned tail* apart from a
/// *corrupt committed record* and a *format compatibility* problem (§23.1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Not enough bytes, or the header/footer checksum did not validate: the
    /// record was never fully written (a torn or incomplete tail).
    #[error("torn or incomplete record framing")]
    Incomplete,

    /// The bytes are fully present but structurally invalid.
    #[error("corrupt record framing: {0}")]
    Corrupt(String),

    /// The record is for an incompatible format version or an unknown
    /// *mandatory* type.
    #[error("incompatible record format: {0}")]
    Compatibility(String),

    /// Checked arithmetic overflowed while interpreting an untrusted length.
    #[error("integer overflow while decoding {0}")]
    Overflow(&'static str),
}

impl From<DecodeError> for OrfsError {
    fn from(e: DecodeError) -> Self {
        match e {
            DecodeError::Incomplete => {
                OrfsError::Corrupt("torn or incomplete record framing".to_string())
            }
            DecodeError::Corrupt(m) => OrfsError::Corrupt(m),
            DecodeError::Compatibility(m) => OrfsError::Compatibility(m),
            DecodeError::Overflow(what) => OrfsError::Overflow { what },
        }
    }
}

// ---------------------------------------------------------------------------
// Record types (§5.2)
// ---------------------------------------------------------------------------

/// The complete set of authoritative record types.
///
/// Every variant here is *mandatory*: a reader that does not understand one of
/// them must refuse to proceed. Unknown *optional* types are expressed by
/// setting [`OPTIONAL_TYPE_BIT`] in the type code and are handled by
/// [`classify_code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordType {
    /// Volume identity record; always the first record.
    VolumeGenesis = 0x0001,
    /// Start of a multi-record transaction.
    TxBegin = 0x0002,
    /// Atomic publication of a transaction.
    TxCommit = 0x0003,
    /// Abandonment of a transaction; no state becomes visible.
    TxAbort = 0x0004,
    /// Creation of an inode.
    InodeCreate = 0x0005,
    /// New metadata version for an inode.
    InodeMetadata = 0x0006,
    /// Attribute change (mode/uid/gid/times).
    InodeSetattr = 0x0007,
    /// Addition of a directory entry.
    DentryAdd = 0x0008,
    /// Removal of a directory entry.
    DentryRemove = 0x0009,
    /// Rename of a directory entry.
    DentryRename = 0x000A,
    /// A file data extent.
    DataExtent = 0x000B,
    /// A logically zeroed range within a file.
    DataZeroRange = 0x000C,
    /// A logical file size change.
    FileResize = 0x000D,
    /// Creation of a symbolic link.
    SymlinkCreate = 0x000E,
    /// Addition of a hard link.
    HardlinkAdd = 0x000F,
    /// Removal of a hard link.
    HardlinkRemove = 0x0010,
    /// Set an extended attribute.
    XattrSet = 0x0011,
    /// Remove an extended attribute.
    XattrRemove = 0x0012,
    /// Publish a named historical root.
    SnapshotRoot = 0x0013,
    /// An index checkpoint embedded in the authoritative log.
    IndexCheckpoint = 0x0014,
    /// An ownership/permission change.
    PermissionChange = 0x0015,
}

impl RecordType {
    /// Every known record type, in definition order.
    pub const ALL: [RecordType; 21] = [
        RecordType::VolumeGenesis,
        RecordType::TxBegin,
        RecordType::TxCommit,
        RecordType::TxAbort,
        RecordType::InodeCreate,
        RecordType::InodeMetadata,
        RecordType::InodeSetattr,
        RecordType::DentryAdd,
        RecordType::DentryRemove,
        RecordType::DentryRename,
        RecordType::DataExtent,
        RecordType::DataZeroRange,
        RecordType::FileResize,
        RecordType::SymlinkCreate,
        RecordType::HardlinkAdd,
        RecordType::HardlinkRemove,
        RecordType::XattrSet,
        RecordType::XattrRemove,
        RecordType::SnapshotRoot,
        RecordType::IndexCheckpoint,
        RecordType::PermissionChange,
    ];

    /// The on-disk type code.
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Stable, human-readable name (used by reports and evidence).
    pub const fn name(self) -> &'static str {
        match self {
            RecordType::VolumeGenesis => "VOLUME_GENESIS",
            RecordType::TxBegin => "TX_BEGIN",
            RecordType::TxCommit => "TX_COMMIT",
            RecordType::TxAbort => "TX_ABORT",
            RecordType::InodeCreate => "INODE_CREATE",
            RecordType::InodeMetadata => "INODE_METADATA",
            RecordType::InodeSetattr => "INODE_SETATTR",
            RecordType::DentryAdd => "DENTRY_ADD",
            RecordType::DentryRemove => "DENTRY_REMOVE",
            RecordType::DentryRename => "DENTRY_RENAME",
            RecordType::DataExtent => "DATA_EXTENT",
            RecordType::DataZeroRange => "DATA_ZERO_RANGE",
            RecordType::FileResize => "FILE_RESIZE",
            RecordType::SymlinkCreate => "SYMLINK_CREATE",
            RecordType::HardlinkAdd => "HARDLINK_ADD",
            RecordType::HardlinkRemove => "HARDLINK_REMOVE",
            RecordType::XattrSet => "XATTR_SET",
            RecordType::XattrRemove => "XATTR_REMOVE",
            RecordType::SnapshotRoot => "SNAPSHOT_ROOT",
            RecordType::IndexCheckpoint => "INDEX_CHECKPOINT",
            RecordType::PermissionChange => "PERMISSION_CHANGE",
        }
    }

    /// The known record type for a code, if any.
    pub fn from_code(code: u16) -> Option<RecordType> {
        Some(match code {
            0x0001 => RecordType::VolumeGenesis,
            0x0002 => RecordType::TxBegin,
            0x0003 => RecordType::TxCommit,
            0x0004 => RecordType::TxAbort,
            0x0005 => RecordType::InodeCreate,
            0x0006 => RecordType::InodeMetadata,
            0x0007 => RecordType::InodeSetattr,
            0x0008 => RecordType::DentryAdd,
            0x0009 => RecordType::DentryRemove,
            0x000A => RecordType::DentryRename,
            0x000B => RecordType::DataExtent,
            0x000C => RecordType::DataZeroRange,
            0x000D => RecordType::FileResize,
            0x000E => RecordType::SymlinkCreate,
            0x000F => RecordType::HardlinkAdd,
            0x0010 => RecordType::HardlinkRemove,
            0x0011 => RecordType::XattrSet,
            0x0012 => RecordType::XattrRemove,
            0x0013 => RecordType::SnapshotRoot,
            0x0014 => RecordType::IndexCheckpoint,
            0x0015 => RecordType::PermissionChange,
            _ => return None,
        })
    }

    /// Whether reaching the *end* of a record of this type publishes a new
    /// committed root. Only genesis and `TX_COMMIT` do (§5.4).
    pub const fn publishes_root(self) -> bool {
        matches!(self, RecordType::VolumeGenesis | RecordType::TxCommit)
    }
}

/// Classification of a raw record type code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeClass {
    /// A record type this build understands.
    Known(RecordType),
    /// An unknown type whose code carries [`OPTIONAL_TYPE_BIT`]; a reader may
    /// skip it.
    OptionalUnknown(u16),
}

/// Classify a raw type code.
///
/// An unknown *mandatory* code yields [`DecodeError::Compatibility`]: the
/// format must not be interpreted on a guess (§5.2).
pub fn classify_code(code: u16) -> std::result::Result<TypeClass, DecodeError> {
    if let Some(t) = RecordType::from_code(code) {
        return Ok(TypeClass::Known(t));
    }
    if code & OPTIONAL_TYPE_BIT != 0 {
        return Ok(TypeClass::OptionalUnknown(code));
    }
    Err(DecodeError::Compatibility(format!(
        "unknown mandatory record type 0x{code:04X}"
    )))
}

/// Human-readable name for a raw type code (unknown codes are labelled).
pub fn record_type_name(code: u16) -> String {
    match RecordType::from_code(code) {
        Some(t) => t.name().to_string(),
        None if code & OPTIONAL_TYPE_BIT != 0 => format!("OPTIONAL_0x{code:04X}"),
        None => format!("UNKNOWN_0x{code:04X}"),
    }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// The fixed 60-byte record header (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub magic: u32,
    pub format_version: u16,
    pub record_type_code: u16,
    pub header_length: u32,
    pub payload_length: u64,
    pub sequence_number: u64,
    pub transaction_id: u64,
    pub inode_id: u64,
    pub previous_inode_offset: u64,
    pub flags: u32,
    pub header_check: u32,
}

impl RecordHeader {
    /// Build a header with a freshly computed `header_check`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        record_type: RecordType,
        sequence_number: u64,
        transaction_id: u64,
        inode_id: u64,
        previous_inode_offset: u64,
        flags: u32,
        payload_length: u64,
    ) -> RecordHeader {
        let mut h = RecordHeader {
            magic: RECORD_MAGIC,
            format_version: crate::FORMAT_VERSION,
            record_type_code: record_type.code(),
            header_length: HEADER_LEN as u32,
            payload_length,
            sequence_number,
            transaction_id,
            inode_id,
            previous_inode_offset,
            flags,
            header_check: 0,
        };
        h.header_check = h.compute_check();
        h
    }

    fn raw_bytes(&self, check: u32) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        put_u32(&mut b, HDR_OFF_MAGIC, self.magic);
        put_u16(&mut b, HDR_OFF_FORMAT_VERSION, self.format_version);
        put_u16(&mut b, HDR_OFF_RECORD_TYPE, self.record_type_code);
        put_u32(&mut b, HDR_OFF_HEADER_LENGTH, self.header_length);
        put_u64(&mut b, HDR_OFF_PAYLOAD_LENGTH, self.payload_length);
        put_u64(&mut b, HDR_OFF_SEQUENCE_NUMBER, self.sequence_number);
        put_u64(&mut b, HDR_OFF_TRANSACTION_ID, self.transaction_id);
        put_u64(&mut b, HDR_OFF_INODE_ID, self.inode_id);
        put_u64(
            &mut b,
            HDR_OFF_PREVIOUS_INODE_OFFSET,
            self.previous_inode_offset,
        );
        put_u32(&mut b, HDR_OFF_FLAGS, self.flags);
        put_u32(&mut b, HDR_OFF_HEADER_CHECK, check);
        b
    }

    /// CRC32C over the header bytes preceding `header_check`.
    fn compute_check(&self) -> u32 {
        let b = self.raw_bytes(0);
        crc32c::crc32c(&b[..HDR_OFF_HEADER_CHECK])
    }

    /// Encode the header as its 60 on-disk bytes.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        self.raw_bytes(self.header_check)
    }

    /// Return a copy with `header_check` recomputed (used after mutating
    /// envelope fields such as `sequence_number`).
    pub fn with_recomputed_check(mut self) -> RecordHeader {
        self.header_check = self.compute_check();
        self
    }

    /// Decode and validate a header from at least [`HEADER_LEN`] bytes.
    ///
    /// Checksum validation is attempted first so that a partially written
    /// header is reported as [`DecodeError::Incomplete`] rather than as a
    /// spurious corruption.
    pub fn decode(buf: &[u8]) -> std::result::Result<RecordHeader, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::Incomplete);
        }
        let stored = get_u32(buf, HDR_OFF_HEADER_CHECK);
        let computed = crc32c::crc32c(&buf[..HDR_OFF_HEADER_CHECK]);
        if stored != computed {
            return Err(DecodeError::Incomplete);
        }
        let magic = get_u32(buf, HDR_OFF_MAGIC);
        if magic != RECORD_MAGIC {
            return Err(DecodeError::Corrupt(format!(
                "bad record magic 0x{magic:08X}"
            )));
        }
        let header_length = get_u32(buf, HDR_OFF_HEADER_LENGTH);
        if header_length as usize != HEADER_LEN {
            return Err(DecodeError::Corrupt(format!(
                "bad header_length {header_length}"
            )));
        }
        let format_version = get_u16(buf, HDR_OFF_FORMAT_VERSION);
        if format_version != crate::FORMAT_VERSION {
            return Err(DecodeError::Compatibility(format!(
                "record format version {format_version} (this build supports {})",
                crate::FORMAT_VERSION
            )));
        }
        let payload_length = get_u64(buf, HDR_OFF_PAYLOAD_LENGTH);
        if payload_length > MAX_PAYLOAD_LEN {
            return Err(DecodeError::Corrupt(format!(
                "payload_length {payload_length} exceeds limit {MAX_PAYLOAD_LEN}"
            )));
        }
        Ok(RecordHeader {
            magic,
            format_version,
            record_type_code: get_u16(buf, HDR_OFF_RECORD_TYPE),
            header_length,
            payload_length,
            sequence_number: get_u64(buf, HDR_OFF_SEQUENCE_NUMBER),
            transaction_id: get_u64(buf, HDR_OFF_TRANSACTION_ID),
            inode_id: get_u64(buf, HDR_OFF_INODE_ID),
            previous_inode_offset: get_u64(buf, HDR_OFF_PREVIOUS_INODE_OFFSET),
            flags: get_u32(buf, HDR_OFF_FLAGS),
            header_check: stored,
        })
    }

    /// Classify this header's record type.
    pub fn classify_type(&self) -> std::result::Result<TypeClass, DecodeError> {
        classify_code(self.record_type_code)
    }

    /// Total framed length (header + payload + footer) with checked arithmetic.
    pub fn total_len(&self) -> std::result::Result<u64, DecodeError> {
        (HEADER_LEN as u64 + FOOTER_LEN as u64)
            .checked_add(self.payload_length)
            .ok_or(DecodeError::Overflow("record total length"))
    }
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

/// The fixed 16-byte record footer (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordFooter {
    pub total_record_length: u64,
    pub record_check: u32,
    pub end_marker: u32,
}

impl RecordFooter {
    fn encode(&self) -> [u8; FOOTER_LEN] {
        let mut b = [0u8; FOOTER_LEN];
        put_u64(&mut b, FTR_OFF_TOTAL_LENGTH, self.total_record_length);
        put_u32(&mut b, FTR_OFF_RECORD_CHECK, self.record_check);
        put_u32(&mut b, FTR_OFF_END_MARKER, self.end_marker);
        b
    }

    /// Decode the footer and validate it against the preceding header+payload
    /// bytes.
    ///
    /// `prefix` is the header + payload; `footer` is the 16 following bytes.
    pub fn validate(
        prefix: &[u8],
        footer: &[u8],
        header: &RecordHeader,
    ) -> std::result::Result<RecordFooter, DecodeError> {
        if footer.len() < FOOTER_LEN {
            return Err(DecodeError::Incomplete);
        }
        let expected = header.total_len()?;
        let total_record_length = get_u64(footer, FTR_OFF_TOTAL_LENGTH);
        if total_record_length != expected {
            return Err(DecodeError::Incomplete);
        }
        let record_check = get_u32(footer, FTR_OFF_RECORD_CHECK);
        if record_check != crc32c::crc32c(prefix) {
            return Err(DecodeError::Incomplete);
        }
        let end_marker = get_u32(footer, FTR_OFF_END_MARKER);
        if end_marker != FOOTER_END_MARKER {
            return Err(DecodeError::Corrupt(format!(
                "bad footer end marker 0x{end_marker:08X}"
            )));
        }
        Ok(RecordFooter {
            total_record_length,
            record_check,
            end_marker,
        })
    }
}

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

/// A complete authoritative record: header plus opaque payload.
///
/// Payload interpretation for non-genesis types is the concern of later planes;
/// the framing layer treats it as bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub header: RecordHeader,
    pub payload: Vec<u8>,
}

impl Record {
    /// Build a record, computing `header_check` and validating the payload
    /// against [`MAX_PAYLOAD_LEN`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        record_type: RecordType,
        sequence_number: u64,
        transaction_id: u64,
        inode_id: u64,
        previous_inode_offset: u64,
        flags: u32,
        payload: Vec<u8>,
    ) -> Result<Record> {
        if payload.len() as u64 > MAX_PAYLOAD_LEN {
            return Err(OrfsError::InvalidArgument(format!(
                "payload length {} exceeds limit {MAX_PAYLOAD_LEN}",
                payload.len()
            )));
        }
        let header = RecordHeader::new(
            record_type,
            sequence_number,
            transaction_id,
            inode_id,
            previous_inode_offset,
            flags,
            payload.len() as u64,
        );
        Ok(Record { header, payload })
    }

    /// The record's type, if it is a known (non-optional) type.
    pub fn known_type(&self) -> std::result::Result<RecordType, DecodeError> {
        match self.header.classify_type()? {
            TypeClass::Known(t) => Ok(t),
            TypeClass::OptionalUnknown(code) => Err(DecodeError::Compatibility(format!(
                "record type 0x{code:04X} is optional and has no known semantics"
            ))),
        }
    }

    /// Total framed length in bytes.
    pub fn total_len(&self) -> std::result::Result<u64, DecodeError> {
        self.header.total_len()
    }

    /// Serialize the record to its exact on-disk bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let payload_len = self.payload.len() as u64;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(OrfsError::InvalidArgument(format!(
                "payload length {payload_len} exceeds limit {MAX_PAYLOAD_LEN}"
            )));
        }
        if payload_len != self.header.payload_length {
            return Err(OrfsError::InvalidArgument(
                "header payload_length disagrees with payload length".to_string(),
            ));
        }
        let total = self.header.total_len().map_err(OrfsError::from)?;
        let mut out = Vec::with_capacity(total as usize);
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.payload);
        let record_check = crc32c::crc32c(&out);
        let footer = RecordFooter {
            total_record_length: total,
            record_check,
            end_marker: FOOTER_END_MARKER,
        };
        out.extend_from_slice(&footer.encode());
        debug_assert_eq!(out.len() as u64, total);
        Ok(out)
    }

    /// Decode a record from a slice that must contain the whole record.
    ///
    /// Returns the record and the number of bytes it occupies. Bounds are
    /// validated before the payload is copied.
    pub fn decode(buf: &[u8]) -> std::result::Result<(Record, usize), DecodeError> {
        let header = RecordHeader::decode(buf)?;
        let total = header.total_len()?;
        let total_usize =
            usize::try_from(total).map_err(|_| DecodeError::Overflow("record total length"))?;
        if buf.len() < total_usize {
            return Err(DecodeError::Incomplete);
        }
        let payload_len = usize::try_from(header.payload_length)
            .map_err(|_| DecodeError::Overflow("payload length"))?;
        let payload_end = HEADER_LEN + payload_len;
        let payload = buf[HEADER_LEN..payload_end].to_vec();
        RecordFooter::validate(&buf[..payload_end], &buf[payload_end..total_usize], &header)?;
        Ok((Record { header, payload }, total_usize))
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(payload: &[u8]) -> Record {
        Record::new(
            RecordType::DataExtent,
            7,
            42,
            3,
            11,
            FLAG_NONE,
            payload.to_vec(),
        )
        .expect("build record")
    }

    #[test]
    fn header_layout_is_exactly_sixty_bytes() {
        let mut off = 0;
        for w in [4usize, 2, 2, 4, 8, 8, 8, 8, 8, 4, 4] {
            off += w;
        }
        assert_eq!(off, HEADER_LEN);
        assert_eq!(HEADER_LEN, 60);
        assert_eq!(FOOTER_LEN, 16);
    }

    #[test]
    fn round_trip_preserves_every_field() {
        for payload in [&b""[..], &b"x"[..], &[0u8; 4096][..]] {
            let rec = sample(payload);
            let bytes = rec.encode().expect("encode");
            assert_eq!(bytes.len() as u64, rec.total_len().unwrap());
            let (decoded, used) = Record::decode(&bytes).expect("decode");
            assert_eq!(used, bytes.len());
            assert_eq!(decoded, rec);
            assert_eq!(decoded.payload, payload);
        }
    }

    #[test]
    fn torn_header_is_incomplete() {
        let rec = sample(b"payload");
        let mut bytes = rec.encode().unwrap();
        // Corrupt the header checksum: the header was never fully written.
        bytes[HDR_OFF_HEADER_CHECK] ^= 0xFF;
        assert_eq!(RecordHeader::decode(&bytes), Err(DecodeError::Incomplete));
    }

    #[test]
    fn short_header_is_incomplete() {
        let rec = sample(b"payload");
        let bytes = rec.encode().unwrap();
        for n in 0..HEADER_LEN {
            assert_eq!(
                RecordHeader::decode(&bytes[..n]),
                Err(DecodeError::Incomplete)
            );
        }
    }

    #[test]
    fn torn_footer_is_incomplete() {
        let rec = sample(b"0123456789");
        let bytes = rec.encode().unwrap();
        // Truncate into the footer.
        assert_eq!(
            Record::decode(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Incomplete)
        );
        // Flip a record-check byte.
        let mut corrupt = bytes.clone();
        let off = bytes.len() - FOOTER_LEN + FTR_OFF_RECORD_CHECK;
        corrupt[off] ^= 0x01;
        assert_eq!(Record::decode(&corrupt), Err(DecodeError::Incomplete));
    }

    #[test]
    fn bad_end_marker_is_corruption() {
        let rec = sample(b"abcd");
        let mut bytes = rec.encode().unwrap();
        let off = bytes.len() - FOOTER_LEN + FTR_OFF_END_MARKER;
        bytes[off] ^= 0xFF;
        // The record check still validates (only the marker changed), so this
        // is a structural corruption rather than a torn tail.
        assert!(matches!(
            Record::decode(&bytes),
            Err(DecodeError::Corrupt(_))
        ));
    }

    #[test]
    fn bad_magic_is_rejected_when_checksum_valid() {
        let rec = sample(b"payload");
        let mut bytes = rec.encode().unwrap();
        put_u32(&mut bytes, HDR_OFF_MAGIC, 0xDEAD_BEEF);
        let check = crc32c::crc32c(&bytes[..HDR_OFF_HEADER_CHECK]);
        put_u32(&mut bytes, HDR_OFF_HEADER_CHECK, check);
        assert!(matches!(
            RecordHeader::decode(&bytes),
            Err(DecodeError::Corrupt(_))
        ));
    }

    #[test]
    fn bad_format_version_is_compatibility() {
        let rec = sample(b"payload");
        let mut bytes = rec.encode().unwrap();
        put_u16(&mut bytes, HDR_OFF_FORMAT_VERSION, 0x00FF);
        let check = crc32c::crc32c(&bytes[..HDR_OFF_HEADER_CHECK]);
        put_u32(&mut bytes, HDR_OFF_HEADER_CHECK, check);
        assert!(matches!(
            RecordHeader::decode(&bytes),
            Err(DecodeError::Compatibility(_))
        ));
    }

    #[test]
    fn oversized_payload_length_is_rejected_before_allocation() {
        let rec = sample(b"payload");
        let mut bytes = rec.encode().unwrap();
        put_u64(&mut bytes, HDR_OFF_PAYLOAD_LENGTH, MAX_PAYLOAD_LEN + 1);
        let check = crc32c::crc32c(&bytes[..HDR_OFF_HEADER_CHECK]);
        put_u32(&mut bytes, HDR_OFF_HEADER_CHECK, check);
        // Only the 60-byte header is supplied; the huge length is rejected.
        assert_eq!(
            RecordHeader::decode(&bytes[..HEADER_LEN]),
            Err(DecodeError::Corrupt(format!(
                "payload_length {} exceeds limit {MAX_PAYLOAD_LEN}",
                MAX_PAYLOAD_LEN + 1
            )))
        );
    }

    #[test]
    fn total_length_overflow_is_checked() {
        let mut h = sample(b"").header;
        h.payload_length = u64::MAX;
        assert_eq!(
            h.total_len(),
            Err(DecodeError::Overflow("record total length"))
        );
    }

    #[test]
    fn unknown_mandatory_type_is_compatibility() {
        assert!(matches!(
            classify_code(0x0020),
            Err(DecodeError::Compatibility(_))
        ));
    }

    #[test]
    fn unknown_optional_type_is_skippable() {
        assert_eq!(
            classify_code(0x8001),
            Ok(TypeClass::OptionalUnknown(0x8001))
        );
    }

    #[test]
    fn known_types_classify() {
        for t in RecordType::ALL {
            assert_eq!(classify_code(t.code()), Ok(TypeClass::Known(t)));
        }
        assert!(RecordType::VolumeGenesis.publishes_root());
        assert!(RecordType::TxCommit.publishes_root());
        assert!(!RecordType::DataExtent.publishes_root());
    }
}
