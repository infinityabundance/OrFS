//! Directory relations and namespace payload codecs (research §6, §7.3, §14).
//!
//! Directory entries are stored **separately** from inodes as relations
//! `(parent_inode, name) -> child_inode`; a name is never part of an inode's
//! identity. A file may have several names (hard links), and renaming a file
//! never changes its inode id (research §6).
//!
//! This module owns the little-endian, CRC32C-checked payload codecs for the
//! namespace record types:
//!
//! ```text
//!   DENTRY_ADD      add the first (or a further) name of an inode
//!   DENTRY_REMOVE   remove a name (tombstone: always appended, never an edit)
//!   DENTRY_RENAME   move or exchange a name (identity preserved)
//!   HARDLINK_ADD    add an additional name for an existing inode
//!   HARDLINK_REMOVE remove one of several names for an inode
//! ```

use crate::error::{OrfsError, Result};
use crate::record::{get_u32, get_u64};

// ---------------------------------------------------------------------------
// Payload magics
// ---------------------------------------------------------------------------

/// `DENTRY_ADD` magic; LE bytes spell `DAD1`.
pub const DENTRY_ADD_MAGIC: u32 = 0x3144_4144;
/// `DENTRY_REMOVE` magic; LE bytes spell `DRM1`.
pub const DENTRY_REMOVE_MAGIC: u32 = 0x314D_5244;
/// `DENTRY_RENAME` magic; LE bytes spell `DRN1`.
pub const DENTRY_RENAME_MAGIC: u32 = 0x314E_5244;
/// `HARDLINK_ADD` magic; LE bytes spell `HLA1`.
pub const HARDLINK_ADD_MAGIC: u32 = 0x3141_4C48;
/// `HARDLINK_REMOVE` magic; LE bytes spell `HLR1`.
pub const HARDLINK_REMOVE_MAGIC: u32 = 0x3152_4C48;

/// Upper bound on a single path component (bytes), matching Linux `NAME_MAX`.
pub const NAME_MAX: usize = 255;

/// Validate a path component.
pub fn validate_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(OrfsError::InvalidArgument(
            "empty directory entry name".into(),
        ));
    }
    if name.len() > NAME_MAX {
        return Err(OrfsError::InvalidArgument(format!(
            "directory entry name is {} bytes, limit {NAME_MAX}",
            name.len()
        )));
    }
    if name.contains(&b'/') || name.contains(&0) {
        return Err(OrfsError::InvalidArgument(
            "directory entry name contains '/' or NUL".into(),
        ));
    }
    if name == b"." || name == b".." {
        return Err(OrfsError::InvalidArgument(
            "'.' and '..' are implicit directory entries".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rename flags
// ---------------------------------------------------------------------------

/// `rename(2)`-style flags for a `DENTRY_RENAME` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RenameFlags {
    /// Ordinary rename (the engine has already appended any destination removal).
    Move = 0,
    /// `RENAME_EXCHANGE`: atomically swap the two names.
    Exchange = 1,
}

impl RenameFlags {
    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<RenameFlags> {
        Some(match code {
            0 => RenameFlags::Move,
            1 => RenameFlags::Exchange,
            _ => return None,
        })
    }
}

// ---------------------------------------------------------------------------
// Codec helpers
// ---------------------------------------------------------------------------

fn finish_crc(b: &mut Vec<u8>) {
    let check = crc32c::crc32c(b);
    b.extend_from_slice(&check.to_le_bytes());
}

fn check_trailing_crc(buf: &[u8], what: &str) -> Result<()> {
    if buf.len() < 4 {
        return Err(OrfsError::Corrupt(format!("{what} payload too short")));
    }
    let n = buf.len();
    if get_u32(buf, n - 4) != crc32c::crc32c(&buf[..n - 4]) {
        return Err(OrfsError::Corrupt(format!(
            "{what} payload checksum mismatch"
        )));
    }
    Ok(())
}

fn put_len_bytes(b: &mut Vec<u8>, bytes: &[u8]) {
    b.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    b.extend_from_slice(bytes);
}

fn take_len_bytes(buf: &[u8], off: usize, what: &str) -> Result<(Vec<u8>, usize)> {
    if off + 4 > buf.len() {
        return Err(OrfsError::Corrupt(format!(
            "{what} truncated length prefix"
        )));
    }
    let len = get_u32(buf, off) as usize;
    let start = off + 4;
    let end = start.checked_add(len).ok_or(OrfsError::Overflow {
        what: "payload field",
    })?;
    if end > buf.len() {
        return Err(OrfsError::Corrupt(format!("{what} truncated field")));
    }
    Ok((buf[start..end].to_vec(), end))
}

// ---------------------------------------------------------------------------
// DENTRY_ADD / HARDLINK_ADD
// ---------------------------------------------------------------------------

/// Payload of `DENTRY_ADD` and `HARDLINK_ADD` (variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DentryAddPayload {
    pub parent: u64,
    pub child: u64,
    pub name: Vec<u8>,
}

impl DentryAddPayload {
    pub fn encode(&self, magic: u32) -> Result<Vec<u8>> {
        validate_name(&self.name)?;
        let mut b = Vec::with_capacity(24 + self.name.len() + 4);
        b.extend_from_slice(&magic.to_le_bytes());
        b.extend_from_slice(&self.parent.to_le_bytes());
        b.extend_from_slice(&self.child.to_le_bytes());
        put_len_bytes(&mut b, &self.name);
        finish_crc(&mut b);
        Ok(b)
    }

    pub fn decode(buf: &[u8], magic: u32, what: &str) -> Result<DentryAddPayload> {
        if buf.len() < 24 || get_u32(buf, 0) != magic {
            return Err(OrfsError::Corrupt(format!("{what} payload bad magic")));
        }
        check_trailing_crc(buf, what)?;
        let (name, end) = take_len_bytes(buf, 20, what)?;
        if end + 4 != buf.len() {
            return Err(OrfsError::Corrupt(format!("{what} payload trailing bytes")));
        }
        // A *committed* record is authoritative history, so its name is treated
        // as hostile input: an out-of-domain name (empty, `..`, embedded `/` or
        // NUL, or longer than `NAME_MAX`) must be refused, never indexed. See
        // research §28 (strict path traversal handling) and §35 (a malformed
        // committed record is corruption, not silently applied content).
        validate_name(&name)
            .map_err(|e| OrfsError::Corrupt(format!("{what} payload has an invalid name: {e}")))?;
        Ok(DentryAddPayload {
            parent: get_u64(buf, 4),
            child: get_u64(buf, 12),
            name,
        })
    }
}

// ---------------------------------------------------------------------------
// DENTRY_REMOVE / HARDLINK_REMOVE
// ---------------------------------------------------------------------------

/// Payload of `DENTRY_REMOVE` and `HARDLINK_REMOVE` (variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DentryRemovePayload {
    pub parent: u64,
    pub name: Vec<u8>,
}

impl DentryRemovePayload {
    pub fn encode(&self, magic: u32) -> Vec<u8> {
        let mut b = Vec::with_capacity(16 + self.name.len() + 4);
        b.extend_from_slice(&magic.to_le_bytes());
        b.extend_from_slice(&self.parent.to_le_bytes());
        put_len_bytes(&mut b, &self.name);
        finish_crc(&mut b);
        b
    }

    pub fn decode(buf: &[u8], magic: u32, what: &str) -> Result<DentryRemovePayload> {
        if buf.len() < 16 || get_u32(buf, 0) != magic {
            return Err(OrfsError::Corrupt(format!("{what} payload bad magic")));
        }
        check_trailing_crc(buf, what)?;
        let (name, end) = take_len_bytes(buf, 12, what)?;
        if end + 4 != buf.len() {
            return Err(OrfsError::Corrupt(format!("{what} payload trailing bytes")));
        }
        validate_name(&name)
            .map_err(|e| OrfsError::Corrupt(format!("{what} payload has an invalid name: {e}")))?;
        Ok(DentryRemovePayload {
            parent: get_u64(buf, 4),
            name,
        })
    }
}

// ---------------------------------------------------------------------------
// DENTRY_RENAME
// ---------------------------------------------------------------------------

/// Payload of `DENTRY_RENAME` (variable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DentryRenamePayload {
    pub flags: RenameFlags,
    pub old_parent: u64,
    pub new_parent: u64,
    pub old_name: Vec<u8>,
    pub new_name: Vec<u8>,
}

impl DentryRenamePayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 + self.old_name.len() + self.new_name.len() + 4);
        b.extend_from_slice(&DENTRY_RENAME_MAGIC.to_le_bytes());
        b.push(self.flags.code());
        b.extend_from_slice(&[0u8; 3]);
        b.extend_from_slice(&self.old_parent.to_le_bytes());
        b.extend_from_slice(&self.new_parent.to_le_bytes());
        put_len_bytes(&mut b, &self.old_name);
        put_len_bytes(&mut b, &self.new_name);
        finish_crc(&mut b);
        b
    }

    pub fn decode(buf: &[u8]) -> Result<DentryRenamePayload> {
        if buf.len() < 32 || get_u32(buf, 0) != DENTRY_RENAME_MAGIC {
            return Err(OrfsError::Corrupt("DENTRY_RENAME payload bad magic".into()));
        }
        check_trailing_crc(buf, "DENTRY_RENAME")?;
        let flags = RenameFlags::from_code(buf[4])
            .ok_or_else(|| OrfsError::Corrupt("DENTRY_RENAME unknown flags".into()))?;
        let (old_name, off) = take_len_bytes(buf, 24, "DENTRY_RENAME old_name")?;
        let (new_name, end) = take_len_bytes(buf, off, "DENTRY_RENAME new_name")?;
        if end + 4 != buf.len() {
            return Err(OrfsError::Corrupt(
                "DENTRY_RENAME payload trailing bytes".into(),
            ));
        }
        for n in [&old_name, &new_name] {
            validate_name(n).map_err(|e| {
                OrfsError::Corrupt(format!("DENTRY_RENAME payload has an invalid name: {e}"))
            })?;
        }
        Ok(DentryRenamePayload {
            flags,
            old_parent: get_u64(buf, 8),
            new_parent: get_u64(buf, 16),
            old_name,
            new_name,
        })
    }
}

// Re-export the fixed-width helpers used above for symmetry with other modules.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dentry_add_round_trips_for_both_magics() {
        let p = DentryAddPayload {
            parent: 1,
            child: 2,
            name: b"hello".to_vec(),
        };
        for (magic, what) in [
            (DENTRY_ADD_MAGIC, "DENTRY_ADD"),
            (HARDLINK_ADD_MAGIC, "HARDLINK_ADD"),
        ] {
            let bytes = p.encode(magic).unwrap();
            assert_eq!(DentryAddPayload::decode(&bytes, magic, what).unwrap(), p);
        }
        assert!(p.encode(DENTRY_ADD_MAGIC).is_ok());
        assert!(DentryAddPayload {
            parent: 1,
            child: 2,
            name: b"a/b".to_vec()
        }
        .encode(DENTRY_ADD_MAGIC)
        .is_err());
    }

    #[test]
    fn dentry_remove_round_trips() {
        let p = DentryRemovePayload {
            parent: 1,
            name: b"x".to_vec(),
        };
        let bytes = p.encode(DENTRY_REMOVE_MAGIC);
        assert_eq!(
            DentryRemovePayload::decode(&bytes, DENTRY_REMOVE_MAGIC, "DENTRY_REMOVE").unwrap(),
            p
        );
    }

    #[test]
    fn dentry_rename_round_trips() {
        let p = DentryRenamePayload {
            flags: RenameFlags::Exchange,
            old_parent: 1,
            new_parent: 2,
            old_name: b"a".to_vec(),
            new_name: b"b".to_vec(),
        };
        assert_eq!(DentryRenamePayload::decode(&p.encode()).unwrap(), p);
        let mut bad = p.encode();
        bad[10] ^= 0xFF;
        assert!(DentryRenamePayload::decode(&bad).is_err());
    }
}
