//! Immutable, version-qualified backing images for kernel FUSE passthrough
//! (Phase 21; research/external-review §2/§9).
//!
//! The Linux FUSE passthrough UAPI lets a FUSE daemon *register* an ordinary
//! regular file (a **backing file**) with the kernel over an ioctl on the
//! `/dev/fuse` descriptor and then *attach* it to an opened file in the `OPEN`
//! reply, so eligible reads are served directly by the kernel and never invoke
//! the daemon (`Documentation/filesystems/fuse/fuse-passthrough.rst`; FUSE ABI
//! 7.40+, `FUSE_PASSTHROUGH = 1 << 37`, `FOPEN_PASSTHROUGH = 1 << 7`,
//! `FUSE_DEV_IOC_BACKING_OPEN`/`_CLOSE`, magic 229).
//!
//! Passthrough is only safe for a file whose bytes an *ordinary descriptor
//! cannot mutate*. A historical snapshot view is exactly that: read-only, pinned
//! to a committed root, and immutable for the mount's lifetime. This module
//! materializes a **byte-exact** copy of such a file into a concealed area and
//! names it by a version-qualified identity that includes the content digest, so
//! a different committed version can never reuse the same backing image.
//!
//! The image is a *manifested* structure: it is version-qualified
//! `(volume uuid, root, inode, inode version, generation, content digest)`,
//! physically accounted ([`crate::stats`]), and **never authoritative** — it is
//! derived from, and verified against, the authoritative log. It is written
//! once (temp file + atomic rename), digest-verified, and reused across opens;
//! a missing or corrupted image is silently rebuilt from the authoritative
//! bytes.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{OrfsError, Result};

/// The concealed directory (hidden from the namespace) that holds backing
/// images beneath a volume root.
pub const PASSTHROUGH_DIR: &str = ".or_passthrough";

/// Schema of the per-image pointer manifest.
const MANIFEST_SCHEMA: u32 = 1;
/// Chunk size used to stream the authoritative bytes into the image.
const READ_CHUNK: u32 = 1 << 20;

/// A version-qualified identity for an immutable backing image.
///
/// Two images with different identities may never be confused: the path embeds
/// every field except the digest, and the digest is verified before reuse, so a
/// read served from a backing image is byte-exact for exactly one committed
/// version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackingIdentity {
    /// The volume UUID (scopes the root offset).
    pub uuid: [u8; 16],
    /// The committed root offset the content was reconstructed at.
    pub root: u64,
    /// The stable inode id.
    pub inode: u64,
    /// The inode's current metadata/content version.
    pub inode_version: u64,
    /// The inode generation (never reused today, recorded for completeness).
    pub generation: u64,
}

impl BackingIdentity {
    /// The canonical hyphenated UUID string (`8-4-4-4-12`).
    pub fn uuid_string(&self) -> String {
        let b = &self.uuid;
        let mut s = String::with_capacity(36);
        for (i, byte) in b.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                s.push('-');
            }
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}

/// A materialized, digest-verified backing image.
#[derive(Debug, Clone)]
pub struct BackingImage {
    /// The concealed path of the image (a regular file, readable by the daemon).
    pub path: PathBuf,
    /// BLAKE3 of the image bytes (the content digest).
    pub digest: [u8; 32],
    /// Logical size in bytes.
    pub size: u64,
    /// Whether an existing image was verified and reused (`true`) or the image
    /// was freshly materialized (`false`).
    pub reused: bool,
}

impl BackingImage {
    /// The content digest as lowercase hex.
    pub fn digest_hex(&self) -> String {
        hex(&self.digest)
    }
}

/// Lowercase hex of a byte slice.
pub fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0xf) as usize] as char);
    }
    s
}

/// The concealed directory holding one identity's image.
fn image_dir(volume_dir: &Path, id: &BackingIdentity) -> PathBuf {
    volume_dir
        .join(PASSTHROUGH_DIR)
        .join(id.uuid_string())
        .join(id.root.to_string())
        .join(format!("{}-{}", id.inode, id.inode_version))
}

/// The per-image pointer manifest (JSON), recording the digest to verify on
/// reuse. `None` fields are never written; the manifest is not authoritative.
fn manifest_path(volume_dir: &Path, id: &BackingIdentity) -> PathBuf {
    image_dir(volume_dir, id).join("manifest.json")
}

/// The image path inside its identity directory.
fn image_path(volume_dir: &Path, id: &BackingIdentity) -> PathBuf {
    image_dir(volume_dir, id).join("image")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Manifest {
    schema: u32,
    volume_uuid: String,
    root: u64,
    inode: u64,
    inode_version: u64,
    generation: u64,
    size: u64,
    digest: String,
    image: String,
}

/// Materialize (or reuse) the byte-exact backing image for `id`.
///
/// `read(offset, len)` must return the authoritative bytes of the file at that
/// range; it is the *only* source of image content, so a passthrough-served read
/// is byte-identical to a daemon-served read by construction. The image is
/// written once, verified against its BLAKE3 digest, and reused on later calls;
/// a missing, truncated, or corrupted image is rebuilt from `read`.
pub fn materialize<F>(
    volume_dir: &Path,
    id: &BackingIdentity,
    size: u64,
    mut read: F,
) -> Result<BackingImage>
where
    F: FnMut(u64, u32) -> Result<Vec<u8>>,
{
    if let Some(image) = try_reuse(volume_dir, id, size)? {
        return Ok(image);
    }

    let dir = image_dir(volume_dir, id);
    std::fs::create_dir_all(&dir)?;

    // Write the image under a unique temporary name, then publish atomically.
    let tmp = dir.join(format!(
        "image.tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));

    let digest = {
        let mut hasher = blake3::Hasher::new();
        let mut file = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        let mut offset = 0u64;
        while offset < size {
            let want = (size - offset).min(READ_CHUNK as u64) as u32;
            let bytes = read(offset, want)?;
            if bytes.is_empty() {
                // The authoritative source ended early: never fabricate bytes.
                let _ = std::fs::remove_file(&tmp);
                return Err(OrfsError::Corrupt(format!(
                    "authoritative read ended at offset {offset} of {size} while \
                     materializing a passthrough backing image"
                )));
            }
            hasher.update(&bytes);
            file.write_all(&bytes)?;
            offset += bytes.len() as u64;
        }
        file.sync_all()?;
        *hasher.finalize().as_bytes()
    };

    let image = image_path(volume_dir, id);
    std::fs::rename(&tmp, &image)?;
    write_manifest(&manifest_path(volume_dir, id), id, size, &digest)?;
    sync_dir(&dir);

    Ok(BackingImage {
        path: image,
        digest,
        size,
        reused: false,
    })
}

/// Attempt to reuse an existing image: the manifest must match the identity
/// exactly, the image length must match, and its BLAKE3 must equal the recorded
/// digest. Any mismatch is a miss (the caller rebuilds).
fn try_reuse(volume_dir: &Path, id: &BackingIdentity, size: u64) -> Result<Option<BackingImage>> {
    let manifest_bytes = match std::fs::read(manifest_path(volume_dir, id)) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    let m: Manifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if m.schema != MANIFEST_SCHEMA
        || m.volume_uuid != id.uuid_string()
        || m.root != id.root
        || m.inode != id.inode
        || m.inode_version != id.inode_version
        || m.generation != id.generation
        || m.size != size
        || m.image != "image"
    {
        return Ok(None);
    }
    let path = image_path(volume_dir, id);
    match std::fs::metadata(&path) {
        Ok(md) if md.len() == size => {}
        _ => return Ok(None),
    }
    let digest = hash_file(&path)?;
    if hex(&digest) != m.digest {
        return Ok(None);
    }
    Ok(Some(BackingImage {
        path,
        digest,
        size,
        reused: true,
    }))
}

fn write_manifest(path: &Path, id: &BackingIdentity, size: u64, digest: &[u8; 32]) -> Result<()> {
    let m = Manifest {
        schema: MANIFEST_SCHEMA,
        volume_uuid: id.uuid_string(),
        root: id.root,
        inode: id.inode,
        inode_version: id.inode_version,
        generation: id.generation,
        size,
        digest: hex(digest),
        image: "image".to_string(),
    };
    let mut bytes = serde_json::to_vec_pretty(&m)
        .map_err(|e| OrfsError::Corrupt(format!("encode passthrough manifest: {e}")))?;
    bytes.push(b'\n');
    let tmp = path.with_extension(format!(
        "json.tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    {
        let mut f = OpenOptions::new().create_new(true).write(true).open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Stream-hash a file with BLAKE3.
fn hash_file(path: &Path) -> Result<[u8; 32]> {
    use std::io::Read;
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; READ_CHUNK as usize];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// Best-effort directory fsync so a published image survives a crash.
fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

/// The physical bytes of the concealed passthrough area beneath `volume_dir`
/// (for [`crate::stats`]).
pub fn area_bytes(volume_dir: &Path) -> u64 {
    crate::manifestation::dir_bytes(&volume_dir.join(PASSTHROUGH_DIR))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(root: u64, inode: u64, version: u64) -> BackingIdentity {
        BackingIdentity {
            uuid: [0x11; 16],
            root,
            inode,
            inode_version: version,
            generation: 1,
        }
    }

    #[test]
    fn materializes_verifies_and_reuses() {
        let dir = tempfile::TempDir::new().unwrap();
        let content = (0..5000u32).map(|i| (i % 251) as u8).collect::<Vec<_>>();
        let size = content.len() as u64;
        let me = id(10, 7, 1);
        let src = content.clone();
        let img = materialize(dir.path(), &me, size, |off, len| {
            let start = off as usize;
            let end = (start + len as usize).min(src.len());
            Ok(src[start..end].to_vec())
        })
        .unwrap();
        assert!(!img.reused);
        assert_eq!(img.size, size);
        assert_eq!(std::fs::read(&img.path).unwrap(), content);

        // Reuse: the same identity verifies and does not rewrite.
        let src2 = content.clone();
        let again = materialize(dir.path(), &me, size, |off, len| {
            let start = off as usize;
            let end = (start + len as usize).min(src2.len());
            Ok(src2[start..end].to_vec())
        })
        .unwrap();
        assert!(again.reused);
        assert_eq!(again.digest, img.digest);
        assert_eq!(again.path, img.path);
    }

    #[test]
    fn corrupt_image_is_rebuilt() {
        let dir = tempfile::TempDir::new().unwrap();
        let content = vec![9u8; 4096];
        let size = content.len() as u64;
        let me = id(1, 1, 1);
        let src = content.clone();
        let img = materialize(dir.path(), &me, size, |off, len| {
            let s = off as usize;
            let e = (s + len as usize).min(src.len());
            Ok(src[s..e].to_vec())
        })
        .unwrap();
        // Corrupt the image in place; the next materialize must rebuild it.
        std::fs::write(&img.path, vec![0u8; 4096]).unwrap();
        let src2 = content.clone();
        let rebuilt = materialize(dir.path(), &me, size, |off, len| {
            let s = off as usize;
            let e = (s + len as usize).min(src2.len());
            Ok(src2[s..e].to_vec())
        })
        .unwrap();
        assert!(!rebuilt.reused);
        assert_eq!(std::fs::read(&rebuilt.path).unwrap(), content);
    }

    #[test]
    fn different_versions_never_share_a_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let a = id(10, 7, 1);
        let b = id(11, 7, 1);
        let c = id(10, 7, 2);
        assert_ne!(image_path(dir.path(), &a), image_path(dir.path(), &b));
        assert_ne!(image_path(dir.path(), &a), image_path(dir.path(), &c));
    }
}
