//! Manifested **direct-page atlas** (reviewer research §5) — a page-aligned,
//! contiguous copy of an object's committed logical content, for selected (hot)
//! objects.
//!
//! The measured EKBLOOM frontier (§5) shows EKBLOOM wins for tiny random reads but
//! **not** for 4–64 KiB reads: a `path` bloom costs one symbol lookup per byte,
//! while the authoritative extent read is already `O(1)` when the object is
//! unfragmented. The gap §5 names is *physical form*: a manifested structure that
//! serves a different request shape well. The atlas is exactly that — a single
//! contiguous image of the logical bytes, read by **direct slicing** (one bounded
//! copy, no EKBLOOM decode). It is built from the committed extent data at a
//! committed root and is opt-in per object.
//!
//! This module mirrors the trigram plane's store + manifest + digest pattern
//! (`src/trigram.rs`): an append-only catalogue over a concealed subdirectory,
//! immutable self-validating manifests, and a recovered "newest per inode"
//! published set. It deliberately invents **no** new on-disk scheme.
//!
//! **Derived and never authoritative.** The atlas is a copy of committed history;
//! it is consulted only when it is qualified for the exact `(volume, inode,
//! inode_version, root, logical length)` of the read, its payload digest is
//! verified against the sealed manifest, and the read planner only *adds* it as a
//! measured candidate. A missing, stale, or corrupt atlas simply leaves reads on
//! the authoritative path — the bytes can never change.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use crate::error::{OrfsError, Result};
use crate::manifestation::{
    dir_bytes, Catalogue, CatalogueEntry, Dec, Enc, CAT_FAMILY_ATLAS, MANIFEST_DIR_SYNC_INTERVAL,
};
use crate::segment::fsync_dir;

/// The concealed subdirectory holding atlas payloads and manifests.
pub const ATLAS_DIR: &str = "atlas";
/// The atlas payload format schema (bump on any incompatible change).
pub const ATLAS_SCHEMA: u32 = 1;
/// The atlas format identifier surfaced in evidence.
pub const ATLAS_VERSION: &str = "1";
/// The alignment of the content region inside a payload (bytes). The atlas is a
/// **page-aligned** image: the logical bytes begin at this file offset, so an
/// `O_DIRECT` read of the content region is aligned and needs no bounce buffer.
pub const ATLAS_ALIGN: u64 = 4096;

const ATLAS_MAGIC: u32 = 0x4F52_4154; // "ORAT"

// ---------------------------------------------------------------------------
// The payload image
// ---------------------------------------------------------------------------

/// Build the aligned payload image for `source`: a small self-describing header
/// padded to [`ATLAS_ALIGN`], then the logical bytes verbatim.
///
/// Returns the payload and the content offset (always [`ATLAS_ALIGN`]).
pub fn build_atlas_payload(source: &[u8], logical_start: u64) -> (Vec<u8>, u64) {
    let content_offset = ATLAS_ALIGN;
    let mut out = vec![0u8; content_offset as usize + source.len()];
    let mut e = Enc::new();
    e.u32(ATLAS_MAGIC);
    e.u32(ATLAS_SCHEMA);
    e.u64(source.len() as u64);
    e.u64(logical_start);
    let header = e.into_vec();
    out[..header.len()].copy_from_slice(&header);
    out[content_offset as usize..].copy_from_slice(source);
    (out, content_offset)
}

// ---------------------------------------------------------------------------
// The version-qualified manifest
// ---------------------------------------------------------------------------

/// A committed, self-validating direct-page atlas manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPageManifest {
    pub schema: u32,
    pub generation: u64,
    pub volume_uuid: [u8; 16],
    pub inode: u64,
    pub inode_version: u64,
    pub root: u64,
    /// The length of the covered logical range.
    pub logical_len: u64,
    /// The first logical byte the atlas covers (0 for a complete atlas).
    pub logical_start: u64,
    /// The alignment of the content region within the payload.
    pub align: u64,
    /// The file offset at which the content region begins.
    pub content_offset: u64,
    pub payload_rel_path: String,
    pub payload_blake3: [u8; 32],
    pub payload_bytes: u64,
    pub manifest_blake3: [u8; 32],
}

impl DirectPageManifest {
    /// Whether this atlas is usable for exactly this identity. Any mismatch
    /// (inode, version, root, or logical length) is a refusal, not a warning.
    pub fn usable_for(&self, inode: u64, inode_version: u64, root: u64, logical_len: u64) -> bool {
        self.inode == inode
            && self.inode_version == inode_version
            && self.root == root
            && self.logical_len == logical_len
    }

    /// Whether this atlas covers the logical range `[offset, end)`.
    pub fn covers(&self, offset: u64, end: u64) -> bool {
        offset >= self.logical_start
            && end <= self.logical_start.saturating_add(self.logical_len)
            && end >= offset
    }

    /// The payload byte range `[start, end)` for the logical range `[offset, end)`,
    /// when covered.
    pub fn payload_range(&self, offset: u64, end: u64) -> Option<(usize, usize)> {
        if !self.covers(offset, end) {
            return None;
        }
        let start = self.content_offset + (offset - self.logical_start);
        let stop = self.content_offset + (end - self.logical_start);
        Some((start as usize, stop as usize))
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u32(ATLAS_MAGIC);
        e.u32(self.schema);
        e.u64(self.generation);
        e.arr(&self.volume_uuid);
        e.u64(self.inode);
        e.u64(self.inode_version);
        e.u64(self.root);
        e.u64(self.logical_len);
        e.u64(self.logical_start);
        e.u64(self.align);
        e.u64(self.content_offset);
        e.str(&self.payload_rel_path);
        e.arr(&self.payload_blake3);
        e.u64(self.payload_bytes);
        e.into_vec()
    }

    /// The self-integrity digest over every preceding canonical field.
    pub fn compute_digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// Seal: stamp the self-digest.
    pub fn sealed(mut self) -> DirectPageManifest {
        self.manifest_blake3 = self.compute_digest();
        self
    }

    fn is_sealed(&self) -> bool {
        self.manifest_blake3 == self.compute_digest()
    }

    /// Encode the sealed manifest.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.canonical_bytes();
        bytes.extend_from_slice(&self.manifest_blake3);
        bytes
    }

    /// Decode and validate a manifest (self-digest, magic, schema, no trailing
    /// bytes). Any failure is an error; the caller treats it as uncommitted.
    pub fn decode(bytes: &[u8]) -> Result<DirectPageManifest> {
        let tail = bytes
            .len()
            .checked_sub(32)
            .ok_or_else(|| OrfsError::Corrupt("atlas manifest is truncated".into()))?;
        let (body, digest) = bytes.split_at(tail);
        let mut d = Dec::new(body);
        let corrupt = |what: &str| OrfsError::Corrupt(format!("atlas manifest {what}"));
        if d.u32()? != ATLAS_MAGIC {
            return Err(corrupt("has a bad magic"));
        }
        let schema = d.u32()?;
        let generation = d.u64()?;
        let volume_uuid = d.arr16()?;
        let inode = d.u64()?;
        let inode_version = d.u64()?;
        let root = d.u64()?;
        let logical_len = d.u64()?;
        let logical_start = d.u64()?;
        let align = d.u64()?;
        let content_offset = d.u64()?;
        let payload_rel_path = d.string()?;
        let payload_blake3 = d.arr32()?;
        let payload_bytes = d.u64()?;
        if d.remaining() != 0 {
            return Err(corrupt("has trailing bytes"));
        }
        let mut digest_arr = [0u8; 32];
        digest_arr.copy_from_slice(digest);
        let m = DirectPageManifest {
            schema,
            generation,
            volume_uuid,
            inode,
            inode_version,
            root,
            logical_len,
            logical_start,
            align,
            content_offset,
            payload_rel_path,
            payload_blake3,
            payload_bytes,
            manifest_blake3: digest_arr,
        };
        if !m.is_sealed() {
            return Err(corrupt("fails its self-digest"));
        }
        Ok(m)
    }

    /// A JSON projection for evidence and the CLI.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "generation": self.generation,
            "volume_uuid": hex(&self.volume_uuid),
            "inode": self.inode,
            "inode_version": self.inode_version,
            "root": self.root,
            "logical_len": self.logical_len,
            "logical_start": self.logical_start,
            "align": self.align,
            "content_offset": self.content_offset,
            "payload_rel_path": self.payload_rel_path,
            "payload_blake3": hex(&self.payload_blake3),
            "payload_bytes": self.payload_bytes,
            "manifest_blake3": hex(&self.manifest_blake3),
        })
    }
}

/// Lowercase hex of a byte slice.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// The generation store
// ---------------------------------------------------------------------------

/// A recovery summary of the committed atlas set.
#[derive(Debug, Clone, Default)]
pub struct DirectAtlasRecovery {
    /// Valid committed manifests, ascending by generation.
    pub generations: Vec<DirectPageManifest>,
    /// Candidates rejected (torn, corrupt, or with a missing/torn payload).
    pub rejected: usize,
}

impl DirectAtlasRecovery {
    /// The newest valid manifest per inode.
    pub fn newest_per_inode(&self) -> BTreeMap<u64, DirectPageManifest> {
        let mut out: BTreeMap<u64, DirectPageManifest> = BTreeMap::new();
        for m in &self.generations {
            let replace = match out.get(&m.inode) {
                Some(cur) => (m.inode_version, m.generation) > (cur.inode_version, cur.generation),
                None => true,
            };
            if replace {
                out.insert(m.inode, m.clone());
            }
        }
        out
    }
}

/// The result of a catalogue-accelerated recovery of the published atlas set.
#[derive(Debug, Clone)]
pub struct DirectAtlasLatest {
    /// The newest valid manifest per inode.
    pub published: BTreeMap<u64, DirectPageManifest>,
    /// Distinct committed generations (catalogue record count on the fast path).
    pub committed: u64,
    /// Candidates rejected (always `0` on the fast path).
    pub rejected: usize,
    /// Whether the fast catalogue path was used.
    pub catalogue_used: bool,
}

/// The on-disk atlas store rooted at `<volume>/.or_bloom/atlas`.
#[derive(Debug, Clone)]
pub struct DirectPageStore {
    volume_root: PathBuf,
    root_dir: PathBuf,
    catalogue: Catalogue,
    /// Serializes catalogue appends/seals across threads (mirrors the generation
    /// and trigram stores). Shared by every clone.
    append_lock: Arc<Mutex<()>>,
}

impl DirectPageStore {
    /// The store for a volume backing directory.
    pub fn new(volume_root: &Path) -> DirectPageStore {
        let root_dir = volume_root.join(".or_bloom").join(ATLAS_DIR);
        let catalogue = Catalogue::new(root_dir.join("catalogue"), CAT_FAMILY_ATLAS);
        DirectPageStore {
            volume_root: volume_root.to_path_buf(),
            root_dir,
            catalogue,
            append_lock: Arc::new(Mutex::new(())),
        }
    }

    /// The volume backing root.
    pub fn volume_root(&self) -> &Path {
        &self.volume_root
    }

    /// The atlas subdirectory.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Create the directory (idempotent).
    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.root_dir)?;
        fs::create_dir_all(self.catalogue.dir())?;
        Ok(())
    }

    /// The relative payload path for a generation.
    pub fn payload_rel_path(&self, generation: u64, inode: u64, version: u64, root: u64) -> String {
        format!(".or_bloom/{ATLAS_DIR}/{inode}-v{version}-r{root}-g{generation}.atlas")
    }

    /// The absolute payload path for a generation.
    pub fn payload_path(&self, generation: u64, inode: u64, version: u64, root: u64) -> PathBuf {
        self.volume_root
            .join(self.payload_rel_path(generation, inode, version, root))
    }

    fn manifest_path(&self, generation: u64) -> PathBuf {
        self.root_dir.join(format!("{generation:020}.manifest"))
    }

    /// The set of generation numbers with a manifest file on disk.
    pub fn manifest_generations(&self) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.root_dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(stem) = name.strip_suffix(".manifest") {
                if let Ok(gen) = stem.parse::<u64>() {
                    out.push(gen);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// The next unused generation number, taking the catalogue into account so a
    /// number is never reused.
    pub fn next_generation(&self) -> Result<u64> {
        let mut max = self.manifest_generations()?.into_iter().max();
        if let Some((entries, _)) = self.catalogue.latest() {
            for e in entries.values() {
                max = Some(max.map_or(e.generation, |m| m.max(e.generation)));
            }
        }
        Ok(max.map(|m| m + 1).unwrap_or(1))
    }

    /// Load and validate one manifest by generation number.
    pub fn load_generation(&self, generation: u64) -> Result<Option<DirectPageManifest>> {
        let bytes = match fs::read(self.manifest_path(generation)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(DirectPageManifest::decode(&bytes).ok())
    }

    /// Validate a manifest's payload against its recorded BLAKE3 and length.
    pub fn payload_matches(&self, m: &DirectPageManifest) -> bool {
        match hash_file(&self.volume_root.join(&m.payload_rel_path)) {
            Ok((digest, len)) => digest == m.payload_blake3 && len == m.payload_bytes,
            Err(_) => false,
        }
    }

    /// Publish a generation: append its immutable catalogue entry, then write the
    /// payload and manifest (catalogue-first ordering, exactly as the generation
    /// and trigram stores).
    pub fn publish(&self, manifest: &DirectPageManifest, payload: &[u8]) -> Result<()> {
        self.ensure_dirs()?;
        let entry = CatalogueEntry {
            generation: manifest.generation,
            volume_uuid: manifest.volume_uuid,
            inode: manifest.inode,
            inode_version: manifest.inode_version,
            root: manifest.root,
            manifest_blake3: manifest.manifest_blake3,
            payload_blake3: manifest.payload_blake3,
        };
        let sealed = {
            let _guard = self.append_lock.lock();
            self.migrate_legacy_catalogue()?;
            self.catalogue.append(&entry)?
        };

        let payload_path = self.volume_root.join(&manifest.payload_rel_path);
        let tmp = payload_path.with_extension("atlas.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(payload)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &payload_path)?;

        let final_path = self.manifest_path(manifest.generation);
        let mtmp = final_path.with_extension("manifest.tmp");
        {
            let mut f = File::create(&mtmp)?;
            f.write_all(&manifest.encode())?;
            f.sync_all()?;
        }
        fs::rename(&mtmp, &final_path)?;
        if manifest.generation <= MANIFEST_DIR_SYNC_INTERVAL || sealed {
            fsync_dir(&self.root_dir)?;
        }
        Ok(())
    }

    /// Recover the committed atlas set by scanning every manifest and validating
    /// its payload digest.
    pub fn recover(&self) -> Result<DirectAtlasRecovery> {
        let mut generations = Vec::new();
        let mut rejected = 0usize;
        for gen in self.manifest_generations()? {
            match self.load_generation(gen)? {
                Some(m) if self.payload_matches(&m) => generations.push(m),
                _ => rejected += 1,
            }
        }
        generations.sort_by_key(|m| m.generation);
        Ok(DirectAtlasRecovery {
            generations,
            rejected,
        })
    }

    /// One-time migration for a pre-catalogue volume: when the catalogue has no
    /// segments but atlas manifests exist, fold every existing manifest into the
    /// catalogue in bulk. A volume whose catalogue already has segments is left
    /// untouched.
    pub fn migrate_legacy_catalogue(&self) -> Result<bool> {
        if self.catalogue.segment_path(0).exists() {
            return Ok(false);
        }
        if !self.catalogue.is_empty() {
            return Ok(false);
        }
        let gens: std::collections::BTreeSet<u64> =
            self.manifest_generations()?.into_iter().collect();
        if gens.is_empty() {
            return Ok(false);
        }
        let mut entries = Vec::with_capacity(gens.len());
        for g in gens {
            if let Some(m) = self.load_generation(g)? {
                entries.push(CatalogueEntry {
                    generation: m.generation,
                    volume_uuid: m.volume_uuid,
                    inode: m.inode,
                    inode_version: m.inode_version,
                    root: m.root,
                    manifest_blake3: m.manifest_blake3,
                    payload_blake3: m.payload_blake3,
                });
            }
        }
        self.catalogue.bulk_load(&entries)?;
        Ok(true)
    }

    /// Recover the newest valid manifest per inode using the append-only
    /// catalogue (newest usable summary plus only the segments after it), falling
    /// back to the full validated scan when the catalogue is absent or unusable.
    pub fn latest_published(&self) -> Result<DirectAtlasLatest> {
        if let Some((entries, count)) = self.catalogue.latest() {
            let mut published: BTreeMap<u64, DirectPageManifest> = BTreeMap::new();
            let mut all_valid = true;
            for (inode, e) in &entries {
                match self.load_generation(e.generation)? {
                    Some(m)
                        if m.inode == *inode
                            && m.manifest_blake3 == e.manifest_blake3
                            && self.payload_matches(&m) =>
                    {
                        published.insert(*inode, m);
                    }
                    _ => all_valid = false,
                }
            }
            if all_valid {
                return Ok(DirectAtlasLatest {
                    published,
                    committed: count,
                    rejected: 0,
                    catalogue_used: true,
                });
            }
        }
        let recovery = self.recover()?;
        let committed = recovery.generations.len() as u64;
        Ok(DirectAtlasLatest {
            published: recovery.newest_per_inode(),
            committed,
            rejected: recovery.rejected,
            catalogue_used: false,
        })
    }

    /// Bytes under the atlas subdirectory (for accounting/evidence).
    pub fn bytes(&self) -> u64 {
        dir_bytes(&self.root_dir)
    }
}

fn hash_file(path: &Path) -> Result<([u8; 32], u64)> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((*hasher.finalize().as_bytes(), total))
}

// ---------------------------------------------------------------------------
// Published state
// ---------------------------------------------------------------------------

/// The published direct-page atlas set, shared between the namespace and the read
/// planner.
pub struct DirectPageState {
    store: DirectPageStore,
    uuid: [u8; 16],
    published: RwLock<BTreeMap<u64, DirectPageManifest>>,
}

impl DirectPageState {
    /// Recover the published set from disk (newest per inode), using the
    /// append-only catalogue when usable and the full validated scan otherwise.
    pub fn recover(store: DirectPageStore, uuid: [u8; 16]) -> Result<Arc<DirectPageState>> {
        let latest = store.latest_published()?;
        Ok(Arc::new(DirectPageState {
            store,
            uuid,
            published: RwLock::new(latest.published),
        }))
    }

    /// The generation store.
    pub fn store(&self) -> &DirectPageStore {
        &self.store
    }

    /// The owning volume UUID.
    pub fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    /// Every currently published atlas (newest per inode).
    pub fn published(&self) -> Vec<DirectPageManifest> {
        self.published.read().values().cloned().collect()
    }

    /// The number of published atlases (newest per inode).
    pub fn generation_count(&self) -> u64 {
        self.published.read().len() as u64
    }

    /// Total published payload bytes.
    pub fn manifested_bytes_total(&self) -> u64 {
        self.published
            .read()
            .values()
            .map(|m| m.payload_bytes)
            .sum()
    }

    /// The newest published atlas for an inode, if any.
    pub fn latest_for(&self, inode: u64) -> Option<DirectPageManifest> {
        self.published.read().get(&inode).cloned()
    }

    /// The newest atlas *exactly* qualified for `(inode, version, root)` and
    /// matching `logical_len`. Any mismatch yields `None`.
    pub fn usable_for(
        &self,
        inode: u64,
        inode_version: u64,
        root: u64,
        logical_len: u64,
    ) -> Option<DirectPageManifest> {
        let guard = self.published.read();
        let m = guard.get(&inode)?;
        if m.usable_for(inode, inode_version, root, logical_len) {
            Some(m.clone())
        } else {
            None
        }
    }

    /// Load and verify one atlas payload against its committed manifest digest.
    /// Never returns bytes that do not match the manifest.
    pub fn load_payload(&self, m: &DirectPageManifest) -> Result<Vec<u8>> {
        let path = self.store.volume_root().join(&m.payload_rel_path);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(OrfsError::Corrupt(format!(
                    "atlas payload is absent: {}",
                    m.payload_rel_path
                )))
            }
            Err(e) => return Err(e.into()),
        };
        if bytes.len() as u64 != m.payload_bytes {
            return Err(OrfsError::Corrupt(
                "atlas payload length does not match the committed manifest".into(),
            ));
        }
        if *blake3::hash(&bytes).as_bytes() != m.payload_blake3 {
            return Err(OrfsError::Corrupt(
                "atlas payload BLAKE3 does not match the committed manifest".into(),
            ));
        }
        Ok(bytes)
    }

    /// Publish a sealed manifest and its payload.
    pub fn publish(&self, m: &DirectPageManifest, payload: &[u8]) -> Result<()> {
        self.store.publish(m, payload)?;
        self.record_published(m.clone());
        Ok(())
    }

    fn record_published(&self, manifest: DirectPageManifest) {
        let mut guard = self.published.write();
        let replace = match guard.get(&manifest.inode) {
            Some(cur) => {
                (manifest.inode_version, manifest.generation) > (cur.inode_version, cur.generation)
            }
            None => true,
        };
        if replace {
            guard.insert(manifest.inode, manifest);
        }
    }
}

/// The outcome of one `Namespace::manifest_direct_page_atlas` call.
#[derive(Debug, Clone)]
pub struct DirectAtlasOutcome {
    pub inode: u64,
    pub inode_version: u64,
    pub root: u64,
    pub generation: u64,
    pub logical_len: u64,
    pub payload_bytes: u64,
    pub content_offset: u64,
    pub align: u64,
    pub published: bool,
    pub detail: String,
}
