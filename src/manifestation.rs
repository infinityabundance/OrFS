//! The concealed operational body: asynchronous, version-qualified
//! manifestation with physical accounting (research §9, §10, §11, §16, §33).
//!
//! Plane C builds **additional** operational structures (EKBLOOM histories,
//! checkpoints, transition blooms, and the optional other acceleration
//! families) behind the ordinary logical namespace. Two laws bound it:
//!
//! * Law I — manifestation **never** removes or rewrites authoritative history.
//!   Every structure here is derived, disposable, and rebuildable; a fault in
//!   this plane must never corrupt the authoritative plane. Logical output is
//!   identical with or without any manifested structure.
//! * I6 — every committed generation records the exact object identity it was
//!   built from (inode, inode version, authoritative root). A structure built
//!   for one inode version must **not** be used against another.
//!
//! # Generation identity
//!
//! A [`GenerationManifest`] records *all* identity and accounting fields the
//! research requires: volume identity, inode identity, inode version,
//! authoritative root, EKBLOOM version, manifestation profile, logical range,
//! physical range, construction parameters, certification state, integrity
//! information (BLAKE3 over the payload and over the manifest), and the physical
//! byte size.
//!
//! # Publication protocol
//!
//! Every generation is published atomically:
//!
//! ```text
//! write payload  ->  write manifest  ->  fsync  ->  publish (advertise)
//! ```
//!
//! The payload is written and fsynced by the builder; the manifest is written to
//! `<gen>.manifest.tmp`, fsynced, atomically renamed to `<gen>.manifest`, and the
//! directory is fsynced. Only then is the generation **advertised** by updating
//! `manifests/HEAD`. Recovery selects the newest **valid** committed generation
//! per inode; a torn manifest or a torn `HEAD` is simply skipped and can never
//! invalidate an earlier commit. A job cancelled after it wrote some physical
//! bytes leaves an *orphan* payload that is referenced by no committed manifest
//! and is therefore invisible to ordinary reads.
//!
//! # Bounded workers, backpressure, cancellation
//!
//! CPU worker threads construct payloads; `io_uring` is deliberately **not** used
//! to construct (research §20 Ring B is a persistence optimisation, not a build
//! engine). The job queue is bounded: when it is full, [`ManifestationEngine::submit`]
//! returns [`QueueFull`] and the optional construction is dropped — the
//! authoritative commit path never blocks on it. A newer inode version cancels
//! and supersedes older pending jobs (research §10.3).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex, RwLock};

use crate::error::{OrfsError, Result};
use crate::segment::fsync_dir;

/// The EKBLOOM engine version this build is compiled against. Kept in lockstep
/// with the rev-pinned `ekbloom` git dependency in `Cargo.toml` (`= 0.3.0`); it
/// is recorded verbatim in every generation manifest.
pub const EKBLOOM_VERSION: &str = "0.3.0";

/// The concealed operational-body directory (research §4, §9).
pub const BLOOM_DIR: &str = ".or_bloom";
/// The generation-manifest directory under [`BLOOM_DIR`].
pub const MANIFEST_DIR: &str = "manifests";
/// The EKBLOOM payload directory under [`BLOOM_DIR`].
pub const EKBLOOM_DIR: &str = "ekbloom";

/// Magic for a canonical generation manifest (`MFS1`, little-endian).
const MANIFEST_MAGIC: u32 = 0x3153_464D;
/// Magic for the `HEAD` advertisement (`MHD1`).
const HEAD_MAGIC: u32 = 0x3144_484D;
/// On-disk schema version of a generation manifest. Schema 2 adds the
/// generational overlay fields (`base_generation`, `base_manifest_blake3`,
/// `overlay_depth`, `regions`); a schema-1 document still decodes (its overlay
/// fields default to a self-contained full base).
pub const MANIFEST_SCHEMA: u32 = 2;

/// The hard cap on the overlay indirection depth (Phase 22). A committed
/// generation never records `overlay_depth` greater than this: an overlay whose
/// depth would exceed it is instead published as a *flattened* generation, so a
/// committed version resolves to its regions through at most this many hops.
/// The bound is small and fixed so accumulated generations cannot blow up read
/// latency.
pub const MAX_OVERLAY_DEPTH: u16 = 8;

/// The number of overlay generations after which the engine prefers to emit a
/// flattened readable view even though the depth cap has not yet been reached
/// (adaptive flattening: the read benefit of a compact table justifies the
/// index-only cost).
pub const FLATTEN_AFTER_OVERLAYS: u16 = 4;

// ---------------------------------------------------------------------------
// Manifestation profiles (research §10.1)
// ---------------------------------------------------------------------------

/// A progressive operational-body profile. Each variant names an *executable
/// path*, not merely a label; the exact structures are built by EKBLOOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManifestationProfile {
    /// Authoritative executable core only.
    Root,
    /// Sparse complete restart states at `interval`.
    Sparse { interval: u32 },
    /// Denser retained state history at `interval`.
    Dense { interval: u32 },
    /// Complete non-withdrawal per-position state projection.
    Full,
    /// Certified `depth`-step transition bloom.
    Bloom { depth: u16 },
    /// Regional transition blooms.
    Regional { depth: u16, region_bytes: u32 },
    /// Exact path-specific `depth`-symbol manifestation.
    Path { depth: u16 },
    /// Fastest verified configuration for the selected workload.
    MaxSpeed,
}

impl ManifestationProfile {
    /// Parse a profile name. Names mirror the research §10.1 set; the optional
    /// `depth`, `interval`, and `region_bytes` overrides refine the parameters.
    pub fn parse(
        name: &str,
        depth: Option<u16>,
        interval: Option<u32>,
        region_bytes: Option<u32>,
    ) -> Result<ManifestationProfile> {
        let base = match name {
            "root" => ManifestationProfile::Root,
            "sparse" => ManifestationProfile::Sparse {
                interval: interval.unwrap_or(1024),
            },
            "dense" => ManifestationProfile::Dense {
                interval: interval.unwrap_or(256),
            },
            "full" => ManifestationProfile::Full,
            "bloom4" | "bloom" => ManifestationProfile::Bloom {
                depth: depth.unwrap_or(4),
            },
            "bloom8" => ManifestationProfile::Bloom {
                depth: depth.unwrap_or(8),
            },
            "regional" => ManifestationProfile::Regional {
                depth: depth.unwrap_or(4),
                region_bytes: region_bytes.unwrap_or(64 * 1024),
            },
            "path4" | "path" => ManifestationProfile::Path {
                depth: depth.unwrap_or(4),
            },
            "max-speed" | "maxspeed" => ManifestationProfile::MaxSpeed,
            other => {
                return Err(OrfsError::InvalidArgument(format!(
                    "unknown manifestation profile {other:?} \
                     (expected root|sparse|dense|full|bloom4|bloom8|regional|path4|max-speed)"
                )))
            }
        };
        Ok(base.with_params(depth, interval, region_bytes))
    }

    /// Apply parameter overrides to a profile that bears them. The `depth` flag
    /// makes a `bloom4` request render as `bloom(D)`; `interval` refines
    /// sparse/dense; `region_bytes` refines regional.
    pub fn with_params(
        self,
        depth: Option<u16>,
        interval: Option<u32>,
        region_bytes: Option<u32>,
    ) -> ManifestationProfile {
        match self {
            ManifestationProfile::Sparse { interval: i } => ManifestationProfile::Sparse {
                interval: interval.unwrap_or(i),
            },
            ManifestationProfile::Dense { interval: i } => ManifestationProfile::Dense {
                interval: interval.unwrap_or(i),
            },
            ManifestationProfile::Bloom { depth: d } => ManifestationProfile::Bloom {
                depth: depth.unwrap_or(d),
            },
            ManifestationProfile::Regional {
                depth: d,
                region_bytes: r,
            } => ManifestationProfile::Regional {
                depth: depth.unwrap_or(d),
                region_bytes: region_bytes.unwrap_or(r),
            },
            ManifestationProfile::Path { depth: d } => ManifestationProfile::Path {
                depth: depth.unwrap_or(d),
            },
            other => other,
        }
    }

    /// The stable numeric kind code recorded in a manifest.
    pub const fn kind_code(self) -> u8 {
        match self {
            ManifestationProfile::Root => 0,
            ManifestationProfile::Sparse { .. } => 1,
            ManifestationProfile::Dense { .. } => 2,
            ManifestationProfile::Full => 3,
            ManifestationProfile::Bloom { .. } => 4,
            ManifestationProfile::Regional { .. } => 5,
            ManifestationProfile::Path { .. } => 6,
            ManifestationProfile::MaxSpeed => 7,
        }
    }

    /// The construction parameters carried by this profile.
    pub const fn params(self) -> (Option<u32>, Option<u16>, Option<u32>) {
        match self {
            ManifestationProfile::Sparse { interval }
            | ManifestationProfile::Dense { interval } => (Some(interval), None, None),
            ManifestationProfile::Bloom { depth } | ManifestationProfile::Path { depth } => {
                (None, Some(depth), None)
            }
            ManifestationProfile::Regional {
                depth,
                region_bytes,
            } => (None, Some(depth), Some(region_bytes)),
            ManifestationProfile::Root
            | ManifestationProfile::Full
            | ManifestationProfile::MaxSpeed => (None, None, None),
        }
    }

    /// The EKBLOOM profile this maps to (the construction engine's own type).
    pub fn to_ekbloom(self) -> ekbloom::ManifestationProfile {
        use ekbloom::ManifestationProfile as E;
        match self {
            ManifestationProfile::Root => E::Root,
            ManifestationProfile::Sparse { interval } => E::Sparse { interval },
            ManifestationProfile::Dense { interval } => E::Dense { interval },
            ManifestationProfile::Full => E::Full,
            ManifestationProfile::Bloom { depth } => E::Bloom { depth },
            ManifestationProfile::Regional {
                depth,
                region_bytes,
            } => E::Regional {
                depth,
                region_bytes,
            },
            ManifestationProfile::Path { depth } => E::Path { depth },
            ManifestationProfile::MaxSpeed => E::MaxSpeed,
        }
    }

    /// The canonical label (delegates to EKBLOOM's own stable labels so the two
    /// crates never drift).
    pub fn label(self) -> String {
        self.to_ekbloom().label()
    }
}

// ---------------------------------------------------------------------------
// Certification
// ---------------------------------------------------------------------------

/// The certification state of a manifested generation (mirrors the EKBLOOM
/// certification lattice, plus "built without any certified bloom").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificationState {
    /// No structure manifested (the `root` profile).
    Unmanifested,
    /// Structures built; none carries a bloom that needs certifying.
    Built,
    /// A bloom was built but is not (yet) certified.
    Unverified,
    /// At least one bloom was proven exact over its declared key domain.
    Certified,
    /// A bloom was proven insufficient (a counterexample exists).
    Rejected,
}

impl CertificationState {
    /// A stable name for evidence and extended attributes.
    pub const fn name(self) -> &'static str {
        match self {
            CertificationState::Unmanifested => "unmanifested",
            CertificationState::Built => "built",
            CertificationState::Unverified => "unverified",
            CertificationState::Certified => "certified",
            CertificationState::Rejected => "rejected",
        }
    }

    const fn code(self) -> u8 {
        match self {
            CertificationState::Unmanifested => 0,
            CertificationState::Built => 1,
            CertificationState::Unverified => 2,
            CertificationState::Certified => 3,
            CertificationState::Rejected => 4,
        }
    }

    fn from_code(code: u8) -> Result<CertificationState> {
        Ok(match code {
            0 => CertificationState::Unmanifested,
            1 => CertificationState::Built,
            2 => CertificationState::Unverified,
            3 => CertificationState::Certified,
            4 => CertificationState::Rejected,
            _ => return Err(OrfsError::Corrupt("bad certification code".into())),
        })
    }
}

/// One accounted component of a manifested payload (mirrors EKBLOOM's
/// `inspect` report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestComponent {
    pub name: String,
    pub kind: String,
    pub bytes: u64,
}

/// One manifested region of an incremental (overlay or flattened) generation.
///
/// A region owns the logical byte range `[logical_start, logical_end)` and maps
/// it onto a manifested payload file (an EKBLOOM body built over exactly that
/// slice of authoritative bytes). `payload_offset` is the local offset within
/// that payload corresponding to `logical_start`; a consumer reads payload
/// position `payload_offset + (pos - logical_start)` for global position `pos`.
/// Regions in one manifest are disjoint and sorted by `logical_start`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRegion {
    pub logical_start: u64,
    pub logical_end: u64,
    pub owner_generation: u64,
    pub payload_offset: u64,
    pub payload_rel_path: String,
    pub payload_blake3: [u8; 32],
    pub visible_bytes: u64,
    pub physical_bytes: u64,
    pub profile_kind: u8,
    pub certification: u8,
    pub ekbloom_object_id: Option<[u8; 16]>,
}

// ---------------------------------------------------------------------------
// The generation manifest
// ---------------------------------------------------------------------------

/// The complete identity, construction, certification, integrity, and physical
/// accounting record of one committed acceleration generation (research §9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationManifest {
    /// Schema version of this document.
    pub schema: u32,
    /// Monotonic generation number (unique per volume).
    pub generation: u64,
    /// Volume identity (UUID) the generation belongs to.
    pub volume_uuid: [u8; 16],
    /// Inode identity the generation was built from.
    pub inode: u64,
    /// Inode version the generation was built from (I6).
    pub inode_version: u64,
    /// Authoritative committed root the generation was constructed at.
    pub root: u64,
    /// The construction backend (`"ekbloom"`).
    pub backend: String,
    /// The EKBLOOM engine version.
    pub ekbloom_version: String,
    /// The EKBLOOM on-disk format version (`"0.3"`).
    pub ekbloom_format: String,
    /// The manifestation profile label as recorded.
    pub profile: String,
    /// The profile's numeric kind.
    pub profile_kind: u8,
    /// Logical range `[logical_start, logical_end)` this acceleration serves.
    pub logical_start: u64,
    pub logical_end: u64,
    /// Physical range `[physical_start, physical_end)` inside the payload file.
    pub physical_start: u64,
    pub physical_end: u64,
    /// Construction parameters.
    pub interval: Option<u32>,
    pub depth: Option<u16>,
    pub region_bytes: Option<u32>,
    /// Certification state and the method that established it.
    pub certification: CertificationState,
    pub certification_method: String,
    /// The payload's path relative to the volume root (`".or_bloom/ekbloom/…"`).
    pub payload_rel_path: String,
    /// The EKBLOOM content-derived object identity, when available.
    pub ekbloom_object_id: Option<[u8; 16]>,
    /// BLAKE3 of the payload bytes.
    pub payload_blake3: [u8; 32],
    /// Revealed (visible) bytes.
    pub visible_bytes: u64,
    /// Total physical payload bytes (the actual on-disk file length).
    pub physical_bytes: u64,
    /// Concealed bytes (`physical - visible`).
    pub concealed_bytes: u64,
    /// Source (logical) bytes the generation was built from.
    pub source_bytes: u64,
    /// Per-component accounting.
    pub components: Vec<ManifestComponent>,
    /// For an overlay generation: the base generation whose manifested content
    /// supplies every byte not covered by `regions` (Phase 22). `None` for a
    /// self-contained generation (a full base or a flattened table).
    pub base_generation: Option<u64>,
    /// Integrity binding to the base manifest's self-digest, when overlaying.
    pub base_manifest_blake3: Option<[u8; 32]>,
    /// The overlay indirection depth: `0` for a self-contained generation and
    /// `base.overlay_depth + 1` for an overlay. Never exceeds
    /// [`MAX_OVERLAY_DEPTH`].
    pub overlay_depth: u16,
    /// The manifested regions this generation owns or references. For a flattened
    /// generation these cover `[logical_start, logical_end)` completely with no
    /// base; for an overlay they are only the *changed* ranges.
    pub regions: Vec<ManifestRegion>,
    /// BLAKE3 over every preceding canonical field (self-integrity).
    pub manifest_blake3: [u8; 32],
}

impl GenerationManifest {
    /// Whether this generation may be used for `(inode, version)` at `root`.
    ///
    /// A structure built for one inode version must not be used against another
    /// unless exact compatibility is established; here compatibility is *exact*
    /// identity of inode, inode version, and committed root.
    pub fn usable_for(&self, inode: u64, inode_version: u64, root: u64) -> Result<()> {
        if self.inode != inode {
            return Err(OrfsError::InvalidArgument(format!(
                "generation {} is for inode {} not {inode}",
                self.generation, self.inode
            )));
        }
        if self.inode_version != inode_version {
            return Err(OrfsError::InvalidArgument(format!(
                "generation {} is for inode {inode} version {} not {inode_version}",
                self.generation, self.inode_version
            )));
        }
        if self.root != root {
            return Err(OrfsError::InvalidArgument(format!(
                "generation {} is for root {} not {root}",
                self.generation, self.root
            )));
        }
        Ok(())
    }

    /// The logical length this generation serves.
    pub fn logical_len(&self) -> u64 {
        self.logical_end.saturating_sub(self.logical_start)
    }

    /// Whether this generation overlays a base generation (its `regions` are
    /// only the changed ranges).
    pub fn is_overlay(&self) -> bool {
        self.base_generation.is_some()
    }

    /// Whether this generation is a compact *flattened* region table: no base,
    /// with a complete region set out of its own top-level payload.
    pub fn is_flattened_table(&self) -> bool {
        self.base_generation.is_none() && !self.regions.is_empty()
    }

    /// Whether this generation is a plain self-contained full object (legacy
    /// schema-1 shape): one top-level payload covering the whole extent.
    pub fn is_plain_full(&self) -> bool {
        self.base_generation.is_none() && self.regions.is_empty()
    }

    /// Whether any part of this generation is served by region overlays (so it
    /// needs region resolution rather than a single top-level body).
    pub fn is_region_backed(&self) -> bool {
        !self.regions.is_empty() || self.base_generation.is_some()
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u32(MANIFEST_MAGIC);
        e.u32(self.schema);
        e.u64(self.generation);
        e.arr(&self.volume_uuid);
        e.u64(self.inode);
        e.u64(self.inode_version);
        e.u64(self.root);
        e.str(&self.backend);
        e.str(&self.ekbloom_version);
        e.str(&self.ekbloom_format);
        e.str(&self.profile);
        e.u8(self.profile_kind);
        e.u64(self.logical_start);
        e.u64(self.logical_end);
        e.u64(self.physical_start);
        e.u64(self.physical_end);
        e.opt_u32(self.interval);
        e.opt_u16(self.depth);
        e.opt_u32(self.region_bytes);
        e.u8(self.certification.code());
        e.str(&self.certification_method);
        e.str(&self.payload_rel_path);
        e.opt_arr16(self.ekbloom_object_id);
        e.arr(&self.payload_blake3);
        e.u64(self.visible_bytes);
        e.u64(self.physical_bytes);
        e.u64(self.concealed_bytes);
        e.u64(self.source_bytes);
        e.u32(self.components.len() as u32);
        for c in &self.components {
            e.str(&c.name);
            e.str(&c.kind);
            e.u64(c.bytes);
        }
        if self.schema >= 2 {
            match self.base_generation {
                Some(g) => {
                    e.u8(1);
                    e.u64(g);
                }
                None => e.u8(0),
            }
            match self.base_manifest_blake3 {
                Some(d) => {
                    e.u8(1);
                    e.arr(&d);
                }
                None => e.u8(0),
            }
            e.u16(self.overlay_depth);
            e.u32(self.regions.len() as u32);
            for r in &self.regions {
                e.u64(r.logical_start);
                e.u64(r.logical_end);
                e.u64(r.owner_generation);
                e.u64(r.payload_offset);
                e.str(&r.payload_rel_path);
                e.arr(&r.payload_blake3);
                e.u64(r.visible_bytes);
                e.u64(r.physical_bytes);
                e.u8(r.profile_kind);
                e.u8(r.certification);
                e.opt_arr16(r.ekbloom_object_id);
            }
        }
        e.0
    }

    /// Recompute the self-digest over the canonical fields.
    pub fn compute_digest(&self) -> [u8; 32] {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    /// Finish an in-construction manifest by computing its self-digest.
    pub fn sealed(mut self) -> GenerationManifest {
        self.manifest_blake3 = self.compute_digest();
        self
    }

    /// The full canonical byte encoding (canonical fields + self-digest).
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.canonical_bytes();
        bytes.extend_from_slice(&self.manifest_blake3);
        bytes
    }

    /// Decode and fully validate a manifest document.
    pub fn decode(bytes: &[u8]) -> Result<GenerationManifest> {
        let mut d = Dec::new(bytes);
        if d.u32()? != MANIFEST_MAGIC {
            return Err(OrfsError::Corrupt("generation manifest bad magic".into()));
        }
        let schema = d.u32()?;
        let generation = d.u64()?;
        let volume_uuid = d.arr16()?;
        let inode = d.u64()?;
        let inode_version = d.u64()?;
        let root = d.u64()?;
        let backend = d.string()?;
        let ekbloom_version = d.string()?;
        let ekbloom_format = d.string()?;
        let profile = d.string()?;
        let profile_kind = d.u8()?;
        let logical_start = d.u64()?;
        let logical_end = d.u64()?;
        let physical_start = d.u64()?;
        let physical_end = d.u64()?;
        let interval = d.opt_u32()?;
        let depth = d.opt_u16()?;
        let region_bytes = d.opt_u32()?;
        let certification = CertificationState::from_code(d.u8()?)?;
        let certification_method = d.string()?;
        let payload_rel_path = d.string()?;
        let ekbloom_object_id = d.opt_arr16()?;
        let payload_blake3 = d.arr32()?;
        let visible_bytes = d.u64()?;
        let physical_bytes = d.u64()?;
        let concealed_bytes = d.u64()?;
        let source_bytes = d.u64()?;
        let component_count = d.u32()? as usize;
        let mut components = Vec::with_capacity(component_count.min(1024));
        for _ in 0..component_count {
            let name = d.string()?;
            let kind = d.string()?;
            let bytes = d.u64()?;
            components.push(ManifestComponent { name, kind, bytes });
        }
        let mut base_generation = None;
        let mut base_manifest_blake3 = None;
        let mut overlay_depth = 0u16;
        let mut regions = Vec::new();
        if schema >= 2 {
            base_generation = if d.u8()? != 0 { Some(d.u64()?) } else { None };
            base_manifest_blake3 = if d.u8()? != 0 { Some(d.arr32()?) } else { None };
            overlay_depth = d.u16()?;
            let region_count = d.u32()? as usize;
            if region_count > 1_000_000 {
                return Err(OrfsError::Corrupt(
                    "generation manifest region count is implausible".into(),
                ));
            }
            regions.reserve(region_count.min(4096));
            for _ in 0..region_count {
                regions.push(ManifestRegion {
                    logical_start: d.u64()?,
                    logical_end: d.u64()?,
                    owner_generation: d.u64()?,
                    payload_offset: d.u64()?,
                    payload_rel_path: d.string()?,
                    payload_blake3: d.arr32()?,
                    visible_bytes: d.u64()?,
                    physical_bytes: d.u64()?,
                    profile_kind: d.u8()?,
                    certification: d.u8()?,
                    ekbloom_object_id: d.opt_arr16()?,
                });
            }
        }
        let digest_at = d.pos;
        let stored = d.arr32()?;
        if d.remaining() != 0 {
            return Err(OrfsError::Corrupt(
                "generation manifest has trailing bytes".into(),
            ));
        }
        let manifest = GenerationManifest {
            schema,
            generation,
            volume_uuid,
            inode,
            inode_version,
            root,
            backend,
            ekbloom_version,
            ekbloom_format,
            profile,
            profile_kind,
            logical_start,
            logical_end,
            physical_start,
            physical_end,
            interval,
            depth,
            region_bytes,
            certification,
            certification_method,
            payload_rel_path,
            ekbloom_object_id,
            payload_blake3,
            visible_bytes,
            physical_bytes,
            concealed_bytes,
            source_bytes,
            components,
            base_generation,
            base_manifest_blake3,
            overlay_depth,
            regions,
            manifest_blake3: stored,
        };
        let computed = *blake3::hash(&bytes[..digest_at]).as_bytes();
        if computed != stored {
            return Err(OrfsError::Corrupt(
                "generation manifest self-digest mismatch".into(),
            ));
        }
        Ok(manifest)
    }

    /// A human/JSON-friendly view (hex digests, no binary blobs).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": self.schema,
            "generation": self.generation,
            "volume_uuid": hex(&self.volume_uuid),
            "inode": self.inode,
            "inode_version": self.inode_version,
            "root": self.root,
            "backend": self.backend,
            "ekbloom_version": self.ekbloom_version,
            "ekbloom_format": self.ekbloom_format,
            "profile": self.profile,
            "profile_kind": self.profile_kind,
            "logical_range": [self.logical_start, self.logical_end],
            "physical_range": [self.physical_start, self.physical_end],
            "parameters": {
                "interval": self.interval,
                "depth": self.depth,
                "region_bytes": self.region_bytes,
            },
            "certification": {
                "state": self.certification.name(),
                "method": self.certification_method,
            },
            "payload": self.payload_rel_path,
            "ekbloom_object_id": self.ekbloom_object_id.map(|a| hex(&a)),
            "payload_blake3": hex(&self.payload_blake3),
            "manifest_blake3": hex(&self.manifest_blake3),
            "visible_bytes": self.visible_bytes,
            "physical_bytes": self.physical_bytes,
            "concealed_bytes": self.concealed_bytes,
            "source_bytes": self.source_bytes,
            "overlay": {
                "base_generation": self.base_generation,
                "base_manifest_blake3": self.base_manifest_blake3.map(|a| hex(&a)),
                "overlay_depth": self.overlay_depth,
                "region_count": self.regions.len(),
                "regions": self.regions.iter().map(|r| serde_json::json!({
                    "logical_range": [r.logical_start, r.logical_end],
                    "owner_generation": r.owner_generation,
                    "payload_offset": r.payload_offset,
                    "payload": r.payload_rel_path,
                    "payload_blake3": hex(&r.payload_blake3),
                    "visible_bytes": r.visible_bytes,
                    "physical_bytes": r.physical_bytes,
                    "profile_kind": r.profile_kind,
                    "certification": r.certification,
                })).collect::<Vec<_>>(),
            },
            "components": self.components.iter().map(|c| serde_json::json!({
                "name": c.name, "kind": c.kind, "bytes": c.bytes,
            })).collect::<Vec<_>>(),
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
// The construction backend
// ---------------------------------------------------------------------------

/// The parameters handed to a [`ManifestationBuilder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildSpec {
    pub profile: ManifestationProfile,
    pub logical_start: u64,
    pub logical_end: u64,
}

/// What a builder produced, as reported by the codec (not the file length).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltPayload {
    /// Bytes the codec counts as manifested.
    pub physical_bytes: u64,
    /// Bytes revealed (visible to a consumer).
    pub visible_bytes: u64,
    /// The EKBLOOM content-derived object identity.
    pub object_id: Option<[u8; 16]>,
    /// Certification state.
    pub certification: CertificationState,
    /// The method that established the certification state.
    pub certification_method: String,
    /// Per-component accounting.
    pub components: Vec<ManifestComponent>,
}

/// A pluggable payload constructor. `io_uring` is deliberately not used here:
/// construction is CPU work (research §20).
pub trait ManifestationBuilder: Send + Sync {
    /// The backend name recorded in the manifest.
    fn backend(&self) -> &'static str;

    /// Build the physical payload for `source` at `dest` and report its
    /// accounting. `dest`'s parent directory exists; the builder may write a
    /// sibling temporary file and rename it atomically.
    fn build(&self, source: &[u8], spec: &BuildSpec, dest: &Path) -> Result<BuiltPayload>;
}

/// The production builder: real EKBLOOM construction (`create` + `write_body`).
///
/// The EKBLOOM crate is consumed unchanged as a rev-pinned git dependency;
/// its state machinery is never reimplemented here.
pub struct EkbloomBuilder;

impl EkbloomBuilder {
    pub fn new() -> EkbloomBuilder {
        EkbloomBuilder
    }
}

impl Default for EkbloomBuilder {
    fn default() -> Self {
        EkbloomBuilder::new()
    }
}

impl ManifestationBuilder for EkbloomBuilder {
    fn backend(&self) -> &'static str {
        "ekbloom"
    }

    fn build(&self, source: &[u8], spec: &BuildSpec, dest: &Path) -> Result<BuiltPayload> {
        let body = ekbloom::create(source, spec.profile.to_ekbloom())?;
        ekbloom::write_body(dest, &body)?;
        let report = ekbloom::inspect(&body);

        use ekbloom::Certification;
        let certification = if body
            .certificates
            .iter()
            .any(|c| c.status == Certification::Rejected)
        {
            CertificationState::Rejected
        } else if body
            .certificates
            .iter()
            .any(|c| c.status == Certification::Certified)
        {
            CertificationState::Certified
        } else if body.blooms.is_empty() && body.history.is_none() && body.checkpoints.is_empty() {
            CertificationState::Unmanifested
        } else if body.blooms.is_empty() {
            CertificationState::Built
        } else {
            CertificationState::Unverified
        };
        let certification_method = if body.blooms.is_empty() {
            "structural".to_string()
        } else {
            "ekbloom-bloom-certification".to_string()
        };

        Ok(BuiltPayload {
            physical_bytes: report.physical_bytes,
            visible_bytes: report.visible_bytes,
            object_id: Some(body.object_id),
            certification,
            certification_method,
            components: report
                .components
                .into_iter()
                .map(|c| ManifestComponent {
                    name: c.name,
                    kind: c.kind,
                    bytes: c.bytes,
                })
                .collect(),
        })
    }
}

// ---------------------------------------------------------------------------
// The generation store
// ---------------------------------------------------------------------------

/// A recovery outcome over the manifest directory.
#[derive(Debug, Clone)]
pub struct ManifestRecovery {
    /// Every valid committed generation discovered, ascending by generation.
    pub generations: Vec<GenerationManifest>,
    /// The number of manifests that failed validation and were skipped.
    pub rejected: usize,
    /// Whether the `HEAD` advertisement was present and used for discovery.
    pub head_used: bool,
    /// Whether `HEAD` was missing or torn (discovery fell back to a scan).
    pub head_fallback: bool,
}

impl ManifestRecovery {
    /// The newest valid generation for each inode (by version, then generation).
    pub fn newest_per_inode(&self) -> BTreeMap<u64, GenerationManifest> {
        let mut out: BTreeMap<u64, GenerationManifest> = BTreeMap::new();
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

/// The on-disk generation store rooted at `<volume>/.or_bloom`.
#[derive(Debug, Clone)]
pub struct GenerationStore {
    volume_root: PathBuf,
    bloom_root: PathBuf,
}

impl GenerationStore {
    /// The store for a volume backing directory.
    pub fn new(volume_root: &Path) -> GenerationStore {
        GenerationStore {
            volume_root: volume_root.to_path_buf(),
            bloom_root: volume_root.join(BLOOM_DIR),
        }
    }

    /// The volume backing directory.
    pub fn volume_root(&self) -> &Path {
        &self.volume_root
    }

    /// The `.or_bloom/` directory.
    pub fn bloom_root(&self) -> &Path {
        &self.bloom_root
    }

    /// The payload directory (`ekbloom/`).
    pub fn payload_dir(&self) -> PathBuf {
        self.bloom_root.join(EKBLOOM_DIR)
    }

    /// The manifest directory (`manifests/`).
    pub fn manifest_dir(&self) -> PathBuf {
        self.bloom_root.join(MANIFEST_DIR)
    }

    /// The `HEAD` advertisement path.
    pub fn head_path(&self) -> PathBuf {
        self.manifest_dir().join("HEAD")
    }

    /// Create the payload and manifest directories (idempotent).
    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(self.payload_dir())?;
        fs::create_dir_all(self.manifest_dir())?;
        Ok(())
    }

    /// The payload path for a generation (relative to the volume root).
    pub fn payload_rel_path(&self, generation: u64, inode: u64, version: u64, root: u64) -> String {
        format!("{BLOOM_DIR}/{EKBLOOM_DIR}/{inode}-v{version}-r{root}-g{generation}.ekb")
    }

    /// The absolute payload path for a generation.
    pub fn payload_path(&self, generation: u64, inode: u64, version: u64, root: u64) -> PathBuf {
        self.volume_root
            .join(self.payload_rel_path(generation, inode, version, root))
    }

    /// The payload path for one changed region of a generation (relative to the
    /// volume root). Region payloads are distinct files so a small write never
    /// rewrites the whole-object payload.
    pub fn region_payload_rel_path(
        &self,
        generation: u64,
        inode: u64,
        version: u64,
        root: u64,
        index: usize,
    ) -> String {
        format!("{BLOOM_DIR}/{EKBLOOM_DIR}/{inode}-v{version}-r{root}-g{generation}-x{index}.ekb")
    }

    /// The absolute payload path for one changed region of a generation.
    pub fn region_payload_path(
        &self,
        generation: u64,
        inode: u64,
        version: u64,
        root: u64,
        index: usize,
    ) -> PathBuf {
        self.volume_root
            .join(self.region_payload_rel_path(generation, inode, version, root, index))
    }

    fn manifest_path(&self, generation: u64) -> PathBuf {
        self.manifest_dir()
            .join(format!("{generation:020}.manifest"))
    }

    /// The set of generation numbers with a manifest file on disk.
    pub fn manifest_generations(&self) -> Result<Vec<u64>> {
        let mut out = Vec::new();
        let dir = self.manifest_dir();
        let entries = match fs::read_dir(&dir) {
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

    /// The next unused generation number (`max + 1`).
    pub fn next_generation(&self) -> Result<u64> {
        let max = self.manifest_generations()?.into_iter().max();
        Ok(max.map(|m| m + 1).unwrap_or(1))
    }

    /// Load and fully validate one generation manifest by number.
    pub fn load_generation(&self, generation: u64) -> Result<Option<GenerationManifest>> {
        let path = self.manifest_path(generation);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match GenerationManifest::decode(&bytes) {
            Ok(m) => Ok(Some(m)),
            Err(_) => Ok(None),
        }
    }

    /// Validate a manifest's payload against its recorded BLAKE3, if the payload
    /// is present. An absent payload is *not* an error during recovery; it is
    /// reported by the caller and the generation is treated as present-but-torn.
    ///
    /// A region-backed generation has no top-level payload body: every region
    /// payload (and, because a flattened table reuses them, their referenced
    /// files) must be present and match its recorded digest.
    pub fn payload_matches(&self, m: &GenerationManifest) -> Result<bool> {
        if !m.payload_rel_path.is_empty() {
            return self.file_matches(&m.payload_rel_path, &m.payload_blake3);
        }
        // No top-level payload: a region-backed generation.
        if m.regions.is_empty() {
            // A pure overlay (e.g. a shrink or a metadata-only change) reuses its
            // base entirely; it has no payload of its own, so its validity is the
            // base's and is established by the chain check in `recover`.
            return Ok(m.base_generation.is_some());
        }
        for r in &m.regions {
            if !self.file_matches(&r.payload_rel_path, &r.payload_blake3)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether the file at `rel` (relative to the volume root) is present and has
    /// the given BLAKE3 digest.
    fn file_matches(&self, rel: &str, digest: &[u8; 32]) -> Result<bool> {
        let path = self.volume_root.join(rel);
        let mut f = match File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(*hasher.finalize().as_bytes() == *digest)
    }

    /// Every payload file a generation references (its top-level payload, if any,
    /// plus each region payload). Used by the orphan sweep.
    pub fn referenced_payloads(m: &GenerationManifest) -> Vec<String> {
        let mut out = Vec::new();
        if !m.payload_rel_path.is_empty() {
            out.push(m.payload_rel_path.clone());
        }
        for r in &m.regions {
            if !r.payload_rel_path.is_empty() {
                out.push(r.payload_rel_path.clone());
            }
        }
        out
    }

    /// Publish a generation: write the manifest, fsync, rename, fsync the
    /// directory, then advertise it in `HEAD`.
    ///
    /// Torn writes are safe: the manifest is immutable and self-validating, and
    /// `HEAD` is only a discovery index. A failure before the rename leaves a
    /// `.tmp` file that is ignored; a failure after it leaves a committed
    /// manifest that a later `HEAD` update will advertise.
    pub fn publish(&self, manifest: &GenerationManifest) -> Result<()> {
        self.ensure_dirs()?;
        let final_path = self.manifest_path(manifest.generation);
        let tmp_path = final_path.with_extension("manifest.tmp");
        {
            let mut f = File::create(&tmp_path)?;
            f.write_all(&manifest.encode())?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &final_path)?;
        fsync_dir(&self.manifest_dir())?;

        // Advertise: update HEAD with the union of the existing list and this
        // generation. A torn HEAD is recovered by a full scan.
        let mut gens = self.read_head().unwrap_or_default();
        gens.push(manifest.generation);
        gens.sort_unstable();
        gens.dedup();
        self.write_head(&gens)?;
        Ok(())
    }

    /// Read the advertised generation numbers, if `HEAD` is present and valid.
    pub fn read_head(&self) -> Option<Vec<u64>> {
        let bytes = fs::read(self.head_path()).ok()?;
        decode_head(&bytes)
    }

    /// Write the `HEAD` advertisement atomically.
    pub fn write_head(&self, generations: &[u64]) -> Result<()> {
        self.ensure_dirs()?;
        let path = self.head_path();
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&encode_head(generations))?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &path)?;
        fsync_dir(&self.manifest_dir())?;
        Ok(())
    }

    /// Recover the committed generation set.
    ///
    /// Discovery prefers `HEAD`; if it is missing or torn, every `*.manifest` is
    /// scanned. Each candidate is validated (self-digest, schema, payload BLAKE3
    /// when the payload is present); invalid candidates are skipped and never
    /// invalidate earlier commits.
    pub fn recover(&self) -> Result<ManifestRecovery> {
        let head = self.read_head();
        let all = self.manifest_generations()?;
        let (candidates, head_used, head_fallback) = match &head {
            Some(list) => {
                let mut merged: Vec<u64> = list.clone();
                for g in &all {
                    if !merged.contains(g) {
                        merged.push(*g);
                    }
                }
                merged.sort_unstable();
                merged.dedup();
                (merged, true, false)
            }
            None => (all, false, true),
        };

        let mut accepted: BTreeMap<u64, GenerationManifest> = BTreeMap::new();
        let mut rejected = 0usize;
        // Process ascending so a generation's base is validated before it is.
        // An overlay is accepted only if its base generation is present, valid,
        // for the same inode, and digest-bound; otherwise the overlay is skipped
        // and a strictly earlier commit remains selected (crash safety).
        let mut ordered = candidates;
        ordered.sort_unstable();
        ordered.dedup();
        for gen in ordered {
            match self.load_generation(gen)? {
                Some(m) => {
                    if !self.payload_matches(&m).unwrap_or(false) {
                        rejected += 1;
                        continue;
                    }
                    if m.overlay_depth > MAX_OVERLAY_DEPTH {
                        rejected += 1;
                        continue;
                    }
                    let accepted_ok = match m.base_generation {
                        Some(bg) => accepted.get(&bg).is_some_and(|b| {
                            b.inode == m.inode
                                && m.base_manifest_blake3
                                    .is_none_or(|d| d == b.manifest_blake3)
                                && m.overlay_depth == b.overlay_depth.saturating_add(1)
                        }),
                        None => m.overlay_depth == 0,
                    };
                    if accepted_ok {
                        accepted.insert(m.generation, m);
                    } else {
                        rejected += 1;
                    }
                }
                None => rejected += 1,
            }
        }
        let mut generations: Vec<GenerationManifest> = accepted.into_values().collect();
        generations.sort_by_key(|m| m.generation);
        Ok(ManifestRecovery {
            generations,
            rejected,
            head_used,
            head_fallback,
        })
    }

    /// The total on-disk bytes of committed payloads under `ekbloom/`.
    pub fn committed_payload_bytes(&self) -> u64 {
        dir_bytes(&self.payload_dir())
    }

    /// Remove orphan payloads: `.ekb` files referenced by no committed manifest.
    ///
    /// This is the disposable-structure retention policy: only *uncommitted*
    /// physical tail is reclaimed. Committed generations are never removed here.
    pub fn sweep_orphans(&self) -> Result<u64> {
        let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
        for m in self.recover()?.generations {
            for rel in GenerationStore::referenced_payloads(&m) {
                referenced.insert(rel);
            }
        }
        let mut removed = 0u64;
        let dir = self.payload_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy().to_string();
            if !name.ends_with(".ekb") {
                continue;
            }
            let rel = format!("{BLOOM_DIR}/{EKBLOOM_DIR}/{name}");
            if !referenced.contains(&rel) {
                let path = entry.path();
                if let Ok(meta) = entry.metadata() {
                    removed += meta.len();
                }
                let _ = fs::remove_file(&path);
            }
        }
        Ok(removed)
    }
}

fn encode_head(generations: &[u64]) -> Vec<u8> {
    let mut e = Enc::new();
    e.u32(HEAD_MAGIC);
    e.u32(MANIFEST_SCHEMA);
    e.u32(generations.len() as u32);
    for g in generations {
        e.u64(*g);
    }
    e.0
}

fn decode_head(bytes: &[u8]) -> Option<Vec<u64>> {
    let mut d = Dec::new(bytes);
    if d.u32().ok()? != HEAD_MAGIC || d.u32().ok()? != MANIFEST_SCHEMA {
        return None;
    }
    let count = d.u32().ok()? as usize;
    // Every generation is an 8-byte u64, so a declared count that exceeds the
    // remaining input is corrupt; enforce before allocating (research §28).
    if count > 1_000_000 || count > d.remaining() / 8 {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(d.u64().ok()?);
    }
    if d.remaining() != 0 {
        return None;
    }
    Some(out)
}

/// The total byte length of every regular file beneath `dir` (recursive).
///
/// Implemented with an explicit worklist rather than call-stack recursion, and
/// it never follows symbolic links nor descends into the same directory twice.
/// A concealer scanning a backing directory that an adversary has populated with
/// a symlink loop or an extremely deep tree therefore cannot cause unbounded
/// recursion or allocation (research §28, no uncontrolled recursion; §29 warns
/// that the backing store may be less trusted than the logical mount).
pub fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack: Vec<PathBuf> = vec![dir.to_path_buf()];
    let mut visited: HashSet<(u64, u64)> = HashSet::new();
    while let Some(cur) = stack.pop() {
        // Refuse to walk the same physical directory twice (bounded by the real
        // tree, not by a hostile link graph).
        if let Ok(md) = fs::symlink_metadata(&cur) {
            use std::os::unix::fs::MetadataExt;
            if !visited.insert((md.dev(), md.ino())) {
                continue;
            }
        }
        let entries = match fs::read_dir(&cur) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            // `file_type` does not follow the link, so a symlink (even a loop, or
            // one pointing outside `dir`) is never treated as a directory to
            // descend into.
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file() {
                if let Ok(md) = entry.metadata() {
                    total = total.saturating_add(md.len());
                }
            }
        }
    }
    total
}

// ---------------------------------------------------------------------------
// Published state (shared with the namespace engine)
// ---------------------------------------------------------------------------

/// A version-qualified summary of an inode's newest published generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestSummary {
    pub inode: u64,
    pub inode_version: u64,
    pub generation: u64,
    pub profile: String,
    pub physical_bytes: u64,
    pub concealed_bytes: u64,
    pub logical_bytes: u64,
}

/// The published-generation index, shared between the engine and the namespace.
pub struct ManifestationState {
    store: GenerationStore,
    uuid: [u8; 16],
    published: RwLock<BTreeMap<u64, GenerationManifest>>,
}

impl ManifestationState {
    /// Recover the published set from disk.
    pub fn recover(store: GenerationStore, uuid: [u8; 16]) -> Result<Arc<ManifestationState>> {
        let recovery = store.recover()?;
        let state = ManifestationState {
            store,
            uuid,
            published: RwLock::new(recovery.newest_per_inode()),
        };
        Ok(Arc::new(state))
    }

    /// The generation store.
    pub fn store(&self) -> &GenerationStore {
        &self.store
    }

    /// The owning volume UUID.
    pub fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    /// Every currently published generation (newest per inode).
    pub fn published(&self) -> Vec<GenerationManifest> {
        self.published.read().values().cloned().collect()
    }

    /// Total published manifested payload bytes.
    pub fn manifested_bytes_total(&self) -> u64 {
        self.published
            .read()
            .values()
            .map(|m| m.physical_bytes)
            .sum()
    }

    /// The number of published generations (newest per inode).
    pub fn generation_count(&self) -> u64 {
        self.published.read().len() as u64
    }

    /// The newest published generation for an inode, if any.
    pub fn latest_for(&self, inode: u64) -> Option<GenerationManifest> {
        self.published.read().get(&inode).cloned()
    }

    /// A version-qualified summary: `Some` only when a generation exists for
    /// *exactly* this inode version (I6). A mismatched version yields `None`.
    pub fn summary(&self, inode: u64, inode_version: u64) -> Option<ManifestSummary> {
        let guard = self.published.read();
        let m = guard.get(&inode)?;
        if m.inode_version != inode_version {
            return None;
        }
        Some(ManifestSummary {
            inode,
            inode_version,
            generation: m.generation,
            profile: m.profile.clone(),
            physical_bytes: m.physical_bytes,
            concealed_bytes: m.concealed_bytes,
            logical_bytes: m.logical_len(),
        })
    }

    fn record_published(&self, manifest: GenerationManifest) {
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

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// Configuration for the manifestation engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestationConfig {
    /// Worker threads; `0` selects `available_parallelism()`.
    pub workers: usize,
    /// Bounded job-queue capacity (backpressure).
    pub queue_capacity: usize,
    /// Whether the caller waits for the generation before acknowledging a write.
    pub synchronous: bool,
    /// The profile applied to newly enqueued jobs.
    pub profile: ManifestationProfile,
    /// Objects larger than this are not captured for manifestation.
    pub max_source_bytes: u64,
}

impl Default for ManifestationConfig {
    fn default() -> Self {
        ManifestationConfig {
            workers: 0,
            queue_capacity: 64,
            synchronous: false,
            profile: ManifestationProfile::Bloom { depth: 4 },
            max_source_bytes: 16 * 1024 * 1024,
        }
    }
}

/// A truthful report of what the engine engaged.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ManifestationEngineReport {
    pub workers: usize,
    pub queue_capacity: usize,
    pub synchronous: bool,
    pub profile: String,
    pub backend: String,
    pub ekbloom_version: String,
    pub recovered_generations: u64,
    pub recovered_rejected: usize,
}

/// How a job concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestationStatus {
    /// A committed generation was published.
    Published,
    /// The job was cancelled before it committed.
    Canceled,
    /// A newer inode version superseded the job.
    Superseded,
    /// The structure was not built (empty or oversized source).
    Skipped,
    /// Construction or publication failed.
    Failed,
}

impl ManifestationStatus {
    pub const fn name(self) -> &'static str {
        match self {
            ManifestationStatus::Published => "published",
            ManifestationStatus::Canceled => "canceled",
            ManifestationStatus::Superseded => "superseded",
            ManifestationStatus::Skipped => "skipped",
            ManifestationStatus::Failed => "failed",
        }
    }
}

/// The outcome of one manifestation job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestationOutcome {
    pub inode: u64,
    pub inode_version: u64,
    pub status: ManifestationStatus,
    pub generation: Option<u64>,
    pub physical_bytes: u64,
    pub profile: String,
    pub detail: Option<String>,
    /// Authoritative *changed* bytes the job had to build (Phase 22).
    pub changed_bytes: u64,
    /// Wall-clock nanoseconds spent constructing payloads (Phase 22).
    pub build_nanos: u64,
    /// Number of newly manifested regions in this generation.
    pub regions: usize,
    /// The committed overlay depth (0 for a self-contained generation).
    pub overlay_depth: u16,
    /// Whether this generation is a flattened readable view.
    pub flattened: bool,
    /// Authoritative bytes reused from the base (logical length minus changed).
    pub reused_bytes: u64,
}

impl ManifestationOutcome {
    fn new(
        inode: u64,
        inode_version: u64,
        profile: ManifestationProfile,
        status: ManifestationStatus,
        detail: Option<String>,
    ) -> Self {
        ManifestationOutcome {
            inode,
            inode_version,
            status,
            generation: None,
            physical_bytes: 0,
            profile: profile.label(),
            detail,
            changed_bytes: 0,
            build_nanos: 0,
            regions: 0,
            overlay_depth: 0,
            flattened: false,
            reused_bytes: 0,
        }
    }
}

/// One changed region handed to an incremental job: the authoritative bytes of
/// `[logical_start, logical_start + data.len())` at the committed root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionInput {
    pub logical_start: u64,
    pub data: Vec<u8>,
}

/// What a job must build.
#[derive(Debug, Clone)]
pub enum JobContent {
    /// A self-contained base over the whole logical object.
    Full { source: Vec<u8> },
    /// Only the changed regions; everything else is reused from `base`.
    Incremental { regions: Vec<RegionInput> },
}

/// A job request: the identity, plus either the full authoritative source or the
/// authoritative changed ranges and the base generation to overlay.
#[derive(Debug, Clone)]
pub struct JobSpec {
    pub inode: u64,
    pub inode_version: u64,
    pub root: u64,
    pub profile: ManifestationProfile,
    /// The logical length the resulting generation must cover.
    pub logical_len: u64,
    /// The base generation for an incremental job (I6-qualified by the engine).
    pub base: Option<u64>,
    /// Force a flattened readable view even if the depth cap is not reached.
    pub flatten: bool,
    pub content: JobContent,
}

impl JobSpec {
    /// A self-contained full-base job over the whole object.
    pub fn full(
        inode: u64,
        inode_version: u64,
        root: u64,
        profile: ManifestationProfile,
        source: Vec<u8>,
    ) -> JobSpec {
        let logical_len = source.len() as u64;
        JobSpec {
            inode,
            inode_version,
            root,
            profile,
            logical_len,
            base: None,
            flatten: false,
            content: JobContent::Full { source },
        }
    }

    /// An incremental job overlaying `base` with the given changed regions.
    #[allow(clippy::too_many_arguments)]
    pub fn incremental(
        inode: u64,
        inode_version: u64,
        root: u64,
        profile: ManifestationProfile,
        logical_len: u64,
        base: u64,
        regions: Vec<RegionInput>,
        flatten: bool,
    ) -> JobSpec {
        JobSpec {
            inode,
            inode_version,
            root,
            profile,
            logical_len,
            base: Some(base),
            flatten,
            content: JobContent::Incremental { regions },
        }
    }

    /// Whether this job is an incremental overlay.
    pub fn is_incremental(&self) -> bool {
        matches!(self.content, JobContent::Incremental { .. })
    }

    /// The authoritative source bytes this job was handed (empty when the job is
    /// incremental).
    pub fn source_bytes(&self) -> &[u8] {
        match &self.content {
            JobContent::Full { source } => source,
            JobContent::Incremental { .. } => &[],
        }
    }
}

/// The queue was full; the optional construction was refused (not an error on
/// the authoritative path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

impl std::fmt::Display for QueueFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "manifestation queue is full")
    }
}

impl std::error::Error for QueueFull {}

/// Cumulative engine statistics.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct EngineStats {
    pub submitted: u64,
    pub dropped_full: u64,
    pub published: u64,
    pub canceled: u64,
    pub superseded: u64,
    pub skipped: u64,
    pub failed: u64,
}

struct JobShared {
    inode: u64,
    inode_version: u64,
    cancel: AtomicBool,
    completed: Mutex<Option<ManifestationOutcome>>,
    cond: Condvar,
}

impl JobShared {
    fn new(inode: u64, inode_version: u64) -> JobShared {
        JobShared {
            inode,
            inode_version,
            cancel: AtomicBool::new(false),
            completed: Mutex::new(None),
            cond: Condvar::new(),
        }
    }

    fn finish(&self, outcome: ManifestationOutcome) {
        *self.completed.lock() = Some(outcome);
        self.cond.notify_all();
    }
}

/// A handle to an asynchronously submitted job.
pub struct JobHandle {
    shared: Arc<JobShared>,
}

impl JobHandle {
    /// The job's inode identity.
    pub fn inode(&self) -> u64 {
        self.shared.inode
    }

    /// The job's inode version.
    pub fn inode_version(&self) -> u64 {
        self.shared.inode_version
    }

    /// Request cancellation. If construction has not yet committed, the
    /// generation is discarded and never becomes visible.
    pub fn cancel(&self) {
        self.shared.cancel.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    pub fn is_canceled(&self) -> bool {
        self.shared.cancel.load(Ordering::SeqCst)
    }

    /// Wait up to `timeout` for the job to conclude.
    pub fn wait(&self, timeout: Duration) -> Option<ManifestationOutcome> {
        let deadline = Instant::now() + timeout;
        let mut slot = self.shared.completed.lock();
        loop {
            if let Some(o) = slot.clone() {
                return Some(o);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            self.shared.cond.wait_for(&mut slot, deadline - now);
        }
    }

    /// Whether the job has concluded.
    pub fn is_done(&self) -> bool {
        self.shared.completed.lock().is_some()
    }
}

struct QueuedJob {
    spec: JobSpec,
    shared: Arc<JobShared>,
}

struct EngineInner {
    store: GenerationStore,
    uuid: [u8; 16],
    builder: Arc<dyn ManifestationBuilder>,
    cfg: ManifestationConfig,
    workers: usize,
    queue: Mutex<VecDeque<QueuedJob>>,
    not_empty: Condvar,
    not_full: Condvar,
    shutdown: AtomicBool,
    next_generation: Mutex<u64>,
    latest: Mutex<HashMap<u64, u64>>,
    in_flight: AtomicUsize,
    idle: Condvar,
    state: Arc<ManifestationState>,
    stats: Mutex<EngineStats>,
}

impl EngineInner {
    fn is_superseded(&self, inode: u64, version: u64) -> bool {
        self.latest.lock().get(&inode).is_some_and(|v| *v > version)
    }

    fn alloc_generation(&self) -> u64 {
        let mut g = self.next_generation.lock();
        let v = *g;
        *g = v + 1;
        v
    }

    fn note_version(&self, inode: u64, version: u64) {
        let mut latest = self.latest.lock();
        let e = latest.entry(inode).or_insert(0);
        if *e < version {
            *e = version;
        }
    }

    fn bump(&self, f: impl FnOnce(&mut EngineStats)) {
        f(&mut self.stats.lock());
    }

    fn bump_outcome(&self, outcome: &ManifestationOutcome) {
        self.bump(|s| match outcome.status {
            ManifestationStatus::Published => s.published += 1,
            ManifestationStatus::Canceled => s.canceled += 1,
            ManifestationStatus::Superseded => s.superseded += 1,
            ManifestationStatus::Skipped => s.skipped += 1,
            ManifestationStatus::Failed => s.failed += 1,
        });
    }

    /// Construct and publish one generation on the calling thread.
    fn execute(&self, spec: &JobSpec, shared: &JobShared) -> ManifestationOutcome {
        if shared.cancel.load(Ordering::SeqCst) {
            return ManifestationOutcome::new(
                spec.inode,
                spec.inode_version,
                spec.profile,
                ManifestationStatus::Canceled,
                None,
            );
        }
        self.publish_spec(spec, shared)
    }

    fn publish_spec(&self, spec: &JobSpec, shared: &JobShared) -> ManifestationOutcome {
        match &spec.content {
            JobContent::Full { source } => self.publish_full(spec, source, shared),
            JobContent::Incremental { regions } => self.publish_incremental(spec, regions, shared),
        }
    }

    /// Build and publish a self-contained full-base generation (the Phase-7
    /// behaviour, still used for the first manifestation of an object and by the
    /// explicit `manifest_eligible` path).
    fn publish_full(
        &self,
        spec: &JobSpec,
        source: &[u8],
        shared: &JobShared,
    ) -> ManifestationOutcome {
        let started = Instant::now();
        let generation = self.alloc_generation();
        let rel =
            self.store
                .payload_rel_path(generation, spec.inode, spec.inode_version, spec.root);
        let dest = self
            .store
            .payload_path(generation, spec.inode, spec.inode_version, spec.root);
        let build_spec = BuildSpec {
            profile: spec.profile,
            logical_start: 0,
            logical_end: source.len() as u64,
        };

        let built = match self.builder.build(source, &build_spec, &dest) {
            Ok(b) => b,
            Err(e) => {
                let _ = fs::remove_file(&dest);
                return ManifestationOutcome::new(
                    spec.inode,
                    spec.inode_version,
                    spec.profile,
                    ManifestationStatus::Failed,
                    Some(e.to_string()),
                );
            }
        };

        if shared.cancel.load(Ordering::SeqCst)
            || self.is_superseded(spec.inode, spec.inode_version)
        {
            let _ = fs::remove_file(&dest);
            let status = if shared.cancel.load(Ordering::SeqCst) {
                ManifestationStatus::Canceled
            } else {
                ManifestationStatus::Superseded
            };
            return ManifestationOutcome::new(
                spec.inode,
                spec.inode_version,
                spec.profile,
                status,
                None,
            );
        }

        let (payload_blake3, file_len) = match hash_file(&dest) {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_file(&dest);
                return ManifestationOutcome::new(
                    spec.inode,
                    spec.inode_version,
                    spec.profile,
                    ManifestationStatus::Failed,
                    Some(e.to_string()),
                );
            }
        };

        let (interval, depth, region_bytes) = spec.profile.params();
        let build_nanos = started.elapsed().as_nanos() as u64;
        let manifest = GenerationManifest {
            schema: MANIFEST_SCHEMA,
            generation,
            volume_uuid: self.uuid,
            inode: spec.inode,
            inode_version: spec.inode_version,
            root: spec.root,
            backend: self.builder.backend().to_string(),
            ekbloom_version: EKBLOOM_VERSION.to_string(),
            ekbloom_format: ekbloom_format_version(),
            profile: spec.profile.label(),
            profile_kind: spec.profile.kind_code(),
            logical_start: 0,
            logical_end: source.len() as u64,
            physical_start: 0,
            physical_end: file_len,
            interval,
            depth,
            region_bytes,
            certification: built.certification,
            certification_method: built.certification_method.clone(),
            payload_rel_path: rel,
            ekbloom_object_id: built.object_id,
            payload_blake3,
            visible_bytes: built.visible_bytes.min(file_len),
            physical_bytes: file_len,
            concealed_bytes: file_len.saturating_sub(built.visible_bytes),
            source_bytes: source.len() as u64,
            components: built.components.clone(),
            base_generation: None,
            base_manifest_blake3: None,
            overlay_depth: 0,
            regions: Vec::new(),
            manifest_blake3: [0u8; 32],
        }
        .sealed();

        if let Err(e) = self.store.publish(&manifest) {
            return ManifestationOutcome::new(
                spec.inode,
                spec.inode_version,
                spec.profile,
                ManifestationStatus::Failed,
                Some(e.to_string()),
            );
        }
        self.state.record_published(manifest);

        let mut outcome = ManifestationOutcome::new(
            spec.inode,
            spec.inode_version,
            spec.profile,
            ManifestationStatus::Published,
            None,
        );
        outcome.generation = Some(generation);
        outcome.physical_bytes = file_len;
        outcome.changed_bytes = source.len() as u64;
        outcome.build_nanos = build_nanos;
        outcome.reused_bytes = 0;
        outcome
    }

    /// Build and publish an incremental generation (Phase 22): build payloads for
    /// only the changed regions, reuse the base for every other byte, and either
    /// publish a compact overlay or (adaptively) a flattened readable view.
    fn publish_incremental(
        &self,
        spec: &JobSpec,
        regions: &[RegionInput],
        shared: &JobShared,
    ) -> ManifestationOutcome {
        let started = Instant::now();
        let generation = self.alloc_generation();
        let base_gen = match spec.base {
            Some(g) => g,
            None => {
                return ManifestationOutcome::new(
                    spec.inode,
                    spec.inode_version,
                    spec.profile,
                    ManifestationStatus::Failed,
                    Some("incremental job has no base generation".into()),
                )
            }
        };
        let base = match self.store.load_generation(base_gen) {
            Ok(Some(m)) => m,
            _ => {
                return ManifestationOutcome::new(
                    spec.inode,
                    spec.inode_version,
                    spec.profile,
                    ManifestationStatus::Failed,
                    Some(format!("base generation {base_gen} is missing or invalid")),
                )
            }
        };
        if base.inode != spec.inode {
            return ManifestationOutcome::new(
                spec.inode,
                spec.inode_version,
                spec.profile,
                ManifestationStatus::Failed,
                Some(format!(
                    "base generation {base_gen} is for a different inode"
                )),
            );
        }

        // Build one payload per changed region. Construction cost is proportional
        // to the changed bytes, never to the unchanged object size.
        let mut built_regions: Vec<ManifestRegion> = Vec::with_capacity(regions.len());
        let mut changed_bytes = 0u64;
        for (idx, r) in regions.iter().enumerate() {
            if r.data.is_empty() {
                continue;
            }
            let rel = self.store.region_payload_rel_path(
                generation,
                spec.inode,
                spec.inode_version,
                spec.root,
                idx,
            );
            let dest = self.store.region_payload_path(
                generation,
                spec.inode,
                spec.inode_version,
                spec.root,
                idx,
            );
            let build_spec = BuildSpec {
                profile: spec.profile,
                logical_start: r.logical_start,
                logical_end: r.logical_start + r.data.len() as u64,
            };
            let built = match self.builder.build(&r.data, &build_spec, &dest) {
                Ok(b) => b,
                Err(e) => {
                    for region in &built_regions {
                        let _ = fs::remove_file(
                            self.store.volume_root().join(&region.payload_rel_path),
                        );
                    }
                    let _ = fs::remove_file(&dest);
                    return ManifestationOutcome::new(
                        spec.inode,
                        spec.inode_version,
                        spec.profile,
                        ManifestationStatus::Failed,
                        Some(e.to_string()),
                    );
                }
            };
            let (payload_blake3, file_len) = match hash_file(&dest) {
                Ok(v) => v,
                Err(e) => {
                    let _ = fs::remove_file(&dest);
                    return ManifestationOutcome::new(
                        spec.inode,
                        spec.inode_version,
                        spec.profile,
                        ManifestationStatus::Failed,
                        Some(e.to_string()),
                    );
                }
            };
            changed_bytes += r.data.len() as u64;
            built_regions.push(ManifestRegion {
                logical_start: r.logical_start,
                logical_end: r.logical_start + r.data.len() as u64,
                owner_generation: generation,
                payload_offset: 0,
                payload_rel_path: rel,
                payload_blake3,
                visible_bytes: built.visible_bytes.min(file_len),
                physical_bytes: file_len,
                profile_kind: spec.profile.kind_code(),
                certification: built.certification.code(),
                ekbloom_object_id: built.object_id,
            });
        }

        // Cancellation / supersession after construction: discard every region
        // payload; nothing is committed.
        if shared.cancel.load(Ordering::SeqCst)
            || self.is_superseded(spec.inode, spec.inode_version)
        {
            for region in &built_regions {
                let _ = fs::remove_file(self.store.volume_root().join(&region.payload_rel_path));
            }
            let status = if shared.cancel.load(Ordering::SeqCst) {
                ManifestationStatus::Canceled
            } else {
                ManifestationStatus::Superseded
            };
            return ManifestationOutcome::new(
                spec.inode,
                spec.inode_version,
                spec.profile,
                status,
                None,
            );
        }

        let build_nanos = started.elapsed().as_nanos() as u64;
        let would_depth = base.overlay_depth.saturating_add(1);
        let flatten = spec.flatten
            || would_depth > MAX_OVERLAY_DEPTH
            || base.overlay_depth >= FLATTEN_AFTER_OVERLAYS;

        let manifest = if flatten {
            // Adaptive flattening: materialize a complete region table over the
            // whole object. This is index-only (it references the base's existing
            // payloads; it does not rebuild unchanged bytes), and it resets the
            // overlay depth to 0 so a read resolves in a single hop.
            let table = match resolve_coverage(&self.store, &base) {
                Ok(t) => t,
                Err(e) => {
                    for region in &built_regions {
                        let _ = fs::remove_file(
                            self.store.volume_root().join(&region.payload_rel_path),
                        );
                    }
                    return ManifestationOutcome::new(
                        spec.inode,
                        spec.inode_version,
                        spec.profile,
                        ManifestationStatus::Failed,
                        Some(e.to_string()),
                    );
                }
            };
            let mut merged = table;
            for r in &built_regions {
                merged = overwrite_region(&merged, r);
            }
            let merged = clip_and_merge(merged, 0, spec.logical_len);
            let visible: u64 = merged.iter().map(|r| r.visible_bytes).sum();
            let physical: u64 = merged.iter().map(|r| r.physical_bytes).sum();
            GenerationManifest {
                schema: MANIFEST_SCHEMA,
                generation,
                volume_uuid: self.uuid,
                inode: spec.inode,
                inode_version: spec.inode_version,
                root: spec.root,
                backend: self.builder.backend().to_string(),
                ekbloom_version: EKBLOOM_VERSION.to_string(),
                ekbloom_format: ekbloom_format_version(),
                profile: format!("flattened({})", spec.profile.label()),
                profile_kind: spec.profile.kind_code(),
                logical_start: 0,
                logical_end: spec.logical_len,
                physical_start: 0,
                physical_end: 0,
                interval: spec.profile.params().0,
                depth: spec.profile.params().1,
                region_bytes: spec.profile.params().2,
                certification: aggregate_certification(&merged),
                certification_method: "incremental-flattened-table".to_string(),
                payload_rel_path: String::new(),
                ekbloom_object_id: None,
                payload_blake3: [0u8; 32],
                visible_bytes: visible.min(physical),
                physical_bytes: physical,
                concealed_bytes: physical.saturating_sub(visible),
                source_bytes: spec.logical_len,
                components: Vec::new(),
                base_generation: None,
                base_manifest_blake3: None,
                overlay_depth: 0,
                regions: merged,
                manifest_blake3: [0u8; 32],
            }
            .sealed()
        } else {
            let visible: u64 = built_regions.iter().map(|r| r.visible_bytes).sum();
            let physical: u64 = built_regions.iter().map(|r| r.physical_bytes).sum();
            GenerationManifest {
                schema: MANIFEST_SCHEMA,
                generation,
                volume_uuid: self.uuid,
                inode: spec.inode,
                inode_version: spec.inode_version,
                root: spec.root,
                backend: self.builder.backend().to_string(),
                ekbloom_version: EKBLOOM_VERSION.to_string(),
                ekbloom_format: ekbloom_format_version(),
                profile: format!("incremental({})", spec.profile.label()),
                profile_kind: spec.profile.kind_code(),
                logical_start: 0,
                logical_end: spec.logical_len,
                physical_start: 0,
                physical_end: 0,
                interval: spec.profile.params().0,
                depth: spec.profile.params().1,
                region_bytes: spec.profile.params().2,
                certification: aggregate_certification(&built_regions),
                certification_method: "incremental-overlay".to_string(),
                payload_rel_path: String::new(),
                ekbloom_object_id: None,
                payload_blake3: [0u8; 32],
                visible_bytes: visible.min(physical),
                physical_bytes: physical,
                concealed_bytes: physical.saturating_sub(visible),
                source_bytes: changed_bytes,
                components: Vec::new(),
                base_generation: Some(base_gen),
                base_manifest_blake3: Some(base.manifest_blake3),
                overlay_depth: would_depth,
                regions: built_regions.clone(),
                manifest_blake3: [0u8; 32],
            }
            .sealed()
        };

        if let Err(e) = self.store.publish(&manifest) {
            return ManifestationOutcome::new(
                spec.inode,
                spec.inode_version,
                spec.profile,
                ManifestationStatus::Failed,
                Some(e.to_string()),
            );
        }
        self.state.record_published(manifest.clone());

        let mut outcome = ManifestationOutcome::new(
            spec.inode,
            spec.inode_version,
            spec.profile,
            ManifestationStatus::Published,
            None,
        );
        outcome.generation = Some(generation);
        outcome.physical_bytes = manifest.physical_bytes;
        outcome.changed_bytes = changed_bytes;
        outcome.build_nanos = build_nanos;
        outcome.regions = built_regions.len();
        outcome.overlay_depth = manifest.overlay_depth;
        outcome.flattened = flatten;
        outcome.reused_bytes = spec.logical_len.saturating_sub(changed_bytes);
        outcome
    }
}

/// The EKBLOOM on-disk format version (`major.minor`).
pub fn ekbloom_format_version() -> String {
    format!(
        "{}.{}",
        ekbloom::format::FORMAT_MAJOR,
        ekbloom::format::FORMAT_MINOR
    )
}

/// Resolve a committed generation to a *complete* sorted region table over its
/// logical extent (Phase 22, bounded-depth lookup).
///
/// The table is produced by walking the overlay chain (at most
/// [`MAX_OVERLAY_DEPTH`] hops, each base manifest digest-verified and inode-
/// qualified) down to a self-contained base or flattened table, then applying
/// each generation's changed regions newest-wins. This is the compact, verified
/// indirection a reader uses: it never walks an unbounded chain and never
/// trusts an unverified base.
pub fn resolve_coverage(
    store: &GenerationStore,
    manifest: &GenerationManifest,
) -> Result<Vec<ManifestRegion>> {
    let mut changes: Vec<Vec<ManifestRegion>> = Vec::new();
    let mut cur = manifest.clone();
    let mut hops: u32 = 0;
    let base_table: Vec<ManifestRegion> = loop {
        match cur.base_generation {
            Some(bg) => {
                changes.push(cur.regions.clone());
                hops += 1;
                if hops > u32::from(MAX_OVERLAY_DEPTH) {
                    return Err(OrfsError::Corrupt(
                        "overlay indirection exceeds the depth bound".into(),
                    ));
                }
                let bm = store.load_generation(bg)?.ok_or_else(|| {
                    OrfsError::Corrupt(format!("overlay base generation {bg} is missing"))
                })?;
                if bm.inode != manifest.inode {
                    return Err(OrfsError::Corrupt(
                        "overlay base generation is for a different inode".into(),
                    ));
                }
                if let Some(d) = cur.base_manifest_blake3 {
                    if d != bm.manifest_blake3 {
                        return Err(OrfsError::Corrupt(
                            "overlay base manifest digest mismatch".into(),
                        ));
                    }
                }
                cur = bm;
            }
            None => {
                if cur.regions.is_empty() {
                    break vec![ManifestRegion {
                        logical_start: cur.logical_start,
                        logical_end: cur.logical_end,
                        owner_generation: cur.generation,
                        payload_offset: 0,
                        payload_rel_path: cur.payload_rel_path.clone(),
                        payload_blake3: cur.payload_blake3,
                        visible_bytes: cur.visible_bytes,
                        physical_bytes: cur.physical_bytes,
                        profile_kind: cur.profile_kind,
                        certification: cur.certification.code(),
                        ekbloom_object_id: cur.ekbloom_object_id,
                    }];
                } else {
                    break cur.regions.clone();
                }
            }
        }
    };
    // Apply the changed ranges oldest-first, so the newest overlay wins on any
    // (unusual) overlap.
    let mut table = base_table;
    for ch in changes.into_iter().rev() {
        for r in &ch {
            table = overwrite_region(&table, r);
        }
    }
    Ok(clip_and_merge(
        table,
        manifest.logical_start,
        manifest.logical_end,
    ))
}

/// Carve `ch`'s logical range out of `table` and insert `ch` in its place.
fn overwrite_region(table: &[ManifestRegion], ch: &ManifestRegion) -> Vec<ManifestRegion> {
    let mut out: Vec<ManifestRegion> = Vec::with_capacity(table.len() + 1);
    for r in table {
        if r.logical_end <= ch.logical_start || r.logical_start >= ch.logical_end {
            out.push(r.clone());
        } else {
            if r.logical_start < ch.logical_start {
                let mut lo = r.clone();
                lo.logical_end = ch.logical_start;
                out.push(lo);
            }
            if r.logical_end > ch.logical_end {
                let mut hi = r.clone();
                hi.payload_offset = r.payload_offset + (ch.logical_end - r.logical_start);
                hi.logical_start = ch.logical_end;
                out.push(hi);
            }
        }
    }
    out.push(ch.clone());
    out.sort_by_key(|r| r.logical_start);
    out
}

/// Clip a region table to `[start, end)` and coalesce contiguous runs that map
/// onto the same payload (so the compact table keeps read hops small).
fn clip_and_merge(mut table: Vec<ManifestRegion>, start: u64, end: u64) -> Vec<ManifestRegion> {
    let mut out: Vec<ManifestRegion> = Vec::with_capacity(table.len());
    for mut r in table.drain(..) {
        if r.logical_end <= start || r.logical_start >= end {
            continue;
        }
        if r.logical_start < start {
            r.payload_offset += start - r.logical_start;
            r.logical_start = start;
        }
        if r.logical_end > end {
            r.logical_end = end;
        }
        if r.logical_start >= r.logical_end {
            continue;
        }
        out.push(r);
    }
    out.sort_by_key(|r| r.logical_start);
    let mut merged: Vec<ManifestRegion> = Vec::with_capacity(out.len());
    for r in out {
        if let Some(last) = merged.last_mut() {
            let contiguous = last.logical_end == r.logical_start
                && last.payload_offset + (last.logical_end - last.logical_start)
                    == r.payload_offset;
            if last.payload_rel_path == r.payload_rel_path
                && last.payload_blake3 == r.payload_blake3
                && contiguous
            {
                last.logical_end = r.logical_end;
                continue;
            }
        }
        merged.push(r);
    }
    merged
}

/// The aggregate certification of a region set (conservative).
fn aggregate_certification(regions: &[ManifestRegion]) -> CertificationState {
    if regions.is_empty() {
        return CertificationState::Built;
    }
    let mut any_unverified = false;
    let mut any_real = false;
    for r in regions {
        match CertificationState::from_code(r.certification) {
            Ok(CertificationState::Rejected) => return CertificationState::Rejected,
            Ok(CertificationState::Certified) => any_real = true,
            Ok(CertificationState::Unverified) => {
                any_unverified = true;
                any_real = true;
            }
            _ => {}
        }
    }
    if any_unverified {
        CertificationState::Unverified
    } else if any_real {
        CertificationState::Certified
    } else {
        CertificationState::Built
    }
}

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

/// The asynchronous, version-qualified manifestation engine.
pub struct ManifestationEngine {
    inner: Arc<EngineInner>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    state: Arc<ManifestationState>,
}

impl ManifestationEngine {
    /// Recover the published set and start a bounded worker pool.
    pub fn start(
        store: GenerationStore,
        uuid: [u8; 16],
        builder: Arc<dyn ManifestationBuilder>,
        cfg: ManifestationConfig,
    ) -> Result<(Arc<ManifestationEngine>, ManifestationEngineReport)> {
        store.ensure_dirs()?;
        let recovery = store.recover()?;
        let recovered_generations = recovery.generations.len() as u64;
        let recovered_rejected = recovery.rejected;
        let state = Arc::new(ManifestationState {
            store: store.clone(),
            uuid,
            published: RwLock::new(recovery.newest_per_inode()),
        });
        let next_generation = store.next_generation()?;
        let workers = if cfg.workers == 0 {
            thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
        } else {
            cfg.workers
        }
        .max(1);

        let inner = Arc::new(EngineInner {
            store,
            uuid,
            builder,
            cfg: cfg.clone(),
            workers,
            queue: Mutex::new(VecDeque::new()),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
            shutdown: AtomicBool::new(false),
            next_generation: Mutex::new(next_generation),
            latest: Mutex::new(HashMap::new()),
            in_flight: AtomicUsize::new(0),
            idle: Condvar::new(),
            state: state.clone(),
            stats: Mutex::new(EngineStats::default()),
        });

        let mut handles = Vec::with_capacity(workers);
        for i in 0..workers {
            let inner = inner.clone();
            let handle = thread::Builder::new()
                .name(format!("orfs-manifest-{i}"))
                .spawn(move || worker_loop(inner))
                .map_err(OrfsError::Io)?;
            handles.push(handle);
        }

        let report = ManifestationEngineReport {
            workers,
            queue_capacity: cfg.queue_capacity,
            synchronous: cfg.synchronous,
            profile: cfg.profile.label(),
            backend: inner.builder.backend().to_string(),
            ekbloom_version: EKBLOOM_VERSION.to_string(),
            recovered_generations,
            recovered_rejected,
        };
        Ok((
            Arc::new(ManifestationEngine {
                inner,
                workers: Mutex::new(handles),
                state,
            }),
            report,
        ))
    }

    /// The shared published-generation state.
    pub fn state(&self) -> Arc<ManifestationState> {
        self.state.clone()
    }

    /// The active configuration.
    pub fn config(&self) -> &ManifestationConfig {
        &self.inner.cfg
    }

    /// Record that an inode advanced to `version`, superseding any older pending
    /// job for that inode (research §10.3).
    pub fn note_committed_version(&self, inode: u64, version: u64) {
        self.inner.note_version(inode, version);
    }

    /// Enqueue a job. Returns [`QueueFull`] when the bounded queue is full; in
    /// that case the optional construction is dropped and the caller proceeds.
    pub fn submit(&self, spec: JobSpec) -> std::result::Result<JobHandle, QueueFull> {
        let shared = Arc::new(JobShared::new(spec.inode, spec.inode_version));
        let mut queue = self.inner.queue.lock();
        if queue.len() >= self.inner.cfg.queue_capacity {
            drop(queue);
            self.inner.bump(|s| s.dropped_full += 1);
            return Err(QueueFull);
        }
        // Supersede older pending jobs for this inode.
        self.inner.note_version(spec.inode, spec.inode_version);
        for job in queue.iter() {
            if job.spec.inode == spec.inode && job.spec.inode_version < spec.inode_version {
                job.shared.cancel.store(true, Ordering::SeqCst);
            }
        }
        queue.push_back(QueuedJob {
            spec,
            shared: shared.clone(),
        });
        self.inner.bump(|s| s.submitted += 1);
        self.inner.not_empty.notify_one();
        Ok(JobHandle { shared })
    }

    /// Submit and wait for the job to conclude (bounded by `timeout` in total).
    pub fn submit_blocking(
        &self,
        spec: JobSpec,
        timeout: Duration,
    ) -> Option<ManifestationOutcome> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.submit(spec.clone()) {
                Ok(handle) => return handle.wait(timeout),
                Err(QueueFull) => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    /// Build and publish a generation synchronously on the calling thread. This
    /// is the explicit synchronous path (a caller that opts in waits for the
    /// optional construction).
    pub fn publish_now(&self, spec: JobSpec) -> ManifestationOutcome {
        self.inner.note_version(spec.inode, spec.inode_version);
        let shared = JobShared::new(spec.inode, spec.inode_version);
        let outcome = self.inner.execute(&spec, &shared);
        self.inner.bump_outcome(&outcome);
        outcome
    }

    /// Cumulative statistics.
    pub fn stats(&self) -> EngineStats {
        self.inner.stats.lock().clone()
    }

    /// Whether the queue is empty and no job is in flight.
    pub fn is_idle(&self) -> bool {
        self.inner.queue.lock().is_empty() && self.inner.in_flight.load(Ordering::SeqCst) == 0
    }

    /// Wait until the queue is drained and workers are idle, or `timeout` elapses.
    pub fn wait_idle(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.is_idle() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Sweep orphan payloads referenced by no committed generation.
    pub fn sweep_orphans(&self) -> Result<u64> {
        self.inner.store.sweep_orphans()
    }

    /// The number of worker threads.
    pub fn worker_count(&self) -> usize {
        self.inner.workers
    }

    fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        {
            let _guard = self.inner.queue.lock();
            self.inner.not_empty.notify_all();
            self.inner.not_full.notify_all();
        }
        let mut workers = self.workers.lock();
        for h in workers.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for ManifestationEngine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn worker_loop(inner: Arc<EngineInner>) {
    loop {
        let job = {
            let mut queue = inner.queue.lock();
            while queue.is_empty() {
                if inner.shutdown.load(Ordering::SeqCst) {
                    return;
                }
                inner.not_empty.wait(&mut queue);
            }
            match queue.pop_front() {
                Some(j) => {
                    inner.not_full.notify_one();
                    j
                }
                None => continue,
            }
        };
        inner.in_flight.fetch_add(1, Ordering::SeqCst);
        let outcome = inner.execute(&job.spec, &job.shared);
        inner.in_flight.fetch_sub(1, Ordering::SeqCst);
        {
            let q = inner.queue.lock();
            if q.is_empty() && inner.in_flight.load(Ordering::SeqCst) == 0 {
                inner.idle.notify_all();
            }
        }
        inner.bump_outcome(&outcome);
        job.shared.finish(outcome);
    }
}

// ---------------------------------------------------------------------------
// Canonical little-endian codecs (shared with the other concealed-structure
// modules; see `src/trigram.rs`)
// ---------------------------------------------------------------------------

pub(crate) struct Enc(Vec<u8>);

impl Enc {
    pub(crate) fn new() -> Enc {
        Enc(Vec::new())
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn arr(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }

    pub(crate) fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.arr(s.as_bytes());
    }

    fn opt_u16(&mut self, v: Option<u16>) {
        match v {
            Some(x) => {
                self.u8(1);
                self.u16(x);
            }
            None => self.u8(0),
        }
    }

    fn opt_u32(&mut self, v: Option<u32>) {
        match v {
            Some(x) => {
                self.u8(1);
                self.u32(x);
            }
            None => self.u8(0),
        }
    }

    fn opt_arr16(&mut self, v: Option<[u8; 16]>) {
        match v {
            Some(a) => {
                self.u8(1);
                self.arr(&a);
            }
            None => self.u8(0),
        }
    }
}

pub(crate) struct Dec<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Dec<'a> {
        Dec { b, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.b.len().saturating_sub(self.pos)
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(OrfsError::Overflow {
            what: "manifest decode",
        })?;
        if end > self.b.len() {
            return Err(OrfsError::Corrupt(
                "generation manifest is truncated".into(),
            ));
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    pub(crate) fn u64(&mut self) -> Result<u64> {
        let s = self.take(8)?;
        Ok(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    pub(crate) fn arr16(&mut self) -> Result<[u8; 16]> {
        let s = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub(crate) fn arr32(&mut self) -> Result<[u8; 32]> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub(crate) fn string(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| OrfsError::Corrupt("manifest string is not UTF-8".into()))
    }

    pub(crate) fn opt_u16(&mut self) -> Result<Option<u16>> {
        Ok(if self.u8()? != 0 {
            Some(self.u16()?)
        } else {
            None
        })
    }

    pub(crate) fn opt_u32(&mut self) -> Result<Option<u32>> {
        Ok(if self.u8()? != 0 {
            Some(self.u32()?)
        } else {
            None
        })
    }

    pub(crate) fn opt_arr16(&mut self) -> Result<Option<[u8; 16]>> {
        Ok(if self.u8()? != 0 {
            Some(self.arr16()?)
        } else {
            None
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> GenerationManifest {
        GenerationManifest {
            schema: MANIFEST_SCHEMA,
            generation: 7,
            volume_uuid: [1u8; 16],
            inode: 42,
            inode_version: 3,
            root: 1000,
            backend: "ekbloom".into(),
            ekbloom_version: EKBLOOM_VERSION.into(),
            ekbloom_format: "0.3".into(),
            profile: "bloom(D=4)".into(),
            profile_kind: 4,
            logical_start: 0,
            logical_end: 512,
            physical_start: 0,
            physical_end: 2048,
            interval: None,
            depth: Some(4),
            region_bytes: None,
            certification: CertificationState::Certified,
            certification_method: "ekbloom-bloom-certification".into(),
            payload_rel_path: ".or_bloom/ekbloom/42-v3-r1000-g7.ekb".into(),
            ekbloom_object_id: Some([9u8; 16]),
            payload_blake3: [2u8; 32],
            visible_bytes: 512,
            physical_bytes: 2048,
            concealed_bytes: 1536,
            source_bytes: 512,
            components: vec![ManifestComponent {
                name: "core".into(),
                kind: "core".into(),
                bytes: 512,
            }],
            base_generation: None,
            base_manifest_blake3: None,
            overlay_depth: 0,
            regions: Vec::new(),
            manifest_blake3: [0u8; 32],
        }
        .sealed()
    }

    #[test]
    fn manifest_round_trips_and_detects_tamper() {
        let m = sample_manifest();
        let bytes = m.encode();
        let back = GenerationManifest::decode(&bytes).unwrap();
        assert_eq!(m, back);
        let mut bad = bytes.clone();
        bad[40] ^= 0xFF;
        assert!(GenerationManifest::decode(&bad).is_err());
        // truncation
        assert!(GenerationManifest::decode(&bytes[..bytes.len() - 3]).is_err());
    }

    #[test]
    fn version_qualification_is_exact() {
        let m = sample_manifest();
        assert!(m.usable_for(42, 3, 1000).is_ok());
        assert!(m.usable_for(42, 4, 1000).is_err());
        assert!(m.usable_for(43, 3, 1000).is_err());
        assert!(m.usable_for(42, 3, 1001).is_err());
    }

    #[test]
    fn head_round_trips() {
        let bytes = encode_head(&[3, 1, 2]);
        assert_eq!(decode_head(&bytes), Some(vec![3, 1, 2]));
        assert_eq!(decode_head(&bytes[..bytes.len() - 1]), None);
    }

    #[test]
    fn profiles_parse_and_map() {
        assert_eq!(
            ManifestationProfile::parse("bloom4", None, None, None).unwrap(),
            ManifestationProfile::Bloom { depth: 4 }
        );
        assert_eq!(
            ManifestationProfile::parse("bloom8", None, None, None).unwrap(),
            ManifestationProfile::Bloom { depth: 8 }
        );
        assert_eq!(
            ManifestationProfile::parse("sparse", None, Some(64), None).unwrap(),
            ManifestationProfile::Sparse { interval: 64 }
        );
        assert!(ManifestationProfile::parse("nope", None, None, None).is_err());
        assert_eq!(
            ManifestationProfile::MaxSpeed.label(),
            ManifestationProfile::MaxSpeed.to_ekbloom().label()
        );
    }
}
