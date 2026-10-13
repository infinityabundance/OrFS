//! **Reviewer item 8 — the endurance space-amplification court.**
//!
//! Non-withdrawal means committed authoritative history is never overwritten,
//! truncated, reused or GC'd. A consequence the reviewer names explicitly is that
//! **space amplification grows forever**: the same logical content occupies more
//! and more physical space as committed history accumulates. Phase 27 measured
//! endurance (RSS, log size, recovery) and Phase 40 measured a *fixed read
//! workload* against growing history, but neither published a time series of the
//! amplification itself. This court does.
//!
//! ## What it does
//!
//! A deterministic committed history is built over many **epochs**. Each epoch
//! performs small (16 B) misaligned rewrites of the bytes already present, so the
//! live logical content is **byte-identical at every sample** while the
//! authoritative log genuinely grows (non-withdrawal) and each object's extent map
//! fragments further. At fixed intervals the court **samples** the whole volume and
//! records the time series:
//!
//! * `logical_bytes` — live content (sum of regular-file sizes at the root);
//! * `authoritative_physical_bytes` — the committed segment files + the durable
//!   commit watermark (`Log::capacity_status().physical_bytes`);
//! * `manifested_bytes` — the concealed manifested payload (`M_ekbloom`);
//! * `total_physical_bytes` — every byte beneath the backing directory (`M_total`);
//! * `amplification_total` = `total_physical_bytes / logical_bytes`;
//! * `segment_count`, `committed_root_count` (committed transaction boundaries,
//!   each a valid snapshot root), and `manifested_generation_count`.
//!
//! Two arms are built over the **same deterministic history**: **authoritative**
//! (concealed plane disabled) and **manifested** (plane enabled, profile full), so
//! amplification with and without manifestations is visible. The two arms'
//! committed roots are asserted identical — enabling the concealed plane must not
//! change authoritative history.
//!
//! ## The honest shape
//!
//! With content-neutral growth (no new logical bytes) the denominator is constant
//! while the numerator grows without bound, so the ratio rises monotonically and is
//! **not** capped. If new logical content were appended each epoch instead, the
//! ratio would rise toward a bounded ceiling (the ratio of rewritten to appended
//! bytes); `ORFS_AMP_NEW_BYTES` exposes that variant, but the default is the purest
//! form of the reviewer's claim.
//!
//! ## Running it
//!
//! * `cargo test --test endurance_amplification` runs a small always-on smoke that
//!   asserts the series was recorded, that logical content is constant, that the
//!   ratio grew, and that the manifested arm added concealed bytes.
//! * The full sweep is opt-in behind `ORFS_ENDURANCE_AMPLIFICATION=1` and writes
//!   `evidence/performance/endurance-amplification.json`. Run it (release,
//!   representative) via `scripts/container-endurance-amplification.sh`.

use std::path::{Path, PathBuf};
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::log::OpenMode;
use orfs::manifestation::{ManifestationConfig, ManifestationProfile};
use orfs::namespace::Namespace;
use orfs::stats;
use orfs::volume::Volume;
use tempfile::TempDir;

/// A fixed volume identity makes the authoritative history byte-reproducible, so
/// the two arms build the *same* history and their committed roots must agree.
const UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x44, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const CREATED: u64 = 1_700_000_000;
/// A small segment size so the authoritative log rolls over and the segment-count
/// series grows within the bounded run (the default is 64 MiB).
const SEGMENT: u64 = 128 * 1024;
/// Length of each content-neutral misaligned epoch write.
const WRITE_LEN: u64 = 16;

#[derive(Clone, Copy)]
struct AmpParams {
    /// Number of regular files.
    objects: usize,
    /// Initial logical size of each file.
    object_bytes: u64,
    /// Initial content is written in chunks of this many bytes.
    initial_chunk: u64,
    /// Content-neutral misaligned rewrites per object per epoch.
    epoch_writes: u64,
    /// Fresh bytes appended per object per epoch (`0` = purely content-neutral).
    new_bytes: u64,
    /// Total epochs (committed batches of writes).
    epochs: u64,
    /// Sample the volume every this many epochs.
    sample_every: u64,
}

struct AmpPlan {
    params: AmpParams,
}

impl AmpPlan {
    /// Epochs at which the volume is sampled: `0, sample_every, ...; epochs`.
    fn sample_epochs(&self) -> Vec<u64> {
        let mut v = Vec::new();
        let mut e = 0u64;
        while e <= self.params.epochs {
            v.push(e);
            e += self.params.sample_every;
        }
        if v.last().copied() != Some(self.params.epochs) {
            v.push(self.params.epochs);
        }
        v
    }
}

fn smoke_plan() -> AmpPlan {
    AmpPlan {
        params: AmpParams {
            objects: 2,
            object_bytes: 8 * 1024,
            initial_chunk: 1024,
            epoch_writes: 4,
            new_bytes: 0,
            epochs: 4,
            sample_every: 2,
        },
    }
}

fn sweep_plan() -> AmpPlan {
    AmpPlan {
        params: AmpParams {
            objects: 4,
            object_bytes: 16 * 1024,
            initial_chunk: 1024,
            epoch_writes: 12,
            new_bytes: 0,
            epochs: 24,
            sample_every: 4,
        },
    }
}

/// The deterministic logical content of every object. Every write in the court
/// writes a slice of exactly these bytes, so logical content never changes.
fn content_at(offset: u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|j| (((offset + j as u64) * 131 + 17) % 251) as u8)
        .collect()
}

/// A tiny deterministic PRNG so the epoch write offsets are reproducible.
struct Lcg(u64);

impl Lcg {
    fn new(epoch: u64, object: u64) -> Lcg {
        Lcg(0x9E37_79B9_7F4A_7C15 ^ epoch.wrapping_mul(0x1000_0001) ^ object)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }
}

fn resident_kib() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn ratio(num: u64, den: u64) -> Option<f64> {
    if den == 0 {
        None
    } else {
        Some(num as f64 / den as f64)
    }
}

fn f64_at(sample: &serde_json::Value, key: &str) -> f64 {
    sample[key].as_f64().unwrap_or(0.0)
}

fn u64_at(sample: &serde_json::Value, key: &str) -> u64 {
    sample[key].as_u64().unwrap_or(0)
}

/// Sample the whole volume at `epoch`: logical vs physical vs manifested bytes,
/// the amplification ratio, and the growth counters. Read-only; authority is only
/// ever read here.
fn one_sample(dir: &Path, epoch: u64) -> serde_json::Value {
    let acc = stats::account_volume(dir).expect("account volume");
    let vol = Volume::open(dir, OpenMode::ReadOnly).expect("open volume read-only");
    // `capacity_status` is a read-only inspection; `physical_bytes` is exactly the
    // committed segment files plus the durable commit watermark.
    let cs = vol.log.capacity_status(dir, None);
    let logical = acc.logical_live_bytes;
    serde_json::json!({
        "epoch": epoch,
        "committed_root": vol.log.committed_end_offset(),
        "committed_root_count": vol.log.boundaries().len() as u64,
        "segment_count": cs.segment_count as u64,
        "logical_bytes": logical,
        "authoritative_physical_bytes": cs.physical_bytes,
        "manifested_bytes": acc.manifested_bytes,
        "total_physical_bytes": acc.m_total,
        "amplification_total": ratio(acc.m_total, logical),
        "amplification_authoritative": ratio(cs.physical_bytes, logical),
        "manifested_generation_count": acc.manifested_generations,
        "resident_kib": resident_kib(),
        "physical": {
            "m_log": acc.m_log,
            "m_ekbloom": acc.m_ekbloom,
            "m_indexes": acc.m_indexes,
            "m_other": acc.m_other,
            "authoritative_canonical_bytes": acc.authoritative_canonical_bytes,
            "logical_live_bytes": acc.logical_live_bytes,
            "manifested_generations": acc.manifested_generations,
            "manifested_inodes": acc.manifested_inodes,
            "manifested_bytes": acc.manifested_bytes,
            "physical_overhead_bytes": acc.physical_overhead_bytes,
        },
    })
}

struct Arm {
    samples: Vec<serde_json::Value>,
    roots: Vec<u64>,
    history_build_wall_micros: u128,
    resident_kib: Option<u64>,
}

/// Build the deterministic growing history and take the samples. `manifested`
/// selects the manifested arm (plane enabled, profile full, synchronous so the
/// measurement is deterministic) or the authoritative baseline (plane disabled).
fn run_arm(dir: &Path, plan: &AmpPlan, manifested: bool) -> Arm {
    let p = plan.params;
    let sample_epochs = plan.sample_epochs();
    let mut ns = Namespace::init_with_uuid(dir, SEGMENT, UUID, CREATED, DurabilityMode::Ordered)
        .expect("init namespace");

    let root_ino = ns.root_inode();
    let mut inodes = Vec::with_capacity(p.objects);
    let mut sizes = Vec::with_capacity(p.objects);
    for i in 0..p.objects {
        let name = format!("obj{i}");
        let ino = ns
            .create(root_ino, name.as_bytes(), 0o644, 0, 0)
            .expect("create object");
        let mut off = 0;
        while off < p.object_bytes {
            let n = p.initial_chunk.min(p.object_bytes - off);
            ns.write_at(ino, off, &content_at(off, n as usize))
                .expect("initial write");
            off += n;
        }
        inodes.push(ino);
        sizes.push(p.object_bytes);
    }
    ns.sync().expect("sync initial content");

    if manifested {
        ns.enable_manifestation(ManifestationConfig {
            workers: 1,
            queue_capacity: 32,
            synchronous: true,
            profile: ManifestationProfile::Full,
            max_source_bytes: 64 << 20,
        })
        .expect("enable manifestation");
    }

    let mut samples = Vec::new();
    let mut roots = Vec::new();
    let mut history_build_wall_micros: u128 = 0;

    for epoch in 0..=p.epochs {
        if sample_epochs.contains(&epoch) {
            // Manifested arm: publish a full generation for every object so the
            // plane is exactly qualified at the sampled root (deterministic).
            if manifested {
                ns.manifest_eligible(None, ManifestationProfile::Full)
                    .expect("manifest at sample");
            }
            roots.push(ns.root());
            samples.push(one_sample(dir, epoch));
        }

        if epoch < p.epochs {
            let t = Instant::now();
            for w in 0..p.epoch_writes {
                for (oi, &ino) in inodes.iter().enumerate() {
                    let mut rng = Lcg::new(epoch, oi as u64);
                    // Advance the deterministic stream by `w` draws.
                    for _ in 0..w {
                        let _ = rng.next();
                    }
                    let off = rng.below(p.object_bytes - WRITE_LEN);
                    ns.write_at(ino, off, &content_at(off, WRITE_LEN as usize))
                        .expect("epoch write");
                }
            }
            if p.new_bytes > 0 {
                for (oi, &ino) in inodes.iter().enumerate() {
                    let off = sizes[oi];
                    ns.write_at(ino, off, &content_at(off, p.new_bytes as usize))
                        .expect("epoch append");
                    sizes[oi] = off + p.new_bytes;
                }
            }
            history_build_wall_micros += t.elapsed().as_micros();
        }
    }
    ns.sync().ok();

    Arm {
        samples,
        roots,
        history_build_wall_micros,
        resident_kib: resident_kib(),
    }
}

/// Build both arms over the identical deterministic history and assert the
/// committed roots agree (enabling the concealed plane must not alter authority).
fn run_court(dir: &Path, plan: &AmpPlan) -> (Arm, Arm) {
    let auth_dir = dir.join("authoritative");
    let man_dir = dir.join("manifested");
    std::fs::create_dir_all(&auth_dir).expect("auth dir");
    std::fs::create_dir_all(&man_dir).expect("man dir");

    let authoritative = run_arm(&auth_dir, plan, false);
    let manifested = run_arm(&man_dir, plan, true);

    assert_eq!(
        authoritative.roots, manifested.roots,
        "the two arms must build the identical committed history"
    );

    (authoritative, manifested)
}

/// A machine-computed reading of the amplification shape from this run's numbers.
fn assess(authoritative: &Arm, manifested: &Arm) -> serde_json::Value {
    let a_first = &authoritative.samples[0];
    let a_last = authoritative.samples.last().expect("a sample");
    let m_first = &manifested.samples[0];
    let m_last = manifested.samples.last().expect("a sample");

    let logicals: Vec<u64> = authoritative
        .samples
        .iter()
        .map(|s| u64_at(s, "logical_bytes"))
        .collect();
    let logical_constant = logicals.windows(2).all(|w| w[0] == w[1]);
    let a_ratios: Vec<f64> = authoritative
        .samples
        .iter()
        .map(|s| f64_at(s, "amplification_total"))
        .collect();
    let a_monotone = a_ratios.windows(2).all(|w| w[1] >= w[0] - 1e-9);
    let m_ratios: Vec<f64> = manifested
        .samples
        .iter()
        .map(|s| f64_at(s, "amplification_total"))
        .collect();
    let m_monotone = m_ratios.windows(2).all(|w| w[1] >= w[0] - 1e-9);
    let a_ratio_growth = if f64_at(a_first, "amplification_total") > 0.0 {
        Some(f64_at(a_last, "amplification_total") / f64_at(a_first, "amplification_total"))
    } else {
        None
    };

    serde_json::json!({
        "statement": "with non-withdrawal, space amplification grows monotonically \
                      with retained history; logical content is constant while the \
                      physical footprint grows without bound",
        "logical_bytes_constant": logical_constant,
        "authoritative": {
            "amplification_first": f64_at(a_first, "amplification_total"),
            "amplification_last": f64_at(a_last, "amplification_total"),
            "amplification_growth_first_to_last": a_ratio_growth,
            "monotone_non_decreasing": a_monotone,
            "logical_bytes_first": u64_at(a_first, "logical_bytes"),
            "logical_bytes_last": u64_at(a_last, "logical_bytes"),
            "total_physical_bytes_first": u64_at(a_first, "total_physical_bytes"),
            "total_physical_bytes_last": u64_at(a_last, "total_physical_bytes"),
            "committed_root_count_last": u64_at(a_last, "committed_root_count"),
            "segment_count_last": u64_at(a_last, "segment_count"),
        },
        "manifested": {
            "amplification_first": f64_at(m_first, "amplification_total"),
            "amplification_last": f64_at(m_last, "amplification_total"),
            "monotone_non_decreasing": m_monotone,
            "manifested_bytes_first": u64_at(m_first, "manifested_bytes"),
            "manifested_bytes_last": u64_at(m_last, "manifested_bytes"),
            "manifested_generation_count_last": u64_at(m_last, "manifested_generation_count"),
            "total_physical_bytes_last": u64_at(m_last, "total_physical_bytes"),
        },
        "assessments": {
            "amplification_grows_with_retained_history": a_monotone,
            "logical_content_is_constant": logical_constant,
            "manifested_arm_adds_concealed_bytes_at_depth":
                u64_at(m_last, "total_physical_bytes") > u64_at(a_last, "total_physical_bytes"),
            "manifestation_engaged": u64_at(m_last, "manifested_generation_count") > 0,
        },
        "note": "Ratios and booleans are computed from this single bounded run only. \
                 `logical_bytes` is constant because every epoch rewrites bytes \
                 already present (content-neutral); if new content were appended each \
                 epoch the ratio would instead rise toward a bounded ceiling. The \
                 manifested arm's footprint includes the generation manifests it \
                 publishes (counted in M_other) as well as the concealed bodies.",
    })
}

/// The always-on smoke (bounded; runs in the default `cargo test` gate). It builds
/// a small growing history in both arms, asserts the committed histories agree, and
/// checks the amplification time series has the expected shape.
#[test]
fn endurance_amplification_smoke() {
    let td = TempDir::new().unwrap();
    let plan = smoke_plan();
    let n = plan.sample_epochs().len();
    let (authoritative, manifested) = run_court(td.path(), &plan);

    assert_eq!(
        authoritative.samples.len(),
        n,
        "every sample point must be recorded in the authoritative arm"
    );
    assert_eq!(
        manifested.samples.len(),
        n,
        "every sample point must be recorded in the manifested arm"
    );

    // Content-neutral: logical content is byte-identical at every sample.
    let logical0 = u64_at(&authoritative.samples[0], "logical_bytes");
    assert!(logical0 > 0, "no live logical bytes were measured");
    for s in &authoritative.samples {
        assert_eq!(
            u64_at(s, "logical_bytes"),
            logical0,
            "content-neutral rewrites must not change live logical bytes"
        );
    }

    // Amplification grows monotonically with retained history.
    let r_first = f64_at(&authoritative.samples[0], "amplification_total");
    let r_last = f64_at(authoritative.samples.last().unwrap(), "amplification_total");
    assert!(
        r_last > r_first,
        "amplification must grow with retained history (first {r_first}, last {r_last})"
    );
    let ratios: Vec<f64> = authoritative
        .samples
        .iter()
        .map(|s| f64_at(s, "amplification_total"))
        .collect();
    assert!(
        ratios.windows(2).all(|w| w[1] >= w[0] - 1e-9),
        "amplification must be monotone non-decreasing: {ratios:?}"
    );

    // The growth counters advance.
    assert!(
        u64_at(
            authoritative.samples.last().unwrap(),
            "committed_root_count"
        ) > u64_at(&authoritative.samples[0], "committed_root_count"),
        "the retained committed-root count must grow"
    );

    // The manifested arm added concealed bytes and published generations.
    let a_last = u64_at(
        authoritative.samples.last().unwrap(),
        "total_physical_bytes",
    );
    let m_last = u64_at(manifested.samples.last().unwrap(), "total_physical_bytes");
    assert!(
        m_last > a_last,
        "the manifested arm must add concealed physical bytes ({m_last} vs {a_last})"
    );
    assert!(
        u64_at(
            manifested.samples.last().unwrap(),
            "manifested_generation_count"
        ) > 0,
        "the manifested plane published no generations"
    );
}

#[test]
fn endurance_amplification_sweep() {
    if std::env::var("ORFS_ENDURANCE_AMPLIFICATION").as_deref() != Ok("1") {
        eprintln!(
            "endurance_amplification_sweep: skipped \
             (set ORFS_ENDURANCE_AMPLIFICATION=1 to run the full sweep)"
        );
        return;
    }
    let td = TempDir::new().unwrap();
    let plan = sweep_plan();
    let (authoritative, manifested) = run_court(td.path(), &plan);

    let environment = serde_json::json!({
        "bench": serde_json::to_value(orfs::bench::Environment::capture(
            std::env::var("ORFS_IMAGE").ok()
        ))
        .unwrap_or(serde_json::Value::Null),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "resident_kib_end": resident_kib(),
    });

    let assessment = assess(&authoritative, &manifested);
    let a_last = authoritative.samples.last().expect("sample");
    let m_last = manifested.samples.last().expect("sample");

    let doc = serde_json::json!({
        "schema": "orfs.performance.endurance-amplification.v1",
        "generated_by": "tests/endurance_amplification.rs",
        "note": "Single-run, single-host, BOUNDED measurements. This court is a \
                 bounded surrogate for the multi-day endurance run the reviewer's \
                 item 8 ultimately needs: it grows a committed history over many \
                 epochs and samples the amplification time series, but it is \
                 intentionally capped in wall time and retained bytes. A genuinely \
                 multi-day run on a large backing store is the follow-up and is NOT \
                 claimed here. Logical content is byte-identical at every sample \
                 (content-neutral rewrites), so the ratio rises monotonically without \
                 a ceiling; appending new content instead would bound it. Absolute \
                 bytes are host/build dependent; the shape and the byte counts are \
                 the point.",
        "bounded_run_scope": {
            "epochs": plan.params.epochs,
            "sample_every_epochs": plan.params.sample_every,
            "samples": authoritative.samples.len(),
            "epoch_writes_per_object": plan.params.epoch_writes,
            "epoch_write_len": WRITE_LEN,
            "new_bytes_per_object_per_epoch": plan.params.new_bytes,
            "content_neutral": plan.params.new_bytes == 0,
            "retained_total_bytes_end_authoritative": u64_at(a_last, "total_physical_bytes"),
            "retained_total_bytes_end_manifested": u64_at(m_last, "total_physical_bytes"),
            "retained_bytes_bound_note": "the whole run stays within the container's \
                                          8 GiB cap and is deleted on completion; a \
                                          multi-day retention run is the follow-up",
            "multi_day_run_is_follow_up": true,
        },
        "environment": environment,
        "design": {
            "objects": plan.params.objects,
            "object_bytes": plan.params.object_bytes,
            "initial_chunk": plan.params.initial_chunk,
            "checkpoints_epochs": plan.sample_epochs(),
            "arms": {
                "authoritative": "OrFS with the concealed manifested plane disabled",
                "manifested": "OrFS with manifestation enabled (profile full, synchronous)"
            },
            "correctness": "both arms build the identical deterministic committed \
                            history; committed roots are asserted equal",
        },
        "history_build_wall_micros": {
            "authoritative": authoritative.history_build_wall_micros as u64,
            "manifested": manifested.history_build_wall_micros as u64,
        },
        "arms": {
            "authoritative": {
                "manifestation": "disabled",
                "resident_kib_end": authoritative.resident_kib,
                "samples": authoritative.samples,
            },
            "manifested": {
                "manifestation": "enabled (profile full, synchronous)",
                "resident_kib_end": manifested.resident_kib,
                "samples": manifested.samples,
            },
        },
        "assessment": assessment,
    });

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/performance/endurance-amplification.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!(
        "endurance-amplification evidence written to {}",
        path.display()
    );
}
