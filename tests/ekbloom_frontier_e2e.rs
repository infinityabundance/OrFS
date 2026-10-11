//! Phase 16 **manifestation frontier, end to end**.
//!
//! Phase 12 measured the EKBLOOM frontier *through the in-crate read planner*
//! and found that the read planner correctly fell back to the authoritative
//! extent path for the benchmarked byte reads. Phase 16 asks the harder
//! question: through a **real FUSE mount with real POSIX syscalls**, does the
//! concealed manifested body make any operation genuinely faster — and if not,
//! where does it genuinely help?
//!
//! This test runs only under `ORFS_FUSE_TEST=1` (the `orfs-kmount` container,
//! `scripts/container-fuse-test.sh`). Outside it, it prints the reason and
//! returns, so a plain `cargo test` stays green without a mount.
//!
//! ## What is measured, and how the effects are separated
//!
//! * **`e2e_byte_reads_profile_sweep`** — for a fixed logical object, vary the
//!   manifested profile (`none`, `path(1/4/8)`, `bloom(4)`, `full`,
//!   `max-speed`), and read random single bytes and random 4 KiB regions
//!   through the mount with `pread`, both with `FOPEN_DIRECT_IO` (every read
//!   reaches FUSE) and page-cache-warm. The *only* axis that changes between
//!   rows is the manifested structure, so any difference is attributable to
//!   EKBLOOM, never to transport (identical mount options) or the kernel cache
//!   (both variants measured for every profile).
//! * **`e2e_search_grep_vs_index`** — build the concealed trigram index and
//!   compare equal-result content searches: the indexed typed query API, the
//!   scan fallback of the same API, and ordinary `grep -r` **through the
//!   mount**. `grep` reads file contents through POSIX and does **not** invoke
//!   the index (research §12.1); it is measured to say so plainly.
//! * **`defensive_no_extent_map_baseline`** — the authoritative OrFS read is
//!   O(1) (extent-map lookup). To isolate the manifestation's value we compare
//!   it against a *defensive* baseline with no offset-addressable extent map
//!   (a prefix read that must decode from the start), which is where a
//!   structure that guarantees O(1) random access would win.
//! * **`e2e_fragmented_object_path_bloom`** — a real case where the
//!   authoritative path is **not** O(1): the extent map is scanned linearly
//!   (`ExtentMap::plan_read`), so an object built from many small scattered
//!   writes has an O(N) authoritative read. A certified `path` bloom addresses
//!   the object by logical position, independent of fragmentation, so this is
//!   where the manifested body genuinely wins — measured both through the mount
//!   and at the library level.
//!
//! Evidence: `evidence/performance/ekbloom-e2e.json` (machine-generated).

use std::fs::{self, File};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::fuse::{self, MountOptions, StatfsMode};
use orfs::index::ROOT_INODE;
use orfs::log::{OpenMode, DEFAULT_SEGMENT_SIZE};
use orfs::manifestation::{ManifestationConfig, ManifestationProfile, ManifestationStatus};
use orfs::namespace::{Namespace, SetAttr};
use orfs::query::QueryRequest;
use orfs::readpath::{ReadPlanner, ReadQuery};
use orfs::trigram::TrigramConfig;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("serialize");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}

/// The build profile the test was compiled with (`debug`/`release`). FUSE test
/// builds are debug by default; a release run can be recorded separately with
/// `ORFS_E2E_SUFFIX=-release`.
fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// Evidence filename with an optional `ORFS_E2E_SUFFIX` (so a debug and a
/// release run never clobber each other).
fn evidence_file(base: &str) -> PathBuf {
    let suffix = std::env::var("ORFS_E2E_SUFFIX").unwrap_or_default();
    manifest_dir()
        .join("evidence/performance")
        .join(format!("{base}{suffix}.json"))
}

/// Deterministic PRNG so the access pattern is byte-reproducible.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Lcg {
        Lcg(seed)
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

#[derive(Clone, Copy)]
struct Percentiles {
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    min_ns: u64,
    mean_ns: f64,
    samples: usize,
}

fn percentiles(mut v: Vec<u64>) -> Percentiles {
    v.sort_unstable();
    let n = v.len();
    let q = |p: f64| -> u64 {
        if n == 0 {
            0
        } else {
            v[(((n as f64) * p) as usize).min(n - 1)]
        }
    };
    Percentiles {
        min_ns: v.first().copied().unwrap_or(0),
        mean_ns: if n == 0 {
            0.0
        } else {
            v.iter().sum::<u64>() as f64 / n as f64
        },
        p50_ns: q(0.50),
        p95_ns: q(0.95),
        p99_ns: q(0.99),
        samples: n,
    }
}

impl Percentiles {
    fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "samples": self.samples,
            "min_ns": self.min_ns,
            "mean_ns": self.mean_ns,
            "p50_ns": self.p50_ns,
            "p95_ns": self.p95_ns,
            "p99_ns": self.p99_ns,
        })
    }
}

fn write_pattern(buf: &mut [u8], seed: u64) {
    let mut s = seed | 1;
    for b in buf.iter_mut() {
        // xorshift64 for speed over large buffers
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s & 0xff) as u8;
    }
}

fn unique_scratch(prefix: &str) -> PathBuf {
    let base = manifest_dir().join("target").join("perf-e2e");
    fs::create_dir_all(&base).expect("perf-e2e base");
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}-{pid}-{nanos}"));
    fs::create_dir_all(&dir).expect("scratch");
    dir
}

fn current_uid_gid() -> (u32, u32) {
    // SAFETY: geteuid/getegid are pure queries.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

/// Drop the backing page cache for every file under `dir` (cold-cache control).
/// The FUSE daemon reads the same inodes, so this is a genuinely cold backing.
fn drop_backing_cache(dir: &Path) {
    use std::os::unix::io::AsRawFd;
    fn walk(dir: &Path) {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p);
                } else if let Ok(f) = File::open(&p) {
                    // SAFETY: `f` is an open regular file; fadvise is a hint.
                    unsafe {
                        libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
                    }
                }
            }
        }
    }
    walk(dir);
}

/// The profile ladder exercised end to end.
fn profile_ladder() -> Vec<(&'static str, ManifestationProfile)> {
    vec![
        ("path-1", ManifestationProfile::Path { depth: 1 }),
        ("path-4", ManifestationProfile::Path { depth: 4 }),
        ("path-8", ManifestationProfile::Path { depth: 8 }),
        ("bloom-4", ManifestationProfile::Bloom { depth: 4 }),
        ("full", ManifestationProfile::Full),
        ("max-speed", ManifestationProfile::MaxSpeed),
    ]
}

/// Create a volume with one large file, owned by the mounting uid, optionally
/// manifested with `profile`. Returns `(backing, inode, manifested_bytes,
/// construction_ns)`.
fn make_byte_volume(
    scratch: &Path,
    profile: Option<ManifestationProfile>,
    data: &[u8],
) -> (PathBuf, u64, u64, u64) {
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    fs::create_dir_all(&mnt).expect("mnt");
    let (uid, gid) = current_uid_gid();
    let mut ns = Namespace::init(&backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered)
        .expect("init volume");
    ns.setattr(
        ROOT_INODE,
        &SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        },
    )
    .expect("chown root");
    let ino = ns
        .create(ROOT_INODE, b"big.bin", 0o644, uid, gid)
        .expect("create");
    ns.write_at(ino, 0, data).expect("write");
    ns.sync().expect("sync");

    let mut manifested_bytes = 0u64;
    let mut construction_ns = 0u64;
    if let Some(p) = profile {
        ns.enable_manifestation(ManifestationConfig {
            workers: 1,
            synchronous: true,
            profile: p,
            max_source_bytes: 64 << 20,
            ..Default::default()
        })
        .expect("enable manifestation");
        let t = Instant::now();
        let outcomes = ns.manifest_eligible(Some(ino), p).expect("manifest");
        construction_ns = t.elapsed().as_nanos() as u64;
        for o in &outcomes {
            assert_eq!(
                o.status,
                ManifestationStatus::Published,
                "profile {} did not publish: {:?}",
                p.label(),
                o.detail
            );
        }
        manifested_bytes = orfs::stats::account_volume(&backing)
            .expect("account")
            .m_ekbloom;
    }
    (backing, ino, manifested_bytes, construction_ns)
}

fn mount_opts(profile: Option<ManifestationProfile>, direct_io: bool) -> MountOptions {
    MountOptions {
        read_only: true,
        statfs: StatfsMode::PhysicalSafe,
        direct_io,
        manifest: profile,
        manifest_sync: false,
        manifest_workers: 1,
        ..Default::default()
    }
}

/// Random byte reads through a mounted file. Returns per-length percentiles.
fn e2e_random_reads_on(
    mountpoint: &Path,
    file_name: &str,
    data_len: u64,
    length: u64,
    iterations: u64,
    seed: u64,
) -> Percentiles {
    let path = mountpoint.join(file_name);
    let f = File::open(&path).expect("open through mount");
    let mut rng = Lcg::new(seed);
    let mut buf = vec![0u8; length as usize];
    let mut samples = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let off = rng.below(data_len.saturating_sub(length) + 1);
        let t = Instant::now();
        f.read_exact_at(&mut buf, off).expect("pread through mount");
        samples.push(t.elapsed().as_nanos() as u64);
    }
    percentiles(samples)
}

/// Random byte reads through a mounted `big.bin`.
fn e2e_random_reads(
    mountpoint: &Path,
    data_len: u64,
    length: u64,
    iterations: u64,
    seed: u64,
) -> Percentiles {
    e2e_random_reads_on(mountpoint, "big.bin", data_len, length, iterations, seed)
}

// ---------------------------------------------------------------------------
// (1) end-to-end byte reads: profile sweep, direct + warm
// ---------------------------------------------------------------------------

#[test]
fn e2e_byte_reads_profile_sweep() {
    if std::env::var("ORFS_FUSE_TEST").as_deref() != Ok("1") {
        eprintln!(
            "ekbloom_frontier_e2e: skipped (ORFS_FUSE_TEST unset); \
             run under scripts/container-fuse-test.sh"
        );
        return;
    }
    let scratch = unique_scratch("e2e-bytes");
    const DATA: usize = 256 * 1024;
    let mut data = vec![0u8; DATA];
    write_pattern(&mut data, 0x51ED);
    let len = DATA as u64;

    const N1: u64 = 4_000;
    const N4K: u64 = 1_500;

    let mut rows: Vec<serde_json::Value> = Vec::new();

    // The `none` row: no manifest, so the mount uses the authoritative extent
    // path for every read (the honest F1-equivalent baseline).
    for (name, profile) in std::iter::once(("none", None))
        .chain(profile_ladder().into_iter().map(|(n, p)| (n, Some(p))))
    {
        let (backing, _ino, m_bytes, construction_ns) = make_byte_volume(&scratch, profile, &data);
        let mnt = scratch.join("mnt");
        let desc = profile
            .map(|p| p.label())
            .unwrap_or_else(|| "none".to_string());

        let mount = fuse::spawn(&backing, &mnt, &mount_opts(profile, true))
            .unwrap_or_else(|e| panic!("mount failed for {name}: {e}"));

        // Warm once, then measure direct (every read reaches FUSE).
        let _ = e2e_random_reads(&mnt, len, 1, 200, 1);
        let direct_1b = e2e_random_reads(&mnt, len, 1, N1, 0xE2E1);
        let direct_4k = e2e_random_reads(&mnt, len, 4096, N4K, 0xE2E4);
        mount.unmount().expect("unmount");

        // Cold variant: drop the backing cache, then re-mount direct and read.
        drop_backing_cache(&backing);
        let mount = fuse::spawn(&backing, &mnt, &mount_opts(profile, true))
            .unwrap_or_else(|e| panic!("re-mount failed for {name}: {e}"));
        let cold_1b = e2e_random_reads(&mnt, len, 1, N1, 0xE2E1);
        let cold_4k = e2e_random_reads(&mnt, len, 4096, N4K, 0xE2E4);
        mount.unmount().expect("unmount");

        // Warm page cache (no direct_io): the kernel serves repeated pages.
        let mount = fuse::spawn(&backing, &mnt, &mount_opts(profile, false))
            .unwrap_or_else(|e| panic!("warm mount failed for {name}: {e}"));
        let _ = e2e_random_reads(&mnt, len, 1, 200, 1);
        let _ = e2e_random_reads(&mnt, len, 4096, 200, 2);
        let warm_1b = e2e_random_reads(&mnt, len, 1, N1, 0xE2E1);
        let warm_4k = e2e_random_reads(&mnt, len, 4096, N4K, 0xE2E4);
        mount.unmount().expect("unmount");

        let _ = fs::remove_dir_all(&backing);
        fs::create_dir_all(&backing).ok();

        rows.push(serde_json::json!({
            "profile": name,
            "profile_label": desc,
            "manifested_bytes": m_bytes,
            "manifested_ratio": m_bytes as f64 / len as f64,
            "construction_ns": construction_ns,
            "read_1b": { "direct": direct_1b.to_json(), "cold_direct": cold_1b.to_json(), "warm": warm_1b.to_json() },
            "read_4k": { "direct": direct_4k.to_json(), "cold_direct": cold_4k.to_json(), "warm": warm_4k.to_json() },
        }));
        eprintln!("e2e_byte_reads_profile_sweep: {name} done");
    }

    let doc = serde_json::json!({
        "schema": "orfs.ekbloom-e2e.v1",
        "generated_by": "tests/ekbloom_frontier_e2e.rs",
        "build_profile": build_profile(),
        "through_fuse": true,
        "object_bytes": len,
        "iterations": { "read_1b": N1, "read_4k": N4K },
        "environment": orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok()),
        "separation": {
            "transport": "identical mount options for every row; the only axis that changes is the manifested profile",
            "page_cache": "both a direct-IO variant (every read reaches FUSE) and a warm page-cache variant are recorded for every profile; a cold variant drops the backing page cache first",
            "baseline": "the `none` row is the same mount with no manifested structure (the authoritative extent path)",
            "note": "the daemon's read planner measures and selects paths per (generation, size class); it is free to fall back to the authoritative extent path",
            "caveat": "the cold variant drops the backing page cache once before the run, so it can include a first-access payload reload; single-run cold figures are noisy",
        },
        "workloads": rows,
    });
    write_json(&evidence_file("ekbloom-e2e"), &doc);
    let _ = fs::remove_dir_all(&scratch);
}

// ---------------------------------------------------------------------------
// (2) content search: indexed API vs scan API vs grep through the mount
// ---------------------------------------------------------------------------

fn text(len: usize, seed: u64) -> Vec<u8> {
    // A small alphabet, like tests/query.rs, so most trigrams are uninformative.
    let mut rng = Lcg::new(seed);
    (0..len)
        .map(|_| b"abcdefg "[(rng.next() as usize) % 8])
        .collect()
}

#[test]
fn e2e_search_grep_vs_index() {
    if std::env::var("ORFS_FUSE_TEST").as_deref() != Ok("1") {
        eprintln!(
            "ekbloom_frontier_e2e: skipped (ORFS_FUSE_TEST unset); \
             run under scripts/container-fuse-test.sh"
        );
        return;
    }
    let scratch = unique_scratch("e2e-search");
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    fs::create_dir_all(&mnt).expect("mnt");
    let (uid, gid) = current_uid_gid();

    const FILES: usize = 48;
    const FILE_BYTES: usize = 16 * 1024;
    let needle = b"NEEDLE-IN-THE-HAYSTACK".to_vec();

    // Build a corpus; every file is owned by the mounting uid so it is readable
    // through the mount.
    {
        let mut ns =
            Namespace::init(&backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered).expect("init");
        ns.setattr(
            ROOT_INODE,
            &SetAttr {
                uid: Some(uid),
                gid: Some(gid),
                ..Default::default()
            },
        )
        .expect("chown root");
        let dir = ns
            .mkdir(ROOT_INODE, b"corpus", 0o755, uid, gid)
            .expect("mkdir");
        for i in 0..FILES {
            let mut body = text(FILE_BYTES, 1000 + i as u64);
            if i == FILES / 2 {
                let at = FILE_BYTES / 2;
                body[at..at + needle.len()].copy_from_slice(&needle);
            }
            let f = ns
                .create(dir, format!("f{i}").as_bytes(), 0o644, uid, gid)
                .expect("create");
            ns.write_at(f, 0, &body).expect("write");
        }
        ns.sync().expect("sync");

        // Build the concealed index synchronously and report its cost.
        ns.enable_trigram(TrigramConfig {
            synchronous: true,
            ..Default::default()
        })
        .expect("enable trigram");
        let t = Instant::now();
        let outcomes = ns.index_trigram_eligible(None).expect("index");
        let build_ns = t.elapsed().as_nanos() as u64;
        let published = outcomes.iter().filter(|o| o.status == "published").count();
        let payload_bytes: u64 = outcomes.iter().map(|o| o.payload_bytes).sum();
        let idx_dir_bytes = orfs::stats::account_volume(&backing)
            .expect("account")
            .bloom_subdir_bytes
            .get("trigram")
            .copied()
            .unwrap_or(0);

        // Library-level: indexed query (same namespace, index attached) vs scan
        // query (a fresh namespace with no trigram plane). Both return equal
        // results over the same pinned root.
        let root = ns.root();
        let req = QueryRequest::new(ROOT_INODE, root, needle.clone());
        let scan = Namespace::open(&backing, OpenMode::ReadOnly, DurabilityMode::Ordered)
            .expect("reopen for scan");
        let _ = scan.query(req.clone()).expect("scan warmup");
        let _ = ns.query(req.clone()).expect("indexed warmup");

        const ITERS: usize = 21;
        let mut indexed = Vec::with_capacity(ITERS);
        let mut scan_t = Vec::with_capacity(ITERS);
        let mut indexed_bytes = 0u64;
        let mut scan_bytes = 0u64;
        let mut indexed_matches = 0usize;
        let mut scan_matches = 0usize;
        for _ in 0..ITERS {
            let t = Instant::now();
            let r = ns.query(req.clone()).expect("indexed query");
            indexed.push(t.elapsed().as_nanos() as u64);
            indexed_bytes = r.stats.content_bytes_read;
            indexed_matches = r.matches.len();
            let t = Instant::now();
            let r = scan.query(req.clone()).expect("scan query");
            scan_t.push(t.elapsed().as_nanos() as u64);
            scan_bytes = r.stats.content_bytes_read;
            scan_matches = r.matches.len();
        }
        assert_eq!(indexed_matches, scan_matches, "indexed and scan disagree");
        let indexed_p = percentiles(indexed);
        let scan_p = percentiles(scan_t);

        // Mount read-only (no manifestation needed) and measure grep -r through
        // FUSE. grep reads POSIX contents and does NOT use the trigram index.
        let mount = fuse::spawn(&backing, &mnt, &mount_opts(None, false))
            .unwrap_or_else(|e| panic!("search mount failed: {e}"));
        let corpus = mnt.join("corpus");
        // Warm the mount, then measure.
        let grep_once = |pat: &str| -> u64 {
            let t = Instant::now();
            let out = std::process::Command::new("grep")
                .args(["-r", "-l", "--binary-files=text", pat])
                .arg(&corpus)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output()
                .expect("run grep");
            assert!(out.status.success() || out.status.code() == Some(1));
            t.elapsed().as_nanos() as u64
        };
        let pat = String::from_utf8_lossy(&needle).to_string();
        let _ = grep_once(&pat);
        const GREP_ITERS: usize = 7;
        let mut grep_t = Vec::with_capacity(GREP_ITERS);
        for _ in 0..GREP_ITERS {
            grep_t.push(grep_once(&pat));
        }
        let grep_p = percentiles(grep_t);
        mount.unmount().expect("unmount");

        write_json(
            &evidence_file("ekbloom-search-e2e"),
            &serde_json::json!({
                "schema": "orfs.ekbloom-search-e2e.v1",
                "generated_by": "tests/ekbloom_frontier_e2e.rs",
                "build_profile": build_profile(),
                "through_fuse": true,
                "environment": orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok()),
                "search": {
                    "dataset": {
                        "files": FILES,
                        "bytes_per_file": FILE_BYTES,
                        "pattern": pat,
                        "needle_matches": indexed_matches,
                    },
                    "indexed_query_api": indexed_p.to_json(),
                    "scan_query_api": scan_p.to_json(),
                    "grep_r_through_mount": grep_p.to_json(),
                    "content_bytes_read": { "indexed": indexed_bytes, "scan": scan_bytes },
                    "indexed_speedup_over_scan": scan_p.p50_ns as f64 / indexed_p.p50_ns.max(1) as f64,
                    "index_build": {
                        "objects_published": published,
                        "objects_attempted": outcomes.len(),
                        "elapsed_ns": build_ns,
                        "payload_bytes_total": payload_bytes,
                        "payload_bytes_on_disk": idx_dir_bytes,
                    },
                    "honesty": "the typed query API is the only consumer of the trigram index; ordinary `grep -r` reads POSIX contents and uses the authoritative extent path (research §12.1)",
                },
            }),
        );
    }

    let _ = fs::remove_dir_all(&scratch);
}

// ---------------------------------------------------------------------------
// (3) defensive no-extent-map baseline (library level, no FUSE)
// ---------------------------------------------------------------------------

#[test]
fn defensive_no_extent_map_baseline() {
    if std::env::var("ORFS_FUSE_TEST").as_deref() != Ok("1") {
        eprintln!(
            "ekbloom_frontier_e2e: skipped (ORFS_FUSE_TEST unset); \
             run under scripts/container-fuse-test.sh"
        );
        return;
    }
    let scratch = unique_scratch("defensive");
    const DATA: usize = 256 * 1024;
    let mut data = vec![0u8; DATA];
    write_pattern(&mut data, 0xDEF0);
    let len = DATA as u64;
    let profile = ManifestationProfile::Path { depth: 4 };
    let (backing, ino, _m, _c) = make_byte_volume(&scratch, Some(profile), &data);

    // Re-open read-only with the planner attached, at the same root/version.
    let mut ns =
        Namespace::open(&backing, OpenMode::ReadOnly, DurabilityMode::Ordered).expect("reopen");
    ns.enable_manifestation(ManifestationConfig {
        workers: 1,
        synchronous: true,
        profile,
        ..Default::default()
    })
    .expect("enable");
    let root = ns.root();
    let st = ns.getattr(ino, root).expect("stat");
    let planner: &ReadPlanner = ns.read_planner().expect("planner");

    // Per-path measured latency at a mid offset (min/mean over iterations).
    let q = ReadQuery {
        inode: ino,
        inode_version: st.version,
        root,
        logical_len: len,
        offset: len / 2,
        length: 1,
    };
    let mut auth = |o: u64, l: u64| ns.read_extent(ino, root, o, l);
    let measured: Vec<serde_json::Value> = planner
        .measure_paths(&q, &mut auth, 500)
        .unwrap_or_default()
        .into_iter()
        .map(|l| {
            serde_json::json!({
                "path": l.path.name(),
                "certified": l.certified,
                "min_ns": l.min_ns,
                "mean_ns": l.mean_ns,
            })
        })
        .collect();

    // The defensive no-extent-map baseline: to read one byte at `off` without an
    // offset-addressable map, a design must decode from the start — modelled
    // here by reading the whole prefix [0, off]. The authoritative OrFS read is
    // the O(1) extent path; the manifested path is the planner's selection.
    let mut offsets = Vec::new();
    let mut rng = Lcg::new(0x0FF5E7);
    for _ in 0..32 {
        offsets.push(rng.below(len));
    }
    let mut prefix = Vec::new();
    let mut authoritative = Vec::new();
    let mut planner_ns = Vec::new();
    for &off in &offsets {
        let t = Instant::now();
        let whole = ns.read_extent(ino, root, 0, off + 1).expect("prefix");
        prefix.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(whole.last());

        let t = Instant::now();
        let one = ns.read_extent(ino, root, off, 1).expect("authoritative");
        authoritative.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(&one);

        let t = Instant::now();
        let p = ns.planned_read(ino, root, off, 1).expect("planned");
        planner_ns.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(&p.bytes);
    }

    let prefix_p = percentiles(prefix);
    let auth_p = percentiles(authoritative);
    let plan_p = percentiles(planner_ns);

    // Random 4 KiB planned vs authoritative over the real log (mirrors the
    // mounted workload at the planner level, without FUSE).
    let mut rng = Lcg::new(0x4EC3);
    let blocks = len / 4096;
    let mut a4k = Vec::new();
    let mut p4k = Vec::new();
    for _ in 0..300 {
        let off = rng.below(blocks) * 4096;
        let t = Instant::now();
        let v = ns.read_extent(ino, root, off, 4096).expect("auth 4k");
        a4k.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(&v);
        let t = Instant::now();
        let v = ns.planned_read(ino, root, off, 4096).expect("planned 4k");
        p4k.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(&v.bytes);
    }

    // Which path the planner actually chose for the 1-byte reads above.
    let chosen: Vec<serde_json::Value> = planner
        .chosen_counts()
        .into_iter()
        .map(|(p, c)| serde_json::json!({ "path": p.name(), "reads": c }))
        .collect();

    let doc = serde_json::json!({
        "schema": "orfs.ekbloom-e2e-defensive.v1",
        "generated_by": "tests/ekbloom_frontier_e2e.rs",
        "build_profile": build_profile(),
        "through_fuse": false,
        "object_bytes": len,
        "profile": profile.label(),
        "defensive_no_extent_map_baseline": {
            "note": "The authoritative OrFS read is O(1) via the extent map, so no manifested structure can beat it. This compares it against a defensive baseline without an offset-addressable map (decode-from-start prefix read), where a structure guaranteeing O(1) random access would win.",
            "decode_from_start_prefix": prefix_p.to_json(),
            "authoritative_extent_o1": auth_p.to_json(),
            "planned_read": plan_p.to_json(),
            "measured_paths": measured,
            "paths_chosen_by_the_planner": chosen,
        },
        "real_log_4k_planned_vs_authoritative": {
            "authoritative_extent": percentiles(a4k).to_json(),
            "planned_read": percentiles(p4k).to_json(),
        },
    });
    write_json(&evidence_file("ekbloom-e2e-defensive"), &doc);
    let _ = fs::remove_dir_all(&scratch);
}

// ---------------------------------------------------------------------------
// (4) fragmented object: the authoritative extent scan is O(N); a path bloom
//     addresses by logical position and is fragmentation-independent
// ---------------------------------------------------------------------------

/// Build a volume whose one object is assembled from many small scattered
/// writes, so its authoritative extent map has many entries and
/// `ExtentMap::plan_read` must scan them.
fn make_fragmented_volume(
    scratch: &Path,
    profile: Option<ManifestationProfile>,
    writes: u64,
    stride: u64,
    chunk: u64,
) -> (PathBuf, u64, u64, u64, u64, u64) {
    let backing = scratch.join("backing");
    let mnt = scratch.join("mnt");
    fs::create_dir_all(&mnt).expect("mnt");
    let (uid, gid) = current_uid_gid();
    let mut ns = Namespace::init(&backing, DEFAULT_SEGMENT_SIZE, DurabilityMode::Ordered)
        .expect("init volume");
    ns.setattr(
        ROOT_INODE,
        &SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        },
    )
    .expect("chown root");
    let ino = ns
        .create(ROOT_INODE, b"frag.bin", 0o644, uid, gid)
        .expect("create");
    let setup = Instant::now();
    let mut buf = vec![0u8; chunk as usize];
    for i in 0..writes {
        write_pattern(&mut buf, 0xF00D_0000 ^ i);
        ns.write_at(ino, i * stride, &buf).expect("scattered write");
    }
    ns.sync().expect("sync");
    let setup_ns = setup.elapsed().as_nanos() as u64;

    let mut manifested_bytes = 0u64;
    let mut construction_ns = 0u64;
    if let Some(p) = profile {
        ns.enable_manifestation(ManifestationConfig {
            workers: 1,
            synchronous: true,
            profile: p,
            max_source_bytes: 64 << 20,
            ..Default::default()
        })
        .expect("enable manifestation");
        let t = Instant::now();
        let outcomes = ns.manifest_eligible(Some(ino), p).expect("manifest");
        construction_ns = t.elapsed().as_nanos() as u64;
        for o in &outcomes {
            assert_eq!(
                o.status,
                ManifestationStatus::Published,
                "fragmented manifest did not publish: {:?}",
                o.detail
            );
        }
        manifested_bytes = orfs::stats::account_volume(&backing)
            .expect("account")
            .m_ekbloom;
    }
    // The extent count is the honest measure of authoritative read work: a
    // linear extent-map scan costs O(extents) per arbitrary-offset read. A
    // read-only diagnostic accessor on the namespace.
    let extent_count = ns.extent_count(ino, ns.root()).unwrap_or(0) as u64;
    (
        backing,
        ino,
        manifested_bytes,
        construction_ns,
        setup_ns,
        extent_count,
    )
}

#[test]
fn e2e_fragmented_object_path_bloom() {
    if std::env::var("ORFS_FUSE_TEST").as_deref() != Ok("1") {
        eprintln!(
            "ekbloom_frontier_e2e: skipped (ORFS_FUSE_TEST unset); \
             run under scripts/container-fuse-test.sh"
        );
        return;
    }
    let scratch = unique_scratch("e2e-frag");
    const WRITES: u64 = 2_048;
    const STRIDE: u64 = 512;
    const CHUNK: u64 = 64;
    let len = (WRITES - 1) * STRIDE + CHUNK;
    let profile = ManifestationProfile::Path { depth: 4 };
    const N: u64 = 4_000;

    // Baseline: the same fragmented object, no manifested structure.
    let (backing, _ino, _m, _c, setup_ns, extents) =
        make_fragmented_volume(&scratch, None, WRITES, STRIDE, CHUNK);
    let mnt = scratch.join("mnt");
    let mount = fuse::spawn(&backing, &mnt, &mount_opts(None, true)).expect("mount none");
    let _ = e2e_random_reads_on(&mnt, "frag.bin", len, 1, 200, 1);
    let none_direct = e2e_random_reads_on(&mnt, "frag.bin", len, 1, N, 0xF4A6);
    mount.unmount().expect("unmount none");
    let _ = fs::remove_dir_all(&backing);
    fs::create_dir_all(&backing).ok();

    // Manifested: a certified path bloom addresses by logical position.
    let (backing2, ino2, m_bytes, construction_ns, _s2, extents2) =
        make_fragmented_volume(&scratch, Some(profile), WRITES, STRIDE, CHUNK);
    let mount = fuse::spawn(&backing2, &mnt, &mount_opts(Some(profile), true)).expect("mount path");
    let _ = e2e_random_reads_on(&mnt, "frag.bin", len, 1, 200, 1);
    let path_direct = e2e_random_reads_on(&mnt, "frag.bin", len, 1, N, 0xF4A6);
    mount.unmount().expect("unmount path");

    // Library-level isolation on the same manifested volume.
    let mut ns =
        Namespace::open(&backing2, OpenMode::ReadOnly, DurabilityMode::Ordered).expect("reopen");
    ns.enable_manifestation(ManifestationConfig {
        workers: 1,
        synchronous: true,
        profile,
        ..Default::default()
    })
    .expect("enable");
    let root = ns.root();
    let mut rng = Lcg::new(0xF4A6);
    let mut auth_ns = Vec::with_capacity(N as usize);
    let mut plan_ns = Vec::with_capacity(N as usize);
    for _ in 0..N {
        let off = rng.below(len);
        let t = Instant::now();
        let v = ns.read_extent(ino2, root, off, 1).expect("auth");
        auth_ns.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(&v);
        let t = Instant::now();
        let v = ns.planned_read(ino2, root, off, 1).expect("planned");
        plan_ns.push(t.elapsed().as_nanos() as u64);
        std::hint::black_box(&v.bytes);
    }
    let chosen: Vec<serde_json::Value> = ns
        .read_planner()
        .map(|p| {
            p.chosen_counts()
                .into_iter()
                .map(|(k, c)| serde_json::json!({ "path": k.name(), "reads": c }))
                .collect()
        })
        .unwrap_or_default();

    let doc = serde_json::json!({
        "schema": "orfs.ekbloom-fragmented-e2e.v1",
        "generated_by": "tests/ekbloom_frontier_e2e.rs",
        "build_profile": build_profile(),
        "through_fuse": true,
        "environment": orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok()),
        "fragmented_object": {
            "logical_bytes": len,
            "scattered_writes": WRITES,
            "stride_bytes": STRIDE,
            "chunk_bytes": CHUNK,
            "extent_count_no_manifest": extents,
            "extent_count_manifested": extents2,
            "setup_ns_no_manifest": setup_ns,
            "manifested_profile": profile.label(),
            "manifested_bytes": m_bytes,
            "manifested_ratio": m_bytes as f64 / len as f64,
            "construction_ns": construction_ns,
        },
        "e2e_random_1b_direct": {
            "no_manifest": none_direct.to_json(),
            "path_bloom": path_direct.to_json(),
            "speedup": none_direct.p50_ns as f64 / path_direct.p50_ns.max(1) as f64,
        },
        "library_random_1b": {
            "authoritative_extent": percentiles(auth_ns).to_json(),
            "planned_read": percentiles(plan_ns).to_json(),
            "paths_chosen_by_the_planner": chosen,
        },
        "note": "ExtentMap::plan_read scans the extent map linearly, so an object built from many small scattered writes has an O(N) authoritative read; a certified path bloom addresses the object by logical position and is independent of fragmentation. The two mounts use identical options, so the difference is attributable to the manifested structure, not to transport.",
    });
    write_json(&evidence_file("ekbloom-fragmented-e2e"), &doc);
    let _ = fs::remove_dir_all(&scratch);
}
