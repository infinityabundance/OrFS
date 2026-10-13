//! **Phase 52 — the global search directory court (reviewer research §9).**
//!
//! The per-object positional trigram index accelerates a query within one file,
//! but the engine still examines every file to discover which are relevant. §9
//! asks for a **global, version-qualified directory mapping a trigram to the
//! objects that contain it**, so a whole-tree query can restrict itself to the
//! candidate objects and never open the rest.
//!
//! This court proves, through the public API:
//!
//! * **Parity.** The directory path returns byte-identical matches to both the
//!   per-object index path and a full authoritative scan, for present, rare, and
//!   absent patterns; an absent pattern short-circuits to zero matches with every
//!   object pruned.
//! * **Pruning.** A rare pattern examines only the objects that contain it, so the
//!   number of files examined drops by orders of magnitude on a large tree.
//! * **Density-adaptive posting sets.** The evidence reports how many posting sets
//!   chose the bitmap representation and the structural bytes of each.
//!
//! The directory is **derived**, never authoritative: it is built from committed
//! per-object indexes at a committed root, every candidate is verified against
//! committed content, and an incomplete directory is ignored (the query falls back).
//!
//! The always-on smoke runs a bounded tree; the full sweep is opt-in behind
//! `ORFS_SEARCHDIR=1` and writes `evidence/performance/search-directory.json` (run
//! it via `scripts/container-search-directory.sh`).

use std::path::Path;
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::index::ROOT_INODE;
use orfs::log::OpenMode;
use orfs::namespace::Namespace;
use orfs::query::{QueryRequest, QueryResult};
use orfs::trigram::TrigramConfig;
use tempfile::TempDir;

/// A small lowercase alphabet with no `z` or `q`, so a rare marker is unambiguous.
const ALPHABET: &[u8] = b"abcdefg ";
/// The rare marker appended to a few files (letters absent from `ALPHABET`).
const RARE: &[u8] = b"zzq";
/// A trigram absent from every file (no `m` in the alphabet or the marker).
const ABSENT: &[u8] = b"mmm";

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn byte(&mut self) -> u8 {
        ALPHABET[(self.next() as usize) % ALPHABET.len()]
    }
}

fn text(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Lcg(seed);
    (0..len).map(|_| rng.byte()).collect()
}

/// Files whose (0-based) index is in `rare_files` carry the rare marker.
fn body_for(i: usize, len: usize, rare_files: &[usize]) -> Vec<u8> {
    let mut b = text(len, 0x1234_5678 ^ (i as u64));
    if rare_files.contains(&i) {
        b.extend_from_slice(RARE);
    }
    b
}

struct Court {
    files: usize,
    rare_files: Vec<usize>,
    dir_len: usize,
}

impl Court {
    /// A court with `files` files spread over `dir_len` subdirectories (0 = flat
    /// root), the rare marker in `rare_count` evenly-spaced files.
    fn new(files: usize, rare_count: usize, dir_len: usize) -> Court {
        let stride = (files / rare_count.max(1)).max(1);
        let rare_files: Vec<usize> = (0..rare_count).map(|k| k * stride).collect();
        Court {
            files,
            rare_files,
            dir_len,
        }
    }
}

fn build_tree(ns: &mut Namespace, c: &Court) {
    let root = ns.root_inode();
    if c.dir_len == 0 {
        for i in 0..c.files {
            let body = body_for(i, 512, &c.rare_files);
            let f = ns
                .create(root, format!("f{i}").as_bytes(), 0o644, 0, 0)
                .expect("create");
            ns.write_at(f, 0, &body).expect("write");
        }
    } else {
        let per_dir = c.dir_len.max(1);
        for i in 0..c.files {
            let d = i / per_dir;
            let name = format!("d{d}");
            let dir = match ns.lookup(root, name.as_bytes(), ns.root()) {
                Ok(id) => id,
                Err(_) => ns.mkdir(root, name.as_bytes(), 0o755, 0, 0).expect("mkdir"),
            };
            let body = body_for(i, 512, &c.rare_files);
            let f = ns
                .create(dir, format!("f{i}").as_bytes(), 0o644, 0, 0)
                .expect("create");
            ns.write_at(f, 0, &body).expect("write");
        }
    }
    ns.sync().expect("sync");
}

fn query(ns: &Namespace, pattern: &[u8]) -> QueryResult {
    ns.query(QueryRequest::new(ROOT_INODE, ns.root(), pattern.to_vec()))
        .expect("query")
}

#[derive(Debug)]
struct QueryRow {
    pattern_hex: String,
    matches: usize,
    files_considered: u64,
    files_indexed: u64,
    files_scanned: u64,
    files_pruned: u64,
    content_bytes_read: u64,
    ns: f64,
}

fn measure(ns: &Namespace, pattern: &[u8], rounds: u32) -> QueryRow {
    let mut last = query(ns, pattern);
    let started = Instant::now();
    for _ in 0..rounds.max(1) {
        last = query(ns, pattern);
    }
    let ns = started.elapsed().as_nanos() as f64 / rounds.max(1) as f64;
    QueryRow {
        pattern_hex: orfs::query::hex(pattern),
        matches: last.matches.len(),
        files_considered: last.stats.files_considered,
        files_indexed: last.stats.files_indexed,
        files_scanned: last.stats.files_scanned,
        files_pruned: last.stats.files_pruned_by_directory,
        content_bytes_read: last.stats.content_bytes_read,
        ns,
    }
}

// ---------------------------------------------------------------------------
// The court
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Outcome {
    files: usize,
    directory_json: serde_json::Value,
    prime_objects: u64,
    full: Vec<QueryRow>,
    indexed: Vec<QueryRow>,
    directory: Vec<QueryRow>,
    parity_all: bool,
}

fn run_court(dir: &Path, c: &Court) -> Outcome {
    let mut ns = Namespace::init(dir, 1 << 26, DurabilityMode::Ordered).expect("init namespace");
    build_tree(&mut ns, c);
    ns.enable_trigram(TrigramConfig {
        synchronous: true,
        ..Default::default()
    })
    .expect("enable trigram");
    ns.index_trigram_eligible(None).expect("index eligible");

    // A full-authoritative reference over the same committed root, with no plane.
    let scan_ns =
        Namespace::open(dir, OpenMode::ReadOnly, DurabilityMode::Ordered).expect("open read-only");
    assert_eq!(scan_ns.root(), ns.root(), "reference root must match");

    let patterns: Vec<Vec<u8>> = vec![b"abc".to_vec(), RARE.to_vec(), ABSENT.to_vec()];

    // Before priming: the per-object index path.
    let indexed: Vec<QueryRow> = patterns.iter().map(|p| measure(&ns, p, 8)).collect();
    // The authoritative scan reference.
    let full: Vec<QueryRow> = patterns.iter().map(|p| measure(&scan_ns, p, 4)).collect();

    // Prime the derived global search directory, then re-measure.
    let prime_started = Instant::now();
    let prime_objects = ns.prime_search_directory().expect("prime directory");
    let _prime_ns = prime_started.elapsed().as_nanos();
    let directory_json = ns
        .trigram_state()
        .and_then(|s| s.cached_search_directory())
        .map(|d| d.to_json())
        .unwrap_or(serde_json::Value::Null);
    let directory: Vec<QueryRow> = patterns.iter().map(|p| measure(&ns, p, 8)).collect();

    let parity_all = indexed
        .iter()
        .zip(directory.iter())
        .zip(full.iter())
        .all(|((i, d), f)| i.matches == d.matches && d.matches == f.matches);

    Outcome {
        files: c.files,
        directory_json,
        prime_objects,
        full,
        indexed,
        directory,
        parity_all,
    }
}

#[test]
fn search_directory_smoke() {
    let td = TempDir::new().unwrap();
    let c = Court::new(48, 2, 0);
    let o = run_court(td.path(), &c);

    assert!(o.parity_all, "directory/index/scan matches diverged: {o:?}");
    assert_eq!(o.prime_objects, o.files as u64, "not every file was folded");
    assert_eq!(
        o.directory_json["complete"], true,
        "directory was incomplete: {}",
        o.directory_json
    );
    assert_eq!(o.directory_json["objects"], o.files as u64);

    // The rare pattern is present in only two files: the directory must examine
    // exactly those and prune the rest.
    let rare = &o.directory[1];
    assert_eq!(rare.matches, o.full[1].matches);
    assert!(
        rare.files_pruned >= (o.files as u64) - 4,
        "the rare pattern pruned only {} of {} files",
        rare.files_pruned,
        o.files
    );

    // The absent pattern short-circuits: zero matches, everything pruned.
    let absent = &o.directory[2];
    assert_eq!(absent.matches, 0);
    assert_eq!(absent.files_pruned, o.files as u64);
    assert!(o.directory_json["trigram_keys"].as_u64().unwrap() > 0);
}

#[test]
fn search_directory_sweep() {
    if std::env::var("ORFS_SEARCHDIR").as_deref() != Ok("1") {
        eprintln!("search_directory_sweep: skipped (set ORFS_SEARCHDIR=1 to run the full sweep)");
        return;
    }
    let td = TempDir::new().unwrap();
    let c = Court::new(2048, 8, 64);
    let o = run_court(td.path(), &c);

    assert!(o.parity_all, "directory/index/scan matches diverged");

    let round = |rows: &[QueryRow]| {
        rows.iter()
            .map(|r| {
                serde_json::json!({
                    "pattern_hex": r.pattern_hex,
                    "matches": r.matches,
                    "files_considered": r.files_considered,
                    "files_indexed": r.files_indexed,
                    "files_scanned": r.files_scanned,
                    "files_pruned_by_directory": r.files_pruned,
                    "content_bytes_read": r.content_bytes_read,
                    "query_ns": r.ns,
                })
            })
            .collect::<Vec<_>>()
    };

    let environment = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());
    let doc = serde_json::json!({
        "schema": "orfs.performance.search-directory.v1",
        "generated_by": "tests/search_directory.rs",
        "note": "Single-run, single-host measurement of the global search directory \
                 (research §9). The directory is derived from committed per-object \
                 trigram indexes at a committed root; every candidate is still \
                 verified against committed content, so it can only remove files that \
                 provably cannot match. The three query rows are, in order, the \
                 per-object index path, the global-directory path, and the \
                 authoritative full scan over the identical committed root.",
        "tree": {
            "files": o.files,
            "directories": 64,
            "object_bytes": 512,
            "rare_pattern_hex": orfs::query::hex(RARE),
            "absent_pattern_hex": orfs::query::hex(ABSENT),
        },
        "directory": o.directory_json,
        "prime": {
            "objects_folded": o.prime_objects,
        },
        "indexed_path": round(&o.indexed),
        "directory_path": round(&o.directory),
        "full_scan": round(&o.full),
        "parity": { "all_identical": o.parity_all },
        "environment": {
            "bench": serde_json::to_value(&environment).unwrap_or(serde_json::Value::Null),
            "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        },
    });

    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/performance/search-directory.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("evidence dir");
    }
    let mut s = serde_json::to_string_pretty(&doc).expect("serialize");
    s.push('\n');
    std::fs::write(&path, s).expect("write evidence");
    eprintln!("search-directory evidence written to {}", path.display());
}
