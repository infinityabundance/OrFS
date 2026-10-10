//! Phase 9 tests: concealed query structures and the typed query API
//! (research §11.1, §11.2, §11.3, §12).
//!
//! The governing laws proved here:
//!
//! * **Parity** — for many patterns (present, absent, overlapping, binary,
//!   multi-match, shorter than a trigram), the indexed query and the full-scan
//!   query return byte-identical match sets over the same pinned root.
//! * **No false matches** — candidate matches from the trigram index are verified
//!   against the actual logical content; a deliberate false candidate is
//!   discarded and never reported.
//! * **Version qualification** — after a write bumps an inode version, the stale
//!   structure is refused and the query falls back to a full scan with identical
//!   results; re-indexing restores the accelerated path.
//! * **Corruption fallback** — a tampered payload is rejected and the query
//!   still returns the correct result by scanning.
//! * **Limits, cancellation, permissions** — the API honours a match limit, a
//!   cancellation flag / callback stop, and the transport's POSIX read rule.
//!
//! It emits machine-generated evidence
//! `evidence/correctness/query-parity.json` and
//! `evidence/performance/search-latency.json`.

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use orfs::commit::DurabilityMode;
use orfs::index::ROOT_INODE;
use orfs::log::OpenMode;
use orfs::namespace::Namespace;
use orfs::query::{Credential, MatchFlow, QueryMatch, QueryRequest, QueryResult, QUERY_SCHEMA};
use orfs::suffix::SuffixAutomaton;
use orfs::trigram::TrigramConfig;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_json(path: &Path, value: &serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create evidence dir");
    }
    let mut s = serde_json::to_string_pretty(value).expect("serialize json");
    s.push('\n');
    std::fs::write(path, s).expect("write evidence");
}

/// A deterministic PRNG so evidence is byte-reproducible.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn byte(&mut self, alphabet: &[u8]) -> u8 {
        alphabet[(self.next() as usize) % alphabet.len()]
    }
}

/// A fresh, deterministic byte buffer over a small alphabet.
fn text(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Lcg(seed);
    (0..len).map(|_| rng.byte(b"abcdefg ")).collect()
}

fn mkdir_file(ns: &mut Namespace, dir: u64, name: &[u8], body: &[u8], mode: u32) -> u64 {
    let f = ns.create(dir, name, mode, 0, 0).expect("create");
    if !body.is_empty() {
        ns.write_at(f, 0, body).expect("write");
    }
    f
}

/// The authoritative scan result for a request (a namespace with no trigram
/// state attached). Used as the parity reference.
fn scan_query(ns: &Namespace, req: &QueryRequest) -> QueryResult {
    ns.query(req.clone()).expect("scan query")
}

/// The indexed result for a request (a namespace with the trigram plane on).
fn indexed_query(ns: &Namespace, req: &QueryRequest) -> QueryResult {
    ns.query(req.clone()).expect("indexed query")
}

// ---------------------------------------------------------------------------
// Parity corpus
// ---------------------------------------------------------------------------

/// The pattern corpus exercised by the parity test (some deliberately absent,
/// some overlapping, some binary, some shorter than a trigram).
fn parity_patterns() -> Vec<Vec<u8>> {
    vec![
        b"abc".to_vec(),
        b"abcd".to_vec(),
        b"abcabc".to_vec(), // overlapping occurrences
        b"aaaa".to_vec(),   // overlapping run
        b"gfe".to_vec(),
        b"not present here".to_vec(),
        b"a".to_vec(), // shorter than a trigram -> scan
        b"ab".to_vec(),
        vec![0x00, 0x01, 0x02],       // binary
        vec![0xff, 0xfe, 0xfd, 0x00], // binary, absent
        b"abc nope".to_vec(),
    ]
}

#[test]
fn query_parity_indexed_vs_full_scan() {
    let dir = TempDir::new().unwrap();
    let mut ns = Namespace::init(dir.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let root = ns.root_inode();

    // A corpus with overlapping runs and binary content.
    let bodies: Vec<Vec<u8>> = vec![
        b"abcabcabc".to_vec(),
        b"zzzz".to_vec(),
        b"the abcd and abcabc here".to_vec(),
        vec![0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x03],
        b"aaaa bbbb aaaa".to_vec(),
        Vec::new(),
        text(4096, 7),
    ];
    let sub = ns.mkdir(root, b"d", 0o755, 0, 0).unwrap();
    for (i, body) in bodies.iter().enumerate() {
        mkdir_file(&mut ns, root, format!("f{i}").as_bytes(), body, 0o644);
        mkdir_file(&mut ns, sub, format!("s{i}").as_bytes(), body, 0o644);
    }
    ns.sync().unwrap();

    // Build the concealed index for every eligible file, then attach it.
    ns.enable_trigram(TrigramConfig {
        synchronous: true,
        ..Default::default()
    })
    .unwrap();
    let built = ns.index_trigram_eligible(None).unwrap();
    assert!(built.iter().any(|o| o.status == "published"));

    let mut cases = Vec::new();
    let mut all_identical = true;
    // The scan reference is a separate namespace with no trigram plane attached.
    let scan_ns = Namespace::open(dir.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    assert_eq!(scan_ns.root(), ns.root());
    for pat in parity_patterns() {
        let req = QueryRequest::new(ROOT_INODE, ns.root(), pat.clone());
        let indexed = indexed_query(&ns, &req);
        let scan = scan_query(&scan_ns, &req);
        let identical = indexed.matches == scan.matches;
        all_identical &= identical;
        assert!(
            identical,
            "parity failure for pattern {:?}: indexed {:?} vs scan {:?}",
            orfs::query::hex(&pat),
            indexed.matches,
            scan.matches
        );
        // The indexed run must have actually exercised candidate verification
        // (or fallen back), never bypassing content checks.
        cases.push(serde_json::json!({
            "pattern_hex": orfs::query::hex(&pat),
            "pattern_len": pat.len(),
            "matches": indexed.matches.len(),
            "identical": identical,
            "indexed": {
                "files_indexed": indexed.stats.files_indexed,
                "files_scanned": indexed.stats.files_scanned,
                "indexed_candidates": indexed.stats.indexed_candidates,
                "verified_matches": indexed.stats.verified_matches,
                "false_candidates": indexed.stats.false_candidates,
                "impossible_by_index": indexed.stats.impossible_by_index,
            },
            "scan": {
                "files_scanned": scan.stats.files_scanned,
                "content_bytes_read": scan.stats.content_bytes_read,
            },
            "indexed_content_bytes_read": indexed.stats.content_bytes_read,
        }));
    }
    assert!(all_identical);

    write_json(
        Path::new("evidence/correctness/query-parity.json"),
        &serde_json::json!({
            "schema": QUERY_SCHEMA,
            "title": "indexed vs full-scan byte-identical match parity",
            "pinned_root": ns.root(),
            "pattern_count": cases.len(),
            "all_identical": all_identical,
            "cases": cases,
        }),
    );
}

#[test]
fn index_never_reports_a_false_match() {
    // A source in which every pattern trigram exists, but the full pattern does
    // not: the index yields a candidate that must be rejected by verification.
    let source = b"abc bcd cde".to_vec();
    let dir = TempDir::new().unwrap();
    let mut ns = Namespace::init(dir.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let root = ns.root_inode();
    mkdir_file(&mut ns, root, b"t", &source, 0o644);
    ns.sync().unwrap();
    ns.enable_trigram(TrigramConfig {
        synchronous: true,
        ..Default::default()
    })
    .unwrap();
    ns.index_trigram_eligible(None).unwrap();

    let req = QueryRequest::new(ROOT_INODE, ns.root(), b"abcde".to_vec());
    let indexed = indexed_query(&ns, &req);
    let scan_ns = Namespace::open(dir.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    let scan = scan_query(&scan_ns, &req);
    assert!(indexed.matches.is_empty(), "index reported a false match");
    assert_eq!(indexed.matches, scan.matches);
    assert!(
        indexed.stats.indexed_candidates >= 1,
        "expected a candidate to verify"
    );
    assert!(
        indexed.stats.false_candidates >= 1,
        "candidate should have failed content verification"
    );
    assert_eq!(indexed.stats.files_indexed, 1);
}

#[test]
fn stale_version_is_rejected_and_reindex_restores_speed() {
    let dir = TempDir::new().unwrap();
    let mut ns = Namespace::init(dir.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let root = ns.root_inode();
    let f = mkdir_file(&mut ns, root, b"doc", b"hello world abcdef", 0o644);
    ns.sync().unwrap();
    ns.enable_trigram(TrigramConfig {
        synchronous: true,
        ..Default::default()
    })
    .unwrap();
    ns.index_trigram_eligible(None).unwrap();

    // The v1 structure serves v1 at the v1 root.
    let v1 = indexed_query(
        &ns,
        &QueryRequest::new(ROOT_INODE, ns.root(), b"abcdef".to_vec()),
    );
    assert_eq!(v1.stats.files_indexed, 1);
    drop(ns);

    // Mutate through a namespace with NO query plane, so no auto-refresh runs and
    // the committed structure genuinely goes stale.
    // Overwrite the whole content so the needle really disappears.
    let mut mutator =
        Namespace::open(dir.path(), OpenMode::ReadWrite, DurabilityMode::Ordered).unwrap();
    mutator
        .write_at(f, 0, b"replaced content without the needle at all")
        .unwrap();
    mutator.sync().unwrap();
    drop(mutator);

    // A read-only namespace attaches the now-stale structure; the query must
    // refuse it (version/root mismatch) and fall back to a full scan.
    let mut q = Namespace::open(dir.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    assert!(q.attach_trigram().unwrap() >= 1);
    let v2 = indexed_query(
        &q,
        &QueryRequest::new(ROOT_INODE, q.root(), b"abcdef".to_vec()),
    );
    assert!(v2.matches.is_empty(), "old pattern must be gone");
    assert_eq!(v2.stats.files_indexed, 0, "stale structure must be refused");
    assert!(v2.stats.files_scanned >= 1);
    drop(q);

    // Rebuild for the current version and confirm the accelerated path agrees
    // with an independent full-scan namespace.
    let mut b = Namespace::open(dir.path(), OpenMode::ReadWrite, DurabilityMode::Ordered).unwrap();
    b.enable_trigram(TrigramConfig {
        synchronous: true,
        ..Default::default()
    })
    .unwrap();
    b.write_at(f, 0, b"abcdef again").unwrap();
    b.sync().unwrap();
    b.index_trigram_eligible(Some(f)).unwrap();
    let cur = indexed_query(
        &b,
        &QueryRequest::new(ROOT_INODE, b.root(), b"abcdef".to_vec()),
    );
    assert!(cur.stats.files_indexed >= 1);
    drop(b);
    let s = Namespace::open(dir.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    let scan = scan_query(
        &s,
        &QueryRequest::new(ROOT_INODE, s.root(), b"abcdef".to_vec()),
    );
    assert_eq!(cur.matches, scan.matches);
}

#[test]
fn corrupt_payload_falls_back_to_scan() {
    let dir = TempDir::new().unwrap();
    let mut ns = Namespace::init(dir.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let root = ns.root_inode();
    mkdir_file(&mut ns, root, b"doc", b"findmeplease and more text", 0o644);
    ns.sync().unwrap();
    ns.enable_trigram(TrigramConfig {
        synchronous: true,
        ..Default::default()
    })
    .unwrap();
    ns.index_trigram_eligible(None).unwrap();

    // Tamper the only payload on disk.
    let trigram_dir = dir.path().join(".or_bloom").join("trigram");
    let payload = std::fs::read_dir(&trigram_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "tri").unwrap_or(false))
        .expect("a payload");
    let mut bytes = std::fs::read(&payload).unwrap();
    bytes[0] ^= 0xFF;
    std::fs::write(&payload, &bytes).unwrap();

    // A fresh namespace recovers the manifest but the payload digest fails, so
    // the query must fall back to a full scan with identical results.
    let mut ns2 = Namespace::open(dir.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    let recovered = ns2.attach_trigram().unwrap();
    assert_eq!(recovered, 0, "the corrupt payload must not be recovered");
    let req = QueryRequest::new(ROOT_INODE, ns2.root(), b"findmeplease".to_vec());
    let got = indexed_query(&ns2, &req);
    let scan = scan_query(&ns2, &req);
    assert!(!got.matches.is_empty());
    assert_eq!(got.matches, scan.matches);
    assert!(got.stats.files_scanned >= 1);
}

#[test]
fn limits_cancellation_and_streaming_order() {
    let dir = TempDir::new().unwrap();
    let mut ns = Namespace::init(dir.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let root = ns.root_inode();
    for i in 0..5 {
        mkdir_file(
            &mut ns,
            root,
            format!("f{i}").as_bytes(),
            b"aaa aaa aaa",
            0o644,
        );
    }
    ns.sync().unwrap();

    // Limit: 3 matches reported at most.
    let req = QueryRequest::new(ROOT_INODE, ns.root(), b"aaa".to_vec()).with_limit(3);
    let limited = ns.query(req).unwrap();
    assert_eq!(limited.matches.len(), 3);
    assert!(limited.stats.limit_reached);

    // Cancellation before the run yields no matches and the canceled flag.
    let cancel = AtomicBool::new(true);
    let req = QueryRequest::new(ROOT_INODE, ns.root(), b"aaa".to_vec());
    let stats = ns
        .query_stream(req, &cancel, |_| MatchFlow::Continue)
        .unwrap();
    assert!(stats.canceled);
    assert_eq!(stats.verified_matches, 0);

    // Streaming callback: matches arrive in (inode, offset) order and Stop halts.
    let req = QueryRequest::new(ROOT_INODE, ns.root(), b"aaa".to_vec());
    let cancel = AtomicBool::new(false);
    let mut seen: Vec<QueryMatch> = Vec::new();
    let stats = ns
        .query_stream(req, &cancel, |m| {
            seen.push(m.clone());
            if seen.len() == 2 {
                MatchFlow::Stop
            } else {
                MatchFlow::Continue
            }
        })
        .unwrap();
    assert_eq!(seen.len(), 2);
    assert_eq!(stats.verified_matches, 2);
    let mut sorted = seen.clone();
    sorted.sort_by_key(|m| (m.inode, m.offset));
    assert_eq!(seen, sorted);
}

#[test]
fn permission_enforcement_matches_the_read_rule() {
    let dir = TempDir::new().unwrap();
    let mut ns = Namespace::init(dir.path(), 1 << 20, DurabilityMode::Ordered).unwrap();
    let root = ns.root_inode();
    let secret = mkdir_file(&mut ns, root, b"secret", b"top secret data", 0o000);
    let public = mkdir_file(&mut ns, root, b"public", b"public secret data", 0o644);
    ns.sync().unwrap();
    let cred = Credential {
        uid: 1000,
        gid: 1000,
    };

    // Directly querying a file the credential may not read is an error.
    let req = QueryRequest::new(secret, ns.root(), b"secret".to_vec())
        .without_recursion()
        .with_credential(cred);
    assert!(ns.query(req).is_err());

    // A recursive search skips the unreadable file but finds the readable one.
    let req = QueryRequest::new(ROOT_INODE, ns.root(), b"secret".to_vec()).with_credential(cred);
    let result = ns.query(req).unwrap();
    assert!(result.stats.files_skipped_unreadable >= 1);
    assert!(result.matches.iter().all(|m| m.inode == public));

    // Root bypasses the check and sees both.
    let req = QueryRequest::new(ROOT_INODE, ns.root(), b"secret".to_vec());
    let result = ns.query(req).unwrap();
    assert!(result.matches.iter().any(|m| m.inode == secret));
}

#[test]
fn suffix_automaton_matches_brute_force() {
    let corpus = b"abracadabra bananarama".to_vec();
    let sam = SuffixAutomaton::build(&corpus);
    for pat in [
        &b"abra"[..],
        &b"banana"[..],
        &b"a"[..],
        &b"ra"[..],
        &b"zzz"[..],
        &b"cadab"[..],
    ] {
        let mut expect = Vec::new();
        for s in 0..=corpus.len().saturating_sub(pat.len()) {
            if &corpus[s..s + pat.len()] == pat {
                expect.push(s as u64);
            }
        }
        assert_eq!(sam.contains(pat), !expect.is_empty());
        assert_eq!(sam.count(pat), expect.len() as u64);
        assert_eq!(sam.match_positions(pat), expect);
    }
}

// ---------------------------------------------------------------------------
// Search-latency benchmark (indexed vs full scan) + construction + suffix cost
// ---------------------------------------------------------------------------

fn median(mut v: Vec<u128>) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

#[test]
fn search_latency_indexed_vs_scan() {
    const FILES: usize = 48;
    const FILE_BYTES: usize = 16 * 1024;
    let dir = TempDir::new().unwrap();
    let mut ns = Namespace::init(dir.path(), 8 << 20, DurabilityMode::Ordered).unwrap();
    let root = ns.root_inode();

    // Filler files over a tiny alphabet so most trigrams are uninformative; one
    // file carries a distinctive, selective pattern.
    let needle = b"NEEDLE-IN-THE-HAYSTACK".to_vec();
    let mut needle_file = 0u64;
    for i in 0..FILES {
        let mut body = text(FILE_BYTES, 1000 + i as u64);
        if i == FILES / 2 {
            let at = FILE_BYTES / 2;
            body[at..at + needle.len()].copy_from_slice(&needle);
            needle_file = mkdir_file(&mut ns, root, format!("f{i}").as_bytes(), &body, 0o644);
        } else {
            mkdir_file(&mut ns, root, format!("f{i}").as_bytes(), &body, 0o644);
        }
    }
    ns.sync().unwrap();
    let needle_file = needle_file;

    // Construction cost: index every eligible file.
    ns.enable_trigram(TrigramConfig {
        synchronous: true,
        ..Default::default()
    })
    .unwrap();
    let build_start = Instant::now();
    let outcomes = ns.index_trigram_eligible(None).unwrap();
    let build = build_start.elapsed();
    let published = outcomes.iter().filter(|o| o.status == "published").count();
    let payload_bytes: u64 = outcomes.iter().map(|o| o.payload_bytes).sum();
    let postings: u64 = outcomes.iter().map(|o| o.posting_count).sum();
    let payload_on_disk = orfs::stats::account_volume(dir.path())
        .unwrap()
        .bloom_subdir_bytes
        .get("trigram")
        .copied()
        .unwrap_or(0);

    let req = QueryRequest::new(ROOT_INODE, ns.root(), needle.clone());

    // Warm both paths, then measure.
    let _ = indexed_query(&ns, &req);
    let scan_ns = Namespace::open(dir.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    let _ = scan_query(&scan_ns, &req);

    const ITERS: usize = 25;
    let mut indexed_ns = Vec::with_capacity(ITERS);
    let mut scan_ns_times = Vec::with_capacity(ITERS);
    let mut indexed_bytes = 0u64;
    let mut scan_bytes = 0u64;
    let mut indexed_cands = 0u64;
    for _ in 0..ITERS {
        let t = Instant::now();
        let r = indexed_query(&ns, &req);
        indexed_ns.push(t.elapsed().as_nanos());
        assert!(r.matches.iter().any(|m| m.inode == needle_file));
        indexed_bytes = r.stats.content_bytes_read;
        indexed_cands = r.stats.indexed_candidates;

        let t = Instant::now();
        let r = scan_query(&scan_ns, &req);
        scan_ns_times.push(t.elapsed().as_nanos());
        scan_bytes = r.stats.content_bytes_read;
    }
    let indexed_median = median(indexed_ns.clone());
    let scan_median = median(scan_ns_times.clone());
    let speedup = scan_median as f64 / indexed_median.max(1) as f64;

    // The index must read strictly less content than the full scan. (It only
    // reads files that have a candidate; the scan reads every file.)
    assert!(
        indexed_bytes < scan_bytes,
        "indexed content read {indexed_bytes} should be < scan {scan_bytes}"
    );

    // Suffix-automaton metrics (research §11.2): construction and each operation.
    let suffix_src = text(64 * 1024, 9);
    let s = Instant::now();
    let sam = SuffixAutomaton::build(&suffix_src);
    let suffix_build = s.elapsed();
    let needle_pat = &needle;
    let q = Instant::now();
    let exists = sam.contains(needle_pat);
    let suffix_contains = q.elapsed();
    let q = Instant::now();
    let count = sam.count(needle_pat);
    let suffix_count = q.elapsed();
    let q = Instant::now();
    let positions = sam.match_positions(&suffix_src[0..8]); // a present 8-byte window
    let suffix_positions = q.elapsed();

    write_json(
        Path::new("evidence/performance/search-latency.json"),
        &serde_json::json!({
            "schema": "orfs.search-latency.v1",
            "note": "indexed and scan are both `orfs query` API runs; ordinary grep -r is NOT measured here (research §12.1)",
            "dataset": {
                "files": FILES,
                "bytes_per_file": FILE_BYTES,
                "needle_file_inode": needle_file,
                "pattern_hex": orfs::query::hex(&needle),
            },
            "indexed": {
                "iterations": ITERS,
                "median_ns": indexed_median,
                "min_ns": indexed_ns.iter().copied().min().unwrap(),
                "content_bytes_read": indexed_bytes,
                "indexed_candidates": indexed_cands,
            },
            "scan": {
                "iterations": ITERS,
                "median_ns": scan_median,
                "min_ns": scan_ns_times.iter().copied().min().unwrap(),
                "content_bytes_read": scan_bytes,
            },
            "speedup_scan_over_indexed": speedup,
            "construction": {
                "objects_published": published,
                "objects_attempted": outcomes.len(),
                "elapsed_ns": build.as_nanos(),
                "payload_bytes_total": payload_bytes,
                "payload_bytes_on_disk": payload_on_disk,
                "posting_count_total": postings,
            },
            "suffix": {
                "source_len": suffix_src.len(),
                "states": sam.state_count(),
                "transitions": sam.transition_count(),
                "memory_bytes_estimate": sam.memory_bytes(),
                "build_ns": suffix_build.as_nanos(),
                "contains_ns": suffix_contains.as_nanos(),
                "contains_result": exists,
                "count_ns": suffix_count.as_nanos(),
                "count_result": count,
                "positions_ns": suffix_positions.as_nanos(),
                "positions_len": positions.len(),
            },
        }),
    );
}

// ---------------------------------------------------------------------------
// Image probe (research §11.3): recognition/dimensions are real; surfaces are not
// ---------------------------------------------------------------------------

#[test]
fn image_recognition_is_by_content() {
    use orfs::image::{recognize, ImageFormat};
    // A PNG signature is recognised regardless of name; arbitrary bytes are not.
    let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    assert_eq!(recognize(&png), Some(ImageFormat::Png));
    assert_eq!(
        recognize(b"this is not an image, despite a .png name"),
        None
    );
}
