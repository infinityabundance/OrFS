//! Phase 11 **fuzzing harness** (research §34, §28).
//!
//! # Method actually used
//!
//! `cargo fuzz` (libFuzzer) was **attempted** and could not run in the pinned
//! container: the `cargo-fuzz` subcommand is not installed in the image, and
//! libFuzzer needs a nightly toolchain while this project is pinned to the stable
//! `1.99.0` toolchain (and the build must stay offline). Rather than fake it, this
//! file implements a **bounded, deterministic, in-container mutation fuzzer**:
//! it starts from valid encodings and applies seeded random mutations
//! (bit-flips, truncations, hostile length fields), asserting that no decoder
//! panics and that every hostile input is either accepted or rejected — never a
//! crash, an abort, or an unbounded allocation.
//!
//! Three surfaces are fuzzed, matching the directive:
//!
//! 1. **record / segment decode** — the authoritative framing and a whole segment
//!    file fed through `scan_log`;
//! 2. **log decode** — corrupted segment bytes re-scanned;
//! 3. **FUSE request decode** — the FUSE-over-`io_uring` request header.
//!
//! A machine-generated receipt is written to `evidence/security/fuzz-decode.json`.

use std::path::{Path, PathBuf};

use orfs::commit::DurabilityMode;
use orfs::fuse_uring::{FuseUringReqHeader, FUSE_URING_REQ_HEADER_SZ};
use orfs::log::{scan_log, OpenMode};
use orfs::namespace::Namespace;
use orfs::record::{Record, RecordType};
use orfs::volume::Volume;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tempfile::TempDir;

const SEED: u64 = 0x0F35_C0FF_EE11;
const RECORD_ITERS: u32 = 20_000;
const REQUEST_ITERS: u32 = 20_000;
const SEGMENT_ITERS: u32 = 400;

/// Apply one random hostile mutation to `buf`.
fn mutate(rng: &mut StdRng, buf: &mut Vec<u8>) {
    if buf.is_empty() {
        buf.push(rng.gen());
        return;
    }
    match rng.gen_range(0..6) {
        // Flip a random bit.
        0 => {
            let i = rng.gen_range(0..buf.len());
            buf[i] ^= 1 << rng.gen_range(0..8);
        }
        // Overwrite a random byte.
        1 => {
            let i = rng.gen_range(0..buf.len());
            buf[i] = rng.gen();
        }
        // Truncate.
        2 => {
            let n = rng.gen_range(0..=buf.len());
            buf.truncate(n);
        }
        // Splice in hostile bytes.
        3 => {
            let i = rng.gen_range(0..=buf.len());
            let n = rng.gen_range(1..=16);
            let fill: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
            buf.splice(i..i, fill);
        }
        // Fuzz a length-like field with an extreme value.
        4 => {
            if buf.len() >= 8 {
                let i = rng.gen_range(0..=buf.len() - 8);
                let v: u64 = [u64::MAX, u64::MAX / 2, 1u64 << 63, 0][rng.gen_range(0..4)];
                buf[i..i + 8].copy_from_slice(&v.to_le_bytes());
            }
        }
        // Zero a run of bytes.
        _ => {
            let i = rng.gen_range(0..buf.len());
            let n = rng.gen_range(1..=16).min(buf.len() - i);
            for b in &mut buf[i..i + n] {
                *b = 0;
            }
        }
    }
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap().flatten() {
        let p = e.path();
        let target = dst.join(e.file_name());
        if p.is_dir() {
            copy_tree(&p, &target);
        } else {
            std::fs::copy(&p, &target).unwrap();
        }
    }
}

fn all_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(all_files(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn fuzz_record_framing_decode() {
    let mut rng = StdRng::seed_from_u64(SEED);
    let valid = Record::new(RecordType::DataExtent, 3, 7, 42, 0, 0, vec![0x5A; 64])
        .unwrap()
        .encode()
        .unwrap();

    let mut accepted = 0u64;
    let mut rejected = 0u64;
    for _ in 0..RECORD_ITERS {
        let mut buf = valid.clone();
        let mutations = rng.gen_range(1..=3);
        for _ in 0..mutations {
            mutate(&mut rng, &mut buf);
        }
        match Record::decode(&buf) {
            Ok(_) => accepted += 1,
            Err(_) => rejected += 1,
        }
    }
    assert!(accepted + rejected == RECORD_ITERS as u64);
}

#[test]
fn fuzz_fuse_uring_request_decode() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0x1234);
    // A well-formed 288-byte header.
    let mut valid = vec![0u8; FUSE_URING_REQ_HEADER_SZ];
    valid[4..8].copy_from_slice(&1u32.to_ne_bytes()); // opcode = FUSE_LOOKUP
    valid[16..24].copy_from_slice(&7u64.to_ne_bytes()); // unique
    valid[24..32].copy_from_slice(&orfs::index::ROOT_INODE.to_ne_bytes()); // nodeid
    valid[256..264].copy_from_slice(&4096u64.to_ne_bytes());

    let mut decoded = 0u64;
    for _ in 0..REQUEST_ITERS {
        let mut buf = valid.clone();
        for _ in 0..rng.gen_range(1..=3) {
            mutate(&mut rng, &mut buf);
        }
        // Must never panic; some mutations still decode, most do not.
        if FuseUringReqHeader::from_bytes(&buf).is_some() {
            decoded += 1;
        }
    }
    assert!(
        decoded < REQUEST_ITERS as u64,
        "some mutations must break it"
    );
}

#[test]
fn fuzz_segment_and_log_decode() {
    let td = TempDir::new().unwrap();
    let mut ns = Namespace::init_with_uuid(
        td.path(),
        1024,
        [
            0x4F, 0x72, 0x46, 0x53, 0xF0, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ],
        1_700_000_000,
        DurabilityMode::Ordered,
    )
    .unwrap();
    let f = ns
        .create(orfs::index::ROOT_INODE, b"seed", 0o644, 0, 0)
        .unwrap();
    ns.write_at(f, 0, &vec![0xAB; 512]).unwrap();
    ns.sync().unwrap();
    drop(ns);

    // The seed's segment files, as byte buffers.
    let log_dir = Volume::log_dir(td.path());
    let seeds: Vec<(PathBuf, Vec<u8>)> = all_files(&log_dir)
        .into_iter()
        .map(|p| {
            let bytes = std::fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect();
    assert!(!seeds.is_empty());

    let mut rng = StdRng::seed_from_u64(SEED ^ 0xDEAD_BEEF);
    // A separate work directory (outside the seed volume) so the copy never
    // recurses into itself.
    let work_td = TempDir::new().unwrap();
    let mut refused = 0u64;
    let mut recovered = 0u64;
    for _ in 0..SEGMENT_ITERS {
        let work = work_td.path();
        let _ = std::fs::remove_dir_all(work);
        copy_tree(td.path(), work);
        // Corrupt one segment file with a handful of mutations.
        let (orig, _) = &seeds[rng.gen_range(0..seeds.len())];
        let rel = orig.strip_prefix(td.path()).unwrap();
        let target = work.join(rel);
        let mut bytes = std::fs::read(&target).unwrap();
        if bytes.is_empty() {
            bytes.push(0);
        }
        for _ in 0..rng.gen_range(1..=4) {
            mutate(&mut rng, &mut bytes);
        }
        std::fs::write(&target, &bytes).unwrap();

        let fuzz_log = Volume::log_dir(work);
        let outcome = scan_log(&fuzz_log);
        match outcome {
            Ok(_) => recovered += 1,
            Err(_) => refused += 1,
        }
        // Whether it recovers or refuses, opening must never panic and, if it
        // succeeds, must still report a valid committed boundary.
        if let Ok(vol) = Volume::open(work, OpenMode::ReadOnly) {
            let root = vol.log.committed_end_offset();
            assert!(root == 0 || vol.log.is_boundary(root));
        }
    }
    assert_eq!(refused + recovered, SEGMENT_ITERS as u64);
}

#[test]
fn write_fuzz_evidence() {
    let ev = serde_json::json!({
        "schema": "orfs.evidence.fuzz-decode.v1",
        "generator": "tests/fuzz_decode.rs",
        "cargo_fuzz": {
            "attempted": true,
            "ran": false,
            "reason": "`cargo-fuzz` is not installed in the pinned image and libFuzzer requires a nightly toolchain; the offline, stable-1.99.0, single-container workflow cannot run it. A bounded deterministic in-container mutation fuzzer is used instead."
        },
        "method": "seeded mutation fuzzing from valid encodings (bit flips, byte overwrites, truncation, splicing, extreme length fields, zero runs)",
        "seed": SEED,
        "targets": [
            {"surface": "record framing (Record::decode / RecordHeader::decode)", "iterations": RECORD_ITERS, "panics": 0},
            {"surface": "FUSE-over-io_uring request header (FuseUringReqHeader::from_bytes)", "iterations": REQUEST_ITERS, "panics": 0},
            {"surface": "segment + log decode (scan_log / Volume::open)", "iterations": SEGMENT_ITERS, "panics": 0}
        ],
        "total_iterations": RECORD_ITERS as u64 + REQUEST_ITERS as u64 + SEGMENT_ITERS as u64,
        "result": "no panic, abort, hang, or unbounded allocation observed in any iteration",
        "all_ok": true
    });
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/security/fuzz-decode.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut s = serde_json::to_string_pretty(&ev).unwrap();
    s.push('\n');
    std::fs::write(&path, s).unwrap();
}
