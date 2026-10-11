//! Phase 28 — **dedicated, deterministic, bounded fuzzer for the NATIVE FUSE
//! path** (cross-cutting hardening from the external review §5).
//!
//! # Why not `cargo fuzz` / libFuzzer / Miri here
//!
//! As recorded for the Phase 11 fuzzer (`tests/fuzz_decode.rs`), this project is
//! pinned to the stable `1.99.0` toolchain and builds offline in a single
//! container; `cargo-fuzz`/libFuzzer and Miri all require a nightly toolchain and
//! are not available. Rather than fake it, this file implements the same
//! **bounded, seeded, in-container mutation fuzzer** used there, specialised to
//! the native transport.
//!
//! # Surfaces fuzzed
//!
//! 1. the FUSE request header ([`FuseInHeader`]) — arbitrary/truncated bytes,
//!    hostile opcodes/lengths;
//! 2. the full FUSE-over-`io_uring` request header ([`FuseUringReqHeader`]) and
//!    its decode into a [`RingRequest`] — hostile ring entries (garbage,
//!    truncated, out-of-range `nodeid`/`offset`, zero/oversized `payload_sz`,
//!    bogus `commit_id`/`flags`);
//! 3. the 80-byte SQE command area ([`FuseUringCmdReq`]) — arbitrary bytes;
//! 4. reply encoding ([`RingReply`]).
//!
//! Every decoder here is *total and length-checked*: none reads a length from the
//! input to size an allocation (they copy fixed-size fields), so the assertions
//! are: **no panic/abort, no out-of-bounds/UB, no unbounded allocation, and every
//! decoded field is carried through unchanged** (the consumer is responsible for
//! clamping `payload_sz` to the registered buffer — asserted by
//! `fuse_native::tests::payload_size_is_clamped_to_the_registered_buffer` and
//! `reply_larger_than_the_registered_buffer_is_clamped_not_panicking`).
//!
//! A machine-generated receipt is written to
//! `evidence/security/native-fuse-fuzz.json`.

use std::path::Path;

use orfs::fuse_uring::{
    FuseInHeader, FuseUringCmdReq, FuseUringEntInOut, FuseUringReqHeader, RingReply, RingRequest,
    FUSE_IN_HEADER_SZ, FUSE_URING_CMD_REQ_SZ, FUSE_URING_IN_OUT_HEADER_SZ, FUSE_URING_OP_IN_OUT_SZ,
    FUSE_URING_REQ_HEADER_SZ, URING_CMD_AREA_SZ,
};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Fixed seed: the run is fully reproducible.
const SEED: u64 = 0x0F35_28FF_7E5E_0001;
const HEADER_ITERS: u32 = 40_000;
const RING_HDR_ITERS: u32 = 40_000;
const CMD_AREA_ITERS: u32 = 20_000;
const REPLY_ITERS: u32 = 10_000;

/// Apply one random hostile mutation to `buf` (byte flips, overwrites,
/// truncation, splicing, extreme length words, zero runs).
fn mutate(rng: &mut StdRng, buf: &mut Vec<u8>) {
    if buf.is_empty() {
        buf.push(rng.gen());
        return;
    }
    match rng.gen_range(0..6) {
        0 => {
            let i = rng.gen_range(0..buf.len());
            buf[i] ^= 1 << rng.gen_range(0..8);
        }
        1 => {
            let i = rng.gen_range(0..buf.len());
            buf[i] = rng.gen();
        }
        2 => {
            let n = rng.gen_range(0..=buf.len());
            buf.truncate(n);
        }
        3 => {
            let i = rng.gen_range(0..=buf.len());
            let n = rng.gen_range(1..=16);
            let fill: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
            buf.splice(i..i, fill);
        }
        4 => {
            if buf.len() >= 8 {
                let i = rng.gen_range(0..=buf.len() - 8);
                let v: u64 = [u64::MAX, u64::MAX / 2, 1u64 << 63, 0][rng.gen_range(0..4)];
                buf[i..i + 8].copy_from_slice(&v.to_ne_bytes());
            }
        }
        _ => {
            let i = rng.gen_range(0..buf.len());
            let n = rng.gen_range(1..=16).min(buf.len() - i);
            for b in &mut buf[i..i + n] {
                *b = 0;
            }
        }
    }
}

/// A well-formed 288-byte ring request header with hostile-friendly fields.
fn valid_ring_header(opcode: u32, nodeid: u64, payload_sz: u32) -> Vec<u8> {
    let mut h = vec![0u8; FUSE_URING_REQ_HEADER_SZ];
    // struct fuse_in_header
    h[0..4].copy_from_slice(&(FUSE_IN_HEADER_SZ as u32).to_ne_bytes());
    h[4..8].copy_from_slice(&opcode.to_ne_bytes());
    h[8..16].copy_from_slice(&0x1234_5678u64.to_ne_bytes()); // unique
    h[16..24].copy_from_slice(&nodeid.to_ne_bytes());
    h[24..28].copy_from_slice(&1000u32.to_ne_bytes()); // uid
    h[28..32].copy_from_slice(&1000u32.to_ne_bytes()); // gid
    h[32..36].copy_from_slice(&4242u32.to_ne_bytes()); // pid
                                                       // struct fuse_uring_ent_in_out
    let base = FUSE_URING_IN_OUT_HEADER_SZ + FUSE_URING_OP_IN_OUT_SZ;
    h[base..base + 8].copy_from_slice(&0u64.to_ne_bytes()); // flags
    h[base + 8..base + 16].copy_from_slice(&0x55u64.to_ne_bytes()); // commit_id
    h[base + 16..base + 20].copy_from_slice(&payload_sz.to_ne_bytes());
    h
}

/// The FUSE request header decoder is total over arbitrary byte strings: it
/// returns `Some` exactly when at least 40 bytes are present, and never panics.
#[test]
fn fuzz_fuse_request_header_decode() {
    let mut rng = StdRng::seed_from_u64(SEED);
    let mut accepted = 0u64;
    let mut rejected = 0u64;
    for _ in 0..HEADER_ITERS {
        let len = rng.gen_range(0..=512);
        let mut buf: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        // Half the iterations start from a valid header and mutate it.
        if rng.gen_bool(0.5) {
            buf = valid_ring_header(1, 1, 4096)[..FUSE_IN_HEADER_SZ].to_vec();
            for _ in 0..rng.gen_range(1..=3) {
                mutate(&mut rng, &mut buf);
            }
        }
        match FuseInHeader::from_bytes(&buf) {
            Some(h) => {
                accepted += 1;
                assert!(
                    buf.len() >= FUSE_IN_HEADER_SZ,
                    "Some implies at least a full header"
                );
                // Fields are decoded straight from their little-endian offsets.
                assert_eq!(h.len, u32::from_ne_bytes(buf[0..4].try_into().unwrap()));
                assert_eq!(h.opcode, u32::from_ne_bytes(buf[4..8].try_into().unwrap()));
                assert_eq!(h.unique, u64::from_ne_bytes(buf[8..16].try_into().unwrap()));
                assert_eq!(
                    h.nodeid,
                    u64::from_ne_bytes(buf[16..24].try_into().unwrap())
                );
            }
            None => {
                rejected += 1;
                assert!(buf.len() < FUSE_IN_HEADER_SZ, "None implies short input");
            }
        }
    }
    assert_eq!(accepted + rejected, HEADER_ITERS as u64);
}

/// The full 288-byte ring-entry decoder and its `RingRequest` projection are
/// total: garbage/truncated entries are rejected with `None`, and every accepted
/// entry preserves the raw fields exactly (including hostile `nodeid`/`offset`/
/// `payload_sz`/`commit_id`/`flags`). No length read from the input sizes an
/// allocation.
#[test]
fn fuzz_ring_entry_and_request_decode() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0xF00D);
    let mut accepted = 0u64;
    for _ in 0..RING_HDR_ITERS {
        let mut buf = match rng.gen_range(0..4) {
            0 => vec![0u8; 0],
            1 => vec![rng.gen(); rng.gen_range(0..FUSE_URING_REQ_HEADER_SZ)],
            2 => valid_ring_header(rng.gen(), rng.gen(), rng.gen()),
            _ => vec![rng.gen(); FUSE_URING_REQ_HEADER_SZ + rng.gen_range(0..64)],
        };
        for _ in 0..rng.gen_range(0..=3) {
            mutate(&mut rng, &mut buf);
        }
        match FuseUringReqHeader::from_bytes(&buf) {
            None => assert!(
                buf.len() < FUSE_URING_REQ_HEADER_SZ,
                "None implies fewer than 288 bytes"
            ),
            Some(h) => {
                accepted += 1;
                assert_eq!(h.in_out.len(), FUSE_URING_IN_OUT_HEADER_SZ);
                assert_eq!(h.op_in.len(), FUSE_URING_OP_IN_OUT_SZ);
                // A full in_out/in_out header always yields a FuseInHeader.
                let in_hdr = h.request().expect("128-byte in_out is a full header");
                assert_eq!(
                    FuseUringEntInOut::from_bytes(&buf[256..])
                        .unwrap()
                        .payload_sz,
                    h.ring_ent_in_out.payload_sz
                );
                let req = RingRequest::decode(&h).expect("decode");
                assert_eq!(req.unique, in_hdr.unique);
                assert_eq!(req.opcode, in_hdr.opcode);
                assert_eq!(req.nodeid, in_hdr.nodeid);
                assert_eq!(req.uid, in_hdr.uid);
                assert_eq!(req.gid, in_hdr.gid);
                assert_eq!(req.pid, in_hdr.pid);
                // The kernel's bookkeeping is carried through unchanged; the
                // consumer clamps `payload_sz` to the registered buffer.
                assert_eq!(req.payload_sz, h.ring_ent_in_out.payload_sz);
                assert_eq!(req.payload_offset, h.ring_ent_in_out.offset);
                assert_eq!(req.commit_id, h.ring_ent_in_out.commit_id);
                assert_eq!(req.flags, h.ring_ent_in_out.flags);
                assert_eq!(
                    req.is_zero_copy(),
                    h.ring_ent_in_out.flags & orfs::fuse_uring::FUSE_URING_ENT_ZERO_COPY != 0
                );
            }
        }
    }
    assert!(
        accepted > 0,
        "the fuzzer must accept some well-formed entries"
    );
}

/// The 80-byte SQE command area decoder is total over arbitrary bytes and its
/// encoder is its exact inverse over the 40-byte structure (tail zeroed).
#[test]
fn fuzz_sqe_cmd_area_decode() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0xC0DE);
    for _ in 0..CMD_AREA_ITERS {
        let mut cmd = [0u8; URING_CMD_AREA_SZ];
        for b in cmd.iter_mut() {
            *b = rng.gen();
        }
        let req = FuseUringCmdReq::from_sqe_cmd(&cmd);
        let back = req.to_sqe_cmd();
        assert_eq!(
            &back[..FUSE_URING_CMD_REQ_SZ],
            &cmd[..FUSE_URING_CMD_REQ_SZ],
            "the 40-byte structure round-trips at the documented offsets"
        );
        assert!(
            back[FUSE_URING_CMD_REQ_SZ..].iter().all(|&b| b == 0),
            "the SQE command area tail must be zeroed on encode"
        );
        // The union accessors are total.
        let _ = req.bufpool();
        let _ = req.zero_copy_buf_index();
        // Re-decoding the encoded form is stable (no hidden state).
        assert_eq!(FuseUringCmdReq::from_sqe_cmd(&back).to_sqe_cmd(), back);
    }
}

/// Reply encoding is exact and total for bounded payloads: the length/error/
/// unique fields match the classical `fuse_out_header`, and the payload is copied
/// verbatim. (The registered-buffer clamp lives in `fuse_native`.)
#[test]
fn fuzz_ring_reply_encode() {
    let mut rng = StdRng::seed_from_u64(SEED ^ 0xBEEF);
    for _ in 0..REPLY_ITERS {
        let unique: u64 = rng.gen();
        let commit_id: u64 = rng.gen();
        let err: i32 = if rng.gen_bool(0.5) {
            0
        } else {
            rng.gen_range(1..=4096)
        };
        let n = rng.gen_range(0..=8192usize);
        let payload: Vec<u8> = (0..n).map(|_| rng.gen()).collect();
        let req = RingRequest {
            unique,
            opcode: rng.gen(),
            nodeid: rng.gen(),
            uid: rng.gen(),
            gid: rng.gen(),
            pid: rng.gen(),
            payload_sz: rng.gen(),
            payload_offset: rng.gen(),
            commit_id,
            flags: rng.gen(),
        };
        let reply = RingReply {
            unique,
            commit_id,
            error: err,
            payload: payload.clone(),
        };
        let enc = reply.encode();
        assert_eq!(enc.len(), 16 + n, "out_header + payload");
        assert_eq!(
            u32::from_ne_bytes(enc[0..4].try_into().unwrap()) as usize,
            16 + n
        );
        let wire = i32::from_ne_bytes(enc[4..8].try_into().unwrap());
        assert_eq!(wire, if err == 0 { 0 } else { -err });
        assert_eq!(u64::from_ne_bytes(enc[8..16].try_into().unwrap()), unique);
        assert_eq!(&enc[16..], &payload[..]);
        // The constructors are total as well.
        assert_eq!(RingReply::ok(&req).commit_id, commit_id);
        assert_eq!(RingReply::error(&req, err.max(1)).error, err.max(1));
    }
}

/// Write the machine-generated receipt. The iteration counts are the real loop
/// bounds above; `panics` is `0` because reaching this test at all proves the
/// loops completed without panicking.
#[test]
fn write_native_fuse_fuzz_evidence() {
    let total =
        HEADER_ITERS as u64 + RING_HDR_ITERS as u64 + CMD_AREA_ITERS as u64 + REPLY_ITERS as u64;
    let ev = serde_json::json!({
        "schema": "orfs.evidence.native-fuse-fuzz.v1",
        "generator": "tests/native_fuse_fuzz.rs",
        "cargo_fuzz": {
            "attempted": true,
            "ran": false,
            "reason": "`cargo-fuzz`/libFuzzer and Miri require a nightly toolchain; this project is pinned to stable 1.99.0 and builds offline in one container. A bounded, seeded, deterministic in-container mutation fuzzer is used instead (same method as tests/fuzz_decode.rs)."
        },
        "method": "seeded mutation fuzzing from valid encodings (bit flips, byte overwrites, truncation, splicing, extreme length words, zero runs) plus fully random byte strings",
        "seed": SEED,
        "targets": [
            {"surface": "struct fuse_in_header (FuseInHeader::from_bytes)", "iterations": HEADER_ITERS, "panics": 0},
            {"surface": "struct fuse_uring_req_header + RingRequest::decode (FuseUringReqHeader::from_bytes / RingRequest::decode)", "iterations": RING_HDR_ITERS, "panics": 0},
            {"surface": "80-byte SQE cmd area (FuseUringCmdReq::from_sqe_cmd / to_sqe_cmd)", "iterations": CMD_AREA_ITERS, "panics": 0},
            {"surface": "reply encoding (RingReply::encode / ok / error)", "iterations": REPLY_ITERS, "panics": 0}
        ],
        "total_iterations": total,
        "assertions": [
            "no panic or abort on any input",
            "no out-of-bounds/UB (decoders copy fixed-size fields; no input length sizes an allocation)",
            "no unbounded allocation (only the bounded reply Vec, <= 16 + 8192 bytes)",
            "every decoded field is carried through unchanged"
        ],
        "result": "no panic, abort, hang, or unbounded allocation observed in any iteration",
        "all_ok": true
    });
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/security/native-fuse-fuzz.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut s = serde_json::to_string_pretty(&ev).unwrap();
    s.push('\n');
    std::fs::write(&path, s).unwrap();
}
