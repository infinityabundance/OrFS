//! Benchmark harness (dependency-free for Phase 0; extended by later phases).
//!
//! Built with `harness = false`, so this file owns `main`. It measures the
//! EKBLOOM machine round-trip and reports throughput to stdout. Later phases
//! add FUSE/io_uring/manifestation workloads; the JSON evidence writer lives
//! under `evidence/performance/`.

use std::time::Instant;

use ekbloom::{OrMachine, NL2};

fn bench_roundtrip(len: usize, iters: u32) {
    let src: Vec<u8> = (0..len).map(|i| (i * 131 + 7) as u8).collect();
    let start = Instant::now();
    let mut acc = 0u64;
    for _ in 0..iters {
        let core = NL2.encode(&src).expect("encode");
        let out = NL2.decode(&core, src.len() as u64).expect("decode");
        acc = acc.wrapping_add(out.len() as u64);
    }
    let elapsed = start.elapsed();
    let bytes = (len as u64) * (iters as u64) * 2; // encode + decode
    let secs = elapsed.as_secs_f64();
    let mbps = (bytes as f64) / secs / 1e6;
    println!(
        "ekbloom roundtrip len={len:>8} iters={iters:>6} acc={acc} {:.1} MB/s ({secs:.3}s)",
        mbps
    );
}

fn main() {
    bench_roundtrip(1024, 20_000);
    bench_roundtrip(64 * 1024, 2_000);
    bench_roundtrip(1024 * 1024, 256);
}
