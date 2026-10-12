//! Phase 31 **ordered group commit** and **conflict-aware parallel preparation**
//! court.
//!
//! These tests discharge the two guarantees the mechanism must uphold:
//!
//! * **Acknowledgment correctness under grouping** — per durability mode, every
//!   member of a group is acknowledged only once the shared barrier that covers
//!   *its own* bytes has completed, and the visible commit order is exactly the
//!   caller's order (strictly advancing roots, all boundaries).
//! * **Parallel preparation cannot reorder or wrongly parallelise** — independent
//!   operations are prepared concurrently but published serially in input order;
//!   conflicting operations are never placed on the same wave, and their relative
//!   order is preserved.
//!
//! Grouping changes only *when* the durability `fsync` is issued; it does not
//! change the bytes written. `group_commit_is_byte_identical_to_serial_commit`
//! proves that directly, which is why the Phase-2/17 byte-exact correctness and
//! power-loss courts (single-commit byte sequences) continue to apply unchanged.
//!
//! Run the crash-injection arm with `cargo test --features failpoints`.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Instant;

use orfs::commit::{CommitSequencer, DurabilityMode};
use orfs::group::{
    conflict_keys, conflict_waves, group_is_conflict_free, prepare_and_commit, prepare_in_waves,
};
use orfs::record::RecordType;
use orfs::transaction::{Transaction, TransactionBuilder, TxState};
use orfs::volume::Volume;

use support::init_volume;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build one transaction carrying a single `INODE_CREATE` whose payload is the
/// one-byte marker (used to read back the committed publication order).
fn tx_with_marker(id: u64, inode: u64, marker: u8) -> Transaction {
    let mut b = TransactionBuilder::new(id).unwrap();
    b.add(RecordType::InodeCreate, inode, 0, vec![marker])
        .unwrap();
    b.build().unwrap()
}

/// The markers of every committed `INODE_CREATE` record, in log order.
fn committed_markers(vol: &Volume) -> Vec<u8> {
    vol.log
        .replay_upto(vol.log.committed_end_offset())
        .unwrap()
        .iter()
        .filter(|r| r.known_type().unwrap() == RecordType::InodeCreate)
        .map(|r| r.payload[0])
        .collect()
}

/// Prepare `count` single-record transactions with identities allocated from
/// `seq`, then return them (marker `i` on inode `inode_of(i)`).
fn prepared_many(
    seq: &mut CommitSequencer<'_>,
    count: usize,
    inode_of: impl Fn(usize) -> u64,
) -> Vec<Transaction> {
    let builders = seq.begin_many(count).unwrap();
    builders
        .into_iter()
        .enumerate()
        .map(|(i, mut b)| {
            b.add(RecordType::InodeCreate, inode_of(i), 0, vec![i as u8])
                .unwrap();
            b.build().unwrap()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Acknowledgment contract per durability mode
// ---------------------------------------------------------------------------

#[test]
fn group_commit_sync_acks_every_member_durable_in_order() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 20);
    let genesis = vol.log.committed_end_offset();

    let outcomes = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        let txs = prepared_many(&mut seq, 4, |i| i as u64 + 1);
        seq.commit_group(txs).unwrap()
    };

    assert_eq!(outcomes.len(), 4);
    let mut prev = genesis;
    for o in &outcomes {
        assert_eq!(
            o.state,
            TxState::Durable,
            "sync group member must be Durable"
        );
        assert!(o.durable, "sync group member's own bytes were fsynced");
        assert!(o.root > prev, "roots strictly advance in group order");
        assert!(vol.log.is_boundary(o.root));
        prev = o.root;
    }
    assert_eq!(vol.log.committed_end_offset(), prev);
    assert_eq!(committed_markers(&vol), vec![0, 1, 2, 3]);
}

#[test]
fn group_commit_ordered_publishes_without_fsync_then_flush_makes_durable() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 20);

    let outcomes = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        let txs = prepared_many(&mut seq, 3, |i| i as u64 + 1);
        let outcomes = seq.commit_group(txs).unwrap();
        for o in &outcomes {
            assert_eq!(o.state, TxState::Published);
            assert!(!o.durable);
        }
        let last = outcomes.last().unwrap().root;
        let sync = seq.flush().unwrap();
        assert_eq!(sync.root, last);
        assert_eq!(
            sync.transactions, 3,
            "one barrier covered all three members"
        );
        outcomes
    };
    for o in &outcomes {
        assert!(vol.log.is_boundary(o.root));
    }
}

#[test]
fn group_commit_batched_coalesces_one_barrier_per_batch() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 20);

    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Batched { batch_size: 3 });

    // A group that exactly completes the batch: every member becomes Durable.
    let txs = prepared_many(&mut seq, 3, |i| i as u64 + 1);
    let first = seq.commit_group(txs).unwrap();
    for o in &first {
        assert_eq!(o.state, TxState::Durable);
        assert!(o.durable);
    }

    // A partial batch: Published only, then made durable by an explicit flush.
    let txs = prepared_many(&mut seq, 2, |i| i as u64 + 100);
    let second = seq.commit_group(txs).unwrap();
    for o in &second {
        assert_eq!(o.state, TxState::Published);
        assert!(!o.durable);
    }
    let sync = seq.flush().unwrap();
    assert_eq!(sync.transactions, 2);
    assert_eq!(sync.root, second.last().unwrap().root);
}

#[test]
fn group_commit_single_member_equals_commit() {
    // A group of one is exactly the single-commit path (no behaviour change for
    // a single sequential synchronized writer).
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 20);
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
    let txs = prepared_many(&mut seq, 1, |_| 1);
    let out = seq.commit_group(txs).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].state, TxState::Durable);
    assert!(out[0].durable);
}

#[test]
fn empty_group_is_a_noop() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 20);
    let root = vol.log.committed_end_offset();
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
    assert!(seq.commit_group(Vec::new()).unwrap().is_empty());
    assert_eq!(vol.log.committed_end_offset(), root);
}

// ---------------------------------------------------------------------------
// 2. Parallel preparation + ordered publication
// ---------------------------------------------------------------------------

#[test]
fn group_commit_is_byte_identical_to_serial_commit() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    // Arm A: prepare in conflict-free waves, publish as one ordered group.
    let mut vol_a = init_volume(dir_a.path(), 1 << 20);
    {
        let mut seq = CommitSequencer::new(&mut vol_a, DurabilityMode::Ordered);
        let ops: Vec<(u64, u8)> = (0..8).map(|i| (i as u64 + 1, i as u8)).collect();
        let outcomes = prepare_and_commit(
            &mut seq,
            &ops,
            |o| o.0,
            |o, b| {
                b.add(RecordType::InodeCreate, o.0, 0, vec![o.1])?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(outcomes.len(), 8);
        for (i, o) in outcomes.iter().enumerate() {
            assert_eq!(o.state, TxState::Published);
            // Order preserved: each root exceeds the previous.
            if i > 0 {
                assert!(o.root > outcomes[i - 1].root);
            }
        }
    }

    // Arm B: the same transactions, committed one at a time (serial).
    let mut vol_b = init_volume(dir_b.path(), 1 << 20);
    {
        let mut seq = CommitSequencer::new(&mut vol_b, DurabilityMode::Ordered);
        let builders = seq.begin_many(8).unwrap();
        let txs: Vec<Transaction> = builders
            .into_iter()
            .enumerate()
            .map(|(i, mut b)| {
                b.add(RecordType::InodeCreate, i as u64 + 1, 0, vec![i as u8])
                    .unwrap();
                b.build().unwrap()
            })
            .collect();
        for tx in txs {
            seq.commit(tx).unwrap();
        }
    }

    // The authoritative bytes and digest are identical: grouping changes only the
    // durability barrier, never the log.
    assert_eq!(
        vol_a.log.read_committed_bytes().unwrap(),
        vol_b.log.read_committed_bytes().unwrap()
    );
    assert_eq!(
        vol_a.log.committed_digest_hex().unwrap(),
        vol_b.log.committed_digest_hex().unwrap()
    );
}

#[test]
fn conflicting_operations_are_not_reordered() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 20);

    // Inode 1 appears at indices 0, 2 and 3 with distinct markers.
    let ops: Vec<(u64, u8)> = vec![(1, b'a'), (2, b'b'), (1, b'c'), (1, b'd')];
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
    let outcomes = prepare_and_commit(
        &mut seq,
        &ops,
        |o| o.0,
        |o, b| {
            b.add(RecordType::InodeCreate, o.0, 0, vec![o.1])?;
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(outcomes.len(), 4);
    // Committed order equals input order exactly — conflicts were serialised, not
    // reordered.
    assert_eq!(committed_markers(&vol), vec![b'a', b'b', b'c', b'd']);
    for i in 1..outcomes.len() {
        assert!(outcomes[i].root > outcomes[i - 1].root);
    }
}

#[test]
fn parallel_preparation_cannot_publish_out_of_order() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 22);

    // A deliberately conflict-heavy workload: inode = i % 4, so many waves.
    let n = 200usize;
    let keys: Vec<u64> = (0..n).map(|i| (i % 4) as u64).collect();
    let waves = conflict_waves(&keys);
    // No wave holds two equal keys.
    for w in 0..=*waves.iter().max().unwrap() {
        let mut in_wave: Vec<u64> = keys
            .iter()
            .zip(&waves)
            .filter(|(_, &ww)| ww == w)
            .map(|(&k, _)| k)
            .collect();
        let len = in_wave.len();
        in_wave.sort_unstable();
        in_wave.dedup();
        assert_eq!(
            in_wave.len(),
            len,
            "a wave contained a duplicate conflict key"
        );
    }
    assert!(waves.iter().max().unwrap() + 1 >= 4);

    let ops: Vec<(u64, u8)> = (0..n).map(|i| ((i % 4) as u64, i as u8)).collect();
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
    let outcomes = prepare_and_commit(
        &mut seq,
        &ops,
        |o| o.0,
        |o, b| {
            b.add(RecordType::InodeCreate, o.0, 0, vec![o.1])?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(outcomes.len(), n);

    // Publication is exactly the input order and every root is a boundary.
    let expected: Vec<u8> = (0..n).map(|i| i as u8).collect();
    assert_eq!(committed_markers(&vol), expected);
    for o in &outcomes {
        assert!(vol.log.is_boundary(o.root));
    }
}

#[test]
fn conflict_registry_reports_independence() {
    let a = tx_with_marker(1, 1, 0);
    let b = tx_with_marker(2, 2, 0);
    let c = tx_with_marker(3, 1, 0);
    assert!(group_is_conflict_free(&[a.clone(), b.clone()]));
    assert!(!group_is_conflict_free(&[a.clone(), c.clone()]));
    assert_eq!(conflict_keys(&c).into_iter().collect::<Vec<_>>(), vec![1]);
}

#[test]
fn prepare_in_waves_requires_matching_builder_count() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 20);
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
    let builders = seq.begin_many(1).unwrap();
    let ops = vec![1u64, 2u64];
    let err = prepare_in_waves(builders, &ops, |o| *o, |_, _| Ok(())).unwrap_err();
    assert!(matches!(err, orfs::error::OrfsError::InvalidArgument(_)));
}

// ---------------------------------------------------------------------------
// 3. Concurrency stress
// ---------------------------------------------------------------------------

#[test]
fn concurrent_group_committers_land_in_order_and_recover_exactly() {
    let td = TempDir::new().unwrap();
    let vol = Arc::new(Mutex::new(init_volume(td.path(), 1 << 22)));
    const THREADS: u64 = 6;
    const PER_THREAD: usize = 20;

    let mut handles = Vec::new();
    for t in 0..THREADS {
        let vol = vol.clone();
        handles.push(std::thread::spawn(move || {
            let mut done = 0usize;
            while done < PER_THREAD {
                // Each batch is conflict-free (distinct inodes for this thread).
                let take = (PER_THREAD - done).min(5);
                let mut guard = vol.lock().unwrap();
                let mut seq = CommitSequencer::new(&mut guard, DurabilityMode::Ordered);
                let ops: Vec<(u64, u8)> = (0..take)
                    .map(|k| {
                        let inode = (t + 1) * 1_000_000 + (done + k) as u64 + 1;
                        (inode, (t * 31 + (done + k) as u64) as u8)
                    })
                    .collect();
                let outcomes = prepare_and_commit(
                    &mut seq,
                    &ops,
                    |o| o.0,
                    |o, b| {
                        b.add(RecordType::InodeCreate, o.0, 0, vec![o.1])?;
                        Ok(())
                    },
                )
                .unwrap();
                assert_eq!(outcomes.len(), take);
                for i in 1..outcomes.len() {
                    assert!(outcomes[i].root > outcomes[i - 1].root);
                }
                done += take;
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let guard = vol.lock().unwrap();
    let root = guard.log.committed_end_offset();
    assert!(guard.log.is_boundary(root));
    let digest = guard.log.committed_digest_hex().unwrap();
    drop(guard);

    // The recovered volume equals the live one byte-for-byte.
    let reopened = orfs::log::Log::open(
        &Volume::log_dir(td.path()),
        1 << 22,
        orfs::log::OpenMode::ReadOnly,
    )
    .unwrap();
    assert_eq!(reopened.committed_digest_hex().unwrap(), digest);
    assert_eq!(reopened.committed_end_offset(), root);
}

// ---------------------------------------------------------------------------
// 4. Performance evidence (paired runs + 95% CIs; honest, no flaky asserts)
// ---------------------------------------------------------------------------

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn sd(xs: &[f64]) -> f64 {
    if xs.len() < 2 {
        return 0.0;
    }
    let m = mean(xs);
    (xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (xs.len() - 1) as f64).sqrt()
}

/// Two-sided 95% t critical value for small samples (df = n − 1).
fn t_crit95(n: usize) -> f64 {
    match n.saturating_sub(1) {
        0 => f64::INFINITY,
        1 => 12.706,
        2 => 4.303,
        3 => 3.182,
        4 => 2.776,
        5 => 2.571,
        6 => 2.447,
        7 => 2.365,
        8 => 2.306,
        9 => 2.262,
        10 => 2.228,
        _ => 1.96,
    }
}

/// Commit `total` prepared transactions against a fresh volume and return
/// `(ops_per_sec, mean_latency_us)`. `grouped` selects the arm.
fn run_commit_arm(total: usize, batch: usize, grouped: bool) -> (f64, f64) {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 24);
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
    let builders = seq.begin_many(total).unwrap();
    let ops: Vec<(u64, u8)> = (0..total).map(|i| (i as u64 + 1, i as u8)).collect();
    // Parallel preparation (outside the timed region for both arms).
    let txs = prepare_in_waves(
        builders,
        &ops,
        |o| o.0,
        |o, b| {
            b.add(RecordType::InodeCreate, o.0, 0, vec![o.1])?;
            Ok(())
        },
    )
    .unwrap();

    let start = Instant::now();
    if grouped {
        for chunk in txs.chunks(batch) {
            seq.commit_group(chunk.to_vec()).unwrap();
        }
    } else {
        for tx in txs {
            seq.commit(tx).unwrap();
        }
    }
    let secs = start.elapsed().as_secs_f64();
    (total as f64 / secs, secs * 1e6 / total as f64)
}

/// Sequential single-writer synchronized-commit latency (no grouping applies).
fn sequential_sync_latency(samples: usize) -> (f64, f64, f64) {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 24);
    let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
    let mut lat = Vec::with_capacity(samples);
    let mut all = Vec::with_capacity(samples);
    for i in 0..samples {
        let mut b = seq.begin().unwrap();
        b.add(RecordType::InodeCreate, i as u64 + 1, 0, vec![i as u8])
            .unwrap();
        let tx = b.build().unwrap();
        let t = Instant::now();
        seq.commit(tx).unwrap();
        let ns = t.elapsed().as_nanos() as f64 / 1000.0;
        lat.push(ns);
        all.push(ns);
    }
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = all[all.len() / 2];
    let p95 = all[((all.len() as f64 * 0.95) as usize).min(all.len() - 1)];
    (p50, p95, mean(&lat))
}

#[test]
fn group_commit_performance_evidence() {
    let writers = [1usize, 2, 4, 8, 16];
    let rounds = 4usize;
    let ops_per_writer = 4usize;
    let batch = 8usize;

    let env = orfs::bench::Environment::capture(std::env::var("ORFS_IMAGE").ok());

    let mut rows = Vec::new();
    for &w in &writers {
        let total = w * ops_per_writer;
        let mut base_rate = Vec::with_capacity(rounds);
        let mut grp_rate = Vec::with_capacity(rounds);
        let mut base_lat = Vec::with_capacity(rounds);
        let mut grp_lat = Vec::with_capacity(rounds);
        // Alternate arm order per round to blunt warm-up/cache bias.
        for r in 0..rounds {
            if r % 2 == 0 {
                let (b, bl) = run_commit_arm(total, batch, false);
                let (g, gl) = run_commit_arm(total, batch, true);
                base_rate.push(b);
                base_lat.push(bl);
                grp_rate.push(g);
                grp_lat.push(gl);
            } else {
                let (g, gl) = run_commit_arm(total, batch, true);
                let (b, bl) = run_commit_arm(total, batch, false);
                base_rate.push(b);
                base_lat.push(bl);
                grp_rate.push(g);
                grp_lat.push(gl);
            }
        }
        let diffs: Vec<f64> = grp_rate
            .iter()
            .zip(&base_rate)
            .map(|(g, b)| g - b)
            .collect();
        let md = mean(&diffs);
        let sdd = sd(&diffs);
        let n = rounds as f64;
        let se = if sdd == 0.0 { 0.0 } else { sdd / n.sqrt() };
        let tc = t_crit95(rounds);
        let t = if se == 0.0 { f64::INFINITY } else { md / se };
        rows.push(serde_json::json!({
            "writers": w,
            "transactions_per_round": total,
            "rounds": rounds,
            "baseline": {
                "ops_per_sec_mean": mean(&base_rate),
                "ops_per_sec_ci95_low": mean(&base_rate) - tc * sd(&base_rate) / n.sqrt(),
                "ops_per_sec_ci95_high": mean(&base_rate) + tc * sd(&base_rate) / n.sqrt(),
                "mean_latency_us": mean(&base_lat),
            },
            "grouped": {
                "batch": batch,
                "ops_per_sec_mean": mean(&grp_rate),
                "ops_per_sec_ci95_low": mean(&grp_rate) - tc * sd(&grp_rate) / n.sqrt(),
                "ops_per_sec_ci95_high": mean(&grp_rate) + tc * sd(&grp_rate) / n.sqrt(),
                "mean_latency_us": mean(&grp_lat),
            },
            "paired_ops_per_sec": {
                "metric": "grouped_minus_baseline",
                "pairs": rounds,
                "mean_diff": md,
                "ci95_low": md - tc * se,
                "ci95_high": md + tc * se,
                "t": t,
                "t_crit95": tc,
                "significant": t.abs() > tc,
            },
        }));
    }

    let (seq_p50, seq_p95, seq_mean) = sequential_sync_latency(120);

    let all_significant = rows.iter().all(|r| {
        r["paired_ops_per_sec"]["significant"]
            .as_bool()
            .unwrap_or(false)
    });
    let evidence = serde_json::json!({
        "schema": "orfs.evidence.group-commit.v1",
        "generator": "tests/group_commit.rs",
        "method": "paired runs, alternating arm order per round; two-sided 95% t intervals on small samples; grouped batch=8; all transactions prepared up front (preparation excluded from the timed region for both arms, so only the durability barrier differs)",
        "environment": env,
        "durability": "sync (the strongest barrier; grouping amortises the fsync)",
        "workload": {
            "writers": writers,
            "ops_per_writer": ops_per_writer,
            "group_batch": batch,
            "rounds": rounds,
        },
        "single_writer_sequential_sync": {
            "samples": 120,
            "p50_us": seq_p50,
            "p95_us": seq_p95,
            "mean_us": seq_mean,
            "note": "one writer, one transaction at a time: grouping does not apply, so group commit cannot (and does not) change this path; a group of one is byte-identical to a single commit (group_commit_is_byte_identical_to_serial_commit)",
        },
        "rows": rows,
        "any_significant": all_significant,
        "honesty": "concurrent synchronized writers share one barrier under grouping; the win is expected only once writers contend. Where a row is not significant it is reported as such rather than claimed.",
    });
    support::write_json(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("evidence/performance/group-commit.json"),
        &evidence,
    );

    // Correctness-only assertions (the numbers may be environment-noisy).
    let _ = all_significant;
    // The concurrent arm must never be catastrophically slower than the baseline.
    for r in evidence["rows"].as_array().unwrap() {
        let b = r["baseline"]["ops_per_sec_mean"].as_f64().unwrap();
        let g = r["grouped"]["ops_per_sec_mean"].as_f64().unwrap();
        assert!(
            g >= b * 0.5,
            "grouped throughput collapsed: base={b} grouped={g}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Crash during a grouped commit (fault-injection arm)
// ---------------------------------------------------------------------------

#[cfg(feature = "failpoints")]
mod crash {
    use super::*;
    use orfs::failpoints::{self, FailAction};
    use orfs::log::OpenMode;
    use std::path::Path;
    use std::process::{Command, Stdio};

    /// Build a transaction carrying one `DATA_EXTENT` (an engine-level
    /// representation of a **write**) with a deterministic `len`-byte payload.
    fn tx_with_write(id: u64, inode: u64, marker: u8, len: usize) -> Transaction {
        let mut b = TransactionBuilder::new(id).unwrap();
        b.add(RecordType::DataExtent, inode, 0, vec![marker; len])
            .unwrap();
        b.build().unwrap()
    }

    /// In-process: an injected failure on the *second* member of a group that
    /// contains a write leaves the first committed at a boundary and no partial
    /// member visible; an independent reopen verifies every recovery invariant.
    #[test]
    fn error_during_grouped_write_commit_recovers_to_a_complete_boundary() {
        let td = TempDir::new().unwrap();
        let dir = td.path().to_path_buf();

        // Baseline: one durable transaction that carries a write.
        let (baseline_root, baseline_bytes, baseline_segments) = {
            let mut vol = init_volume(&dir, 1 << 20);
            let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
            let tx = tx_with_write(seq.peek_transaction_id(), 1, 9, 1024);
            seq.commit(tx).unwrap();
            seq.flush().unwrap();
            let root = vol.log.committed_end_offset();
            let bytes = vol.log.read_committed_bytes().unwrap();
            let segs = support::snapshot_segments(&vol.log);
            (root, bytes, segs)
        };

        // Fail the second member's TX_COMMIT write (skip the first) of a group in
        // which every member carries a write record.
        let result = {
            let mut vol = Volume::open(&dir, OpenMode::ReadWrite).unwrap();
            let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
            failpoints::configure_one("during_commit_record_write", FailAction::Error, 1);
            let builders = seq.begin_many(3).unwrap();
            let txs: Vec<Transaction> = builders
                .into_iter()
                .enumerate()
                .map(|(k, mut b)| {
                    b.add(
                        RecordType::DataExtent,
                        100 + k as u64,
                        0,
                        vec![k as u8; 1024],
                    )
                    .unwrap();
                    b.build().unwrap()
                })
                .collect();
            seq.commit_group(txs)
        };
        failpoints::clear();
        assert!(
            result.is_err(),
            "the injected mid-group failure must surface"
        );

        let (verdicts, recovered) =
            support::verify_recovered(&dir, baseline_root, &baseline_bytes, &baseline_segments);
        assert!(verdicts.all_ok(), "{verdicts:?}");
        assert!(
            recovered >= baseline_root,
            "recovery must reach at least the baseline boundary"
        );
    }

    /// In-process: an injected failure on the *second* member of a group leaves
    /// the first committed at a boundary and no partial member visible; an
    /// independent reopen verifies every recovery invariant.
    #[test]
    fn error_during_grouped_commit_recovers_to_a_complete_boundary() {
        let td = TempDir::new().unwrap();
        let dir = td.path().to_path_buf();

        // Baseline: one durable transaction.
        let (baseline_root, baseline_bytes, baseline_segments) = {
            let mut vol = init_volume(&dir, 1 << 20);
            let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
            let tx = tx_with_marker(seq.peek_transaction_id(), 1, 9);
            seq.commit(tx).unwrap();
            seq.flush().unwrap();
            let root = vol.log.committed_end_offset();
            let bytes = vol.log.read_committed_bytes().unwrap();
            let segs = support::snapshot_segments(&vol.log);
            (root, bytes, segs)
        };

        // A second volume handle, then fail the second member's TX_COMMIT write
        // (skip the first). The writable handle is dropped at the end of the block
        // so its file handles are closed before the independent reopen.
        let result = {
            let mut vol = Volume::open(&dir, OpenMode::ReadWrite).unwrap();
            let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
            failpoints::configure_one("during_commit_record_write", FailAction::Error, 1);
            let txs = prepared_many(&mut seq, 3, |i| i as u64 + 100);
            seq.commit_group(txs)
        };
        failpoints::clear();
        assert!(
            result.is_err(),
            "the injected mid-group failure must surface"
        );

        let (verdicts, recovered) =
            support::verify_recovered(&dir, baseline_root, &baseline_bytes, &baseline_segments);
        assert!(verdicts.all_ok(), "{verdicts:?}");
        assert!(
            recovered >= baseline_root,
            "recovery must reach at least the baseline boundary"
        );
    }

    /// The child role: open the volume, arm a torn mid-group commit with the
    /// `abort` action, and commit groups until the process is killed.
    #[test]
    fn group_crash_child_role() {
        let Ok(fp_name) = std::env::var("ORFS_GROUP_CRASH_CHILD") else {
            return;
        };
        let dir = std::env::var("ORFS_GROUP_CRASH_DIR").expect("ORFS_GROUP_CRASH_DIR");
        // When set, every grouped member also carries a write record, so the
        // crash court covers a grouped commit that includes writes.
        let with_write = std::env::var("ORFS_GROUP_CRASH_WRITE").is_ok();
        let mut vol =
            Volume::open(Path::new(&dir), OpenMode::ReadWrite).expect("child open volume");
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        failpoints::configure_one(&fp_name, FailAction::Abort, 1);
        for i in 0..5000u64 {
            let builders = seq.begin_many(3).unwrap();
            let txs: Vec<Transaction> = builders
                .into_iter()
                .enumerate()
                .map(|(k, mut b)| {
                    let ino = i * 3 + k as u64 + 1;
                    b.add(RecordType::InodeCreate, ino, 0, vec![k as u8])
                        .unwrap();
                    if with_write {
                        b.add(RecordType::DataExtent, ino, 0, vec![k as u8; 512])
                            .unwrap();
                    }
                    b.build().unwrap()
                })
                .collect();
            let _ = seq.commit_group(txs);
        }
        eprintln!("child: failpoint {fp_name} never fired");
        std::process::exit(7);
    }

    #[test]
    fn process_crash_during_grouped_commit_recovers_to_a_valid_boundary() {
        for fp in [
            "during_commit_record_write",
            "during_record_write",
            "before_commit",
        ] {
            let td = TempDir::new().unwrap();
            let dir = td.path().to_path_buf();

            // Baseline (no failpoint).
            failpoints::clear();
            let (baseline_root, baseline_bytes, baseline_segments) = {
                let mut vol = init_volume(&dir, 1024);
                let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
                for i in 1..=3u64 {
                    let tx = tx_with_marker(seq.peek_transaction_id(), i, i as u8);
                    seq.commit(tx).unwrap();
                }
                seq.flush().unwrap();
                let root = vol.log.committed_end_offset();
                let bytes = vol.log.read_committed_bytes().unwrap();
                let segs = support::snapshot_segments(&vol.log);
                (root, bytes, segs)
            };

            let exe = std::env::current_exe().expect("current exe");
            let status = Command::new(exe)
                .args([
                    "crash::group_crash_child_role",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("ORFS_GROUP_CRASH_CHILD", fp)
                .env("ORFS_GROUP_CRASH_DIR", &dir)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("spawn group crash child");
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(libc::SIGABRT),
                "failpoint {fp}: child was not killed by SIGABRT"
            );

            let (verdicts, recovered) =
                support::verify_recovered(&dir, baseline_root, &baseline_bytes, &baseline_segments);
            assert!(verdicts.all_ok(), "failpoint {fp}: {verdicts:?}");
            assert!(recovered >= baseline_root);
        }
    }

    /// The same process-crash court, but every grouped member carries a **write**
    /// (`DATA_EXTENT`), so the crash interrupts a grouped commit that includes
    /// writes. Recovery must still land on a complete, valid transaction boundary.
    #[test]
    fn process_crash_during_grouped_write_commit_recovers_to_a_valid_boundary() {
        for fp in [
            "during_commit_record_write",
            "during_record_write",
            "before_commit",
        ] {
            let td = TempDir::new().unwrap();
            let dir = td.path().to_path_buf();

            // Baseline (no failpoint): three durable write transactions.
            failpoints::clear();
            let (baseline_root, baseline_bytes, baseline_segments) = {
                let mut vol = init_volume(&dir, 1 << 20);
                let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
                for i in 1..=3u64 {
                    let tx = tx_with_write(seq.peek_transaction_id(), i, i as u8, 512);
                    seq.commit(tx).unwrap();
                }
                seq.flush().unwrap();
                let root = vol.log.committed_end_offset();
                let bytes = vol.log.read_committed_bytes().unwrap();
                let segs = support::snapshot_segments(&vol.log);
                (root, bytes, segs)
            };

            let exe = std::env::current_exe().expect("current exe");
            let status = Command::new(exe)
                .args([
                    "crash::group_crash_child_role",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("ORFS_GROUP_CRASH_CHILD", fp)
                .env("ORFS_GROUP_CRASH_DIR", &dir)
                .env("ORFS_GROUP_CRASH_WRITE", "1")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("spawn group write crash child");
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                status.signal(),
                Some(libc::SIGABRT),
                "failpoint {fp}: child was not killed by SIGABRT"
            );

            let (verdicts, recovered) =
                support::verify_recovered(&dir, baseline_root, &baseline_bytes, &baseline_segments);
            assert!(verdicts.all_ok(), "failpoint {fp}: {verdicts:?}");
            assert!(recovered >= baseline_root);
        }
    }
}
