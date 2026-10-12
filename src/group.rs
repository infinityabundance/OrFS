//! Conflict-aware parallel preparation and ordered group commit (Phase 31).
//!
//! This module implements the *preparation* half of external review §6 P1 while
//! leaving the authoritative publication path untouched and serial:
//!
//! ```text
//!   parallel PREPARATION (many threads)         serial PUBLICATION (one)
//!   ────────────────────────────────────         ────────────────────────
//!   validate · build payloads · checksums   →     reserve · seal · write
//!   extent planning · bracket metadata            TX_COMMIT · publish root
//!   … per conflict-free wave                      … in submission order
//! ```
//!
//! Two guarantees are enforced here, not merely documented:
//!
//! 1. **A conflict rule prevents wrong parallelisation.** Two operations that
//!    touch the same authoritative object (an inode or a directory — the conflict
//!    key) are never prepared onto the same wave, because they may read each
//!    other's state. Conflicting operations are placed on successive waves, so
//!    they run in a defined order, never concurrently.
//! 2. **Ordering of dependent operations is preserved.** The prepared
//!    transactions are returned, and later published, in the caller's original
//!    order regardless of which wave prepared them. The commit itself is
//!    serialised by [`CommitSequencer::commit_group`], which publishes in that
//!    same order.
//!
//! Publication is *never* parallel: [`prepare_and_commit`] prepares on many
//! threads and then hands the ordered vector to the single commit sequencer.

use std::collections::BTreeSet;

use crate::commit::{CommitOutcome, CommitSequencer};
use crate::error::{OrfsError, Result};
use crate::transaction::{Transaction, TransactionBuilder};

/// A conflict key: an identity for the authoritative object an operation reads
/// or mutates. Two operations with the same key must not be prepared
/// concurrently. In OrFS the natural key is the inode id (which is also the
/// directory id for directory entries), matching the per-inode/per-directory
/// rule the review suggests.
pub type ConflictKey = u64;

/// The conflict keys a transaction touches: the set of inode ids named by its
/// records. Two transactions that share any key conflict.
pub fn conflict_keys(tx: &Transaction) -> BTreeSet<ConflictKey> {
    tx.records().iter().map(|r| r.header.inode_id).collect()
}

/// Whether a set of transactions is pairwise conflict-free (no two transactions
/// name the same inode). Used by tests and by callers that want to assert a batch
/// was correctly partitioned before committing it as one group.
pub fn group_is_conflict_free(txs: &[Transaction]) -> bool {
    let mut seen = BTreeSet::new();
    for tx in txs {
        for key in conflict_keys(tx) {
            if !seen.insert(key) {
                return false;
            }
        }
    }
    true
}

/// Partition `keys` into conflict-free waves, greedily (first-fit).
///
/// Returns one wave index per key. Two equal keys always receive different wave
/// indices, so a wave never contains two operations that conflict. Keys preserve
/// their relative order: a later duplicate is always placed on a later wave than
/// an earlier one, so dependent operations run in the caller's order.
pub fn conflict_waves(keys: &[ConflictKey]) -> Vec<usize> {
    let mut waves: Vec<BTreeSet<ConflictKey>> = Vec::new();
    let mut out = Vec::with_capacity(keys.len());
    for &key in keys {
        let mut placed = None;
        for (w, set) in waves.iter_mut().enumerate() {
            if !set.contains(&key) {
                set.insert(key);
                placed = Some(w);
                break;
            }
        }
        let wave = match placed {
            Some(w) => w,
            None => {
                let mut set = BTreeSet::new();
                set.insert(key);
                waves.push(set);
                waves.len() - 1
            }
        };
        out.push(wave);
    }
    out
}

/// Prepare `ops` concurrently in conflict-free waves and return the resulting
/// transactions **in the original input order**.
///
/// `builders` must supply exactly one [`TransactionBuilder`] per op (allocate
/// them with [`CommitSequencer::begin_many`], which reserves the identities
/// before preparation so they can never be reissued). `build` appends the op's
/// records — payload construction, checksums, extent planning — and runs
/// concurrently with the other members of its wave.
///
/// A wave of one op runs inline, without paying for a thread; a batch whose ops
/// all conflict therefore degrades to fully serial preparation (correctly — there
/// is nothing to parallelise). Preparation errors abort the whole batch before
/// any publication.
pub fn prepare_in_waves<O, K, F>(
    mut builders: Vec<TransactionBuilder>,
    ops: &[O],
    conflict_key: K,
    build: F,
) -> Result<Vec<Transaction>>
where
    O: Sync,
    K: Fn(&O) -> ConflictKey + Sync,
    F: Fn(&O, &mut TransactionBuilder) -> Result<()> + Sync,
{
    if builders.len() != ops.len() {
        return Err(OrfsError::InvalidArgument(format!(
            "preparation needs one builder per op ({} builders for {} ops)",
            builders.len(),
            ops.len()
        )));
    }
    let keys: Vec<ConflictKey> = ops.iter().map(&conflict_key).collect();
    let waves = conflict_waves(&keys);
    let wave_count = waves.iter().copied().max().map_or(0, |m| m + 1);

    let mut slots: Vec<Option<Transaction>> = (0..ops.len()).map(|_| None).collect();
    let mut builders: Vec<Option<TransactionBuilder>> = builders.drain(..).map(Some).collect();

    for wave in 0..wave_count {
        let members: Vec<usize> = (0..ops.len()).filter(|&i| waves[i] == wave).collect();
        let prepared: Vec<(usize, Transaction)> = if members.len() == 1 {
            let i = members[0];
            let mut builder = builders[i].take().expect("builder present");
            build(&ops[i], &mut builder)?;
            vec![(i, builder.build()?)]
        } else {
            let to_run: Vec<(usize, TransactionBuilder)> = members
                .iter()
                .map(|&i| (i, builders[i].take().expect("builder present")))
                .collect();
            let build = &build;
            std::thread::scope(|scope| -> Result<Vec<(usize, Transaction)>> {
                let handles: Vec<_> = to_run
                    .into_iter()
                    .map(|(i, mut builder)| {
                        let op = &ops[i];
                        scope.spawn(move || {
                            build(op, &mut builder)?;
                            builder.build().map(|tx| (i, tx))
                        })
                    })
                    .collect();
                let mut out = Vec::with_capacity(handles.len());
                for handle in handles {
                    match handle.join() {
                        Ok(result) => out.push(result?),
                        Err(_) => {
                            return Err(OrfsError::InvalidArgument(
                                "a preparation worker panicked".into(),
                            ))
                        }
                    }
                }
                Ok(out)
            })?
        };
        for (i, tx) in prepared {
            slots[i] = Some(tx);
        }
    }

    slots
        .into_iter()
        .map(|slot| slot.ok_or_else(|| OrfsError::InvalidArgument("op was not prepared".into())))
        .collect()
}

/// The one-stop Phase 31 entry point: prepare `ops` concurrently in
/// conflict-free waves, then publish them as one ordered group.
///
/// Identities are allocated from `seq` before preparation. Publication is serial
/// and in the input order (see [`CommitSequencer::commit_group`]); a conflict
/// only prevents concurrent *preparation*, never correct ordering.
pub fn prepare_and_commit<O, K, F>(
    seq: &mut CommitSequencer<'_>,
    ops: &[O],
    conflict_key: K,
    build: F,
) -> Result<Vec<CommitOutcome>>
where
    O: Sync,
    K: Fn(&O) -> ConflictKey + Sync,
    F: Fn(&O, &mut TransactionBuilder) -> Result<()> + Sync,
{
    if ops.is_empty() {
        return Ok(Vec::new());
    }
    let builders = seq.begin_many(ops.len())?;
    let txs = prepare_in_waves(builders, ops, conflict_key, build)?;
    seq.commit_group(txs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::RecordType;

    fn tx_with_inodes(id: u64, inodes: &[u64]) -> Transaction {
        let mut b = TransactionBuilder::new(id).unwrap();
        for &ino in inodes {
            b.add(RecordType::InodeMetadata, ino, 0, vec![0u8; 4])
                .unwrap();
        }
        b.build().unwrap()
    }

    #[test]
    fn conflict_waves_never_place_equal_keys_together() {
        // Keys 1,2,1,3,2 → greedy first-fit waves.
        let waves = conflict_waves(&[1, 2, 1, 3, 2]);
        // Equal keys must differ; distinct keys may share.
        assert_ne!(waves[0], waves[2], "two 1s must not share a wave");
        assert_ne!(waves[1], waves[4], "two 2s must not share a wave");
        // Every wave is conflict-free by construction.
        let mut per_wave: Vec<Vec<u64>> = vec![Vec::new(); waves.iter().max().unwrap() + 1];
        for (i, &w) in waves.iter().enumerate() {
            per_wave[w].push([1u64, 2, 1, 3, 2][i]);
        }
        for set in per_wave {
            let mut sorted = set.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), set.len(), "a wave had a duplicate key");
        }
    }

    #[test]
    fn distinct_keys_parallelise_into_one_wave() {
        let waves = conflict_waves(&[10, 20, 30, 40]);
        assert!(waves.iter().all(|&w| w == 0));
    }

    #[test]
    fn group_independence_check() {
        let a = tx_with_inodes(1, &[1, 2]);
        let b = tx_with_inodes(2, &[3, 4]);
        let c = tx_with_inodes(3, &[2, 5]);
        assert!(group_is_conflict_free(&[a.clone(), b.clone()]));
        assert!(!group_is_conflict_free(&[a, c]));
    }

    #[test]
    fn waves_preserve_input_order_and_conflicts_are_serial() {
        // Same inode in ops 0 and 2: they must be split across waves, but the
        // returned vector must still be in input order.
        let ops: Vec<u64> = vec![7, 7, 7];
        let builders: Vec<TransactionBuilder> = (1..=3u64)
            .map(|i| TransactionBuilder::new(i).unwrap())
            .collect();
        let txs = prepare_in_waves(
            builders,
            &ops,
            |k| *k,
            |op, b| {
                b.add(RecordType::InodeMetadata, *op, 0, vec![0u8; 1])?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(txs.len(), 3);
        assert_eq!(txs[0].id(), 1);
        assert_eq!(txs[1].id(), 2);
        assert_eq!(txs[2].id(), 3);
    }

    #[test]
    fn builder_count_must_match_ops() {
        let ops = vec![1u64, 2];
        let builders = vec![TransactionBuilder::new(1).unwrap()];
        let err = prepare_in_waves(builders, &ops, |k| *k, |_, _| Ok(())).unwrap_err();
        assert!(matches!(err, OrfsError::InvalidArgument(_)));
    }
}
