//! Phase 2 transaction-model tests: builder validation, typed payload codecs,
//! the explicit state machine, the commit sequencer's ordering and publication
//! rule, durability acknowledgment contracts, and in-process failpoint recovery.
//!
//! Everything here runs in a single process; the genuine *process-crash* tests
//! live in `tests/crash_recovery.rs`.

mod support;

use orfs::commit::{CommitSequencer, DurabilityMode};
#[cfg(feature = "failpoints")]
use orfs::error::OrfsError;
#[cfg(feature = "failpoints")]
use orfs::log::OpenMode;
use orfs::record::{Record, RecordType};
use orfs::transaction::{
    bracket_checksum, AbortReason, TransactionBuilder, TxBeginPayload, TxCommitPayload, TxState,
};

use proptest::prelude::*;
use support::{build_transaction, init_volume};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Builder and codec
// ---------------------------------------------------------------------------

#[test]
fn builder_validates_before_reserving() {
    // Zero id rejected.
    assert!(TransactionBuilder::new(0).is_err());
    // Structural types rejected as data records.
    let mut b = TransactionBuilder::new(1).unwrap();
    assert!(b.add(RecordType::TxBegin, 0, 0, Vec::new()).is_err());
    assert!(b.add(RecordType::TxCommit, 0, 0, Vec::new()).is_err());
    assert!(b.add(RecordType::TxAbort, 0, 0, Vec::new()).is_err());
    assert!(b.add(RecordType::VolumeGenesis, 0, 0, Vec::new()).is_err());
    // Oversized payload rejected by Record::new before any reservation.
    assert!(b
        .add(RecordType::DataExtent, 1, 0, vec![0u8; 65 * 1024 * 1024])
        .is_err());
    // A valid record is accepted and metadata is computed exactly.
    assert!(b.add(RecordType::InodeCreate, 1, 0, vec![1, 2, 3]).is_ok());
    let tx = b.build().unwrap();
    assert_eq!(tx.state(), TxState::Prepared);
    assert_eq!(tx.bracket_record_count(), 2);
    assert_eq!(tx.bracket_byte_length(), (60 + 28 + 16) + (60 + 3 + 16));
}

#[test]
fn payload_codecs_reject_corruption() {
    let begin = TxBeginPayload {
        transaction_id: 9,
        expected_byte_length: 100,
        expected_record_count: 3,
    }
    .encode();
    assert!(TxBeginPayload::decode(&begin).is_ok());
    let mut bad = begin;
    bad[2] ^= 0xFF;
    assert!(TxBeginPayload::decode(&bad).is_err());

    let commit = TxCommitPayload {
        transaction_id: 9,
        record_count: 3,
        bracketed_byte_length: 100,
        commit_sequence_number: 4,
        bracket_checksum: bracket_checksum(b"x"),
    }
    .encode();
    assert!(TxCommitPayload::decode(&commit).is_ok());
    let mut badc = commit;
    badc[70] ^= 0xFF;
    assert!(TxCommitPayload::decode(&badc).is_err());
}

// ---------------------------------------------------------------------------
// Commit sequencing and publication
// ---------------------------------------------------------------------------

#[test]
fn commit_advances_the_root_to_a_transaction_boundary_and_records_typed_payloads() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 20);
    let genesis_root = vol.log.committed_end_offset();

    let (out, begin) = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        let id = seq.peek_transaction_id();
        let tx = build_transaction(id, 3);
        let begin = tx.begin();
        let out = seq.commit(tx).unwrap();
        assert_eq!(out.state, TxState::Durable);
        assert!(out.durable);
        assert!(out.root > genesis_root);
        assert_eq!(out.begin_offset, genesis_root);
        assert!(seq.log().is_boundary(out.root));
        (out, begin)
    };

    assert_eq!(out.root, vol.log.committed_end_offset());

    // The committed prefix is genesis + begin + 3 data + commit.
    let recs = vol.log.replay_upto(out.root).unwrap();
    let types: Vec<RecordType> = recs.iter().map(|r| r.known_type().unwrap()).collect();
    let begin_idx = types.len() - 5;
    assert_eq!(types[0], RecordType::VolumeGenesis);
    assert_eq!(types[begin_idx], RecordType::TxBegin);
    assert_eq!(*types.last().unwrap(), RecordType::TxCommit);

    // TX_BEGIN payload round-trips and agrees with the bracket.
    let begin_rec = &recs[begin_idx];
    let begin_payload = TxBeginPayload::decode(&begin_rec.payload).unwrap();
    assert_eq!(begin_payload, begin);
    // A root never points inside a record.
    assert!(!vol.log.is_boundary(out.root - 1));

    // Recompute the bracket and verify the TX_COMMIT checksum.
    let mut bracket = Vec::new();
    for r in &recs[begin_idx..types.len() - 1] {
        bracket.extend_from_slice(&r.encode().unwrap());
    }
    let commit_payload = TxCommitPayload::decode(&recs[types.len() - 1].payload).unwrap();
    orfs::transaction::verify_bracket(&commit_payload, &bracket, &begin_payload).unwrap();
    assert_eq!(commit_payload.record_count, 4);
    assert_eq!(
        commit_payload.bracketed_byte_length,
        out.bracketed_byte_length
    );
}

#[test]
fn root_does_not_move_until_commit_and_never_exposes_a_partial_transaction() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 20);
    let r0 = vol.log.committed_end_offset();

    // Write a bracket by hand without committing it.
    vol.log.begin(1).unwrap();
    vol.log
        .append(Record::new(RecordType::InodeCreate, 0, 1, 1, 0, 0, vec![1, 2, 3]).unwrap())
        .unwrap();
    // An observer pinning the committed root sees no partial state.
    assert_eq!(vol.log.committed_end_offset(), r0);
    let recs = vol.log.replay_upto(r0).unwrap();
    assert_eq!(
        recs.last().unwrap().known_type().unwrap(),
        RecordType::VolumeGenesis
    );
    // Only an explicit commit moves the root.
    let r1 = vol.log.commit().unwrap();
    assert!(r1 > r0);
    assert!(vol.log.is_boundary(r1));
}

#[test]
fn abort_publishes_nothing_and_is_recoverable() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 1 << 20);
    let r0 = vol.log.committed_end_offset();
    let before = support::snapshot_segments(&vol.log);
    let baseline_bytes = vol.log.read_committed_bytes().unwrap();

    let out = {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        let id = seq.peek_transaction_id();
        let tx = build_transaction(id, 2);
        seq.abort(tx, AbortReason::UserRequested, "test abort")
            .unwrap()
    };
    assert_eq!(out.root, r0);
    assert_eq!(out.reason, AbortReason::UserRequested);
    assert_eq!(vol.log.committed_end_offset(), r0);
    drop(vol);

    // Reopen: the aborted bracket is an uncommitted tail, never canonical.
    let (verdicts, recovered) = support::verify_recovered(td.path(), r0, &baseline_bytes, &before);
    assert!(verdicts.all_ok(), "{verdicts:?}");
    assert_eq!(recovered, r0);
}

// ---------------------------------------------------------------------------
// Durability profiles
// ---------------------------------------------------------------------------

#[test]
fn durability_profiles_have_distinct_acknowledgment_semantics() {
    // --- sync: acknowledged only after fsync -> Durable ---
    {
        let td = TempDir::new().unwrap();
        let mut vol = init_volume(td.path(), 1 << 20);
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        let out = seq.commit(build_transaction(1, 1)).unwrap();
        assert_eq!(out.state, TxState::Durable);
        assert!(out.durable);
    }

    // --- ordered: published after completed writes, not fsynced ---
    {
        let td = TempDir::new().unwrap();
        let mut vol = init_volume(td.path(), 1 << 20);
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Ordered);
        let out = seq.commit(build_transaction(1, 1)).unwrap();
        assert_eq!(out.state, TxState::Published);
        assert!(!out.durable);
        assert!(seq.log().is_boundary(out.root));
        // An explicit flush establishes durability.
        let sync = seq.flush().unwrap();
        assert_eq!(sync.root, out.root);
        assert_eq!(sync.transactions, 1);
    }

    // --- batched: coalesced sync points ---
    {
        let td = TempDir::new().unwrap();
        let mut vol = init_volume(td.path(), 1 << 20);
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Batched { batch_size: 3 });
        let a = seq.commit(build_transaction(1, 1)).unwrap();
        let b = seq.commit(build_transaction(2, 1)).unwrap();
        let c = seq.commit(build_transaction(3, 1)).unwrap();
        assert_eq!(a.state, TxState::Published);
        assert!(!a.durable);
        assert_eq!(b.state, TxState::Published);
        assert_eq!(
            c.state,
            TxState::Durable,
            "third commit completes the batch"
        );
        assert!(c.durable);
        // A partial batch becomes durable only on flush.
        let d = seq.commit(build_transaction(4, 1)).unwrap();
        assert_eq!(d.state, TxState::Published);
        let sync = seq.flush().unwrap();
        assert_eq!(sync.transactions, 1);
        assert_eq!(sync.root, d.root);
    }
}

#[test]
fn durability_mode_never_overstates_power_loss() {
    for mode in [
        DurabilityMode::Sync,
        DurabilityMode::Ordered,
        DurabilityMode::Batched { batch_size: 8 },
    ] {
        assert!(!mode.claims_power_loss_durability());
    }
}

// ---------------------------------------------------------------------------
// Rollover + ordering
// ---------------------------------------------------------------------------

#[test]
fn commits_across_segment_rollover_stay_boundaries() {
    let td = TempDir::new().unwrap();
    let mut vol = init_volume(td.path(), 512);
    let mut roots = Vec::new();
    {
        let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
        for i in 0..40u64 {
            let out = seq.commit(build_transaction(i + 1, 2)).unwrap();
            roots.push(out.root);
        }
    }
    assert!(roots.windows(2).all(|w| w[0] < w[1]));
    assert!(vol.log.extents().len() > 1, "must exercise rollover");
    for &r in &roots {
        assert!(vol.log.is_boundary(r));
        let recs = vol.log.replay_upto(r).unwrap();
        assert_eq!(
            recs.last().unwrap().known_type().unwrap(),
            RecordType::TxCommit
        );
    }
}

// ---------------------------------------------------------------------------
// In-process failpoint recovery (terminates the write path, then reopens)
// ---------------------------------------------------------------------------

/// Commit until a failpoint fires, returning the armed failpoint's name.
#[cfg(feature = "failpoints")]
fn commit_until_failpoint(vol: &mut orfs::volume::Volume, mode: DurabilityMode) -> String {
    let mut seq = CommitSequencer::new(vol, mode);
    for i in 0..400u64 {
        let tx = build_transaction(seq.peek_transaction_id(), 2);
        match seq.commit(tx) {
            Ok(_) => {}
            Err(OrfsError::Failpoint(name)) => return name.to_string(),
            Err(e) => panic!("unexpected error at attempt {i}: {e}"),
        }
    }
    panic!("failpoint never fired");
}

#[cfg(feature = "failpoints")]
#[test]
fn every_failpoint_leaves_a_valid_recoverable_root() {
    use orfs::failpoints::{self, FailAction, Failpoint};

    for fp in Failpoint::ALL {
        let td = TempDir::new().unwrap();
        let dir = td.path().to_path_buf();
        // Establish a known-good baseline WITHOUT any failpoint armed.
        failpoints::clear();
        let (baseline_root, baseline_bytes, baseline_segments) = {
            let mut vol = init_volume(&dir, 1024);
            let mut seq = CommitSequencer::new(&mut vol, DurabilityMode::Sync);
            seq.commit(build_transaction(1, 2)).unwrap();
            seq.commit(build_transaction(2, 2)).unwrap();
            seq.flush().unwrap();
            (
                seq.log().committed_end_offset(),
                seq.log().read_committed_bytes().unwrap(),
                support::snapshot_segments(seq.log()),
            )
        };

        // Arm the failpoint and run the commit path until it terminates.
        failpoints::clear();
        failpoints::configure_one(fp.name(), FailAction::Error, 0);
        {
            let mut vol = orfs::volume::Volume::open(&dir, OpenMode::ReadWrite).unwrap();
            let name = commit_until_failpoint(&mut vol, DurabilityMode::Ordered);
            assert_eq!(name, fp.name());
        }
        failpoints::clear();

        // Reopen independently and verify the recovery invariants.
        let (verdicts, recovered) =
            support::verify_recovered(&dir, baseline_root, &baseline_bytes, &baseline_segments);
        assert!(verdicts.all_ok(), "failpoint {}: {verdicts:?}", fp.name());
        assert!(recovered >= baseline_root);
    }
}

// ---------------------------------------------------------------------------
// Randomized sequences (proptest)
// ---------------------------------------------------------------------------

fn mode_from(idx: u8) -> DurabilityMode {
    match idx % 3 {
        0 => DurabilityMode::Sync,
        1 => DurabilityMode::Ordered,
        _ => DurabilityMode::Batched {
            batch_size: 2 + (idx % 7) as u32,
        },
    }
}

fn build_random_transaction(id: u64, spec: &[(u8, Vec<u8>)]) -> orfs::transaction::Transaction {
    let mut b = TransactionBuilder::new(id).unwrap();
    for (i, (ty, pl)) in spec.iter().enumerate() {
        b.add(
            support::MUTATING_TYPES[*ty as usize % support::MUTATING_TYPES.len()],
            id,
            (i as u64).wrapping_mul(3),
            pl.clone(),
        )
        .unwrap();
    }
    b.build().unwrap()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Any sequence of transactions under any durability mode, after a full
    /// close and reopen, yields a valid committed root that is a byte-exact
    /// extension of history.
    #[test]
    fn random_transaction_sequences_recover_consistently(
        specs in proptest::collection::vec(
            proptest::collection::vec((0u8..6, proptest::collection::vec(any::<u8>(), 0..40)), 0..4),
            0..8,
        ),
        mode_idx in 0u8..9,
        seg in 256usize..2048,
    ) {
        let td = TempDir::new().unwrap();
        let dir = td.path().to_path_buf();
        let (baseline_root, baseline_bytes, baseline_segments) = {
            let mut vol = init_volume(&dir, seg as u64);
            let mut seq = CommitSequencer::new(&mut vol, mode_from(mode_idx));
            for spec in &specs {
                let id = seq.peek_transaction_id();
                let tx = build_random_transaction(id, spec);
                seq.commit(tx).unwrap();
            }
            (
                seq.log().committed_end_offset(),
                seq.log().read_committed_bytes().unwrap(),
                support::snapshot_segments(seq.log()),
            )
        };
        let (verdicts, _recovered) =
            support::verify_recovered(&dir, baseline_root, &baseline_bytes, &baseline_segments);
        prop_assert!(verdicts.all_ok(), "{:?}", verdicts);
    }
}

#[cfg(feature = "failpoints")]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// A randomly chosen failpoint in the middle of a random transaction
    /// sequence: after terminating the write path and reopening, the recovered
    /// root is still a valid, byte-exact extension of history.
    #[test]
    fn random_failpoints_recover_consistently(
        specs in proptest::collection::vec(
            proptest::collection::vec((0u8..6, proptest::collection::vec(any::<u8>(), 0..40)), 0..4),
            1..8,
        ),
        mode_idx in 0u8..9,
        fp_idx in 0usize..11,
        seg in 256usize..2048,
    ) {
        use orfs::failpoints::{self, FailAction, Failpoint};
        let fp = Failpoint::ALL[fp_idx];
        let td = TempDir::new().unwrap();
        let dir = td.path().to_path_buf();
        let (clean_root, clean_bytes, clean_segments) = {
            let mut vol = init_volume(&dir, seg as u64);
            let mut seq = CommitSequencer::new(&mut vol, mode_from(mode_idx));
            let split = specs.len() - 1;
            for spec in &specs[..split] {
                let id = seq.peek_transaction_id();
                seq.commit(build_random_transaction(id, spec)).unwrap();
            }
            let clean_root = seq.log().committed_end_offset();
            let clean_bytes = seq.log().read_committed_bytes().unwrap();
            let clean_segments = support::snapshot_segments(seq.log());
            // Arm the failpoint and attempt the final transaction.
            failpoints::clear();
            failpoints::configure_one(fp.name(), FailAction::Error, 0);
            let id = seq.peek_transaction_id();
            let _ = seq.commit(build_random_transaction(id, specs.last().unwrap()));
            failpoints::clear();
            (clean_root, clean_bytes, clean_segments)
        };
        let (verdicts, recovered) =
            support::verify_recovered(&dir, clean_root, &clean_bytes, &clean_segments);
        prop_assert!(verdicts.all_ok(), "fp {}: {:?}", fp.name(), verdicts);
        prop_assert!(recovered >= clean_root);
    }
}
