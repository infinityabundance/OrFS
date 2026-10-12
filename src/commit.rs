//! The single authoritative commit sequencer (research §21, §22, §7;
//! `research/OrFS prompt.md` §7, §26).
//!
//! Every authoritative logical position is assigned here and nowhere else. The
//! sequencer drives a [`Transaction`] through the states of [`TxState`],
//! performing exactly this sequence (research §21):
//!
//! ```text
//! validate → build records → reserve append positions → write data records
//!   → wait for required write completions → write/validate TX_COMMIT
//!   → publish new in-memory committed root → reply per durability mode
//! ```
//!
//! # Visibility
//!
//! A reader observes exactly one thing: [`Log::committed_end_offset`], the
//! committed root `R`. `R` advances **only** after a complete, valid `TX_COMMIT`
//! has been written and read back from the backing store. Therefore a reader can
//! never observe a partially applied transaction: `R` always sits on a
//! transaction boundary (research §5.4, I3).
//!
//! # The distinction the design insists on
//!
//! ```text
//! allocated ≠ submitted ≠ completed ≠ committed ≠ durable
//! ```
//!
//! * *allocated* — an [`crate::log::AppendReservation`] exists (state `Reserved`).
//! * *submitted* — bytes were handed to the backing store (`Submitted`).
//! * *completed* — the write returned (`DataCompleted`).
//! * *committed* — the `TX_COMMIT` record is fully written and validated
//!   (`CommitCompleted`) and the root is published (`Published`).
//! * *durable* — the required `fsync`/directory durability has completed
//!   (`Durable`).
//!
//! # Durability acknowledgment contracts
//!
//! See [`DurabilityMode`] for the exact acknowledgment semantics of `sync`,
//! `ordered`, and `batched`. A buffered-write acknowledgment is **not** a
//! power-loss durability guarantee, and this module never reports it as one.

use crate::error::{OrfsError, Result};
use crate::failpoints::{self, Failpoint};
use crate::log::{AppendReservation, Log};
use crate::record::{Record, RecordType};
use crate::transaction::{
    bracket_checksum, AbortReason, Transaction, TxAbortPayload, TxBeginPayload, TxCommitPayload,
    TxState,
};

/// The durability profile governing when a commit is acknowledged.
///
/// The three profiles have deliberately different acknowledgment contracts; the
/// difference is *not* merely performance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum DurabilityMode {
    /// Acknowledge only after the transaction's data and `TX_COMMIT` records and
    /// the segment (and any new segment's directory entry) have been made durable
    /// with `fsync`, as far as the backing filesystem's guarantees extend.
    ///
    /// Ack state: [`TxState::Durable`]. A successful reply means the transaction
    /// will survive a *process* crash and, subject to the underlying device's
    /// documented cache behaviour, a power loss.
    Sync,
    /// Write order is preserved and the root is published after the writes
    /// complete; no `fsync` is issued by the commit itself. Durability is
    /// established later by an explicit [`CommitSequencer::flush`] or `fsync`.
    ///
    /// Ack state: [`TxState::Published`]. A successful reply means "ordered and
    /// visible", **not** "power-loss durable".
    Ordered,
    /// Like `ordered`, but a single `fsync` is amortised over up to `batch_size`
    /// transactions (research §22). A reply means "ordered and visible".
    /// Durability for a transaction is established when its batch's sync point is
    /// reached — either when `batch_size` transactions accumulate or when
    /// [`CommitSequencer::flush`] is called.
    ///
    /// Ack state: [`TxState::Published`], or [`TxState::Durable`] if this commit
    /// completed a batch.
    Batched {
        /// Maximum number of unsynced published transactions per sync point.
        batch_size: u32,
    },
}

impl DurabilityMode {
    /// Parse `sync`, `ordered`, or `batched` (optionally `batched:N`).
    pub fn parse(s: &str) -> Result<DurabilityMode> {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "sync" => Ok(DurabilityMode::Sync),
            "ordered" => Ok(DurabilityMode::Ordered),
            "batched" => Ok(DurabilityMode::Batched { batch_size: 64 }),
            _ => {
                if let Some(n) = s.strip_prefix("batched:") {
                    let batch_size = n.parse::<u32>().map_err(|_| {
                        OrfsError::InvalidArgument(format!("invalid batch size in {s:?}"))
                    })?;
                    if batch_size == 0 {
                        return Err(OrfsError::InvalidArgument(
                            "batch size must be non-zero".into(),
                        ));
                    }
                    Ok(DurabilityMode::Batched { batch_size })
                } else {
                    Err(OrfsError::InvalidArgument(format!(
                        "unknown durability mode {s:?}"
                    )))
                }
            }
        }
    }

    /// Stable name for evidence and the CLI.
    pub fn name(self) -> &'static str {
        match self {
            DurabilityMode::Sync => "sync",
            DurabilityMode::Ordered => "ordered",
            DurabilityMode::Batched { .. } => "batched",
        }
    }

    /// Whether a successful commit under this profile is a power-loss durability
    /// claim. Always `false`: even `sync` can only promise what the backing
    /// device documents, and OrFS does not overstate it.
    pub const fn claims_power_loss_durability(self) -> bool {
        false
    }
}

impl std::fmt::Display for DurabilityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The result of a successful commit.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CommitOutcome {
    pub transaction_id: u64,
    /// The new committed root (a transaction boundary).
    pub root: u64,
    pub begin_offset: u64,
    pub commit_offset: u64,
    pub data_record_count: u64,
    pub bracketed_byte_length: u64,
    /// The final lifecycle state (see the durability ack contract).
    pub state: TxState,
    pub durability: DurabilityMode,
    /// Whether this commit's own bytes were `fsync`ed.
    pub durable: bool,
}

/// The result of a successful abort.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AbortOutcome {
    pub transaction_id: u64,
    pub reason: AbortReason,
    /// The committed root, unchanged by the abort.
    pub root: u64,
    pub begin_offset: u64,
    pub abort_offset: u64,
}

/// The result of an explicit synchronization point.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncOutcome {
    /// The root that is now durable.
    pub root: u64,
    /// How many previously-unsynced transactions this sync covered.
    pub transactions: u32,
}

/// The outcome of the write-and-publish phase of a commit, *before* the
/// durability acknowledgment. Shared by single ([`CommitSequencer::commit`]) and
/// grouped ([`CommitSequencer::commit_group`]) commits so that grouped commits
/// can amortise one durability barrier over many published transactions while
/// still reporting each member's exact ordered position.
struct Published {
    transaction_id: u64,
    root: u64,
    begin_offset: u64,
    commit_offset: u64,
    data_record_count: u64,
    bracketed_byte_length: u64,
}

impl Published {
    fn into_outcome(
        self,
        durability: DurabilityMode,
        state: TxState,
        durable: bool,
    ) -> CommitOutcome {
        CommitOutcome {
            transaction_id: self.transaction_id,
            root: self.root,
            begin_offset: self.begin_offset,
            commit_offset: self.commit_offset,
            data_record_count: self.data_record_count,
            bracketed_byte_length: self.bracketed_byte_length,
            state,
            durability,
            durable,
        }
    }
}

/// The single authoritative commit sequencer.
///
/// Owns the *only* handle by which committed roots advance. Construct one per
/// open volume and use it for every mutation.
pub struct CommitSequencer<'a> {
    log: &'a mut Log,
    durability: DurabilityMode,
    next_tx_id: u64,
    /// Number of published-but-unsynced transactions in the current batch.
    unsynced: u32,
    /// The oldest root not yet durable (for reporting).
    oldest_unsynced: Option<u64>,
}

impl<'a> CommitSequencer<'a> {
    /// Create a sequencer over an open [`crate::volume::Volume`].
    ///
    /// Transaction ids are seeded from the committed transaction count so that a
    /// fresh sequencer never reuses an id within a single volume's history of
    /// *committed* transactions.
    pub fn new(
        vol: &'a mut crate::volume::Volume,
        durability: DurabilityMode,
    ) -> CommitSequencer<'a> {
        CommitSequencer::from_log(&mut vol.log, durability)
    }

    /// Create a sequencer directly over a [`Log`].
    ///
    /// Transaction ids are seeded strictly above the greatest id ever observed
    /// in the log — committed, aborted (never published), or abandoned in a
    /// quarantined tail. An id consumed by an aborted transaction is therefore
    /// never reused, and allocation is monotonic across reopen.
    pub fn from_log(log: &'a mut Log, durability: DurabilityMode) -> CommitSequencer<'a> {
        let next_tx_id = log.max_transaction_id().saturating_add(1);
        CommitSequencer {
            log,
            durability,
            next_tx_id,
            unsynced: 0,
            oldest_unsynced: None,
        }
    }

    /// The durability profile in force.
    pub fn durability(&self) -> DurabilityMode {
        self.durability
    }

    /// The next transaction identity that will be allocated.
    pub fn peek_transaction_id(&self) -> u64 {
        self.next_tx_id
    }

    /// Read access to the underlying log.
    pub fn log(&self) -> &Log {
        self.log
    }

    /// Mutable access to the underlying log (for recovery/verification only).
    pub fn log_mut(&mut self) -> &mut Log {
        self.log
    }

    /// Start building a transaction with a freshly allocated identity.
    pub fn begin(&mut self) -> Result<crate::transaction::TransactionBuilder> {
        let id = self.next_tx_id;
        self.next_tx_id = self.next_tx_id.checked_add(1).ok_or(OrfsError::Overflow {
            what: "transaction id",
        })?;
        crate::transaction::TransactionBuilder::new(id)
    }

    /// Commit `tx`, advancing the committed root atomically.
    ///
    /// The transaction is consumed. On any error the caller must discard the log
    /// (drop it and reopen): a failure may have written partial bytes that are
    /// never reused (Law I) but leave the in-memory writer state unusable.
    pub fn commit(&mut self, tx: Transaction) -> Result<CommitOutcome> {
        let result = self.commit_inner(tx);
        if let Err(e) = &result {
            // An unrecoverable authoritative-store failure (out of space or a
            // device error) latches the volume into degraded/read-only mode: it
            // must stop accepting writes rather than acknowledge onto an
            // unreliable store (research I7, I8; §31).
            if e.is_authoritative_store_failure() {
                self.log.degrade(e.to_string());
            }
        }
        result
    }

    fn commit_inner(&mut self, tx: Transaction) -> Result<CommitOutcome> {
        // A degraded/read-only volume refuses every further mutation with EROFS,
        // even before structural checks: it must not accept writes onto an
        // unreliable store (research I7, I8; §31).
        if self.log.is_degraded() {
            let reason = self
                .log
                .capacity()
                .degraded_reason()
                .unwrap_or("unrecoverable authoritative-store failure");
            return Err(OrfsError::ReadOnly(format!("volume degraded: {reason}")));
        }
        if tx.state() != TxState::Prepared {
            return Err(OrfsError::InvalidArgument(format!(
                "transaction {} is not prepared (state {})",
                tx.id(),
                tx.state()
            )));
        }
        if self.log.open_transaction().is_some() {
            return Err(OrfsError::InvalidArgument(
                "a transaction is already open in the log".into(),
            ));
        }

        let published = self.publish_one(tx)?;
        let root = published.root;
        let (state, durable) = self.reply_durability(root)?;
        Ok(published.into_outcome(self.durability, state, durable))
    }

    /// Perform the entire write-and-publish sequence for one prepared
    /// transaction, leaving it `Published` and its root installed in memory.
    ///
    /// This is the shared body of single ([`Self::commit`]) and grouped
    /// ([`Self::commit_group`]) commits; it stops *before* the durability
    /// acknowledgment, which the caller issues (per transaction, or once per
    /// group). All failpoints on the single-commit path fire exactly as before.
    fn publish_one(&mut self, mut tx: Transaction) -> Result<Published> {
        let tx_id = tx.id();
        // The id is now consumed regardless of the outcome: never reissue it.
        self.next_tx_id = self.next_tx_id.max(tx_id.saturating_add(1));

        // --- 0. early authoritative-space admission ------------------------
        // Admit the whole framed transaction (TX_BEGIN + data + TX_COMMIT) before
        // the first byte is written, so a full device refuses cleanly with ENOSPC
        // instead of leaving a partial transaction (research I7, §31).
        let projected = self.projected_transaction_bytes(&tx, tx_id)?;
        self.log.ensure_capacity(projected)?;

        // --- 1. reserve + write TX_BEGIN -----------------------------------
        failpoints::check(Failpoint::BeforeReservation)?;
        let begin_payload = tx.begin().encode();
        let mut begin_rec = Record::new(
            RecordType::TxBegin,
            self.log.next_sequence_number(),
            tx_id,
            0,
            0,
            crate::record::FLAG_NONE,
            begin_payload.to_vec(),
        )?;
        seal(&mut begin_rec, self.log.next_sequence_number(), tx_id);
        let begin_offset = self.write_record(&mut begin_rec)?;
        tx.transition(TxState::Reserved)?;
        tx.transition(TxState::Submitted)?;

        // --- 2. reserve + write data records -------------------------------
        let mut bracket: Vec<u8> = Vec::new();
        bracket.extend_from_slice(&begin_rec.encode()?);
        let data_count = tx.records().len();
        for i in 0..data_count {
            let mut rec = tx.records()[i].clone();
            seal(&mut rec, self.log.next_sequence_number(), tx_id);
            bracket.extend_from_slice(&rec.encode()?);
            self.write_record(&mut rec)?;
            failpoints::check(Failpoint::AfterPartialRecordWrite)?;
        }
        tx.transition(TxState::DataCompleted)?;

        // --- 3. build, write, and validate TX_COMMIT -----------------------
        failpoints::check(Failpoint::BeforeCommit)?;
        let commit_payload = TxCommitPayload {
            transaction_id: tx_id,
            record_count: 1 + data_count as u64,
            bracketed_byte_length: bracket.len() as u64,
            commit_sequence_number: self.log.next_sequence_number(),
            bracket_checksum: bracket_checksum(&bracket),
        };
        let mut commit_rec = Record::new(
            RecordType::TxCommit,
            self.log.next_sequence_number(),
            tx_id,
            0,
            0,
            crate::record::FLAG_NONE,
            commit_payload.encode().to_vec(),
        )?;
        seal(&mut commit_rec, self.log.next_sequence_number(), tx_id);
        let commit_bytes = commit_rec.encode()?;
        let res = self.reserve(commit_bytes.len() as u64)?;
        failpoints::check(Failpoint::AfterReservation)?;
        self.torn_write(&res, &commit_bytes, Failpoint::DuringCommitRecordWrite)?;
        let end = res
            .logical_offset
            .checked_add(res.len)
            .ok_or(OrfsError::Overflow {
                what: "commit end offset",
            })?;

        // Validate TX_COMMIT from the backing store, not from our buffer.
        let readback = self.log.read_back(&res)?;
        let (decoded, used) =
            Record::decode(&readback).map_err(|e| OrfsError::Corrupt(format!("commit: {e}")))?;
        if used != readback.len() {
            return Err(OrfsError::Corrupt(
                "commit record length disagreement".into(),
            ));
        }
        if decoded.known_type().map_err(OrfsError::from)? != RecordType::TxCommit {
            return Err(OrfsError::Corrupt("commit record is not TX_COMMIT".into()));
        }
        let on_disk_commit = TxCommitPayload::decode(&decoded.payload)?;
        if on_disk_commit != commit_payload {
            return Err(OrfsError::Corrupt(
                "commit record payload disagreement".into(),
            ));
        }

        tx.transition(TxState::CommitCompleted)?;

        // --- 4. publish the new committed root -----------------------------
        failpoints::check(Failpoint::AfterCommitCompletion)?;
        failpoints::check(Failpoint::BeforePublication)?;
        self.log
            .record_written(&commit_rec, res.logical_offset, end)?;
        self.log.publish_root_at(end)?;
        tx.transition(TxState::Published)?;

        Ok(Published {
            transaction_id: tx_id,
            root: end,
            begin_offset,
            commit_offset: res.logical_offset,
            data_record_count: data_count as u64,
            bracketed_byte_length: bracket.len() as u64,
        })
    }

    /// Allocate `n` consecutive transaction identities from the sequencer.
    ///
    /// The identities are reserved in the sequencer immediately, so a later
    /// `begin`/`commit` on the same sequencer can never reissue them. They may be
    /// handed to independent workers that build transactions concurrently
    /// before the whole batch is published (Phase 31, parallel preparation).
    pub fn begin_many(&mut self, n: usize) -> Result<Vec<crate::transaction::TransactionBuilder>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.begin()?);
        }
        Ok(out)
    }

    /// Commit a **group** of independently prepared transactions as one ordered
    /// batch (Phase 31 — ordered group commit).
    ///
    /// # Ordering
    ///
    /// Transactions are published **serially, in the order given**, so the
    /// visible commit sequence is exactly the caller's order: each member's root
    /// is strictly greater than the previous member's and every intermediate
    /// root is a complete transaction boundary. Grouping never reorders the
    /// authoritative sequence.
    ///
    /// # Acknowledgment contract under grouping
    ///
    /// The whole group shares **one** durability barrier, issued only after every
    /// member's bytes have been written and published:
    ///
    /// * `sync` — one `fsync` covers the entire group; every member is acked
    ///   [`TxState::Durable`] with `durable == true`.
    /// * `ordered` — no `fsync`; every member is acked [`TxState::Published`]
    ///   (`durable == false`). Ordering and visibility only.
    /// * `batched { batch_size }` — the group's size is added to the running
    ///   unsynced count; if the batch completes, one `fsync` covers every member
    ///   still unsynced and the whole group is acked [`TxState::Durable`],
    ///   otherwise the whole group is acked [`TxState::Published`].
    ///
    /// In every mode the barrier runs **after** every member's bytes are on the
    /// backing store, so no member is acked `Durable` before the `fsync` that
    /// covers *its own* bytes has completed. A caller is never acknowledged for a
    /// durability condition its own bytes did not satisfy.
    ///
    /// # Failure
    ///
    /// If any member fails, the group returns the error and **no** member is
    /// acknowledged: members already published remain committed (each is
    /// individually atomic and sits at a transaction boundary), but the caller is
    /// told the batch failed, never that it succeeded. As with a single commit,
    /// an authoritative-store failure latches the volume degraded.
    pub fn commit_group(&mut self, txs: Vec<Transaction>) -> Result<Vec<CommitOutcome>> {
        let result = self.commit_group_inner(txs);
        if let Err(e) = &result {
            if e.is_authoritative_store_failure() {
                self.log.degrade(e.to_string());
            }
        }
        result
    }

    fn commit_group_inner(&mut self, txs: Vec<Transaction>) -> Result<Vec<CommitOutcome>> {
        if txs.is_empty() {
            return Ok(Vec::new());
        }
        if self.log.is_degraded() {
            let reason = self
                .log
                .capacity()
                .degraded_reason()
                .unwrap_or("unrecoverable authoritative-store failure");
            return Err(OrfsError::ReadOnly(format!("volume degraded: {reason}")));
        }
        // Validate the whole group *before* writing anything: either every member
        // is prepared and no transaction is open, or nothing is published.
        for tx in &txs {
            if tx.state() != TxState::Prepared {
                return Err(OrfsError::InvalidArgument(format!(
                    "transaction {} is not prepared (state {})",
                    tx.id(),
                    tx.state()
                )));
            }
        }
        if self.log.open_transaction().is_some() {
            return Err(OrfsError::InvalidArgument(
                "a transaction is already open in the log".into(),
            ));
        }

        let count = txs.len();
        let mut published = Vec::with_capacity(count);
        for tx in txs {
            published.push(self.publish_one(tx)?);
        }

        // One shared durability barrier for the whole group, issued strictly
        // after every member's bytes are written and published.
        let oldest_root = published[0].root;
        let (state, durable) = self.group_durability(oldest_root, count)?;
        let durability = self.durability;
        Ok(published
            .into_iter()
            .map(|p| p.into_outcome(durability, state, durable))
            .collect())
    }

    /// Issue the shared durability barrier for a group of `count` transactions
    /// whose oldest newly-published root is `oldest_root`, and report the ack
    /// state every member shares (see [`CommitSequencer::commit_group`]).
    fn group_durability(&mut self, oldest_root: u64, count: usize) -> Result<(TxState, bool)> {
        failpoints::check(Failpoint::AfterPublicationBeforeSync)?;
        let count = u32::try_from(count).unwrap_or(u32::MAX);
        match self.durability {
            DurabilityMode::Sync => {
                self.log.sync()?;
                self.unsynced = 0;
                self.oldest_unsynced = None;
                Ok((TxState::Durable, true))
            }
            DurabilityMode::Ordered => {
                self.unsynced = self.unsynced.saturating_add(count);
                self.oldest_unsynced.get_or_insert(oldest_root);
                Ok((TxState::Published, false))
            }
            DurabilityMode::Batched { batch_size } => {
                self.unsynced = self.unsynced.saturating_add(count);
                self.oldest_unsynced.get_or_insert(oldest_root);
                if self.unsynced >= batch_size {
                    self.log.sync()?;
                    self.unsynced = 0;
                    self.oldest_unsynced = None;
                    Ok((TxState::Durable, true))
                } else {
                    Ok((TxState::Published, false))
                }
            }
        }
    }

    /// Abandon `tx` by writing `TX_BEGIN .. TX_ABORT`. The committed root does
    /// not advance, so no state becomes visible.
    pub fn abort(
        &mut self,
        tx: Transaction,
        reason: AbortReason,
        message: &str,
    ) -> Result<AbortOutcome> {
        let result = self.abort_inner(tx, reason, message);
        if let Err(e) = &result {
            if e.is_authoritative_store_failure() {
                self.log.degrade(e.to_string());
            }
        }
        result
    }

    fn abort_inner(
        &mut self,
        mut tx: Transaction,
        reason: AbortReason,
        message: &str,
    ) -> Result<AbortOutcome> {
        if self.log.is_degraded() {
            let why = self
                .log
                .capacity()
                .degraded_reason()
                .unwrap_or("unrecoverable authoritative-store failure");
            return Err(OrfsError::ReadOnly(format!("volume degraded: {why}")));
        }
        if tx.state() != TxState::Prepared {
            return Err(OrfsError::InvalidArgument(
                "only a prepared transaction can be aborted".into(),
            ));
        }
        if self.log.open_transaction().is_some() {
            return Err(OrfsError::InvalidArgument(
                "a transaction is already open in the log".into(),
            ));
        }
        let tx_id = tx.id();
        // The id is now consumed regardless of the outcome: never reissue it.
        self.next_tx_id = self.next_tx_id.max(tx_id.saturating_add(1));

        failpoints::check(Failpoint::BeforeReservation)?;
        let begin_payload = TxBeginPayload {
            transaction_id: tx_id,
            // The bracket of an aborted transaction is *not* checksummed by a
            // commit; report the exact sizes anyway for diagnostics.
            expected_byte_length: 0,
            expected_record_count: 1 + tx.records().len() as u32,
        };
        let mut begin_rec = Record::new(
            RecordType::TxBegin,
            self.log.next_sequence_number(),
            tx_id,
            0,
            0,
            crate::record::FLAG_NONE,
            begin_payload.encode().to_vec(),
        )?;
        seal(&mut begin_rec, self.log.next_sequence_number(), tx_id);
        let begin_offset = self.write_record(&mut begin_rec)?;
        tx.transition(TxState::Reserved)?;
        tx.transition(TxState::Submitted)?;

        let data_count = tx.records().len();
        for i in 0..data_count {
            let mut rec = tx.records()[i].clone();
            seal(&mut rec, self.log.next_sequence_number(), tx_id);
            self.write_record(&mut rec)?;
        }
        tx.transition(TxState::DataCompleted)?;

        failpoints::check(Failpoint::BeforeCommit)?;
        let abort_payload = TxAbortPayload {
            transaction_id: tx_id,
            reason,
            message: message.to_string(),
        };
        let abort_bytes = abort_payload.encode()?;
        let mut abort_rec = Record::new(
            RecordType::TxAbort,
            self.log.next_sequence_number(),
            tx_id,
            0,
            0,
            crate::record::FLAG_NONE,
            abort_bytes,
        )?;
        seal(&mut abort_rec, self.log.next_sequence_number(), tx_id);
        let bytes = abort_rec.encode()?;
        let res = self.reserve(bytes.len() as u64)?;
        failpoints::check(Failpoint::AfterReservation)?;
        self.torn_write(&res, &bytes, Failpoint::DuringRecordWrite)?;
        let end = res
            .logical_offset
            .checked_add(res.len)
            .ok_or(OrfsError::Overflow {
                what: "abort end offset",
            })?;
        self.log
            .record_written(&abort_rec, res.logical_offset, end)?;

        tx.transition(TxState::CommitCompleted)?;

        Ok(AbortOutcome {
            transaction_id: tx_id,
            reason,
            root: self.log.committed_end_offset(),
            begin_offset,
            abort_offset: res.logical_offset,
        })
    }

    /// Force a synchronization point: `fsync` the log and mark every published
    /// transaction durable. Returns the root that is now durable.
    pub fn flush(&mut self) -> Result<SyncOutcome> {
        let root = self.log.committed_end_offset();
        let transactions = self.unsynced;
        self.log.sync()?;
        self.unsynced = 0;
        self.oldest_unsynced = None;
        Ok(SyncOutcome { root, transactions })
    }

    // -- internals ---------------------------------------------------------

    /// The exact framed byte length a transaction will occupy: `TX_BEGIN`, every
    /// data record, and `TX_COMMIT`, each with its 60-byte header and 16-byte
    /// footer. Used for early authoritative-space admission.
    fn projected_transaction_bytes(&self, tx: &Transaction, tx_id: u64) -> Result<u64> {
        let seq = self.log.next_sequence_number();
        let mut total = 0u64;
        let begin_payload = tx.begin().encode();
        let begin_rec = Record::new(
            RecordType::TxBegin,
            seq,
            tx_id,
            0,
            0,
            crate::record::FLAG_NONE,
            begin_payload.to_vec(),
        )?;
        total = total.saturating_add(begin_rec.encode()?.len() as u64);
        for rec in tx.records() {
            let mut rec = rec.clone();
            seal(&mut rec, seq, tx_id);
            total = total.saturating_add(rec.encode()?.len() as u64);
        }
        let commit_payload = TxCommitPayload {
            transaction_id: tx_id,
            record_count: 1 + tx.records().len() as u64,
            bracketed_byte_length: 0,
            commit_sequence_number: seq,
            bracket_checksum: [0u8; crate::transaction::BRACKET_CHECKSUM_LEN],
        };
        let commit_rec = Record::new(
            RecordType::TxCommit,
            seq,
            tx_id,
            0,
            0,
            crate::record::FLAG_NONE,
            commit_payload.encode().to_vec(),
        )?;
        total = total.saturating_add(commit_rec.encode()?.len() as u64);
        Ok(total)
    }

    /// Reserve `len` bytes and write a record, injecting the torn-write
    /// failpoints. Returns the record's logical offset.
    fn write_record(&mut self, record: &mut Record) -> Result<u64> {
        let bytes = record.encode()?;
        let res = self.reserve(bytes.len() as u64)?;
        failpoints::check(Failpoint::AfterReservation)?;
        self.torn_write(&res, &bytes, Failpoint::DuringRecordWrite)?;
        let end = res
            .logical_offset
            .checked_add(res.len)
            .ok_or(OrfsError::Overflow {
                what: "record end offset",
            })?;
        self.log.record_written(record, res.logical_offset, end)?;
        Ok(res.logical_offset)
    }

    /// Reserve an append position, surfacing rollover failpoints (which live in
    /// [`Log::reserve`]).
    fn reserve(&mut self, len: u64) -> Result<AppendReservation> {
        self.log.reserve(len)
    }

    /// Write `bytes`, splitting the write when `fp` is armed so that a failure
    /// leaves a torn record on disk. When `fp` is not armed this is a single
    /// write followed by a no-op check.
    fn torn_write(&mut self, res: &AppendReservation, bytes: &[u8], fp: Failpoint) -> Result<()> {
        if failpoints::armed(fp) {
            let half = bytes.len() / 2;
            if half > 0 {
                self.log.write_partial_reserved(res, &bytes[..half])?;
            }
        }
        failpoints::check(fp)?;
        // Complete the reservation with the full record (idempotent over any
        // prefix already written).
        self.log.write_reserved(res, bytes)?;
        Ok(())
    }

    fn reply_durability(&mut self, root: u64) -> Result<(TxState, bool)> {
        failpoints::check(Failpoint::AfterPublicationBeforeSync)?;
        match self.durability {
            DurabilityMode::Sync => {
                self.log.sync()?;
                self.unsynced = 0;
                self.oldest_unsynced = None;
                Ok((TxState::Durable, true))
            }
            DurabilityMode::Ordered => {
                self.unsynced = self.unsynced.saturating_add(1);
                self.oldest_unsynced.get_or_insert(root);
                Ok((TxState::Published, false))
            }
            DurabilityMode::Batched { batch_size } => {
                self.unsynced = self.unsynced.saturating_add(1);
                self.oldest_unsynced.get_or_insert(root);
                if self.unsynced >= batch_size {
                    self.log.sync()?;
                    self.unsynced = 0;
                    self.oldest_unsynced = None;
                    Ok((TxState::Durable, true))
                } else {
                    Ok((TxState::Published, false))
                }
            }
        }
    }
}

/// Stamp a record's envelope fields and recompute its header checksum.
fn seal(record: &mut Record, sequence_number: u64, transaction_id: u64) {
    record.header.sequence_number = sequence_number;
    record.header.transaction_id = transaction_id;
    record.header.payload_length = record.payload.len() as u64;
    record.header = record.header.with_recomputed_check();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durability_mode_parsing() {
        assert_eq!(DurabilityMode::parse("sync").unwrap(), DurabilityMode::Sync);
        assert_eq!(
            DurabilityMode::parse("ordered").unwrap(),
            DurabilityMode::Ordered
        );
        assert_eq!(
            DurabilityMode::parse("batched").unwrap(),
            DurabilityMode::Batched { batch_size: 64 }
        );
        assert_eq!(
            DurabilityMode::parse("Batched:8").unwrap(),
            DurabilityMode::Batched { batch_size: 8 }
        );
        assert!(DurabilityMode::parse("batched:0").is_err());
        assert!(DurabilityMode::parse("warp").is_err());
        assert!(!DurabilityMode::Sync.claims_power_loss_durability());
    }

    #[test]
    fn durability_names_are_stable() {
        assert_eq!(DurabilityMode::Sync.name(), "sync");
        assert_eq!(DurabilityMode::Ordered.name(), "ordered");
        assert_eq!(DurabilityMode::Batched { batch_size: 1 }.name(), "batched");
    }
}
