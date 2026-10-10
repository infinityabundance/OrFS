//! Transaction model: explicit states, typed payload codecs, and a validating
//! builder (research §5.3, §7; `research/OrFS prompt.md` §7).
//!
//! # Shape of a transaction
//!
//! A transaction is an ordered list of *immutable* records bracketed by
//! `TX_BEGIN … TX_COMMIT` (commit) or `TX_BEGIN … TX_ABORT` (abandonment):
//!
//! ```text
//! TX_BEGIN
//!   INODE_CREATE
//!   DENTRY_ADD
//! TX_COMMIT
//! ```
//!
//! The records are immutable once built: mutation of committed state is always a
//! *new* transaction appended to the log, never an in-place edit (Law I).
//!
//! # States
//!
//! [`TxState`] names the points the commit sequencer ([`crate::commit`]) drives a
//! transaction through. The position of a state is a claim about the physical
//! and in-memory facts at that instant; the sequencer is the *only* component
//! permitted to advance it. In particular the distinctions are deliberately
//! strict:
//!
//! ```text
//! allocated ≠ submitted ≠ completed ≠ committed ≠ durable
//! ```
//!
//! # Payload codecs
//!
//! Each structural record carries a checksummed, versioned, little-endian payload
//! so that recovery and `orfs verify --deep` can cross-check the bracket without
//! trusting the in-memory state. See [`TxBeginPayload`], [`TxCommitPayload`],
//! [`TxAbortPayload`].

use crate::error::{OrfsError, Result};
use crate::record::{get_u16, get_u32, get_u64, put_u32, put_u64, Record, RecordType};

// ---------------------------------------------------------------------------
// Payload magics and lengths
// ---------------------------------------------------------------------------

/// `TX_BEGIN` payload magic; LE bytes spell `TBN1`.
pub const TX_BEGIN_MAGIC: u32 = 0x314E_4254;
/// `TX_COMMIT` payload magic; LE bytes spell `TCM1`.
pub const TX_COMMIT_MAGIC: u32 = 0x314D_4354;
/// `TX_ABORT` payload magic; LE bytes spell `TBA1`.
pub const TX_ABORT_MAGIC: u32 = 0x3141_4254;

/// Fixed `TX_BEGIN` payload length.
pub const TX_BEGIN_PAYLOAD_LEN: usize = 28;
/// Fixed `TX_COMMIT` payload length.
pub const TX_COMMIT_PAYLOAD_LEN: usize = 72;
/// Fixed prefix of a `TX_ABORT` payload (before the reason message).
pub const TX_ABORT_PREFIX_LEN: usize = 20;
/// Maximum reason-message length in a `TX_ABORT` payload.
pub const TX_ABORT_MAX_MESSAGE: usize = 4096;
/// Length of the BLAKE3 bracket checksum carried by `TX_COMMIT`.
pub const BRACKET_CHECKSUM_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Transaction states
// ---------------------------------------------------------------------------

/// The explicit lifecycle states of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TxState {
    /// Records built and validated; nothing reserved or written.
    Prepared,
    /// Append positions have been reserved in the log.
    Reserved,
    /// Data records have been submitted to the backing store.
    Submitted,
    /// Every data record write has completed (not yet committed).
    DataCompleted,
    /// The `TX_COMMIT` record has been written and validated.
    CommitCompleted,
    /// The new committed root has been published in memory.
    Published,
    /// The transaction is durable according to the active durability profile.
    Durable,
    /// The transaction failed and must never become visible.
    Failed,
}

impl TxState {
    /// Stable snake-case name (used by evidence).
    pub const fn name(self) -> &'static str {
        match self {
            TxState::Prepared => "prepared",
            TxState::Reserved => "reserved",
            TxState::Submitted => "submitted",
            TxState::DataCompleted => "data_completed",
            TxState::CommitCompleted => "commit_completed",
            TxState::Published => "published",
            TxState::Durable => "durable",
            TxState::Failed => "failed",
        }
    }

    /// Whether a transition from `self` to `next` is legal.
    ///
    /// The only edges are the forward chain plus "anything → `Failed`". A state
    /// never moves backward, and `Durable`/`Failed` are terminal.
    pub const fn can_transition_to(self, next: TxState) -> bool {
        use TxState::*;
        matches!(
            (self, next),
            (Prepared, Reserved)
                | (Reserved, Submitted)
                | (Submitted, DataCompleted)
                | (DataCompleted, CommitCompleted)
                | (CommitCompleted, Published)
                | (Published, Durable)
        ) || matches!(next, Failed) && !matches!(self, Failed | Durable)
    }

    /// Whether this state is terminal.
    pub const fn is_terminal(self) -> bool {
        matches!(self, TxState::Durable | TxState::Failed)
    }
}

impl std::fmt::Display for TxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

// ---------------------------------------------------------------------------
// TX_BEGIN payload
// ---------------------------------------------------------------------------

/// `TX_BEGIN` payload (v1, 28 bytes).
///
/// ```text
/// off  size  field
///   0     4  magic (TBN1)
///   4     8  transaction_id
///  12     8  expected_byte_length  (framed bytes of TX_BEGIN..last data record)
///  20     4  expected_record_count (records in that range, TX_BEGIN included)
///  24     4  CRC32C over bytes [0, 24)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct TxBeginPayload {
    /// The transaction identity (also present in every record header).
    pub transaction_id: u64,
    /// Expected framed byte length of `TX_BEGIN .. last data record`.
    pub expected_byte_length: u64,
    /// Expected number of records in `TX_BEGIN .. last data record`.
    pub expected_record_count: u32,
}

impl TxBeginPayload {
    /// Encode to the fixed 28-byte payload.
    pub fn encode(&self) -> [u8; TX_BEGIN_PAYLOAD_LEN] {
        let mut b = [0u8; TX_BEGIN_PAYLOAD_LEN];
        put_u32(&mut b, 0, TX_BEGIN_MAGIC);
        put_u64(&mut b, 4, self.transaction_id);
        put_u64(&mut b, 12, self.expected_byte_length);
        put_u32(&mut b, 20, self.expected_record_count);
        let check = crc32c::crc32c(&b[..24]);
        put_u32(&mut b, 24, check);
        b
    }

    /// Decode and validate a `TX_BEGIN` payload.
    pub fn decode(buf: &[u8]) -> Result<TxBeginPayload> {
        if buf.len() != TX_BEGIN_PAYLOAD_LEN {
            return Err(OrfsError::Corrupt(format!(
                "TX_BEGIN payload is {} bytes, expected {TX_BEGIN_PAYLOAD_LEN}",
                buf.len()
            )));
        }
        if get_u32(buf, 0) != TX_BEGIN_MAGIC {
            return Err(OrfsError::Corrupt("TX_BEGIN payload bad magic".into()));
        }
        if get_u32(buf, 24) != crc32c::crc32c(&buf[..24]) {
            return Err(OrfsError::Corrupt(
                "TX_BEGIN payload checksum mismatch".into(),
            ));
        }
        Ok(TxBeginPayload {
            transaction_id: get_u64(buf, 4),
            expected_byte_length: get_u64(buf, 12),
            expected_record_count: get_u32(buf, 20),
        })
    }
}

// ---------------------------------------------------------------------------
// TX_COMMIT payload
// ---------------------------------------------------------------------------

/// `TX_COMMIT` payload (v1, 72 bytes).
///
/// ```text
/// off  size  field
///   0     4  magic (TCM1)
///   4     8  transaction_id
///  12     8  record_count            (records in the bracketed range)
///  20     8  bracketed_byte_length   (framed bytes in the bracketed range)
///  28     8  commit_sequence_number  (this record's own sequence number)
///  36    32  bracket_checksum        (BLAKE3 over the bracketed bytes)
///  68     4  CRC32C over bytes [0, 68)
/// ```
///
/// The *bracketed range* is `TX_BEGIN .. last data record`; the checksum does not
/// include the `TX_COMMIT` record itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct TxCommitPayload {
    pub transaction_id: u64,
    pub record_count: u64,
    pub bracketed_byte_length: u64,
    pub commit_sequence_number: u64,
    pub bracket_checksum: [u8; BRACKET_CHECKSUM_LEN],
}

impl TxCommitPayload {
    /// Encode to the fixed 72-byte payload.
    pub fn encode(&self) -> [u8; TX_COMMIT_PAYLOAD_LEN] {
        let mut b = [0u8; TX_COMMIT_PAYLOAD_LEN];
        put_u32(&mut b, 0, TX_COMMIT_MAGIC);
        put_u64(&mut b, 4, self.transaction_id);
        put_u64(&mut b, 12, self.record_count);
        put_u64(&mut b, 20, self.bracketed_byte_length);
        put_u64(&mut b, 28, self.commit_sequence_number);
        b[36..68].copy_from_slice(&self.bracket_checksum);
        let check = crc32c::crc32c(&b[..68]);
        put_u32(&mut b, 68, check);
        b
    }

    /// Decode and validate a `TX_COMMIT` payload.
    pub fn decode(buf: &[u8]) -> Result<TxCommitPayload> {
        if buf.len() != TX_COMMIT_PAYLOAD_LEN {
            return Err(OrfsError::Corrupt(format!(
                "TX_COMMIT payload is {} bytes, expected {TX_COMMIT_PAYLOAD_LEN}",
                buf.len()
            )));
        }
        if get_u32(buf, 0) != TX_COMMIT_MAGIC {
            return Err(OrfsError::Corrupt("TX_COMMIT payload bad magic".into()));
        }
        if get_u32(buf, 68) != crc32c::crc32c(&buf[..68]) {
            return Err(OrfsError::Corrupt(
                "TX_COMMIT payload checksum mismatch".into(),
            ));
        }
        let mut bracket_checksum = [0u8; BRACKET_CHECKSUM_LEN];
        bracket_checksum.copy_from_slice(&buf[36..68]);
        Ok(TxCommitPayload {
            transaction_id: get_u64(buf, 4),
            record_count: get_u64(buf, 12),
            bracketed_byte_length: get_u64(buf, 20),
            commit_sequence_number: get_u64(buf, 28),
            bracket_checksum,
        })
    }
}

/// Compute the BLAKE3 bracket checksum over the exact encoded bracket bytes.
pub fn bracket_checksum(bracket: &[u8]) -> [u8; BRACKET_CHECKSUM_LEN] {
    *blake3::hash(bracket).as_bytes()
}

// ---------------------------------------------------------------------------
// TX_ABORT payload
// ---------------------------------------------------------------------------

/// Why a transaction was abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    /// The caller abandoned the transaction.
    UserRequested,
    /// An argument or invariant failed validation after the bracket began.
    ValidationFailed,
    /// An internal error (for example an I/O fault) terminated the bracket.
    InternalError,
    /// The requested durability could not be established.
    DurabilityFailure,
}

impl AbortReason {
    /// The on-disk reason code.
    pub const fn code(self) -> u16 {
        match self {
            AbortReason::UserRequested => 1,
            AbortReason::ValidationFailed => 2,
            AbortReason::InternalError => 3,
            AbortReason::DurabilityFailure => 4,
        }
    }

    /// Decode a reason code.
    pub const fn from_code(code: u16) -> Option<AbortReason> {
        Some(match code {
            1 => AbortReason::UserRequested,
            2 => AbortReason::ValidationFailed,
            3 => AbortReason::InternalError,
            4 => AbortReason::DurabilityFailure,
            _ => return None,
        })
    }

    /// Stable snake-case name (used by evidence).
    pub const fn name(self) -> &'static str {
        match self {
            AbortReason::UserRequested => "user_requested",
            AbortReason::ValidationFailed => "validation_failed",
            AbortReason::InternalError => "internal_error",
            AbortReason::DurabilityFailure => "durability_failure",
        }
    }
}

/// `TX_ABORT` payload (v1, variable).
///
/// ```text
/// off  size  field
///   0     4  magic (TBA1)
///   4     8  transaction_id
///  12     2  reason_code
///  14     2  reserved (0)
///  16     4  message_length
///  20    ..  UTF-8 reason message
/// end     4  CRC32C over every preceding byte
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAbortPayload {
    pub transaction_id: u64,
    pub reason: AbortReason,
    pub message: String,
}

impl TxAbortPayload {
    /// Encode to a variable-length payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let msg = self.message.as_bytes();
        if msg.len() > TX_ABORT_MAX_MESSAGE {
            return Err(OrfsError::InvalidArgument(format!(
                "TX_ABORT message is {} bytes, limit {TX_ABORT_MAX_MESSAGE}",
                msg.len()
            )));
        }
        let mut b = Vec::with_capacity(TX_ABORT_PREFIX_LEN + msg.len() + 4);
        b.extend_from_slice(&TX_ABORT_MAGIC.to_le_bytes());
        b.extend_from_slice(&self.transaction_id.to_le_bytes());
        b.extend_from_slice(&self.reason.code().to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(msg.len() as u32).to_le_bytes());
        b.extend_from_slice(msg);
        let check = crc32c::crc32c(&b);
        b.extend_from_slice(&check.to_le_bytes());
        Ok(b)
    }

    /// Decode and validate a `TX_ABORT` payload.
    pub fn decode(buf: &[u8]) -> Result<TxAbortPayload> {
        if buf.len() < TX_ABORT_PREFIX_LEN + 4 {
            return Err(OrfsError::Corrupt("TX_ABORT payload too short".into()));
        }
        if get_u32(buf, 0) != TX_ABORT_MAGIC {
            return Err(OrfsError::Corrupt("TX_ABORT payload bad magic".into()));
        }
        let msg_len = get_u32(buf, 16) as usize;
        if msg_len > TX_ABORT_MAX_MESSAGE {
            return Err(OrfsError::Corrupt("TX_ABORT message too long".into()));
        }
        let body_end = TX_ABORT_PREFIX_LEN
            .checked_add(msg_len)
            .ok_or(OrfsError::Overflow {
                what: "TX_ABORT payload length",
            })?;
        if buf.len() != body_end + 4 {
            return Err(OrfsError::Corrupt(
                "TX_ABORT payload length disagreement".into(),
            ));
        }
        let stored = get_u32(buf, body_end);
        if stored != crc32c::crc32c(&buf[..body_end]) {
            return Err(OrfsError::Corrupt(
                "TX_ABORT payload checksum mismatch".into(),
            ));
        }
        let reason = AbortReason::from_code(get_u16(buf, 12))
            .ok_or_else(|| OrfsError::Corrupt("TX_ABORT unknown reason code".into()))?;
        let message = String::from_utf8(buf[TX_ABORT_PREFIX_LEN..body_end].to_vec())
            .map_err(|_| OrfsError::Corrupt("TX_ABORT message is not UTF-8".into()))?;
        Ok(TxAbortPayload {
            transaction_id: get_u64(buf, 4),
            reason,
            message,
        })
    }
}

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------

/// A validated, immutable transaction: a `TX_BEGIN`, an ordered list of data
/// records, and the bracket metadata computed from them.
#[derive(Debug, Clone)]
pub struct Transaction {
    id: u64,
    state: TxState,
    begin: TxBeginPayload,
    records: Vec<Record>,
}

impl Transaction {
    /// The transaction identity.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The current lifecycle state.
    pub fn state(&self) -> TxState {
        self.state
    }

    /// The `TX_BEGIN` payload.
    pub fn begin(&self) -> TxBeginPayload {
        self.begin
    }

    /// The immutable data records (in order), without assigned sequence numbers.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Set the lifecycle state, rejecting illegal transitions.
    pub fn transition(&mut self, next: TxState) -> Result<()> {
        if !self.state.can_transition_to(next) {
            return Err(OrfsError::InvalidArgument(format!(
                "illegal transaction state transition {} -> {}",
                self.state, next
            )));
        }
        self.state = next;
        Ok(())
    }

    /// Mark the transaction failed (always legal unless already terminal).
    pub fn fail(&mut self) -> Result<()> {
        self.transition(TxState::Failed)
    }

    /// The framed byte length of the bracket (`TX_BEGIN .. last data record`).
    pub fn bracket_byte_length(&self) -> u64 {
        self.begin.expected_byte_length
    }

    /// The number of records in the bracket (`TX_BEGIN` included).
    pub fn bracket_record_count(&self) -> u32 {
        self.begin.expected_record_count
    }
}

/// Builder for a [`Transaction`]. All argument validation happens in
/// [`TransactionBuilder::build`], *before* any append position is reserved.
#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    id: u64,
    records: Vec<Record>,
}

impl TransactionBuilder {
    /// Start building a transaction with the given (non-zero) identity.
    pub fn new(id: u64) -> Result<TransactionBuilder> {
        if id == 0 {
            return Err(OrfsError::InvalidArgument(
                "transaction id must be non-zero".into(),
            ));
        }
        Ok(TransactionBuilder {
            id,
            records: Vec::new(),
        })
    }

    /// Append a data record from its parts.
    ///
    /// `record_type` must be a mutating record type; the structural types
    /// `VOLUME_GENESIS`, `TX_BEGIN`, `TX_COMMIT`, and `TX_ABORT` are rejected
    /// here (they are supplied by the sequencer, not the caller).
    pub fn add(
        &mut self,
        record_type: RecordType,
        inode_id: u64,
        previous_inode_offset: u64,
        payload: Vec<u8>,
    ) -> Result<&mut Self> {
        let record = Record::new(
            record_type,
            /*sequence_number*/ 0,
            self.id,
            inode_id,
            previous_inode_offset,
            crate::record::FLAG_NONE,
            payload,
        )?;
        self.add_record(record)
    }

    /// Append a pre-built data record. Its `transaction_id` is overwritten with
    /// the transaction's id when the transaction is built.
    pub fn add_record(&mut self, record: Record) -> Result<&mut Self> {
        let ty = record.known_type().map_err(OrfsError::from)?;
        if matches!(
            ty,
            RecordType::VolumeGenesis
                | RecordType::TxBegin
                | RecordType::TxCommit
                | RecordType::TxAbort
        ) {
            return Err(OrfsError::InvalidArgument(format!(
                "{} is a structural type and cannot be a transaction data record",
                ty.name()
            )));
        }
        self.records.push(record);
        Ok(self)
    }

    /// How many data records have been added so far.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no data records have been added.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Validate and produce the [`Transaction`].
    ///
    /// Computes `expected_record_count` and `expected_byte_length` from the exact
    /// encoded sizes (sequence numbers are fixed-width, so the sizes are known
    /// before the sequencer assigns them).
    pub fn build(mut self) -> Result<Transaction> {
        // Normalise every data record onto this transaction's identity.
        for r in &mut self.records {
            r.header.transaction_id = self.id;
            r.header.sequence_number = 0;
            r.header = r.header.with_recomputed_check();
        }

        let begin_payload_len = TX_BEGIN_PAYLOAD_LEN as u64;
        let per_record_overhead = (crate::record::HEADER_LEN + crate::record::FOOTER_LEN) as u64;

        let mut byte_length =
            per_record_overhead
                .checked_add(begin_payload_len)
                .ok_or(OrfsError::Overflow {
                    what: "transaction byte length",
                })?;
        for r in &self.records {
            let total = r.total_len().map_err(OrfsError::from)?;
            byte_length = byte_length.checked_add(total).ok_or(OrfsError::Overflow {
                what: "transaction byte length",
            })?;
        }

        let record_count_u64 =
            1u64.checked_add(self.records.len() as u64)
                .ok_or(OrfsError::Overflow {
                    what: "transaction record count",
                })?;
        let record_count = u32::try_from(record_count_u64).map_err(|_| OrfsError::Overflow {
            what: "transaction record count",
        })?;

        let begin = TxBeginPayload {
            transaction_id: self.id,
            expected_byte_length: byte_length,
            expected_record_count: record_count,
        };

        Ok(Transaction {
            id: self.id,
            state: TxState::Prepared,
            begin,
            records: self.records,
        })
    }
}

// ---------------------------------------------------------------------------
// Bracket verification
// ---------------------------------------------------------------------------

/// Cross-check a `TX_COMMIT` payload against the actual bracketed records.
///
/// `bracket` is the exact encoded bytes of `TX_BEGIN .. last data record`. This
/// is used by `orfs verify --deep` and by recovery tests to confirm a committed
/// root describes exactly one complete transaction.
pub fn verify_bracket(
    commit: &TxCommitPayload,
    bracket: &[u8],
    begin: &TxBeginPayload,
) -> Result<()> {
    if commit.bracketed_byte_length != bracket.len() as u64 {
        return Err(OrfsError::Corrupt(format!(
            "TX_COMMIT bracket length {} disagrees with actual {}",
            commit.bracketed_byte_length,
            bracket.len()
        )));
    }
    if commit.record_count != begin.expected_record_count as u64 {
        return Err(OrfsError::Corrupt(
            "TX_COMMIT record count disagrees with TX_BEGIN".into(),
        ));
    }
    if commit.transaction_id != begin.transaction_id {
        return Err(OrfsError::Corrupt(
            "TX_COMMIT transaction id disagrees with TX_BEGIN".into(),
        ));
    }
    if commit.bracket_checksum != bracket_checksum(bracket) {
        return Err(OrfsError::Corrupt(
            "TX_COMMIT bracket checksum mismatch".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_records() -> Transaction {
        let mut b = TransactionBuilder::new(7).unwrap();
        b.add(RecordType::InodeCreate, 7, 0, vec![1, 2, 3, 4])
            .unwrap();
        b.add(RecordType::DentryAdd, 7, 0, vec![9]).unwrap();
        b.build().unwrap()
    }

    #[test]
    fn begin_payload_round_trips() {
        let p = TxBeginPayload {
            transaction_id: 42,
            expected_byte_length: 1234,
            expected_record_count: 5,
        };
        let bytes = p.encode();
        assert_eq!(bytes.len(), TX_BEGIN_PAYLOAD_LEN);
        assert_eq!(TxBeginPayload::decode(&bytes).unwrap(), p);
        let mut bad = bytes;
        bad[5] ^= 0xFF;
        assert!(TxBeginPayload::decode(&bad).is_err());
    }

    #[test]
    fn commit_payload_round_trips() {
        let p = TxCommitPayload {
            transaction_id: 42,
            record_count: 5,
            bracketed_byte_length: 999,
            commit_sequence_number: 17,
            bracket_checksum: bracket_checksum(b"hello bracket"),
        };
        let bytes = p.encode();
        assert_eq!(bytes.len(), TX_COMMIT_PAYLOAD_LEN);
        assert_eq!(TxCommitPayload::decode(&bytes).unwrap(), p);
        let mut bad = bytes;
        bad[40] ^= 0xFF;
        assert!(TxCommitPayload::decode(&bad).is_err());
    }

    #[test]
    fn abort_payload_round_trips() {
        for reason in [
            AbortReason::UserRequested,
            AbortReason::ValidationFailed,
            AbortReason::InternalError,
            AbortReason::DurabilityFailure,
        ] {
            let p = TxAbortPayload {
                transaction_id: 3,
                reason,
                message: "because".into(),
            };
            let bytes = p.encode().unwrap();
            assert_eq!(TxAbortPayload::decode(&bytes).unwrap(), p);
        }
        // Wrong length is rejected.
        let bytes = TxAbortPayload {
            transaction_id: 3,
            reason: AbortReason::InternalError,
            message: "x".into(),
        }
        .encode()
        .unwrap();
        assert!(TxAbortPayload::decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn builder_rejects_structural_types_and_zero_id() {
        assert!(TransactionBuilder::new(0).is_err());
        let mut b = TransactionBuilder::new(1).unwrap();
        assert!(b.add(RecordType::TxCommit, 0, 0, Vec::new()).is_err());
        assert!(b.add(RecordType::VolumeGenesis, 0, 0, Vec::new()).is_err());
        assert!(b.add(RecordType::InodeCreate, 1, 0, vec![0]).is_ok());
    }

    #[test]
    fn builder_computes_bracket_metadata() {
        let tx = sample_records();
        assert_eq!(tx.id(), 7);
        assert_eq!(tx.state(), TxState::Prepared);
        assert_eq!(tx.bracket_record_count(), 3); // begin + 2 data
        let expected = (60 + 28 + 16) // begin
            + (60 + 4 + 16)          // inode create payload 4
            + (60 + 1 + 16); // dentry add payload 1
        assert_eq!(tx.bracket_byte_length(), expected);
        // Transaction id is stamped onto every data record.
        assert!(tx.records().iter().all(|r| r.header.transaction_id == 7));
    }

    #[test]
    fn state_machine_rejects_backward_and_illegal_moves() {
        let mut tx = sample_records();
        assert!(tx.transition(TxState::Reserved).is_ok());
        assert!(tx.transition(TxState::Submitted).is_ok());
        assert!(tx.transition(TxState::DataCompleted).is_ok());
        assert!(tx.transition(TxState::CommitCompleted).is_ok());
        assert!(tx.transition(TxState::Published).is_ok());
        assert!(tx.transition(TxState::Durable).is_ok());
        assert!(tx.transition(TxState::Published).is_err());
        assert!(tx.transition(TxState::Failed).is_err());
        assert!(tx.state().is_terminal());

        let mut tx2 = sample_records();
        assert!(tx2.transition(TxState::Durable).is_err());
        assert!(tx2.fail().is_ok());
        assert!(!tx2.state().can_transition_to(TxState::Reserved));
    }

    #[test]
    fn verify_bracket_accepts_and_rejects() {
        let tx = sample_records();
        let mut bracket = Vec::new();
        let begin_rec = Record::new(
            RecordType::TxBegin,
            0,
            tx.id(),
            0,
            0,
            0,
            tx.begin().encode().to_vec(),
        )
        .unwrap();
        bracket.extend_from_slice(&begin_rec.encode().unwrap());
        for r in tx.records() {
            bracket.extend_from_slice(&r.encode().unwrap());
        }
        let commit = TxCommitPayload {
            transaction_id: tx.id(),
            record_count: tx.bracket_record_count() as u64,
            bracketed_byte_length: bracket.len() as u64,
            commit_sequence_number: 9,
            bracket_checksum: bracket_checksum(&bracket),
        };
        assert!(verify_bracket(&commit, &bracket, &tx.begin()).is_ok());
        let mut bad = bracket.clone();
        bad[0] ^= 0xFF;
        assert!(verify_bracket(&commit, &bad, &tx.begin()).is_err());
    }
}
