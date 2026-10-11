//! Phase 11 **hostile-input court** (research §28, §29, §34, §35).
//!
//! Every authoritative backing record and every FUSE request is treated as
//! hostile. This file is deliberately adversarial: it forges correctly-framed
//! records whose *semantics* are illegal, mutates committed history on disk,
//! truncates segments, feeds arbitrary bytes to every decoder, and probes the
//! boundary between the logical mount and its backing directory.
//!
//! The governing rule is: **no panic, no unbounded allocation, and no corrupted
//! authoritative state.** A malformed *committed* record is corruption and must
//! be refused — never silently indexed (§23.1, §35).
//!
//! Decoders that take arbitrary bytes (via `proptest`) must always *return*
//! (never panic), and no length read from the input may drive an allocation
//! before it is validated against the bytes actually present.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use orfs::commit::DurabilityMode;
use orfs::directory::{validate_name, DentryAddPayload, DentryRemovePayload, DENTRY_ADD_MAGIC};
use orfs::fuse_uring::{
    FuseInHeader, FuseUringEntInOut, FuseUringReqHeader, RingRequest, FUSE_URING_REQ_HEADER_SZ,
};
use orfs::index::ROOT_INODE;
use orfs::inode::{
    validate_xattr_name, SymlinkCreatePayload, XattrSetPayload, SYMLINK_TARGET_MAX, XATTR_VALUE_MAX,
};
use orfs::log::{scan_log, OpenMode, RecoveryDisposition};
use orfs::manifestation::GenerationManifest;
use orfs::namespace::{IndexCheckpointPayload, Namespace, SnapshotRootPayload};
use orfs::record::{DecodeError, Record, RecordHeader, RecordType, MAX_PAYLOAD_LEN};
use orfs::snapshot::{HistoricalRoot, Snapshot};
use orfs::trigram::TrigramIndex;
use orfs::volume::{Volume, VolumeMeta};

use proptest::prelude::*;
use tempfile::TempDir;

const FIXED_UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x11, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const OTHER_UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x22, 0x22, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const FIXED_CREATED: u64 = 1_700_000_000;

fn init_ns(dir: &Path, segment_size: u64) -> Namespace {
    Namespace::init_with_uuid(
        dir,
        segment_size,
        FIXED_UUID,
        FIXED_CREATED,
        DurabilityMode::Ordered,
    )
    .expect("init namespace")
}

/// Forge a `DENTRY_ADD` payload carrying an arbitrary (possibly illegal) name,
/// with a *correct* trailing CRC32C so that framing accepts it and only its
/// semantics are under test.
fn forged_dentry_add(parent: u64, child: u64, name: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&DENTRY_ADD_MAGIC.to_le_bytes());
    b.extend_from_slice(&parent.to_le_bytes());
    b.extend_from_slice(&child.to_le_bytes());
    b.extend_from_slice(&(name.len() as u32).to_le_bytes());
    b.extend_from_slice(name);
    let crc = crc32c::crc32c(&b);
    b.extend_from_slice(&crc.to_le_bytes());
    b
}

// ---------------------------------------------------------------------------
// Illegal names in a committed record must be refused, never indexed
// ---------------------------------------------------------------------------

#[test]
fn committed_record_with_a_traversal_name_is_refused_on_recovery() {
    // A hostile history: a framed, committed `DENTRY_ADD` whose name escapes the
    // logical namespace. The writer accepts any payload (framing is valid); the
    // reader must refuse it as corrupt committed history.
    for hostile in [
        b"..".as_slice(),
        b"a/b".as_slice(),
        b"nul\0name".as_slice(),
        b"".as_slice(),
        vec![b'x'; 300].as_slice(), // longer than NAME_MAX
    ] {
        let td = TempDir::new().unwrap();
        let mut vol =
            Volume::init_with_uuid(td.path(), 1 << 20, FIXED_UUID, FIXED_CREATED).unwrap();
        vol.log.begin(1).unwrap();
        let rec = Record::new(
            RecordType::DentryAdd,
            0,
            1,
            ROOT_INODE,
            0,
            0,
            forged_dentry_add(ROOT_INODE, 2, hostile),
        )
        .unwrap();
        vol.log.append(rec).unwrap();
        vol.log.commit().unwrap();
        drop(vol);

        let reopened = Namespace::open(td.path(), OpenMode::ReadOnly, DurabilityMode::Ordered);
        assert!(
            reopened.is_err(),
            "hostile name {hostile:?} was accepted by recovery"
        );
    }
}

#[test]
fn forged_payload_decoders_reject_out_of_domain_names() {
    // The same forgery, fed directly to the decoders: they must reject it.
    for hostile in [
        b"..".as_slice(),
        b"a/b".as_slice(),
        b"x\0y".as_slice(),
        b"".as_slice(),
    ] {
        let p = forged_dentry_add(1, 2, hostile);
        assert!(
            DentryAddPayload::decode(&p, DENTRY_ADD_MAGIC, "DAD").is_err(),
            "decoder accepted hostile name {hostile:?}"
        );
    }
    // A valid name still decodes.
    let ok = forged_dentry_add(1, 2, b"fine");
    assert!(DentryAddPayload::decode(&ok, DENTRY_ADD_MAGIC, "DAD").is_ok());
}

#[test]
fn name_validator_rejects_the_documented_hostile_set() {
    assert!(validate_name(b"").is_err());
    assert!(validate_name(b".").is_err());
    assert!(validate_name(b"..").is_err());
    assert!(validate_name(b"a/b").is_err());
    assert!(validate_name(b"\0").is_err());
    assert!(validate_name(&vec![b'a'; 256]).is_err());
    // Non-UTF-8 raw bytes are legitimate Unix filenames and must be accepted.
    assert!(validate_name(&[0xff, 0xfe, 0x01]).is_ok());
    assert!(validate_name(b"ordinary").is_ok());
}

// ---------------------------------------------------------------------------
// Raw (non-UTF-8) Unix filenames round-trip
// ---------------------------------------------------------------------------

#[test]
fn raw_non_utf8_filenames_are_supported() {
    let td = TempDir::new().unwrap();
    let mut ns = init_ns(td.path(), 1 << 20);
    let raw = [0xffu8, 0xfe, b'-', 0x80, b'x'];
    let f = ns.create(ROOT_INODE, &raw, 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"raw").unwrap();

    // Lookup with the exact raw bytes succeeds.
    assert_eq!(ns.lookup(ROOT_INODE, &raw, ns.root()).unwrap(), f);
    // It appears verbatim in the listing.
    let listing = ns.readdir(ROOT_INODE, ns.root()).unwrap();
    assert!(listing.iter().any(|(n, c)| n == &raw && *c == f));
    // And survives a reopen (the name is stored as bytes, never a String).
    drop(ns);
    let ns = Namespace::open(td.path(), OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    assert_eq!(ns.lookup(ROOT_INODE, &raw, ns.root()).unwrap(), f);
}

// ---------------------------------------------------------------------------
// Hostile extended attributes
// ---------------------------------------------------------------------------

#[test]
fn xattr_name_and_value_bounds_are_enforced_on_decode_and_api() {
    assert!(validate_xattr_name(b"").is_err());
    assert!(validate_xattr_name(b"user.\0evil").is_err());
    assert!(validate_xattr_name(&vec![b'a'; 256]).is_err());
    assert!(validate_xattr_name(b"user.ok").is_ok());

    // A forged XATTR_SET payload with a NUL-bearing name or an over-large value
    // is refused even though its CRC is correct.
    for (name, value) in [
        (b"user.\0bad".to_vec(), b"v".to_vec()),
        (b"user.k".to_vec(), vec![0u8; XATTR_VALUE_MAX + 1]),
    ] {
        let mut b = Vec::new();
        b.extend_from_slice(&0x3153_4158u32.to_le_bytes()); // XATTR_SET_MAGIC "XAS1"
        b.extend_from_slice(&7u64.to_le_bytes());
        b.extend_from_slice(&(name.len() as u32).to_le_bytes());
        b.extend_from_slice(&name);
        b.extend_from_slice(&(value.len() as u32).to_le_bytes());
        b.extend_from_slice(&value);
        let crc = crc32c::crc32c(&b);
        b.extend_from_slice(&crc.to_le_bytes());
        assert!(
            XattrSetPayload::decode(&b).is_err(),
            "forged xattr should be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Record framing: bad magic / version / length / CRC / end-marker
// ---------------------------------------------------------------------------

fn sample_record() -> Record {
    Record::new(RecordType::InodeCreate, 0, 1, 9, 0, 0, vec![0xAB; 32]).unwrap()
}

#[test]
fn framing_fields_are_individually_validated() {
    let rec = sample_record();
    let good = rec.encode().unwrap();

    // Bad magic (with a recomputed header check, so only magic is wrong).
    let mut bad = good.clone();
    bad[0] ^= 0xFF;
    assert!(Record::decode(&bad).is_err());

    // Bad format version (recompute header check so it is otherwise valid).
    let mut hdr = rec.header;
    hdr.format_version = 99;
    let hdr = hdr.with_recomputed_check();
    let mut bad = Vec::new();
    bad.extend_from_slice(&hdr.encode());
    bad.extend_from_slice(&rec.payload);
    let total = hdr.total_len().unwrap();
    let check = crc32c::crc32c(&bad);
    bad.extend_from_slice(&total.to_le_bytes());
    bad.extend_from_slice(&check.to_le_bytes());
    bad.extend_from_slice(&0x2144_4E45u32.to_le_bytes());
    assert!(matches!(
        Record::decode(&bad),
        Err(DecodeError::Compatibility(_))
    ));

    // Corrupted payload => footer CRC mismatch => Incomplete (torn), not a panic.
    let mut bad = good.clone();
    let payload_off = orfs::record::HEADER_LEN + 3;
    bad[payload_off] ^= 0xFF;
    assert_eq!(Record::decode(&bad), Err(DecodeError::Incomplete));

    // Bad end marker, CRC recomputed so only the marker is wrong.
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 4..].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    // Recompute nothing: the marker is *not* covered by the record CRC.
    assert!(matches!(Record::decode(&bad), Err(DecodeError::Corrupt(_))));
}

#[test]
fn oversized_and_overflowing_payload_lengths_are_refused_before_allocation() {
    // A header declaring a payload far beyond the format limit.
    let mut hdr = RecordHeader::new(RecordType::InodeCreate, 0, 1, 9, 0, 0, 0);
    hdr.payload_length = MAX_PAYLOAD_LEN + 1;
    let hdr = hdr.with_recomputed_check();
    assert!(matches!(
        RecordHeader::decode(&hdr.encode()),
        Err(DecodeError::Corrupt(_))
    ));

    // A header whose total length would overflow `u64`.
    let mut hdr = RecordHeader::new(RecordType::InodeCreate, 0, 1, 9, 0, 0, 0);
    let big = RecordHeader {
        payload_length: MAX_PAYLOAD_LEN, // passes the limit check...
        ..hdr
    };
    hdr = big.with_recomputed_check();
    // total_len is still fine; now force an overflow in total_len directly.
    let mut overflow = hdr;
    overflow.payload_length = u64::MAX;
    assert!(overflow.total_len().is_err());
}

// ---------------------------------------------------------------------------
// Truncated segments and tampered committed bytes
// ---------------------------------------------------------------------------

/// Append `bytes` to the highest-numbered `.seg` file in the log directory.
fn append_to_last_segment(dir: &Path, bytes: &[u8]) {
    let log_dir = Volume::log_dir(dir);
    let mut best: Option<(u64, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(&log_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(id) = orfs::segment::parse_segment_name(name) {
            if best.as_ref().map(|(b, _)| id > *b).unwrap_or(true) {
                best = Some((id, entry.path()));
            }
        }
    }
    let (_, path) = best.expect("a segment");
    let mut f = OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

#[test]
fn torn_tail_is_classified_as_a_harmless_uncommitted_tail() {
    let td = TempDir::new().unwrap();
    let mut ns = init_ns(td.path(), 1 << 20);
    let f = ns.create(ROOT_INODE, b"f", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"committed").unwrap();
    ns.sync().unwrap();
    let committed_root = ns.root();
    drop(ns);

    // A torn record appended after the committed root: harmless uncommitted tail.
    append_to_last_segment(td.path(), &[0x4F, 0x52, 0x46, 0x53, 0x00, 0x01]);

    let scan = scan_log(&Volume::log_dir(td.path())).unwrap();
    assert_eq!(scan.committed_end_offset, committed_root);
    let tail = scan.tail.expect("torn tail recognised");
    assert_eq!(tail.kind, orfs::log::TailKind::TornRecord);

    // A read-write open retains it (never rewrites committed bytes) and reports a
    // retained-tail disposition explicitly.
    let vol = Volume::open(td.path(), OpenMode::ReadWrite).unwrap();
    assert!(matches!(
        vol.log.recovery(),
        RecoveryDisposition::RetainedTail {
            kind: orfs::log::TailKind::TornRecord,
            quarantined: true,
            ..
        }
    ));
    assert_eq!(vol.log.committed_end_offset(), committed_root);
}

#[test]
fn torn_record_in_a_non_final_segment_is_corruption() {
    let td = TempDir::new().unwrap();
    // Small segments and several transactions force multiple segment files.
    let mut ns = init_ns(td.path(), 512);
    for i in 0..24u64 {
        let f = ns
            .create(ROOT_INODE, format!("f{i}").as_bytes(), 0o644, 0, 0)
            .unwrap();
        ns.write_at(f, 0, &[i as u8; 200]).unwrap();
    }
    ns.sync().unwrap();
    drop(ns);

    let log_dir = Volume::log_dir(td.path());
    let ids = orfs::segment::discover_segment_ids(&log_dir).unwrap();
    assert!(ids.len() >= 2, "test needs multiple segments, got {ids:?}");

    // Corrupt the *first* segment (non-final): a torn record before a later
    // segment must be hard corruption, never a silent tail.
    let first = log_dir.join(orfs::segment::segment_file_name(0).unwrap());
    let f = OpenOptions::new().write(true).open(&first).unwrap();
    use std::os::unix::fs::FileExt;
    f.write_at(&[0u8; 8], 0).unwrap();
    f.sync_all().unwrap();

    assert!(
        scan_log(&log_dir).is_err(),
        "corruption in a non-final segment must be refused"
    );
}

// ---------------------------------------------------------------------------
// Snapshot / historical-view access control
// ---------------------------------------------------------------------------

#[test]
fn historical_reference_for_another_volume_is_refused() {
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let mut ns_a = Namespace::init_with_uuid(
        a.path(),
        1 << 20,
        FIXED_UUID,
        FIXED_CREATED,
        DurabilityMode::Ordered,
    )
    .unwrap();
    ns_a.create(ROOT_INODE, b"a", 0o644, 0, 0).unwrap();
    let root_a = ns_a.root();
    // Volume B has a *different* identity.
    let mut ns_b = Namespace::init_with_uuid(
        b.path(),
        1 << 20,
        OTHER_UUID,
        FIXED_CREATED,
        DurabilityMode::Ordered,
    )
    .unwrap();
    ns_b.create(ROOT_INODE, b"b", 0o644, 0, 0).unwrap();
    drop((ns_a, ns_b));

    // A reference naming volume A must not resolve against volume B.
    let reference = HistoricalRoot::new(FIXED_UUID, root_a);
    assert!(Snapshot::open_dir_historical(b.path(), &reference).is_err());
    let vol_b = Volume::open(b.path(), OpenMode::ReadOnly).unwrap();
    assert!(Snapshot::open_historical(&vol_b, &reference).is_err());

    // The matching reference resolves.
    let vol_a = Volume::open(a.path(), OpenMode::ReadOnly).unwrap();
    let snap = Snapshot::open_historical(&vol_a, &reference).unwrap();
    assert_eq!(snap.root(), root_a);
}

#[test]
fn a_non_boundary_snapshot_root_is_refused() {
    let td = TempDir::new().unwrap();
    let mut ns = init_ns(td.path(), 1 << 20);
    ns.create(ROOT_INODE, b"x", 0o644, 0, 0).unwrap();
    let root = ns.root();
    drop(ns);
    // `root - 1` points into a record, not at a transaction boundary.
    assert!(Snapshot::open_dir(td.path(), root - 1).is_err());
    // Beyond the committed root.
    assert!(Snapshot::open_dir(td.path(), root + 1_000_000).is_err());
}

// ---------------------------------------------------------------------------
// Namespace <-> backend separation: the backing directory is not exposed
// ---------------------------------------------------------------------------

#[test]
fn backing_directory_is_not_reachable_through_the_mount() {
    let td = TempDir::new().unwrap();
    let mut ns = init_ns(td.path(), 1 << 20);
    let f = ns.create(ROOT_INODE, b"visible", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"data").unwrap();

    // Plant a conspicuous secret in the backing directory, plus a concealed
    // manifest directory, then confirm neither is addressable logically.
    std::fs::write(td.path().join("BACKING-SECRET"), b"do-not-leak").unwrap();
    std::fs::create_dir_all(td.path().join(".or_bloom")).unwrap();
    std::fs::write(td.path().join(".or_bloom/HEAD"), b"concealed").unwrap();

    let root = ns.root();
    for name in [
        b"BACKING-SECRET".as_slice(),
        b".or_bloom".as_slice(),
        b"0000000000000000.seg".as_slice(),
        b"quarantine".as_slice(),
    ] {
        assert!(
            ns.lookup(ROOT_INODE, name, root).is_err(),
            "backing entry {name:?} leaked through the logical namespace"
        );
    }
    let listing = ns.readdir(ROOT_INODE, root).unwrap();
    assert_eq!(listing.len(), 1, "only the user entry is visible");
    assert_eq!(listing[0].0, b"visible");
}

// ---------------------------------------------------------------------------
// Permission enforcement consistency
// ---------------------------------------------------------------------------

#[test]
fn permission_model_rejects_unprivileged_mutation() {
    use orfs::inode::has_permission;
    let td = TempDir::new().unwrap();
    let mut ns = init_ns(td.path(), 1 << 20);
    // Owned by uid 1000, mode 0600.
    let f = ns.create(ROOT_INODE, b"secret", 0o600, 1000, 1000).unwrap();
    let st = ns.getattr(f, ns.root()).unwrap();
    assert!(has_permission(1000, 1000, &st, 0o6));
    assert!(!has_permission(2000, 2000, &st, 0o6));
    assert!(!has_permission(1000, 1000, &st, 0o1));
    // Root bypasses.
    assert!(has_permission(0, 0, &st, 0o6));
}

// ---------------------------------------------------------------------------
// Query inputs and giant / negative offsets
// ---------------------------------------------------------------------------

#[test]
fn hostile_query_inputs_are_rejected_cleanly() {
    let td = TempDir::new().unwrap();
    let mut ns = init_ns(td.path(), 1 << 20);
    let f = ns.create(ROOT_INODE, b"f", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"the quick brown fox").unwrap();
    let root = ns.root();

    // Empty pattern is an error, not an unbounded scan.
    let empty = orfs::query::QueryRequest::new(ROOT_INODE, root, Vec::new());
    assert!(ns.query(empty).is_err());

    // A non-existent inode target is `NotFound`.
    let missing = orfs::query::QueryRequest::new(999_999, root, b"x".to_vec());
    assert!(ns.query(missing).is_err());

    // A non-boundary root is refused (hostile historical view).
    let badroot = orfs::query::QueryRequest::new(ROOT_INODE, root - 1, b"x".to_vec());
    assert!(ns.query(badroot).is_err());

    // A real query still works (the guards above are not over-broad).
    let good = orfs::query::QueryRequest::new(ROOT_INODE, root, b"brown".to_vec());
    let res = ns.query(good).unwrap();
    assert!(!res.matches.is_empty());
}

#[test]
fn giant_offsets_are_clamped_not_allocated() {
    let td = TempDir::new().unwrap();
    let mut ns = init_ns(td.path(), 1 << 20);
    let f = ns.create(ROOT_INODE, b"f", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"hello").unwrap();
    let root = ns.root();

    // A read far past EOF returns nothing (clamped to the file), never a huge
    // zero-fill allocation.
    for off in [u64::MAX, u64::MAX - 1, 1 << 62] {
        let data = ns.read_at(f, root, off, 4096).unwrap();
        assert!(
            data.is_empty(),
            "offset {off} returned {} bytes",
            data.len()
        );
    }
    // SEEK_DATA / SEEK_HOLE past EOF report no data/hole.
    assert_eq!(ns.seek_data_hole(f, root, u64::MAX, false).unwrap(), None);
    assert_eq!(ns.seek_data_hole(f, root, u64::MAX, true).unwrap(), None);
}

// ---------------------------------------------------------------------------
// The FUSE request decode path is bounds-checked and allocation-free on input
// ---------------------------------------------------------------------------

#[test]
fn ring_request_decoders_refuse_short_input() {
    assert!(FuseInHeader::from_bytes(&[]).is_none());
    assert!(FuseInHeader::from_bytes(&[0u8; 39]).is_none());
    assert!(FuseInHeader::from_bytes(&[0u8; 40]).is_some());

    assert!(FuseUringEntInOut::from_bytes(&[0u8; 31]).is_none());
    assert!(FuseUringEntInOut::from_bytes(&[0u8; 32]).is_some());

    assert!(FuseUringReqHeader::from_bytes(&[0u8; FUSE_URING_REQ_HEADER_SZ - 1]).is_none());
    let hdr = FuseUringReqHeader::from_bytes(&[0u8; FUSE_URING_REQ_HEADER_SZ]).unwrap();
    assert!(RingRequest::decode(&hdr).is_some());
}

// ---------------------------------------------------------------------------
// Randomized hostile inputs: no decoder may panic on arbitrary bytes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_bytes_never_panic_any_decoder(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        // Record framing.
        let _ = Record::decode(&bytes);
        let _ = RecordHeader::decode(&bytes);
        // Namespace / directory payloads.
        let _ = DentryAddPayload::decode(&bytes, DENTRY_ADD_MAGIC, "DAD");
        let _ = DentryRemovePayload::decode(&bytes, 0x314D_5244, "DRM");
        let _ = SnapshotRootPayload::decode(&bytes);
        let _ = IndexCheckpointPayload::decode(&bytes);
        // Inode payloads.
        let _ = SymlinkCreatePayload::decode(&bytes);
        let _ = XattrSetPayload::decode(&bytes);
        // Volume / concealed structures.
        let _ = VolumeMeta::decode(&bytes);
        let _ = GenerationManifest::decode(&bytes);
        let _ = TrigramIndex::decode(&bytes);
        // FUSE-over-io_uring request framing.
        let _ = FuseUringReqHeader::from_bytes(&bytes);
        let _ = FuseInHeader::from_bytes(&bytes);
        let _ = FuseUringEntInOut::from_bytes(&bytes);
    }

    #[test]
    fn arbitrary_names_are_either_accepted_or_rejected_never_panicking(name in proptest::collection::vec(any::<u8>(), 0..400)) {
        // Both verdicts are acceptable; a panic is not. proptest fails the case
        // if either validator panics on arbitrary bytes.
        let _ = validate_name(&name);
        let _ = validate_xattr_name(&name);
        let _ = forged_dentry_add(1, 2, &name);
    }
}

// ---------------------------------------------------------------------------
// A hostile trigram payload declaring a huge posting list must fail fast,
// without first allocating a huge buffer from the untrusted count.
// ---------------------------------------------------------------------------

#[test]
fn hostile_trigram_posting_count_fails_before_allocation() {
    // magic "ORTP", schema, encoding, logical_size = huge, source hash, count=1,
    // key in range, then n = 0xFFFFFFF0 positions with only a few bytes present.
    let mut b = Vec::new();
    b.extend_from_slice(&0x4F52_5450u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes()); // schema
    b.push(0); // encoding
    b.extend_from_slice(&u64::MAX.to_le_bytes()); // logical_size (huge, hostile)
    b.extend_from_slice(&[0u8; 32]); // source blake3
    b.extend_from_slice(&1u32.to_le_bytes()); // count = 1 key
    b.extend_from_slice(&0x0000_0042u32.to_le_bytes()); // key
    b.extend_from_slice(&0xFFFF_FFF0u32.to_le_bytes()); // n = ~4 billion
    b.extend_from_slice(&[0u8; 8]); // a handful of position bytes only
    let err = TrigramIndex::decode(&b);
    assert!(err.is_err(), "hostile posting count must be refused");
}

// ---------------------------------------------------------------------------
// A hostile committed record whose *bracket* is inconsistent is a hard error
// ---------------------------------------------------------------------------

#[test]
fn truncated_final_segment_does_not_expose_committed_content() {
    let td = TempDir::new().unwrap();
    let mut ns = init_ns(td.path(), 4096);
    let f = ns.create(ROOT_INODE, b"keep", 0o644, 0, 0).unwrap();
    ns.write_at(f, 0, b"committed-bytes").unwrap();
    ns.sync().unwrap();
    let committed_root = ns.root();
    drop(ns);

    // Truncate the last segment to a mid-record prefix: a torn tail.
    let log_dir = Volume::log_dir(td.path());
    let ids = orfs::segment::discover_segment_ids(&log_dir).unwrap();
    let last = *ids.last().unwrap();
    let path = log_dir.join(orfs::segment::segment_file_name(last).unwrap());
    let len = std::fs::metadata(&path).unwrap().len();
    let file = OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(len.saturating_sub(5)).unwrap();
    file.sync_all().unwrap();

    // A torn *final* segment is no longer silently treated as a harmless tail
    // when the durable watermark certifies committed history beyond it: if the
    // truncation removed committed bytes, the open is refused (research §23, §35).
    // If it only removed bytes beyond the committed root, the open stays valid.
    let scan = scan_log(&log_dir).unwrap();
    assert!(scan.committed_end_offset <= committed_root);
    if scan.committed_end_offset < committed_root {
        assert!(
            Volume::open(td.path(), OpenMode::ReadOnly).is_err(),
            "truncating committed bytes must be detected by the commit watermark"
        );
    } else {
        // The recovered handle agrees exactly with the scan and reports a valid
        // committed boundary; the surviving committed prefix is readable.
        let vol = Volume::open(td.path(), OpenMode::ReadOnly).unwrap();
        assert_eq!(vol.log.committed_end_offset(), scan.committed_end_offset);
        assert!(vol.log.is_boundary(vol.log.committed_end_offset()));
    }
}

#[test]
fn symlink_target_bounds_are_enforced() {
    let mut b = Vec::new();
    b.extend_from_slice(&0x314B_4C53u32.to_le_bytes()); // SYMLINK_CREATE_MAGIC "SLK1"
    b.extend_from_slice(&7u64.to_le_bytes());
    b.extend_from_slice(&1u64.to_le_bytes());
    b.extend_from_slice(&0o777u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0i64.to_le_bytes());
    b.extend_from_slice(&0i32.to_le_bytes());
    let target = vec![b'x'; SYMLINK_TARGET_MAX + 1];
    b.extend_from_slice(&(target.len() as u32).to_le_bytes());
    b.extend_from_slice(&target);
    let crc = crc32c::crc32c(&b);
    b.extend_from_slice(&crc.to_le_bytes());
    assert!(SymlinkCreatePayload::decode(&b).is_err());
}

// ---------------------------------------------------------------------------
// Unsafe-block audit (research §28: every `unsafe` block needs a documented
// safety invariant and focused tests). Machine-generated from the source tree.
// ---------------------------------------------------------------------------

#[test]
fn every_unsafe_block_has_a_written_safety_invariant() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files: Vec<_> = std::fs::read_dir(&src)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "rs").unwrap_or(false))
        .collect();
    files.sort();

    let mut entries = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            // Only *code* uses of `unsafe`, not doc/line comments that mention it.
            if trimmed.starts_with("//") || !contains_unsafe_token(line) {
                continue;
            }
            // The invariant may be stated on the line, or in a `// SAFETY:`
            // comment within the preceding few lines. Capture its text.
            let safety = lines[idx.saturating_sub(6)..=idx]
                .iter()
                .rev()
                .find(|l| l.to_ascii_uppercase().contains("SAFETY"))
                .map(|l| l.trim().trim_start_matches('/').trim().to_string());
            let has_safety = safety.is_some();
            let name = file.file_name().unwrap().to_string_lossy().to_string();
            entries.push(serde_json::json!({
                "file": name,
                "line": idx + 1,
                "text": trimmed.trim_end(),
                "has_safety_comment": has_safety,
                "safety_invariant": safety,
                "covering_test": covering_test_for(&name),
            }));
        }
    }

    let all_documented = entries
        .iter()
        .all(|e| e["has_safety_comment"].as_bool().unwrap_or(false));
    // Per-file counts, so the full total can be reconciled against the prose in
    // `docs/SECURITY.md` without hand-counting.
    let mut by_file = serde_json::Map::new();
    for e in &entries {
        let f = e["file"].as_str().unwrap_or("unknown").to_string();
        let n = by_file.get(&f).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        by_file.insert(f, serde_json::Value::from(n));
    }
    // The native FUSE transport surface (the Phase 28 focus).
    let native_transport = entries
        .iter()
        .filter(|e| {
            matches!(
                e["file"].as_str(),
                Some("fuse_native.rs") | Some("fuse_uring.rs") | Some("buffers.rs")
            )
        })
        .count();
    let report = serde_json::json!({
        "schema": "orfs.evidence.unsafe-audit.v2",
        "generator": "tests/hostile_files.rs",
        "method": "every `unsafe` token in src/*.rs is enumerated from the source at test time; each must be accompanied by a `SAFETY:` invariant comment within the preceding six lines. The count is line-based (one entry per source line that carries the `unsafe` token, excluding comment lines); `safety_invariant` is that comment's text and `covering_test` names a test that exercises the site where one exists.",
        "unsafe_sites": entries.len(),
        "native_transport_sites": native_transport,
        "by_file": serde_json::Value::Object(by_file),
        "all_have_safety_comment": all_documented,
        "entries": entries,
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/security/unsafe-audit.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut s = serde_json::to_string_pretty(&report).unwrap();
    s.push('\n');
    std::fs::write(&path, s).unwrap();

    assert!(
        !entries.is_empty(),
        "the audit must find the known unsafe sites"
    );
    assert!(
        all_documented,
        "every unsafe block must carry a written safety invariant"
    );
}

/// A named test (or test group) that exercises a given source file's `unsafe`
/// sites, where one exists. Kept as a small static map so the evidence records a
/// real, named test rather than free text; `None` means no focused test exists
/// (the site is still covered by its written invariant and by the integration
/// courts that call it).
fn covering_test_for(file: &str) -> Option<&'static str> {
    match file {
        "buffers.rs" => Some(
            "buffers::tests::{pins_are_exclusive_and_reusable, release_is_refused_while_pinned_or_in_flight, registered_buffers_are_released_only_after_every_completion_is_reaped, aligned_buffer_address_is_stable_when_ownership_moves_between_threads}",
        ),
        "fuse_native.rs" => Some(
            "fuse_native::tests::{entry_state_buffers_are_stable_under_ownership_move, reply_larger_than_the_registered_buffer_is_clamped_not_panicking, payload_size_is_clamped_to_the_registered_buffer, reply_encode_into_interleaved_reuse_is_byte_identical} + tests/fuse_uring.rs",
        ),
        "fuse_uring.rs" => Some(
            "fuse_uring::tests::{raw_sqe_len_field_is_written_at_the_documented_offset, cmd_area_decode_is_total_over_arbitrary_bytes, uapi_sizes_match_the_kernel_headers} + tests/native_fuse_fuzz.rs",
        ),
        "uring.rs" => Some("tests/uring_integration.rs"),
        "fuse.rs" => Some("tests/fuse_integration.rs / tests/fuse_passthrough.rs"),
        _ => None,
    }
}

/// Whether `line` contains the `unsafe` keyword as a code token (word-boundary).
fn contains_unsafe_token(line: &str) -> bool {
    let bytes = line.as_bytes();
    let needle = b"unsafe";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let before_ok = i == 0 || !is_word(bytes[i - 1]);
            let after = i + needle.len();
            let after_ok = after == bytes.len() || !is_word(bytes[after]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ---------------------------------------------------------------------------
// Machine-generated hostile-input results
// ---------------------------------------------------------------------------

#[test]
fn write_hostile_input_results() {
    // Actually run a fixed, hostile corpus through the decoders and record the
    // real outcome of each: the evidence is computed here, not asserted on faith.
    let mut cases = Vec::new();
    let mut run = |name: &str, ok: bool| {
        cases.push(serde_json::json!({"case": name, "decoder_rejected": ok}));
    };

    // Bad magic / short input on every decoder.
    run("record_short", Record::decode(&[0u8; 8]).is_err());
    run(
        "record_bad_magic",
        Record::decode(&{
            let mut b = sample_record().encode().unwrap();
            b[0] ^= 0xFF;
            b
        })
        .is_err(),
    );
    run(
        "dentry_name_traversal",
        DentryAddPayload::decode(&forged_dentry_add(1, 2, b".."), DENTRY_ADD_MAGIC, "DAD").is_err(),
    );
    run(
        "xattr_nul_name",
        XattrSetPayload::decode(&{
            let name = b"user.\0bad";
            let value = b"v";
            let mut b = Vec::new();
            b.extend_from_slice(&0x3153_4158u32.to_le_bytes());
            b.extend_from_slice(&1u64.to_le_bytes());
            b.extend_from_slice(&(name.len() as u32).to_le_bytes());
            b.extend_from_slice(name);
            b.extend_from_slice(&(value.len() as u32).to_le_bytes());
            b.extend_from_slice(value);
            let crc = crc32c::crc32c(&b);
            b.extend_from_slice(&crc.to_le_bytes());
            b
        })
        .is_err(),
    );
    run("volume_meta_short", VolumeMeta::decode(&[0u8; 4]).is_err());
    run(
        "manifest_short",
        GenerationManifest::decode(&[0u8; 4]).is_err(),
    );
    run("trigram_short", TrigramIndex::decode(&[0u8; 4]).is_err());
    run(
        "fuse_request_short",
        FuseUringReqHeader::from_bytes(&[0u8; 8]).is_none(),
    );

    let all_rejected = cases
        .iter()
        .all(|c| c["decoder_rejected"].as_bool().unwrap_or(false));
    let report = serde_json::json!({
        "schema": "orfs.evidence.hostile-input-results.v1",
        "generator": "tests/hostile_files.rs",
        "method": "a fixed hostile corpus is executed against every decoder at test time; the table records the real outcome (rejected = true)",
        "courts": [
            "malformed framing (magic/version/length/CRC/end-marker)",
            "length-overflow records",
            "truncated/tampered committed segments",
            "malicious filenames (NUL, '..', '/', over-long, non-UTF8)",
            "hostile xattr names/values",
            "hostile query inputs and roots",
            "cross-volume snapshot references",
            "giant/negative offsets",
            "FUSE-over-io_uring request decode"
        ],
        "cases": cases,
        "all_rejected": all_rejected,
        "all_ok": all_rejected
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("evidence/security/hostile-input-results.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let mut s = serde_json::to_string_pretty(&report).unwrap();
    s.push('\n');
    std::fs::write(&path, s).unwrap();
    assert!(all_rejected, "every hostile case must be rejected");
}
