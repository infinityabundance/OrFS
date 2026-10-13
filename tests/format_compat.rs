//! Phase 67 — **the frozen `or.log` format-version compatibility court**.
//!
//! Reviewer item #1 ("the #1 filesystem trust gap") is the *non-withdrawal trust
//! gap*: a frozen `or.log` must remain readable by future binaries. The on-disk
//! spec existed, but the authoritative log had no explicit `format_version` in
//! its identity, so nothing machine-checked the guarantee that
//! `L_{n+1} = L_n ⊕ Δ_n` survives years of code changes.
//!
//! This court freezes two tiny, committed mini-volumes under `tests/fixtures/`:
//!
//! * `legacy_v0` — the pre-versioning layout: a **24-byte** genesis payload
//!   (`uuid ‖ segment_size`) with no version field, which a reader must infer as
//!   log format version **0**;
//! * `current_v1` — the current layout: a **26-byte** genesis payload
//!   (`uuid ‖ segment_size ‖ format_version`), version **1**.
//!
//! The two volume identities differ *only* in that trailing two-byte field; the
//! transaction suffix is byte-identical. The court opens each frozen fixture with
//! the current library **and** the real `orfs` binary, replays and
//! `verify --deep`s it, and asserts the reconstructed logical content, committed
//! root, canonical bytes and digest are byte-identical to a freshly written
//! equivalent — so any future format change that stops reading a frozen log turns
//! this court red.
//!
//! It also asserts the version rule: every known version `<= current` is
//! accepted (`0` and `1`), and an unknown **higher** version is refused with the
//! typed [`orfs::OrfsError::UnsupportedFormatVersion`].
//!
//! # Regenerating the fixtures
//!
//! The fixtures are produced — and the "freshly written equivalent" built — by
//! the *same* deterministic builder, `build_mini_volume`, so the frozen bytes
//! and the assertion come from one code path. Regenerate them with:
//!
//! ```sh
//! sh -c '. scripts/lib.sh && docker_run cargo test -p orfs --test format_compat \
//!     -- --ignored generate_fixtures'
//! ```
//!
//! See `tests/fixtures/README.md` for the frozen bytes' provenance.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use orfs::directory::{DentryAddPayload, DENTRY_ADD_MAGIC};
use orfs::extent::DataExtentPayload;
use orfs::inode::{InodeCreatePayload, InodeType, Timespec};
use orfs::log::{Log, OpenMode};
use orfs::record::{Record, RecordType, FOOTER_LEN, HEADER_LEN};
use orfs::segment::{discover_segment_ids, segment_file_name};
use orfs::volume::{
    parse_genesis_payload, Volume, VolumeMeta, GENESIS_PAYLOAD_LEN, LEGACY_GENESIS_PAYLOAD_LEN,
    VOLUME_MAGIC,
};
use orfs::{OrfsError, FORMAT_VERSION, LOG_FORMAT_VERSION};

use tempfile::TempDir;

/// A fixed volume UUID so the fixtures are byte-reproducible.
const FIXTURE_UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x67, 0x11, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
/// A fixed creation timestamp for the fixtures.
const FIXTURE_CREATED: u64 = 1_700_000_000;
/// A small segment-size policy; the whole mini-volume fits in one segment.
const FIXTURE_SEGMENT_SIZE: u64 = 1 << 16;
/// The single file the mini-volume creates and writes.
const FIXTURE_FILE_ID: u64 = 2;
const FIXTURE_FILE_NAME: &[u8] = b"hello.txt";
const FIXTURE_DATA: &[u8] = b"hello, orfs\n";

// ---------------------------------------------------------------------------
// Deterministic builder (shared by the generator and the assertions)
// ---------------------------------------------------------------------------

/// The legacy (version 0) genesis payload: UUID + segment size, no version field.
fn legacy_genesis_payload() -> Vec<u8> {
    let mut v = Vec::with_capacity(LEGACY_GENESIS_PAYLOAD_LEN);
    v.extend_from_slice(&FIXTURE_UUID);
    v.extend_from_slice(&FIXTURE_SEGMENT_SIZE.to_le_bytes());
    assert_eq!(v.len(), LEGACY_GENESIS_PAYLOAD_LEN);
    v
}

/// The current (version 1) genesis payload, written by the library.
fn current_genesis_payload() -> Vec<u8> {
    let v = orfs::volume::genesis_payload(&FIXTURE_UUID, FIXTURE_SEGMENT_SIZE);
    assert_eq!(v.len(), GENESIS_PAYLOAD_LEN);
    v
}

/// Build a deterministic, semantically valid mini-volume (`volume.meta` +
/// `or.log/*.seg`) with the supplied genesis payload, and return its committed
/// root. Every field is fixed (no wall-clock time), so the bytes are reproducible
/// and the volume passes `verify --deep`'s namespace rebuild.
fn build_mini_volume(dir: &Path, genesis: Vec<u8>) -> u64 {
    let log_dir = dir.join("or.log");
    std::fs::create_dir_all(&log_dir).unwrap();
    let mut log = Log::create(&log_dir, FIXTURE_SEGMENT_SIZE).unwrap();
    log.append(Record::new(RecordType::VolumeGenesis, 0, 0, 0, 0, 0, genesis).unwrap())
        .unwrap();

    let ts = Timespec::new(FIXTURE_CREATED as i64, 0);

    // TX 1: create a file inode and link it under the root.
    log.begin(1).unwrap();
    let create = InodeCreatePayload {
        inode_id: FIXTURE_FILE_ID,
        generation: 1,
        kind: InodeType::File,
        mode: 0o644,
        uid: 0,
        gid: 0,
        nlink: 1,
        size: 0,
        atime: ts,
        mtime: ts,
        ctime: ts,
    }
    .encode();
    log.append(Record::new(RecordType::InodeCreate, 0, 1, FIXTURE_FILE_ID, 0, 0, create).unwrap())
        .unwrap();
    let add = DentryAddPayload {
        parent: 1,
        child: FIXTURE_FILE_ID,
        name: FIXTURE_FILE_NAME.to_vec(),
    }
    .encode(DENTRY_ADD_MAGIC)
    .unwrap();
    log.append(Record::new(RecordType::DentryAdd, 0, 1, FIXTURE_FILE_ID, 0, 0, add).unwrap())
        .unwrap();
    log.commit().unwrap();

    // TX 2: write the file's data.
    log.begin(2).unwrap();
    let data = DataExtentPayload {
        offset: 0,
        data: FIXTURE_DATA.to_vec(),
    }
    .encode();
    log.append(Record::new(RecordType::DataExtent, 0, 2, FIXTURE_FILE_ID, 0, 0, data).unwrap())
        .unwrap();
    log.commit().unwrap();

    log.sync().unwrap();
    let root = log.committed_end_offset();

    let meta = VolumeMeta {
        magic: VOLUME_MAGIC,
        format_version: FORMAT_VERSION,
        reserved: 0,
        uuid: FIXTURE_UUID,
        created_at_unix_secs: FIXTURE_CREATED,
        segment_size: FIXTURE_SEGMENT_SIZE,
        meta_check: 0,
    };
    std::fs::write(dir.join("volume.meta"), meta.encode()).unwrap();
    root
}

/// The authoritative files of a volume (`volume.meta` + every `or.log/*.seg`),
/// keyed by their path relative to the volume root. The derived sidecars
/// (`index/`, `.or_bloom/`, `commit.watermark`) are deliberately excluded: they
/// are rebuildable and are not the frozen identity.
fn raw_volume_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    out.insert(
        "volume.meta".to_string(),
        std::fs::read(dir.join("volume.meta")).unwrap(),
    );
    let log_dir = dir.join("or.log");
    for id in discover_segment_ids(&log_dir).unwrap() {
        let name = segment_file_name(id).unwrap();
        out.insert(
            format!("or.log/{name}"),
            std::fs::read(log_dir.join(&name)).unwrap(),
        );
    }
    out
}

/// The committed root of the volume at `dir` as reported by the library.
fn committed_root(dir: &Path) -> u64 {
    Volume::open(dir, OpenMode::ReadOnly)
        .unwrap()
        .log
        .committed_end_offset()
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Build a mini-volume in a temp dir and copy exactly its authoritative files
/// into `tests/fixtures/<name>/`, replacing any previous copy.
fn freeze_fixture(name: &str, genesis: Vec<u8>) -> u64 {
    let dir = fixtures_root().join(name);
    let tmp = TempDir::new().unwrap();
    let root = build_mini_volume(tmp.path(), genesis);
    let files = raw_volume_files(tmp.path());
    if dir.exists() {
        std::fs::remove_dir_all(&dir).unwrap();
    }
    for (rel, bytes) in &files {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }
    root
}

// ---------------------------------------------------------------------------
// Generator (ignored by default; run explicitly to (re)freeze the fixtures)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "writes tests/fixtures/*; run with `cargo test -p orfs --test format_compat -- --ignored generate_fixtures`"]
fn generate_fixtures() {
    let legacy_root = freeze_fixture("legacy_v0", legacy_genesis_payload());
    let current_root = freeze_fixture("current_v1", current_genesis_payload());
    println!(
        "wrote fixtures under {} (legacy root {legacy_root}, current root {current_root})",
        fixtures_root().display()
    );
}

// ---------------------------------------------------------------------------
// Byte-identity against a fresh write (the non-withdrawal guarantee)
// ---------------------------------------------------------------------------

#[test]
fn frozen_fixtures_are_byte_identical_to_a_fresh_write() {
    for (name, genesis, expected_version) in [
        ("legacy_v0", legacy_genesis_payload(), 0u16),
        ("current_v1", current_genesis_payload(), 1u16),
    ] {
        let frozen = fixtures_root().join(name);
        assert!(
            frozen.join("volume.meta").exists(),
            "fixture {name} is missing"
        );

        let tmp = TempDir::new().unwrap();
        let fresh_root = build_mini_volume(tmp.path(), genesis);

        // Raw authoritative bytes are byte-identical to a freshly written volume.
        assert_eq!(
            raw_volume_files(&frozen),
            raw_volume_files(tmp.path()),
            "fixture {name} is not byte-identical to a fresh write"
        );

        let frozen_vol = Volume::open(&frozen, OpenMode::ReadOnly).unwrap();
        let fresh_vol = Volume::open(tmp.path(), OpenMode::ReadOnly).unwrap();

        // The reported log format version is correct (0 for legacy, 1 for current).
        assert_eq!(frozen_vol.log_format_version, expected_version);
        assert_eq!(frozen_vol.log_format_version, fresh_vol.log_format_version);

        // The reconstructed logical content, committed root and digest agree.
        assert_eq!(frozen_vol.log.committed_end_offset(), fresh_root);
        assert_eq!(
            frozen_vol.log.committed_end_offset(),
            fresh_vol.log.committed_end_offset()
        );
        assert_eq!(
            frozen_vol.log.read_committed_bytes().unwrap(),
            fresh_vol.log.read_committed_bytes().unwrap()
        );
        assert_eq!(
            frozen_vol.log.committed_digest_hex().unwrap(),
            fresh_vol.log.committed_digest_hex().unwrap()
        );
        let fr = frozen_vol
            .log
            .replay_upto(frozen_vol.log.committed_end_offset())
            .unwrap();
        let nr = fresh_vol
            .log
            .replay_upto(fresh_vol.log.committed_end_offset())
            .unwrap();
        assert_eq!(fr, nr);

        // `verify --deep` (the library deep path) passes on the frozen fixture.
        assert!(frozen_vol.verify(true).unwrap().ok);
    }
}

// ---------------------------------------------------------------------------
// The layout of each frozen fixture
// ---------------------------------------------------------------------------

#[test]
fn legacy_fixture_is_version_zero_with_a_legacy_genesis() {
    let dir = fixtures_root().join("legacy_v0");
    let vol = Volume::open(&dir, OpenMode::ReadOnly).unwrap();
    assert_eq!(vol.log_format_version, 0);

    // The genesis root is exactly one framed 24-byte-payload record.
    let root = vol.log.boundaries()[0];
    assert_eq!(
        root,
        (HEADER_LEN + LEGACY_GENESIS_PAYLOAD_LEN + FOOTER_LEN) as u64
    );
    let recs = vol.log.replay_upto(root).unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].known_type().unwrap(), RecordType::VolumeGenesis);
    assert_eq!(recs[0].payload.len(), LEGACY_GENESIS_PAYLOAD_LEN);

    let id = parse_genesis_payload(&recs[0].payload).unwrap();
    assert_eq!(id.format_version, 0);
    assert_eq!(id.uuid, FIXTURE_UUID);
    assert_eq!(id.segment_size, FIXTURE_SEGMENT_SIZE);

    let report = vol.verify(true).unwrap();
    assert!(report.ok);
    let lfv = report
        .checks
        .iter()
        .find(|c| c.name == "log_format_version")
        .expect("log_format_version check present");
    assert!(lfv.ok);
    assert!(lfv.detail.contains("version 0"), "detail: {}", lfv.detail);
}

#[test]
fn current_fixture_is_version_one_with_a_versioned_genesis() {
    let dir = fixtures_root().join("current_v1");
    let vol = Volume::open(&dir, OpenMode::ReadOnly).unwrap();
    assert_eq!(vol.log_format_version, 1);

    let root = vol.log.boundaries()[0];
    assert_eq!(root, (HEADER_LEN + GENESIS_PAYLOAD_LEN + FOOTER_LEN) as u64);
    let recs = vol.log.replay_upto(root).unwrap();
    assert_eq!(recs[0].known_type().unwrap(), RecordType::VolumeGenesis);
    assert_eq!(recs[0].payload.len(), GENESIS_PAYLOAD_LEN);

    let id = parse_genesis_payload(&recs[0].payload).unwrap();
    assert_eq!(id.format_version, 1);

    let report = vol.verify(true).unwrap();
    assert!(report.ok);
    assert!(report
        .checks
        .iter()
        .any(|c| c.name == "log_format_version" && c.detail.contains("version 1")));
}

#[test]
fn legacy_and_current_share_the_same_logical_transaction_content() {
    let legacy = Volume::open(&fixtures_root().join("legacy_v0"), OpenMode::ReadOnly).unwrap();
    let current = Volume::open(&fixtures_root().join("current_v1"), OpenMode::ReadOnly).unwrap();
    let lr = legacy
        .log
        .replay_upto(legacy.log.committed_end_offset())
        .unwrap();
    let cr = current
        .log
        .replay_upto(current.log.committed_end_offset())
        .unwrap();

    assert_eq!(lr.len(), cr.len());
    // The genesis payloads differ only by the trailing version field.
    assert_eq!(cr[0].payload.len() - lr[0].payload.len(), 2);
    assert_eq!(
        &cr[0].payload[..LEGACY_GENESIS_PAYLOAD_LEN],
        &lr[0].payload[..]
    );
    // Every non-genesis record is byte-identical.
    for (l, c) in lr.iter().skip(1).zip(cr.iter().skip(1)) {
        assert_eq!(l.encode().unwrap(), c.encode().unwrap());
    }
    // The two committed roots differ by exactly the two added genesis bytes.
    assert_eq!(
        current.log.committed_end_offset() - legacy.log.committed_end_offset(),
        2
    );
}

// ---------------------------------------------------------------------------
// The version rule: accept any known version <= current, refuse a higher one
// ---------------------------------------------------------------------------

#[test]
fn genesis_parser_accepts_every_known_version() {
    let legacy = legacy_genesis_payload();
    let current = current_genesis_payload();

    // 24-byte legacy payload → inferred version 0.
    assert_eq!(parse_genesis_payload(&legacy).unwrap().format_version, 0);
    // 26-byte current payload → version 1.
    assert_eq!(parse_genesis_payload(&current).unwrap().format_version, 1);
    // An explicit version 0 in the versioned layout is still accepted (known).
    let mut explicit_zero = current.clone();
    explicit_zero[LEGACY_GENESIS_PAYLOAD_LEN..LEGACY_GENESIS_PAYLOAD_LEN + 2]
        .copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(
        parse_genesis_payload(&explicit_zero)
            .unwrap()
            .format_version,
        0
    );

    // The shared prefix (uuid + segment size) parses identically for both layouts.
    let a = parse_genesis_payload(&legacy).unwrap();
    let b = parse_genesis_payload(&current).unwrap();
    assert_eq!(a.uuid, b.uuid);
    assert_eq!(a.segment_size, b.segment_size);

    // A payload shorter than the legacy length is malformed, not a version gap.
    assert!(matches!(
        parse_genesis_payload(&[0u8; 4]),
        Err(OrfsError::Corrupt(_))
    ));
}

#[test]
fn unknown_higher_log_format_version_is_rejected() {
    // A forged genesis that declares a version above the current one.
    let mut genesis = current_genesis_payload();
    genesis[LEGACY_GENESIS_PAYLOAD_LEN..LEGACY_GENESIS_PAYLOAD_LEN + 2]
        .copy_from_slice(&(LOG_FORMAT_VERSION + 1).to_le_bytes());

    // The parser refuses it with the typed error.
    assert!(matches!(
        parse_genesis_payload(&genesis),
        Err(OrfsError::UnsupportedFormatVersion { found, supported })
            if found == LOG_FORMAT_VERSION + 1 && supported == LOG_FORMAT_VERSION
    ));

    // A whole forged volume with that genesis is refused at open.
    let tmp = TempDir::new().unwrap();
    build_mini_volume(tmp.path(), genesis);
    let err = match Volume::open(tmp.path(), OpenMode::ReadOnly) {
        Ok(_) => panic!("expected UnsupportedFormatVersion at open, but open succeeded"),
        Err(e) => e,
    };
    match err {
        OrfsError::UnsupportedFormatVersion { found, supported } => {
            assert_eq!(found, LOG_FORMAT_VERSION + 1);
            assert_eq!(supported, LOG_FORMAT_VERSION);
        }
        other => panic!("expected UnsupportedFormatVersion at open, got {other:?}"),
    }

    // The typed error maps to a sane POSIX errno.
    assert_eq!(
        OrfsError::UnsupportedFormatVersion {
            found: LOG_FORMAT_VERSION + 1,
            supported: LOG_FORMAT_VERSION,
        }
        .errno(),
        libc::EPROTONOSUPPORT
    );
}

#[test]
fn unknown_higher_volume_meta_version_is_rejected_but_older_is_accepted() {
    let base = VolumeMeta {
        magic: VOLUME_MAGIC,
        format_version: FORMAT_VERSION,
        reserved: 0,
        uuid: FIXTURE_UUID,
        created_at_unix_secs: FIXTURE_CREATED,
        segment_size: FIXTURE_SEGMENT_SIZE,
        meta_check: 0,
    };

    // The current version is accepted.
    assert!(VolumeMeta::decode(&base.encode()).is_ok());
    // An older (known) version is accepted, never rejected.
    let mut older = base;
    older.format_version = 0;
    assert_eq!(
        VolumeMeta::decode(&older.encode()).unwrap().format_version,
        0
    );
    // A higher version is refused with the typed error.
    let mut higher = base;
    higher.format_version = FORMAT_VERSION + 1;
    assert!(matches!(
        VolumeMeta::decode(&higher.encode()),
        Err(OrfsError::UnsupportedFormatVersion { found, supported })
            if found == FORMAT_VERSION + 1 && supported == FORMAT_VERSION
    ));
}

// ---------------------------------------------------------------------------
// The real binary must open, verify --deep, and report the version
// ---------------------------------------------------------------------------

#[test]
fn cli_verifies_deep_and_reports_the_frozen_fixtures() {
    for (name, expected_version) in [("legacy_v0", 0u16), ("current_v1", 1u16)] {
        let dir = fixtures_root().join(name);
        let dir = dir.to_str().unwrap();

        let verify = Command::new(env!("CARGO_BIN_EXE_orfs"))
            .args(["--json", "verify", "--deep", dir])
            .output()
            .expect("spawn orfs verify");
        assert!(
            verify.status.success(),
            "`orfs verify --deep {name}` failed: {}",
            String::from_utf8_lossy(&verify.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
        assert_eq!(report["ok"], serde_json::json!(true));
        let lfv = report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "log_format_version")
            .expect("log_format_version check present in `verify --deep`");
        assert_eq!(lfv["ok"], serde_json::json!(true));
        assert!(
            lfv["detail"]
                .as_str()
                .unwrap()
                .contains(&format!("version {expected_version}")),
            "detail: {}",
            lfv["detail"]
        );

        let inspect = Command::new(env!("CARGO_BIN_EXE_orfs"))
            .args(["--json", "inspect", dir])
            .output()
            .expect("spawn orfs inspect");
        assert!(
            inspect.status.success(),
            "`orfs inspect {name}` failed: {}",
            String::from_utf8_lossy(&inspect.stderr)
        );
        let info: serde_json::Value = serde_json::from_slice(&inspect.stdout).unwrap();
        assert_eq!(
            info["log_format_version"],
            serde_json::json!(expected_version)
        );
    }
}

/// Guard against a fixture built with the wrong committed root. The layout tests
/// above pin each root exactly; this pins the *relationship* between the two
/// frozen logs (identical transactions, so only the version field differs).
#[test]
fn frozen_fixture_roots_differ_by_the_genesis_version_field() {
    let legacy = committed_root(&fixtures_root().join("legacy_v0"));
    let current = committed_root(&fixtures_root().join("current_v1"));
    assert_eq!(current - legacy, 2);
    assert!(legacy > (HEADER_LEN + LEGACY_GENESIS_PAYLOAD_LEN + FOOTER_LEN) as u64);
}
