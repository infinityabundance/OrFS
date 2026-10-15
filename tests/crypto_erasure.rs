//! **Phase 85/86 — the crypto-erasure court (offline / library + operator CLI).**
//!
//! OrFS is **non-withdrawal**: `unlink`/`rmdir`/`truncate`/overwrite change only
//! the visible namespace and never physically remove authoritative history
//! (`docs/RETENTION.md`). A "secure delete" promise would therefore contradict
//! the filesystem's own behaviour. The only defensible erasure story on top of
//! non-withdrawal is **cryptographic**: seal content under a key and destroy the
//! key, leaving the ciphertext bytes in place, unwithdrawn, but unreadable.
//!
//! Phase 85 sealed the store in *frames*; Phase 86 replaced that with a
//! **length-preserving, per-segment positional keystream** applied at the
//! `Segment`/`ReadAt` I/O seam, so the encrypted store *is* a real OrFS log
//! (`or.log/*.seg`) and can be served by `orfs mount --key-file` (proven by
//! `tests/crypto_erasure_mounted.rs`). This court exercises the same construction
//! **offline** through the library and the real `orfs` binary:
//!
//! * `init` an encrypted volume and write content through a real namespace over
//!   the seal;
//! * read it back — the key-correct read is byte-identical;
//! * reject a **tampered** ciphertext (the per-segment MAC fails closed);
//! * `key rotate` forces a rollover, so the store spans **>1 segment** sealed
//!   under distinct epochs;
//! * `key destroy --epoch 0` makes the store fail **closed** (a typed
//!   `KeyDestroyed`) while the **ciphertext bytes are unchanged** and the surviving
//!   segment still verifies;
//! * prove **crypto-erasure covers a relocated (tiered) copy**, whose bytes are
//!   ciphertext;
//! * prove the **default (unencrypted) path is untouched**;
//! * prove **no key material** appears anywhere in the volume's authoritative
//!   area.
//!
//! ## Running it
//!
//! * `cargo test --test crypto_erasure` runs the always-on smoke.
//! * The full sweep is opt-in behind `ORFS_CRYPTO_ERASURE=1` and writes
//!   `evidence/security/crypto-erasure.json`. Run it (release) via
//!   `scripts/container-crypto-erasure.sh`.
//!
//! See `docs/RETENTION.md` and `docs/ERASURE.md` for the contract and the design.

use std::path::{Path, PathBuf};
use std::process::Command;

use orfs::commit::DurabilityMode;
use orfs::encvol::{self, read_relocated_segment, EncryptedVolume};
use orfs::index::ROOT_INODE;
use orfs::keyring::contains_bytes;
use orfs::log::OpenMode;
use orfs::namespace::Namespace;
use orfs::volume::Volume;
use serde_json::{json, Value};
use tempfile::TempDir;

/// A fixed identity so the **unencrypted** anchor digest is reproducible.
const PLAIN_UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x85, 0x01, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const PLAIN_CREATED: u64 = 1_700_000_000;
const PLAIN_SEGMENT: u64 = 1 << 16;

/// The committed digest of a freshly-initialised unencrypted volume with the
/// fixed identity above (genesis only). Pinned by this court; the frozen-fixture
/// court (`tests/format_compat.rs`) independently pins the same on-disk format
/// against the pre-existing `tests/fixtures/*`, so a change to the unencrypted
/// write path turns that court red too.
const PLAIN_GENESIS_DIGEST: &str =
    "896be1e365543853892085625ee3db1745f4427a8f509838e99a3a14d21c7a23";

const EPOCH0_SECRET: &str = "phase86-epoch-0-secret-marker";
const EPOCH1_CONTENT: &str = "phase86-epoch-1-content-marker";

fn orfs_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_orfs"))
}

/// Run the real `orfs` binary and return (success, stdout, stderr).
fn run_orfs(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(orfs_bin())
        .args(args)
        .output()
        .expect("run orfs");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Run `orfs --json <args>` and parse stdout as JSON.
fn run_orfs_json(args: &[&str]) -> (bool, Value, String) {
    let mut full = vec!["--json"];
    full.extend_from_slice(args);
    let (ok, out, err) = run_orfs(&full);
    let v = serde_json::from_str(&out).unwrap_or(Value::Null);
    (ok, v, err)
}

/// Every regular file beneath `dir`, as (relative path, bytes).
fn all_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(base, &p, out);
            } else if let Ok(bytes) = std::fs::read(&p) {
                let rel = p.strip_prefix(base).unwrap_or(&p).display().to_string();
                out.push((rel, bytes));
            }
        }
    }
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// BLAKE3 (hex) of a byte slice.
fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// The concatenated ciphertext of every `or.log/*.seg`, ascending.
fn segment_ciphertext(vol: &EncryptedVolume) -> Vec<u8> {
    let dir = EncryptedVolume::log_dir(vol.root_dir());
    let mut all = Vec::new();
    let mut ids = vol.physical_segment_ids().unwrap();
    ids.sort_unstable();
    for id in ids {
        all.extend_from_slice(
            &std::fs::read(dir.join(orfs::segment::segment_file_name(id).unwrap())).unwrap(),
        );
    }
    all
}

/// Write `content` to a new file `name` on the encrypted volume, through a real
/// namespace over the seal.
fn write_encrypted(vol: &EncryptedVolume, name: &[u8], content: &[u8]) {
    let v = vol.open_volume(OpenMode::ReadWrite).unwrap();
    let mut ns = Namespace::open_volume(v, OpenMode::ReadWrite, DurabilityMode::Ordered).unwrap();
    let ino = ns.create(ROOT_INODE, name, 0o644, 0, 0).unwrap();
    ns.write_at(ino, 0, content).unwrap();
    ns.sync().unwrap();
}

/// Read the whole of file `name` from the encrypted volume, through the seal.
fn read_encrypted(vol: &EncryptedVolume, name: &[u8]) -> Vec<u8> {
    let v = vol.open_volume(OpenMode::ReadOnly).unwrap();
    let ns = Namespace::open_volume(v, OpenMode::ReadOnly, DurabilityMode::Ordered).unwrap();
    let ino = ns.lookup(ROOT_INODE, name, ns.root()).unwrap();
    let size = ns.getattr(ino, ns.root()).unwrap().size;
    ns.read_at(ino, ns.root(), 0, size as u32).unwrap()
}

// ---------------------------------------------------------------------------
// Smoke: the library end to end (always on)
// ---------------------------------------------------------------------------

#[test]
fn crypto_erasure_smoke() {
    // -- the default (unencrypted) path is untouched ------------------------
    let plain_dir = TempDir::new().unwrap();
    let plain =
        Volume::init_with_uuid(plain_dir.path(), PLAIN_SEGMENT, PLAIN_UUID, PLAIN_CREATED).unwrap();
    assert!(
        !encvol::is_encrypted_volume(plain_dir.path()),
        "an unencrypted volume must not be treated as encrypted"
    );
    assert!(!plain_dir.path().join("crypto.meta").exists());
    assert!(plain_dir.path().join("volume.meta").exists());
    assert_eq!(
        plain.log.committed_digest_hex().unwrap(),
        PLAIN_GENESIS_DIGEST,
        "the unencrypted committed digest changed (the default path must be byte-for-byte unchanged)"
    );

    // -- an encrypted volume on a dedicated directory ----------------------
    let td = TempDir::new().unwrap();
    let dir = td.path().join("enc");
    let key = td.path().join("orfs.keys");
    let mut vol =
        EncryptedVolume::init(&dir, &key, PLAIN_SEGMENT, PLAIN_UUID, PLAIN_CREATED).unwrap();

    // Write through a real namespace over the seal; read it back identically.
    write_encrypted(&vol, b"epoch0", EPOCH0_SECRET.as_bytes());
    assert_eq!(read_encrypted(&vol, b"epoch0"), EPOCH0_SECRET.as_bytes());

    // -- the on-disk bytes are ciphertext, not the plaintext ---------------
    let seg_path =
        EncryptedVolume::log_dir(&dir).join(orfs::segment::segment_file_name(0).unwrap());
    assert!(
        !contains_bytes(&segment_ciphertext(&vol), EPOCH0_SECRET.as_bytes()),
        "the plaintext marker appears in the authoritative segment (not sealed)"
    );

    // -- tamper rejection (per-segment MAC fails closed) -------------------
    let mut raw = std::fs::read(&seg_path).unwrap();
    // Flip one byte inside the authenticated prefix (offset 4 is well within the
    // genesis record's sealed bytes). The framing is untouched, so only the MAC
    // can reject it.
    raw[4] ^= 0x01;
    std::fs::write(&seg_path, &raw).unwrap();
    match EncryptedVolume::open(&dir, &key) {
        Err(orfs::OrfsError::CryptoAuthFailed(_)) => {}
        Ok(_) => panic!("a tampered ciphertext must not open (it did)"),
        Err(e) => panic!("a tampered ciphertext must not open: {e}"),
    }
    raw[4] ^= 0x01;
    std::fs::write(&seg_path, &raw).unwrap();
    // Restored: opens again, byte-identically.
    assert_eq!(
        EncryptedVolume::open(&dir, &key)
            .unwrap()
            .segment_count()
            .unwrap(),
        1
    );
    assert_eq!(read_encrypted(&vol, b"epoch0"), EPOCH0_SECRET.as_bytes());

    // -- rotate forces a rollover: the store now spans >1 segment ----------
    let e1 = vol.rotate(PLAIN_CREATED + 100).unwrap();
    assert_eq!(e1, 1);
    assert!(
        vol.segment_count().unwrap() >= 2,
        "a key rotation must force a segment boundary"
    );
    write_encrypted(&vol, b"epoch1", EPOCH1_CONTENT.as_bytes());
    assert_eq!(read_encrypted(&vol, b"epoch1"), EPOCH1_CONTENT.as_bytes());

    let bytes_before = segment_ciphertext(&vol);
    let digest_before = vol.ciphertext_digest().unwrap();
    let segments_before = vol.segment_count().unwrap();

    // -- destroy epoch 0 (crypto-erasure): the store fails closed ----------
    vol.destroy_epoch(0, PLAIN_CREATED + 200).unwrap();

    // The linear log contains an epoch-0 segment, so the whole store fails closed
    // with the typed error — never a fabricated plaintext.
    match EncryptedVolume::open(&dir, &key) {
        Err(orfs::OrfsError::KeyDestroyed(0)) => {}
        Ok(_) => panic!("a destroyed epoch key must fail the open closed (it opened)"),
        Err(e) => panic!("a destroyed epoch key must fail the open closed: {e}"),
    }
    // The *surviving* segment still authenticates, and the store is in its
    // intended state (verify reports which segment is inaccessible and why).
    let report = vol.verify().unwrap();
    assert!(report.ok, "the store is in its intended post-erasure state");
    assert!(report.unreadable_destroyed.contains(&0));
    assert!(report.readable >= 1, "the epoch-1 segment still verifies");
    assert!(report.unauthenticated.is_empty());

    // -- ciphertext retained: every byte is unchanged ----------------------
    let bytes_after = segment_ciphertext(&vol);
    assert_eq!(bytes_after, bytes_before, "ciphertext bytes changed");
    assert_eq!(vol.ciphertext_digest().unwrap(), digest_before);
    assert_eq!(vol.segment_count().unwrap(), segments_before);

    // -- no key material anywhere in the volume's authoritative area -------
    let master = master_key_bytes(&key);
    for (rel, bytes) in all_files(&dir) {
        assert!(
            !contains_bytes(&bytes, &master),
            "the master key appears in the authoritative area ({rel})"
        );
    }

    // -- relocation copies ciphertext, and erasure covers it ---------------
    let tier = td.path().join("cold-tier");
    let rel = vol.relocate(&tier).unwrap();
    assert_eq!(rel.digest, digest_before);
    let tier_seg = std::fs::read(tier.join(orfs::segment::segment_file_name(0).unwrap())).unwrap();
    assert_eq!(
        tier_seg,
        std::fs::read(&seg_path).unwrap(),
        "the tier copy is the byte-identical ciphertext"
    );
    assert!(
        !contains_bytes(&tier_seg, EPOCH0_SECRET.as_bytes()),
        "the tier copy is ciphertext, not plaintext"
    );
    match read_relocated_segment(vol.cipher(), &tier, 0) {
        Err(orfs::OrfsError::KeyDestroyed(0)) => {}
        other => panic!("the relocated copy must be inaccessible too, got {other:?}"),
    }
}

/// The master key bytes from a key file (the only key material that must never
/// reach the volume).
fn master_key_bytes(key_file: &Path) -> Vec<u8> {
    let v: Value = serde_json::from_slice(&std::fs::read(key_file).unwrap()).unwrap();
    let hex = v["master_key"].as_str().expect("master_key").to_string();
    let mut out = Vec::with_capacity(hex.len() / 2);
    let b = hex.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16).unwrap();
        let lo = (b[i + 1] as char).to_digit(16).unwrap();
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

// ---------------------------------------------------------------------------
// Sweep: the real binary, end to end (opt-in; writes the receipt)
// ---------------------------------------------------------------------------

fn environment() -> Value {
    let digest = std::env::var("ORFS_IMAGE_DIGEST").unwrap_or_else(|_| "unknown".into());
    let env = orfs::bench::Environment::capture(Some(digest));
    json!({
        "bench": serde_json::to_value(&env).unwrap_or(Value::Null),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "toolchain": std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".into()),
    })
}

#[test]
fn crypto_erasure_sweep() {
    if std::env::var("ORFS_CRYPTO_ERASURE").as_deref() != Ok("1") {
        eprintln!("skipping crypto-erasure sweep (set ORFS_CRYPTO_ERASURE=1)");
        return;
    }

    let td = TempDir::new().unwrap();
    let dir = td.path().join("enc");
    let key = td.path().join("orfs.keys");
    let tier = td.path().join("cold-tier");
    let mnt = td.path().join("mnt");
    std::fs::create_dir_all(&mnt).unwrap();
    let dir_s = dir.display().to_string();
    let key_s = key.display().to_string();
    let tier_s = tier.display().to_string();
    let mnt_s = mnt.display().to_string();

    // 1. init an encrypted volume with the real binary.
    let (ok, init, err) = run_orfs_json(&["init", &dir_s, "--key-file", &key_s]);
    assert!(ok, "init failed: {err}");
    assert_eq!(init["encrypted"], json!(true));
    assert!(dir.join("crypto.meta").exists());
    assert!(!dir.join("volume.meta").exists());
    let uuid = init["uuid"].as_str().unwrap().to_string();
    assert_eq!(init["segments"], json!(1));

    // 2. write epoch-0 content through the seal (library), then read it back.
    let vol = EncryptedVolume::open_unverified(&dir, &key).unwrap();
    write_encrypted(&vol, b"epoch0", EPOCH0_SECRET.as_bytes());
    assert_eq!(read_encrypted(&vol, b"epoch0"), EPOCH0_SECRET.as_bytes());
    let on_disk_ciphertext = !contains_bytes(&segment_ciphertext(&vol), EPOCH0_SECRET.as_bytes());

    // 3. baseline ciphertext digest and the raw bytes (before the rollover, so
    //    the relocated copy below matches exactly this state).
    let (ok, d0, err) = run_orfs_json(&["crypt", "digest", &dir_s, "--key-file", &key_s]);
    assert!(ok, "digest failed: {err}");
    let digest_before_rotate = d0["ciphertext_blake3"].as_str().unwrap().to_string();

    // 4. relocate the ciphertext to a cold tier *before* destruction.
    let (ok, rel, err) = run_orfs_json(&[
        "crypt",
        "relocate",
        &dir_s,
        "--key-file",
        &key_s,
        "--tier-root",
        &tier_s,
    ]);
    assert!(ok, "relocate failed: {err}");
    let tier_digest_before = rel["digest"].as_str().unwrap().to_string();
    assert_eq!(tier_digest_before, digest_before_rotate);
    let tier_bytes_before =
        std::fs::read(tier.join(orfs::segment::segment_file_name(0).unwrap())).unwrap();

    // 5. rotate with the real binary: it rotates the keyring AND rolls the log
    //    over, so the store spans more than one segment.
    let (ok, rot, err) = run_orfs_json(&["key", "rotate", &dir_s, "--key-file", &key_s]);
    assert!(ok, "rotate failed: {err}");
    assert_eq!(rot["active_epoch"], json!(1));
    let segments_after_rotate = rot["segments"].as_u64().unwrap();
    assert!(
        segments_after_rotate >= 2,
        "a key rotation must force a segment boundary ({segments_after_rotate} segments)"
    );
    assert_eq!(
        run_orfs_json(&["crypt", "status", &dir_s, "--key-file", &key_s]).1["segments"],
        json!(segments_after_rotate)
    );

    // 6. capture the ciphertext (bytes + digest) immediately before destruction.
    let vol_before = EncryptedVolume::open_unverified(&dir, &key).unwrap();
    let bytes_before = segment_ciphertext(&vol_before);
    let digest_before = vol_before.ciphertext_digest().unwrap();

    // 7. destroy epoch 0 with the real binary.
    let (ok, dk, err) = run_orfs_json(&[
        "key",
        "destroy",
        &dir_s,
        "--key-file",
        &key_s,
        "--epoch",
        "0",
    ]);
    assert!(ok, "destroy failed: {err}");
    assert_eq!(dk["destroyed_epoch"], json!(0));
    assert_eq!(dk["live_epochs"], json!([1]));

    // 8. the store now fails closed: opening it is a typed KeyDestroyed.
    match EncryptedVolume::open(&dir, &key) {
        Err(orfs::OrfsError::KeyDestroyed(0)) => {}
        Ok(_) => panic!("a destroyed epoch key must fail the open closed (it opened)"),
        Err(e) => panic!("a destroyed epoch key must fail the open closed: {e}"),
    }
    let destroyed_open_fails_closed = true;

    // 9. verify reports the destroyed segment honestly and the store's intended
    //    state (never fabricated plaintext).
    let (ok, ver, err) = run_orfs_json(&["crypt", "verify", &dir_s, "--key-file", &key_s]);
    assert!(ok, "verify failed: {err}\nreport: {ver}");
    assert!(ver["report"]["ok"].as_bool().unwrap());
    let unreadable = ver["report"]["unreadable_destroyed"].as_array().unwrap();
    assert!(unreadable.contains(&json!(0)));

    // 10. ciphertext retained: bytes and digest unchanged after destruction.
    let vol = EncryptedVolume::open_unverified(&dir, &key).unwrap();
    let bytes_after = segment_ciphertext(&vol);
    let (ok, d1, err) = run_orfs_json(&["crypt", "digest", &dir_s, "--key-file", &key_s]);
    assert!(ok, "digest failed: {err}");
    let digest_after = d1["ciphertext_blake3"].as_str().unwrap().to_string();
    let ciphertext_unchanged = bytes_after == bytes_before && digest_after == digest_before;
    assert!(ciphertext_unchanged);

    // 11. the relocated ciphertext is inaccessible too, and unchanged.
    match read_relocated_segment(vol.cipher(), &tier, 0) {
        Err(orfs::OrfsError::KeyDestroyed(0)) => {}
        other => panic!("the relocated copy must be inaccessible too, got {other:?}"),
    }
    let tier_inaccessible = true;
    let tier_bytes_after =
        std::fs::read(tier.join(orfs::segment::segment_file_name(0).unwrap())).unwrap();
    let relocated_bytes_unchanged = tier_bytes_after == tier_bytes_before;

    // 11. honest key requirements: verify/recover without the key refuse.
    let (ok, _out, err) = run_orfs_json(&["verify", &dir_s]);
    assert!(!ok, "verify without a key must refuse");
    let verify_without_key_refused = err.contains("encrypted volume");
    let (ok, _out, err) = run_orfs_json(&["recover", &dir_s]);
    assert!(!ok, "recover without a key must refuse");
    let recover_without_key_refused = err.contains("encrypted volume");

    // 12. mounting without the key refuses (the guard returns before /dev/fuse).
    let (ok, _out, err) = run_orfs(&["mount", &dir_s, &mnt_s]);
    assert!(
        !ok,
        "mounting an encrypted volume without a key must refuse"
    );
    let mount_without_key_refused = err.contains("key-file") || err.contains("encrypted volume");

    // 13. a wrong key file is refused.
    let wrong_key = td.path().join("wrong.keys");
    let other = TempDir::new().unwrap();
    let other_dir = other.path().join("other-enc");
    let other_key = other.path().join("other.keys");
    let (ok, _out, err) = run_orfs_json(&[
        "init",
        &other_dir.display().to_string(),
        "--key-file",
        &other_key.display().to_string(),
    ]);
    assert!(ok, "second init failed: {err}");
    std::fs::copy(&other_key, &wrong_key).unwrap();
    let (ok, _out, err) = run_orfs(&[
        "mount",
        &dir_s,
        &mnt_s,
        "--key-file",
        &wrong_key.display().to_string(),
    ]);
    assert!(!ok, "a volume-bound key mismatch must refuse the mount");
    let wrong_key_refused = err.contains("volume") || err.contains("key");

    // 14. no key material anywhere in the authoritative area.
    let master = master_key_bytes(&key);
    let mut key_material_in_volume = false;
    for (_rel, bytes) in all_files(&dir) {
        if contains_bytes(&bytes, &master) {
            key_material_in_volume = true;
        }
    }
    assert!(!key_material_in_volume);

    // 15. the default (unencrypted) path is untouched.
    let plain_dir = td.path().join("plain");
    let (ok, _out, err) = run_orfs_json(&["init", &plain_dir.display().to_string()]);
    assert!(ok, "plain init failed: {err}");
    assert!(plain_dir.join("volume.meta").exists());
    assert!(!plain_dir.join("crypto.meta").exists());
    assert!(!encvol::is_encrypted_volume(&plain_dir));
    let plain = Volume::init_with_uuid(
        &td.path().join("plain2"),
        PLAIN_SEGMENT,
        PLAIN_UUID,
        PLAIN_CREATED,
    )
    .unwrap();
    let plain_digest = plain.log.committed_digest_hex().unwrap();
    let default_path_unchanged =
        plain_digest == PLAIN_GENESIS_DIGEST && !encvol::is_encrypted_volume(&plain_dir);
    assert!(default_path_unchanged);

    let receipt = json!({
        "schema": "orfs.security.crypto-erasure.v1",
        "phase": 86,
        "title": "Length-preserving per-segment seal, and mounting an encrypted volume",
        "git_commit": std::env::var("ORFS_GIT_COMMIT").unwrap_or_else(|_| "unknown".into()),
        "environment": environment(),
        "volume": {
            "kind": "encrypted",
            "uuid": uuid,
            "key_file": key_s,
            "tier_root": tier_s,
            "segments": segments_after_rotate,
            "epochs": {"0": "destroyed", "1": "live"},
        },
        "properties": {
            "ciphertext_round_trip_through_namespace": true,
            "on_disk_segments_are_ciphertext": on_disk_ciphertext,
            "rotate_forces_rollover_multi_segment": segments_after_rotate >= 2,
            "destroyed_epoch_fails_closed_on_open": destroyed_open_fails_closed,
            "verify_reports_destroyed_segment": true,
            "ciphertext_bytes_retained_unchanged": ciphertext_unchanged,
            "relocated_ciphertext_unchanged": relocated_bytes_unchanged,
            "crypto_erasure_covers_relocated_tier_copy": tier_inaccessible,
            "verify_without_key_refused": verify_without_key_refused,
            "recover_without_key_refused": recover_without_key_refused,
            "mount_without_key_refused": mount_without_key_refused,
            "wrong_key_refused": wrong_key_refused,
            "no_key_material_in_authoritative_area": !key_material_in_volume,
            "default_path_unchanged": default_path_unchanged,
        },
        "digests": {
            "ciphertext_blake3_before_destruction": digest_before,
            "ciphertext_blake3_after_destruction": digest_after,
            "relocated_ciphertext_blake3_before_destruction": tier_digest_before,
            "relocated_ciphertext_bytes_before": tier_bytes_before.len(),
            "authoritative_ciphertext_bytes": bytes_after.len(),
        },
        "default_path_anchor": {
            "unencrypted_genesis_committed_digest": plain_digest,
            "pinned": PLAIN_GENESIS_DIGEST,
            "note": "tests/format_compat.rs independently pins the same unencrypted \
                     on-disk format against the pre-existing frozen fixtures; the only \
                     pre-existing source files changed in Phase 86 are src/segment.rs, \
                     src/log.rs, src/volume.rs (one visibility change) and src/main.rs \
                     (the opt-in CLI surface), all gated behind the opt-in key.",
        },
        "wired": [
            "encrypted volume create/verify/relocate (`orfs init --key-file`, `orfs crypt`)",
            "epoch rotation with a forced rollover (`orfs key rotate`)",
            "epoch-key destruction (`orfs key destroy`)",
            "sealed-store verification (`orfs crypt verify`, `orfs verify --key-file`)",
            "length-preserving per-segment seal resolved by the namespace/read path",
        ],
        "not_wired": [],
        "mounted_proof": "evidence/security/crypto-erasure-mounted.json",
    });

    let out_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/security/crypto-erasure.json");
    std::fs::create_dir_all(out_path.parent().unwrap()).unwrap();
    std::fs::write(&out_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    println!("wrote {}", out_path.display());

    // Every demonstrated property must hold for the receipt to be honest.
    for (k, v) in receipt["properties"].as_object().unwrap() {
        assert_eq!(v, &json!(true), "property {k} is not true");
    }
    let _ = blake3_hex(bytes_after.as_slice());
}
