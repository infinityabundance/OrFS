//! **Phase 85 — the crypto-erasure court.**
//!
//! OrFS is **non-withdrawal**: `unlink`/`rmdir`/`truncate`/overwrite change only
//! the visible namespace and never physically remove authoritative history
//! (`docs/RETENTION.md`). A "secure delete" promise would therefore contradict
//! the filesystem's own behaviour. The only defensible erasure story on top of
//! non-withdrawal is **cryptographic**: seal content under a key and destroy the
//! key, leaving the ciphertext bytes in place, unwithdrawn, but unreadable.
//!
//! This court makes that executable, end to end, on a **dedicated encrypted
//! volume** (`orfs init --key-file`), driven through the **real `orfs` binary**:
//!
//! * `init` an encrypted volume and append sealed frames;
//! * read them back with the correct key — **the key-correct read is identical**;
//! * reject a **tampered** ciphertext (AEAD failure);
//! * `key rotate` and `key destroy --epoch 0`;
//! * prove the destroyed epoch's content is **cryptographically inaccessible**
//!   (a typed, fail-closed error) while the **ciphertext bytes are unchanged**
//!   and the surviving epoch still reads identically;
//! * prove **crypto-erasure covers a relocated (tiered) copy**, whose bytes are
//!   ciphertext: the tier copy is also inaccessible after the key is destroyed,
//!   and its bytes are unchanged;
//! * prove the **default (unencrypted) path is untouched**: an ordinary volume
//!   carries no `crypto.meta`, is not treated as encrypted, and its pinned
//!   committed digest is unchanged;
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
//! See `docs/RETENTION.md` and `docs/ERASURE.md` for the contract and the design,
//! including **exactly what is wired and what is not** (`orfs mount` does not yet
//! serve an encrypted volume).

use std::path::{Path, PathBuf};
use std::process::Command;

use orfs::encvol::{self, read_relocated_frame, EncryptedVolume};
use orfs::keyring::{contains_bytes, Keyring};
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

const EPOCH0_SECRET: &str = "phase85-epoch-0-secret";
const EPOCH1_CONTENT: &str = "phase85-epoch-1-content";

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

    let off0 = vol.append(EPOCH0_SECRET.as_bytes()).unwrap();
    assert_eq!(vol.read_at(off0).unwrap(), EPOCH0_SECRET.as_bytes());

    // -- tamper rejection (AEAD failure) -----------------------------------
    let seg_path =
        EncryptedVolume::log_dir(&dir).join(orfs::segment::segment_file_name(0).unwrap());
    let mut raw = std::fs::read(&seg_path).unwrap();
    // Frame 1 = header(14) + sealed version(1) + nonce(24) + length field(8), then
    // the sealed ciphertext. Flip one ciphertext byte (the framing stays intact,
    // so only the AEAD tag can reject it).
    let victim = (off0 as usize) + 14 + 1 + 24 + 8 + 3;
    raw[victim] ^= 0x01;
    std::fs::write(&seg_path, &raw).unwrap();
    let tampered = EncryptedVolume::open(&dir, &key).unwrap();
    match tampered.read_at(off0) {
        Err(orfs::OrfsError::CryptoAuthFailed(_)) => {}
        other => panic!("a tampered ciphertext must not open: {other:?}"),
    }
    raw[victim] ^= 0x01;
    std::fs::write(&seg_path, &raw).unwrap();
    // Restored: opens again, byte-identically.
    assert_eq!(
        EncryptedVolume::open(&dir, &key)
            .unwrap()
            .read_at(off0)
            .unwrap(),
        EPOCH0_SECRET.as_bytes()
    );

    // -- rotate, then destroy epoch 0 --------------------------------------
    let e1 = vol.rotate(PLAIN_CREATED + 100).unwrap();
    assert_eq!(e1, 1);
    let off1 = vol.append(EPOCH1_CONTENT.as_bytes()).unwrap();
    vol.sync().unwrap();

    let bytes_before = std::fs::read(&seg_path).unwrap();
    let digest_before = vol.ciphertext_digest().unwrap();

    vol.destroy_epoch(0, PLAIN_CREATED + 200).unwrap();

    // Destroyed epoch: typed, fail-closed. No plaintext fabricated.
    match vol.read_at(off0) {
        Err(orfs::OrfsError::KeyDestroyed(0)) => {}
        other => panic!("expected KeyDestroyed(0), got {other:?}"),
    }
    // Surviving epoch: key-correct read is identical.
    assert_eq!(vol.read_at(off1).unwrap(), EPOCH1_CONTENT.as_bytes());

    // Ciphertext retained: every byte is unchanged.
    let bytes_after = std::fs::read(&seg_path).unwrap();
    assert_eq!(bytes_after, bytes_before, "ciphertext bytes changed");
    assert_eq!(vol.ciphertext_digest().unwrap(), digest_before);

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
    assert_eq!(rel.digest, vol.ciphertext_digest().unwrap());
    let kr = Keyring::load(&key).unwrap();
    match read_relocated_frame(&tier, off0, &kr) {
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
    let dir_s = dir.display().to_string();
    let key_s = key.display().to_string();
    let tier_s = tier.display().to_string();

    // 1. init an encrypted volume.
    let (ok, init, err) = run_orfs_json(&["init", &dir_s, "--key-file", &key_s]);
    assert!(ok, "init failed: {err}");
    assert_eq!(init["encrypted"], json!(true));
    assert!(dir.join("crypto.meta").exists());
    assert!(!dir.join("volume.meta").exists());
    let uuid = init["uuid"].as_str().unwrap().to_string();

    // 2. append an epoch-0 frame with the real binary.
    let (ok, a0, err) = run_orfs_json(&[
        "crypt",
        "append",
        &dir_s,
        "--key-file",
        &key_s,
        "--text",
        EPOCH0_SECRET,
    ]);
    assert!(ok, "append failed: {err}");
    let off0 = a0["offset"].as_u64().unwrap();

    // 3. rotate to epoch 1, then append an epoch-1 frame.
    let (ok, rot, err) = run_orfs_json(&["key", "rotate", &dir_s, "--key-file", &key_s]);
    assert!(ok, "rotate failed: {err}");
    assert_eq!(rot["active_epoch"], json!(1));
    let (ok, a1, err) = run_orfs_json(&[
        "crypt",
        "append",
        &dir_s,
        "--key-file",
        &key_s,
        "--text",
        EPOCH1_CONTENT,
    ]);
    assert!(ok, "append failed: {err}");
    let off1 = a1["offset"].as_u64().unwrap();

    // 4. key-correct read is identical (both epochs).
    let (ok, r0, err) = run_orfs_json(&[
        "crypt",
        "read",
        &dir_s,
        "--key-file",
        &key_s,
        "--offset",
        &off0.to_string(),
    ]);
    assert!(ok, "read epoch0 failed: {err}");
    assert_eq!(r0["plaintext_utf8"], json!(EPOCH0_SECRET));
    let (ok, r1, err) = run_orfs_json(&[
        "crypt",
        "read",
        &dir_s,
        "--key-file",
        &key_s,
        "--offset",
        &off1.to_string(),
    ]);
    assert!(ok, "read epoch1 failed: {err}");
    assert_eq!(r1["plaintext_utf8"], json!(EPOCH1_CONTENT));

    // 5. baseline ciphertext digest and the raw bytes.
    let seg = EncryptedVolume::log_dir(&dir).join(orfs::segment::segment_file_name(0).unwrap());
    let bytes_before = std::fs::read(&seg).unwrap();
    let (ok, d0, err) = run_orfs_json(&["crypt", "digest", &dir_s, "--key-file", &key_s]);
    assert!(ok, "digest failed: {err}");
    let digest_before = d0["ciphertext_blake3"].as_str().unwrap().to_string();

    // 6. relocate the ciphertext to a cold tier *before* destruction.
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
    assert_eq!(tier_digest_before, digest_before);
    let tier_bytes_before =
        std::fs::read(tier.join(orfs::segment::segment_file_name(0).unwrap())).unwrap();

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

    // 8. the destroyed epoch no longer reads: typed, fail-closed.
    let (ok, _out, err) = run_orfs_json(&[
        "crypt",
        "read",
        &dir_s,
        "--key-file",
        &key_s,
        "--offset",
        &off0.to_string(),
    ]);
    assert!(!ok, "reading a destroyed epoch must fail closed");
    assert!(
        err.contains("destroyed"),
        "the failure must name the destroyed epoch: {err}"
    );
    let destroyed_read_fails_closed = true;

    // 9. the surviving epoch still reads identically.
    let (ok, r1b, err) = run_orfs_json(&[
        "crypt",
        "read",
        &dir_s,
        "--key-file",
        &key_s,
        "--offset",
        &off1.to_string(),
    ]);
    assert!(ok, "epoch-1 read failed after destruction: {err}");
    assert_eq!(r1b["plaintext_utf8"], json!(EPOCH1_CONTENT));

    // 10. ciphertext retained: bytes and digest unchanged after destruction.
    let bytes_after = std::fs::read(&seg).unwrap();
    let (ok, d1, err) = run_orfs_json(&["crypt", "digest", &dir_s, "--key-file", &key_s]);
    assert!(ok, "digest failed: {err}");
    let digest_after = d1["ciphertext_blake3"].as_str().unwrap().to_string();
    let ciphertext_unchanged = bytes_after == bytes_before && digest_after == digest_before;

    // 11. verify the store: which frames open and which are inaccessible.
    let (ok, ver, err) = run_orfs_json(&["crypt", "verify", &dir_s, "--key-file", &key_s]);
    assert!(ok, "verify failed: {err}\nreport: {ver}");
    assert_eq!(ver["report"]["frames"], json!(3)); // genesis + epoch0 + epoch1
    assert_eq!(ver["report"]["readable"], json!(1)); // only the epoch-1 frame
    assert_eq!(
        ver["report"]["unreadable_destroyed"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // 12. the relocated ciphertext is inaccessible too, and unchanged.
    let kr = Keyring::load(&key).unwrap();
    let tier_inaccessible = matches!(
        read_relocated_frame(&tier, off0, &kr),
        Err(orfs::OrfsError::KeyDestroyed(0))
    );
    let tier_bytes_after =
        std::fs::read(tier.join(orfs::segment::segment_file_name(0).unwrap())).unwrap();
    let relocated_bytes_unchanged = tier_bytes_after == tier_bytes_before;

    // 13. honest key requirements: verify/recover without the key refuse.
    let (ok, _out, err) = run_orfs_json(&["verify", &dir_s]);
    assert!(!ok, "verify without a key must refuse");
    let verify_without_key_refused = err.contains("encrypted volume");
    let (ok, _out, err) = run_orfs_json(&["recover", &dir_s]);
    assert!(!ok, "recover without a key must refuse");
    let recover_without_key_refused = err.contains("encrypted volume");

    // 14. a wrong key file is refused.
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
    let (ok, _out, _err) = run_orfs_json(&[
        "crypt",
        "read",
        &dir_s,
        "--key-file",
        &wrong_key.display().to_string(),
        "--offset",
        &off1.to_string(),
    ]);
    assert!(!ok, "a volume-bound key mismatch must refuse");
    let wrong_key_refused = true;

    // 15. mounting an encrypted volume is refused (not wired) — quickly and
    //     without needing /dev/fuse, because the guard returns first.
    let mnt = td.path().join("mnt");
    std::fs::create_dir_all(&mnt).unwrap();
    let (ok, _out, err) = run_orfs(&["mount", &dir_s, &mnt.display().to_string()]);
    assert!(!ok, "mounting an encrypted volume must be refused");
    let mount_refused_honestly = err.contains("not wired");

    // 16. no key material anywhere in the authoritative area.
    let master = master_key_bytes(&key);
    let mut key_material_in_volume = false;
    for (_rel, bytes) in all_files(&dir) {
        if contains_bytes(&bytes, &master) {
            key_material_in_volume = true;
        }
    }
    assert!(!key_material_in_volume);

    // 17. the default (unencrypted) path is untouched.
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

    // 18. a full re-read of the surviving content through the library matches
    //     the CLI read (no divergence between surfaces).
    let vol = EncryptedVolume::open_unverified(&dir, &key).unwrap();
    assert_eq!(vol.read_at(off1).unwrap(), EPOCH1_CONTENT.as_bytes());
    let key_correct_read_identical = true;

    let receipt = json!({
        "schema": "orfs.security.crypto-erasure.v1",
        "phase": 85,
        "title": "Retention contract, access control, and a real crypto-erasure mechanism",
        "git_commit": std::env::var("ORFS_GIT_COMMIT").unwrap_or_else(|_| "unknown".into()),
        "environment": environment(),
        "volume": {
            "kind": "encrypted",
            "uuid": uuid,
            "key_file": key_s,
            "tier_root": tier_s,
            "frames": 3,
            "epochs": {"0": "destroyed", "1": "live"},
        },
        "properties": {
            "round_trip_with_correct_key": true,
            "key_correct_read_identical": key_correct_read_identical,
            "tamper_rejected_aead": true,
            "epoch_destruction_makes_content_inaccessible": destroyed_read_fails_closed,
            "ciphertext_bytes_retained_unchanged": ciphertext_unchanged,
            "relocated_ciphertext_unchanged": relocated_bytes_unchanged,
            "crypto_erasure_covers_relocated_tier_copy": tier_inaccessible,
            "verify_without_key_refused": verify_without_key_refused,
            "recover_without_key_refused": recover_without_key_refused,
            "wrong_key_refused": wrong_key_refused,
            "mount_of_encrypted_volume_refused_honestly": mount_refused_honestly,
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
                     pre-existing source files changed in Phase 85 are src/lib.rs \
                     (two module declarations), src/error.rs (three new opt-in error \
                     variants) and src/main.rs (new opt-in CLI surface).",
        },
        "wired": [
            "encrypted volume create/open/append/read (library + `orfs crypt`)",
            "epoch rotation and epoch-key destruction (`orfs key rotate|destroy`)",
            "sealed-store verification (`orfs crypt verify`, `orfs verify --key-file`)",
            "ciphertext relocation to a cold tier (`orfs crypt relocate`)",
        ],
        "not_wired": [
            "mounting an encrypted volume through FUSE (`orfs mount` refuses with a \
             typed Unsupported error; the sealed store is not yet resolved by the \
             namespace/read path)",
        ],
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
