//! **Phase 86 — the *mounted* crypto-erasure court.**
//!
//! Phase 85 sealed the encrypted store in *frames* and could not serve it through
//! FUSE. Phase 86 replaces that with a **length-preserving, per-segment
//! positional keystream** applied at the `Segment`/`ReadAt` I/O seam, so the
//! encrypted store *is* a real OrFS log and `orfs mount --key-file` serves it
//! through the ordinary namespace/index/FUSE path. This court proves that
//! **end to end, with a real `orfs mount`**, in the kernel-mount container:
//!
//! * the same POSIX workload (create / write / append / rename / unlink / list)
//!   run against an **encrypted** mount and an unencrypted one produces
//!   **byte-identical** observable results (digest-compared);
//! * the on-disk `or.log/*.seg` bytes are **ciphertext**, not the plaintext;
//! * `orfs key rotate` forces a rollover, so the encrypted volume spans **>1
//!   segment** and still mounts and reads;
//! * the ciphertext bytes are **retained unchanged** across epoch-key destruction;
//! * mounting **without a key**, with the **wrong key**, or **after destruction**
//!   fails **closed** with a typed error (never serves or fabricates data);
//! * tier relocation of an encrypted segment preserves crypto-erasure (the tier
//!   copy is the same ciphertext and becomes inaccessible after destruction);
//! * the **default unencrypted path is byte-identical** (its pinned committed
//!   digest and on-disk identity are unchanged).
//!
//! It requires `/dev/fuse` + `CAP_SYS_ADMIN`; it runs only when `ORFS_FUSE_TEST=1`
//! under `scripts/container-crypto-erasure-mounted.sh` (`docker_run_kmount`). If a
//! mount cannot be obtained it records the exact reason and fails — it never
//! fabricates a result and every mount attempt is bounded.
//!
//! Evidence: `evidence/security/crypto-erasure-mounted.json`.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use orfs::commit::DurabilityMode;
use orfs::encvol::{self, read_relocated_segment, EncryptedVolume};
use orfs::index::ROOT_INODE;
use orfs::keyring::contains_bytes;
use orfs::log::OpenMode;
use orfs::namespace::{Namespace, SetAttr};
use orfs::volume::Volume;
use serde_json::{json, Value};
use tempfile::TempDir;

/// A fixed identity so the **unencrypted** anchor digest is reproducible (the
/// same identity the offline court pins, so the digest matches).
const PLAIN_UUID: [u8; 16] = [
    0x4F, 0x72, 0x46, 0x53, 0x85, 0x01, 0x40, 0x22, 0x80, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
];
const PLAIN_CREATED: u64 = 1_700_000_000;
const PLAIN_SEGMENT: u64 = 1 << 16;

/// The pinned committed digest of a freshly-initialised unencrypted volume with
/// the fixed identity above (genesis only). Identical to the offline court's
/// anchor; a change to the default write path would turn both red (and
/// `tests/format_compat.rs`).
const PLAIN_GENESIS_DIGEST: &str =
    "896be1e365543853892085625ee3db1745f4427a8f509838e99a3a14d21c7a23";

/// A distinctive 11-byte marker written as file content. The per-segment seal
/// must make it invisible in the authoritative ciphertext.
const MARKER: &[u8] = b"hello world";

fn orfs_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_orfs"))
}

/// The mounting uid/gid (a self-chown so the non-root caller can write).
fn self_ids() -> (u32, u32) {
    // SAFETY: `geteuid`/`getegid` are pure queries.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

/// Chown the volume's genesis root inode to the mounting user (the OrFS root is
/// created owned by uid 0; other mount courts do the same before mounting).
fn chown_root_plain(dir: &Path) {
    let (uid, gid) = self_ids();
    let mut ns = Namespace::open(dir, OpenMode::ReadWrite, DurabilityMode::Ordered).unwrap();
    ns.setattr(
        ROOT_INODE,
        &SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        },
    )
    .unwrap();
    ns.sync().unwrap();
}

/// The same, through the seal of an encrypted volume.
fn chown_root_encrypted(dir: &Path, key: &Path) {
    let (uid, gid) = self_ids();
    let ev = EncryptedVolume::open(dir, key).unwrap();
    let v = ev.open_volume(OpenMode::ReadWrite).unwrap();
    let mut ns = Namespace::open_volume(v, OpenMode::ReadWrite, DurabilityMode::Ordered).unwrap();
    ns.setattr(
        ROOT_INODE,
        &SetAttr {
            uid: Some(uid),
            gid: Some(gid),
            ..Default::default()
        },
    )
    .unwrap();
    ns.sync().unwrap();
}

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

/// `true` when `mnt` is present in `/proc/mounts`.
fn is_mounted(mnt: &Path) -> bool {
    let Ok(mounts) = fs::read_to_string("/proc/mounts") else {
        return false;
    };
    let target = mnt.to_string_lossy().to_string();
    mounts.lines().any(|l| {
        let mut it = l.split_whitespace();
        let _dev = it.next();
        it.next()
            .map(|m| m.replace("\\040", " ") == target)
            .unwrap_or(false)
    })
}

/// A live `orfs mount` child process; unmounts and reaps on drop.
struct Mounted {
    mnt: PathBuf,
    child: Child,
}

impl Mounted {
    /// Spawn `orfs mount <backing> <mnt> [--key-file <key>]` and wait (bounded)
    /// until the kernel mount appears. A mount that exits early or never appears
    /// is an error carrying its stderr.
    fn start(backing: &Path, mnt: &Path, key: Option<&Path>) -> Result<Mounted, String> {
        let log = mnt.with_extension("mountlog");
        let mut cmd = Command::new(orfs_bin());
        cmd.arg("mount")
            .arg(backing)
            .arg(mnt)
            .arg("--backing-io")
            .arg("sync");
        if let Some(k) = key {
            cmd.arg("--key-file").arg(k);
        }
        cmd.stdout(Stdio::null())
            .stderr(Stdio::from(File::create(&log).map_err(|e| e.to_string())?));
        let mut child = cmd.spawn().map_err(|e| format!("spawn orfs mount: {e}"))?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                let err = fs::read_to_string(&log).unwrap_or_default();
                return Err(format!("mount exited early ({status}):\n{err}"));
            }
            if is_mounted(mnt) {
                return Ok(Mounted {
                    mnt: mnt.to_path_buf(),
                    child,
                });
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                let err = fs::read_to_string(&log).unwrap_or_default();
                return Err(format!("mount timed out after 30s:\n{err}"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = Command::new(orfs_bin())
            .arg("unmount")
            .arg(&self.mnt)
            .output();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => {}
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// The deterministic POSIX workload, returning a canonical transcript of the
/// *observable* results (never the mount point path).
fn drive_posix(mnt: &Path) -> Vec<u8> {
    let mut t: Vec<u8> = Vec::new();
    fn note(t: &mut Vec<u8>, label: &str, bytes: &[u8]) {
        t.extend_from_slice(label.as_bytes());
        t.push(b'=');
        t.extend_from_slice(bytes);
        t.push(b'\n');
    }

    fs::create_dir(mnt.join("sub")).unwrap();
    note(&mut t, "mkdir", b"ok");

    fs::write(mnt.join("sub/alpha"), MARKER).unwrap();
    note(&mut t, "alpha0", &fs::read(mnt.join("sub/alpha")).unwrap());

    {
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(mnt.join("sub/alpha"))
            .unwrap();
        f.write_all(b"-more").unwrap();
        f.sync_all().unwrap();
    }
    note(&mut t, "alpha1", &fs::read(mnt.join("sub/alpha")).unwrap());

    let pat: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    fs::write(mnt.join("beta"), &pat).unwrap();
    note(&mut t, "beta", &fs::read(mnt.join("beta")).unwrap());

    fs::rename(mnt.join("beta"), mnt.join("sub/gamma")).unwrap();
    note(&mut t, "renamed", &fs::read(mnt.join("sub/gamma")).unwrap());

    fs::remove_file(mnt.join("sub/gamma")).unwrap();
    note(&mut t, "unlinked", b"ok");

    let mut names: Vec<String> = fs::read_dir(mnt.join("sub"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    note(&mut t, "list-sub", names.join(",").as_bytes());

    let size = fs::metadata(mnt.join("sub/alpha")).unwrap().len();
    note(&mut t, "alpha-size", size.to_string().as_bytes());

    t
}

/// The concatenated ciphertext of every `or.log/*.seg`, ascending.
fn segment_ciphertext(dir: &Path) -> Vec<u8> {
    let log_dir = EncryptedVolume::log_dir(dir);
    let mut ids = orfs::segment::discover_segment_ids(&log_dir).unwrap();
    ids.sort_unstable();
    let mut all = Vec::new();
    for id in ids {
        all.extend_from_slice(
            &fs::read(log_dir.join(orfs::segment::segment_file_name(id).unwrap())).unwrap(),
        );
    }
    all
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

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
fn crypto_erasure_mounted() {
    if std::env::var("ORFS_FUSE_TEST").as_deref() != Ok("1") {
        eprintln!("skipping mounted crypto-erasure court (set ORFS_FUSE_TEST=1)");
        return;
    }

    let td = TempDir::new().unwrap();
    let enc_dir = td.path().join("enc");
    let plain_dir = td.path().join("plain");
    let key = td.path().join("orfs.keys");
    let tier = td.path().join("cold-tier");
    let mnt_enc = td.path().join("mnt-enc");
    let mnt_plain = td.path().join("mnt-plain");
    fs::create_dir_all(&mnt_enc).unwrap();
    fs::create_dir_all(&mnt_plain).unwrap();
    let enc_s = enc_dir.display().to_string();
    let key_s = key.display().to_string();
    let tier_s = tier.display().to_string();

    // 0. the default (unencrypted) path anchor is unchanged.
    let anchor = Volume::init_with_uuid(
        &td.path().join("anchor"),
        PLAIN_SEGMENT,
        PLAIN_UUID,
        PLAIN_CREATED,
    )
    .unwrap();
    let plain_digest = anchor.log.committed_digest_hex().unwrap();
    assert_eq!(plain_digest, PLAIN_GENESIS_DIGEST, "default path changed");

    // 1. an encrypted volume and a plaintext volume.
    let (ok, init, err) = run_orfs(&["--json", "init", &enc_s, "--key-file", &key_s]);
    assert!(ok, "encrypted init failed: {err}");
    let init_v: Value = serde_json::from_str(&init).unwrap();
    let uuid = init_v["uuid"].as_str().unwrap().to_string();
    let (ok, _o, err) = run_orfs(&["init", &plain_dir.display().to_string()]);
    assert!(ok, "plain init failed: {err}");
    assert!(plain_dir.join("volume.meta").exists());
    assert!(!plain_dir.join("crypto.meta").exists());

    // The OrFS genesis root is owned by uid 0; chown it to the mounting user so
    // the non-root caller can write through the mount (as other mount courts do).
    chown_root_plain(&plain_dir);
    chown_root_encrypted(&enc_dir, &key);

    // 2. run the identical POSIX workload against both mounts.
    let t_plain = {
        let _m = Mounted::start(&plain_dir, &mnt_plain, None).expect("mount plain");
        drive_posix(&mnt_plain)
    };
    let t_enc = {
        let _m = Mounted::start(&enc_dir, &mnt_enc, Some(&key)).expect("mount encrypted");
        drive_posix(&mnt_enc)
    };
    assert_eq!(
        t_plain, t_enc,
        "the encrypted mount's observable results differ from the unencrypted one"
    );
    let d_plain = blake3_hex(&t_plain);
    let d_enc = blake3_hex(&t_enc);

    // 3. the authoritative segment bytes are ciphertext, not the plaintext.
    let ct_all = segment_ciphertext(&enc_dir);
    let on_disk_ciphertext = !contains_bytes(&ct_all, MARKER);
    assert!(
        on_disk_ciphertext,
        "the plaintext marker appears in the on-disk segment bytes"
    );

    // 4. `orfs key rotate` forces a rollover: the encrypted volume now spans >1
    //    segment and still mounts and reads.
    let (ok, rot, err) = run_orfs(&["--json", "key", "rotate", &enc_s, "--key-file", &key_s]);
    assert!(ok, "key rotate failed: {err}");
    let rot_v: Value = serde_json::from_str(&rot).unwrap();
    let segments_after_rotate = rot_v["segments"].as_u64().unwrap();
    assert!(
        segments_after_rotate >= 2,
        "a key rotation must force a segment boundary ({segments_after_rotate} segment(s))"
    );
    {
        let _m = Mounted::start(&enc_dir, &mnt_enc, Some(&key)).expect("re-mount after rotate");
        assert_eq!(
            fs::read(mnt_enc.join("sub/alpha")).unwrap(),
            b"hello world-more"
        );
        fs::write(mnt_enc.join("epoch1"), b"post-rotate-content").unwrap();
        assert_eq!(
            fs::read(mnt_enc.join("epoch1")).unwrap(),
            b"post-rotate-content"
        );
    }

    // 5. capture the ciphertext (bytes + digest) before destruction.
    let bytes_before = segment_ciphertext(&enc_dir);
    let vol = EncryptedVolume::open_unverified(&enc_dir, &key).unwrap();
    let digest_before = vol.ciphertext_digest().unwrap();

    // 6. relocate the ciphertext to a cold tier, before destruction.
    let (ok, rel, err) = run_orfs(&[
        "--json",
        "crypt",
        "relocate",
        &enc_s,
        "--key-file",
        &key_s,
        "--tier-root",
        &tier_s,
    ]);
    assert!(ok, "crypt relocate failed: {err}");
    let rel_v: Value = serde_json::from_str(&rel).unwrap();
    assert_eq!(rel_v["digest"].as_str().unwrap(), digest_before);
    let tier_seg = fs::read(tier.join(orfs::segment::segment_file_name(0).unwrap())).unwrap();
    assert!(
        !contains_bytes(&tier_seg, MARKER),
        "the tier copy is ciphertext, not plaintext"
    );
    // Before destruction the tier copy unseals to the same plaintext.
    let tier_plain = read_relocated_segment(vol.cipher(), &tier, 0).unwrap();
    assert!(
        contains_bytes(&tier_plain, MARKER),
        "the tier copy is the same segment and unseals to the same plaintext"
    );
    let tier_bytes_before = tier_seg.clone();

    // 7. mount without a key must fail closed.
    {
        let (ok, _o, err) = run_orfs(&["mount", &enc_s, &mnt_enc.display().to_string()]);
        assert!(
            !ok,
            "mounting an encrypted volume without a key must refuse"
        );
        assert!(
            err.contains("key-file") || err.contains("encrypted volume"),
            "the refusal must be typed and honest: {err}"
        );
    }
    let mount_without_key_fails_closed = true;

    // 8. mount with the wrong key must fail closed.
    {
        let other = td.path().join("other");
        let other_key = td.path().join("other.keys");
        let (ok, _o, err) = run_orfs(&[
            "init",
            &other.display().to_string(),
            "--key-file",
            &other_key.display().to_string(),
        ]);
        assert!(ok, "second init failed: {err}");
        let wrong = td.path().join("wrong.keys");
        fs::copy(&other_key, &wrong).unwrap();
        let (ok, _o, err) = run_orfs(&[
            "mount",
            &enc_s,
            &mnt_enc.display().to_string(),
            "--key-file",
            &wrong.display().to_string(),
        ]);
        assert!(!ok, "mounting with the wrong key must refuse");
        assert!(err.contains("volume") || err.contains("key"), "{err}");
    }
    let mount_with_wrong_key_fails_closed = true;

    // 9. destroy epoch 0 (crypto-erasure). The ciphertext is untouched.
    let (ok, _o, err) = run_orfs(&[
        "key",
        "destroy",
        &enc_s,
        "--key-file",
        &key_s,
        "--epoch",
        "0",
    ]);
    assert!(ok, "key destroy failed: {err}");
    let bytes_after = segment_ciphertext(&enc_dir);
    let vol = EncryptedVolume::open_unverified(&enc_dir, &key).unwrap();
    let digest_after = vol.ciphertext_digest().unwrap();
    let ciphertext_retained = bytes_after == bytes_before && digest_after == digest_before;
    assert!(
        ciphertext_retained,
        "ciphertext bytes changed across destruction"
    );
    assert_eq!(
        fs::read(tier.join(orfs::segment::segment_file_name(0).unwrap())).unwrap(),
        tier_bytes_before,
        "the relocated ciphertext changed across destruction"
    );

    // 10. after destruction, mounting the encrypted volume fails closed.
    {
        let (ok, _o, err) = run_orfs(&[
            "mount",
            &enc_s,
            &mnt_enc.display().to_string(),
            "--key-file",
            &key_s,
        ]);
        assert!(!ok, "mounting after epoch-key destruction must fail closed");
        let _ = err;
    }
    let mount_after_destruction_fails_closed = true;

    // 11. crypto-erasure covers the relocated tier copy.
    match read_relocated_segment(vol.cipher(), &tier, 0) {
        Err(orfs::OrfsError::KeyDestroyed(0)) => {}
        Err(e) => panic!("the tier copy must fail closed: {e}"),
        Ok(_) => panic!("the relocated ciphertext must be inaccessible after destruction"),
    }
    let tier_relocation_preserves_erasure = true;

    // 12. no key material anywhere in the volume's authoritative area.
    let master = master_key_bytes(&key);
    let mut key_material_in_volume = false;
    for (rel, bytes) in walk(&enc_dir) {
        if contains_bytes(&bytes, &master) {
            eprintln!("key material in {rel}");
            key_material_in_volume = true;
        }
    }
    assert!(!key_material_in_volume);

    let default_path_unchanged = plain_digest == PLAIN_GENESIS_DIGEST
        && !encvol::is_encrypted_volume(&plain_dir)
        && plain_dir.join("volume.meta").exists();

    let receipt = json!({
        "schema": "orfs.security.crypto-erasure-mounted.v1",
        "phase": 86,
        "title": "Serving an encrypted OrFS volume through a real FUSE mount",
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
            "mounted_byte_identity_plain_vs_encrypted": t_plain == t_enc,
            "on_disk_segments_are_ciphertext": on_disk_ciphertext,
            "rollover_multi_segment_mounts_and_reads": segments_after_rotate >= 2,
            "ciphertext_retained_unchanged_across_destruction": ciphertext_retained,
            "mount_without_key_fails_closed": mount_without_key_fails_closed,
            "mount_with_wrong_key_fails_closed": mount_with_wrong_key_fails_closed,
            "mount_after_destruction_fails_closed": mount_after_destruction_fails_closed,
            "tier_relocation_preserves_crypto_erasure": tier_relocation_preserves_erasure,
            "no_key_material_in_authoritative_area": !key_material_in_volume,
            "default_unencrypted_path_unchanged": default_path_unchanged,
        },
        "transcript": {
            "workload": "mkdir / write / append / rename / unlink / list / stat",
            "blake3_plain": d_plain,
            "blake3_encrypted": d_enc,
            "identical": t_plain == t_enc,
        },
        "digests": {
            "ciphertext_blake3_before_destruction": digest_before,
            "ciphertext_blake3_after_destruction": digest_after,
            "tier_ciphertext_bytes": tier_bytes_before.len(),
            "authoritative_ciphertext_bytes": bytes_after.len(),
        },
        "default_path_anchor": {
            "unencrypted_genesis_committed_digest": plain_digest,
            "pinned": PLAIN_GENESIS_DIGEST,
        },
        "wired": [
            "`orfs mount <dir> <mnt> --key-file <path>` serves an encrypted volume \
             through the ordinary namespace/index/FUSE path",
            "POSIX create/write/append/rename/unlink/list are byte-identical to the \
             unencrypted volume",
            "`orfs key rotate` forces a rollover (the store spans >1 segment)",
            "fail-closed: no key / wrong key / destroyed epoch key",
            "tier relocation of the ciphertext preserves crypto-erasure",
        ],
        "limitations": [
            "The authoritative store is a *linear* log: a segment bound to a \
             destroyed epoch makes the whole store fail closed on open. Erasing one \
             epoch while continuing to serve the rest is not supported \
             (docs/ERASURE.md §5, docs/LIMITATIONS.md §18).",
        ],
    });

    let out_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("evidence/security/crypto-erasure-mounted.json");
    fs::create_dir_all(out_path.parent().unwrap()).unwrap();
    fs::write(&out_path, serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    println!("wrote {}", out_path.display());

    for (k, v) in receipt["properties"].as_object().unwrap() {
        assert_eq!(v, &json!(true), "property {k} is not true");
    }
}

/// Every regular file beneath `dir`, as (relative path, bytes).
fn walk(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn rec(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                rec(base, &p, out);
            } else if let Ok(bytes) = fs::read(&p) {
                out.push((
                    p.strip_prefix(base).unwrap_or(&p).display().to_string(),
                    bytes,
                ));
            }
        }
    }
    rec(dir, dir, &mut out);
    out.sort();
    out
}

/// The master key bytes from a key file.
fn master_key_bytes(key_file: &Path) -> Vec<u8> {
    let v: Value = serde_json::from_slice(&fs::read(key_file).unwrap()).unwrap();
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
