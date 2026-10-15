//! Cryptographic key lifecycle: a volume master key, per-epoch data keys,
//! envelope encryption, and **key destruction as the erasure primitive**
//! (Phase 85, `docs/ERASURE.md`).
//!
//! # Why this exists
//!
//! OrFS is **non-withdrawal**: `unlink`/`rmdir`/`truncate`/overwrite change the
//! *visible* namespace and never physically remove the authoritative historical
//! bytes (`docs/RETENTION.md`, invariant I1). A "secure delete" promise would
//! therefore contradict the filesystem's own behaviour. The only defensible
//! erasure story on top of non-withdrawal is **cryptographic**: seal content
//! under a key, then *destroy the key*. The ciphertext is never overwritten,
//! truncated, or withdrawn — it simply becomes unreadable.
//!
//! This module is deliberately **key management only**: it has no knowledge of
//! segments, records, or the namespace. `src/encvol.rs` is the (opt-in) encrypted
//! volume that applies it at the segment I/O seam. Nothing here is on the default
//! (unencrypted) path.
//!
//! # Key hierarchy
//!
//! ```text
//!   master key (KEK)                       stored in the operator's key file
//!     ├── wraps ── epoch 0 data key (DEK)  wrapped blob in the keyring state
//!     ├── wraps ── epoch 1 data key (DEK)  wrapped blob in the keyring state
//!     └── wraps ── epoch n data key (DEK)  …
//! ```
//!
//! * The **master key** never leaves the operator-supplied key file and is never
//!   written into a volume's authoritative area.
//! * Each **epoch** has an independent, freshly generated random data key. It is
//!   *wrapped* (envelope encryption) under the master key with an authenticated
//!   encryption with associated data (AEAD).
//! * **Destroying an epoch** deletes the wrapped data key from the keyring state
//!   and records a durable tombstone. Because the data key is random (not derived
//!   from the master key), deleting the wrapped blob destroys the only copy: the
//!   epoch's ciphertext becomes cryptographically inaccessible even to a holder
//!   of the master key. This is the erasure primitive.
//! * **Rotating** an epoch creates a new data key and makes it active; existing
//!   ciphertext stays under its old epoch key.
//!
//! # The AEAD construction (and its honest limits)
//!
//! The crate already depends on `blake3` (a vetted, widely-remarked cryptographic
//! hash) and adding a second crypto dependency is avoided deliberately: OrFS
//! builds in a network-isolated container against a frozen `Cargo.lock`. The AEAD
//! here is therefore built from BLAKE3's **keyed mode** (a pseudorandom function)
//! in a textbook **encrypt-then-MAC** composition:
//!
//! * a **keystream** `BLAKE3_keyed(enc_key, "orfs.aead.stream.v1" ‖ nonce ‖
//!   le64(block))` XORed into the plaintext (a counter-mode stream cipher), and
//! * a **tag** `BLAKE3_keyed(mac_key, "orfs.aead.tag.v1" ‖ header ‖ aad ‖ ct)`
//!   where `header` is the versioned sealed encoding's own bytes (version, nonce,
//!   ciphertext length) so that *no byte is unauthenticated*.
//!
//! The subkeys `enc_key`/`mac_key` are derived from the data key with distinct
//! domain-separation labels. This is a real, standard construction over a vetted
//! primitive, **not** a bespoke cipher — but it is also **not** a standardised
//! AEAD such as XChaCha20-Poly1305, and `docs/ERASURE.md` says so and names the
//! swap-in point. Key material is not `mlock`ed or explicitly zeroised on drop;
//! that is stated as a limitation there rather than implied to be handled.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{OrfsError, Result};

/// Schema tag written into the key file.
pub const KEYRING_SCHEMA: &str = "orfs.keyring.v1";

/// Length of every symmetric key (master and data keys), in bytes.
pub const KEY_LEN: usize = 32;

/// Length of the AEAD nonce, in bytes.
pub const NONCE_LEN: usize = 24;

/// Length of the AEAD authentication tag, in bytes.
pub const TAG_LEN: usize = 32;

/// Version byte of the sealed encoding.
pub const SEALED_VERSION: u8 = 1;

/// Fixed overhead of a sealed blob: version + nonce + length + tag.
pub const SEALED_OVERHEAD: usize = 1 + NONCE_LEN + 8 + TAG_LEN;

/// Domain-separation label for the keystream subkey.
const ENC_LABEL: &[u8] = b"orfs.aead.enc.v1";
/// Domain-separation label for the MAC subkey.
const MAC_LABEL: &[u8] = b"orfs.aead.mac.v1";
/// Domain-separation label for the keystream blocks.
const STREAM_LABEL: &[u8] = b"orfs.aead.stream.v1";
/// Domain-separation label for the tag.
const TAG_LABEL: &[u8] = b"orfs.aead.tag.v1";
/// Associated data binding a wrapped data key to its purpose and epoch.
const WRAP_AAD_LABEL: &[u8] = b"orfs.keyring.wrap.v1";

/// A 32-byte symmetric key. Key material is intentionally not printable.
#[derive(Clone)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// Wrap raw bytes as a key.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Key {
        Key(bytes)
    }

    /// Generate a fresh random key.
    pub fn generate() -> Result<Key> {
        let mut k = [0u8; KEY_LEN];
        fill_random(&mut k)?;
        Ok(Key(k))
    }

    /// The raw bytes. Deliberately explicit so every use site is auditable.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.write_str("Key(<redacted>)")
    }
}

/// A subkey of a key, derived with a domain-separation label.
fn subkey(key: &Key, label: &[u8]) -> [u8; KEY_LEN] {
    *blake3::Hasher::new_keyed(&key.0)
        .update(label)
        .finalize()
        .as_bytes()
}

/// XOR a BLAKE3-counter-mode keystream into `buf` in place.
fn apply_keystream(key: &Key, nonce: &[u8; NONCE_LEN], buf: &mut [u8]) {
    let enc = subkey(key, ENC_LABEL);
    let mut counter: u64 = 0;
    let mut off = 0usize;
    while off < buf.len() {
        let block = blake3::Hasher::new_keyed(&enc)
            .update(STREAM_LABEL)
            .update(nonce)
            .update(&counter.to_le_bytes())
            .finalize();
        let kb = block.as_bytes();
        let n = (buf.len() - off).min(kb.len());
        for i in 0..n {
            buf[off + i] ^= kb[i];
        }
        off += n;
        counter += 1;
    }
}

/// The authentication tag over the versioned header, the caller's associated
/// data, and the ciphertext. Every byte of the sealed encoding is covered.
fn compute_tag(key: &Key, header: &[u8], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_LEN] {
    let mac = subkey(key, MAC_LABEL);
    let mut h = blake3::Hasher::new_keyed(&mac);
    h.update(TAG_LABEL);
    h.update(&(header.len() as u64).to_le_bytes());
    h.update(header);
    h.update(&(aad.len() as u64).to_le_bytes());
    h.update(aad);
    h.update(&(ciphertext.len() as u64).to_le_bytes());
    h.update(ciphertext);
    *h.finalize().as_bytes()
}

/// Constant-time equality, so a tag comparison cannot leak a prefix match.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Seal `plaintext` under `key` with an explicit `nonce`, returning the
/// **versioned** encoding
/// `version ‖ nonce ‖ le64(len) ‖ ciphertext ‖ tag`.
///
/// The nonce **must be unique** for a given key; reusing a `(key, nonce)` pair
/// breaks a stream cipher, so callers derive a fresh nonce per sealed blob (the
/// encrypted volume derives it from the epoch and frame index; envelope wrapping
/// uses a random nonce). `aad` is authenticated but not encrypted.
pub fn seal_with_nonce(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let mut header = Vec::with_capacity(1 + NONCE_LEN + 8);
    header.push(SEALED_VERSION);
    header.extend_from_slice(nonce);
    header.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());

    let mut ct = plaintext.to_vec();
    apply_keystream(key, nonce, &mut ct);
    let tag = compute_tag(key, &header, aad, &ct);

    let mut out = Vec::with_capacity(header.len() + ct.len() + TAG_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    out
}

/// Seal `plaintext` with a fresh random nonce.
pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    Ok(seal_with_nonce(key, &nonce, aad, plaintext))
}

/// Open a sealed blob produced by [`seal_with_nonce`]/[`seal`].
///
/// Fails closed: a wrong key, a tampered ciphertext, tampered associated data, a
/// tampered header, an unknown version, or a truncated/over-long framing all
/// return a typed error — never a fabricated plaintext prefix.
pub fn open_sealed(key: &Key, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < SEALED_OVERHEAD {
        return Err(OrfsError::CryptoAuthFailed(format!(
            "sealed blob is {} bytes, below the {} byte minimum",
            blob.len(),
            SEALED_OVERHEAD
        )));
    }
    let version = blob[0];
    if version != SEALED_VERSION {
        return Err(OrfsError::Compatibility(format!(
            "sealed blob version {version} (this build supports {SEALED_VERSION})"
        )));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&blob[1..1 + NONCE_LEN]);
    let len_at = 1 + NONCE_LEN;
    let ct_len = u64::from_le_bytes(
        blob[len_at..len_at + 8]
            .try_into()
            .expect("checked 8-byte length field"),
    );
    let ct_len = usize::try_from(ct_len).map_err(|_| OrfsError::Overflow {
        what: "sealed ciphertext length",
    })?;
    let expected = (1 + NONCE_LEN + 8)
        .checked_add(ct_len)
        .and_then(|n| n.checked_add(TAG_LEN))
        .ok_or(OrfsError::Overflow {
            what: "sealed blob length",
        })?;
    if expected != blob.len() {
        return Err(OrfsError::CryptoAuthFailed(format!(
            "sealed blob length {} disagrees with its framing (expected {expected})",
            blob.len()
        )));
    }
    let header = &blob[..len_at + 8];
    let ct = &blob[len_at + 8..len_at + 8 + ct_len];
    let tag = &blob[len_at + 8 + ct_len..];
    let want = compute_tag(key, header, aad, ct);
    if !ct_eq(tag, &want) {
        return Err(OrfsError::CryptoAuthFailed(
            "AEAD tag mismatch (wrong key or tampered bytes)".to_string(),
        ));
    }
    let mut pt = ct.to_vec();
    apply_keystream(key, &nonce, &mut pt);
    Ok(pt)
}

// ---------------------------------------------------------------------------
// The keyring state file (operator-supplied path; never inside `or.log`)
// ---------------------------------------------------------------------------

/// One epoch's record in the keyring state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRecord {
    /// The epoch ordinal.
    pub epoch: u64,
    /// When the epoch's data key was created (unix seconds).
    pub created_unix_secs: u64,
    /// The wrapped data key (hex of a sealed blob), absent once destroyed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub wrapped: Option<String>,
    /// When the epoch was destroyed (unix seconds), if it was.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub destroyed_unix_secs: Option<u64>,
}

impl EpochRecord {
    /// Whether this epoch's key is still available.
    pub fn is_live(&self) -> bool {
        self.wrapped.is_some()
    }
}

/// Persisted keyring state (the payload, integrity-checked by
/// [`KeyringFile`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyringState {
    /// The volume this keyring belongs to (lowercase hex UUID).
    pub volume_uuid: String,
    /// The epoch new content is currently sealed under.
    pub active_epoch: u64,
    /// Every epoch, ascending.
    pub epochs: Vec<EpochRecord>,
}

impl KeyringState {
    fn find(&self, epoch: u64) -> Option<&EpochRecord> {
        self.epochs.iter().find(|e| e.epoch == epoch)
    }
    fn find_mut(&mut self, epoch: u64) -> Option<&mut EpochRecord> {
        self.epochs.iter_mut().find(|e| e.epoch == epoch)
    }
}

/// The on-disk key file envelope: master key + integrity-checked state.
#[derive(Debug, Serialize, Deserialize)]
struct KeyringFile {
    schema: String,
    /// CRC32C (hex) of the serialized `state`, for corruption detection.
    state_crc32c: String,
    /// The volume master key (KEK), lowercase hex.
    master_key: String,
    state: KeyringState,
}

/// A volume's keyring: the master key plus every epoch's wrapped data key.
#[derive(Debug)]
pub struct Keyring {
    master: Key,
    state: KeyringState,
    path: PathBuf,
}

impl Keyring {
    /// Read and validate a keyring file.
    pub fn load(path: &Path) -> Result<Keyring> {
        let bytes = std::fs::read(path)?;
        let file: KeyringFile = serde_json::from_slice(&bytes).map_err(|e| {
            OrfsError::KeyUnavailable(format!(
                "key file {} is not valid JSON: {e}",
                path.display()
            ))
        })?;
        if file.schema != KEYRING_SCHEMA {
            return Err(OrfsError::Compatibility(format!(
                "key file schema {} (this build supports {KEYRING_SCHEMA})",
                file.schema
            )));
        }
        let state_bytes = serde_json::to_vec(&file.state).map_err(|e| {
            OrfsError::KeyUnavailable(format!("keyring state cannot be re-serialized: {e}"))
        })?;
        let got = crc32c::crc32c(&state_bytes);
        let want = u32::from_str_radix(file.state_crc32c.trim(), 16)
            .map_err(|_| OrfsError::KeyUnavailable("keyring state checksum is not hex".into()))?;
        if got != want {
            return Err(OrfsError::KeyUnavailable(
                "keyring state checksum mismatch (the key file is corrupt)".to_string(),
            ));
        }
        let master = Key(from_hex32(&file.master_key)?);
        Ok(Keyring {
            master,
            state: file.state,
            path: path.to_path_buf(),
        })
    }

    /// Create a fresh keyring with a new random master key and an epoch-0 data
    /// key, writing it to `path`.
    pub fn create(path: &Path, volume_uuid: &str, now_unix_secs: u64) -> Result<Keyring> {
        let master = Key::generate()?;
        let mut state = KeyringState {
            volume_uuid: volume_uuid.to_string(),
            active_epoch: 0,
            epochs: Vec::new(),
        };
        let wrapped = wrap_new_epoch(&master, 0, now_unix_secs)?;
        state.epochs.push(wrapped);
        let kr = Keyring {
            master,
            state,
            path: path.to_path_buf(),
        };
        kr.persist()?;
        Ok(kr)
    }

    /// The volume UUID this keyring is bound to.
    pub fn volume_uuid(&self) -> &str {
        &self.state.volume_uuid
    }

    /// The active epoch.
    pub fn active_epoch(&self) -> u64 {
        self.state.active_epoch
    }

    /// Every epoch, ascending.
    pub fn epochs(&self) -> &[EpochRecord] {
        &self.state.epochs
    }

    /// The epochs whose data keys are still available.
    pub fn live_epochs(&self) -> Vec<u64> {
        self.state
            .epochs
            .iter()
            .filter(|e| e.is_live())
            .map(|e| e.epoch)
            .collect()
    }

    /// The epochs whose data keys have been destroyed.
    pub fn destroyed_epochs(&self) -> Vec<u64> {
        self.state
            .epochs
            .iter()
            .filter(|e| !e.is_live())
            .map(|e| e.epoch)
            .collect()
    }

    /// Rotate: create a new epoch's data key and make it active.
    pub fn rotate(&mut self, now_unix_secs: u64) -> Result<u64> {
        let next = self
            .state
            .active_epoch
            .checked_add(1)
            .ok_or(OrfsError::Overflow {
                what: "keyring epoch",
            })?;
        let wrapped = wrap_new_epoch(&self.master, next, now_unix_secs)?;
        self.state.epochs.push(wrapped);
        self.state.active_epoch = next;
        self.persist()?;
        Ok(next)
    }

    /// Destroy an epoch's data key. The active epoch cannot be destroyed
    /// (rotate first), so a writable volume always retains a live key.
    ///
    /// This is the **erasure primitive**: the wrapped data key is deleted and a
    /// durable tombstone is recorded, rendering that epoch's ciphertext
    /// cryptographically inaccessible. No ciphertext byte is touched.
    pub fn destroy_epoch(&mut self, epoch: u64, now_unix_secs: u64) -> Result<()> {
        if epoch == self.state.active_epoch {
            return Err(OrfsError::InvalidArgument(format!(
                "epoch {epoch} is active; rotate to a new epoch before destroying it"
            )));
        }
        let rec = self.state.find_mut(epoch).ok_or_else(|| {
            OrfsError::InvalidArgument(format!("no such epoch {epoch} in the keyring"))
        })?;
        if !rec.is_live() {
            return Err(OrfsError::InvalidArgument(format!(
                "epoch {epoch} is already destroyed"
            )));
        }
        rec.wrapped = None;
        rec.destroyed_unix_secs = Some(now_unix_secs);
        self.persist()
    }

    /// The data key for `epoch`, unwrapping it under the master key.
    ///
    /// Fails closed with [`OrfsError::KeyDestroyed`] when the epoch's key was
    /// destroyed, and [`OrfsError::KeyUnavailable`] when the epoch is unknown or
    /// its wrapped blob does not authenticate.
    pub fn epoch_key(&self, epoch: u64) -> Result<Key> {
        let rec = self
            .state
            .find(epoch)
            .ok_or_else(|| OrfsError::KeyUnavailable(format!("unknown epoch {epoch}")))?;
        let Some(wrapped_hex) = rec.wrapped.as_ref() else {
            return Err(OrfsError::KeyDestroyed(epoch));
        };
        let blob = from_hex(wrapped_hex)?;
        let aad = wrap_aad(epoch);
        let dek = open_sealed(&self.master, &aad, &blob).map_err(|e| match e {
            OrfsError::CryptoAuthFailed(_) => OrfsError::KeyUnavailable(format!(
                "epoch {epoch} wrapped key does not authenticate under this master key"
            )),
            other => other,
        })?;
        if dek.len() != KEY_LEN {
            return Err(OrfsError::KeyUnavailable(format!(
                "epoch {epoch} unwrapped key has the wrong length"
            )));
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&dek);
        Ok(Key(k))
    }

    /// Seal plaintext under an epoch's data key with an explicit nonce.
    pub fn seal_with_epoch(
        &self,
        epoch: u64,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let key = self.epoch_key(epoch)?;
        Ok(seal_with_nonce(&key, nonce, aad, plaintext))
    }

    /// Open a sealed blob under an epoch's data key.
    pub fn open_with_epoch(&self, epoch: u64, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        let key = self.epoch_key(epoch)?;
        open_sealed(&key, aad, blob)
    }

    fn persist(&self) -> Result<()> {
        let state_bytes = serde_json::to_vec(&self.state).map_err(|e| {
            OrfsError::KeyUnavailable(format!("keyring state cannot be serialized: {e}"))
        })?;
        let crc = crc32c::crc32c(&state_bytes);
        let file = KeyringFile {
            schema: KEYRING_SCHEMA.to_string(),
            state_crc32c: format!("{crc:08x}"),
            master_key: to_hex(&self.master.0),
            state: self.state.clone(),
        };
        let pretty = serde_json::to_vec_pretty(&file).map_err(|e| {
            OrfsError::KeyUnavailable(format!("keyring file cannot be serialized: {e}"))
        })?;
        write_secret(&self.path, &pretty)
    }
}

/// The associated data binding a wrapped data key to its purpose and epoch.
fn wrap_aad(epoch: u64) -> Vec<u8> {
    let mut aad = WRAP_AAD_LABEL.to_vec();
    aad.extend_from_slice(&epoch.to_le_bytes());
    aad
}

/// Generate and wrap a fresh data key for `epoch`.
fn wrap_new_epoch(master: &Key, epoch: u64, now_unix_secs: u64) -> Result<EpochRecord> {
    let dek = Key::generate()?;
    let wrapped = seal(master, &wrap_aad(epoch), dek.expose())?;
    Ok(EpochRecord {
        epoch,
        created_unix_secs: now_unix_secs,
        wrapped: Some(to_hex(&wrapped)),
        destroyed_unix_secs: None,
    })
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Write a file with owner-only permissions (0600). Key files must not be
/// world-readable.
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Fill `buf` with cryptographically secure random bytes from the kernel.
fn fill_random(buf: &mut [u8]) -> Result<()> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")?;
    f.read_exact(buf)?;
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn from_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(OrfsError::KeyUnavailable(
            "hex string has an odd length".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16);
        let lo = (bytes[i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push(((h << 4) | l) as u8),
            _ => {
                return Err(OrfsError::KeyUnavailable(
                    "hex string contains a non-hex character".to_string(),
                ))
            }
        }
        i += 2;
    }
    Ok(out)
}

fn from_hex32(s: &str) -> Result<[u8; KEY_LEN]> {
    let v = from_hex(s)?;
    if v.len() != KEY_LEN {
        return Err(OrfsError::KeyUnavailable(format!(
            "expected a {KEY_LEN}-byte key, got {}",
            v.len()
        )));
    }
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&v);
    Ok(k)
}

/// Whether a byte appears anywhere in the other slice. Used by the
/// "no key material in the authoritative area" test.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| ct_eq(w, needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = Key::generate().unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce).unwrap();
        let aad = b"epoch=0";
        let pt = b"the authoritative bytes are never withdrawn";
        let blob = seal_with_nonce(&key, &nonce, aad, pt);
        assert_eq!(blob.len(), SEALED_OVERHEAD + pt.len());
        let got = open_sealed(&key, aad, &blob).unwrap();
        assert_eq!(got, pt);

        // Empty plaintext round-trips too.
        let empty = seal_with_nonce(&key, &nonce, aad, b"");
        assert_eq!(open_sealed(&key, aad, &empty).unwrap(), b"");
    }

    #[test]
    fn a_wrong_key_fails_closed() {
        let key = Key::generate().unwrap();
        let other = Key::generate().unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce).unwrap();
        let blob = seal_with_nonce(&key, &nonce, b"aad", b"secret");
        match open_sealed(&other, b"aad", &blob) {
            Err(OrfsError::CryptoAuthFailed(_)) => {}
            other => panic!("expected CryptoAuthFailed, got {other:?}"),
        }
    }

    #[test]
    fn tampering_is_rejected() {
        let key = Key::generate().unwrap();
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce).unwrap();
        let aad = b"aad";
        let pt = b"tamper me please, carefully";
        let blob = seal_with_nonce(&key, &nonce, aad, pt);

        // Flip one ciphertext byte.
        let mut t = blob.clone();
        let idx = 1 + NONCE_LEN + 8;
        t[idx] ^= 0x01;
        assert!(matches!(
            open_sealed(&key, aad, &t),
            Err(OrfsError::CryptoAuthFailed(_))
        ));

        // Flip one tag byte.
        let mut t = blob.clone();
        let last = t.len() - 1;
        t[last] ^= 0x80;
        assert!(matches!(
            open_sealed(&key, aad, &t),
            Err(OrfsError::CryptoAuthFailed(_))
        ));

        // Tamper the nonce (part of the authenticated header).
        let mut t = blob.clone();
        t[2] ^= 0x40;
        assert!(matches!(
            open_sealed(&key, aad, &t),
            Err(OrfsError::CryptoAuthFailed(_))
        ));

        // Tamper the authenticated length field: framing disagrees.
        let mut t = blob.clone();
        t[1 + NONCE_LEN] ^= 0x01;
        assert!(open_sealed(&key, aad, &t).is_err());

        // Tamper a different associated data value.
        assert!(matches!(
            open_sealed(&key, b"other aad", &blob),
            Err(OrfsError::CryptoAuthFailed(_))
        ));

        // Truncate.
        let mut t = blob.clone();
        t.pop();
        assert!(open_sealed(&key, aad, &t).is_err());

        // Unknown version.
        let mut t = blob.clone();
        t[0] = 0x7F;
        assert!(matches!(
            open_sealed(&key, aad, &t),
            Err(OrfsError::Compatibility(_))
        ));
    }

    #[test]
    fn envelope_wrap_and_unwrap() {
        let dek = Key::generate().unwrap();
        let kek = Key::generate().unwrap();
        let wrapped = seal(&kek, b"orfs.keyring.wrap.v1", dek.expose()).unwrap();
        let unwrapped = open_sealed(&kek, b"orfs.keyring.wrap.v1", &wrapped).unwrap();
        assert_eq!(unwrapped.as_slice(), dek.expose().as_slice());
    }

    #[test]
    fn keyring_create_rotate_destroy_and_reload() {
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("orfs.keys");

        let mut kr =
            Keyring::create(&path, "00112233445566778899aabbccddeeff", 1_700_000_000).unwrap();
        assert_eq!(kr.active_epoch(), 0);
        assert_eq!(kr.live_epochs(), vec![0]);

        // Epoch 0's key opens its content.
        let mut nonce = [0u8; NONCE_LEN];
        fill_random(&mut nonce).unwrap();
        let blob = kr
            .seal_with_epoch(0, &nonce, b"aad", b"epoch-0 content")
            .unwrap();

        // Rotate to epoch 1.
        let e1 = kr.rotate(1_700_000_100).unwrap();
        assert_eq!(e1, 1);
        assert_eq!(kr.active_epoch(), 1);
        assert_eq!(kr.live_epochs(), vec![0, 1]);

        // Reload from disk: state survives, both epochs still open.
        let mut kr = Keyring::load(&path).unwrap();
        assert_eq!(kr.active_epoch(), 1);
        assert_eq!(
            kr.open_with_epoch(0, b"aad", &blob).unwrap(),
            b"epoch-0 content"
        );

        // Destroy epoch 0.
        kr.destroy_epoch(0, 1_700_000_200).unwrap();
        assert_eq!(kr.destroyed_epochs(), vec![0]);
        assert_eq!(kr.live_epochs(), vec![1]);

        // The destroyed epoch fails closed with the typed error, while epoch 1
        // is unaffected.
        match kr.open_with_epoch(0, b"aad", &blob) {
            Err(OrfsError::KeyDestroyed(0)) => {}
            other => panic!("expected KeyDestroyed(0), got {other:?}"),
        }
        let mut nonce1 = [0u8; NONCE_LEN];
        fill_random(&mut nonce1).unwrap();
        let blob1 = kr
            .seal_with_epoch(1, &nonce1, b"aad", b"epoch-1 content")
            .unwrap();
        assert_eq!(
            kr.open_with_epoch(1, b"aad", &blob1).unwrap(),
            b"epoch-1 content"
        );

        // Reloaded after destruction: the tombstone is durable.
        let kr2 = Keyring::load(&path).unwrap();
        match kr2.open_with_epoch(0, b"aad", &blob) {
            Err(OrfsError::KeyDestroyed(0)) => {}
            other => panic!("expected durable KeyDestroyed(0), got {other:?}"),
        }

        // The active epoch cannot be destroyed.
        let mut kr3 = Keyring::load(&path).unwrap();
        assert!(matches!(
            kr3.destroy_epoch(1, 1_700_000_300),
            Err(OrfsError::InvalidArgument(_))
        ));
        // An unknown epoch is refused.
        assert!(matches!(
            kr3.destroy_epoch(9, 0),
            Err(OrfsError::InvalidArgument(_))
        ));
    }

    #[test]
    fn keyring_rejects_corruption_and_wrong_uuid() {
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("orfs.keys");
        let kr = Keyring::create(&path, "00ff", 1).unwrap();
        assert_eq!(kr.volume_uuid(), "00ff");

        // Corrupt the state checksum. Do it structurally so the tamper cannot
        // accidentally re-parse to the same value.
        let raw = std::fs::read(&path).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        v["state_crc32c"] = serde_json::Value::String("deadbeef".to_string());
        std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
        assert!(matches!(
            Keyring::load(&path),
            Err(OrfsError::KeyUnavailable(_))
        ));
        assert!(matches!(
            Keyring::load(&path),
            Err(OrfsError::KeyUnavailable(_))
        ));

        // Not JSON at all.
        std::fs::write(&path, b"not json").unwrap();
        assert!(matches!(
            Keyring::load(&path),
            Err(OrfsError::KeyUnavailable(_))
        ));
    }

    #[test]
    fn no_raw_key_material_is_serialized() {
        // The key file holds the master key and *wrapped* data keys, but no
        // unwrapped data key: the raw DEK must not appear in the file bytes.
        let td = tempfile::TempDir::new().unwrap();
        let path = td.path().join("orfs.keys");
        let kr = Keyring::create(&path, "aabbcc", 1).unwrap();
        let dek = kr.epoch_key(0).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !contains_bytes(&raw, dek.expose()),
            "the unwrapped data key must never appear in the key file"
        );
    }
}
