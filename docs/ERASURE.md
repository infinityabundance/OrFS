# OrFS — Crypto-erasure design (Phase 85; length-preserving seal and FUSE mount in Phase 86)

This is the design of the **opt-in cryptographic erasure mechanism**: a key
hierarchy, envelope encryption, epoch rotation, and **key destruction as the
erasure primitive** — such that destroying an epoch key renders that epoch's
content cryptographically inaccessible **while the authoritative ciphertext bytes
remain, unwithdrawn**.

It is the mechanism behind the secure-delete position stated in
`docs/RETENTION.md` §3: non-withdrawal forbids erasing committed **plaintext**
history, so the only defensible "delete" story on top of it is to destroy the
**key** that makes the retained ciphertext readable.

Companion: `src/keyring.rs` (the key lifecycle), `src/encvol.rs` (the encrypted
store and its seal), `tests/crypto_erasure.rs` (the offline court),
`tests/crypto_erasure_mounted.rs` (the mounted court),
`evidence/security/crypto-erasure.json`,
`evidence/security/crypto-erasure-mounted.json` (the receipts),
`scripts/container-crypto-erasure.sh` and
`scripts/container-crypto-erasure-mounted.sh` (the runners). The unencrypted path
is unchanged (`docs/MIGRATION.md` §6).

> **What is wired, stated plainly.** The encrypted volume's **create / verify /
> rotate / destroy / ciphertext-relocate** and, since Phase 86, its **mount**
> (`orfs mount --key-file`) are wired and tested end to end through the real
> `orfs` binary. Because the seal is **length preserving** (§5), the encrypted
> store *is* a real OrFS log and is served through the ordinary
> namespace/index/FUSE path; there is **no plaintext projection** and no separate
> frame-oriented read path. The remaining honest limits are §8.

---

## 1. The problem, and the position

OrFS retains committed history by construction (`docs/RETENTION.md` §1). If an
operator needs content to become *unrecoverable*, the filesystem cannot overwrite
or truncate the bytes that carry it without breaking Law I
(`L_{n+1} = L_n ⊕ Δ_n`). The only lever that does not withdraw a byte is
**cryptography**: store the content under a key, and later destroy the key.

> **Crypto-erasure is a key-lifecycle layer over non-withdrawal. It is never a
> reason to overwrite, truncate, or withdraw an authoritative byte.**

## 2. Threat model and adversaries

**Protected against:**

| Adversary | Why the mechanism defends |
|---|---|
| **Anyone who later reads the backing store** (a stolen disk, a leaked backup, a curious operator without the key) | The authoritative segment bytes are a keystream ciphertext under an epoch data key held in the operator's key file; the ciphertext alone is not enough. |
| **A holder of the key file, *after* an epoch is destroyed** | The destroyed epoch's data key is a **random** key that was *wrapped* under the master key. Deleting the wrapped blob removes the only copy; even the master key cannot regenerate it (§4). |
| **An attacker who tampers with the stored bytes** | Each segment is authenticated by a keyed-BLAKE3 **MAC** over its ciphertext, held in a master-key-sealed table; a tampered segment is rejected at open/scan with a typed `CryptoAuthFailed` — never a wrong plaintext. |
| **An operator mistake, and any silent-loss path** | A missing or destroyed key is a **typed, fail-closed** error; OrFS never fabricates plaintext and never silently shrinks a volume. |

**Not protected against (out of scope, stated honestly):**

* **A compromised kernel, or an attacker with the key file *before* destruction.**
  Holding a live epoch key opens that epoch's content; holding the master key and
  a live wrapped blob opens it too. Key custody is the operator's job.
* **Traffic/temporal metadata.** The ciphertext's existence and length, the
  number of segments and epochs, the volume UUID and segment size (`crypto.meta`),
  the existence of the sealed authentication table, and the plaintext **derived**
  `index/` accelerators are **not** sealed. The mechanism hides authoritative
  *content*, not all *shape* or *timing*.
* **Key management itself.** Backup, rotation policy, custody, HSM/escrow,
  access to the key file, and whether key destruction satisfies a specific legal
  standard are **outside the filesystem**. OrFS supplies a mechanism and a typed
  error, not a key-management service.
* **Rollback by a privileged attacker.** A principal who can replace the whole
  backing store can substitute an older ciphertext (or an older key file). The
  content authenticates *as the content OrFS wrote under that key*, not as the
  newest state; freshness is not proven by this layer.

## 3. Key hierarchy and envelope encryption

```text
   master key (KEK, 32 bytes)                    in the operator's key file (0600)
     │  wraps epoch data keys (AEAD) and seals the per-segment table
     ├── epoch 0 data key (DEK, 32 bytes, random)   wrapped blob in the keyring state
     ├── epoch 1 data key (DEK, 32 bytes, random)   wrapped blob in the keyring state
     └── epoch n data key …
```

* **The master key never leaves the key file** and is **never** written into a
  volume. It wraps each epoch's data key and seals the per-segment authentication
  table (§5).
* **Each epoch has an independent, freshly generated random data key.** It is
  *wrapped* under the master key (envelope encryption) and the wrapped blob is
  stored in the keyring **state**, which lives at the operator-supplied key path.
* A **data key is random, not derived** from the master key. That is what makes
  destruction real: deleting the wrapped blob destroys the only copy. (If the
  epoch key were derived from the master key, destruction would be a lie — the
  master key could regenerate it.)

### The AEAD

The crate depends on `blake3` (a vetted cryptographic hash) and deliberately adds
**no second crypto dependency** in a network-isolated, `Cargo.lock`-frozen build.
Two independent constructions are built from BLAKE3:

1. **A blob AEAD** (used for the sealed metadata table and for wrapping epoch
   keys), a textbook **encrypt-then-MAC** composition with a random nonce:

   ```text
      enc_key, mac_key  = BLAKE3_keyed(data_key, distinct domain labels)
      keystream[i]      = BLAKE3_keyed(enc_key, "orfs.aead.stream.v1" ‖ nonce ‖ le64(i))
      ct                = plaintext XOR keystream               (counter-mode stream)
      tag               = BLAKE3_keyed(mac_key, "orfs.aead.tag.v1" ‖ header ‖ aad ‖ ct)
      SEALED            = version(1) ‖ nonce(24) ‖ le64(len) ‖ ct ‖ tag(32)
   ```

2. **A positional keystream + per-segment MAC** for the authoritative store
   itself (§5), which is *length preserving* and *random access*.

* The **header** (version byte, nonce, and the length field) is covered by the
  blob AEAD's tag, so **no byte of the sealed encoding is unauthenticated**, and
  the length cannot be used as a truncation oracle (the framing must agree
  exactly).
* The tag comparison is constant-time; a mismatch is a typed `CryptoAuthFailed`,
  never a partial plaintext.
* **Honest limit:** this is a real, standard construction over a vetted primitive,
  but it is **not a standardised AEAD** such as XChaCha20-Poly1305. Adding
  `chacha20poly1305` (RustCrypto) is the intended swap-in: `seal_with_nonce` /
  `open_sealed` in `src/keyring.rs` are the only functions to change, and the
  domain-separation labels already isolate the construction. This is stated as a
  limitation, not hidden.

## 4. Epoch rotation and key destruction as the erasure primitive

* **Rotation** (`orfs key rotate`) generates a new epoch data key, wraps it under
  the master key, and makes it **active**; it then **forces a segment rollover**,
  so subsequent writes are sealed under the new epoch while every existing
  segment keeps the epoch it was created with. Existing ciphertext is unchanged.
* **Destruction** (`orfs key destroy --epoch <n>`) deletes epoch *n*'s wrapped
  data key and records a durable tombstone. It refuses to destroy the **active**
  epoch (rotate first), so a writable volume always retains a live key for new
  writes.
* **Effect.** Any segment bound to epoch *n* — the sealed genesis segment, a data
  segment, or a **relocated tier copy** of the same ciphertext — now returns a
  typed [`OrfsError::KeyDestroyed`] and **no plaintext**. The bytes are untouched.

The erasure is therefore *explicit* (an operator command), *durable* (persisted to
the key file before it takes effect), *typed* (a `KeyDestroyed`/`KeyUnavailable`
errno, `ENOKEY`), and *non-fabricating*.

Because the authoritative store is a **linear** record stream, a segment bound to
a destroyed epoch cannot be scanned past: destroying an epoch key makes the
**whole volume** fail closed on open. `orfs crypt verify` still reports the
store's intended state (which segment is inaccessible, and why). See §8.

## 5. The length-preserving per-segment seal

Phase 85 sealed the store in **frames** (seal-then-length-prefix), which inserted
per-frame overhead: a record's **logical** offset no longer equalled its
**physical** offset inside a segment, so the namespace/scan/watermark path could
not resolve an encrypted volume and `orfs mount` refused. Phase 86 removes that
obstruction with an **offset-preserving** seal:

```text
   ciphertext[i] = plaintext[i] XOR stream(key(epoch), segment_id, i)

   stream(key, id, p) = BLAKE3_keyed(enc_subkey(key),
                          "orfs.seal.pos.v1" ‖ le64(id) ‖ le64(p / 512))[p % 512]
```

* **Random access.** The keystream byte at position `p` depends only on
  `(key, segment_id, p)`, so transforming an arbitrary `[start, start+len)`
  window on its own is byte-identical to transforming the whole segment at once.
* **Length preserving.** The ciphertext of a segment is exactly as long as its
  plaintext, so **every** offset computation above the `Segment` seam (the
  `SegmentLocator`, `scan_log`, the commit watermark, tiering, the
  namespace/index, FUSE) is **unchanged** and works on an encrypted volume
  exactly as it does on an unencrypted one. This is what makes `orfs
  mount --key-file` possible.
* The keystream is applied in `write_at` (seal) and `read_exact_at` (unseal) at
  the existing `Segment`/`ReadAt` boundary; the segment id is the keystream
  domain, so no two segments ever share a stream.

### Integrity without spending a ciphertext byte

Because the data area must stay length preserving, integrity is provided *outside*
it:

```text
   mac(segment id) = BLAKE3_keyed(mac_subkey(key(epoch)),
                        "orfs.seal.segment-tag.v1" ‖ le64(id) ‖ ciphertext[..len] ‖ le64(len))
```

* This **per-segment MAC** is recorded in a **sealed authentication table**
  (`crypto.segments`) in the volume's **metadata tier**, sealed under the **master
  key** (`Keyring::seal_meta`). It is unreadable without the key file, carries no
  key material, and is never written into the authoritative data area or the log's
  framing.
* It binds each segment to the **epoch** that seals it — which is exactly what
  makes an epoch-key destruction render that segment's content inaccessible.
* The authenticated prefix (`len`) is folded in **last**, so the MAC can be
  computed incrementally as a segment is appended and finalised cheaply at the
  durability point.

### What tamper is detected, and **when**

* **At open/scan, for every segment.** Opening a volume (and every scan of it,
  including the one inside `orfs mount --key-file` and `orfs crypt verify`)
  verifies each segment's MAC against the bytes on disk. A flip inside the
  authenticated prefix, a destroyed epoch key, or an unrecorded segment is a
  typed, **fail-closed** error here — long before any byte is trusted.
* **Advanced at each `fsync`.** `Segment::sync`, after the data is durable, calls
  `seal_point`, which is the **only** point at which the store claims bytes are
  authenticated. `seal_point` refuses to **shrink** an authenticated prefix
  (committed bytes are never withdrawn) and uses the segment's **durable physical
  length**.
* **The un-fsynced tail is unauthenticated.** Bytes written but not yet fsynced
  lie beyond the authenticated prefix; the scan treats them exactly like an
  abandoned tail — retained, never decrypted, never trusted — and they are not
  covered by the MAC until the next durability point.
* **Not per-read.** A flipped byte inside an already-open, already-verified
  segment is not re-detected on each `read`; integrity is a boundary property
  (open/scan and durability), not a per-read one.

### Trade-offs vs per-frame sealing

| Property | Per-frame AEAD (Phase 85) | Length-preserving seal (Phase 86) |
|---|---|---|
| Ciphertext overhead | ~73 bytes/frame (version+nonce+len+tag) | **0** bytes |
| Logical == physical offset | **No** (frame framing diverges) | **Yes** |
| Resolvable by namespace/scan/FUSE | **No** | **Yes** (this is what makes mount possible) |
| Tamper detection granularity | **Per frame, per read** | **Per segment, at open/scan + durability** |
| Nonce discipline | Deterministic per `(epoch, frame ordinal)` | Positional `(key, segment id, block index)` |
| Un-fsynced tail | Each frame self-authenticating | Beyond the authenticated prefix (untrusted) |

The length-preserving seal trades *per-frame, per-read* tamper detection for a
**zero-overhead, offset-preserving** store that the whole engine can resolve
unchanged. Non-withdrawal is untouched either way: key destruction rewrites **no**
byte.

## 6. Wire format of an encrypted volume

An encrypted volume is a **distinct volume kind**; it carries `crypto.meta` and no
`volume.meta`. This is a **new, separately versioned** format — the unencrypted
`or.log` format is untouched (`docs/MIGRATION.md` §6).

```text
   <volume>/crypto.meta       plaintext identity (schema + CRC32C): uuid, segment
                              size, created-at, crypto_format_version. NO key bytes.
   <volume>/crypto.segments   the master-key-sealed per-segment authentication table
   <volume>/or.log/NNNN…seg   the real OrFS log, keystream-sealed per segment
                              (length preserving: ciphertext length == plaintext)
   <operator>/<key-file>      master key + wrapped epoch keys (never in the volume)
```

The court's dedicated encrypted volume holds **2 sealed segments** in its
authoritative store, together comprising **1249 bytes** of ciphertext; after
destroying epoch 0 the BLAKE3 digest of those bytes is **identical** before and
after (`evidence/security/crypto-erasure.json`).

## 7. Integration points — and exactly what is wired

| Integration point | Status |
|---|---|
| **`Segment` I/O seam** (`src/segment.rs`) | **Wired.** `write_at` seals, `read_exact_at` unseals, `sync` seals the authenticated prefix — all length preserving. |
| **`Log` / `scan` / watermark** (`src/log.rs`) | **Wired.** `Log::open_resolved_with_cipher` verifies each segment and stops at its authenticated length, so the committed log resolves identically. |
| **Keyring state** | **Wired.** `src/keyring.rs` stores the master key + wrapped epoch keys at the operator path; key material never enters the volume. |
| **Epoch rotation / destruction** | **Wired.** `orfs key rotate` (rotates **and** forces a rollover), `orfs key destroy --epoch <n>`. |
| **`verify` / `recover` on an encrypted volume** | **Wired, honest.** Both **require** `--key-file` and refuse with a typed `KeyUnavailable` when it is absent; `crypt verify` reports which segments authenticate and which epochs were destroyed. |
| **Tier relocation** | **Wired.** `orfs crypt relocate` copies the **ciphertext** verbatim to `--tier-root` and records its BLAKE3 digest. Because the copy is byte-identical ciphertext, destroying the epoch key covers the tier copy too — proven by both courts. |
| **Mount** (`orfs mount --key-file`) | **Wired (Phase 86).** `EncryptedVolume::open_volume` resolves the sealed store to the real `Volume`; the ordinary namespace/index/FUSE path serves it, and ordinary POSIX operations return byte-identical plaintext to an unencrypted volume (proven by `tests/crypto_erasure_mounted.rs`). Without the key, with the wrong key, or after epoch-key destruction the mount **fails closed** with a typed error. |
| **`Namespace::open_volume`** (`src/namespace.rs`) | **Wired.** The new entry point that mounts an already-opened `Volume` (the one the seal resolved). |

## 8. Failure modes and honest limits

* **Lost key = permanent inaccessibility.** A key file that is lost (or a master
  key destroyed) makes every epoch permanently unreadable — by design and without
  a backdoor. This is the deliberate counterpart of crypto-erasure and must be
  handled by the operator's key custody.
* **Destroyed key = intentional, irreversible inaccessibility.** `orfs key
  destroy` is explicit, durable and irreversible; recovery never reconstructs it
  (`orfs recover` on an encrypted volume never fabricates plaintext).
* **Never silent data loss.** A missing/destroyed key produces a typed,
  fail-closed error (`KeyUnavailable`/`KeyDestroyed`, `ENOKEY`); a tampered segment
  produces `CryptoAuthFailed` (`EBADMSG`); neither is ever a wrong or partial
  plaintext, and neither silently shortens or rewrites the store.
* **Non-withdrawal of ciphertext.** Key destruction rewrites **no** byte. Both
  courts assert the store's byte content and BLAKE3 digest are identical before
  and after destruction, and that the relocated tier copy is likewise unchanged.
* **A linear log makes erasure global.** Because the store is a linear record
  stream, an epoch whose segment is part of the log makes the **whole volume**
  fail closed on open once destroyed. Erasing one epoch while continuing to serve
  the rest is **not** supported; `orfs crypt verify` reports the state instead.
* **Key management is out of scope.** Custody, backup, escrow, rotation policy
  and the legal adequacy of key destruction are the operator's; OrFS supplies a
  mechanism and an error type.
* **Metadata leaks.** `crypto.meta` (uuid, segment size, versions), the existence
  of `crypto.segments`, and the plaintext **derived** `index/` accelerators are
  not sealed. The mechanism hides content, not all shape or timing.
* **The AEAD is a construction, not a standardised primitive** (§3): real and
  standard, but a swap to XChaCha20-Poly1305 is named as the hardening step.
* **Key material is not `mlock`ed or explicitly zeroised on drop.** It lives in
  process memory while a volume is open; a core dump or a memory compromise could
  expose a *live* key. This is stated, not implied to be handled.
* **No freshness.** A principal who can replace the whole backing store (or the
  key file) can substitute an older ciphertext; the content authenticates as
  *content OrFS wrote under that key*, not as the newest state.
* **Mounted coverage is bounded.** The mounted court runs one real-`orfs mount`
  workload per arm (create/write/append/rename/unlink/list/stat) plus rollover,
  relocation, destruction and the fail-closed cases. The dedicated POSIX suites
  (`scripts/container-posix-test.sh`) exercise the *unencrypted* mount; running
  pjdfstest against an encrypted mount is deferred (it needs the root-inode
  ownership/uid test scaffolding the encrypted arm does not yet wire).

## 9. Evidence and how to run it

* **Offline court:** `tests/crypto_erasure.rs` (an always-on smoke + an opt-in
  sweep that drives the **real `orfs` binary**: `init --key-file` → a namespace
  write **through the seal** → `key rotate` → `key destroy` → `crypt verify` /
  `crypt digest` / `crypt relocate`, plus the tamper, wrong-key, no-key,
  no-key-material and default-path checks).
* **Mounted court:** `tests/crypto_erasure_mounted.rs` (an opt-in real `orfs
  mount --key-file` arm: the same POSIX workload against an encrypted and an
  unencrypted volume, digest-compared; ciphertext on disk; rollover; relocation;
  epoch-key destruction; the fail-closed mounts; the default-path anchor).
* **Runners:** `scripts/container-crypto-erasure.sh` (offline bounded smoke +
  release sweep) and `scripts/container-crypto-erasure-mounted.sh` (bounded smoke
  + a real mount, one container at a time).
* **Receipts:** `evidence/security/crypto-erasure.json` (schema
  `orfs.security.crypto-erasure.v1`) and
  `evidence/security/crypto-erasure-mounted.json` (schema
  `orfs.security.crypto-erasure-mounted.v1`), each carrying a `properties` object
  the court asserts `true` before writing it — e.g.
  `ciphertext_round_trip_through_namespace`, `on_disk_segments_are_ciphertext`,
  `rotate_forces_rollover_multi_segment`, `destroyed_epoch_fails_closed_on_open`,
  `ciphertext_bytes_retained_unchanged`,
  `crypto_erasure_covers_relocated_tier_copy`, `mount_without_key_refused`,
  `mount_with_wrong_key_fails_closed`,
  `mount_after_destruction_fails_closed`,
  `mounted_byte_identity_plain_vs_encrypted`,
  `no_key_material_in_authoritative_area`, `default_path_unchanged`.

```sh
sh scripts/container-crypto-erasure.sh                 # offline smoke + sweep (writes the receipt)
sh scripts/container-crypto-erasure-mounted.sh         # real-mount court (writes the receipt)
ORFS_CRYPTO_ERASURE=0 sh scripts/container-crypto-erasure.sh          # offline smoke only
ORFS_CRYPTO_ERASURE_MOUNTED=0 sh scripts/container-crypto-erasure-mounted.sh  # compile smoke only
```

Operational surface:

```sh
orfs init  <dir> --key-file <path>         # create an encrypted volume (honours --reserve)
orfs mount <dir> <mnt> --key-file <path>   # serve it through FUSE (fail-closed on any key problem)
orfs crypt status|list|verify|digest <dir> --key-file <p>
orfs crypt relocate <dir> --key-file <p> --tier-root <root>
orfs key status|rotate <dir> --key-file <p>
orfs key destroy  <dir> --key-file <p> --epoch <n>
orfs verify  <dir> --key-file <p>          # encrypted verification (key required)
orfs recover <dir> --key-file <p>          # read-only, never fabricates plaintext
```

[`OrfsError::KeyDestroyed`]: ../src/error.rs
