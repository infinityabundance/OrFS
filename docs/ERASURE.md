# OrFS — Crypto-erasure design (Phase 85)

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
store), `tests/crypto_erasure.rs` (the court),
`evidence/security/crypto-erasure.json` (the receipt),
`scripts/container-crypto-erasure.sh` (the runner). The unencrypted path is
unchanged (`docs/MIGRATION.md` §6).

> **What is wired, stated plainly.** The encrypted volume's **create / open /
> append / read / rotate / destroy / verify / ciphertext-relocate** are all wired
> and tested end to end through the real `orfs` binary. **Mounting** an encrypted
> volume through FUSE is **not wired**: `orfs mount` on a directory that carries
> `crypto.meta` refuses with a typed `Unsupported` error rather than mounting a
> plaintext projection. §6 says exactly why and what the gap is.

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
| **Anyone who later reads the backing store** (a stolen disk, a leaked backup, a curious operator without the key) | Content is AEAD-sealed under an epoch data key held in the operator's key file; the ciphertext alone is not enough. |
| **A holder of the key file, *after* an epoch is destroyed** | The destroyed epoch's data key is a **random** key that was *wrapped* under the master key. Deleting the wrapped blob removes the only copy; even the master key cannot regenerate it (§4). |
| **An attacker who tampers with the stored bytes** | Every frame is authenticated (encrypt-then-MAC); a tampered ciphertext, nonce, length, or AAD is rejected with a typed `CryptoAuthFailed` — never a wrong plaintext. |
| **An operator mistake, and any silent-loss path** | A missing or destroyed key is a **typed, fail-closed** error; OrFS never fabricates plaintext and never silently shrinks a volume. |

**Not protected against (out of scope, stated honestly):**

* **A compromised kernel, or an attacker with the key file *before* destruction.**
  Holding a live epoch key opens that epoch's content; holding the master key and
  a live wrapped blob opens it too. Key custody is the operator's job.
* **Traffic/temporal metadata.** The ciphertext's existence, its length, the
  number of frames and epochs, the volume UUID and segment size (`crypto.meta`),
  and the commit watermark are **plaintext**. The mechanism hides *content*, not
  *shape*.
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
     │  wraps with an AEAD
     ├── epoch 0 data key (DEK, 32 bytes, random)   wrapped blob in the keyring state
     ├── epoch 1 data key (DEK, 32 bytes, random)   wrapped blob in the keyring state
     └── epoch n data key …
```

* **The master key never leaves the key file** and is **never** written into a
  volume. It wraps each epoch's data key.
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
The AEAD is therefore built from BLAKE3's **keyed mode** (a pseudorandom function)
in a textbook **encrypt-then-MAC** composition:

```text
   enc_key, mac_key  = BLAKE3_keyed(data_key, distinct domain labels)
   keystream[i]      = BLAKE3_keyed(enc_key, "orfs.aead.stream.v1" ‖ nonce ‖ le64(i))
   ct                = plaintext XOR keystream               (counter-mode stream)
   tag               = BLAKE3_keyed(mac_key, "orfs.aead.tag.v1" ‖ header ‖ aad ‖ ct)
   SEALED            = version(1) ‖ nonce(24) ‖ le64(len) ‖ ct ‖ tag(32)
```

* The **header** (version byte, nonce, and the length field) is covered by the
  tag, so **no byte of the sealed encoding is unauthenticated**, and the length
  cannot be used as a truncation oracle (the framing must agree exactly).
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
  the master key, and makes it **active**; subsequent appends are sealed under it.
  Existing ciphertext stays under its old epoch key, unchanged.
* **Destruction** (`orfs key destroy --epoch <n>`) deletes epoch *n*'s wrapped
  data key and records a durable tombstone. It refuses to destroy the **active**
  epoch (rotate first), so a writable volume always retains a live key for new
  writes.
* **Effect.** Any frame sealed under epoch *n* — the sealed genesis, a data frame,
  or a **relocated tier copy of the same ciphertext** — now returns a typed
  [`OrfsError::KeyDestroyed`] and **no plaintext**. The bytes are untouched.

The erasure is therefore *explicit* (an operator command), *durable* (persisted to
the key file before it takes effect), *typed* (a `KeyDestroyed`/`KeyUnavailable`
errno, `ENOKEY`), and *non-fabricating*.

## 5. Wire format of an encrypted volume

An encrypted volume is a **distinct volume kind**; it carries `crypto.meta` and no
`volume.meta`. This is a **new, separately versioned** format — the unencrypted
`or.log` format is untouched (`docs/MIGRATION.md` §6).

```text
   <volume>/crypto.meta       plaintext identity: schema + CRC32C, uuid, segment
                              size, created-at, crypto_format_version. NO key bytes.
   <volume>/or.log/NNNN…seg   the sealed authoritative store (all ciphertext)
   <operator>/<key-file>      master key + wrapped epoch keys (never in the volume)

   FRAME  := MAGIC(4) ‖ FRAME_VERSION(2) ‖ epoch(8) ‖ SEALED
   SEALED := version(1) ‖ nonce(24) ‖ le64(ct_len) ‖ ct(ct_len) ‖ tag(32)
```

* The frame's AAD is its fixed header `MAGIC ‖ FRAME_VERSION ‖ epoch`, so the
  **epoch binding is authenticated** and an epoch swap is rejected.
* The **nonce is deterministic** per `(epoch, frame ordinal)`: frames are
  append-only and never rewritten, so an ordinal is never reused within its epoch
  key (which is what makes a deterministic nonce safe here, and makes the
  ciphertext reproducible for testing).
* The sealed store is written through the **existing `Segment` I/O seam**
  (`Segment::append` / `write_at` / `read_exact_at`), so it uses the same segment
  file layout the authoritative log uses — the bytes are simply ciphertext.
* A framed maximum is bounded with **checked arithmetic** at every step; the
  store refuses a trailing partial frame rather than guessing.

The court's dedicated encrypted volume holds **3 sealed frames** (the sealed
genesis frame, one epoch-0 frame, one epoch-1 frame) comprising **335 bytes** of
authoritative ciphertext; after destroying epoch 0 the digest of those 335 bytes
is **identical** before and after (`evidence/security/crypto-erasure.json`).

## 6. Integration points — and exactly what is wired

| Integration point | Status |
|---|---|
| **`Segment` I/O seam** (`src/segment.rs`) | **Wired.** The sealed store appends frames through `Segment::append` and reads through `read_exact_at`. |
| **Keyring state** | **Wired.** `src/keyring.rs` stores the master key + wrapped epoch keys at the operator path; key material never enters the volume. |
| **Epoch rotation / destruction** | **Wired.** `orfs key rotate`, `orfs key destroy --epoch <n>`. |
| **`verify` / `recover` on an encrypted volume** | **Wired, honest.** Both **require** `--key-file` and refuse with a typed `KeyUnavailable` when it is absent; `crypt verify` reports which frames open and which epochs were destroyed. |
| **Tier relocation** | **Wired.** `orfs crypt relocate` copies the **ciphertext** verbatim to `--tier-root` and records its BLAKE3 digest. Because the copy is byte-identical ciphertext, destroying the epoch key covers the tier copy too — proven by the court. |
| **Mount** (`orfs mount`) | **NOT wired.** An encrypted volume is not served through FUSE. |
| **`watermark` / manifests / namespace read path** | **NOT wired** for encrypted volumes: the sealed store has no plaintext record stream for the namespace/index to interpret. |

**Why mount is not wired, precisely.** The unencrypted engine equates a record's
**logical** offset with its **physical** offset inside a segment (segment id ==
first logical offset). Sealing inserts per-frame overhead, so those offsets
diverge; resolving an encrypted volume through the namespace/read/planner path
therefore requires the whole read path to resolve through the sealed store's
frame map. That is a separate, well-scoped phase. Rather than ship a
half-integration, `orfs mount` on an encrypted volume **fails with a typed error**
and this document says so.

## 7. Failure modes

* **Lost key = permanent inaccessibility.** A key file that is lost (or a master
  key destroyed) makes every epoch permanently unreadable — by design and
  without a backdoor. This is the deliberate counterpart of crypto-erasure and
  must be handled by the operator's key custody.
* **Destroyed key = intentional, irreversible inaccessibility.** `orfs key
  destroy` is explicit, durable and irreversible; recovery never reconstructs it
  (`orfs recover` on an encrypted volume never fabricates plaintext).
* **Never silent data loss.** A missing/destroyed key produces a typed, fail-closed
  error (`KeyUnavailable`/`KeyDestroyed`, `ENOKEY`); a tampered frame produces
  `CryptoAuthFailed` (`EBADMSG`); neither is ever a wrong or partial plaintext,
  and neither silently shortens or rewrites the store.
* **Non-withdrawal of ciphertext.** Key destruction rewrites **no** byte. The
  court asserts the store's byte content and BLAKE3 digest are identical before
  and after destruction, and that the relocated tier copy is likewise unchanged.

## 8. Honest limits

1. **Key management is out of scope.** Custody, backup, escrow, rotation policy
   and the legal adequacy of key destruction are the operator's; OrFS supplies a
   mechanism and an error type.
2. **Metadata leaks.** `crypto.meta` (uuid, segment size, versions), the frame
   count and per-frame epoch/offsets, and the commit watermark are plaintext. The
   mechanism hides content, not shape or timing.
3. **The AEAD is a construction, not a standardised primitive** (§3): real and
   standard, but a swap to XChaCha20-Poly1305 is named as the hardening step.
4. **Key material is not `mlock`ed or explicitly zeroised on drop.** It lives in
   process memory while a volume is open; a core dump or a memory compromise could
   expose a *live* key. This is stated, not implied to be handled.
5. **The sealed store uses a single segment** in this phase; the segment-size
   policy is recorded but not yet exercised for the encrypted store (the
   unencrypted log's rollover is unchanged).
6. **No mount, no namespace, no in-FUSE reads** for an encrypted volume (§6).
7. **The encrypted volume has no capacity guard / reserve**: `orfs init
   --key-file` does not accept the plaintext `--reserve` policy.

## 9. Evidence and how to run it

* The court: `tests/crypto_erasure.rs` (an always-on smoke + an opt-in sweep that
  drives the **real `orfs` binary**: `init --key-file` → `crypt append` →
  `crypt read` → `key rotate` → `key destroy` → `crypt verify` → `crypt digest`
  → `crypt relocate`, plus the tamper, wrong-key, no-key, no-key-material and
  default-path checks).
* The runner: `scripts/container-crypto-erasure.sh` (bounded smoke + opt-in
  release sweep, one container at a time).
* The receipt: `evidence/security/crypto-erasure.json`, schema
  `orfs.security.crypto-erasure.v1`, whose `properties` object records each
  demonstrated property (`round_trip_with_correct_key`,
  `key_correct_read_identical`, `tamper_rejected_aead`,
  `epoch_destruction_makes_content_inaccessible`,
  `ciphertext_bytes_retained_unchanged`, `relocated_ciphertext_unchanged`,
  `crypto_erasure_covers_relocated_tier_copy`, `verify_without_key_refused`,
  `recover_without_key_refused`, `wrong_key_refused`,
  `mount_of_encrypted_volume_refused_honestly`,
  `no_key_material_in_authoritative_area`, `default_path_unchanged`), each
  asserted `true` by the court before it writes the file.

```sh
sh scripts/container-crypto-erasure.sh                 # smoke + sweep (writes the receipt)
ORFS_CRYPTO_ERASURE=0 sh scripts/container-crypto-erasure.sh   # smoke only
```

Operational surface:

```sh
orfs init <dir> --key-file <path>          # create an encrypted volume
orfs crypt append <dir> --key-file <p> --text <s>   # seal a frame
orfs crypt read   <dir> --key-file <p> --offset <n> # open a frame (fail-closed)
orfs crypt list|verify|digest <dir> --key-file <p>
orfs crypt relocate <dir> --key-file <p> --tier-root <root>
orfs key status|rotate <dir> --key-file <p>
orfs key destroy  <dir> --key-file <p> --epoch <n>
orfs verify  <dir> --key-file <p>          # encrypted verification (key required)
orfs recover <dir> --key-file <p>          # read-only, never fabricates plaintext
```

[`OrfsError::KeyDestroyed`]: ../src/error.rs
