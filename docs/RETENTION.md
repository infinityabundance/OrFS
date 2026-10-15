# OrFS — Retention and access-control contract (Phase 85)

This document is the **precise, referable retention and access-control contract**
for an OrFS volume. It states what `unlink`/`rmdir`/`truncate`/overwrite actually
do to logical versus physical state, **who may mount, read, write, relocate, and
administer** a volume and what the mount options and the operating-system access
model do and do **not** enforce, the **secure-delete position** (and its precise
limits), and a **matrix of retention guarantees per data category** that an
operator can put in front of an auditor.

It is the fulfilment of the standing item recorded in `docs/THREAT-MODEL.md`:
*"Threat model + security model — who can mount, what `AUTH` prevents, what it
doesn't"*, and of the operational requirement that *"a secure-delete promise
would contradict non-withdrawal unless a separate cryptographic key-lifecycle
design makes old content inaccessible"*.

Companion documents: the mechanism is `docs/ERASURE.md` + `src/keyring.rs` +
`src/encvol.rs`; per-surface hardening is `docs/SECURITY.md`; the consolidated
model is `docs/THREAT-MODEL.md`; the standing limits are `docs/LIMITATIONS.md`.

---

## 1. What logical deletion does — and does not do

OrFS is **append-only and non-withdrawal**. There is exactly one authoritative
stream, `or.log` (a set of immutable segment files, `docs/ON_DISK.md`), and
**Law I** holds: committed authoritative history is never overwritten,
truncated, reused, or garbage-collected; every committed transition extends the
previous history, `L_{n+1} = L_n ⊕ Δ_n`.

| Operation | Logical effect (the visible namespace) | Physical effect (the authoritative log) |
|---|---|---|
| `unlink` / `rmdir` | A new `DENTRY_REMOVE` record hides the name from the **current** root. | **None.** Every byte of the directory entry and of the file's content stays in `or.log`, byte-for-byte, forever (invariant **I1**). A historical root taken before the unlink still shows the file. |
| `truncate`-down / `ftruncate` | A new metadata/extent record changes the **visible size**; bytes past the new size are no longer reachable through the current root. | **None.** The superseded extent bytes remain in the log; a snapshot pinned before the truncate still reads them. |
| Overwrite (same offset re-written) | A new `DATA_EXTENT` record replaces the mapping for that range in the **current** root. | **None.** The previous bytes are retained; the write **appends**. This is why "retained growth tracks *written* bytes, not live bytes" (`docs/STORAGE-ECONOMICS.md`). |
| `rename` over an existing name | A new `DENTRY_RENAME` record changes the visible name; the overwritten target's bytes are retained. | **None.** Both the source's and the displaced target's history remain. |
| `fallocate` punch-hole | A new extent/metadata record makes the hole visible. | **None.** The pinned-out bytes remain in the log. |
| `commit.watermark` update | n/a (metadata) | An **added** completeness witness for the committed prefix; it never rewrites a committed byte (`src/watermark.rs`). |
| `orfs reclaim` / `orfs tier relocate` | n/a (never visible) | Moves **sealed** segments to a cold tier or drops **rebuildable** structures. It never touches the active head or an authoritative byte whose root is still pinned; the displaced copy is verified byte-identical and the committed root/digest/watermark are asserted unchanged (`docs/TIERING.md`, `docs/CAPACITY.md` §14). |

**Consequence (the honest permanence guarantee).** A path that has been unlinked
remains physically present in the authoritative log, byte-for-byte, forever. Any
party who can read the backing store, or who can mount an earlier committed root
as a read-only snapshot, can still read it.

## 2. Who can do what

OrFS is a **FUSE** filesystem; the mount is the security boundary
(`docs/THREAT-MODEL.md` §1).

| Role | Requirement | What it grants | What it does **not** grant |
|---|---|---|---|
| **Mount** | `CAP_SYS_ADMIN` + `/dev/fuse`. OrFS ships **no setuid helper and no setuid mount path**. | The ability to project the backing store as a namespace, and to issue every FUSE request the kernel relays. | Nothing about the *content* of other volumes; nothing beyond the backing store the daemon can read under the mounting user's credentials. |
| **Read a mounted view** | The POSIX permission rule (`src/inode.rs::has_permission_grouped`), applied at `open`/`create` and honoured thereafter through the **open file description** (`docs/FUSE-SEMANTICS.md` §6). `default_permissions` delegates the mode-bit half of that decision to the kernel. | Access to the objects the rule permits, under the caller's credentials and supplementary groups. | It is **not** a MAC: it is owner/group/other bits plus groups. There is no per-object encryption, no per-user key, no capability model beyond the POSIX bits. |
| **Write a mounted view** | As above, plus a writable mount (not `--read-only`) and a non-degraded volume. | Appending new authoritative records. | It does **not** overwrite or erase prior history — a "write" is an append. |
| **Read history (snapshot/historical mount)** | The **same** POSIX permission rule, evaluated at the pinned root; snapshot mounts are strictly read-only (`EROFS` for every mutation). | The state as of that committed root. | A snapshot of a root is **not** a permission bypass (`docs/SECURITY.md` §2, §6). |
| **Relocate a segment / reclaim** | Direct access to the backing directory (and the tier root) — i.e. the backing-store trust domain (`docs/TIERING.md`). | Bounded, non-withdrawing relocation of **sealed** segments and dropping of **rebuildable** structures. | It cannot relocate the active head, cannot withdraw a pinned root, and cannot change the committed root/digest. |
| **Administer the volume** | Direct read/write of the backing directory. | Everything the backing store's own permissions allow: read every retained byte, rewrite segments, delete them. | OrFS enforces **nothing** against a principal who can write the backing store — see §2.1. |

### 2.1 What the OS access model and the mount options enforce

* **The backing directory must be protected more strictly than the mount.** The
  mount is a purely logical projection; the retained history lives in the
  backing directory, so it should carry the controls appropriate to the *most
  sensitive content the volume has ever stored* — not merely those appropriate to
  the current namespace (`docs/SECURITY.md` §2).
* **`allow_other`** widens who may traverse the mount to users other than the
  mounting user; it does **not** change the POSIX rule or the backing store's
  protections.
* **`default_permissions`** moves the mode-bit part of the access decision into
  the kernel; OrFS still applies its own rule where the kernel does not
  (e.g. `orfs query`, which runs under an explicit `Credential`).
* **`--read-only`** refuses mutations with `EROFS`; it does **not** make the
  backing store read-only.

### 2.2 What `AUTH`/authorisation prevents — and what it does not

OrFS has **no `AUTH` record type and no authentication protocol in the
authoritative log.** Nothing in `orfs init`/`open` authenticates a caller to the
volume. To be exact:

* **What authorisation prevents.** Once a volume is mounted, the POSIX rule above
  is enforced per request: an unprivileged local user who cannot mount can issue
  only the operations their credentials permit, filesystem-wide. The
  **backing-store separation** (`docs/SECURITY.md` §5) prevents a hostile process
  that can plant files/symlinks in the *namespace* from reaching the backend.
  Historical views cannot be used to bypass the permissions in force at their
  root.
* **What it does not prevent.** There is **no cryptographic authentication of the
  store** — the record envelope carries CRC32C and derived structures carry
  BLAKE3, but these are *integrity and framing* checks, **not a MAC or a
  signature**, so a principal who can rewrite the backing directory and recompute
  the digests is not stopped (`docs/THREAT-MODEL.md` §2). Non-withdrawal is
  **enforced by this implementation**, not by a cryptographic accumulator or
  signature, and is therefore not a defence against a privileged attacker with
  write access to the backing store (`docs/THREAT-MODEL.md` §5). The mount options
  cannot make a hostile backing store trustworthy.
* **The opt-in encrypted volume (Phase 85) adds integrity + confidentiality for
  content.** `orfs init --key-file` seals the authoritative store under an
  operator-held key, so the bytes on disk authenticate (a tampered ciphertext is
  rejected) and are unreadable without the key (`docs/ERASURE.md`). That is
  **message authentication of the content**, still **not** a mount-time identity
  or access-control protocol: it tells you the bytes are the bytes OrFS wrote
  under that key; it does not identify the caller.

## 3. The secure-delete position

> **Logical deletion is not secure erasure, and non-withdrawal forbids erasing
> committed plaintext history.**

This is not a disclaimer added after the fact; it is the direct expression of
invariant I1. Therefore:

1. **A "secure delete"/right-to-erasure promise is not available on the plaintext
   path at any price**, because the plaintext history is retained by construction
   and this implementation never overwrites or truncates committed bytes.
2. **A defensible "delete" story requires cryptographic key destruction.** The
   only guarantee OrFS can honestly offer is: *seal content under a key, then
   destroy the key.* The Phase-85 mechanism does exactly this
   (`docs/ERASURE.md`), with the following **precise** guarantee:

   * **What it gives.** For content written under epoch *n*, destroying epoch
     *n*'s data key deletes the only copy of that key. The **ciphertext bytes
     remain in place, unwithdrawn and byte-unchanged**, but their plaintext
     becomes **cryptographically inaccessible** — OrFS returns a typed,
     fail-closed [`OrfsError::KeyDestroyed`] (`ENOKEY`) and **never fabricates
     plaintext**. This holds for the **local store and any relocated (tiered)
     ciphertext copy**, because a tier copy is byte-for-byte the same ciphertext.
   * **What it does not give.** It does **not** make the ciphertext bytes
     disappear, and it does **not** erase them from the media: the bytes (and
     their length, offsets, timing, and the volume's existence) remain observable.
     Whether key destruction satisfies a *particular* legal/regulatory erasure
     standard is **out of OrFS's scope** and depends on the key-management
     practice around the key file — which OrFS does not operate
     (`docs/ERASURE.md` §8).
   * **It does not weaken non-withdrawal.** Destruction touches **no** byte of
     the log: it removes a key, not content. The committed history, the committed
     root, the digest and the watermark are all unchanged.
3. **The default (unencrypted) path is unchanged.** An ordinary volume stores no
   keys and gains nothing here: its content is retained in plaintext. Mixing the
   two is not possible — a volume is either encrypted (carries `crypto.meta`) or
   not, and the two on-disk layouts never overlap.

## 4. Retention guarantee matrix

For each data category an operator can state a precise guarantee to an auditor:

| Data category | Location (unencrypted) | Retained? | Withdrawable by OrFS? | Erasable by (opt-in) key destruction? | What an operator can promise |
|---|---|---|---|---|---|
| **Authoritative log records** (`or.log/*.seg`) | `or.log/*.seg` | **Yes, forever** (I1) | **No** (Law I) | **Only if** the volume was created encrypted and the covering epoch key is destroyed — then the plaintext is inaccessible while the ciphertext remains | "History is permanent; a named file's content is unrecoverable iff its epoch key was destroyed." |
| **Commit watermark** (`or.log/commit.watermark`) | `or.log/commit.watermark` | Yes, and superseded values are not retained (a single atomically-replaced completeness witness) | n/a | **No** (contains no content; it is coordinates + a CRC) | "The committed prefix is witnessed; the witness leaks only `(root, segment, len)`." |
| **Sealed genesis / volume identity** | `volume.meta` (unencrypted) / `crypto.meta` + a sealed genesis segment (encrypted) | Yes | No | Encrypted: **yes** (destroying the epoch holding the sealed genesis makes the identity unreadable; `crypto.meta` still reveals the UUID/size/versions) | "Metadata is not secret on the unencrypted path; on the encrypted path only the plaintext `crypto.meta` fields leak." |
| **Manifests / derived structures** (EKBLOOM catalogues, trigram index, direct-page atlases) | `.or_bloom/`, `index/` | Yes, but **rebuildable** | **Yes** — `orfs reclaim --drop-rebuildable` drops them; a rebuild reproduces byte-identical structures | n/a (derived) | "Acceleration structures can be dropped and rebuilt; they never carry authority." |
| **Relocation catalogue** (tier state) | Metadata category (`docs/TIERING.md`) | Yes (append-only) | Not by reclaim | **no** (no content; it names digests) | "Where a sealed segment lives is recorded and immutable." |
| **Tier copies** (relocated sealed segments) | the operator's `--tier-root` | Yes, **ciphertext** | Segment recall frees it; recall does not withdraw authority | **Yes** — the same epoch key covers the byte-identical ciphertext copy | "A cold copy offers no erasure advantage over the local one; both are covered (or neither is)." |
| **Temporary construction space** | `target/`-like scratch, container-local | No (transient) | n/a | n/a | "Construction scratch is not authoritative and is not part of the volume." |
| **Key material** (master key, wrapped epoch keys) | the operator's `--key-file`, mode 0600 | Yes | **destroying an epoch key** removes its wrapped blob | n/a (this *is* the erasure lever) | "Key material never enters the volume's authoritative area; its custody is the operator's." |

The four "physical" categories above are the same four `orfs doctor --economics`
accounts (`docs/STORAGE-ECONOMICS.md`): authoritative history, rebuildable
manifestations, metadata, and temporary construction space — so the retention
matrix and the capacity accounting agree by construction.

## 5. Threat model summary for retention

| Adversary | Can it read retained history? | Can it erase it? |
|---|---|---|
| **Unprivileged local user** without mount or backing-store access | No | No |
| **User who can mount** (permitted by POSIX rule) | Only what the rule permits | No (Law I) — only new records are appended |
| **Holder of the backing store** | Yes, everything (unencrypted) / only ciphertext (encrypted) | Can delete the files (an *external* act, outside OrFS's contract) — OrFS cannot prevent it |
| **Holder of the encrypted volume's key file** | Yes (can open every live epoch) | Yes, deliberately, by `orfs key destroy` |
| **Attacker who destroyed/deleted the key by accident** | No — permanent, **explicitly not silent**: reads fail closed | n/a |

## 6. What an operator can promise an auditor

1. **No silent erasure:** `unlink`/`rmdir`/`truncate`/overwrite never remove
   authoritative history; a named path's prior content remains readable at an
   earlier committed root (gate A, `tests/log_model.rs`, and the `format_compat`
   byte-identity court).
2. **No silent loss of commitment:** a committed root is a complete transaction
   boundary; a torn tail is retained (quarantined, never truncated)
   (`docs/RECOVERY.md`, gate J).
3. **Erasure is cryptographic and opt-in:** on an encrypted volume, the only
   erasure primitive is epoch-key destruction; it is explicit, durable, typed
   (`KeyDestroyed`), and **never fabricates plaintext**. Absent a key, the volume
   **fails closed**.
4. **The bytes are never withdrawn:** key destruction leaves every ciphertext
   byte — including relocated tier copies — unchanged, so the non-withdrawal
   invariant is preserved even under erasure.
5. **The plaintext path makes no confidentiality or erasure promise.** Do not
   deploy an unencrypted volume where those are required.

[`OrfsError::KeyDestroyed`]: ../src/error.rs
