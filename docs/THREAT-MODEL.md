# OrFS threat model and security model

This document states, in one place, **who can do what** to an OrFS volume, **what the
security model prevents**, and — just as importantly — **what it does not**. It
consolidates `docs/SECURITY.md` (the per-surface hardening and the Phase-11
vulnerability log) into the model a person deploying OrFS needs. `docs/LIMITATIONS.md`
lists it under the standing limitations.

## 1. Trust boundaries and who can mount

OrFS is a **FUSE** filesystem. The mount is the security boundary, and mounting
requires the privilege the kernel demands for FUSE:

* **Mounting requires `CAP_SYS_ADMIN` and `/dev/fuse`.** OrFS ships no setuid
  helper and no setuid mount path; a process that cannot mount cannot reach a
  mounted OrFS view at all. Once mounted, the kernel routes requests to the OrFS
  daemon, which runs with the mounting user's privileges.
* **A person who can mount is trusted with the backing store.** Mounting exposes
  every object the daemon can read from the backing directory, under the requested
  credentials; there is no additional per-mount secret. The backing directory must
  therefore be protected **more strictly than the mount**: the mount can be shared
  with ordinary users, the backing store should not (`docs/SECURITY.md` §2).
* **Within a mounted view**, access is enforced by the ordinary POSIX rule
  (`src/inode.rs::has_permission_grouped`, shared by both transports): owner/group/
  other bits, the caller's supplementary groups, `default_permissions` handling, and
  symlink-safe resolution. The rule is applied **at `open`/`create`**, the POSIX
  gate; `read`/`write` then honour the **open file description's** access mode (a
  descriptor opened while permitted keeps its rights after a later `chmod`, and a
  `0444`-created file is writable through the creating descriptor). The Phase 82
  correction that made `write`/`read` trust the descriptor was a **conformance fix,
  not a relaxation**: access is still decided at `open`/`create`
  (`docs/SECURITY.md` §3.7, `docs/FUSE-SEMANTICS.md` §6). A query (`orfs query`)
  runs under an explicit `Credential` and applies the same read rule.

## 2. What integrity mechanisms exist — and what they are not

OrFS's on-disk checks are **integrity and framing checks, not authentication**:

* The record envelope carries a **CRC32C** and the log segments carry structural
  validation (`src/record.rs`, `src/segment.rs`, `docs/ON_DISK.md`).
* Derived structures carry **BLAKE3** digests of their payloads and self-digests of
  their manifests (`src/manifestation.rs`, `src/trigram.rs`).
* The read planner certifies a manifested structure against the **authoritative
  content** before trusting it, and re-checks identity (volume, inode, version,
  root, generation) — defence in depth against a tampered *derived* structure
  (`docs/SECURITY.md` §3.14).

There is **no message-authentication code, no signature, and no encryption** on the
authoritative log. CRC32C/BLAKE3 detect accidental corruption and casual tampering;
they do **not** stop an adversary who can rewrite the backing directory and
recompute the digests. Do not treat OrFS's checks as a MAC (see `docs/ON_DISK.md`,
which says the same at the wire level).

## 3. Adversaries considered (and answered)

| Adversary | Capability | Answered by |
|---|---|---|
| **Hostile backing data** | Arbitrary bytes in `or_log/*.seg`; a forged but correctly-framed record; a truncated committed segment; an unsupported format version | `src/record.rs`, `src/segment.rs`, `src/log.rs`, every payload decoder; `evidence/correctness/*`, `tests/fuzz_decode.rs` |
| **Hostile FUSE client** | Arbitrary opcodes, node ids, names, offsets, sizes, xattr names, masks, handles | `src/fuse.rs`, `src/fuse_uring.rs`, `src/namespace.rs`, `src/index.rs`; native-FUSE fuzzing (`docs/SECURITY.md` §4.1) |
| **Unprivileged local user** | Mounts (possibly with `default_permissions`) and issues ordinary POSIX operations | the shared permission rule; supplementary groups; symlink-safe resolution |
| **Tampered derived structure** | Rewrites a concealed structure (e.g. a passthrough image) and matches its manifest | authoritative re-verification and identity qualification before any manifested path serves |
| **Hostile backing directory** | Reads the directory, or plants files/symlinks in it | `docs/SECURITY.md` §5 (namespace ↔ backend separation) |
| **Process crash / torn write** | Killed mid-write; no destructor runs | `tests/crash_recovery.rs`, `tests/recovery_adversarial.rs`, `docs/RECOVERY.md` |

## 4. Explicitly out of scope

* A **compromised kernel**, or a **privileged attacker with raw device access** — they
  can read and rewrite everything, including history.
* **Power-loss / device-cache reordering.** A process kill is *not* a power-loss
  simulation; power-loss is a separate, identified proof obligation with a
  **simulated** device model (`docs/TRANSACTIONS.md`, `docs/POWERLOSS.md`).
* **Confidentiality.** OrFS does **not** encrypt an ordinary volume; anyone who
  can read the backing directory can read the content. An **opt-in encrypted
  volume** (`orfs init --key-file`, Phase 85) seals the authoritative store under
  an operator-held keyring, so its ciphertext is unreadable without the key and
  authenticates; it still leaks shape (frame count, epochs, `crypto.meta`) and
  **does not** encrypt the unencrypted path. See `docs/ERASURE.md`.
  **Erasure:** logical deletion is not secure erasure; the only erasure primitive
  is epoch-key destruction on an encrypted volume (`docs/RETENTION.md` §3).
* **Denial of service by the host.** A container/host that starves CPU, memory, or
  file descriptors can make OrFS unavailable; the daemon bounds its own allocation and
  recursion but does not defend against host-level resource exhaustion.

## 5. Non-withdrawal is a design law, not a cryptographic guarantee

Law I (non-withdrawal) is enforced **by the implementation**: committed history is
never overwritten, truncated, reused, or garbage-collected, and every committed
transition extends the previous history (`L_{n+1} = L_n ⊕ Δ_n`). It is **not** backed
by a cryptographic accumulator or signature, so an adversary with write access to the
backing store can violate it. The law constrains OrFS's own behaviour and is verified
by the model courts (gate A, `tests/log_model.rs`); it is not a defence against a
privileged attacker.

The Phase-85 encrypted volume and its **crypto-erasure** primitive **add** a
key-lifecycle layer; they never weaken this law. Destroying an epoch key removes a
*key*, not a byte: the ciphertext is retained, unwithdrawn, and the court asserts
the store's bytes and digest are byte-identical before and after destruction
(`docs/ERASURE.md` §7, `docs/RETENTION.md` §3).

## 6. Evidence

* `docs/SECURITY.md` — per-surface hardening, the `unsafe`-block audit, the
  vulnerability log, and the native-FUSE fuzzing/sanitizer results.
* `docs/LIMITATIONS.md` — the standing limits, including that containerized tooling is
  **not** kernel isolation.
* `evidence/security/` — `unsafe-audit.json`, `fuzz-decode.json`,
  `native-fuse-fuzz.json`, `valgrind.json`, `hostile*`, and
  `crypto-erasure.json` (the Phase-85 retention/erasure court).
* `docs/RETENTION.md` (the retention and access-control contract) and
  `docs/ERASURE.md` (the crypto-erasure design and what is wired vs. specified).
* `docs/GATES.md` — the acceptance gate definitions (gate A is non-withdrawal; gate J
  is recovery incl. the fault-injection and power-loss courts).
