# OrFS — Known Limitations

## 1. EKBLOOM is an independent, published public dependency

OrFS depends on **EKBLOOM** (`ekbloom` 0.3.0), a separate crate developed
independently and, at times, **concurrently** by another process. EKBLOOM is
**not** vendored or copied into OrFS. Since Phase 35 OrFS consumes EKBLOOM as an
**exact-version crates.io dependency**:

```toml
ekbloom = "=0.3.0"
```

Before Phase 35 the dependency was a rev-pinned git dependency on
`https://github.com/infinityabundance/EKBLOOM` at rev `708c3491`. That form is
**not publishable**: crates.io rejects any dependency that is not itself on
crates.io, which blocked `cargo publish` for OrFS. Switching to the published
`=0.3.0` release was therefore required to publish OrFS, and was a deliberate,
reviewed dependency change (Phase 35).

Consequences:

* Every build fetches exactly `ekbloom` 0.3.0 from crates.io. `Cargo.lock`
  records the resolved `registry+https://github.com/rust-lang/crates.io-index`
  source and the checksum
  `b02f89add93be1429809445c7570c1271a68957702728c95437887243bdcf2cf`, so the
  version is locked.
* **The published 0.3.0 is newer than the previously pinned revision.** The
  crates.io release has 47 source files where rev `708c3491` had 30 (new
  modules such as `machine_rans`, `machine_store`, `planner`, `tiles`, `blocks`,
  `packed`). One consuming call site changed with it: `Machine::init` now takes
the core bytes and returns `Result<Snapshot>` (`src/readpath.rs::state_at`), so
  the call became `machine.init(&body.core)?`. The full OrFS test suite
  (including the manifested-vs-authoritative equivalence courts and the EKBLOOM
  roundtrip tests) passes against the published release, which is the evidence
  that the upgrade preserved OrFS's contract. No EKBLOOM source was read into or
  copied into OrFS to make the change.
* A **version-number collision** was resolved in favour of crates.io: the older
  pinned revision and the published release were both labelled `0.3.0`. crates.io
  versions are immutable, so the published source is authoritative for that
  number and any future repin must use a new version.
* No `git` is needed to build OrFS any more; the dependency comes from the
  registry. (The base images still install `git` for other tooling.)
* OrFS never modifies, copies, or reimplements EKBLOOM's source or its state
  machine. The exact version and the list of consumed public items are recorded
  in `evidence/receipts/ekbloom.json`; the source commit and pin are recorded in
  `evidence/receipts/source-commit.json`; the item-by-item contract is in
  `docs/EKBLOOM-INTEGRATION.md`.
* Re-pinning is a deliberate, reviewable act: change the version (and
  `evidence/receipts/{ekbloom,source-commit}.json`, and `Cargo.lock`) together.

## 2. Host kernel use for FUSE and io_uring

The containerized workflow provides toolchain isolation, **not** kernel
isolation. FUSE mounts and `io_uring` inevitably run against the host kernel
(see `scripts/lib.sh`). The FUSE mount tests additionally require the host's
`/dev/fuse`, `SYS_ADMIN`, and unconfined AppArmor/seccomp, and are confined to
`scripts/container-fuse-test.sh`.

On this host Docker's data-root is a **RAM-backed tmpfs** that is shared with
other builds, so transient `ENOSPC` is possible under contention. `scripts/lib.sh`
therefore sets `TMPDIR` (and the FUSE mount scripts set `CARGO_TARGET_DIR`) to the
project's bind-mounted drive rather than the container's writable layer.

### 2.1 Pre-existing unremovable mount-test containers (host state)

This host currently carries **12 pre-existing `orfs-kmount:1.99.0` containers** in
`Up` state that **cannot be removed by `docker rm -f`** — docker reports *"tried to
kill container, but did not receive an exit event"* (each in uninterruptible sleep,
holding a defunct `fuse_uring-…`/mount). They predate the present work, were not
created by any current script, and do **not** affect a run that starts *one*
container at a time (the project's rule): a single kmount container completes
cleanly, and **concurrency is the apparent trigger** for the hang. Clearing them
requires a host Docker restart (`systemctl restart docker`), which is outside this
repository's control. `scripts/container-fuse-test.sh` uses `--rm` and leaves no
containers behind when a run completes.

## 3. Accelerated reads are exactness-preserving, not free

The EKBLOOM read planner only uses a concealed structure when it is compatible
(same inode, inode version, and committed root), certified, and measured to be
worth it; otherwise it falls back to the authoritative extent read. Absolute
latencies in the evidence come from unoptimized test builds; the *selection*, not
the absolute figure, is the point.

## 4. FUSE-over-`io_uring` (profile F2) is active here (Phase 15)

**Resolved in Phase 15.** The three former blockers are closed, and a real F2
mount now works on this host (kernel 7.2.9-2-cachyos, FUSE ABI 7.45,
`fuse.enable_uring=Y`):

1. **`fuse.enable_uring` is now `Y`.** The kernel offers `FUSE_OVER_IO_URING` in
   the `FUSE_INIT` request, and the server echoes it (`flags2`). This is the gate
   (`fs/fuse/inode.c`; `fs/fuse/dev_uring.c`).
2. **The `sqe->len` gap is closed (`src/fuse_uring.rs`).** `FUSE_IO_URING_CMD_REGISTER`
   needs `sqe->len == 2`; `entry128_set_len` writes that ABI field into the
   `#[repr(C)]` 128-byte SQE, so `REGISTER` is accepted (no `-EINVAL`).
3. **OrFS now owns the `/dev/fuse` fd (`src/fuse_native.rs`).** The F2 session
   opens `/dev/fuse`, mounts it (`mount(2)`, or the setuid `fusermount3` helper
   when the uid has no effective `CAP_SYS_ADMIN` — verified in the kmount
   container, `CapEff=0`), performs the `INIT` handshake, and drives the
   `COMMIT_AND_FETCH` ring. It does not use `fuser` for the F2 path.

`orfs mount --transport fuse-uring` therefore negotiates F2 for real and serves
POSIX operations through the ring; `orfs doctor` performs a live negotiation.
The fallback to F1/F0 remains exact and content-preserving when F2 cannot engage.

Residual F2 limits on this kernel: `ADD_QUEUE`/`ADD_BUFPOOL` and the buffer-pool
`offset` field do not exist at FUSE ABI 7.45, so only the baseline register/commit
interface is used; zero-copy is not exercised; a native F2 mount exposes no `fuser`
`Notifier` (`OrfsMount::notifier()` is `None`); and `auto_unmount` is not forwarded
to the session. See `docs/FUSE_URING.md`.

## 5. Logical deletion is not secure erasure (research §29)

OrFS is append-only and non-withdrawal. `unlink`, `rmdir`, truncation, and
rename-over change only the *visible* namespace; they never physically remove or
overwrite the underlying committed bytes, which remain in the authoritative log.
**OrFS is therefore inappropriate for workflows that require reliable physical
deletion** unless a separately specified data-retention and cryptographic policy
is applied on top of it. Revoking a namespace path does not make the historical
bytes unrecoverable, and a party able to read the backing store (or to mount an
earlier committed root) can still read them. The **backing directory should be
protected more strictly than the logical mount**. See `docs/SECURITY.md` §2.

## 6. Trailing-segment loss is now detected (Phase 12)

**Fixed in Phase 12.** If the *trailing* committed segment files are physically
removed or truncated outside OrFS, a pure segment scan would still see a
contiguous chain and silently recover a strictly earlier root. OrFS now records a
**durable commit watermark** (`or.log/commit.watermark`) at every durability
point: the committed root `R` and the physical coordinate
`(segment_id, segment_valid_len)` just before `R`, with a CRC32C. On open the
watermark is validated against the surviving committed bytes; if it certifies
more history than survives, the open **refuses** rather than silently recovering
a shorter log (research §23, §35).

Properties of the fix:

* **Additive, non-withdrawal-respecting.** The watermark is new metadata; it never
  rewrites a committed byte and never changes the record stream.
* **Written only after the bytes it describes are durable**, so it can never
  certify more durable history than the backing store holds. It is written at
  `sync`/`flush`/batch-sync points (per-commit under `sync` durability).
* **A missing watermark is tolerated, not fatal**: a legacy volume (or one whose
  watermark is deleted) opens as *unvalidated*; the next durability point
  establishes one. Interior gaps, sequence breaks, and roots dangling past present
  bytes remain refused as before.
* **Cost.** The watermark adds a small (36-byte) `write-tmp → rename → fsync` at
  each durability point. This is a deliberate space/robustness-for-writes tradeoff;
  it is not on the ordered/buffered hot path (only at sync points).

Residual window: a crash *between* committing bytes and persisting the watermark
leaves the watermark one durability point behind, so loss of exactly those
not-yet-watermarked bytes cannot be detected. This is inherent to any scheme that
cannot rewrite committed history. See `docs/RECOVERY.md` §5.

## 7. Performance: no portability claim

Phase 12 measured real configurations (`conventional`, `F0`, `F1`, `E1`) on one
host/container; Phase 15 added `F2` (and `E2`, `F0`/`F1` comparisons in
`evidence/performance/fuse-uring.json`). The full methodology and numbers are in
`docs/PERFORMANCE.md` and `docs/FUSE_URING.md`. The figures are **warm-cache
single-run** measurements and are not a portable benchmark. `fio`, `hyperfine`,
and `perf` are absent from the pinned image, and hardware counters are
additionally blocked by the default container's seccomp profile (which denies
`perf_event_open` with `EPERM`) — **not** by `perf_event_paranoid=2`, which
permits user-space counters, nor by a dropped `CAP_PERFMON`, which restores them
(see `docs/PMU.md`);
Criterion/Divan were not added (the pinned build is offline-capable and
dependency-free). No performance superiority is claimed.

## 8. Extended-attribute access rule

OrFS stores xattr names as bounded opaque bytes (≤ 255, no NUL) and enforces one
uniform access rule independent of namespace: reading an attribute requires read
permission on the inode; setting or removing one requires write permission. There
There is no special privilege for `security.*`, `trusted.*`, or `system.*` names and no
`CAP_SYS_ADMIN`/`CAP_FOWNER` override; a caller that needs those semantics must
enforce them above OrFS.

## 9. Power-loss durability is tested with a *simulated* device, not real hardware

The process-crash court (Phases 2/11) kills the process, but the OS page cache
survives, so it cannot model a volatile device write-back cache, reordering, or
torn sectors. Phase 17 adds a controlled **simulated** storage device
(`src/powerloss.rs`, feature `powerloss`, on by default and compiled out with
`--no-default-features`): a configurable write-back cache with `barrier` /
`partial` / `reordered_partial` flushes, optional durable-image damage
(`tear_tail` / `lost_watermark`), and a `power_fail()` that discards un-flushed
writes and materialises the surviving image. A whole OrFS volume is run on it and
recovered independently in `tests/power_loss.rs` (evidence
`evidence/recovery/power-loss.json`).

What it establishes: OrFS never exposes a partially applied transaction, never
withdraws committed history, always recovers to a valid committed boundary or
explicitly refuses; under a device that honours `fsync`, exactly the
acknowledged-durable `sync` mutations survive.

**What it does not establish:** real-hardware durability. The model is software
with assumed device semantics — sector-granularity caching and `fsync` behaviour
are simplifications, and real devices, filesystems, and caches differ. Only an
instrumented power-loss rig can test real hardware. `sync` still promises only
what the backing device documents
(`DurabilityMode::claims_power_loss_durability()` remains `false` for every
profile). See `docs/POWERLOSS.md`.

## 10. FUSE passthrough requires `CAP_SYS_ADMIN` and the native F2 session

Phase 21 adds kernel FUSE passthrough for **immutable snapshot** reads only
(`docs/FUSE_PASSTHROUGH.md`). Two kernel/workflow constraints are honest limits,
not choices:

* **`CAP_SYS_ADMIN` is required by the kernel** for
  `FUSE_DEV_IOC_BACKING_OPEN` (`fs/fuse/backing.c`). Docker grants an added
  capability only to the **root** user, so the ordinary non-root project uid runs
  with `CapEff=0` and the ioctl returns `EPERM`; OrFS then falls back to
  daemon-served reads with identical bytes. The passthrough **court** therefore
  runs in a root container (`scripts/lib.sh` `docker_run_kmount_root`, invoked by
  `scripts/container-fuse-test.sh`); the mechanism itself is unchanged for
  unprivileged use — it simply declines.
* **Only the native F2 session can register backings** (it owns `/dev/fuse`;
  `fuser` 0.18 does not expose the fd). `F0`/`F1` snapshots, or any kernel that
  does not offer `FUSE_PASSTHROUGH` at `INIT`, serve reads through the daemon.

The feature is deliberately scoped to read-only historical views
(`OrfsCore::passthrough_backing` defaults to `None`); no mutable file is ever
passthrough-eligible, so a descriptor can never observe bytes changing behind an
open file. The measured numbers in `docs/FUSE_PASSTHROUGH.md` §6 are warm-cache
single-run figures and are not a portability claim.

## 11. Capacity is finite and exhausted by an orderly read-only transition

Phase 23 makes the (previously implicit) capacity behaviour explicit
(`docs/CAPACITY.md`). Two honest limits remain:

* **The reserve and quotas bound *this* volume, not the device.** Another tenant
  can fill the backing store; OrFS then degrades on the OS `ENOSPC`, never
  silently. The device-derived capacity is sampled at open, so a shrinking or
  concurrently-filled filesystem is caught by the OS error rather than predicted.
* **Exhaustion is not reclamation.** OrFS is append-only (see §5): the capacity
  policy can only *refuse* growth. It never truncates, reclaims, or rewrites
  committed history, so an exhausted volume requires freed space (or a larger
  device) to become writable again — reopening re-evaluates capacity.

One ordering subtlety is documented rather than hidden: if the commit watermark
cannot be written *after* the segment bytes were made durable, the durable
committed root lags the bytes, so recovery may include a mutation that was never
acknowledged. That is the safe direction (acknowledged ⇒ survives); the converse
never happens. See `docs/CAPACITY.md` §8 and `docs/RECOVERY.md` §7.

## 12. POSIX deviations found by the standard suite (Phase 24; closed in Phase 25)

The pjdfstest court (`docs/FUSE-SEMANTICS.md` §11.1,
`evidence/correctness/pjdfstest.json`) compares a mounted OrFS volume against a
reference ext4 directory on the same suite. Three real bugs it found were fixed
there (an over-long name now returns `ENAMETOOLONG`; `rmdir` now enforces the
sticky-bit rule; the FUSE adapter now reports the true `nlink`, including `0` for
an unlinked-but-open file). It also recorded a set of POSIX semantic deviations,
which **Phase 25 has now closed**, each verified against the reference:

* **Implicit timestamps** (`dir_timestamp`, `file_timestamp`). Namespace
  mutations now advance the containing directory's `mtime`/`ctime`, and content
  mutations (write/truncate) advance the file's `mtime`/`ctime`, each as an
  append-only `INODE_SETATTR` record in the same authoritative transaction
  (`docs/FUSE-SEMANTICS.md` §5.1). Explicit `utimensat` values and
  `UTIME_OMIT`/`UTIME_NOW` are preserved.
* **`setuid`/`setgid` on a non-owner write** (`setuid_sgid_killpriv`). OrFS now
  negotiates `FUSE_HANDLE_KILLPRIV(_V2)` and clears the bits itself on write —
  and on a truncate by a caller without `CAP_FSETID` — in the same transaction
  (§5.2).
* **`utimensat(UTIME_NOW)` with only write permission**
  (`utime_now_write_permission`). A pure `ATTR_TOUCH` time update
  (`times == NULL` or both `UTIME_NOW`) now needs only write permission for a
  non-owner, returning `EACCES` (not `EPERM`) when it is absent (§6).
* **Truncation through a writable fd re-checking inode write permission**
  (`fd_truncate_permission`). A `SETATTR` carrying an already-open writable
  handle no longer re-checks the inode's write permission (Linux checks it at
  `open`).
* **Supplementary-group `chgrp`** (`supplementary_group_chgrp`). A non-root owner
  may now `chgrp` to its effective or a supplementary group, read from the
  kernel's `/proc/<pid>/status`; a group whose membership cannot be confirmed is
  still refused with `EPERM` (§6).

The only remaining pjdfstest failure that is not a mechanically unsupported node
type is `unlink/08.t` #2, which the reference ext4 run fails too — an
environment/suite artefact, not an OrFS deviation. Every deviation is (or was)
recorded in `scripts/posix/pjdfstest-expected.tsv` and asserted by the gate so it
cannot silently grow; that allowlist now contains only the shared artefact.

None of these changes alters a byte of committed history (each implicit timestamp
is an appended record) and none returns a wrong success.

## 13. Phase 33 hardening: honest costs and remaining bounds

The consolidation phase fixed five review findings and made derived-structure
integrity explicit. The honest costs and residual bounds are:

* **Supplementary groups come from `/proc`.** Both transports read the caller's
  supplementary groups from `/proc/<pid>/status` `Groups:` to apply the Linux
  `in_group_p` rule to *every* permission decision (not just `chgrp`). If `/proc`
  is not mounted, or the caller's pid is not visible to the daemon (e.g. a
  different pid namespace), membership cannot be established: the caller is
  classified by its effective ids alone. This can **over-deny** but never
  over-grant. The typed query API (`src/query.rs`) is not a POSIX request and
  carries no pid, so it takes its supplementary groups from `Credential`
  (`groups: Vec<u32>`, empty by default) — a caller that wants grouped access
  must supply them.
* **The FUSE-passthrough integrity anchor re-reads authority once per version.**
  Reuse now requires the image digest to match *authoritative* history, so a
  tampered image + manifest is refused. Establishing that anchor costs one
  authoritative read of the whole file the first time a version is materialized
  in a mount; the result is cached (`Snapshot::passthrough_cache`), so it is paid
  once per mounted version, not per read. It is a deliberate correctness cost,
  not a per-read cost.
* **The read-planner calibration budget bounds candidates, not wall-clock.**
  budget is checked **before** each candidate, so it bounds how many
  candidates a single foreground read will attempt to time, but a single slow
  candidate can still exceed the budget. The guarantee the planner actually
  makes is stronger and simpler: **an unmeasured candidate is never selected** —
  with no calibrated candidate, or with a zero budget, the read is served by the
  authoritative path.

## 14. Security model and threat model

OrFS's security model is stated in full in **`docs/THREAT-MODEL.md`**: who can mount
and with what privilege; what the model prevents (hostile backing data, hostile FUSE
clients, tampered derived structures, permission bypass, traversal); and what it
**does not** (raw-device/privileged attackers, confidentiality, host-level DoS).
Two points belong on this limitations list specifically:

* **The on-disk checks are integrity, not authentication.** CRC32C framing and
  BLAKE3 digests detect accidental corruption and casual tampering; they are not a
  MAC and there is no signature or encryption. An attacker with write access to the
  backing directory can rewrite history and recompute the digests.
* **Non-withdrawal is a design law, not a cryptographic guarantee.** Law I constrains
  OrFS's own behaviour and is verified by the model courts (gate A); it is not a
  defence against a privileged attacker.

The per-surface hardening, the `unsafe`-block audit, the vulnerability log, and the
native-FUSE fuzzing/sanitizer results remain in `docs/SECURITY.md`; the acceptance
gate definitions (including gate A) are published in `docs/GATES.md`.
