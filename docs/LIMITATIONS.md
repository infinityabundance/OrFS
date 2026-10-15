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
deletion** on its own. The **only** defensible erasure mechanism on top of
non-withdrawal is cryptographic — seal content under a key and destroy the key,
leaving the ciphertext bytes in place but unreadable — and Phase 85/86 supply it
as an **opt-in encrypted volume** (`orfs init --key-file`, `orfs mount
--key-file`, `docs/ERASURE.md`). That mechanism has its own real limits (§22).
Revoking a namespace path still does not make the historical bytes
unrecoverable, and a party able to read the backing store (or to mount an
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
cannot rewrite committed history. See `docs/RECOVERY.md` §5. Phase 80 makes this
an **explicit property** of a three-class failure-state model, with a per-mode
detectable/undetectable classification and a tested `residual_window` field:
`docs/DURABILITY.md` §4 (court `tests/durability_qualification.rs`, evidence
`evidence/recovery/durability-qualification.json`). Detection cannot be
strengthened without an additional synchronous write on the acknowledgment path or
rewriting committed bytes (forbidden by non-withdrawal), so the receipt records
`can_be_strengthened: false` with the reason.

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
(see `docs/PMU.md`). Granted `--cap-add PERFMON`, the microarchitecture and the
mounted hot-path courts read real counters (`docs/PERFORMANCE.md` §18/§34); the
kernel exposes **no** TLB read-miss event on this host (`dtlb_read_misses` →
`ENOENT`, `itlb_read_misses` → `EINVAL`), which those courts record rather than
estimate;
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
* **`write`/`read` re-checking the inode's mode** (Phase 82; found at the
  application layer, not by pjdfstest). The same principle is now applied to the
  plain data path: `write`/`read` honour the **open file description's** access
  mode, so a `0444`-created file is writable through the creating descriptor (the
  `git` loose-object pattern) and an open descriptor keeps its rights after a later
  `chmod`. Access is still decided at `open`/`create` — a conformance correction,
  not a relaxation (`docs/FUSE-SEMANTICS.md` §6, `docs/LIMITATIONS.md` §20).
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

## 15. The image pixel-surface pyramid is rejected, not merely unimplemented

Earlier phases described a "pixel-surface pyramid" (decoded, downsampled image
surfaces under `.or_bloom/image/`) as a designed feature that was not
materialised. Phase 71 resolves that ambiguity: the feature is **rejected**, not
deferred, and has been removed from the implemented spec (`docs/QUERY.md` §9.1,
`docs/ORFS-SPEC.md` §4). The reasons — the geometry alone provides no
user-visible capability, and materialising real surfaces needs a decoder
dependency this project deliberately avoids, and it is on no critical path —
along with a possible dependency-free (uncompressed-BMP) reconsideration, are in
**`docs/REJECTED.md`**. Image **recognition**, dimension and colour-semantics
parsing, and the descriptive `pyramid_levels` geometry remain implemented and
tested (`src/image.rs`).

## 16. Tier relocation is local-directory and single-host (Phase 76)

`orfs tier` implements immutable tier relocation (`docs/TIERING.md`): sealed
segments move to a cold tier without withdrawing authority. Honest bounds:

* **The cold tier is a local filesystem directory.** There is no object-store (S3
  &c.) backend: `--tier-root` is a path — a cheaper local device, a network mount,
  or an object-store FUSE mount. The content-addressed layout
  (`orfs-tier/<uuid>/<segment id>/<digest>.seg`) is what an object-store backend
  would key on, but the transport here is POSIX file I/O.
* **No background tiering daemon.** Relocation is an explicit operator command run
  while the volume is not mounted; there is no automatic, online, watermarked
  relocation. The court proves the durable state machine, idempotence, and crash
  convergence — not an online controller.
* **The relocation catalogue is integrity-checked, not authenticated.** Its
  records carry a CRC32C and the tier objects a BLAKE3 digest — the same
  integrity-not-authentication caveat as §14: an attacker with write access to the
  volume or the tier can rewrite both.
* **The measured numbers are bounded and host/build dependent.** The court's
  byte counts are deterministic for its fixed fixture, but the absolute footprint
  figures are single-run, single-host (see the receipt's `note`).

## 17. Bounded reclaim is derived-only and local (Phase 77)

`orfs reclaim` (`docs/CAPACITY.md` §14) frees local space under a byte-identity
proof. Honest bounds:

* **It never frees an authoritative byte.** The bounded actions move a verified
  copy to a cold tier and/or drop *derived* structures. There is no path to
  reclaim permanent authoritative history — that is non-withdrawal
  (`docs/LIMITATIONS.md` §5). If nothing derived remains, the only remedies are a
  larger/other backing device or a fresh volume.
* **The cold tier is a local filesystem directory.** As in §16, there is no
  object-store backend: `--tier-root` is a path. A reclaim whose tier is on the
  **same** filesystem frees no *device* free space (the bytes merely move) — it
  still shrinks the volume's local authoritative footprint. The measured
  free-space increase in the receipt places the volume and tier on different
  filesystems deliberately.
* **A reclaim runs while the volume is unmounted.** It is an explicit operator
  command, not an online controller; there is no background reclamation and no
  automatic coordination with a mounted daemon. The internal ordering is
  **relocate → drop rebuildable → drop derived metadata**, matching the decision
  tree.
* **Dropping is irreversible for the dropped derived bytes.** They rebuild on
  demand (at a read- or mount-latency cost), but the *reclaim* itself does not
  rebuild them; a subsequent read or open does.
* **The autonomous expansion controller is now subordinate to the governor, so it
  cannot silently undo a reclaim (Phase 78).** `src/expansion.rs`
  (`docs/MANIFESTATION.md` §14.8, `docs/CAPACITY.md` §15) consults
  `CapacityGovernor::optional_allowed` before **every** object and accounts its
  **measured** bytes, so it re-manifests into freed space only while the governor
  *currently* allows optional construction with *currently* free optional
  headroom. Its construction is also cancelable and bounded. The remaining honest
  limit is the same one the governor already states: if the governor *does* allow
  optional construction after a reclaim (the volume is healthy and under its soft
  quota), re-manifestation is *permitted* — that is the intended behavior, not a
  defect.
* **The measured numbers are bounded and host/build dependent**, as in §16: the
  receipt's `note` says so, and the byte-equality (not the absolute byte counts) is
  the point. For the subordination court the **refusal and cancelation** counts
  (not the byte totals) are the deterministic result.

## 18. Adversarial concurrency is a native equivalent, not the real tools (Phase 79)

The reviewer's P0 ask was sustained filesystem correctness under adversarial
concurrent workloads, extending the POSIX court to `fsx`, `fsstress`, `fs_mark`
and custom rename/link/unlink races. Honest bounds:

* **The real tools are not runnable here.** `fsx`/`fsstress` ship with `xfsprogs`
  / `xfstests`, which do not configure or start in this environment (`make` needs
  `libtool` + `acl`/`attr`/`uuid` dev libraries; `./check` refuses to begin without
  `fsstress`; there is no `FSTYP` for OrFS). `evidence/correctness/xfstests.json`
  records `ran:false` with the exact attempted commands. Every court in
  `tests/adversarial_concurrency.rs` is a **native Rust equivalent**, labelled as
  such in the code, in `docs/POSIX-COMPAT.md` §6, and in the receipt's `tools`
  field — never a run of the real tool.
* **The in-process courts serialise mutations.** `OrfsCore`/`Namespace` is `&mut`
  and the court shares one `Mutex<Namespace>`, so the in-process `fsstress`
  equivalent exercises *real* OS-thread contention on the commit path but not
  lock-free mutation concurrency (OrFS serialises commits by design). Genuine
  transport-level concurrency is exercised by the **mounted arm**.
* **The mounted arm uses a `direct_io` mount.** On a cached (write-through) mount
  a client read of an *actively appended* file can transiently observe a
  client-side page-cache artefact (a zero-filled page the kernel fetched beyond
  the then-committed EOF before OrFS's invalidation notification arrived) — a
  documented FUSE client-cache coherence property, not a commit-atomicity defect.
  The court mounts with `--direct-io` so every read is served by the daemon and a
  concurrent reader observes exactly the committed bytes. The court records this
  explicitly rather than smoothing it over.
* **Latency is host/load-sensitive.** The mounted p50/p95/p99/p99.9 figures are a
  single run on one host under external load; the deterministic, load-independent
  result is **zero mismatches / orphans / duplicate inodes / torn reads**, not the
  absolute times (the receipt says so).
* **Scope of the `fs_mark` equivalent.** `fs_mark`'s full sweep (millions of
  files) is bounded here to thousands (`ORFS_FSMARK_FILES`, default 4 000) because
  each file is a full authoritative transaction; the parameters are honoured
  verbatim if a larger bounded run is wanted.

## 19. Durability qualification distinguishes failure classes but is still a simulation (Phase 80)

Phase 80 adds an explicit failure-state model with three **distinguished failure
classes** (`Process`, `Kernel`, `Storage`) and an extended fault matrix (in-flight
completions, metadata tearing, remount cycles, reordered writes, lost flushes). It
qualifies OrFS's durability *relative to the model*, and states the honest bounds:

* **It is a simulation.** `tests/durability_qualification.rs` runs the
  deterministic in-process device (`src/powerloss.rs`). Every class retains a
  *modelled* set of bytes; a green run proves recovery correct relative to the
  model's assumed device semantics, **not** real-hardware durability. `sync` still
  promises only what the backing device documents
  (`claims_power_loss_durability()` remains `false`). See `docs/DURABILITY.md`.
* **Real block-device faults are not injected here.** The Phase-62/80 `dm` probe
  (elevated container) records `ran:false` on this host: the pinned image ships no
  `dmsetup` and exposes no `/dev/mapper/control`, so no `dm-flaky`/`dm-error`
  target can be built. The receipt's `dm_probe` field carries the exact failing
  commands; the fault matrix uses the simulated device and direct byte injection
  instead. No `dm-*` result is fabricated.
* **For OrFS, `Process` and `Kernel` retain the same bytes.** The commit path has
  no acknowledged-but-unwritten userspace data, so the two coincide for the
  acknowledged contract; the model differs only in that `Kernel` may reorder the
  retained writes. The measurable class distinction for OrFS is between
  cache-retaining (`Process`/`Kernel`) and cache-losing (`Storage`) devices.
* **The residual window cannot be closed without changing the contract.** The
  loss of durable bytes between the last persisted watermark and the committed
  root is undetectable by the watermark alone. Strengthening detection would need
  an additional synchronous write on the acknowledgment path or rewriting committed
  bytes (forbidden by non-withdrawal); the receipt records
  `can_be_strengthened: false` with the reason rather than claiming it closed.
* **The generation manifest/catalogue is out of the log-device's scope.** It lives
  outside the log directory, so the log-directory device does not tear it; that is
  covered by the manifestation courts (Phases 42/78).
* **The matrix is bounded and opt-in.** The always-on smoke is small; the full
  mode × class × profile sweep runs only under `ORFS_DQ_SWEEP=1`, one container at
  a time, and its numbers (matrix size, refusals, residual rows) are the
  deterministic result, not a timing claim.

## 20. Application workloads: OrFS is slower, but `git` runs (Phase 81; `git` blocker resolved in Phase 82)

Phase 81 drives five **real applications** (`git`, `sqlite3`, `tar`, `make`/`gcc`,
and an in-process metadata-heavy tree) end to end against a real OrFS mount and
against external baselines, and publishes the results honestly
(`docs/APPLICATIONS.md`, `evidence/performance/application-workloads.json`).

* **OrFS loses every workload.** Against the same-device host filesystem
  baseline, the completed workloads are **8.9×** (`git`), **2.9×** (SQLite),
  **29.6×** (tar extraction), **1.4×** (`make -j` source build) and **52.1×**
  (a 50 000-file metadata tree) slower. The mechanism is the FUSE round-trip plus
  authoritative-commit cost already documented in `docs/PERFORMANCE.md`
  §20/§31.2 and `docs/FUSE-SEMANTICS.md`. This is the application-layer
  quantification of the standing position that OrFS is **not yet a faster
  general-purpose replacement** for ext4/tmpfs.
* **`git` now runs on OrFS (the Phase 81 blocker was fixed in Phase 82).** The
  Phase 81 court found that `git` wrote a loose object by creating a file with
  mode `0444` and writing through the returned descriptor, and OrFS **re-checked
  the inode's write bit on every `write`**, so the write was refused with `EACCES`
  and `git` aborted (`fatal: unable to write loose object file: Permission
  denied`). That was a POSIX-conformance defect, not a security feature: the
  permission was already enforced at `open`/`create`. Phase 82 makes `write` (and
  `read`) honour the **open file description's** access mode, so the `0444`-create
  probe now reports `ok` on OrFS, the `git` workload **completes** (OrFS median
  **1.083 s** vs `host_fs` **0.122 s**), and the `0444` loose-object pattern is a
  mounted conformance check (`fuse_integration` `write_through_created_fd`). Access
  is still decided at `open`/`create`; see `docs/SECURITY.md` and
  `docs/THREAT-MODEL.md` — the threat model is unchanged.
* **The image-extraction workload is synthetic.** It is a bounded OCI-layer-like
  tarball extracted with `tar`, **not** a real `docker pull`.
* **The tmpfs arm is a RAM reference floor**, not the headline comparator; the
  headline baseline is on the **same device** as the OrFS backing, so the
  comparison isolates the filesystem stack. Wall-clock is host/load-sensitive;
  the verdict booleans are the machine-readable, non-drifting result.

## 21. The mounted overhead is dominated by irreducible FUSE dispatch (Phase 84)

Phase 84 (`tests/transport_ceiling.rs`, `docs/PERFORMANCE.md` §35) measures the
**same bounded metadata/read/write workload** through a real mount on every OrFS
transport, through a plain directory on the **same device with no FUSE**, and
directly through the in-process engine. Decomposing each mounted transport's
overhead over the same-device baseline into client CPU + daemon CPU + a kernel
residual, the residual is **~74 %** of F0's overhead on this host (**23.2 µs/op**
kernel vs **8.0 µs/op** daemon user-space work).

* **What this means.** Even a hypothetical zero-cost daemon would leave OrFS F0 at
  roughly the same-device baseline plus that kernel residual (~24.6 µs/op for the
  mixed workload here). The FUSE round-trip, VFS work, and scheduling are **not
  OrFS's to optimise**; they bound every hot-path change. OrFS's own separable work
  is real but smaller: the engine costs **73.0 allocs/op** and **~8 µs/op** of
  daemon CPU against **14.8 allocs/op** of dispatch/framing on top.
* **No transport escapes it.** F2 (single-loop and pool) makes the kernel residual
  **larger** (33.8–48.8 µs/op) on this ABI; this is why F0 stays the latency default
  (`docs/PERFORMANCE.md` §31.1).
* **What the decomposition is not.** The daemon counter is *user-space* only
  (`exclude_kernel=1`) and summed across every daemon thread, divided by the client's
  measured syscall count; converting cycles to ns uses a **measured** `cycles_per_ns`
  on the calling thread (same CPU class, not the same instant), so the kernel
  residual is an estimate of the dispatch share, not a per-syscall budget. The
  `read` sub-op is page-cached and the F0/F2 transports differ in whether a write
  invalidates it, so the `read` column is not a clean cross-transport comparison
  (the metadata ops are). The immutable read-only arm negotiated FUSE passthrough but
  registered no backing, so it is daemon-served and labelled, not a zero-copy claim.

## 22. Crypto-erasure is a key-lifecycle layer with real limits (Phase 85; mounted in Phase 86)

Phase 85 added an **opt-in encrypted volume** whose authoritative store is sealed
under an operator-held keyring, so that **destroying an epoch key** renders that
epoch's content cryptographically inaccessible while the ciphertext bytes remain
unwithdrawn (`docs/ERASURE.md`). Phase 86 makes the seal **length preserving** (a
per-segment positional keystream applied at the `Segment`/`ReadAt` seam), so the
encrypted store *is* a real OrFS log and `orfs mount --key-file` now serves it
through the ordinary namespace/index/FUSE path
(`tests/crypto_erasure_mounted.rs`,
`evidence/security/crypto-erasure-mounted.json`). The mechanism is real and
tested end to end, but it is **not** a total erasure or confidentiality story.
Stated plainly:

* **Erasure makes the whole store fail closed (a linear-log bound).** The
  authoritative store is a *linear* record stream: a segment bound to a destroyed
  epoch cannot be scanned past, so destroying an epoch key makes the **whole
  volume** fail closed on open (`KeyDestroyed`) rather than erasing one epoch and
  continuing to serve the rest. `orfs crypt verify` still reports the store's
  intended state (which segment is inaccessible, and why). Erasing part of a live
  volume while keeping the rest mounted is **not** supported.
* **Tamper is detected at a durability point, not per byte read.** Integrity is a
  **per-segment keyed-BLAKE3 MAC** over the segment's ciphertext, held in a
  master-key-sealed table (`crypto.segments`) in the volume's metadata tier — no
  ciphertext byte is spent on it. It is verified **at open/scan** (every segment)
  and advanced at each `fsync` (`seal_point`). Bytes written but not yet fsynced
  lie beyond the authenticated prefix and are treated exactly like an abandoned
  tail (retained, never decrypted, never trusted); they are not covered by the MAC
  until the next durability point. A flipped ciphertext byte inside the
  authenticated prefix is therefore rejected **at open**, not detected mid-`read`
  of an already-open, already-verified segment. This is the deliberate trade-off
  of a length-preserving seal; the alternatives and their costs are in
  `docs/ERASURE.md` §5.
* **Key management is out of scope.** Custody, backup, escrow, rotation policy,
  and the legal adequacy of key destruction are the operator's. OrFS supplies a
  mechanism and a typed error, not a key-management service.
* **Metadata leaks.** `crypto.meta` (uuid, segment size, versions), the existence
  of the sealed `crypto.segments` table, and the **derived** `index/`
  accelerators (rebuilt on demand) are metadata, not sealed authoritative
  content. The mechanism hides authoritative *content*, not all shape or timing.
* **The AEAD is a construction, not a standardised primitive.** It is a
  real, textbook encrypt-then-MAC over BLAKE3's keyed mode (the crate's only
  crypto dependency, kept because the build is network-isolated against a frozen
  `Cargo.lock`), **not** XChaCha20-Poly1305; the swap-in point is named in
  `docs/ERASURE.md` §3.
* **Key material is not `mlock`ed or explicitly zeroised on drop.** It lives in
  process memory while a volume is open; a core dump or memory compromise could
  expose a *live* key.
* **No freshness.** A principal who can replace the whole backing store (or the
  key file) can substitute an older ciphertext; the content authenticates as
  *content OrFS wrote under that key*, not as the newest state.
* **The default (unencrypted) path makes no confidentiality or erasure promise**
  and is byte-for-byte unchanged; all of the above applies only to a volume
  created with `--key-file`.
