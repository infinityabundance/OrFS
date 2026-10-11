# OrFS — Known Limitations

## 1. EKBLOOM is an independent, rev-pinned public dependency

OrFS depends on **EKBLOOM** (`ekbloom` 0.3.0), a separate crate developed
independently and, at times, **concurrently** by another process. EKBLOOM is
**not** vendored or copied into OrFS. To keep OrFS builds reproducible despite
that concurrent development, OrFS consumes EKBLOOM as an **immutable git
revision of a public repository**:

```toml
ekbloom = { git = "https://github.com/infinityabundance/EKBLOOM", rev = "708c349128668bf26b50684ce473d8de4058dc31", version = "=0.3.0" }
```

Consequences:

* Every build fetches exactly the committed source at rev `708c349` (EKBLOOM
  `origin/main`, version `0.3.0`), **regardless of any other checkout** on the
  machine. `Cargo.lock` records the resolved
  `git+https://github.com/infinityabundance/EKBLOOM?rev=708c349…#708c349…`
  source, so the pin is locked.
* The pin is an existing commit on the public `origin/main`, so a **clean
  `git clone` of OrFS builds with no sibling EKBLOOM working tree**. (This
  replaced an earlier local `file://` pin at rev `255452e1`, which stopped
  resolving when EKBLOOM's history was force-pushed; see Phase 13.)
* Cargo needs `git` to fetch the dependency. The `rust:1.99.0-slim-bookworm`
  base image ships no `git`, so both `Dockerfile` and `Dockerfile.kmount`
  install it.
* OrFS never modifies, copies, or reimplements EKBLOOM's source or its state
  machine. The exact revision and the list of consumed public items are recorded
  in `evidence/receipts/ekbloom.json`; the source commit and pin are recorded in
  `evidence/receipts/source-commit.json`; the item-by-item contract is in
  `docs/EKBLOOM-INTEGRATION.md`.
* Re-pinning is a deliberate, reviewable act: change the `rev` (and
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
additionally blocked by `perf_event_paranoid=2` and dropped `CAP_PERFMON`;
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
