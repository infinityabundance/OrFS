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
is no special privilege for `security.*`, `trusted.*`, or `system.*` names and no
`CAP_SYS_ADMIN`/`CAP_FOWNER` override; a caller that needs those semantics must
enforce them above OrFS.
