# OrFS — Known Limitations

## 1. EKBLOOM is a local, concurrently-developed dependency

OrFS depends on **EKBLOOM** (`ekbloom` 0.3.0), a separate crate that lives at the
sibling path `/mnt/1tb_kingston/EKBLOOM`. EKBLOOM is **not** vendored or copied
into OrFS; it is developed independently and, at times, **concurrently** by
another process. Its working tree is therefore not a stable input: a bare path
dependency would silently rebuild OrFS against whatever edits happened to be
present at build time.

**How OrFS pins it.** OrFS consumes EKBLOOM as an **immutable git revision**:

```toml
ekbloom = { git = "file:///mnt/1tb_kingston/EKBLOOM", rev = "255452e1a803080de99f7a18aaef840c8c835209", version = "=0.3.0" }
```

Consequences:

* Every build fetches exactly the committed source at rev `255452e`
  (EKBLOOM `main`, version `0.3.0`), **regardless of uncommitted changes** in
  the EKBLOOM working tree. `Cargo.lock` records the resolved
  `git+file:///...?rev=255452e...#255452e...` source, so the pin is locked.
* The URL and rev are **absolute and host-specific**: the EKBLOOM checkout must
  exist at `/mnt/1tb_kingston/EKBLOOM`, and that path must be visible inside the
  build container at the same path (`scripts/lib.sh` bind-mounts the parent
  directory there). This pin is reproducible on this machine, not portable.
* Cargo needs `git` to fetch the dependency. The `rust:1.99.0-slim-bookworm`
  base image ships no `git`, so both `Dockerfile` and `Dockerfile.kmount`
  install it.
* OrFS never modifies, copies, or reimplements EKBLOOM's source or its state
  machine. The exact revision and the list of consumed public items are recorded
  in `evidence/receipts/ekbloom.json`; the item-by-item contract is in
  `docs/EKBLOOM-INTEGRATION.md`.
* Re-pinning is a deliberate, reviewable act: change the `rev` (and
  `evidence/receipts/ekbloom.json`, and `Cargo.lock`) together.

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

## 4. FUSE-over-`io_uring` (profile F2) is implemented but not active here

The native F2 transport adapter is implemented and tested, but a real F2 mount
is **not achievable on this host**, for three independent reasons detailed in
`docs/FUSE_URING.md` §7:

1. **`fuse.enable_uring=0`.** The running kernel (`7.2.9`, FUSE ABI 7.45) gates
   FUSE-over-`io_uring` on the `fuse.enable_uring` module parameter
   (`fs/fuse/inode.c`, `fs/fuse/dev_uring.c`). It is off; the parameter is
   `root:root 0644` and the container runs unprivileged. The kernel therefore
   never offers `FUSE_OVER_IO_URING` at `INIT`, and every `IORING_OP_URING_CMD`
   would be rejected with `-EOPNOTSUPP`. Changing a host-global kernel parameter
   is deliberately out of scope.
2. **`io-uring` 0.7.15 cannot set `sqe->len`.** `FUSE_IO_URING_CMD_REGISTER`
   requires `sqe->len == 2`; the crate's `UringCmd80` builder exposes no `len`
   setter. Closing this needs a raw-SQE path.
3. **`fuser` 0.18 does not expose the `/dev/fuse` fd.** A native ring cannot
   attach to a `fuser`-managed session; a full F2 driver would own the session.

Consequently `orfs mount --transport fuse-uring` performs the real `INIT`
negotiation, records the precise reason, and continues as F1/F0 with
**byte-identical contents**. `orfs doctor` reports F2 as *not usable* with the
exact reason rather than merely "plausible". Zero-copy is opt-in and
capability-checked (`CAP_SYS_ADMIN`) and, because F2 does not engage here, is not
exercised; no zero-copy performance number is claimed.
