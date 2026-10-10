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

The containerized workflow provides toolchain isolation, **not kernel
isolation**. FUSE mounts and `io_uring` inevitably run against the host kernel
(see `scripts/lib.sh`). The FUSE mount tests additionally require the host's
`/dev/fuse`, `SYS_ADMIN`, and unconfined AppArmor/seccomp, and are confined to
`scripts/container-fuse-test.sh`.

## 3. Accelerated reads are exactness-preserving, not free

The EKBLOOM read planner only uses a concealed structure when it is compatible
(same inode, inode version, and committed root), certified, and measured to be
worth it; otherwise it falls back to the authoritative extent read. Absolute
latencies in the evidence come from unoptimized test builds; the *selection*, not
the absolute figure, is the point.
