# FUSE passthrough for immutable snapshots (Phase 21)

> **Goal.** Make the fastest read never invoke the daemon. For an immutable
> historical snapshot — a read-only view pinned to a committed root — a read can
> be served **directly by the kernel** from a private, byte-exact backing file,
> bypassing the OrFS FUSE session entirely.

This is the Linux FUSE **passthrough** feature. OrFS uses it only where it is
provably safe: a file whose bytes no ordinary descriptor can mutate. That is
exactly a committed snapshot view, and nothing else.

## 1. Mechanism (verified against the running kernel)

The daemon:

1. **registers a backing file** with the kernel by issuing an ioctl on its
   `/dev/fuse` descriptor, receiving a small integer **backing id**;
2. **attaches** that backing id to a file it is opening, in the `OPEN` reply,
   by setting `FOPEN_PASSTHROUGH` in `fuse_open_out::open_flags` and writing the
   backing id into `fuse_open_out::backing_id`.

From then on, `read(2)`/`write(2)`/`splice(2)`/`mmap(2)` on that *open file
description* go straight to the backing file (`fs/fuse/passthrough.c`,
`fuse_passthrough_read_iter` → `backing_file_read_iter`); no `FUSE_READ` is ever
sent to the daemon.

### 1.1 The exact UAPI (FUSE ABI 7.45)

Transcribed from the running kernel's `uapi/linux/fuse.h`
(`FUSE_KERNEL_VERSION 7.45`, `CONFIG_FUSE_PASSTHROUGH=y`) and cross-checked
against `fs/fuse/{inode,backing,dev,iomode}.c`:

```c
#define FUSE_PASSTHROUGH        (1ULL << 37)   /* INIT capability (flags2 bit 5) */
#define FOPEN_PASSTHROUGH       (1 << 7)       /* fuse_open_out.open_flags */

struct fuse_backing_map {                       /* argument to BACKING_OPEN */
    int32_t  fd;        /* an open fd of the backing regular file */
    uint32_t flags;     /* must be 0 */
    uint64_t padding;   /* must be 0 */
};

#define FUSE_DEV_IOC_MAGIC        229
#define FUSE_DEV_IOC_BACKING_OPEN  _IOW(FUSE_DEV_IOC_MAGIC, 1, struct fuse_backing_map)
#define FUSE_DEV_IOC_BACKING_CLOSE _IOW(FUSE_DEV_IOC_MAGIC, 2, uint32_t)
```

On x86_64 (`_IOC_WRITE == 1`) these are:

| ioctl | number |
|---|---|
| `FUSE_DEV_IOC_BACKING_OPEN` | `1074849025` (`0x4010E501`) |
| `FUSE_DEV_IOC_BACKING_CLOSE` | `1074062594` (`0x4004E502`) |

`FUSE_DEV_IOC_BACKING_OPEN` **returns the backing id** (`> 0`) or a negative
errno; `FUSE_DEV_IOC_BACKING_CLOSE` takes a pointer to the id and removes the
kernel's reference. A unit test (`src/fuse_native.rs`) recomputes both numbers
from the `_IOW` formula and decodes the fields, so the transcription cannot
silently drift.

### 1.2 Negotiation and kernel-side gates

At `FUSE_INIT`, OrFS sets `FUSE_INIT_EXT` in `flags` (so the kernel reads
`flags2`) and, when passthrough is requested, `FUSE_PASSTHROUGH` in `flags2`
plus `max_stack_depth = 2`. The kernel enables `fc->passthrough` only when
(`fs/fuse/inode.c`, `process_init_reply`):

* `CONFIG_FUSE_PASSTHROUGH` is enabled,
* the reply sets `FUSE_PASSTHROUGH`,
* `0 < max_stack_depth <= FILESYSTEM_MAX_STACK_DEPTH` (2), and
* `FUSE_WRITEBACK_CACHE` is **not** set (OrFS never sets it).

The registration ioctl then succeeds only if (`fs/fuse/backing.c`,
`fuse_backing_open`):

* `fc->passthrough` was enabled **and** the caller is `capable(CAP_SYS_ADMIN)`,
* `map.flags == 0 && map.padding == 0`,
* the referenced descriptor is a **regular file**, and
* the backing file's superblock stack depth is below `max_stack_depth`.

Attaching (`fs/fuse/iomode.c`) additionally requires that the open flags
contain only the passthrough-compatible set (`FOPEN_PASSTHROUGH`,
`FOPEN_DIRECT_IO`, `FOPEN_PARALLEL_DIRECT_WRITES`, `FOPEN_NOFLUSH`), and — once
an inode is open for passthrough — **every** subsequent open of that inode must
also use passthrough.

## 2. Version-qualified backing images

A passthrough-served read must return EXACTLY the authoritative bytes for that
committed version. OrFS therefore materializes a **write-once, digest-verified**
copy of the file — a *manifested* structure, never the source of truth.

**Identity.** A backing image is qualified by

```
(volume uuid, committed root, inode, inode version, inode generation)
```

and, on disk, by the **content digest** (BLAKE3), so a different committed
version can never be mistaken for the same image.

**Location.** Beneath the volume, in a concealed area (hidden from the
namespace, but fully accounted):

```
<volume>/.or_passthrough/<uuid>/<root>/<inode>-<version>/
    manifest.json    # {schema, uuid, root, inode, inode_version, generation, size, digest, image}
    image            # the materialized bytes
```

**Materialization** (`src/passthrough.rs`):

* bytes come from the *same* code path a daemon-served read uses
  (`Snapshot::read_at`), so equivalence is by construction;
* the image is streamed to a temporary file, `fsync`ed, then published by atomic
  `rename`; the manifest is written the same way;
* on a miss the image is rebuilt; on a hit the manifest must match the identity
  exactly, the length must match, and the recomputed BLAKE3 must equal the
  recorded digest, otherwise it is treated as a miss and rebuilt.

**Accounting** (`src/stats.rs`): the total bytes under `.or_passthrough/` appear
as **`M_passthrough`** and are included in `M_total`, so the concealed structure
is visible to administrative accounting and never hidden.

## 3. Lifetime rules

* **Registration is refcounted per image path.** The first open of a version
  registers the backing (`FUSE_DEV_IOC_BACKING_OPEN`) and pins it; concurrent
  opens of the same version reuse the same backing id (refcount bump) without a
  second registration.
* **Pin for the open-file lifetime; unpin on close.** Each file handle records
  the image it pinned. On `RELEASE` the refcount drops; on the **last** release
  the kernel reference is dropped with `FUSE_DEV_IOC_BACKING_CLOSE` and the
  userspace descriptor is closed.
* **Clean teardown.** The session also releases every live registration while
  the connection is still open (before the `/dev/fuse` fd closes), so unmount
  never leaves a dangling backing reference.
* **A version mismatch is a different identity, never a silent reuse.** A
  different `root` (or inode version) yields a different directory, a different
  image, and a different backing id. There is no code path that reuses a backing
  across versions (proved by `tests/fuse_passthrough.rs`).
* **Failure is always a fallback, never a wrong answer.** A missing/denied
  registration, a short authoritative read, or a materialization error leaves the
  open without passthrough; reads are then served by the daemon with identical
  bytes.

## 4. Read-only-only policy (and the live-file prohibition)

Passthrough is offered by **exactly one** core method,
`OrfsCore::passthrough_backing`, which **defaults to `None`**. Only
`Snapshot` (a read-only historical view) overrides it, and only for regular
files. The live `Namespace` core — whose files any descriptor can mutate — never
returns a backing, so **no mutable file is ever passthrough-eligible**. The
decision is further restricted to clean read-only opens (`O_RDONLY`, no
`O_DIRECT`/direct-io) on the native session.

This is the review's core constraint: passthrough is never enabled for a file
that another descriptor could mutate. A future version that wants passthrough
for a mutable file must first give that file a **distinct identity per committed
version** so its bytes cannot change behind an open descriptor.

## 5. Which transport can use it

Passthrough requires the **native F2 session** (`src/fuse_native.rs`), the only
transport that owns the `/dev/fuse` descriptor. The classical `fuser` transport
(`F0`/`F1`) cannot register backing files, because `fuser` 0.18 does not expose
that fd. A snapshot mounted without F2 (or on a kernel that does not offer
`FUSE_PASSTHROUGH`) simply serves reads through the daemon.

## 6. Measured results

`evidence/correctness/fuse-passthrough.json` (engagement + byte-exactness) and
`evidence/performance/passthrough.json` (latency), both generated under
`scripts/container-fuse-test.sh` on kernel `7.2.9-2-cachyos`, FUSE ABI 7.45,
`fuse.enable_uring=Y`, `CONFIG_FUSE_PASSTHROUGH=y`.

**Engagement proof** — after a read of a 256 KiB snapshot file:

* daemon-side read counter `daemon_reads` = **0** (unchanged across the read),
* `passthrough_opens` = 1/2, `passthrough_registered` = 1, `passthrough_reused` ≥ 1,
  `passthrough_releases` ≥ 1, `passthrough_fallbacks` = 0,
* the read bytes equal an independent authoritative replay (`fs::read` byte-for-byte
  against `Snapshot::read_at`).

**Latency** (full-file 256 KiB read, 200 iterations, page-cache warm):

| arm | p50 | mean |
|---|---|---|
| **passthrough** (kernel-served) | **16.6 µs** | 18.2 µs |
| daemon-served (native F2, no passthrough) | 446 µs | 491 µs |
| cached plain file (ext4) | 3.2 µs | 3.2 µs |

Passthrough is **≈ 27×** faster than the daemon-served read of the same bytes,
and within ≈ 5× of a raw cached `read(2)` — the residual is the FUSE file's
`read_iter` entry, which remains but no longer crosses `/dev/fuse`.

## 7. Limitations

* **`CAP_SYS_ADMIN` is required by the kernel** for `FUSE_DEV_IOC_BACKING_OPEN`
  (`fs/fuse/backing.c`), for resource-accounting and filesystem-stacking-safety
  reasons. In the test workflow the passthrough court therefore runs in a **root**
  container: the project's usual non-root uid runs with an empty effective
  capability set (Docker `CapEff=0`), so the ioctl correctly returns `EPERM` and
  OrFS falls back. This is a kernel policy, not an OrFS choice.
* **Native F2 only.** F0/F1 cannot register backings; see §5.
* **Read paths only.** OrFS attaches passthrough only for read-only opens of an
  immutable snapshot; the write path is never passthrough-eligible. `mmap` and
  `splice` may also be served by the kernel for those opens, but are not
  separately asserted by the court.
* **Revocation.** Closing the last handle releases the registration; an already
  attached open holds its own kernel file reference and continues to read the
  immutable image, which cannot change, so no read can be served stale bytes.
* **No portability claim.** The measured figures are warm-cache single-run on one
  host/container (see §6) and are not a portable benchmark.
* **Cost.** Materialization writes a full copy of the file once (space for speed),
  which is the deliberate concealed-expansion tradeoff; the copy is version-
  qualified and accounted as `M_passthrough`.
