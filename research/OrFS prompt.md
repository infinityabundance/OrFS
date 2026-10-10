# OrFS — Native Rust Implementation Directive

## Build the Non-Withdrawal, Concealed-Expansion FUSE and io_uring Filesystem

**Project:** OrFS  
**Repository:** `orfs`  
**Rust crate:** `orfs`  
**Executable:** `orfs`  
**Platform:** Linux  
**Filesystem interface:** FUSE  
**Asynchronous I/O:** `io_uring`  
**Acceleration engine:** EKBLOOM  
**Persistence:** Append-only, non-withdrawal  
**Architecture:** One native-Rust filesystem crate  
**Execution:** Minimal pinned Docker Hub containers only  
**Development:** Independent subagents, adversarial verification, reproducible evidence

# 0. Mission

Implement **OrFS**, a real, mountable, native-Rust Linux filesystem that combines permanent authoritative history with concealed physical expansion for maximum execution speed.

OrFS has two fundamental laws.

### Law I — Non-withdrawal

Committed authoritative history is never overwritten, physically truncated, reused, or garbage-collected.

Every committed transition extends the previous authoritative history.

\[
L_{n+1}=L_n\oplus\Delta_n
\]

The prior history remains.

### Law II — Concealed expansion

Additional operational structures are physically manifested behind the ordinary logical filesystem namespace.

These structures deliberately consume more storage, memory, and construction work to accelerate future operations.

The governing objective is:

\[
\boxed{\textbf{Spend manifested space to maximise speed.}}
\]

EKBLOOM provides the primary state-history and multi-step transition manifestation engine.

OrFS provides the persistent historical substrate, filesystem namespace, transactional machinery, asynchronous I/O, and operational integration.

The implementation must deliver an actual working filesystem, not another architecture proposal.

It must:

1. Mount through FUSE.
2. Support real filesystem operations.
3. Preserve committed authoritative history.
4. Reconstruct namespace state from that history.
5. Support historical root snapshots.
6. Use `io_uring` for backing-store operations.
7. Support a feature-gated FUSE-over-`io_uring` transport.
8. Generate concealed EKBLOOM structures asynchronously.
9. Select verified manifested structures on actual read paths.
10. Demonstrate correctness under crashes, concurrency, and hostile inputs.
11. Measure execution speed against physical manifestation.
12. Produce independently reproducible evidence.

Do not replace OrFS with an ordinary copy-on-write filesystem.

Do not replace EKBLOOM with conventional indexes or caches and claim that the central machinery has been implemented.

Do not reinterpret the governing objective.

Do not treat expanding physical storage as an architectural defect.

Do not produce speculative performance claims.

Build the machine.

---

# 1. Authoritative design and precedence

Use the supplied OrFS specification and subsequent design decisions as the architectural foundation.

Preserve:

- The authoritative `or.log`.
- The non-withdrawal rule.
- The absence of authoritative space reclamation.
- Append-only logical transitions.
- Root-by-offset historical identity.
- Tombstone-based logical removal.
- Committed-prefix snapshots.
- Rebuildable indexes.
- Concealed `.or_bloom` storage.
- EKBLOOM acceleration.
- Asynchronous manifestation construction.
- Logical namespace simplicity.
- Full physical accounting.

The original conceptual terminology may be retained in explanatory documentation, but the implementation must use precise filesystem semantics.

**OrFS** is the filesystem.

**EKBLOOM** is the acceleration technology.

Do not introduce additional competing product names.

When an originating specification contains an underspecified mechanism, preserve its intended invariant and solve the implementation problem explicitly.

Do not silently redefine the invariant to make implementation easier.

---

# 2. Hard development constraints

## 2.1 One filesystem crate

Use exactly one primary Rust crate:

```toml
[package]
name = "orfs"
```

The repository must not become a multi-crate workspace.

Internal modules, integration tests, benchmarks, and optional binaries within the same package are permitted.

EKBLOOM must be consumed as an independently versioned native-Rust dependency, pinned to a verified version or Git commit.

Do not copy EKBLOOM's source into OrFS.

Do not create a separate EKBLOOM implementation inside OrFS.

Do not add speculative service processes, distributed nodes, microservices, or unrelated infrastructure.

Keep the architecture cohesive.

## 2.2 Native Rust

The filesystem core must be implemented in Rust.

Use mature Rust libraries for Linux interfaces where appropriate.

Initial verified dependency candidates:

- `fuser = "=0.18.0"`
- `io-uring = "=0.7.15"`
- `libc`
- `nix`
- `clap`
- `tracing`
- `tracing-subscriber`
- `proptest`
- `criterion` or `divan`

Check compatibility with the selected Rust toolchain before finalizing.

Avoid unnecessary dependencies.

The principal transaction engine, log machinery, extent handling, state interpretation, recovery, and acceleration integration must be native Rust.

Do not depend on C libfuse as the main filesystem implementation.

For advanced kernel interfaces not supported by the initial Rust adapter, implement an independently reviewed native-Rust transport module using the documented Linux UAPI.

## 2.3 Docker-only execution

All project execution occurs inside minimal pinned Docker Hub containers.

The host may launch Docker, supply a test directory, and inspect results.

Do not run project compilation, tests, fuzzers, benchmarks, or filesystem experiments directly on the host.

Start from the official Rust image:

```text
rust:1.99.0-slim-bookworm
```

Resolve its exact registry digest and pin it.

Do not fabricate the digest.

Use a multi-stage Dockerfile where useful.

Separate:

- a minimal reproducible build/test image;
- a mount-testing image with necessary FUSE utilities;
- a kernel-interface-testing image with explicit required permissions.

Do not run privileged containers by default.

For actual FUSE mount tests, use only the device access, user namespaces, mount namespace configuration, and capabilities that the selected environment demonstrably requires.

Never silently modify the host's kernel configuration, security policy, or global mount state.

Containerized FUSE and `io_uring` still depend on the host kernel. Record that dependency and do not claim complete kernel isolation.

## 2.4 Mandatory independent subagents

Use independent subagents throughout substantial development.

At minimum:

| Subagent | Responsibility |
|---|---|
| Log architect | Physical non-withdrawal, segmentation, roots |
| Transaction engineer | Commit ordering, atomic publication, durability |
| FUSE engineer | Kernel operation semantics and POSIX behavior |
| `io_uring` engineer | SQE/CQE lifecycle, registered buffers, asynchronous I/O |
| Kernel transport engineer | FUSE-over-`io_uring` UAPI |
| Namespace engineer | Inodes, dentries, extents, snapshots |
| EKBLOOM integrator | Correct manifested read paths |
| Recovery adversary | Torn writes, incomplete transactions, corrupted logs |
| Security adversary | Hostile inputs, permissions, isolation |
| Performance engineer | Throughput, latency, cache behavior, physical expansion |
| Reproducibility auditor | Containers, tests, machine-generated evidence |

Subagents must perform independent analysis where appropriate.

They should submit executable implementations, minimal counterexamples, failing tests, corrected invariants, and measured evidence.

Do not use subagents merely to produce multiple versions of the same summary.

If independent agent execution is unavailable, state that limitation explicitly.

---

# 3. Architecture

Implement four distinct functional planes.

```text
                         LINUX VFS
                             |
                  +----------+----------+
                  |                     |
              /dev/fuse          FUSE-over-io_uring
                  |               where supported
                  +----------+----------+
                             |
                      FUSE dispatcher
                             |
                  Transport-neutral core
                             |
             +---------------+---------------+
             |               |               |
        Namespace        Versioned        Access
          engine         inode state       planner
             |               |               |
             +---------------+---------------+
                             |
                      Commit sequencer
                             |
                    AUTHORITATIVE LOG
                             |
                          or.log
                             |
                     Committed roots
                             |
                  +----------+----------+
                  |                     |
             Rebuildable          EKBLOOM
                indexes           manifestation
                  |                     |
                  +----------+----------+
                             |
                    CONCEALED BODY
                             |
                         .or_bloom/
                             |
                       Fast read path
```

### Plane A — Authoritative history

Owns permanent records, transaction ordering, and committed roots.

### Plane B — Namespace interpretation

Maps the historical log into ordinary filesystem objects and metadata.

### Plane C — Manifested acceleration

Generates EKBLOOM structures and other optional operational views.

### Plane D — Linux transport and storage

Implements FUSE, backing `io_uring`, and advanced kernel interfaces.

Keep these planes independently testable.

A failure in Plane C must never corrupt Plane A.

A change to FUSE transport must not change filesystem semantics.

---

# 4. Physical non-withdrawal

The authoritative log is the primary source of truth.

Preserve the conceptual path:

```text
backing/or.log
```

Implement it as one logical append-only record stream backed by immutable physical segments.

Recommended layout:

```text
backing/
├── volume.meta
├── or.log/
│   ├── 0000000000000000.seg
│   ├── 0000000000000001.seg
│   └── ...
├── index/
│   └── ...
└── .or_bloom/
    ├── ekbloom/
    ├── trigram/
    ├── suffix/
    ├── image/
    ├── directory/
    └── manifests/
```

The segment abstraction is necessary to reconcile permanent physical retention with recovery after incomplete appends.

A torn write may leave a partial physical tail.

That tail must not become part of the committed logical filesystem state.

Do not truncate the physical segment to remove it.

Instead:

1. Preserve the original segment.
2. Mark its valid committed boundary.
3. Quarantine its incomplete tail from logical replay.
4. Start a fresh physical segment.
5. Continue the canonical logical stream.

Distinguish:

- Physical bytes ever written.
- Valid physical records.
- Committed authoritative records.
- Canonical logical log positions.

The logical `or.log` must remain continuously addressable even if physically distributed across multiple segments.

Implement a segment locator that maps canonical logical offsets to immutable physical storage.

No committed authoritative byte may be physically rewritten or removed.

---

# 5. Historical root identity

A committed historical root is a logical byte offset:

\[
R=\operatorname{committed\_end\_offset}.
\]

An external historical identity is:

\[
(\text{volume UUID},R).
\]

Do not use a content hash as the historical root.

Checksums are permitted for corruption detection.

They do not replace offset identity.

Each committed root must identify exactly one valid historical filesystem state.

Never publish a root pointing into:

- an incomplete record;
- an uncommitted transaction;
- a corrupt record;
- a physical gap;
- a partially synchronized commit.

A historical snapshot consists of the authoritative transactions committed through its root.

For every valid root \(R\):

\[
\operatorname{Replay}(L[0:R])
\]

must reconstruct the exact corresponding logical namespace.

This is a mandatory tested invariant.

---

# 6. Authoritative record format

Create a precise, versioned binary record format.

Every record has:

```text
HEADER
    magic
    version
    record_type
    header_length
    payload_length
    sequence_number
    transaction_id
    inode_id
    previous_inode_record
    flags
    header_check

PAYLOAD
    typed binary payload

FOOTER
    total_record_length
    record_check
    end_marker
```

Specify exact byte widths and offsets in `docs/ON_DISK.md`.

Use little-endian wire integers.

Never serialize native Rust structs by blindly copying their memory representation.

Required record types include:

```text
VOLUME_GENESIS

TX_BEGIN
TX_COMMIT
TX_ABORT

INODE_CREATE
INODE_METADATA
INODE_SETATTR

DENTRY_ADD
DENTRY_REMOVE
DENTRY_RENAME

DATA_EXTENT
DATA_ZERO_RANGE
FILE_RESIZE

SYMLINK_CREATE
HARDLINK_ADD
HARDLINK_REMOVE

XATTR_SET
XATTR_REMOVE

SNAPSHOT_ROOT
INDEX_CHECKPOINT
```

Unknown mandatory record types must produce a controlled compatibility error.

Unknown optional records may be skipped only when the wire format explicitly allows it.

Use checked length arithmetic throughout.

Reject invalid record boundaries before allocating payload buffers.

---

# 7. Transaction semantics

Filesystem mutations must be represented as atomic logical transactions.

Example file creation:

```text
TX_BEGIN
INODE_CREATE
DENTRY_ADD
TX_COMMIT
```

Example atomic rename:

```text
TX_BEGIN
DENTRY_REMOVE
DENTRY_ADD
INODE_METADATA
TX_COMMIT
```

The visible namespace must never expose a partially applied transaction.

Use a single authoritative commit order.

Define explicit transaction states:

```text
PREPARED
RESERVED
SUBMITTED
DATA_COMPLETED
COMMIT_COMPLETED
PUBLISHED
DURABLE
FAILED
```

Do not assume submission order equals completion order.

Do not assume an I/O completion means power-loss durability.

The implementation must distinguish ordinary write acknowledgment from durable synchronization.

## 7.1 Acknowledgment

For the initial write-through profile, return successful mutations only after their accepted authoritative transaction is complete and published according to the documented acknowledgment contract.

For `fsync`, ensure all necessary underlying data and commit records have become durable according to the backing filesystem's guarantees.

For `O_SYNC` and equivalent modes, honor the requested synchronization semantics.

## 7.2 Failure

If a transaction fails before commit, it is not visible as a committed state.

Its physical bytes may remain in the append-only body.

The next transaction must not reuse them.

Any partial transaction must be ignored during logical replay.

---

# 8. Exact `io_uring` ordering

Use the Rust `io-uring` crate for backing operations.

The following is non-negotiable:

> Submitting an SQE for a write before an SQE for an fsync does not, by itself, establish that the fsync includes the write.

Implement explicit ordering using the mechanisms supported by the selected kernel:

- linked SQEs;
- `IOSQE_IO_DRAIN`;
- completion barriers;
- or explicit dependency-controlled submissions.

Select the mechanism based on real correctness and performance measurements.

Do not use `IOSQE_IO_HARDLINK` as a replacement for failure-sensitive dependency handling.

Validate every CQE.

Associate every CQE with its exact operation using stable `user_data` identifiers.

Handle:

- negative CQE results;
- short writes;
- partial reads;
- canceled operations;
- ring saturation;
- interrupted submissions;
- lost worker availability;
- resource exhaustion.

A positive but short write is not a complete successful record.

Loop or retry as appropriate while preserving the original append reservation.

Registered buffers must remain valid until the relevant operations can no longer access them.

Cancellation is not proof that a buffer is immediately safe to release.

Use explicit ownership and completion tracking.

---

# 9. Ring architecture

Implement three logical I/O responsibilities.

### Ring W — Authoritative writer

Owns ordered log writes and durability barriers.

Only the commit sequencer may assign authoritative logical positions.

Support batching without sacrificing transaction visibility.

### Ring R — Read engine

Performs concurrent reads of immutable segments and manifested structures.

Support bounded read-ahead.

Readers must pin a valid committed root or inode version.

### Ring B — Manifestation persistence

Writes and reads generated EKBLOOM and other operational structures.

Bloom construction itself runs on CPU workers, not magically inside `io_uring`.

Start with a small, measurable ring configuration.

Allow responsibilities to share or split physical rings when benchmarks justify it.

Do not hardcode one physical ring per CPU without evidence.

Implement bounded queues and backpressure.

Optional manifestation jobs must not starve authoritative commits.

---

# 10. Inodes, directories, and extent mapping

Implement a proper versioned inode model.

Each inode has:

```text
inode ID
generation
type
permissions
uid/gid
link count
logical length
timestamps
extended attributes
current version
historical versions
logical extent map
```

Names belong to directory entries, not to the inode's permanent identity.

Directory relationships are:

\[
(\text{parent inode},\text{name})\mapsto\text{child inode}.
\]

Support hard links correctly.

Renaming a directory entry must not change inode identity.

## 10.1 Arbitrary writes

Every write appends new immutable data records.

The active inode's logical extent mapping changes through a committed transaction.

An overwrite of existing logical bytes must not overwrite their historical storage.

Support:

- writes at offset zero;
- middle-of-file writes;
- EOF writes;
- overlapping writes;
- sparse writes;
- writes beyond EOF;
- partial writes;
- concurrent writes.

## 10.2 Truncation

A shrink operation appends a new logical size.

It does not reclaim historical extents.

A subsequent extension must not resurrect previously truncated bytes.

Newly exposed logical ranges must obey correct zero-fill semantics.

## 10.3 Unlink

An unlink appends a directory-entry removal.

Historical records remain.

Open file handles remain valid under documented POSIX behavior.

## 10.4 Rename

Implement atomic rename transactions.

Support and test:

- ordinary rename;
- overwrite destination;
- `RENAME_NOREPLACE`;
- `RENAME_EXCHANGE` where advertised;
- rename across directories;
- directory cycle rejection;
- open handles during rename.

---

# 11. Rebuildable namespace index

The authoritative log must be sufficient to reconstruct the filesystem without any derived index.

Implement rebuildable mappings:

```text
inode → current version
(parent, name) → child inode
inode → logical extent map
inode → xattrs
root → committed snapshot
```

Start with a deterministic native-Rust implementation.

Select hot data structures based on measured behavior.

Do not make SQLite or another database the authoritative source of truth.

A derived persistent index is permissible if it accelerates mounting or lookup.

If the index is absent or corrupted, rebuild it from `or.log`.

If an index disagrees with authoritative replay, the log wins.

## 11.1 Index checkpoints

Implement periodic authoritative index-checkpoint records.

Mounting should:

1. discover a valid committed checkpoint;
2. load and validate it;
3. replay subsequent committed records;
4. reconstruct the latest state.

If a checkpoint is corrupt, fall back to an earlier checkpoint or full replay.

Do not claim constant-time mount merely because checkpoints exist.

Measure the actual recovery and replay cost.

---

# 12. Historical snapshots

Support read-only historical roots.

A root identifies a committed prefix of the logical log.

Expose an API equivalent to:

```rust
pub fn open_snapshot(
    volume: &OrfsVolume,
    root: HistoricalRoot,
) -> Result<Snapshot, OrfsError>;
```

Snapshot reads must return:

- historical file contents;
- historical file sizes;
- historical metadata;
- historical directory entries;
- historical symlink targets;
- historical permissions as defined by the snapshot access policy.

A snapshot must not observe later writes.

Snapshot references must be stable across remounts.

Provide a command:

```text
orfs snapshot list
orfs snapshot inspect <root>
orfs snapshot mount <root> <mountpoint>
```

Snapshot mounts are read-only.

A historical root number is a reference to history, not a substitute for storing history.

Do not claim that a root xattr alone contains sufficient bytes to rebuild the complete volume.

A separate historical-carrier export operation may be implemented for self-contained snapshots.

---

# 13. Traditional FUSE transport

Implement a correct native-Rust FUSE adapter using `fuser`.

The initially verified version is `0.18.0`.

Use its current typed interfaces rather than copying obsolete examples from older releases.

Keep the filesystem core transport-neutral.

Implement all operations advertised by the selected compatibility profile.

Mandatory operations:

```text
init
destroy

lookup
forget
getattr
setattr

opendir
readdir
readdirplus
releasedir

open
read
write
flush
fsync
release

create
mknod
mkdir
unlink
rmdir
rename
link
symlink
readlink

getxattr
setxattr
listxattr
removexattr

statfs
access
fallocate
lseek
copy_file_range

getlk
setlk
flock
```

Where the Rust API represents locking operations differently, use the actual supported interface.

Unsupported operations must return correct documented errors.

Do not silently advertise unsupported kernel capabilities.

Do not ship a filesystem that mounts successfully but implements only trivial reads and writes.

---

# 14. FUSE semantic correctness

Test every supported operation against Linux VFS expectations.

Particular attention is required for:

### Inode lookup accounting

`lookup` and `forget` counts must be managed correctly.

`readdirplus` also affects lookup references.

An inode must not be incorrectly reused while the kernel may retain references.

### File handles

Distinguish inode identity from open handle identity.

An unlinked file may remain accessible through an existing handle.

### Directory iteration

Support stable directory iteration cookies.

Do not assume a cookie is simply an array index that remains valid after arbitrary mutations.

Use a documented snapshot or mutation-consistency policy for directory handles.

### Flush versus fsync

`flush` is not automatically a durable synchronization barrier.

`fsync` must implement the required durability behavior.

### Sparse files

Support tested `SEEK_DATA` and `SEEK_HOLE` behavior if advertised.

### Permissions

Enforce the chosen permission model consistently across lookup, read, write, xattrs, snapshots, and query interfaces.

Do not permit private historical content to leak through the concealed namespace.

---

# 15. FUSE caching

Start in conservative write-through mode.

Expose cache configuration explicitly.

Test:

- write-through;
- direct I/O;
- read caching;
- readahead;
- writeback caching.

Do not enable writeback caching until OrFS's acknowledgment and visibility semantics have been verified under it.

In Linux FUSE writeback-cache mode, `write(2)` may return before the userspace filesystem receives the corresponding write request.

The implementation must account for that distinction.

Do not report EKBLOOM speed gains when the observed improvement comes solely from page-cache behavior.

Use appropriate inode and directory-entry invalidation.

A newly completed EKBLOOM bloom must not alter visible file contents.

It should normally change only the internal read strategy.

---

# 16. FUSE-over-io_uring

Implement an optional advanced FUSE transport using the documented Linux FUSE-over-`io_uring` UAPI.

This is a real implementation requirement for capable test environments, not an empty feature flag.

The current kernel interface includes:

```text
FUSE_IO_URING_CMD_ADD_QUEUE
FUSE_IO_URING_CMD_ADD_BUFPOOL
FUSE_IO_URING_CMD_REGISTER
FUSE_IO_URING_CMD_COMMIT_AND_FETCH
```

These operations are carried through `IORING_OP_URING_CMD`.

Implement:

1. capability discovery;
2. queue creation;
3. payload-buffer pool registration where supported;
4. entry registration;
5. CQE request handling;
6. reply commit;
7. fetch-next lifecycle;
8. request cancellation;
9. safe shutdown;
10. automatic fallback.

Do not assume every FUSE operation arrives through an I/O ring.

Maintain the classical `/dev/fuse` path for operations still requiring it, including applicable notifications and interrupts.

Do not use outdated experimental command names in production code.

Read the exact UAPI headers for the selected kernel.

If the Rust `fuser` version cannot expose the required interface, implement a narrowly scoped native-Rust transport adapter rather than discarding the advanced transport objective.

## 16.1 Three transport profiles

Implement:

**F0 — Traditional FUSE**

`/dev/fuse` transport with ordinary backing I/O.

**F1 — Traditional FUSE + backing io_uring**

`/dev/fuse` transport with asynchronous backing operations.

**F2 — FUSE-over-io_uring + backing io_uring**

Supported FUSE requests use the advanced ring transport, while the traditional path remains available where required.

F2 must negotiate support at runtime.

Unsupported kernels must fall back cleanly without changing filesystem contents.

---

# 17. FUSE registered buffers and zero-copy

Investigate the modern FUSE UAPI buffer-pool mechanism.

Implement the supported queue setup sequence correctly.

The advanced transport may use shared registered payload buffers for both FUSE requests and backing I/O.

This may reduce copying and repeated buffer mapping.

Measure the actual result.

Do not assume registered buffers always improve performance.

Implement buffer lifetime tracking with strict ownership.

Investigate FUSE zero-copy only after the normal F2 path is correct.

The kernel currently imposes additional privilege requirements, including `CAP_SYS_ADMIN`, for the documented zero-copy path.

Zero-copy must be opt-in, capability-checked, and independently benchmarked.

Do not require privileged zero-copy support for ordinary mounts.

---

# 18. Concealed EKBLOOM integration

EKBLOOM is a first-class dependency and acceleration engine.

OrFS must use EKBLOOM's actual public API.

Do not duplicate its mathematical state machinery.

For an eligible object, OrFS may manifest:

```text
sparse state checkpoints
dense state checkpoints
full retained state history
certified four-step blooms
deeper transition blooms
regional blooms
path-specific blooms
```

These are physical operational structures.

They may exceed the logical object's size.

That is permitted.

Each manifested generation must reference:

```text
volume identity
inode identity
inode version
authoritative root
EKBLOOM version
manifestation profile
logical range
physical range
construction parameters
certification state
integrity information
```

A bloom built for one inode version must not be used against a different version unless exact compatibility has been established.

---

# 19. Background manifestation

After a successful authoritative write:

```text
Commit authoritative transaction
            |
Publish new inode version
            |
Enqueue EKBLOOM job
            |
Build operational manifestation
            |
Verify logical equivalence
            |
Write concealed physical body
            |
Commit manifested generation
            |
Make available to readers
```

The foreground write must not wait for optional bloom construction unless the caller explicitly requests synchronous manifestation.

Use bounded queues.

Use cancellation for obsolete jobs.

If a job is canceled after writing some physical bloom data, the incomplete generation must remain uncommitted and inaccessible to ordinary reads.

A later cleanup policy may reclaim disposable acceleration structures according to the selected acceleration retention policy.

It must never remove authoritative log history.

Full-retention EKBLOOM histories must obey their own declared non-withdrawal guarantee.

---

# 20. Manifested read path

The read planner must operate on the exact committed inode version.

Conceptually:

```rust
fn read_at(
    &self,
    inode: InodeId,
    root: HistoricalRoot,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, OrfsError>;
```

The planner evaluates available compatible structures.

Potential paths:

```text
exact EKBLOOM path bloom
certified EKBLOOM transition bloom
full manifested state
regional bloom
sparse checkpoint
ordinary logical extent read
```

Select according to measured performance for the workload.

Do not simply always choose the largest structure.

The objective is speed.

If a bloom is:

- absent;
- incomplete;
- corrupt;
- built for the wrong version;
- uncertified for the requested domain;

reject it and use a valid alternative.

Logical output must remain identical.

A missing EKBLOOM structure must never make the authoritative file unreadable.

---

# 21. Additional operational manifestations

Implement the optional acceleration families defined by the OrFS specification.

## 21.1 Trigram index

Generate positional trigram structures for byte-oriented substring searches.

Maintain source-version identity.

Return exact candidate positions.

Verify matches against logical file content where required.

Do not claim fixed performance improvements before benchmarking.

## 21.2 Suffix structure

Investigate a suffix automaton or a comparable structure.

Distinguish substring existence from enumerating all matching positions.

Measure both construction cost and actual query speed.

## 21.3 Image pyramid

For supported image types, manifest multiresolution surfaces.

Treat image recognition, decoding, orientation, color space, and dimensions as explicit correctness concerns.

Do not use an image extension as proof of format.

All derived views remain tied to an authoritative inode version.

---

# 22. Query API

Provide a typed query API.

Do not make arbitrary-size searches depend on `getxattr`.

Extended attributes are not a suitable transport for unbounded result sets.

Implement:

```text
orfs query <path> --pattern <bytes>
```

and a corresponding library interface.

Support:

- exact byte patterns;
- streaming match positions;
- result limits;
- cancellation;
- consistent inode versions;
- permission enforcement;
- fallback scanning;
- asynchronous index generation.

A query must produce the same logical result whether or not a manifested index exists.

Benchmark equivalent query interfaces.

Ordinary `grep -r` must not be represented as using the index unless the implementation actually routes it through that index.

---

# 23. Filesystem statistics

Separate logical and physical accounting.

Track:

```text
logical live bytes
logical file count
authoritative historical bytes
uncommitted physical tail bytes
EKBLOOM manifested bytes
other acceleration bytes
index/checkpoint bytes
total physical allocated bytes
available backing capacity
```

Implement `statfs` accurately for the default production profile.

No free list does not mean infinite physical capacity.

Provide an optional explicitly experimental logical-plenum reporting mode if desired.

Do not expose fabricated unlimited physical capacity as a truthful default.

Physical administrative statistics must always remain available.

---

# 24. Capacity management

Non-withdrawal guarantees unbounded historical growth over time unless external limits stop further writes.

Implement:

- volume capacity policy;
- configurable authoritative reserve;
- soft and hard quotas;
- early `ENOSPC` detection;
- background bloom throttling;
- read-only transition on exhaustion;
- clear physical-growth diagnostics.

When storage becomes constrained, stop optional manifestation before it prevents authoritative operations from succeeding.

Do not silently reclaim authoritative history.

Do not disguise physical allocation failures.

A capacity estimate must consider the transaction's minimum required record and commit space, not merely its payload size.

---

# 25. Crash recovery

Implement deterministic recovery.

On mount:

1. discover valid volume metadata;
2. enumerate physical log segments;
3. validate segment order and identity;
4. scan record framing;
5. validate transaction boundaries;
6. locate the last valid committed root;
7. preserve incomplete physical tails;
8. reconstruct the canonical logical stream;
9. load a valid index checkpoint;
10. replay subsequent records;
11. rebuild missing indexes;
12. validate manifested generation manifests;
13. quarantine invalid acceleration;
14. expose the recovered namespace.

Distinguish:

- a harmless uncommitted tail;
- an incomplete commit;
- a malformed committed record;
- a missing committed segment;
- an unsupported format;
- physical corruption.

Do not silently skip corrupted committed history and pretend the volume remains complete.

Implement explicit degraded or read-only recovery modes where appropriate.

---

# 26. Durability model

Provide at least:

```text
ordered
sync
batched
```

Durability choices must have documented acknowledgment semantics.

For `sync`, acknowledge only after required durable operations complete.

For `ordered`, preserve transaction ordering and honor explicit synchronization calls.

For `batched`, permit coalesced synchronization while preserving the documented visibility and durability contract.

For newly created physical segments, account for directory-entry durability as well as file-data synchronization.

`fsync` on a file does not automatically guarantee the enclosing directory entry is durable.

Test all three durability modes independently.

Do not report a fast buffered-write result as equivalent to a durable synchronous-write result.

---

# 27. Concurrency

Use one authoritative commit order.

Permit concurrent reads against immutable committed views.

Use stable root/version references.

Avoid holding global locks during:

- disk I/O;
- bloom construction;
- long query execution;
- FUSE response transmission.

Atomic namespace transactions must remain indivisible.

Required concurrency tests:

- overlapping writes to one inode;
- writes to independent inodes;
- rename/unlink races;
- create/unlink races;
- open file during unlink;
- snapshot reads during writes;
- bloom publication during reads;
- mount recovery after incomplete concurrent activity.

Use Loom for suitable reduced concurrency models.

Do not claim lock freedom merely because atomic variables are present.

---

# 28. Filesystem security

Treat every backing record and every FUSE request as potentially hostile.

Implement:

- checked offsets and lengths;
- bounded allocations;
- raw Unix filename support;
- strict path traversal handling;
- valid inode references;
- permission enforcement;
- symlink safety;
- namespace/backend separation;
- xattr access rules;
- proper FUSE mount options;
- secure historical-view access;
- file-handle validation;
- no untrusted pointer casting;
- no uncontrolled recursion.

The backing directory must not be recursively exposed through the mounted filesystem.

Prevent accidental visibility of concealed manifests or historical deleted content through ordinary userspace queries.

Use safe Rust wherever practical.

Every unsafe block requires a documented safety invariant and focused tests.

---

# 29. Non-withdrawal privacy implications

Document the permanence guarantee accurately.

Logical deletion does not physically destroy historical content.

Consequently, OrFS is inappropriate for workflows requiring reliable physical deletion unless a separately specified data-retention and cryptographic policy addresses that requirement.

Do not advertise deletion as secure erasure.

Do not promise that a revoked namespace path makes the underlying historical bytes unrecoverable.

Historical access must be permission-controlled.

The physical backing store may need stricter access controls than the logical mount.

---

# 30. Performance methodology

The benchmark program must isolate distinct mechanisms.

Test at least:

| Configuration | FUSE transport | Backing I/O | Manifestation |
|---|---|---|---|
| F0 | Traditional | Conventional | None |
| F1 | Traditional | io_uring | None |
| F2 | io_uring | io_uring | None |
| E1 | Traditional | io_uring | EKBLOOM |
| E2 | io_uring | io_uring | EKBLOOM |

Where a kernel cannot support F2/E2, report them as unavailable.

Do not invent a result.

Keep workload, durability mode, cache state, and hardware consistent between comparable configurations.

Measure:

- sequential read throughput;
- sequential append throughput;
- random 4 KiB reads;
- random 4 KiB writes;
- one-byte random reads;
- metadata lookup;
- create/unlink;
- rename;
- directory enumeration;
- concurrent readers;
- fsync latency;
- mount time;
- recovery time;
- search latency;
- historical snapshot latency.

---

# 31. The EKBLOOM manifestation frontier

For a fixed logical object and workload, vary physical manifestation.

Let:

\[
M=\text{actual manifested bytes}.
\]

Measure:

\[
P(M)=\text{execution performance}.
\]

Investigate budgets including:

\[
0.5\times,1\times,2\times,4\times,8\times,16\times,32\times,64\times
\]

relative to logical size, when feasible.

A larger body is permitted.

A larger body is not automatically faster.

The best profile is the one that produces the highest measured performance for the selected workload.

Measure:

- sequential throughput;
- random single-symbol latency;
- random 4 KiB latency;
- random 64 KiB latency;
- P50/P95/P99;
- CPU cycles;
- instructions;
- cache misses;
- memory bandwidth;
- physical bytes;
- construction time.

The experiment must separate improvements caused by EKBLOOM manifestation from improvements caused by FUSE transport or page caching.

---

# 32. Benchmark controls

Use:

- `fio`;
- Criterion or Divan;
- `perf`;
- `hyperfine` where useful;
- deterministic corpus generators;
- targeted filesystem microbenchmarks.

Test:

- cold cache;
- warm page cache;
- cache-resident EKBLOOM tables;
- DRAM-resident structures;
- storage-backed reads;
- synchronous durability;
- buffered durability;
- multiple reader counts;
- multiple region sizes.

Do not use misleadingly weak baselines.

Report measured evidence rather than speculative speedups.

Every benchmark receipt must include hardware, kernel, container image, compiler, mount options, data size, and workload details.

---

# 33. POSIX compatibility court

Use applicable parts of:

- `pjdfstest`;
- xfstests generic tests;
- custom FUSE lifecycle tests;
- filesystem model-based tests.

Create deterministic model tests that compare OrFS logical behavior against a trusted ordinary filesystem for operations where semantics are expected to match.

Test:

```text
create
open
read
write
pread
pwrite
append
truncate
fallocate
rename
unlink
link
symlink
mkdir
rmdir
stat
chmod
chown
utimens
xattr
readdir
fsync
fdatasync
mmap
SEEK_DATA
SEEK_HOLE
```

Where a behavior is intentionally unsupported, document it and verify the correct error.

Do not claim full POSIX compatibility until the claimed test set passes.

---

# 34. Fault-injection court

Build a reusable failpoint system.

Inject failures at:

1. Before log reservation.
2. After reservation.
3. During record write.
4. After partial record write.
5. Before transaction commit.
6. During commit record write.
7. After commit completion.
8. Before publication.
9. After publication but before required synchronization.
10. During physical segment rollover.
11. During directory synchronization.
12. During index checkpoint creation.
13. During EKBLOOM construction.
14. During manifested generation publication.
15. During FUSE shutdown.

For each injected failure:

- terminate the relevant process;
- remount in an independent test run;
- verify the recovered committed root;
- verify logical contents;
- verify retained historical records;
- verify no incomplete manifestation was published.

Distinguish process-crash tests from actual power-loss tests.

A process kill does not simulate all storage reordering or device-cache failure modes.

For stronger power-loss evidence, use an appropriate controlled virtualized storage fault model when available, executed through the prescribed container workflow.

Never perform destructive fault testing against real user data or the host root filesystem.

---

# 35. Recovery and historical invariants

The following must hold after every successful recovery:

\[
R_{\mathrm{recovered}}
\]

identifies a complete committed transaction boundary.

All committed roots up to that point remain valid.

No uncommitted record is exposed as authoritative content.

No previous committed record is rewritten.

No invalid bloom is selected for ordinary reads.

The namespace reconstructed from the authoritative log matches the namespace that existed at the recovered root.

These are hard correctness requirements.

---

# 36. CLI

Implement one executable:

```text
orfs
```

Required commands:

```text
orfs init
orfs mount
orfs unmount

orfs inspect
orfs stat
orfs verify
orfs recover

orfs snapshot list
orfs snapshot inspect
orfs snapshot mount

orfs manifest
orfs grow
orfs query

orfs bench
orfs doctor
```

Representative usage:

```sh
orfs init ./backing

orfs mount ./backing ./mnt \
    --transport fuse \
    --backing-io uring \
    --durability ordered

orfs mount ./backing ./mnt \
    --transport fuse-uring \
    --backing-io uring

orfs inspect ./backing --json

orfs verify ./backing --deep

orfs snapshot list ./backing

orfs snapshot mount ./backing <root> ./snapshot-mnt

orfs manifest ./backing/example.bin \
    --profile bloom4

orfs query ./mnt/example.txt \
    --pattern "needle"

orfs bench ./backing \
    --workload random-4k \
    --output evidence/performance/random-4k.json
```

A command must not be advertised as operational if it is only a placeholder.

`doctor` should report real kernel and container capabilities, including whether FUSE-over-`io_uring` is usable.

---

# 37. Repository layout

Use a compact single-crate structure:

```text
orfs/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── Dockerfile
├── README.md
├── src/
│   ├── lib.rs
│   ├── main.rs
│   ├── error.rs
│   ├── volume.rs
│   ├── log.rs
│   ├── segment.rs
│   ├── record.rs
│   ├── transaction.rs
│   ├── commit.rs
│   ├── recovery.rs
│   ├── inode.rs
│   ├── directory.rs
│   ├── extent.rs
│   ├── namespace.rs
│   ├── snapshot.rs
│   ├── checkpoint.rs
│   ├── index.rs
│   ├── fuse.rs
│   ├── fuse_uring.rs
│   ├── uring.rs
│   ├── buffers.rs
│   ├── manifestation.rs
│   ├── query.rs
│   ├── permissions.rs
│   ├── stats.rs
│   └── verify.rs
├── tests/
│   ├── log_model.rs
│   ├── transaction_model.rs
│   ├── namespace_model.rs
│   ├── snapshot_model.rs
│   ├── fuse_integration.rs
│   ├── uring_integration.rs
│   ├── crash_recovery.rs
│   ├── manifestation.rs
│   └── hostile_files.rs
├── benches/
├── scripts/
├── docs/
└── evidence/
```

These are internal modules, not separate crates.

Merge or remove modules when unnecessary.

Keep the codebase coherent and maintainable.

---

# 38. Required documentation

Produce:

```text
docs/ORFS-SPEC.md
docs/ON_DISK.md
docs/LOG-INVARIANTS.md
docs/TRANSACTIONS.md
docs/FUSE-SEMANTICS.md
docs/IO_URING.md
docs/FUSE_URING.md
docs/EKBLOOM-INTEGRATION.md
docs/RECOVERY.md
docs/SECURITY.md
docs/PERFORMANCE.md
docs/LIMITATIONS.md
```

Every normative behavioral claim must have corresponding tests or an explicitly identified proof obligation.

Do not claim completed features in the README when they remain unimplemented.

Keep documentation synchronized with actual source behavior.

---

# 39. Required evidence

Generate machine-readable evidence:

```text
evidence/
├── correctness/
│   ├── log-replay.json
│   ├── committed-roots.json
│   ├── inode-semantics.json
│   ├── snapshot-equivalence.json
│   ├── posix-results.json
│   └── ekbloom-read-equivalence.json
├── recovery/
│   ├── torn-write.json
│   ├── commit-interruption.json
│   ├── segment-rollover.json
│   └── manifested-generation.json
├── performance/
│   ├── fuse-baseline.json
│   ├── backing-uring.json
│   ├── fuse-uring.json
│   ├── ekbloom-frontier.json
│   ├── random-read.json
│   ├── sequential-read.json
│   ├── append-write.json
│   └── mount-replay.json
├── security/
└── receipts/
    ├── container.json
    ├── toolchain.json
    ├── source-commit.json
    └── environment.json
```

Do not manufacture successful result files.

A skipped test must report the concrete reason.

A missing kernel feature must be reported as unsupported or untested, not as passed.

---

# 40. Implementation phases

Execute the following phases in order, while allowing independent research to run in parallel.

## Phase 0 — Environment and evidence foundation

Create the repository, pinned container workflow, reproducible Cargo build, test scripts, logging, and evidence infrastructure.

**Exit:** clean checkout builds and tests inside the pinned image.

## Phase 1 — Authoritative append-only log

Implement physical segments, record framing, append reservations, committed root identity, and safe replay.

**Exit:** deterministic replay from committed prefixes; no rewriting of committed records.

## Phase 2 — Transactions and durability

Implement transaction records, commit sequencer, proper I/O ordering, flush semantics, and injected failure recovery.

**Exit:** torn and incomplete transactions never become visible.

## Phase 3 — Namespace and extents

Implement real inodes, directories, links, arbitrary-offset writes, truncation, logical deletion, and historical versions.

**Exit:** model-based filesystem semantics tests pass.

## Phase 4 — Traditional FUSE

Implement a real mountable filesystem using the current Rust FUSE API.

Support required file and directory operations, permissions, handles, synchronization, and namespace behavior.

**Exit:** targeted POSIX conformance tests pass on a mounted filesystem.

## Phase 5 — Backing io_uring

Implement ring-based writes, reads, completion processing, ordering, cancellation, and fallback behavior.

**Exit:** correctness remains identical and measurable performance data exists.

## Phase 6 — Historical snapshots and index checkpoints

Implement committed-root snapshots, read-only historical mounts, derived index checkpointing, and accelerated recovery.

**Exit:** arbitrary tested committed roots reconstruct correctly.

## Phase 7 — Concealed manifestation

Implement `.or_bloom`, version-qualified manifests, asynchronous workers, publication, and physical accounting.

**Exit:** generated structures can be removed or rebuilt without changing authoritative logical output, subject to their declared retention policies.

## Phase 8 — EKBLOOM integration

Use the real EKBLOOM dependency.

Implement certified manifested read paths and correct fallback behavior.

**Exit:** all accelerated reads match authoritative reads, including historical versions.

## Phase 9 — Concealed query structures

Implement trigram-based query acceleration and the typed query interface.

Investigate additional suffix and image manifestations.

**Exit:** equal-result query parity and measured performance evidence.

## Phase 10 — FUSE-over-io_uring

Implement the documented advanced transport where supported, with classical FUSE fallback.

**Exit:** transport-equivalence tests pass; real F2 measurements exist on a capable kernel.

## Phase 11 — Security and crash-hardening

Complete adversarial reviews, fuzzing, concurrency model checks, corrupted-log tests, and recovery fault injection.

**Exit:** no known critical correctness or security failures remain unresolved.

## Phase 12 — Hostile performance court

Benchmark all transport and manifestation configurations under controlled hardware and durability conditions.

**Exit:** independent, reproducible evidence identifies the actual performance frontier.

---

# 41. Hard acceptance gates

Do not declare OrFS complete unless all applicable gates pass.

### Gate A — Genuine non-withdrawal

No committed authoritative record is overwritten, reused, or physically removed.

### Gate B — Valid historical roots

Every published root identifies one complete committed logical state.

### Gate C — Log-only reconstruction

The authoritative log reconstructs every supported filesystem object and metadata field without derived indexes.

### Gate D — Transaction atomicity

No reader can observe a partially applied committed mutation.

### Gate E — Real FUSE functionality

The filesystem mounts and supports actual operations through the Linux VFS.

### Gate F — Correct io_uring execution

Ordering, CQE processing, buffer lifetimes, error handling, and durability semantics are verified.

### Gate G — Real historical snapshots

Committed-prefix snapshots reproduce the exact historical namespace and data.

### Gate H — Concealed manifestation

Operational structures are physically generated, stored, verified, and selected by real code.

### Gate I — EKBLOOM correctness

Accelerated paths return exactly the same logical bytes as authoritative reads.

### Gate J — Recovery

Interrupted or corrupted operations cannot silently produce an invalid committed state.

### Gate K — Physical accounting

Actual historical and manifested storage consumption is reported.

### Gate L — FUSE-over-io_uring

Where the target kernel supports the required UAPI, the advanced transport operates and passes its equivalence tests.

### Gate M — Reproducibility

All required tests and benchmarks execute inside the prescribed pinned-container environment.

### Gate N — Measured advantage

Performance claims are backed by genuine benchmark results, not theoretical estimates.

---

# 42. Implementation references

Study the following authoritative interfaces before writing the relevant modules.

These are engineering references. They do not redefine OrFS or EKBLOOM.

## Linux FUSE

https://www.kernel.org/doc/html/latest/filesystems/fuse/index.html

## Linux FUSE I/O modes

https://www.kernel.org/doc/html/latest/filesystems/fuse/fuse-io.html

## FUSE-over-io_uring design

https://www.kernel.org/doc/html/latest/filesystems/fuse/fuse-io-uring.html

## FUSE-over-io_uring UAPI

https://www.kernel.org/doc/html/latest/filesystems/fuse/uapi/fuse-uapi-io-uring.html

## FUSE passthrough

https://www.kernel.org/doc/html/latest/filesystems/fuse/fuse-passthrough.html

## Rust fuser

https://docs.rs/fuser/0.18.0/fuser/

## Rust io-uring

https://docs.rs/io-uring/0.7.15/io_uring/

## io_uring linked requests

https://man7.org/linux/man-pages/man7/io_uring_linked_requests.7.html

## fsync durability

https://man7.org/linux/man-pages/man2/fsync.2.html

## Extended attributes

https://man7.org/linux/man-pages/man7/xattr.7.html

## FUSE low-level operation contracts

https://libfuse.github.io/doxygen/structfuse__lowlevel__ops.html

## Docker official Rust images

https://hub.docker.com/_/rust

Use the precise kernel UAPI matching the tested kernel version.

Do not copy older API examples without checking compatibility.

---

# 43. Execution discipline

Begin implementation immediately.

Do not stop after writing an architecture document.

At each phase:

1. Assign independent subagents where available.
2. Inspect the relevant source/API contracts.
3. Define invariants.
4. Write adversarial tests.
5. Implement the real functionality.
6. Run everything inside the pinned container.
7. Correct failing tests.
8. Verify crash and concurrency behavior.
9. Produce evidence.
10. Record the exact source commit.
11. Continue to the next phase.

Do not replace difficult requirements with placeholders.

Do not mark incomplete functionality as completed.

Do not fabricate benchmarking or review results.

When a kernel feature is unavailable, finish all independent work and document the capability limitation precisely.

Make the code buildable, testable, reviewable, and reproducible.

Keep the implementation as simple as correctness permits and as aggressive as measured speed justifies.

---

# 44. Final directive

Build OrFS as an actual Linux filesystem.

Its authoritative history must obey:

\[
\boxed{
L_{n+1}=L_n\oplus\Delta_n
}
\]

Its historical roots must remain valid.

Its namespace operations must be correct.

Its committed records must never be withdrawn.

Its EKBLOOM acceleration must deliberately manifest physical operational structure.

Its asynchronous I/O must preserve ordering, lifetime, and durability semantics.

Its FUSE interfaces must work against the real Linux VFS.

Its fast paths must return exact data.

Its speed gains must be measured.

The governing objective remains:

\[
\boxed{\textbf{Spend manifested space to maximise speed.}}
\]

**Deliver a working, durable, adversarially tested, high-performance native-Rust OrFS filesystem—not another proposal, scaffold, simulation, or collection of unverified performance claims.**