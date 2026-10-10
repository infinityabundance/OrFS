# OrFS — Non-Withdrawal, Concealed-Expansion Filesystem

**Version:** 0.2 — Proposed Engineering Specification  
**Platform:** Linux  
**Filesystem interface:** FUSE  
**Asynchronous I/O:** `io_uring`  
**Implementation language:** Native Rust  
**Codec and acceleration engine:** EKBLOOM  
**Persistence model:** Append-only, non-withdrawal  
**Status:** Design specification; performance and correctness require implementation evidence

---

## 0. Purpose

OrFS is a Linux userspace filesystem built around two independent but complementary principles:

1. **Non-withdrawal:** previously committed authoritative filesystem history is never overwritten, truncated, or garbage-collected.
2. **Concealed expansion:** additional physical operational structures are deliberately manifested to increase execution speed without changing the ordinary logical view of the filesystem.

The authoritative body grows.

The operational body can grow faster.

The visible namespace remains a conventional filesystem interface.

OrFS does not require its manifested physical body to be smaller than its logical contents.

Its performance principle is:

\[
\boxed{
\textbf{Spend manifested space to maximise speed.}
}
\]

The authoritative history provides continuity. EKBLOOM provides outward acceleration.

The essential separation is:

\[
\boxed{
\text{OrFS}=
\text{permanent authoritative body}
+
\text{concealed manifested acceleration}
+
\text{POSIX-facing namespace}.
}
\]

OrFS is not intended to be a universal replacement for every general-purpose filesystem.

Its strongest initial application classes are systems that value retained history, reproducibility, snapshots, auditability, and read acceleration through deliberately generated operational structure.

The implementation must also support ordinary filesystem operations faithfully within its documented compatibility profile.

---

# 1. Relationship to the original design

This specification develops the supplied OrFS v0.1 design.

Its originating principles remain authoritative:

- no filesystem-managed free list for committed historical records;
- no reuse of committed authoritative log space;
- `or.log` as the source of truth;
- stable log-offset identity rather than content-hash identity;
- tombstones for logical removal;
- valid committed log prefixes as historical snapshots;
- rebuildable indexes;
- a concealed operational namespace;
- asynchronous bloom construction;
- deliberate physical expansion for speed.

The original conceptual terminology may be retained in documentation:

| Term | OrFS role |
|---|---|
| **Or** | Retained authoritative log |
| **Kav** | Outward-generated operational structures |
| **Reshimu** | Historical root/position identifying a committed view |
| **Visible vessel** | Filesystem namespace presented through FUSE |

These terms describe the intended architecture, not independent proofs of storage correctness or physical capacity.

The precise implementation is governed by the invariants below.

---

# 2. Core invariants

## I1 — Authoritative non-withdrawal

For committed authoritative history:

\[
L_0\preceq L_1\preceq L_2\preceq\cdots
\]

where each successive committed log extends the preceding one.

An existing committed record may not be:

- overwritten;
- removed;
- reordered;
- repurposed for a different object;
- silently compacted away.

Logical deletion is recorded as a new event.

Logical truncation is recorded as a new version.

A rename creates new namespace state without changing history.

## I2 — Root-by-position identity

A root is a position identifying a committed prefix of the canonical logical log.

\[
\boxed{
R=\operatorname{committed\_end\_offset}.
}
\]

A root is not a content hash.

The root identifies a historical filesystem state by its position in the volume's authoritative record sequence.

Identity is scoped to a particular OrFS volume.

Therefore an externally meaningful reference is:

\[
(\text{volume ID},R).
\]

An offset alone is not globally unique.

## I3 — Prefix snapshots

For every committed root \(R\), the complete committed logical prefix:

\[
L[0:R]
\]

must reconstruct one valid historical filesystem state.

**The endpoint must be a committed transaction boundary.**

An arbitrary byte offset inside a record or incomplete transaction is not a valid snapshot.

## I4 — Rebuildability

The authoritative log is sufficient to reconstruct:

- inode identities;
- directory relationships;
- current logical file contents;
- historical versions;
- metadata;
- extended attributes;
- snapshot roots.

Indexes, acceleration structures, and materialized views may be regenerated from retained authoritative data.

## I5 — Concealed manifestation

OrFS may maintain a substantially larger physical operational representation than the logical namespace reveals.

The operational representation may contain:

- EKBLOOM state histories;
- EKBLOOM transition blooms;
- trigram indexes;
- suffix-oriented search structures;
- image pyramids;
- file extents;
- directory accelerators;
- snapshot navigation structures;
- cache-local replicas;
- application-specific materialized surfaces.

Logical concealment does not exempt these structures from physical accounting.

## I6 — Immutable committed generations

Every committed acceleration generation records the authoritative root or object version from which it was constructed.

It must not be used against incompatible content.

## I7 — No false success

A filesystem operation must not report successful completion when the corresponding accepted data or metadata transition has not reached the documented acknowledgment stage.

## I8 — Physical capacity is finite

The filesystem has no logical free list for historical data.

That does not make the backing device infinite.

When backing storage cannot accept another record, OrFS must apply its declared quota/capacity policy and return the appropriate error.

No-write-withdrawal cannot imply unlimited physical capacity.

---

# 3. Architecture

```text
                        LINUX VFS
                            │
                     FUSE connection
                            │
                 ┌──────────┴───────────┐
                 │                      │
          /dev/fuse transport    FUSE io_uring transport
                 │                 when supported
                 └──────────┬───────────┘
                            │
                     OrFS dispatcher
                            │
             ┌──────────────┼───────────────┐
             │              │               │
       Namespace engine  Version engine  Access planner
             │              │               │
             └──────────────┼───────────────┘
                            │
                     Commit sequencer
                            │
                  AUTHORITATIVE BODY
                            │
                       or.log
                            │
                  committed roots
                            │
          ┌─────────────────┴─────────────────┐
          │                                   │
    Rebuildable indexes                 EKBLOOM builder
          │                                   │
     metadata views                    state histories
     directory views                   transition blooms
     extent maps                       positional surfaces
          │                                   │
          └─────────────────┬─────────────────┘
                            │
                  CONCEALED OPERATIONAL
                          BODY
                            │
                     .or_bloom/
                            │
                   fastest valid reader
```

The architecture is divided into four planes.

### Plane A — Authoritative history

Owns permanent records, transaction ordering, and committed roots.

### Plane B — Namespace interpretation

Reconstructs ordinary filesystem semantics from the log.

### Plane C — Manifested acceleration

Builds additional read, query, and navigation structures without changing the authoritative history.

### Plane D — Kernel and storage I/O

Implements FUSE transport, asynchronous backing operations, and optional accelerated kernel interfaces.

Each plane has a separate correctness contract.

---

# 4. Backing layout

The conceptual backing layout remains:

```text
backing/
    or.log
    index/
    .or_bloom/
```

For crash-safe physical realization, `or.log` is a **logical append-only stream** backed by immutable physical segments.

Recommended physical layout:

```text
backing/
├── volume.meta
├── or.log/
│   ├── 0000000000000000.seg
│   ├── 0000000000000001.seg
│   └── ...
├── index/
│   ├── current.snapshot
│   └── ...
└── .or_bloom/
    ├── ekbloom/
    ├── trigram/
    ├── suffix/
    ├── image/
    ├── directory/
    └── manifests/
```

The segment structure is deliberate.

A single physical append-only file cannot always guarantee both:

1. never remove or overwrite an incomplete physical tail;
2. retain a valid contiguous committed record sequence after a torn write.

After a partial write, preserving every physical byte may leave an unusable tail. Continuing behind that tail without framing or segmentation compromises the original arbitrary-prefix rule.

OrFS therefore distinguishes:

- **physical history**, including incomplete abandoned segment tails;
- **canonical committed log**, consisting only of validated committed records in logical order.

When a physical segment ends with a torn or incomplete record, OrFS preserves that physical segment and starts a fresh one.

The canonical log remains a continuous logical sequence.

Its root remains a logical committed byte offset, not a content hash.

A clean single-segment filesystem may still expose:

```text
or.log
```

as a contiguous read-only view.

---

# 5. Physical log records

## 5.1 Record envelope

Every authoritative record uses explicit framing.

Proposed wire format:

```text
RECORD HEADER
    magic                  u32
    format_version         u16
    record_type            u16
    header_length          u32
    payload_length         u64
    sequence_number        u64
    transaction_id         u64
    inode_id               u64
    previous_inode_offset  u64
    flags                  u32
    header_check           u32

PAYLOAD
    bytes[payload_length]

RECORD FOOTER
    total_record_length    u64
    record_check           u32
    end_marker             u32
```

Wire fields are little-endian.

No Rust struct may be cast directly over untrusted bytes without appropriate validation.

The check fields exist exclusively to detect malformed or corrupted records.

They do not define record identity.

A CRC such as CRC32C is a candidate integrity mechanism, subject to explicit threat-model limits. If adversarial tampering must be detected, a separate authenticated integrity layer is required.

Neither checksum nor authentication digest replaces the authoritative offset identity.

## 5.2 Record types

Define at least:

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

PERMISSION_CHANGE
```

Unknown mandatory record types must prevent unsafe mounting.

Unknown optional types may be skipped only when the format explicitly permits skipping them.

## 5.3 Transaction records

Multi-record operations use one transaction.

For example, a file create may require:

```text
TX_BEGIN
INODE_CREATE
DENTRY_ADD
TX_COMMIT
```

A rename may require:

```text
TX_BEGIN
DENTRY_REMOVE
DENTRY_ADD
INODE_METADATA
TX_COMMIT
```

The transaction becomes visible atomically.

A partially written transaction is not a committed filesystem state.

## 5.4 Root

The root advances only after a complete, valid commit.

\[
R_{n+1}
=
R_n+
\text{committed transaction bytes}.
\]

A root must never point into an incomplete transaction.

---

# 6. Inode and namespace semantics

A filesystem cannot represent all files as merely the most recent physical log offset.

Arbitrary overwrites, holes, truncation, and multiple writes require a logical mapping from file positions to retained data extents.

Each inode has:

```text
stable inode ID
inode generation
type
mode
uid
gid
link count
logical size
timestamps
xattrs
version
extent map
latest authoritative record
```

Directory entries are stored separately as relationships:

\[
(\text{parent inode},\text{name})
\rightarrow
\text{child inode}.
\]

A file may have multiple names through hard links.

Renaming a file does not change its inode identity.

Unlinking one directory entry does not necessarily destroy the inode's remaining namespace references.

Even after all names are removed, its historical authoritative records remain.

---

# 7. File contents and extent interpretation

Each write appends a new immutable data extent and a corresponding logical mapping update.

For example:

```text
Initial logical file:
    [ A A A A A A A A ]

Write "BB" at offset 3:
    [ A A A B B A A A ]
```

The original `A` bytes remain in the log.

The new version references the original unaffected ranges and the newly written `B` extent.

The logical file is reconstructed from the active version's extent map.

The extent map is a derived index and may be rebuilt from authoritative records.

## 7.1 Arbitrary-offset writes

Support writes at:

- beginning;
- middle;
- end;
- beyond end-of-file.

Writes beyond EOF must satisfy documented POSIX zero-fill behavior.

Logical holes may be represented by explicit zero-range records.

If a strict direct-manifestation profile is selected, OrFS may generate a physical zero-byte surface for faster reads.

The representation choice must not alter logical output.

## 7.2 Truncation

A shrink operation appends:

```text
FILE_RESIZE(new_size)
```

It does not remove existing historical extents.

A later extension of the file must not resurrect old truncated bytes merely because the physical history still contains them.

Newly exposed logical regions must obey zero-fill semantics unless explicitly written.

## 7.3 Logical deletion

`unlink()` removes a current directory relationship by appending a record.

It does not reclaim the historical bytes.

Open handles to the unlinked inode remain functional as required by the selected POSIX compatibility profile.

## 7.4 Snapshot semantics

A snapshot is a committed root:

\[
S_R=L[0:R].
\]

All lookups through that snapshot reconstruct the namespace as of \(R\).

Snapshot mounts are read-only unless OrFS explicitly implements branching history.

---

# 8. Historical roots and extended attributes

Preserve the original root concept.

Expose a historical creation root through a read-only attribute such as:

```text
user.orfs.creation_root
```

Also provide:

```text
user.orfs.current_root
user.orfs.version
user.orfs.history_available
user.orfs.manifested_bytes
user.orfs.ekbloom_profile
```

For compatibility with the original specification, an alias for:

```text
user.or.ein_sof_root
```

may be provided.

Values must obey normal extended-attribute size and access rules.

Important distinction:

> The root identifies a historical volume state. The root number alone does not contain the full filesystem history.

A file holding a root can select a reproducible state **when the corresponding log body is available**.

If a self-contained historical carrier is desired, OrFS must explicitly embed or export the necessary authoritative log prefix.

That is a separate feature.

---

# 9. The concealed operational body

The directory:

```text
.or_bloom/
```

contains generated acceleration structures.

These may be dropped and rebuilt without changing authoritative logical content.

This does not weaken the non-withdrawal invariant for the authoritative log.

The original design's distinction remains:

- authoritative body: permanent;
- acceleration body: generated and rebuildable.

EKBLOOM full-history mode may have its own stronger retention contract. When enabled, committed EKBLOOM state-history records must obey that contract.

Do not conflate ordinary disposable acceleration caches with immutable full-history manifestations.

Each acceleration generation records:

```text
object identity
source inode version
source committed root
structure type
construction parameters
physical size
logical domain
integrity information
verification status
```

An acceleration structure must not be used against an incompatible file version.

---

# 10. EKBLOOM as the first-class acceleration engine

EKBLOOM is the principal codec-related manifestation engine.

For an eligible file, OrFS may materialize:

- sparse operational-state checkpoints;
- dense checkpoints;
- full retained state history;
- complete restart states;
- certified four-step transition blooms;
- deeper transition blooms;
- regional blooms;
- exact path-specific blooms.

These remain EKBLOOM structures.

Do not rename their underlying technology.

The filesystem's job is to store, generate, publish, select, and safely access them.

The codec's job is to produce exact outputs and certified operational transitions.

## 10.1 Manifestation profiles

Provide:

```text
root
sparse
dense
full
bloom4
bloom8
regional
path4
max-speed
```

OrFS must record the actual profile used and its exact physical byte consumption.

## 10.2 Read selection

A read request follows:

```text
logical inode
    ↓
committed inode version
    ↓
extent selection
    ↓
available certified manifestation
    ↓
fastest compatible path
    ↓
logical bytes
```

A missing or invalid bloom causes a fallback to the authoritative data path.

It must not cause incorrect bytes to be returned.

## 10.3 Background construction

After a write:

```text
authoritative log transaction
        ↓
commit publication
        ↓
enqueue EKBLOOM construction
        ↓
manifested output/state/bloom generation
        ↓
verify against committed object version
        ↓
publish acceleration generation
```

The bloom worker must not publish an acceleration structure for a newer inode version merely because its construction finished later.

Generation identity is mandatory.

---

# 11. Additional concealed structures

The supplied v0.1 design proposes three additional structures.

Retain them as optional independently measured manifestation families.

## 11.1 Trigram index

For text-oriented data, build a positional trigram index.

Required components:

```text
trigram key
posting list
source inode version
source logical size
posting encoding
verification metadata
```

Queries must verify candidate matches against the actual logical file.

A trigram search is not generally \(O(k)\) for all query workloads. It depends on pattern length, posting-list size, candidate verification, and output size.

Benchmark these quantities separately.

## 11.2 Suffix-oriented structure

Investigate suffix automata or equivalent substring-supporting structures.

Distinguish:

- substring existence;
- match count;
- all match positions.

A fast substring-existence query does not automatically give constant-time enumeration of every occurrence.

Measure the actual memory and query behavior.

## 11.3 Image pyramid

For recognized image formats, optionally generate multiresolution image surfaces.

A conventional two-dimensional pyramid whose dimensions halve in both directions adds approximately one third of the base pixel count across all lower resolutions, before metadata and format effects.

That estimate is not a universal byte-level expansion guarantee.

Image decoding, dimensions, pixel formats, color semantics, and materialization must be specified.

A generic binary file must not be interpreted as an image merely because an extension suggests it.

---

# 12. Queries: do not misuse extended attributes

The original proposal includes:

```text
getxattr user.or.grep=PAT
```

as a query mechanism.

For compatibility experiments, this may be supported in a tightly bounded form.

It should not be the principal search API.

Extended attributes have size and naming limits; they are not designed to stream arbitrarily large match sets. Linux also imposes practical VFS limits on attribute names and values.

Use a dedicated query interface.

Recommended:

```text
orfs query <path> --pattern PATTERN
```

with a typed internal API:

```rust
pub struct QueryRequest {
    pub inode: u64,
    pub root: u64,
    pub pattern: Vec<u8>,
    pub limit: Option<u64>,
}
```

Support streaming match positions and cancellation.

Optionally expose an ioctl or a privileged control socket for mounted-filesystem query operations.

The query interface must use the same permission checks and inode-version rules as ordinary reads.

## 12.1 Benchmark honesty

Ordinary:

```text
grep -r
```

reads file contents through POSIX operations.

It does not automatically invoke OrFS's trigram index.

To measure the index, compare equivalent query APIs and equivalent returned results.

Separately benchmark ordinary `grep -r` to measure filesystem read throughput.

Do not attribute query-index acceleration to ordinary POSIX reads unless the implementation actually provides that behavior.

---

# 13. FUSE architecture

Use the FUSE low-level semantics as the correctness target.

A native-Rust implementation may initially use `fuser` for traditional `/dev/fuse` transport.

The filesystem core must remain independent of the transport adapter.

Suggested interface:

```rust
pub trait OrfsCore {
    fn lookup(
        &self,
        parent: u64,
        name: &[u8],
    ) -> Result<InodeEntry, FsError>;

    fn read(
        &self,
        inode: u64,
        offset: u64,
        length: u32,
        handle: u64,
    ) -> Result<Vec<u8>, FsError>;

    fn write(
        &self,
        inode: u64,
        offset: u64,
        data: &[u8],
        handle: u64,
    ) -> Result<u32, FsError>;
}
```

This is illustrative, not a complete public API.

Use `OsStr`-compatible raw filename handling rather than assuming filenames are UTF-8.

File and directory handles must be independently managed.

---

# 14. Required FUSE operations

| Operation | OrFS semantics |
|---|---|
| `init` | Validate backing, recover committed log, negotiate capabilities |
| `lookup` | Resolve parent/name in current or pinned historical root |
| `forget` | Release kernel lookup references without deleting retained history |
| `getattr` | Return version-consistent inode metadata |
| `setattr` | Append metadata/size transition |
| `opendir` | Create directory iteration handle |
| `readdir` | Return logical visible children |
| `readdirplus` | Return children and attributes with correct lookup accounting |
| `releasedir` | Release iteration handle |
| `open` | Validate permissions and create file handle |
| `read` | Resolve logical extents; select valid manifested path |
| `write` | Serialize logical mutation into authoritative transaction |
| `flush` | Process handle-level buffered errors; not automatically a full durability barrier |
| `fsync` | Durably commit required file content and metadata |
| `fsyncdir` | Durably commit required directory changes |
| `release` | Release open handle |
| `create` | Atomically create inode and directory entry |
| `mkdir` | Atomically create directory |
| `mknod` | Implement supported types or reject explicitly |
| `unlink` | Append logical directory removal |
| `rmdir` | Reject nonempty directories; append removal for empty ones |
| `rename` | One atomic namespace transaction |
| `link` | Add hard link; adjust logical link count |
| `symlink` | Append symlink content and directory relationship |
| `readlink` | Return authoritative symlink target |
| `getxattr` | Read supported logical attributes |
| `setxattr` | Append attribute mutation |
| `listxattr` | List attributes permitted by the view |
| `removexattr` | Append logical attribute removal |
| `statfs` | Report capacity according to declared accounting mode |
| `access` | Enforce applicable access policy |
| `fallocate` | Support declared modes; reject unsupported ones |
| `copy_file_range` | Implement through logical extents or explicitly decline |
| `lseek` | Support SEEK_SET/CUR/END and tested SEEK_DATA/HOLE semantics |
| `lock`/`flock` | Implement correctly if advertised; otherwise declare limitation |

The implementation must not rely on default trait methods silently returning inappropriate behavior.

POSIX compliance is a tested compatibility target, not a label granted by compiling.

---

# 15. Open handles, unlink, and historical identity

Unlink is logical removal, not physical destruction.

If a file is open when its final directory name is unlinked:

- the file disappears from ordinary namespace lookup;
- existing open handles may continue to read/write as specified by POSIX behavior;
- new writes through an authorized open handle create further authoritative records;
- the historical inode identity remains;
- physical log records remain.

Stable inode identity must not be confused with current namespace visibility.

A snapshot handle remains pinned to its historical root.

A regular live handle follows documented live inode semantics, not an accidental snapshot.

Directory enumeration must remain consistent with its chosen iteration model.

---

# 16. FUSE cache modes

Start with conservative FUSE caching.

The initial compatibility profile should use:

- write-through behavior;
- controlled entry TTL;
- controlled attribute TTL;
- explicit inode and entry invalidation when needed.

Evaluate direct I/O separately.

Linux FUSE supports distinct direct-I/O, cached write-through, and writeback-cache modes.

They have materially different semantics.

Do not enable writeback caching merely because it improves a benchmark.

Writeback caching can delay the time at which the filesystem daemon receives writes.

OrFS's acknowledgment, ordering, and durability semantics must account for that difference.

Later profiles may enable:

- writeback cache;
- larger readahead;
- parallel directory operations;
- inode notifications;
- larger maximum write sizes.

Every cache profile requires its own correctness and crash-recovery tests.

---

# 17. Two `io_uring` domains

OrFS must distinguish two technically different uses of `io_uring`.

## Domain A — Backing-store I/O

This is the primary mandatory implementation.

Use `io_uring` for:

- authoritative append writes;
- reads from immutable log segments;
- reading EKBLOOM structures;
- writing generated bloom files;
- flush operations;
- metadata publication;
- asynchronous prefetch.

This path works with traditional `/dev/fuse` request transport.

## Domain B — FUSE-over-io-uring

Modern Linux also supports an `io_uring`-based transport between the FUSE kernel module and userspace.

This is a distinct optional fast path.

The implementation must not assume that using `io_uring` for backing I/O automatically enables FUSE-over-io-uring.

The relevant kernel interface uses `IORING_OP_URING_CMD` and FUSE-specific registration and commit/fetch operations.

Some notifications and interrupts still require the conventional FUSE interface.

The interface is evolving and must be version/capability negotiated.

Implement it behind an explicit feature and runtime capability check.

A native-Rust implementation should not require replacing the filesystem core.

---

# 18. Transport profiles

Define three transport profiles.

## F0 — Conventional FUSE

```text
/dev/fuse
    ↓
Rust dispatcher
    ↓
backing I/O
```

This is the compatibility baseline.

## F1 — Conventional FUSE with io_uring backing

```text
/dev/fuse
    ↓
Rust dispatcher
    ↓
io_uring backing rings
```

This is the initial performance target.

## F2 — FUSE-over-io-uring with io_uring backing

```text
FUSE uring queues
    ↓
Rust dispatcher
    ↓
io_uring backing rings
```

This is the advanced transport target.

Where FUSE-over-io-uring is unavailable or prohibited, the filesystem must fall back to F1 or F0 without changing logical content.

Do not claim F2 is active merely because the backing implementation uses an I/O ring.

---

# 19. FUSE-over-io-uring implementation boundary

Do not assume the selected Rust FUSE library already exposes the full modern FUSE-over-io-uring transport.

Investigate the exact versions and kernel APIs.

For a native-Rust implementation, one possible path is a dedicated internal transport adapter for the supported UAPI.

The authoritative kernel documentation describes:

- queue registration;
- request delivery through CQEs;
- commit-and-fetch;
- buffer pools;
- optional registered buffers;
- feature-gated zero-copy.

The filesystem core should expose transport-neutral request/reply types.

This prevents kernel transport evolution from forcing changes to the authoritative log or EKBLOOM integration.

When implementing zero-copy FUSE transport, respect privilege requirements. The kernel's FUSE zero-copy pathway currently requires `CAP_SYS_ADMIN` and an appropriate buffer pool.

Do not require these privileges for ordinary mounting when a less privileged transport is sufficient.

---

# 20. Backing I/O ring design

Use a deliberate division of responsibilities.

## Ring W — Authoritative writer

One logical commit sequencer owns authoritative transaction ordering.

It assigns monotonically increasing record positions and physical append locations.

Multiple requests may be batched.

However, completions may arrive out of order.

OrFS must not publish a commit until all its dependent writes have completed successfully.

An unlinked set of SQEs does not establish ordered durability.

Use linked operations, explicit CQE barriers, or `IOSQE_IO_DRAIN` where appropriate.

For correctness, distinguish:

1. allocated log space;
2. submitted I/O;
3. completed I/O;
4. logically committed transaction;
5. durable commit.

These are different states.

## Ring R — Read engine

Handles:

- immutable extent reads;
- positional log reads;
- bloom loads;
- read-ahead;
- historical snapshot reads.

Reads may execute concurrently.

A reader pins a committed root for the duration of its logical operation.

## Ring B — Bloom persistence

Handles asynchronous writes and reads for generated EKBLOOM and other operational structures.

Bloom construction itself runs in CPU workers.

`io_uring` does not perform CPU-intensive construction on behalf of the codec.

Do not use a fixed number of rings or workers without measurement.

The original two-ring design remains a valid small starting configuration; this specification separates logical responsibilities so they can later be combined or split according to measured performance.

---

# 21. Commit protocol

The authoritative commit protocol should resemble:

```text
Receive logical mutation
       ↓
Validate inode permissions and arguments
       ↓
Acquire required logical ordering
       ↓
Build immutable transaction records
       ↓
Reserve append positions
       ↓
Submit backing writes
       ↓
Wait for required write completions
       ↓
Write/validate TX_COMMIT
       ↓
Publish new in-memory committed root
       ↓
Reply to caller according to durability mode
```

For operations requiring durable acknowledgment:

```text
data writes
    ↓
commit record
    ↓
required fsync/fdatasync
    ↓
successful completion
    ↓
reply
```

For ordinary buffered writes, the declared contract may permit acknowledgment after the transaction is accepted into the backing filesystem's page cache and published in memory, with durability ensured by later `fsync`.

Do not misrepresent that as power-loss durability.

For `O_SYNC` or equivalent modes, honor the required synchronization semantics before returning success.

Every failure path must preserve earlier committed roots.

---

# 22. Durability modes

Offer explicit durability profiles.

### `sync`

A successful mutating operation is made durable before acknowledgment, subject to the underlying storage's documented guarantees.

### `ordered`

Mutations are ordered and published after completed backing writes; normal `fsync` establishes durable persistence.

### `batched`

Multiple transactions may share synchronization points, with acknowledgment rules explicitly documented.

A batch size such as 64 entries may be a benchmark starting point.

It is not a substitute for handling explicit `fsync`, `O_SYNC`, or power-loss recovery correctly.

Performance results must always identify the durability profile.

---

# 23. Recovery

Mount-time recovery performs:

1. validate volume genesis;
2. discover committed physical segments;
3. inspect record framing;
4. locate the last valid transaction boundary;
5. establish the canonical committed root;
6. ignore incomplete transactions;
7. rebuild or load a verified namespace index;
8. validate required metadata dependencies;
9. schedule regeneration of missing acceleration structures.

Incomplete physical tails are retained if the non-withdrawal policy requires that they not be truncated.

They are not part of the canonical committed logical log.

New authoritative writes continue in a new valid segment.

## 23.1 No silent repair

OrFS must distinguish:

- incomplete final write;
- malformed uncommitted tail;
- corrupted committed record;
- missing committed segment;
- incompatible format version.

A malformed uncommitted tail may be ignored.

A corrupted committed record must not be silently skipped while presenting the resulting filesystem as complete.

Use an explicit recovery or degraded read-only mode as appropriate.

## 23.2 Rebuildable indexes

If an index snapshot is missing, rebuild it from authoritative records.

If an index snapshot disagrees with replay, discard or quarantine the index.

The authoritative log wins.

If the authoritative log itself is corrupt, index rebuilding cannot magically restore missing data.

## 23.3 Filesystem checking

Append-only construction reduces some classes of damage but does not eliminate the need for verification.

Provide:

```text
orfs verify
orfs inspect-log
orfs recover
```

A separate verification command is necessary even if the filesystem does not perform traditional block-allocation repair.

---

# 24. Index checkpointing

Full log replay is:

\[
O(|L|).
\]

That will eventually become expensive.

Retain the original proposal to store periodic index checkpoints **inside the authoritative log**.

A checkpoint record contains enough information to reconstruct a verified namespace state at a particular root.

On mount:

1. discover the newest valid authoritative index checkpoint;
2. load and validate it;
3. replay subsequent authoritative records;
4. reconstruct the latest committed state.

If a checkpoint fails validation, fall back to an earlier checkpoint or full replay.

Checkpoint intervals should be chosen through measurement of:

- checkpoint construction cost;
- physical manifested size;
- mount time;
- replay time;
- update rate.

Do not claim constant-time mount unless the implementation actually achieves the required bound.

---

# 25. Namespace index

The hot namespace index may use native Rust maps, trees, or another measured data structure.

Conceptually:

```text
inode_id → inode version
(parent_inode, name) → directory entry
inode_id → extent map
inode_id → xattr map
root → snapshot metadata
```

The original SQLite index proposal remains a possible derived implementation, but SQLite is not the authoritative store.

No correctness property may depend on a cache database surviving.

The hot namespace implementation should be selected by measured lookup and update performance.

Derived index snapshots may be manifested aggressively when that improves speed.

---

# 26. Concurrency model

Use one logical transaction commit order.

Allow concurrent independent reads.

Use short-lived immutable committed-root views to avoid exposing partially applied transactions.

A suitable design is:

```text
Atomic committed-root pointer
            │
        Immutable view
            │
    Concurrent FUSE readers
```

Mutations are serialized through the commit sequencer or another proven equivalent.

Directory mutations requiring atomic namespace changes occur in one transaction.

Long-running bloom jobs never hold global namespace locks.

An acceleration generation is published atomically after verification.

## 26.1 Open-handle isolation

Live handles and snapshot handles are different.

A snapshot handle is pinned to its selected historical root.

A live handle resolves its data according to current file semantics and operation ordering.

Unlink does not invalidate already open file handles.

## 26.2 FUSE lookup accounting

Respect lookup/forget reference counts.

Do not reuse inode numbers for unrelated identities while the kernel may retain references.

Stable historical inode IDs are particularly useful here.

---

# 27. FUSE cache invalidation

OrFS may update namespace or inode metadata in response to committed mutations.

Where kernel caches may be stale, use appropriate FUSE invalidation mechanisms.

Relevant operations include:

- invalidating directory entries;
- invalidating inode attributes;
- invalidating file data ranges.

Do not invoke notifications while holding locks in ways that can deadlock related filesystem operations.

Start with short TTLs and conservative caching.

Increase them after correctness tests pass.

A bloom becoming available should not require changing canonical file contents or invalidating file data.

It should usually affect only the chosen internal read path.

---

# 28. Advanced kernel fast paths

Two advanced Linux features merit separate research.

## 28.1 FUSE-over-io-uring

May reduce kernel/userspace transport overhead.

Use only when negotiated and supported.

## 28.2 FUSE passthrough

Linux also supports privileged FUSE passthrough for certain operations.

Passthrough can let eligible reads execute against a registered backing file without routing every operation through the daemon.

However, OrFS must never use passthrough writes to bypass the authoritative append-only transaction protocol.

A read-only immutable, contiguous object extent may be eligible for a carefully constrained passthrough mode.

This is an optimization candidate, not part of the initial correctness foundation.

The kernel feature and privilege requirements must be checked explicitly.

---

# 29. POSIX behavior and compatibility

Define a compatibility matrix and run conformance tests.

Important behaviors include:

- atomic rename;
- hard links;
- unlink while open;
- append semantics;
- overlapping writes;
- sparse files;
- truncation and re-extension;
- file timestamps;
- permission checks;
- symlinks;
- directory iteration;
- extended attributes;
- file locking;
- `fsync`;
- `fdatasync`;
- memory-mapped reads;
- partial failure.

Do not claim broad POSIX compatibility until the relevant court passes.

Operations that are intentionally unsupported must return consistent errors and be listed in the compatibility matrix.

---

# 30. Capacity, statfs, and the visible void

The originating specification proposes:

```text
f_blocks = U64_MAX
f_bfree = U64_MAX
f_bavail = U64_MAX
```

to represent the visible free-space illusion.

Preserve this as an explicitly named **conceptual mode**, not an unqualified production capacity claim.

Define two reporting modes.

## 30.1 Physical-safe mode

Default for ordinary filesystem use.

Report available backing capacity and applied quotas truthfully.

Include the physical cost of retained history and EKBLOOM manifestation when determining whether additional writes are possible.

## 30.2 Logical-plenum mode

An opt-in experimental mode that presents an intentionally unbounded logical-space abstraction.

Its documentation must explicitly state that the physical backing remains finite and operations can still fail with `ENOSPC`.

It must not be advertised as a trustworthy free-space report to applications that require real physical capacity.

This preserves the conceptual distinction while preventing false promises about physical resources.

Administrative tools must always be able to report actual consumption.

---

# 31. Storage exhaustion and non-withdrawal

No authoritative garbage collection means physical growth can be unbounded over the lifetime of the volume.

Implement:

- minimum-free-space reserve;
- configurable soft/hard quotas;
- per-volume maximum historical size;
- emergency read-only transition;
- early allocation failure handling;
- bloom generation throttling;
- physical-capacity alerts.

When free space becomes scarce, stop generating optional bloom structures before allowing them to starve authoritative log commits.

The strictest deployment mode must retain all committed historical data locally.

If archival migration is later introduced, it must have an explicit contract for whether moving bytes to another storage tier still satisfies the intended physical non-withdrawal semantics.

Do not silently delete historical records after copying them elsewhere.

---

# 32. Privacy and security model

Permanent retention has significant implications.

Deleting a file from the logical namespace does not remove its bytes from the authoritative history.

Consequently, OrFS should not be recommended as a general-purpose private-data filesystem without a carefully specified retention and cryptographic access policy.

Even cryptographic key destruction would change the effective recoverability of retained data and may not satisfy the strongest non-withdrawal interpretation.

Document this explicitly.

Security requirements include:

- correct uid/gid and mode enforcement;
- resistance to path traversal through backing paths;
- mountpoint/backend separation;
- strict control of concealed operational files;
- permission checks on historical and query interfaces;
- no unprivileged exposure of deleted content through xattrs;
- safe handling of symlinks;
- no accidental privilege escalation through setuid/setgid bits;
- restricted FUSE `allow_other` behavior;
- corruption rejection;
- bounded allocation from untrusted records.

The backing directory must not be reachable recursively through the mounted namespace.

---

# 33. Physical accounting

Every manifestation has an actual byte cost.

Record:

\[
M_{\mathrm{log}}
\]

for authoritative historical records,

\[
M_{\mathrm{ekbloom}}
\]

for EKBLOOM structures,

\[
M_{\mathrm{indexes}}
\]

for search and namespace structures,

\[
M_{\mathrm{checkpoints}}
\]

for replay accelerators,

and:

\[
M_{\mathrm{total}}
=
M_{\mathrm{log}}
+
M_{\mathrm{ekbloom}}
+
M_{\mathrm{indexes}}
+
M_{\mathrm{checkpoints}}
+
M_{\mathrm{other}}.
\]

Avoid double-counting shared physical extents.

Report:

- logical bytes;
- total historical bytes;
- current live logical bytes;
- bloom bytes;
- total allocated physical bytes;
- growth rate;
- optional retained historical event count.

A concealed structure may be absent from ordinary `readdir`.

It must not be absent from administrative accounting.

---

# 34. Performance model

Avoid unsupported complexity claims.

The principal operations have different costs.

| Operation | Initial expected structure | Important cost |
|---|---|---|
| Create | ordered append transaction | FUSE, commit, index update |
| Sequential write | append extent | I/O and durability profile |
| Random overwrite | new extent + logical mapping change | mapping update and append |
| Read | extent lookup + physical read | mapping depth, caching, copying |
| Snapshot | root record/reference | publication and metadata |
| Unlink | append namespace tombstone | log and metadata update |
| Mount | checkpoint load + replay | time since latest checkpoint |
| EKBLOOM read | certified manifestation selection | bloom residency and read-path work |
| Search | manifested index + candidate verification | postings and result cardinality |
| Historical read | pinned root + historical extent map | index and storage locality |

The original v0.1 100× search acceleration and fixed bloom-size ratios remain **experimental hypotheses**, not achieved results.

No speedup is claimed until measured against a semantically equivalent baseline.

---

# 35. Benchmark methodology

Use independent benchmark dimensions.

## 35.1 FUSE overhead

Compare:

- backing filesystem directly;
- conventional FUSE without special backing I/O;
- FUSE with `io_uring` backing;
- FUSE-over-io-uring where supported.

This isolates transport effects.

## 35.2 Non-withdrawal log

Measure:

- append throughput;
- random overwrite;
- metadata operations;
- snapshot creation;
- replay;
- mount time;
- historical reads;
- physical growth.

Compare against a conventional userspace filesystem and relevant backing filesystems.

## 35.3 EKBLOOM manifestation

For a fixed logical object and workload, vary the physical manifestation budget.

Measure:

\[
\operatorname{Speed}(M)
\]

and identify the fastest valid manifested configuration.

Include full state history and certified multi-step blooms where implemented.

## 35.4 Concealed search

Compare equal-result substring searches:

- direct scan;
- ordinary indexed scan;
- OrFS trigram structure;
- OrFS suffix-oriented structure.

Measure query latency, index-building time, physical bytes, and correctness.

## 35.5 Cross-factor experiment

Use a matrix:

```text
FUSE classic / FUSE uring
        ×
backing sync / backing io_uring
        ×
core only / EKBLOOM acceleration
        ×
cold / warm
        ×
durability profile
```

This prevents crediting EKBLOOM for a speedup actually caused by FUSE transport or page-cache changes.

---

# 36. Benchmark tools and metrics

Suggested tools include:

- `fio` for read/write workloads;
- Criterion or Divan for focused Rust microbenchmarks;
- `perf` for hardware counters;
- `hyperfine` for selected end-to-end commands;
- `pjdfstest` for POSIX behavior;
- xfstests generic tests where applicable;
- custom deterministic replay/crash-fault tests.

Collect:

- throughput;
- IOPS;
- P50/P95/P99 latency;
- CPU cycles;
- instructions;
- cache misses;
- page faults;
- bytes copied;
- physical bytes written;
- journal/log growth;
- system calls;
- queue occupancy;
- synchronization wait time;
- bloom generation time;
- bloom hit rate;
- recovery time.

Do not claim benchmark superiority from one warm-cache run.

Document the exact test host, container, backing medium, kernel, mount options, and data corpus.

---

# 37. Crash and adversarial courts

The filesystem requires a fault-injection court.

At minimum, inject failure:

1. before log reservation;
2. after reservation;
3. during record write;
4. after some records but before commit;
5. during commit footer;
6. after commit completion but before in-memory publication;
7. after in-memory publication but before durable synchronization;
8. during EKBLOOM generation;
9. during bloom publication;
10. during index-checkpoint creation.

Every recovered mount must select a valid committed state.

Earlier committed historical states must remain intact.

No incomplete bloom may be treated as certified.

Additional courts must test:

- concurrent writes to the same inode;
- concurrent rename/unlink;
- random write ordering;
- open-unlink-read;
- snapshot reads during mutation;
- hard-link lifecycle;
- large file offsets;
- integer overflow;
- malicious record lengths;
- malformed filenames;
- corrupted index snapshots;
- missing bloom files;
- ENOSPC during commit.

---

# 38. Native-Rust organization

OrFS should remain one coherent filesystem crate, with the independently developed EKBLOOM engine used as a dependency.

Suggested package structure:

```text
orfs/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── Dockerfile
├── README.md
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── fuse.rs
│   ├── fuse_uring.rs
│   ├── namespace.rs
│   ├── inode.rs
│   ├── extent.rs
│   ├── log.rs
│   ├── transaction.rs
│   ├── segment.rs
│   ├── commit.rs
│   ├── recovery.rs
│   ├── snapshot.rs
│   ├── checkpoint.rs
│   ├── uring.rs
│   ├── manifestation.rs
│   ├── query.rs
│   ├── permissions.rs
│   ├── stats.rs
│   └── error.rs
├── tests/
├── benches/
├── scripts/
├── docs/
└── evidence/
```

Do not build a multi-crate filesystem workspace merely to separate modules.

EKBLOOM retains its own single technology identity.

OrFS is the filesystem that uses it.

The EKBLOOM dependency version or source commit must be pinned.

The filesystem must not reimplement EKBLOOM's state mathematics.

---

# 39. Docker-only development

All project execution occurs in minimal pinned Docker Hub containers.

Never build or benchmark directly on the host.

Provide:

```text
scripts/container-build.sh
scripts/container-test.sh
scripts/container-fuse-test.sh
scripts/container-uring-test.sh
scripts/container-recovery-test.sh
scripts/container-bench.sh
scripts/container-reproduce.sh
```

Pin image digests and toolchains.

Use non-root containers whenever possible.

Mount testing requires access to the FUSE kernel interface, typically `/dev/fuse`, and an appropriately permitted mount environment.

Do not assume this is available in every container.

The default test environment must run:

- log tests;
- namespace tests;
- transaction tests;
- recovery tests;
- EKBLOOM integration tests;

without requiring a FUSE mount.

Run actual mount tests only in a container with the necessary device and permissions.

Do not bypass security restrictions by silently modifying host kernel settings.

Some advanced FUSE-over-io-uring and zero-copy features require kernel configuration or privileges.

If unavailable, record the skipped capability honestly and continue with supported transport modes.

---

# 40. Subagent responsibilities

For implementation, use independent subagents throughout.

Minimum responsibilities:

| Subagent | Focus |
|---|---|
| Log correctness | Non-withdrawal and committed-root identity |
| Transaction engineer | Ordering, atomicity, durability |
| FUSE engineer | POSIX request semantics |
| `io_uring` engineer | SQE/CQE lifetimes, ordering, transport |
| EKBLOOM integrator | Correct accelerated reads |
| Namespace engineer | Inodes, links, extents, snapshots |
| Recovery adversary | Torn writes, corruption, replay |
| Security adversary | Permissions, hostile backing data |
| Performance engineer | Profiles, benchmarking, bottlenecks |
| Reproducibility auditor | Pinned containers and receipts |

Independent reviews should challenge the architecture before declaring milestones complete.

Do not fabricate subagent results if the environment does not provide subagent execution.

---

# 41. Implementation milestones

## M0 — Authoritative log

Deliver:

- volume genesis;
- append-only framed records;
- transaction begin/commit;
- root-by-position identity;
- committed-prefix replay;
- physical segment recovery.

No FUSE required yet.

**Exit gate:** randomized transactions and injected crashes recover to valid committed roots without modifying prior authoritative records.

## M1 — Namespace engine

Deliver:

- inode IDs;
- directories;
- files;
- extent maps;
- logical deletion;
- truncation;
- rename;
- metadata;
- historical snapshot views.

**Exit gate:** filesystem-model tests pass, including arbitrary offset writes and open-unlink behavior at the core API level.

## M2 — FUSE mount

Deliver:

- native-Rust traditional FUSE adapter;
- ordinary read/write/create/unlink;
- permissions;
- correct open-file handles;
- `fsync`;
- real capacity reporting.

**Exit gate:** targeted POSIX tests and crash tests pass.

## M3 — Backing `io_uring`

Deliver:

- ordered append sequencer;
- asynchronous read ring;
- bloom persistence ring;
- bounded backpressure;
- synchronous fallback.

**Exit gate:** identical behavior and verified durability, with performance comparison against synchronous backing I/O.

## M4 — Concealed operational namespace

Deliver:

- `.or_bloom` physical storage;
- logical namespace filtering;
- version-qualified manifests;
- regeneration;
- physical accounting.

**Exit gate:** removing operational structures does not change logical file contents or historical roots.

## M5 — EKBLOOM integration

Deliver:

- EKBLOOM-backed object reads;
- state-history integration;
- certified bloom selection;
- asynchronous generation;
- exact fallback.

**Exit gate:** accelerated and unaccelerated reads return identical data across all tested offsets and versions.

## M6 — Query structures

Deliver:

- trigram indexes;
- substring query API;
- optional suffix structure;
- typed manifest identification;
- independent rebuild.

**Exit gate:** exhaustive small-corpus search parity and larger deterministic corpus correctness.

## M7 — FUSE-over-io-uring

Deliver:

- capability-negotiated optional transport;
- safe fallback;
- transport correctness tests;
- performance comparison.

**Exit gate:** equivalence with traditional FUSE across the supported operation set.

## M8 — Hostile performance court

Deliver:

- transport comparison;
- backing I/O comparison;
- manifestation-size frontier;
- query benchmarks;
- concurrency benchmarks;
- long-term growth and mount-time tests.

**Exit gate:** reproducible results with no unsupported performance claims.

---

# 42. Hard acceptance requirements

OrFS is not complete until the following are demonstrated.

### A. Non-withdrawal

No committed authoritative record is overwritten or removed.

### B. Root identity

Every published root identifies one complete committed historical filesystem state.

### C. Replay

The authoritative log alone reconstructs all supported logical state.

### D. Transaction correctness

Multi-record operations are atomically visible.

### E. POSIX consistency

Supported filesystem operations behave consistently with their documented semantics.

### F. Crash recovery

Interrupted writes and publication do not corrupt earlier committed roots.

### G. Concealed manifestation

EKBLOOM and other generated structures are hidden from ordinary namespace enumeration but physically accounted for.

### H. Exact accelerated reads

Acceleration never changes logical output.

### I. Correct asynchronous I/O

SQE/CQE ordering, buffer lifetimes, errors, and durability barriers are verified.

### J. Reproducibility

All build, correctness, and benchmark steps execute in pinned containers.

### K. Measured performance

Every claimed speed improvement has machine-generated evidence.

---

# 43. Open research questions

**R1.** How much faster can ordinary file reads become when EKBLOOM manifestations are generated specifically for the observed access pattern?

**R2.** Can an OrFS file reach near-memory-speed positional access when its full operational state is manifested?

**R3.** What manifestation size maximises sequential read throughput on a given processor and storage device?

**R4.** Can `io_uring` backing I/O and FUSE-over-io-uring transport compose without introducing new serialization bottlenecks?

**R5.** Can committed history checkpoints make mount time depend primarily on recent activity rather than total retained history?

**R6.** Can new query surfaces be generated without rewriting established authoritative payload?

**R7.** Can snapshot navigation become a constant-small-record operation while historical reads remain efficient?

**R8.** Can EKBLOOM's history and the filesystem's authoritative history share operational structures without conflating their different state semantics?

**R9.** How much extra physical manifestation can be spent before memory bandwidth, cache capacity, or backing storage becomes the limiting resource?

**R10.** Can long-lived immutable file regions use safe kernel passthrough while every mutation still passes through the non-withdrawal log?

These are construction and measurement questions, not established outcomes.

---

# 44. Reference implementation sources

The following are engineering references for Linux interfaces and implementation behavior.

They do not define OrFS's mathematical principles.

**Linux FUSE overview**

https://www.kernel.org/doc/html/latest/filesystems/fuse/index.html

**Linux FUSE I/O modes**

https://www.kernel.org/doc/html/latest/filesystems/fuse-io.html

**FUSE-over-io-uring design**

https://www.kernel.org/doc/html/latest/filesystems/fuse/fuse-io-uring.html

**FUSE-over-io-uring UAPI**

https://www.kernel.org/doc/html/latest/filesystems/fuse/uapi/fuse-uapi-io-uring.html

**FUSE passthrough**

https://www.kernel.org/doc/html/latest/filesystems/fuse/fuse-passthrough.html

**Rust `fuser`**

https://docs.rs/fuser/latest/fuser/

**Rust `io-uring`**

https://docs.rs/io-uring/latest/io_uring/

**Linked `io_uring` requests**

https://man7.org/linux/man-pages/man7/io_uring_linked_requests.7.html

**Filesystem synchronization**

https://man7.org/linux/man-pages/man2/fsync.2.html

**Extended attribute semantics**

https://man7.org/linux/man-pages/man7/xattr.7.html

**FUSE low-level operation contracts**

https://libfuse.github.io/doxygen/structfuse__lowlevel__ops.html

The implementation must verify all capability assumptions against the exact target kernel and selected Rust library versions.

---

# 45. Final specification

OrFS has one authoritative historical direction:

\[
\boxed{
L_{n+1}
=
L_n
\oplus
\text{new committed history}.
}
\]

No prior committed history is withdrawn.

It also has an independent outward acceleration direction:

\[
\boxed{
A_{n+1}
=
A_n
\oplus
\text{new manifested capability}.
}
\]

The second direction is governed by EKBLOOM's principle:

\[
\boxed{
\textbf{Spend manifested space to maximise speed.}
}
\]

The visible filesystem presents ordinary logical files and directories.

The retained log provides historical continuity.

The concealed operational body provides additional speed.

FUSE provides the Linux filesystem interface.

`io_uring` provides asynchronous backing operations and, on supported systems, an additional FUSE transport path.

The requirements are complementary.

They must not be conflated.

**OrFS succeeds when it preserves its complete authoritative history, maintains correct filesystem semantics, and proves through reproducible measurements that deliberate outward manifestation makes useful operations faster.**

No invented benchmarks.

No false capacity claims.

No silently discarded history.

No corrupt or uncertified acceleration used as truth.

No incomplete filesystem semantics passed off as production-ready.

Build and evaluate the actual non-withdrawal, concealed-expansion filesystem.