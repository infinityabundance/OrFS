# OrFS Concealed Manifestation and Physical Accounting

Normative notes for Phase 7: the concealed operational body — asynchronous,
version-qualified manifestation with physical accounting. Implements research
§2 (I5, I6, I8), §4, §9, §10, §16, §33.

## 1. Two planes, one log

OrFS separates an **authoritative body** (permanent, non-withdrawal) from a
**concealed operational body** (generated, rebuildable). Phase 7 realises the
operational body in `src/manifestation.rs`; `src/stats.rs` accounts for both.

```
authoritative plane     Plane A   volume.meta + or.log        (never withdrawn)
namespace plane         Plane B   index/                      (rebuildable)
concealed plane         Plane C   .or_bloom/                  (disposable, rebuildable)
transport plane         Plane D   FUSE + io_uring
```

**Law I** — a fault in Plane C can never corrupt Plane A. The manifestation
engine never writes to `or.log`; it only *reads* authoritative bytes. Logical
reads are byte-identical with or without any manifested structure, and after
deleting all of `.or_bloom/` (research §2 I5, §16).

## 2. Physical layout (research §4)

`orfs init` creates the concealed body:

```
backing/
├── volume.meta
├── or.log/
├── index/
└── .or_bloom/
    ├── ekbloom/      # EKBLOOM payloads ("<inode>-v<version>-r<root>-g<gen>.ekb")
    ├── trigram/      # optional other acceleration families (Phase 9)
    │   └── catalogue/  # append-only discovery log for trigram manifests
    ├── suffix/
    ├── image/
    ├── directory/
    └── manifests/    # generation manifests ("<gen>.manifest")
        ├── catalogue/  # append-only discovery log (segments + summary + pointer)
        │   ├── CURRENT
        │   ├── seg-<index:010>.cat
        │   └── sum-<through:010>.sum
        └── HEAD        # legacy advertisement, read-compatible only
```

`src/volume.rs::BLOOM_SUBDIRS` is the single source of truth for the subdirectory
set. Generation manifests live under `manifests/`; EKBLOOM payloads under
`ekbloom/`; the append-only catalogue under `manifests/catalogue/` (§7.1).

## 3. Generation identity (research §2 I6, §9)

Every committed generation is a [`GenerationManifest`] recording **all** required
identity, construction, certification, integrity, and accounting fields:

| Field | Meaning |
|---|---|
| `volume_uuid` | volume identity |
| `inode` | object (inode) identity |
| `inode_version` | the source inode **version** (I6) |
| `root` | the authoritative committed root it was built from |
| `ekbloom_version` / `ekbloom_format` | EKBLOOM engine (0.3.0) and on-disk format (0.3) |
| `profile` / `profile_kind` | the manifestation profile used |
| `logical_range` | `[logical_start, logical_end)` the structure serves |
| `physical_range` | `[physical_start, physical_end)` in the payload file |
| `parameters` | `interval`, `depth`, `region_bytes` |
| `certification` | state (`unmanifested`/`built`/`unverified`/`certified`/`rejected`) + method |
| `payload_blake3` | BLAKE3 over the payload bytes |
| `manifest_blake3` | BLAKE3 over every preceding canonical field (self-integrity) |
| `visible_bytes` / `physical_bytes` / `concealed_bytes` | physical size accounting |
| `components` | per-structure byte breakdown (EKBLOOM `inspect`) |

On disk a manifest is a canonical little-endian document with a trailing
self-digest. Decoding rejects any document whose self-digest does not match,
that is truncated, or that has trailing bytes.

### Version qualification (I6)

`GenerationManifest::usable_for(inode, version, root)` requires **exact**
compatibility of inode, inode version, and committed root. A structure built for
one inode version is refused against another. `ManifestationState::summary(inode,
version)` returns `None` on any mismatch, so a consumer cannot accidentally read
against incompatible content.

## 4. Profiles (research §10.1)

`ManifestationProfile` mirrors the research set and maps 1:1 onto
`ekbloom::ManifestationProfile` (the labels are EKBLOOM's own, so the two crates
never drift):

```
root | sparse | dense | full | bloom4 | bloom8 | regional | path4 | max-speed
```

`orfs manifest`/`orfs grow` accept these names plus `--depth`, `--interval`, and
`--region-bytes` overrides. The **actual** profile and its exact physical byte
consumption are recorded in every manifest; nothing is inferred later.

## 5. Background construction and the commit path (research §10.3)

After a successful authoritative commit **and** version publication,
`Namespace::commit_plan` enqueues a manifestation job **only if** the plane is
enabled. The foreground write never waits for optional construction unless the
caller explicitly opts into synchronous manifestation
(`ManifestationConfig::synchronous`, `orfs mount --manifest-sync`, or a
one-shot `orfs manifest`/`orfs grow`, which build on the calling thread).

The job captures the inode's authoritative logical bytes at enqueue time; CPU
worker threads build from that immutable snapshot. **Workers never touch the
authoritative log**, so construction cannot perturb it, and `io_uring` is
deliberately **not** used to construct (research §20 Ring B is a persistence
optimisation, not a build engine).

The **bounded** worker pool and queue provide backpressure: when the queue is
full, `ManifestationEngine::submit` returns `QueueFull` and the optional
construction is dropped. The authoritative commit is never blocked or failed by
a full queue (verified by
`bounded_queue_backpressure_does_not_starve_commits`).

## 6. Cancellation and supersession (research §9, §10.3)

Two mechanisms prevent a stale structure from being used:

* **Cancellation.** A job may be cancelled while it is in flight. Cancellation is
  checked before construction and again immediately after it; if set, the
  generated payload is deleted and **no** manifest is written. The incomplete
  generation stays uncommitted and invisible to ordinary reads.
* **Supersession.** The engine tracks each inode's newest requested version. When
  a newer version is enqueued, older pending jobs for that inode are cancelled,
  and a worker refuses to publish if the inode has since advanced (research
  §10.3: "the bloom worker must not publish an acceleration structure for a newer
  inode version merely because its construction finished later").

A cancelled job leaves **no committed generation** (verified by
`cancel_mid_construction_leaves_no_committed_generation`, which asserts both the
in-memory published set and the on-disk recovery are empty).

## 7. Publication protocol

A generation becomes visible through an explicit, crash-safe protocol:

```
1. write payload    (builder writes "<…>.ekb" atomically: tmp + fsync + rename)
2. append catalogue (one immutable, CRC32C-framed record: O_APPEND + fsync)
3. write manifest   ("<gen>.manifest.tmp" -> fsync -> rename)
4. batch fsync      (the manifest directory is fsynced for small volumes and
                     otherwise at the catalogue segment boundary)
```

The **commit point** is the durable catalogue record together with the durable
manifest. The catalogue is appended *before* the manifest is written, so any
durable manifest is already catalogued; a catalogue entry whose manifest is
missing or invalid is detected at recovery and triggers a full validated scan.
Publication never rewrites a whole discovery list, so its cost is **O(1)
[amortized]** and flat in the number of accumulated generations `G`. (Before this
change publication rewrote the entire `HEAD` generation list — read + sort +
serialize + fsync a file whose length grows with `G` — i.e. `O(G)` per
publication and `O(G²)` cumulatively.)

Recovery selects the **newest valid committed generation** per inode:

* discovery prefers the append-only catalogue; the legacy `HEAD` advisory and the
  full `*.manifest` scan remain as the backward-compatible fallback;
* each candidate is validated by its self-digest and, when the payload is
  present, by its recorded BLAKE3;
* an invalid candidate is **skipped**, never used, and never invalidates an
  earlier commit.

A torn manifest, a torn catalogue record, a corrupt catalogue summary, or a torn
legacy `HEAD` therefore costs at most the newest generation, not correctness.
(Verified by `recovery_selects_newest_valid_and_ignores_torn` and
`catalogue_equals_full_scan_and_survives_damage`.)

### 7.1 The append-only generation catalogue

The catalogue (`manifests/catalogue/`) is an immutable, append-only record log
that replaces the whole-list rewrite:

| file | role |
|---|---|
| `seg-<index:010>.cat` | append-only segment; immutable once sealed; fixed 128-byte records |
| `CURRENT` | small pointer naming the active segment; rewritten **only** when a segment is sealed, never per record |
| `sum-<through:010>.sum` | immutable folded *newest-per-inode* summary, written at a seal |

A **record** is a fixed body — `family`, schema, `generation`, `volume_uuid`,
`inode`, `inode_version`, `root`, `manifest_blake3`, `payload_blake3` — framed as
`body_len || body || crc32c`. A segment is sealed (`sum-<index>.sum` written,
`CURRENT` advanced) once it passes 128 KiB; a fresh segment then receives further
appends. Because every record is fixed-size and checksummed, a **torn or
truncated tail is detected and skipped**, and a **corrupt summary is ignored** so
recovery re-reads the segments (or an earlier summary). A sealed segment, like a
manifest, is never rewritten (non-withdrawal).

The summary folds the **newest entry per inode** through the sealed segment, so
recovery reads the newest usable summary plus **only the segments after it**
(proportional to the catalogue suffix, not the whole history). The same design is
used, with a distinct family tag, for the concealed trigram registry
(`trigram/catalogue/`).

The catalogue is **derived and reconstructible**: deleting `manifests/catalogue/`
never changes the recoverable set — recovery falls back to the legacy `HEAD`/
full `*.manifest` scan and the catalogue is re-seeded by the next publication
(for example `orfs manifest`/`orfs grow`). A manifest-directory `fsync` (whose
cost grows with `G`) is batched to the seal, keeping publication amortized
constant; a manifest whose directory entry is not yet durable is simply rejected
at recovery (the fast path falls back and selects the previous, committed
generation).

## 8. Retention policy and rebuild

Committed generations are **disposable acceleration**: dropping all of
`.or_bloom/` and rebuilding must yield byte-identical **logical** reads
(research §2 I5, §16; verified by `drop_all_and_rebuild_yields_identical_logical_bytes`).

The retention policy distinguishes:

* **committed generations** — retained; never removed by the engine, either
  explicitly or by a sweep;
* **orphan payloads** — `.ekb` files referenced by no committed manifest (for
  example a job cancelled after it wrote physical bytes, or a manifest whose
  payload was torn). `GenerationStore::sweep_orphans` is the only reclamation
  path and removes *only* unreferenced payloads.
* **the catalogue** — derived discovery state; it is rebuildable (see §7.1) and
  its segments and summaries are immutable (appended, never rewritten).

EKBLOOM's full-history mode may carry a stronger retention contract of its own;
this document governs only OrFS's disposable acceleration plane and does not
weaken the authoritative non-withdrawal invariant (research §9).

## 9. Physical accounting (research §33)

`src/stats.rs` reports logical and physical quantities separately and never
claims unlimited capacity:

* **logical** — `logical_live_bytes` (sum of live regular-file sizes at the
  committed root), `logical_file_count`, `logical_directory_count`,
  `logical_symlink_count`, `logical_inode_count`;
* **physical categories** — `M_log` (authoritative `or.log/`, including retained
  non-canonical tails), `M_ekbloom` (`.or_bloom/ekbloom/`), `M_indexes`
  (`index/` + the optional search families), `M_checkpoints` (replay
  accelerators; index checkpoints are records *inside* `or.log`, so this separate
  area is empty today and documented as such), and `M_other` (generation
  manifests + residual metadata);
* **capacity** — `backing_capacity` returns the real `statvfs` totals; available
  space is never fabricated. `orfs stat` reports all of the above; the FUSE
  `statfs` `physical-safe` mode reports the real backing capacity, while
  `logical-plenum` remains the explicitly opt-in illusion (research §30).

The five categories **partition** every byte beneath the backing directory, so
the invariant

```
M_total == measured on-disk total
```

holds exactly (verified by `accounting_matches_on_disk_bytes`).

The derived `user.orfs.*` extended attributes are wired to this plane:
`user.orfs.manifested_bytes` reports the inode's manifested physical bytes for
its **current** version (`0` when nothing is manifested, and `0`/`none` on any
version mismatch), and `user.orfs.ekbloom_profile` reports the recorded profile
(`none` when unmanifested). A historical `Snapshot` reports `0`/`none` — it does
not carry the live volume's manifested structures.

## 10. CLI

```sh
orfs stat    <backing-or-mount> [--json]         # logical vs physical accounting
orfs manifest <backing> [--inode N] \
              --profile <p> [--depth D] [--interval K] [--region-bytes R] [--json]
orfs grow     <backing> --profile <p> [...] [--json]
orfs mount    <backing> <mnt> --manifest <profile> [--manifest-sync] [--manifest-workers N]
```

`orfs manifest`/`orfs grow` open the volume read-only, build and publish
generations synchronously, and report per-object outcomes. `orfs mount
--manifest` enables the asynchronous plane for a live mount (default: disabled).

## 11. Invariants exercised by tests (`tests/manifestation.rs`)

* **I6** — generations are version-qualified; a mismatched version is refused.
* **Cancellation** — a mid-construction cancel leaves no committed generation.
* **Rebuild** — dropping all of `.or_bloom/` and rebuilding yields identical
  logical bytes.
* **§16** — a completed manifestation changes no visible file contents.
* **§33** — accounting totals equal actual on-disk byte counts.
* **Backpressure** — a bounded queue does not starve authoritative commits.
* **Round-trip** — a randomized (`proptest`) manifest encode/decode round-trips
  and rejects any tampered byte.
* **Catalogue** — the append-only catalogue round-trips, rejects a wrong-family,
  truncated, or tampered record/pointer/summary, and (in
  `tests/manifestation_catalogue.rs`) its accelerated recovery equals a full scan
  on the recoverable set under a torn record, a corrupt summary, and a missing
  manifest or payload.

Evidence: `evidence/recovery/manifested-generation.json` (publication,
cancellation, recovery, version-qualification verdicts and the committed
manifests) and `evidence/performance/manifestation-accounting.json` (logical vs
physical figures with the on-disk totals match).

## 12. Explicitly out of scope for Phase 7

* The **read path** that selects and consumes a manifested structure (§10.2
  fastest compatible path) is Phase 8, delivered in `src/readpath.rs` and
  documented in `docs/EKBLOOM-INTEGRATION.md`. Phase 7 builds, publishes,
  recovers, and accounts for generations; it does not itself serve reads from
  them, and no Phase 7 code changes the bytes any read returns.
* The optional trigram/suffix/image families (research §11) and the typed
  query API (§12) are Phase 9, delivered in `src/trigram.rs`, `src/query.rs`,
  `src/suffix.rs`, and `src/image.rs`, and documented in `docs/QUERY.md`. They
  are accounted for here (under `M_indexes`) but are not built by this phase.

## 13. Phase 16: where the manifested body actually wins (end to end)

The governing objective is *spend manifested space to maximise speed*, so Phase
16 measured the concealed body **end to end through a real FUSE mount with real
POSIX syscalls**, and separated the effect of the structure from FUSE transport
and the page cache (`tests/ekbloom_frontier_e2e.rs`; evidence
`evidence/performance/ekbloom-e2e.json` with the `fragmented-e2e`, `search-e2e`,
and `e2e-defensive` variants and their `-release` counterparts; discussion in
`docs/PERFORMANCE.md` §5.4–5.6). The honest findings:

* **Random single-byte reads on a large file *do* win — in a release build.**
  A compatible **certified** `path`/`full`/`max-speed` generation serves a byte
  from the concealed payload in ~26 ns instead of a backing `pread`, so through
  the mount a random 1-byte read is ~**1.3–1.4× faster** than the same mount
  with no manifestation (P50 2955–3166 ns vs 4118 ns). The *uncertified*
  `bloom(4)` profile is **slower** (5050 ns) because verify-on-use re-reads the
  authoritative path; a manifest with no *certified* path structure is not a
  win. In a debug build the planner's per-read overhead hides the win, and that
  is reported, not omitted.
* **4 KiB reads do not win.** A path bloom costs one `symbol_at` per byte and
  the authoritative extent read is already O(1); the planner correctly selects
  the authoritative path (`paths_chosen_by_the_planner` records this) and the
  returned bytes are identical.
* **Fragmented objects win clearly.** `ExtentMap::plan_read` scans the extent
  list linearly, so an object built from many small scattered writes has an
  O(N) authoritative read. A certified `path(4)` bloom is fragmentation-agnostic:
  **1.24× (release) / 1.75× (debug)** for random 1-byte reads, at identical
  mount options.
* **Warm page-cache reads are unaffected** (≈110–220 ns for every profile): the
  kernel cache, not the manifestation, decides that case.
* **Content search is the big, unambiguous win** and comes from the concealed
  **trigram index** (under `M_indexes`), not the EKBLOOM `M_ekbloom` ladder: it
  is **8.6–8.8×** faster than the typed API's own scan and reads **48×** less
  content. Ordinary `grep -r` does **not** use it (research §12.1) and is a
  transport-bound scan.
* **Best value per byte:** `path(8)` (M ≈ 2.5× logical) is within ~4% of the
  fastest single-byte profile in release, so it is the best space-for-speed
  point; larger `M` (`path(1)`, `max-speed`) buys no further speed. Notably the
  best profile is **not the largest** — `max-speed` (7.0×) is not faster than
  `path(8)` (2.5×).

The bytes any read returns are unchanged with or without a manifested body
(§8, and the Phase-8/16 equivalence courts), and dropping `.or_bloom/` restores
byte-identical logical reads.

## 14. Phase 22: incremental, adaptive generational manifestation

A Phase-7 job reconstructed the **entire** logical object into a source buffer,
so for a large object the construction cost `T_build` was proportional to the
object size `N` even when a transaction changed a few kilobytes. Phase 22 makes
the unit of work the **changed ranges**, not the whole object.

### 14.1 The overlay model

Every generation is now either a *self-contained* generation or an *overlay*:

* a **full base** (legacy shape) — one top-level payload over `[0, N)`;
* a **flattened table** — no base, with a complete region table over `[0, N)`,
  each region referencing a committed payload (built adaptively, see §14.3);
* an **overlay** — `base_generation` plus the *changed* ranges only. Every byte
  not in a changed range is **reused** from the base.

A `GenerationManifest` (schema 2) records `base_generation`,
`base_manifest_blake3`, `overlay_depth`, and a `regions` vector. Each
`ManifestRegion` maps a logical range onto a payload file, records the payload's
BLAKE3 and EKBLOOM object identity, and carries `payload_offset` (the local
offset within that payload corresponding to `logical_start`). Schema-1 documents
still decode (their overlay fields default to a self-contained full base).

A change is captured from the authoritative commit itself: the transaction plan
records the exact logical byte ranges each touched inode wrote (`write_at`,
`zero_range`, and a size change). The enqueue path reads **only those ranges**
from the log and hands the worker the changed authoritative slices; the worker
builds one small EKBLOOM payload per range. A metadata-only change produces an
empty-delta overlay that keeps the acceleration version-current at index cost.

### 14.2 Reuse, compatibility, and integrity

Reuse is only ever of **committed** manifested content, subject to explicit
checks. On every read a region is accepted only if:

* the base manifest exists, decodes, self-verifies, is for the **same inode**,
  and its self-digest matches `base_manifest_blake3`;
* the region payload's on-disk BLAKE3 matches the recorded digest, its EKBLOOM
  object identity matches, and EKBLOOM's own `verify` passes (core hash and
  decode length);
* the region is inside the generation's logical extent.

Authority still determines every byte: a changed range's payload is built from
the authoritative bytes of exactly that range at the committed root, and an
unchanged range is reused only because the transaction that produced the overlay
did not touch it. The read planner additionally **verifies an overlay on first
use** against the authoritative read; on any disagreement the overlay is barred
for that identity and the authoritative bytes are served. Accelerated reads are
therefore byte-identical with authoritative ones.

### 14.3 Bounded-depth lookup and adaptive flattening

Resolving a committed version to its regions walks the overlay chain at most
`MAX_OVERLAY_DEPTH = 8` hops (`manifestation::resolve_coverage`). The engine
never publishes a deeper overlay: when an overlay would exceed
the bound — or once `FLATTEN_AFTER_OVERLAYS = 4` overlays have accumulated — it
publishes a **flattened readable view** instead: a complete region table with
`overlay_depth = 0` that references the existing committed payloads. Flattening
is **index-only** (it does not rebuild unchanged bytes) and leaves authoritative
history untouched. A read then resolves in a single hop, and the depth, not the
number of accumulated generations, bounds read latency. Region lookup within the
flat table is a binary search over disjoint sorted regions.

### 14.4 Crash-safety

The publication protocol is unchanged: each region payload is written and
fsynced, the manifest is written atomically (`tmp` → fsync → rename → fsync
dir), and only then is the generation advertised in `HEAD`. An incomplete
incremental manifestation has **no manifest** and is invisible. Recovery selects
the newest **valid** committed generation: it validates each candidate's payloads
and then, ascending by generation, accepts an overlay only if its base is itself
accepted, valid, for the same inode, and digest-bound. A newest overlay whose
base is missing or torn is skipped, and a strictly earlier commit remains
selected. A cancelled incremental job deletes every region payload it wrote.

### 14.5 Measured economics

`evidence/performance/incremental-manifestation.json` (generated by
`tests/manifestation.rs`) measures the construction `ekbloom::create` performs
per payload, so the figure is not polluted by fsync:

| object size | full build (whole object) | 64-byte change (incremental) |
|---|---|---|
| 32 KiB | 0.86 ms | 7.4 µs |
| 128 KiB | 2.79 ms | 3.4 µs |
| 512 KiB | 11.57 ms | 6.1 µs |

The full build grows with the object; the incremental build stays small (~3–7 µs)
and roughly flat in the unchanged size. At a fixed 256 KiB object the incremental
build grows with the changed bytes
(64 B ≈ 7.3 µs, 1 KiB ≈ 24.1 µs, 8 KiB ≈ 168.8 µs, 32 KiB ≈ 676.2 µs), which is
the intended `T_incremental ≈ T_changed_regions + T_index_update`.
The same evidence records read latency against generation depth (~3 µs, flat,
because flattening bounds the depth) and the flattening effect.

### 14.6 Invariants exercised by tests

The Phase-22 courts extend `tests/manifestation.rs` and `tests/ekbloom_read.rs`:
construction cost independent of unchanged size
(`incremental_build_cost_tracks_changed_bytes_not_object_size`); bounded read
latency and depth with flattening
(`read_latency_bounded_and_flattening_caps_depth`); a crash mid-incremental
build leaving no committed generation or orphan region payload
(`crash_mid_incremental_build_leaves_no_committed_generation`); and overlay reads
equal to the authoritative bytes across many interleaved writes and historical
snapshots
(`overlay_reads_are_authoritative_across_generations_and_snapshots`); plus an
async chained-overlay court
(`async_incremental_generations_recover_without_rejection`) that every committed
generation recovers with no rejection.

### 14.7 History-scaling court (reviewer item 4)

`tests/history_scaling.rs` measures what happens to the time spent answering the
same historical read workload as certified manifestations accumulate over a
growing committed history, and compares it with the same history answered with
the manifested plane **disabled**. Construction, persistent bytes, foreground
work, recovery and reuse are all recorded; byte-exactness of the pinned-root reads
across the two arms is asserted. The result is nuanced and reported as measured:
the generic `history` body is a roughly constant ~3.1 ns/byte, flat once selected
but **slower** than a lightly-fragmented authoritative read and **faster** than a
heavily-fragmented one, while construction and persistent bytes grow steeply and
manifested-plane recovery grows with the accumulated generation count. See
**`docs/PERFORMANCE.md` §13** for the numbers and
`evidence/performance/history-scaling.json` for the evidence; run the sweep with
`sh scripts/container-history-scaling.sh`.

## 15. The append-only catalogue and its scaling court (reviewer task)

`GenerationStore` and `TrigramStore` discover committed generations through the
append-only catalogue described in §7.1. The catalogue is **derived** (Plane C) and
never authoritative: it is rebuilt from the immutable manifests after damage, its
segments are immutable, and the authoritative log and every manifest are
untouched by it.

`tests/manifestation_catalogue.rs` is the acceptance/scaling court. Its always-on
parts assert that the catalogue-accelerated recovery equals a full scan on the
recoverable set after a torn record, a corrupt summary, and a missing manifest or
payload, and that per-publication work does not scale with `G`. Its opt-in sweep
(`ORFS_CATALOGUE_SCALING=1`, run by
`sh scripts/container-manifestation-catalogue.sh` in a release build) publishes and
recovers at **1 000 / 10 000 / 100 000 / 1 000 000** accumulated generations and
records publication p50/p99, metadata bytes rewritten per publication, directory
operations, recovery time (catalogue-accelerated and full scan), and resident
memory. It writes `evidence/performance/manifestation-catalogue.json`; the numbers
and the honest caveats (single run, single host; a bulk fixture for the very large
checkpoints) are discussed in **`docs/PERFORMANCE.md` §14**.
