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
    ├── suffix/
    ├── image/
    ├── directory/
    └── manifests/    # generation manifests ("<gen>.manifest") + HEAD
```

`src/volume.rs::BLOOM_SUBDIRS` is the single source of truth for the subdirectory
set. Generation manifests live under `manifests/`; EKBLOOM payloads under
`ekbloom/`.

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
1. write payload   (builder writes "<…>.ekb" atomically: tmp + fsync + rename)
2. write manifest  ("<gen>.manifest.tmp" -> fsync -> rename -> fsync(dir))
3. fsync           (payload and manifest are durable before advertisement)
4. publish         (update "manifests/HEAD": tmp -> fsync -> rename -> fsync(dir))
```

Only after the immutable, self-validating manifest is durable is the generation
**advertised** in `HEAD`. Recovery selects the **newest valid committed
generation** per inode:

* discovery prefers `HEAD`; if `HEAD` is missing or torn, every `*.manifest` is
  scanned (the same fallback discipline as index checkpoints);
* each candidate is validated by its self-digest and, when the payload is
  present, by its recorded BLAKE3;
* an invalid candidate is **skipped**, never used, and never invalidates an
  earlier commit.

A torn manifest or torn `HEAD` therefore costs at most the newest generation, not
correctness. (Verified by `recovery_selects_newest_valid_and_ignores_torn`.)

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
