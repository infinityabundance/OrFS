# OrFS Concealed Query Structures and the Typed Query API

Normative notes for Phase 9: the concealed query body and the typed query
surface. Implements research §11.1 (positional trigram index), §11.2
(suffix-oriented structure), §11.3 (image recognition and multiresolution
geometry), and §12 (a dedicated typed query interface; do not misuse extended
attributes; benchmark honesty). The query plane lives in Plane C (concealed,
disposable, rebuildable) and is accounted for by `src/stats.rs` under
`M_indexes`.

## 1. The one law that governs everything here

> **A query returns the same logical result whether or not a manifested index
> exists.**

Every result is verified against the authoritative logical content
(`Namespace::read_extent`), so a concealed structure can change *how fast* a
query runs but never *what* it returns. An absent, stale, partial, or corrupt
structure degrades to a full authoritative scan with byte-identical output.

## 2. Positional trigram index (`src/trigram.rs`, research §11.1)

The index maps every distinct trigram (a packed 24-bit window `b0 b1 b2`) of a
source to the ascending list of byte positions at which it occurs.

| research §11.1 component | representation |
|---|---|
| trigram key | `u32` (three bytes) |
| posting list | ascending `u32` positions; on disk absolute-first then delta + LEB128 |
| source inode version | `TrigramManifest::inode_version` |
| source logical size | `TrigramManifest::source_logical_size` |
| posting encoding | `PostingEncoding::DeltaLeb128` (recorded in the manifest *and* the payload) |
| verification metadata | `TrigramManifest::source_blake3` (BLAKE3 of the captured source) and `payload_blake3` |

A **candidate** is a byte offset at which the pattern *could* start. The index
selects the **rarest** trigram present in the pattern and returns its posting
positions offset by that trigram's relative position. This is a superset of the
true match starts (a real match always contains that trigram at that relative
position), so the index can never produce a false *negative*. It can produce
false *candidates*; those are removed by content verification (§4).

### 2.1 The compact presence sketch

A positional trigram index is, by construction, roughly as large as its source
(every position is stored). Loading one per file would therefore cost more than
scanning the file. Each manifest therefore also carries a **compact presence
sketch** — a Bloom-style bit set (~1 KiB, sized to ≈10 bits per distinct key,
clamped to 8 KiB) over the index's distinct trigram keys.

The sketch has **no false negatives** (every key is inserted), so it can only
*refute*: if any trigram of the pattern is absent from the sketch, the pattern is
provably absent and the file is skipped **without loading its positional payload
or its content**. False positives merely cost one payload load that verification
would have performed anyway. The sketch lives inside the manifest, which is
already resident in memory after recovery, so the pruning check is free of I/O.

This is what makes the index a net win: the query reads only the payloads and
content of files that survive the sketch (see §9).

## 3. Version identity (research §2 I6)

Every trigram generation is a `TrigramManifest` that records **all** required
identity and integrity fields and is sealed with a self-digest:

```
schema, generation, volume_uuid, inode, inode_version, root,
source_logical_size, source_blake3, posting_encoding,
trigram_count, posting_count, sketch_bits, sketch,
payload_rel_path, payload_blake3, payload_bytes, manifest_blake3
```

`TrigramManifest::usable_for(inode, version, root, logical_size)` requires
**exact** agreement of inode, inode version, committed root, and logical size. A
structure built for one inode version is refused against another.
`TrigramState::usable_for` returns `None` on any mismatch, so a consumer cannot
accidentally read against incompatible content. Decoding rejects any document
whose self-digest does not match, that is truncated, or that has trailing bytes.

Because an OrFS content identity is `(inode, inode_version, root)` — the same
rule Phase 8 uses — a matching manifest means the recorded index describes
exactly the bytes that `read_extent` will return. No re-hashing of the source is
needed per query; the source digest is retained as verification metadata and is
re-checked by the full-scan reference path.

## 4. Verification: candidates are not matches

For a file served by the index, the query reads the file's logical content once
and checks each candidate offset against the actual bytes before reporting it.
A candidate that does not match is counted in `QueryStats::false_candidates` and
discarded. **The index can never report a false match.** This is verified by a
deliberate false-candidate fixture (`index_never_reports_a_false_match`): a
source in which every pattern trigram exists but the full pattern does not.

## 5. Fallback

A file is served by a full authoritative scan whenever the index is

* **absent** — no compatible manifest;
* **stale** — inode version, root, or logical size mismatch;
* **partial/corrupt** — the manifest self-digest fails, the payload BLAKE3
  fails, the payload does not decode, or the payload's own logical size
  disagrees;
* **inapplicable** — the pattern is shorter than a trigram.

The fallback path and the indexed path produce identical match sets (ascending
inode id, then ascending offset). Even within the indexed path, every reported
match is content-verified, so parity is structural, not incidental.

## 6. Asynchronous generation (reuses the Phase-7 machinery)

`TrigramEngine` reuses the Phase-7 job/worker/publication discipline
(`src/manifestation.rs` is the model; the canonical codecs and `dir_bytes` are
shared directly):

* a **bounded** worker pool and queue; when the queue is full `submit` returns
  `TrigramQueueFull` and the optional build is dropped — the commit path is
  never blocked;
* **cancellation** (`TrigramBuildHandle::cancel`) checked before and after
  construction; a cancelled job writes no committed generation;
* **supersession** — a newer inode version refuses to publish a stale structure
  (the engine tracks each inode's newest requested version);
* the **publication protocol** — payload (`tmp → fsync → rename`), manifest
  (`tmp → fsync → rename → fsync(dir)`), then advertisement in `HEAD`. Recovery
  prefers `HEAD`, falls back to a scan of `*.manifest`, and skips any invalid
  candidate.

The plane is enabled explicitly (`Namespace::enable_trigram`). When enabled with
`TrigramConfig::synchronous`, an authoritative commit also synchronously
(refreshes) the touched inode's structure — so a live mount or an
`orfs query --build` can keep the index current. When it is not enabled, a query
still works: it simply scans.

## 7. Typed query API (`src/query.rs`, research §12)

```rust
pub struct QueryRequest {
    pub inode: u64,
    pub root: u64,
    pub pattern: Vec<u8>,
    pub limit: Option<u64>,
    pub recursive: bool,
    pub credential: Credential, // uid/gid for permission enforcement
}
```

* **Streaming** — `Namespace::query_stream(req, &cancel, on_match)` invokes a
  callback per match and accepts an `AtomicBool` cancellation flag; the callback
  may return `MatchFlow::Stop` to stop early.
* **Collecting** — `Namespace::query(req) -> QueryResult` (library interface),
  used by `orfs query`.
* **Limits** — `limit` caps the reported matches; `stats.limit_reached` records
  truncation.
* **Cancellation** — polling between files and within scans; `stats.canceled`.
* **Permissions** — the query calls the *same* POSIX rule as mounted reads
  (`crate::inode::has_permission`, shared with `src/fuse.rs`). A directly
  requested unreadable object is `PermissionDenied`; within a recursion,
  unreadable files are skipped and counted.
* **Consistency** — the request pins one committed `root`; the inode version is
  read from that pinned view and held for the whole run.

### 7.1 Do not misuse extended attributes

The query API is a dedicated interface. It is **not** delivered through
`getxattr`: extended attributes have size/naming limits and are not designed to
stream unbounded result sets (research §12). The `user.orfs.*` attributes remain
scalar administrative values only.

## 8. Suffix-oriented structure (`src/suffix.rs`, research §11.2)

A suffix automaton over a byte sequence supports, with genuinely distinct costs:

| operation | method | cost |
|---|---|---|
| substring existence | `contains` | `O(m)` |
| match count | `count` | `O(m)` |
| all match positions | `match_positions` | `O(m + k)` for `k` occurrences |

Construction is `O(n)` time and `O(n)` states (≤ `2n − 1`). The distinction
§11.2 draws is preserved: a constant-time-ish existence query does **not** give
constant-time enumeration — enumerating occurrences is proportional to the
output. `memory_bytes()` reports an honest footprint estimate. The automaton is
a measured alternative to the trigram index; it is not wired into the query
plane (the trigram index is), and it never changes query semantics.

## 9. Image recognition and geometry (`src/image.rs`, research §11.3)

§11.3 names three correctness concerns, and this module implements exactly
those:

* **format recognition by content, not extension** — `recognize` inspects the
  byte signature (PNG, GIF, BMP, JPEG, WebP, TIFF); a `.png` that is not a PNG
  is rejected and a PNG with no extension is accepted;
* **dimensions** — parsed from the format's own header with its own endianness
  and layout (PNG IHDR, GIF logical-screen descriptor, BMP DIB header, JPEG
  SOF markers);
* **pixel/colour semantics** — the colour model and bit depth are parsed and
  validated; an internally inconsistent header (for example a PNG colour type
  with an impossible bit depth, or a zero dimension) is **rejected**, never
  reinterpreted.

`pyramid_levels(width, height)` reports the conventional halving geometry
(each dimension floored to half, clamped to 1), from which the ~⅓ extra-pixel
figure of §11.3 can be measured.

### 9.1 What is *not* implemented, precisely

The **pixel-surface pyramid** — decoded, downsampled image data materialised
under `.or_bloom/image/` — is deliberately not built, and is never claimed to
be. Producing real surfaces requires a PNG decoder: a zlib/DEFLATE inflater, PNG
filter reconstruction, interlace handling, and colour-space conversion. That is
a real codec dependency (`png`/`image`, or `flate2` + `miniz_oxide`). This build
is offline and single-crate/minimal-dependency, so such a crate cannot be added
here; and hand-rolling an unaudited inflater and lifting pass would directly
threaten the pixel/colour correctness that §11.3 elevates to a correctness
concern. The geometry reported here is *descriptive*; it is not a set of
materialised surfaces, and `src/image.rs` documents this at the source.

## 10. Benchmark honesty (research §12.1)

Ordinary `grep -r` reads file contents through POSIX operations and **does not**
invoke the trigram index. Only `orfs query` (and the library API) uses it.
Speedups are measured against the **equivalent full-scan query API run**, never
attributed to plain POSIX reads. Construction cost, posting counts, the compact
sketch, and the suffix-automaton costs are reported separately.

Refer to `evidence/performance/search-latency.json` for the measured figures on
the current build: on a 48-file / 16 KiB corpus with one selective needle, the
indexed query read 16 KiB of content versus 768 KiB for the scan (≈8.4× lower
median latency), at a one-time construction cost recorded in the same file.

## 11. CLI

```sh
orfs query <path> --pattern <bytes> [--hex] [--limit N] [--build] [--no-recurse] [--json]
```

`<path>` is a backing volume or any path inside one (the volume root is found by
walking up to the directory containing `volume.meta`). `--hex` interprets the
pattern as hex (binary patterns). `--build` builds/refreshes the concealed index
synchronously before querying; without it the query simply attaches the recovered
state and falls back to a scan where no structure exists.

## 12. Invariants exercised by tests (`tests/query.rs`, unit tests)

* **Parity** — indexed and full-scan match sets are byte-identical across
  present/absent/overlapping/binary/multi-match/sub-trigram patterns.
* **No false matches** — a deliberate false candidate is discarded by content
  verification.
* **Version qualification** — a post-write structure is refused; re-indexing
  restores the accelerated, still-correct path.
* **Corruption fallback** — a tampered payload is rejected and the correct
  result is returned by scanning.
* **Limits, cancellation, streaming order, permissions.**
* **Sketch soundness** — the presence sketch never hides a real match.
* **Image recognition** — content-based, extension-independent.

Evidence: `evidence/correctness/query-parity.json` and
`evidence/performance/search-latency.json`.
