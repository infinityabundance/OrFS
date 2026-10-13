# OrFS — Rejected Design Candidates (Phase 71)

This file records design candidates that OrFS has **deliberately rejected**, so that
a reader cannot mistake a rejected idea for a feature that is "designed but not yet
implemented". A rejected candidate is removed from the implemented specification
(the phase tables and the normative documents); it lives here instead, with the
reason and the conditions under which it would be reconsidered.

The project's honesty rule applies: nothing is presented as implemented unless it
is, and nothing is presented as pending work when it has actually been decided
against. See `docs/ORFS-SPEC.md` §4/§5.

## 1. The image pixel-surface pyramid — REJECTED

**What it was.** Research §11.3 describes image "recognition and multiresolution
geometry"; an earlier reading of that idea proposed a *pixel-surface pyramid* — a
set of decoded, downsampled image surfaces materialised under `.or_bloom/image/`
(next to the other concealed manifestations), so that a thumbnail-like level could
be served directly.

**Why it is rejected.**

1. **Geometry alone provides no user-visible capability.** `src/image.rs` parses a
   file's format by content, its dimensions, and its colour/bit-depth semantics, and
   `pyramid_levels(width, height)` reports the conventional halving geometry. That is
   a *descriptive* answer about the header — it is not a pixel surface, it accelerates
   no query, and nothing in OrFS reads it back as an image. Keeping it in the spec as
   a "not materialised" feature implied a capability that does not exist.
2. **Materialising real surfaces needs a decoder dependency the project deliberately
   avoids.** Producing PNG surfaces requires a zlib/DEFLATE inflater, PNG filter
   reconstruction, interlace handling, and colour-space conversion — a real codec
   dependency (`png`/`image`, or `flate2` + `miniz_oxide`). OrFS is an offline,
   single-crate, minimal-dependency build, and hand-rolling an unaudited inflater and
   lifting pass would directly threaten the pixel/colour correctness that §11.3
   elevates to a correctness concern.
3. **It is not on any critical path.** No query, read path, snapshot, recovery, or
   POSIX operation depends on a pixel surface. There is no court that would measure
   one, and no operator workflow that would use one.

**Status now (Phase 71).**

* Removed from the implemented spec. `docs/QUERY.md` §9.1 now declares it rejected
  and points here; `docs/ORFS-SPEC.md` §4 no longer lists it as an intended-but-
  unbuilt feature; `README.md` and `docs/LIMITATIONS.md` state the rejection.
* **Kept, implemented, and tested:** content-based image **recognition**,
  **dimension** parsing, **colour/bit-depth semantics**, and the descriptive
  `pyramid_levels` geometry (`src/image.rs`, `tests/query.rs`). These are honest,
  self-contained capabilities; only the *materialised pyramid* is rejected.

**Reconsidered — a possible dependency-free BMP path (proposal only).** The pyramid
could be materialised for one format *without* a decoder dependency: an
**uncompressed BMP** (24- or 32-bit `BI_RGB`) is already parsed by `probe_bmp`, and
its pixel array is stored little-endian, row-padded, and uncompressed, so a
dependency-free reader and a box-downsample are a couple of small steps — no
inflater, no filter/interlace/colour-space handling. This is offered only as a
follow-up if a concrete use for materialised surfaces ever appears; it is **not**
implemented here, and if pursued it is a separate coding task with its own court and
its own `docs/PERFORMANCE.md` section. Until then the pyramid remains rejected.

## 2. How to add a rejected candidate

Add a numbered section: what the idea was, the concrete reasons it is rejected (not
merely "unimplemented"), where it is excluded from the spec, and — only if a cheap,
honest path exists — a clearly-labelled *reconsidered* note that proposes (does not
implement) a follow-up. Do not leave the idea in the phase tables.
