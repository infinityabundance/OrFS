# OrFS — The Index-Spine Decision (Phase 71)

This document records the **final index-spine decision**: which physical layout
backs the inode-id index for which role, the exact criteria used to decide it, and
why the production writer spine is **not** replaced. It reconciles the two courts
that asked the question — `docs/PERFORMANCE.md` §16 (the layout competition) and
§24 (the historical integration) — into one decision a reviewer or operator can
read without re-deriving it from the evidence.

## 1. The question

OrFS keeps a namespace index that maps:

* **numeric inode ids** (`u64`, allocated densely and monotonically) to inodes; and
* **byte-string directory names** to child inode ids.

Historically both used one physical layout: the Phase-27 **path-copying persistent
treap** (`PMap`, `src/persistent.rs`). The index is *published to readers as an
immutable snapshot at every commit*, so any replacement must not merely be faster
to look up — it must not regress **publication** (the `Clone` that hands readers a
new root) or **namespace mutation** (an insert/remove, i.e. two path copies).

There are two distinct consumers with opposite needs:

1. the **live writer** index inside a mutable `Namespace`, whose snapshot is
   republished on every commit; and
2. a **sealed historical** index — a committed root decoded from an accelerator that
   is *only ever read*, never mutated.

## 2. Decision

| Role | Spine | Name returned by `Index::inode_layout()` | Why |
|---|---|---|---|
| Live, publication-sensitive **writer** index | persistent path-copying **treap** (`PMap`) | `persistent-treap` | `O(1)` publication and `O(log n)` small-node copies; no candidate beat it without regressing mutation (§16) |
| **Sealed, immutable historical** index | **sealed dense-ordinal** (`InodeStore::Sealed`, `src/index.rs`) | `sealed-dense-ordinal` | a direct id-indexed array is flat `O(1)` and far more compact; a committed root is never mutated, so the mutable spine's advantage is irrelevant and its pointer overhead is not wanted |
| Byte-string **directory** index (`children`) | persistent path-copying treap | — | unchanged; the layout competition was for the numeric inode-id role only |

The live spine **stays the treap**; the sealed role **uses the dense-ordinal**.
Nothing about the two roles overlaps: `Index::from_log`, `apply_range`,
`apply_record`, and the commit path never seal, so a mutable index is always
`persistent-treap`; only the decode of an immutable historical accelerator
(`Index::decode_packed`, `historical::decode_historical`, via `Index::seal_inodes`)
produces `sealed-dense-ordinal`.

## 3. The exact criteria (the decisive rule)

A candidate layout is integrated **only where it wins and cannot regress anything**.
Applied literally:

* For the **live** role the rule from §16 is:

  > *a faster point lookup is insufficient if snapshot publication or namespace
  > mutation regresses.*

  A candidate must beat the treap on point lookup **without** making publication or
  mutation worse. Neither prototype did, so the treap remains.

* For the **sealed historical** role the rule from §24 is:

  > *integrate only where it wins and cannot regress publication or mutation: the
  > sealed layout must be more compact and not slower on the point lookup, and the
  > live spine must remain the treap.*

  The dense-ordinal satisfies all three conjuncts, so it is integrated — **and only
  there**.

Publication is never the differentiator: it is `O(1)` for every persistent
candidate (`Clone` ≈ 20–30 ns, flat in scale) and for a sealed layout (an `Arc`
clone), so it cannot decide. **Mutation decides.**

## 4. Why the treap is not replaced

* **Mutation regresses for the alternatives.** In `evidence/performance/index-layout.json`
  (retained scales 10 000 / 100 000 / 1 000 000), the page tree's insert+remove is
  **2.66×** the treap's at 1 M inodes and the segmented radix's is **2.42×**
  (2.4–2.9× and 2.4–4.3× across the sweep): a page copy moves far more bytes than
  the treap's `O(log n)` small nodes. Per the decisive rule this alone disqualifies
  them as a live spine.
* **A byte-radix is the wrong shape for dense sequential ids.** Inode ids are
  allocated monotonically, so they are dense and sequential — the adversarial case
  for a trie. The measured radix degenerates (depth 8, ~1 entry per leaf) and uses
  ~1.7× the treap's bytes.
* **The prototypes remain court candidates, never production.** `src/radix.rs` and
  `src/pagetree.rs` are separate types; they do not touch the production index API or
  the snapshot/immutability guarantees. `index-layout.json` carries a machine-computed
  `decision` with `integrate = null` (no candidate wins at every scale).

## 5. Why the sealed dense-ordinal for the historical role

Because inode ids are dense and monotonic, a committed root's inode-id spine can be
a direct-ordinal array indexed by id. That is legal *only* because the domain is
dense, and it is desirable *only* because the root is immutable:

* **Flat `O(1)` lookup.** A constant p50 of **20 ns** at every scale, versus the
  treap's 30 → 40 → 60 ns as it grows; the bulk mean is 0–1 ns at 1 M versus 289 ns
  for the treap — no pointer chasing, no cache-miss-bound `O(log n)` walk.
* **~7× more compact.** The one-pointer-slot sealed spine is **8.0 MB** versus the
  treap's **56.0 MB** at 1 M inodes (ratio 0.143). (§16's *`u64`→`u64`* dense form
  was already ~3.5× smaller, 16 MB vs 56 MB; the sealed form is smaller again
  because a slot here is one pointer, not a key-value pair.)
* **It cannot regress the writer.** The live spine measured at every scale is
  `persistent-treap`; the integration adds no code to `from_log` / `apply_record` /
  commit, so live mutation and publication are the pre-existing Phase-27 behaviour
  *by construction*. Publication is unchanged (an `Index` clone is a handful of `Arc`
  copies for both layouts, ~50–60 ns, flat).
* **The cost is a one-time re-seal at decode.** Building the dense array from the
  treap takes 237 µs / 2.9 ms / 101 ms at 10 k / 100 k / 1 M — paid when an
  accelerator is decoded (a warm historical-root open or a validated quick open),
  never on the live path.
* **Correctness is asserted, not assumed.** The two forms answer identical lookups
  (present and absent ids), ordered id enumeration, `readdir`, dentry `lookup`,
  `parent_of`, `is_live_dir`, `latest_offset`, share a canonical digest, and compare
  **equal by content** (`PartialEq` is structural, not representational). A sealed
  spine that is ever mutated **thaws** back to the treap; a sparse id domain (never
  produced by a well-formed history) is left as the treap.

## 6. Evidence

Both numbers below are machine-checked by `scripts/check-docs-receipts.sh` against
the committed receipts.

* **Spine size at 1 M inodes.** sealed **8 000 048 B** vs treap **56 000 056 B** — ratio **0.143** (about **7×** smaller).
  Source: `evidence/performance/historical-index-integrated.json`
  (`orfs.performance.historical-index-integrated.v1`).
* **Mutation penalty that disqualifies the live prototypes.** The page tree's namespace mutation is **2.66×** the treap's at 1 M inodes (radix **2.42×**).
  Source: `evidence/performance/index-layout.json`.

Full tables, methodology, and caveats are in `docs/PERFORMANCE.md` §16 (the
competition) and §24 (the historical integration); the per-phase records are
`docs/PROGRESS.md` Phase 48 and Phase 58.

## 7. What this decision does not claim

* It does **not** claim the treap is the fastest point lookup — the page tree has a
  faster point lookup and the sealed dense-ordinal is `O(1)`. It claims the treap is
  the correct **live, publication-sensitive** spine because replacing it regresses
  mutation.
* It does **not** claim the historical accelerator is authoritative. It is derived:
  a corrupt, torn, truncated, foreign, or missing accelerator always falls back to
  the authoritative reconstruction (`tests/historical_fast.rs`).
* Absolute nanoseconds are single-run, host/build-sensitive; the **spine-bytes ratio
  and the shape** are the load-independent, decisive results.
