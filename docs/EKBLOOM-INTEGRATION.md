# OrFS ↔ EKBLOOM Integration (Phase 8: certified read paths)

Normative notes for the accelerated read path. Implements research §10
(EKBLOOM as the first-class engine), §10.1 (profiles), §10.2 (read selection),
§20 Ring R (read engine), and the §2 I6 commitment.

## 1. Boundary: EKBLOOM's mathematics vs. OrFS's storage/selection

EKBLOOM is consumed **unchanged** as an immutable, rev-pinned git dependency
(`ekbloom = { git = "https://github.com/infinityabundance/EKBLOOM", rev = "708c349…", version = "= 0.3.0" }`).
Pinning to a committed revision on the public `origin/main` makes OrFS builds
reproducible from a clean checkout, independent of any other checkout on the
machine (see [`docs/LIMITATIONS.md`](LIMITATIONS.md) §1 and
`evidence/receipts/{ekbloom,source-commit}.json`).
OrFS never copies, modifies, or reimplements EKBLOOM's state machine.

The division of labour (research §10):

* **EKBLOOM owns** the authoritative byte machine (`OrANS-NL2`), the resumable
  state, the exact transition/state machinery, the manifested-structure
  encodings, and the certification verdicts.
* **OrFS owns** *store, generate, publish, select, and safely access*: it
  decides *which* structure a read uses, enforces compatibility, and falls back.
  Where EKBLOOM does not export a read entry point for a structure, OrFS drives
  EKBLOOM's exported primitives — it does not re-derive the machine.

## 2. EKBLOOM items OrFS depends on (version `0.3.0`)

Consumed from the crate root (`ekbloom::…`) unless a module path is given.
Only items that are `pub` and re-exported (or public within a `pub mod`) are
used; nothing private is reached into.

| Item | Where | Purpose in OrFS |
|---|---|---|
| `ManifestationProfile` | root | maps 1:1 to OrFS's profile enum (`to_ekbloom`) |
| `create`, `grow`, `manifest` | root | build a manifested body (production builder) |
| `write_body`, `append_generation` | root | publish a `.ekb` payload atomically |
| `inspect`, `ManifestationReport`, `ComponentReport` | root | per-component physical accounting |
| `EkbloomBody` | root | the loaded/validated body (`core`, `history`, `checkpoints`, `blooms`, `certificates`, `logical_len`, `machine_id`, `core_hash`, `object_id`, `generation`, `profiles`) |
| `reader::open_bytes` | `reader` | parse + structurally validate a `.ekb` image |
| `verify`, `VerificationReport`, `CheckOutcome` | root | recompute the certification of every structure |
| `machine_by_id`, `OrMachine` (`init`/`reveal`/`check_core`), `MACHINE_NL2` | root | drive the authoritative machine (history/checkpoint/tail reads) |
| `History` (`snapshot_at`, `logical_len`, `core_hash`, `verify_against`) | root | the full per-position state projection |
| `CheckpointSet` (`restart_point`, `restore`, `interval`) | root | sparse/complete restart states |
| `bloom::{Certification, BloomKind, BloomShell, Outcome}` | `bloom` | certification states, kinds, shell envelope |
| `bloom_path::PathBloom` (`from_shell`, `symbol_at`, `logical_len`) | `bloom_path` | the exact/path table |
| `bloom_global::GlobalBloom` (`from_shell`, `step`, `depth`) | `bloom_global` | the universal `D`-step transition bloom |
| `bloom_region::RegionTable` (`from_shell`, `look`, `logical_start`, `logical_len`, `status`, `depth`) | `bloom_region` | regional `D`-step transition blooms |
| `Snapshot` | root | resumable state `Omega = (state, cursor)` |
| `EkbloomError` | root | surfaced through `OrfsError::Ekbloom` |

Items **not** used: `filesystem::OrFs` (OrFS has its own namespace/FUSE plane),
`bloom_context::ContextBloom` (not part of the documented OrFS read set),
`fastpath::{read_random_1b, read_ranges, read_sequential}` (single-device
convenience wrappers, not needed by the planner), `recovery`, `sweep`,
`worker`, `asyncpub`.

Version/format are pinned in two places: the `Cargo.toml` git-rev dependency
(`rev = "708c349…"`, `= 0.3.0`) and `manifestation::EKBLOOM_VERSION`
(`"0.3.0"`), which is recorded verbatim in every generation manifest and
re-checked on every read. The exact rev is in `evidence/receipts/ekbloom.json`.

## 3. Generation identity (research §2 I6)

A `GenerationManifest` records the volume UUID, **inode**, **inode version**,
**committed root**, EKBLOOM engine + format version, profile, logical/physical
ranges, parameters, certification state + method, payload BLAKE3, a manifest
self-digest, and per-component bytes. `usable_for(inode, version, root)`
requires **exact** identity of all three.

Consequence (by design, and enforced): because the committed root advances on
*any* commit, a generation is usable only while it is the newest structure for
its inode **at the current root and version**. After an unrelated commit an
untouched inode's structure is root-stale and refused, and the read falls back
to the authoritative extent read — correct bytes always, acceleration only when
compatible. The background engine re-manifests a touched inode at the new root,
so the just-written object is immediately accelerated again.

## 4. Certification model

A structure is **usable without fallback** only if it is *certified* and
*compatible*. The planner enforces, **on every read** (not only at construction):

1. **Compatibility.** `latest_for(inode)` exists; `usable_for(inode, version,
   root)` matches exactly; `ekbloom_version == "0.3.0"`; the manifest's logical
   range equals the object's current logical extent.
2. **Payload integrity.** The payload bytes are read once per generation and
   must hash (BLAKE3) to the committed `payload_blake3`. A missing or corrupt
   payload is rejected.
3. **Structural validation.** `ekbloom::reader::open_bytes` must accept the
   image, and the body's `object_id`, `logical_len`, and `machine_id` must agree
   with the manifest.
4. **Certification.** `ekbloom::verify(&body)` recomputes, against the object's
   own positions: the core hash, the authoritative decode length, each history,
   each checkpoint's restart ordinals, each bloom's `Phi_D` reproduction, and
   every certificate receipt. The per-structure `CheckOutcome` decides usability:
   * a **path bloom** is certified iff its check passes *and* EKBLOOM marked the
     shell `Certification::Certified` (exact by construction);
   * **history** and **checkpoints** are exact by construction and certified by
     their passing check;
   * a **universal/regional `D`-step bloom** is certified iff EKBLOOM's re-derived
     verdict is `Certification::Certified` (the **bloom key sufficiency law**:
     the 16-bit state key is sufficient iff no key maps to two distinct `Phi_D`
     outcomes). An `Unverified` bloom is **verified-on-use**: the planner
     compares it byte-for-byte with the authoritative read and rejects it on any
     disagreement (a `Rejected`/failing check is never a candidate).

OrFS's `CertificationState` in the manifest is the recorded construction
verdict; the read planner trusts the *recomputed* EKBLOOM verdict, never a stored
label alone.

## 5. Candidate paths (research §10.2)

For a compatible generation the planner enumerates, per request:

| Path | EKBLOOM primitive | Exactness |
|---|---|---|
| `logical-extent` | the authoritative extent read (OrFS) | authoritative |
| `path-bloom` | `PathBloom::symbol_at` | exact by construction |
| `history` | `History::snapshot_at` + `OrMachine::reveal` | exact by construction |
| `checkpoint` | `CheckpointSet::restore` + `OrMachine::reveal` | exact (bounded replay) |
| `transition-bloom` | `GlobalBloom::step` / `RegionTable::look` (state from history/checkpoint/machine) | exact iff certified; else verified-on-use |

The ordinary logical extent read is itself a candidate, so the planner can
decide that *no* manifested structure is worth using for a given request.

## 6. Selection by measurement

Selection is **mechanical and measured**, never "pick the largest structure":

* The planner keeps an EWMA latency model per `(path, size class)`; size classes
  are `empty`, `byte` (1), `small` (≤4 KiB), `medium` (≤64 KiB), `large` (>64 KiB).
* On the **first** request for a given `(generation, size class)` it
  **calibrates**: every applicable candidate is executed once and timed, and the
  fastest is used. This grounds the model in real measurements for every path.
* On subsequent requests it picks the cheapest applicable candidate under the
  measured model (ties prefer certified paths, then a fixed priority order).
* A candidate that fails for a generation is barred for that generation, so a
  read never retries a structure that cannot serve the object.
* A structure cannot slow a read call: if the authoritative extent read measures
  faster (as it does for large reads in an unoptimized build), it is chosen.

Measured per-path latencies and the resulting selection are recorded in
`evidence/performance/ekbloom-read-paths.json`.

## 7. Fallback rules

On **any** rejection — absent, incomplete, corrupt, wrong version/root,
uncertified-for-domain, decode failure, out-of-coverage position — the planner
uses the ordinary authoritative extent read (`Namespace::read_extent`). A
manifested structure can therefore never change the bytes a read returns. The
planner records why it fell back in `PlannedRead::fallback_reason`.

## 8. Which EKBLOOM profiles are real

* **Certified-by-construction** (a `Certification::Certified` bloom):
  `path(D)` (exact path table) and `max-speed` (history + checkpoints K=1024 +
  certified path bloom).
* **Exact-by-construction, structurally certified** (no bloom certificate):
  `full` (history), `dense(K)` (history + checkpoints), `sparse(K)`
  (checkpoints). `root` yields the core only and therefore no acceleration.
* **Real but `Unverified`** (used only verify-on-use, never as a direct
  accelerator): `bloom(D)` (universal 16-bit-state `T_D`) and
  `regional(D, R)`. This mirrors EKBLOOM's own reader, which likewise does not
  consult universal/regional/contextual blooms on its fast path.
* **Not used by OrFS reads**: `contextual` blooms (not in the documented read
  set) and the optional trigram/suffix/image/directory families (Phase 9).

## 9. Invariants exercised by tests (`tests/ekbloom_read.rs`, `tests/fuse_integration.rs`)

* **Equivalence** — planned == authoritative byte-for-byte across many inodes,
  versions, roots, and randomized `(offset, length)` including single bytes,
  random 4 KiB, and spans; a `proptest` covers the offset/length space.
* **Historical versions** — reads at a historical root agree with a read-only
  `Snapshot`; compatible structures are used, newer-root/version ones refused.
* **Rejection** — wrong inode version, wrong root, wrong EKBLOOM engine version,
  absent payload, and corrupt payload all reject and fall back with identical
  bytes; an insufficient uncertified bloom is rejected by verify-on-use.
* **FUSE** — a mounted read served by the planner returns exactly the visible
  contents and a concealed payload exists.

Evidence: `evidence/correctness/ekbloom-read-equivalence.json` (per-case
verdicts, including historical versions, and explicit rejection verdicts) and
`evidence/performance/ekbloom-read-paths.json` (measured latency per path for
random-1B and random-4K versus the authoritative path, plus the measured
selection model and the paths the planner chose).

## 10. Known limitations / Phase 9 risks

* Root qualification is exact, so acceleration is available only for the newest
  structure at the current root+version. This is conservative and safe.
* Absolute latencies in the evidence come from an unoptimized test build, where
  per-symbol loops dominate; *selection*, not the absolute figure, is the point.
* Trigram/query (§11) is Phase 9. It must define its own compatibility and must
  not leak query results through `getxattr` (research §12).
