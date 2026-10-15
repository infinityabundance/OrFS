# OrFS on-disk migration and `or.log` compatibility (Phase 67)

This is the companion to reviewer item #7 (a migration guide) and to the Phase-67
**non-withdrawal trust gap** work: the authoritative log's identity now carries an
explicit `format_version`, and the compatibility rule is machine-checked by frozen
fixtures and a court.

The guarantee this document supports: a frozen `or.log` written by any commit in a
supported range must remain **readable, replayable and `verify --deep`-clean** by a
later binary, so `L_{n+1} = L_n ⊕ Δ_n` survives across code changes.

* The normative wire layout is in `docs/ON_DISK.md` (esp. §4.1 and §10).
* The version rule and compat matrix are in `docs/ON_DISK.md` §10.1.
* The frozen fixtures and their provenance are in `tests/fixtures/README.md`.
* The court is `tests/format_compat.rs`.

---

## 1. The log format version

The authoritative-log format version lives in the **genesis payload** — the
payload of the first committed record, `VOLUME_GENESIS`. This is the log's
identity, so a reader decides compatibility from the log itself and never trusts a
rebuildable sidecar for that decision.

* Current: `LOG_FORMAT_VERSION = 1` (`src/lib.rs`).
* Legacy: `0` — a genesis written **before** the field existed. Absent **and**
  explicit-zero both mean `0`.
* Oldest accepted: `MIN_LOG_FORMAT_VERSION = 0`.

Enforcement is at **open**: `Volume::open` reads the genesis and parses it before
returning, so a future-format volume is refused rather than interpreted on a guess.
`orfs inspect` reports `log_format_version`; `orfs verify` reports it as the
`log_format_version` check.

## 2. On-disk field locations (so a third party can implement a reader)

All integers are little-endian. The genesis record is a standard framed record:
a 60-byte header (`docs/ON_DISK.md` §6.3), the payload below, then a 16-byte
footer (§6.5). The payload is:

| Genesis payload offset | Size | Field | Present |
|---:|---:|---|---|
| 0 | 16 | volume `uuid` (`[u8; 16]`) | always |
| 16 | 8 | `segment_size` (`u64`) | always |
| 24 | 2 | `format_version` (`u16`) | **only** in the versioned (≥ 26-byte) layout |

Reader algorithm (`parse_genesis_payload`, `src/volume.rs`):

```text
len = payload.length
if len < 24:         reject (Corrupt: too short)
if len == 24:        format_version = 0            # legacy: field absent
elif len >= 26:      format_version = u16_le(payload[24..26])
else:                reject (Corrupt: length 25 is malformed)
if format_version > LOG_FORMAT_VERSION:
    reject (UnsupportedFormatVersion { found, supported })   # never guess
accept                                                   # 0 <= version <= current
```

The same accept-if-`≤`-current / refuse-if-higher rule applies to
`volume.meta`'s `format_version` (`VolumeMeta::decode`), which is a distinct field
at offset 4 of the 44-byte `volume.meta` (`docs/ON_DISK.md` §4).

## 3. Compatibility matrix (`or.log` v0 → v1 reader support)

| Frozen log | v0 (pre-versioning) reader | v1 (current) reader |
|---|---|---|
| **v0** — 24-byte genesis, version inferred `0` | reads (it wrote it) | **reads**: replays, `verify --deep`s, reports `format_version = 0` |
| **v1** — 26-byte genesis, version `1` | **must not guess**: the trailing 2 bytes are an unrecognised extension. A v0 reader may read the shared 24-byte prefix, but must treat the format as newer and refuse | **reads**: reports `format_version = 1` |
| **v>1** — unknown higher version | — | **refuses** with `UnsupportedFormatVersion`; never reinterprets |

### What a v0 reader must never do

* Interpret a versioned genesis as if the payload ended at 24 bytes (silently
  dropping `format_version`), or fold the trailing bytes into `segment_size`.
* **Reject** a known older version: a v1 reader must never refuse a v0 log.
* Silently truncate, rewrite, or “repair” a record; mount on a guess. (See
  `docs/LOG-INVARIANTS.md` *No silent repair* and `docs/RECOVERY.md` §2.4.)
* The torn-tail rule is unchanged and independent of version: a physical tail
  beyond the committed root is never reinterpreted or rewritten
  (`docs/ON_DISK.md` §10.4).

### What a v1 reader accepts / rejects

* **Accepts** `format_version ∈ {0, 1}` (any known version `≤` current), in either
  the 24-byte legacy layout or the 26-byte versioned layout.
* **Rejects** any `format_version > 1` with
  `OrfsError::UnsupportedFormatVersion { found, supported }` (errno
  `EPROTONOSUPPORT`) — at open, not at first use.
* The record-header `format_version` remains a separate framing field: a record
  header whose version this build does not implement is a `Compatibility` error
  (`RecordHeader::decode`).

## 4. Migrating a frozen log forward

A log is never rewritten to a new format. “Migration” means: a newer binary reads
the old bytes and, if it writes at all, appends **new** records in the new format
(the append-only, root-by-position model). Concretely:

1. A v0 log opened by a v1 binary is read as-is; the genesis is *not* rewritten.
2. If the v1 binary appends, it continues the stream at the committed root. The
   resulting log is a v1 stream whose prefix is v0 bytes — still readable, because a
   v1 reader accepts the v0 genesis.
3. To *record* the newer format explicitly, a volume should be **created** anew by
   the newer binary (a fresh 26-byte genesis). Existing volumes are never mutated
   in place.

There is no destructive upgrade path, by design: the old bytes stay authoritative.

## 5. Freezing a new fixture when the format changes

When a change alters the authoritative on-disk format, add a frozen fixture so the
compatibility guarantee stays machine-checked. The generator and the court share
one deterministic builder (`build_mini_volume` in `tests/format_compat.rs`).

1. **Register the version.** Add the new value to the registry in
   `docs/ON_DISK.md` §10.1.1 and (if it is the current one) bump
   `LOG_FORMAT_VERSION` in `src/lib.rs`, keeping every older version accepted.
2. **Add a fixture variant** to `tests/format_compat.rs` (the genesis payload for
   the new layout) alongside `legacy_v0` / `current_v1`.
3. **Generate the bytes** inside the pinned container:

   ```sh
   sh -c '. scripts/lib.sh && docker_run cargo test -p orfs --test format_compat \
       -- --ignored generate_fixtures'
   ```

4. **Extend the assertions**: byte-identity against a fresh write, replay
   equivalence, the reported `format_version`, and the unknown-higher-version
   rejection.
5. **Commit the frozen bytes** under `tests/fixtures/<name>/` (only `volume.meta`
   and `or.log/*.seg`; the derived sidecars are omitted) and update
   `tests/fixtures/README.md` with: what the fixture is, the format version it
   encodes, the exact regeneration command, and the source commit range it
   represents.
6. **Update this document** (the compat matrix) and `docs/ON_DISK.md` §10.

A fixture is never edited by hand and never regenerated silently: if a change
stops reading a frozen fixture, `tests/format_compat.rs` is expected to fail.

## 6. The encrypted volume is a new, opt-in format (Phase 85)

The encrypted volume (`orfs init --key-file`, `docs/ERASURE.md`) is a **distinct
volume kind**, not a change to `or.log`:

* It carries `crypto.meta` and no `volume.meta`; the ordinary volume carries
  `volume.meta` and no `crypto.meta`. The two layouts never overlap.
* The **unencrypted** `or.log` format is **unchanged**: `LOG_FORMAT_VERSION` stays
  `1`, the frozen `legacy_v0`/`current_v1` fixtures still read byte-identically
  (`tests/format_compat.rs`), and the whole pre-existing suite and receipts are
  unaffected.
* The encrypted store has its **own** version fields
  (`crypto_format_version`, `FRAME_VERSION`, the sealed version byte; see
  `docs/ON_DISK.md` §11), so a future change to the sealed layout is detectable
  without reinterpreting old bytes.
* There is no in-place conversion between the two kinds: an unencrypted volume is
  **not** encrypted in place (the historical plaintext bytes cannot be made
  unreadable without rewriting them, which non-withdrawal forbids), and an
  encrypted volume is not decoded to plaintext. Moving data between them means
  creating the target volume and re-writing the content through it.
