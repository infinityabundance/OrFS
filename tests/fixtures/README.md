# Frozen `or.log` compatibility fixtures (Phase 67)

These are **committed, byte-frozen** mini-volumes used by the compatibility court
`tests/format_compat.rs`. They exist to make the *non-withdrawal trust gap*
machine-checked: a frozen authoritative log must remain readable, replayable and
`verify --deep`-clean across future code changes. If a change stops reading one of
these fixtures, the court turns red — it is never regenerated silently.

Each fixture is a minimal but *semantically valid* volume: `volume.meta` plus a
single `or.log/0000000000000000.seg` segment containing a `VOLUME_GENESIS` record
and two committed transactions (create `hello.txt`, then write `hello, orfs\n`).
The derived sidecars (`index/`, `.or_bloom/`, `commit.watermark`) are deliberately
**absent**: they are rebuildable and are not part of the frozen identity.

## The fixtures

| Fixture | Genesis payload | Log format version | Layout |
|---|---|---:|---|
| `legacy_v0/` | 24 bytes: `uuid ‖ segment_size` (no version field) | **0** (legacy; inferred) | pre-versioning |
| `current_v1/` | 26 bytes: `uuid ‖ segment_size ‖ format_version` | **1** (current) | current |

The two volume identities differ **only** in the trailing 2-byte version field;
every transaction record is byte-identical between them. So the frozen
`current_v1` root is exactly 2 bytes larger than the `legacy_v0` root.

## The on-disk genesis layout

The genesis payload is the payload of the first committed record
(`VOLUME_GENESIS`). It is little-endian:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 16 | volume `uuid` |
| 16 | 8 | `segment_size` u64 |
| 24 | 2 | `format_version` u16 — **present only in the versioned (v1) layout** |

A payload of exactly **24** bytes carries no version field and must be read as
version **0**. A payload of **>= 26** bytes carries the version at offset 24. A
reader must accept every known version `<= LOG_FORMAT_VERSION` (`0` and `1`) and
refuse an unknown **higher** version with `OrfsError::UnsupportedFormatVersion`.

## Regenerating

The fixtures are written by the ignored `generate_fixtures` test in
`tests/format_compat.rs`, using the exact builder (`build_mini_volume`) that the
assertions compare against. Regenerate with:

```sh
sh -c '. scripts/lib.sh && docker_run cargo test -p orfs --test format_compat \
    -- --ignored generate_fixtures'
```

(The same builder also constructs the "freshly written equivalent" used for the
byte-identity assertions, so the frozen bytes and the expectation come from one
code path.)

## Source commit range

* `legacy_v0/` represents the **pre-versioning** on-disk format: every commit from
  Phase 1 up to and including base commit
  `0a8e672656aeb153b37d5c410854501be00b7707` (the parent of the Phase-67 commit).
  It is what the writer produced before `format_version` was added to the genesis.
* `current_v1/` represents the **Phase 67** format and later (the commit that
  introduced `format_version` into the genesis payload).

The compatibility rule and the migration guidance live in `docs/MIGRATION.md`;
the version registry and compat matrix are in `docs/ON_DISK.md` §10.
