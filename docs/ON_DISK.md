# OrFS On-Disk Format (Phase 1)

**Status:** implemented (Phase 1). This document is normative for the bytes this
build writes and accepts. It refines `research/OrFS.md` §4–§5; where they
differ, `research/OrFS.md` governs.

All multi-byte integers are **little-endian**. Fields are encoded and decoded
explicitly, field by field; no Rust struct is ever reinterpreted over untrusted
bytes.

## 1. Volume directory

```text
<volume>/
├── volume.meta         volume identity (fixed size, checksummed)
├── or.log/             the authoritative log
│   ├── 0000000000000000.seg
│   ├── 0000000000000001.seg
│   ├── ...
│   └── quarantine/     retained abandoned segment tails (never canonical)
├── index/              rebuildable namespace index snapshots
└── .or_bloom/          concealed acceleration structures
    ├── ekbloom/
    ├── trigram/
    ├── suffix/
    ├── image/
    ├── directory/
    └── manifests/
```

### 1.1 Segments

* File name: `NNNNNNNNNNNNNNNN.seg` — exactly 16 decimal digits, zero-padded.
* **Segment id** = the **first logical byte offset** the segment covers.
  Therefore for any canonical logical offset `L` in a segment with id `S`, the
  physical offset within that file is `L - S`.
* Segment ids are unique and strictly increasing; the canonical log is
  contiguous, so for consecutive segments `S[i+1].id == S[i].id + valid_len(S[i])`.
* Segments are append-only. A record never straddles two segments.
* A 16-digit name bounds ids to `0 … 9_999_999_999_999_999` (≈ 9.99 × 10¹⁵ B).

## 2. Record envelope

```text
RECORD HEADER   (60 bytes)
PAYLOAD         (payload_length bytes)
RECORD FOOTER   (16 bytes)
```

`total_record_length = header_length + payload_length + footer_length`.

### 2.1 Header (60 bytes)

| Offset | Size | Field                    | Notes |
|-------:|-----:|--------------------------|-------|
| 0      | 4    | `magic` u32              | `0x5346524F`; LE bytes `4F 52 46 53` = `"ORFS"` |
| 4      | 2    | `format_version` u16     | currently `1` |
| 6      | 2    | `record_type` u16        | see §2.4 |
| 8      | 4    | `header_length` u32      | `60` |
| 12     | 8    | `payload_length` u64     | ≤ `MAX_PAYLOAD_LEN` (64 MiB) |
| 20     | 8    | `sequence_number` u64    | contiguous from `0` |
| 28     | 8    | `transaction_id` u64     | `0` for genesis and outside a transaction |
| 36     | 8    | `inode_id` u64           | subject inode, or `0` |
| 44     | 8    | `previous_inode_offset` u64 | offset of a previous record for the same inode, or `0` |
| 52     | 4    | `flags` u32              | reserved; `0` in format version 1 |
| 56     | 4    | `header_check` u32       | CRC32C over bytes `[0, 56)` |

Decode order (checksum first, so a partially written header is reported as a
torn tail rather than corruption):

1. fewer than 60 bytes → torn;
2. `header_check != CRC32C(bytes[0..56))` → torn;
3. `magic` mismatch → corrupt;
4. `header_length != 60` → corrupt;
5. `format_version != 1` → **compatibility** error;
6. `payload_length > 64 MiB` → corrupt (rejected **before** any payload buffer
   is allocated);
7. unknown `record_type` → classification in §2.4.

### 2.2 Payload

`payload_length` opaque bytes. Only `VOLUME_GENESIS` has a defined payload in
format version 1 (§4) for the framing layer. The typed payloads of the
structural records (`TX_BEGIN`, `TX_COMMIT`, `TX_ABORT`) are specified in
`docs/TRANSACTIONS.md` §1.2; the typed payloads of the inode, directory, and
extent records are specified in `docs/NAMESPACE.md` §2.1, §3, and §4. The
framing layer still treats every non-genesis payload as opaque bytes and never
casts a struct over untrusted bytes.

### 2.3 Footer (16 bytes)

| Offset | Size | Field                  | Notes |
|-------:|-----:|------------------------|-------|
| 0      | 8    | `total_record_length` u64 | `60 + payload_length + 16` |
| 8      | 4    | `record_check` u32     | CRC32C over header (60 B) followed by payload |
| 12     | 4    | `end_marker` u32       | `0x21444E45`; LE bytes `45 4E 44 21` = `"END!"` |

A footer whose `total_record_length` or `record_check` disagrees is reported as
**torn**; a bad `end_marker` (with a valid record check) is reported as
**corrupt**.

### 2.4 Record types

Type codes are `u16`. **Bit 15 (`0x8000`) marks a type *optional*.** An unknown
type with bit 15 clear is *mandatory* and must stop the reader with a
compatibility error. An unknown type with bit 15 set may be skipped.

| Code   | Name              | Mandatory |
|-------:|-------------------|:---------:|
| 0x0001 | `VOLUME_GENESIS`  | yes |
| 0x0002 | `TX_BEGIN`        | yes |
| 0x0003 | `TX_COMMIT`       | yes |
| 0x0004 | `TX_ABORT`        | yes |
| 0x0005 | `INODE_CREATE`    | yes |
| 0x0006 | `INODE_METADATA`  | yes |
| 0x0007 | `INODE_SETATTR`   | yes |
| 0x0008 | `DENTRY_ADD`      | yes |
| 0x0009 | `DENTRY_REMOVE`   | yes |
| 0x000A | `DENTRY_RENAME`   | yes |
| 0x000B | `DATA_EXTENT`     | yes |
| 0x000C | `DATA_ZERO_RANGE` | yes |
| 0x000D | `FILE_RESIZE`     | yes |
| 0x000E | `SYMLINK_CREATE`  | yes |
| 0x000F | `HARDLINK_ADD`    | yes |
| 0x0010 | `HARDLINK_REMOVE` | yes |
| 0x0011 | `XATTR_SET`       | yes |
| 0x0012 | `XATTR_REMOVE`    | yes |
| 0x0013 | `SNAPSHOT_ROOT`   | yes |
| 0x0014 | `INDEX_CHECKPOINT`| yes |
| 0x0015 | `PERMISSION_CHANGE` | yes |

The codes `0x8000 … 0xFFFF` are reserved for optional extensions (bit 15 set).

## 3. Transactions

Records between a `TX_BEGIN` and its matching `TX_COMMIT` are one atomic unit.
The committed root advances **only** to the end offset of a `TX_COMMIT` (or, for
the first record, of `VOLUME_GENESIS`). `TX_ABORT` closes the transaction
without publishing. Sequence numbers are contiguous from `0` across the whole
canonical stream. In format version 1 every non-genesis record must lie inside a
matching transaction; only `VOLUME_GENESIS` is a standalone record.

## 4. `volume.meta` (44 bytes)

| Offset | Size | Field                    | Notes |
|-------:|-----:|--------------------------|-------|
| 0      | 4    | `magic` u32              | `0x5646524F`; LE bytes `4F 52 46 56` = `"ORFV"` |
| 4      | 2    | `format_version` u16     | currently `1` |
| 6      | 2    | `reserved` u16           | `0` |
| 8      | 16   | `uuid` [u8; 16]          | RFC 4122 v4 |
| 24     | 8    | `created_at_unix_secs` u64 | Unix seconds |
| 32     | 8    | `segment_size` u64       | segment-size policy in bytes |
| 40     | 4    | `meta_check` u32         | CRC32C over bytes `[0, 40)` |

`volume.meta` is written to a temporary file, fsynced, and renamed into place;
the containing directory is then fsynced. It is written **after** the genesis
record, so a crash during `init` leaves an orphan log (not a volume) rather than
a volume without authoritative content.

### 4.1 Genesis payload (24 or 26 bytes)

The genesis payload is the payload of the first committed record
(`VOLUME_GENESIS`); it is the **authoritative-log identity**. It carries the
log format version explicitly, so a reader decides compatibility from the log
itself rather than from a rebuildable sidecar.

| Offset | Size | Field | Layout |
|-------:|-----:|-------|--------|
| 0      | 16   | volume `uuid` | both |
| 16     | 8    | `segment_size` u64 | both |
| 24     | 2    | `format_version` u16 | **v1 only** |

* A payload of exactly **24** bytes has **no** version field; the version is
  inferred as **0** (*legacy* — a genesis written before the field existed).
* A payload of **≥ 26** bytes carries the little-endian `format_version` at
  offset 24. The current writer emits **26** bytes with `format_version = 1`
  (`LOG_FORMAT_VERSION`, `src/lib.rs`; `LegacyGenesis`, `genesis_payload`,
  `parse_genesis_payload`, `GenesisIdentity`, `src/volume.rs`).
* The first 24 bytes are a strict prefix shared by both layouts, so a reader that
  predates the field can still read the UUID and segment size.

`volume.meta` and the genesis payload redundantly carry the UUID and segment
size so that `orfs verify` can cross-check identity against authoritative
content. `volume.meta` carries its own `format_version` (currently `1`, §4); the
reader accepts any known version `≤` the current one there too.

## 5. Integrity model

* `header_check` and `record_check` are **CRC32C**. They detect malformed or
  corrupted framing only; they are not authentication and do not define record
  identity (a root is a position, never a hash).
* `MAX_PAYLOAD_LEN` = 64 MiB bounds allocation from untrusted records.
* All length arithmetic is checked (`u64` overflow yields a controlled error).

---

# Part II — Wire specification (implementable)

The sections below restate and extend Part I into a specification another
implementation can parse from alone. They add the byte-exact envelope, a
versioned record-type registry, an explicit account of what authentication does
(and does not) exist, the immutable manifestation catalogue, and the
versioning/forward-compatibility rules. Every field, magic, offset, and rule
here is read from the source cited inline; nothing is inferred.

All multi-byte integers are **little-endian** unless a table says otherwise.
Fields are encoded and decoded explicitly, field by field; no Rust struct is
cast over untrusted bytes (`src/record.rs`, module doc, lines 1–23).

## 6. Segment and envelope wire format (byte-exact)

### 6.1 Segment files

| Property | Value | Source |
|---|---|---|
| File-name suffix | `.seg` (`SEGMENT_SUFFIX`) | `src/segment.rs` |
| Name format | `NNNNNNNNNNNNNNNN.seg` — exactly **16** decimal digits, zero-padded (`SEGMENT_NAME_DIGITS = 16`) | `src/segment.rs` |
| Maximum id | `MAX_SEGMENT_ID = 9_999_999_999_999_999` (≈ 9.99 × 10¹⁵) | `src/segment.rs` |
| Segment id | the **first logical byte offset** the segment covers | `src/segment.rs` |
| Logical→physical | for a canonical logical offset `L` in segment `S`: physical offset `= L - S` | `src/segment.rs` |
| Contiguity | `extents[i+1].id == extents[i].end()`, where `end == id + valid_len`; a gap or overlap is rejected | `src/segment.rs` (`SegmentLocator::from_extents`) |
| First id | must be `0` | `src/segment.rs` (`SegmentLocator::from_extents`) |

Parsing rules (`src/segment.rs::parse_segment_name`): a name is a segment name
iff it ends in `.seg`, the stem is exactly 16 bytes, **and every stem byte is an
ASCII decimal digit**. Anything else yields no id. Therefore `quarantine`, `0.seg`,
`00000000000000000.seg`, `000000000000000a.seg`, and `0000000000000000.seg.bak`
are all **not** segments (asserted in `src/segment.rs` tests).

Discovery (`src/segment.rs::discover_segment_ids`) reads the log directory,
ignores every non-segment entry (including the `quarantine/` directory), sorts
ids ascending, and reports **duplicate ids as corruption**.

Segments are append-only and a record never straddles two segments (the writer
rolls over before writing, never mid-record) (`src/segment.rs`, module doc).

### 6.2 Envelope shape

```text
RECORD HEADER   (60 bytes, fixed)
PAYLOAD         (payload_length bytes)
RECORD FOOTER   (16 bytes, fixed)
total_record_length = 60 + payload_length + 16
```

`total_record_length` is computed with checked `u64` arithmetic
(`RecordHeader::total_len`, `src/record.rs`).

### 6.3 Header (60 bytes)

Offsets are from the start of the record (equivalently, of the header, since the
header is first). Constants are the `HDR_OFF_*` values in `src/record.rs`.

| Offset | Width | Field | Rust constant | Type / endianness | Meaning |
|-------:|------:|-------|---------------|-------------------|---------|
| 0 | 4 | `magic` | `HDR_OFF_MAGIC` | `u32` LE | `RECORD_MAGIC = 0x5346_524F`; on-disk bytes `4F 52 46 53` = `"ORFS"` |
| 4 | 2 | `format_version` | `HDR_OFF_FORMAT_VERSION` | `u16` LE | currently `1` (`crate::FORMAT_VERSION`) |
| 6 | 2 | `record_type` | `HDR_OFF_RECORD_TYPE` | `u16` LE | raw type code, §7 |
| 8 | 4 | `header_length` | `HDR_OFF_HEADER_LENGTH` | `u32` LE | `HEADER_LEN = 60` |
| 12 | 8 | `payload_length` | `HDR_OFF_PAYLOAD_LENGTH` | `u64` LE | ≤ `MAX_PAYLOAD_LEN` (64 MiB) |
| 20 | 8 | `sequence_number` | `HDR_OFF_SEQUENCE_NUMBER` | `u64` LE | contiguous from `0` across the canonical stream |
| 28 | 8 | `transaction_id` | `HDR_OFF_TRANSACTION_ID` | `u64` LE | `0` for genesis and outside a transaction |
| 36 | 8 | `inode_id` | `HDR_OFF_INODE_ID` | `u64` LE | subject inode, or `0` |
| 44 | 8 | `previous_inode_offset` | `HDR_OFF_PREVIOUS_INODE_OFFSET` | `u64` LE | offset of a previous record for the same inode, or `0` |
| 52 | 4 | `flags` | `HDR_OFF_FLAGS` | `u32` LE | reserved; `FLAG_NONE = 0` in format version 1 |
| 56 | 4 | `header_check` | `HDR_OFF_HEADER_CHECK` | `u32` LE | CRC32C over bytes `[0, 56)` |

`header_check = crc32c::crc32c(bytes[0..56])` (`RecordHeader::compute_check`,
`src/record.rs`).

**Header decode order** (`RecordHeader::decode`, `src/record.rs`) — checksum first,
so a partially written header is a *torn tail*, not corruption:

1. fewer than 60 bytes → `DecodeError::Incomplete` (torn);
2. `header_check != CRC32C(bytes[0..56))` → `Incomplete` (torn);
3. `magic != RECORD_MAGIC` → `Corrupt`;
4. `header_length != 60` → `Corrupt`;
5. `format_version != FORMAT_VERSION` → `Compatibility`;
6. `payload_length > MAX_PAYLOAD_LEN` → `Corrupt` (checked **before** any payload
   buffer is allocated);
7. otherwise the header decodes; the type code is classified per §7.

### 6.4 Payload

`payload_length` opaque bytes at offset 60. The framing layer never interprets a
non-genesis payload; typed payloads are the concern of later planes
(`src/record.rs`). The genesis payload is defined in §4.1 (`VOLUME_GENESIS`, 24
bytes).

### 6.5 Footer (16 bytes)

Offsets are from the start of the footer. Constants are `FTR_OFF_*`
(`src/record.rs`).

| Offset | Width | Field | Type / endianness | Meaning |
|-------:|------:|-------|-------------------|---------|
| 0 | 8 | `total_record_length` | `u64` LE | must equal `60 + payload_length + 16` |
| 8 | 4 | `record_check` | `u32` LE | CRC32C over the header (60 B) **followed by** the payload |
| 12 | 4 | `end_marker` | `u32` LE | `FOOTER_END_MARKER = 0x2144_4E45`; on-disk bytes `45 4E 44 21` = `"END!"` |

`record_check = crc32c::crc32c(header_bytes || payload_bytes)`, i.e. CRC32C over
bytes `[0, 60 + payload_length)` (`Record::encode`, `src/record.rs`).

**Footer validation order** (`RecordFooter::validate`, `src/record.rs`):

1. fewer than 16 bytes → `Incomplete`;
2. `total_record_length != 60 + payload_length + 16` → `Incomplete` (torn);
3. `record_check != CRC32C(header || payload)` → `Incomplete` (torn);
4. `end_marker != FOOTER_END_MARKER` → `Corrupt`.

So a footer whose length or checksum disagrees is reported **torn**; a bad end
marker (with an otherwise valid record check) is **corrupt**.

### 6.6 CRC32C coverage summary

| Checksum | Field | Covers |
|---|---|---|
| CRC32C | `header_check` (hdr[56..60]) | header bytes `[0, 56)` |
| CRC32C | `record_check` (ftr[8..12]) | header (60 B) `||` payload |

**These are integrity/framing checks, not authentication.** They detect a
truncated or corrupted frame; they carry **no key, no MAC, and no signature**, and
they do not define record identity (a root is a position, never a hash)
(`src/record.rs`; §5 above).

### 6.7 Commit watermark (`commit.watermark`)

A durability witness written beside the segments (`WATERMARK_FILE =
"commit.watermark"`), fixed **36 bytes**, little-endian (`src/watermark.rs`). It is
**added metadata**, never part of the authoritative record stream.

| Offset | Width | Field | Type | Meaning |
|-------:|------:|-------|------|---------|
| 0 | 4 | `magic` | `u32` LE | `WATERMARK_MAGIC = 0x5746_524F`; on-disk bytes `4F 52 46 57` = `"ORFW"` |
| 4 | 2 | `format_version` | `u16` LE | `crate::FORMAT_VERSION` |
| 6 | 2 | `reserved` | `u16` LE | `0` |
| 8 | 8 | `committed_root` | `u64` LE | the root `R` certified |
| 16 | 8 | `segment_id` | `u64` LE | segment holding the committed frontier |
| 24 | 8 | `segment_valid_len` | `u64` LE | committed bytes within that segment |
| 32 | 4 | `crc32c` | `u32` LE | CRC32C over bytes `[0, 32)` |

Decode (`Watermark::decode`): fewer than 36 bytes → error; CRC over `[0,32)`
mismatch → `Corrupt`; bad magic → `Corrupt`; `format_version` mismatch →
`Compatibility`. The file is written with an atomic `tmp → fsync → rename →
dir fsync` sequence (`Watermark::write`). Recovery **refuses** an open when
`watermark.committed_root > recovered_committed_root` (a trailing committed
segment is missing or truncated) rather than silently recovering shorter history
(`validate`, `src/watermark.rs`). A missing watermark is *unvalidated* (`Ok(None)`),
not an error; a present-but-corrupt watermark is an error, never ignored.

## 7. Record type registry (versioned)

The record type code is a `u16` in header bytes `[6, 8)`. Classification
(`classify_code`, `src/record.rs`):

* a code in the registry below → `TypeClass::Known(t)`;
* any other code with **bit 15 set** (`OPTIONAL_TYPE_BIT = 0x8000`) →
  `TypeClass::OptionalUnknown(code)`, which a reader **may skip**;
* any other code with bit 15 **clear** → `DecodeError::Compatibility` (the format
  must not be interpreted on a guess).

`record_type_name` labels an unknown optional code `OPTIONAL_0xNNNN` and an
unknown mandatory code `UNKNOWN_0xNNNN` (`src/record.rs`).

### 7.1 Registry for `format_version = 1`

Source: the `RecordType` enum (`#[repr(u16)]`), its `from_code`, `name`, and the
per-variant doc comments, all in `src/record.rs`. **Every** listed variant is a
known (mandatory-class) type: a reader that does not understand one must refuse to
proceed (`src/record.rs`, `RecordType` doc comment). Payload descriptions are the
enum's own one-line doc comments.

| Code | Name | Registry class | Payload (one line, from `src/record.rs`) |
|-----:|------|:--------------:|------------------------------------------|
| `0x0001` | `VOLUME_GENESIS` | known (mandatory) | Volume identity record; always the first record (payload defined in §4.1) |
| `0x0002` | `TX_BEGIN` | known (mandatory) | Start of a multi-record transaction |
| `0x0003` | `TX_COMMIT` | known (mandatory) | Atomic publication of a transaction |
| `0x0004` | `TX_ABORT` | known (mandatory) | Abandonment of a transaction; no state becomes visible |
| `0x0005` | `INODE_CREATE` | known (mandatory) | Creation of an inode |
| `0x0006` | `INODE_METADATA` | known (mandatory) | New metadata version for an inode |
| `0x0007` | `INODE_SETATTR` | known (mandatory) | Attribute change (mode/uid/gid/times) |
| `0x0008` | `DENTRY_ADD` | known (mandatory) | Addition of a directory entry |
| `0x0009` | `DENTRY_REMOVE` | known (mandatory) | Removal of a directory entry |
| `0x000A` | `DENTRY_RENAME` | known (mandatory) | Rename of a directory entry |
| `0x000B` | `DATA_EXTENT` | known (mandatory) | A file data extent |
| `0x000C` | `DATA_ZERO_RANGE` | known (mandatory) | A logically zeroed range within a file |
| `0x000D` | `FILE_RESIZE` | known (mandatory) | A logical file size change |
| `0x000E` | `SYMLINK_CREATE` | known (mandatory) | Creation of a symbolic link |
| `0x000F` | `HARDLINK_ADD` | known (mandatory) | Addition of a hard link |
| `0x0010` | `HARDLINK_REMOVE` | known (mandatory) | Removal of a hard link |
| `0x0011` | `XATTR_SET` | known (mandatory) | Set an extended attribute |
| `0x0012` | `XATTR_REMOVE` | known (mandatory) | Remove an extended attribute |
| `0x0013` | `SNAPSHOT_ROOT` | known (mandatory) | Publish a named historical root |
| `0x0014` | `INDEX_CHECKPOINT` | known (mandatory) | An index checkpoint embedded in the authoritative log |
| `0x0015` | `PERMISSION_CHANGE` | known (mandatory) | An ownership/permission change |

Any code with bit 15 set (`0x8000 … 0xFFFF`) is the **optional** extension space; an
unrecognised code there may be skipped. There are no optional or reserved codes in
the version-1 registry itself. (The rule is exactly "bit 15 set": `classify_code`
treats `0x8000` as optional too.)

### 7.2 Root-publishing semantics

Only two types publish a new committed root when their record **ends**:
`VolumeGenesis` and `TxCommit` (`RecordType::publishes_root`, `src/record.rs`;
`docs/LOG-INVARIANTS.md`, *Committed boundary rule*). `TX_ABORT` and ordinary
records never advance the root.

## 8. Authentication: what exists, and what does not ("AUTH construction")

**There is no AUTH construction.** OrFS defines **no authentication record type,
no AUTH field, no message-authentication code (MAC), and no signature** anywhere
in the log or the envelope. This is a deliberate, documented property, not an
omission, and an implementer must not invent one.

What the source establishes:

* A search of `src/` finds no authentication or MAC construct on the log path:
  there is no `AUTH` record type, no MAC, no signature, and no HMAC in
  `src/record.rs`, `src/log.rs`, `src/segment.rs`, or `src/watermark.rs`. The only
  similarly named items are unrelated: an `auth_slice` benchmark helper
  (`benches/mechanisms.rs`), the word "authoritative", and the query API's
  `Credential` (`src/query.rs`), which carries `uid`/`gid`/supplementary groups for
  permission enforcement (§8.1) and authenticates nothing.
* The two envelope checksums are **CRC32C**, keyed by nothing (§6.6).
* The derived-structure digests are **BLAKE3** content hashes used for integrity
  and identity, not for authentication (`src/manifestation.rs`,
  `src/trigram.rs`; `docs/SECURITY.md` §3.14).

> **The on-disk checks are integrity, not authentication.** CRC32C framing and
> BLAKE3 digests detect accidental corruption and casual tampering; they are not a
> MAC and there is no signature or encryption. An attacker with write access to the
> backing directory can rewrite history and recompute the digests.
> (`docs/LIMITATIONS.md` §14)

`docs/THREAT-MODEL.md` §2 states the same at the model level: *"There is **no
message-authentication code, no signature, and no encryption** on the
authoritative log."* The authoritative log is validated **structurally** — CRC32C
framing plus transaction/sequence rules (§6, `docs/LOG-INVARIANTS.md`) and BLAKE3
digests for derived content — never cryptographically.

### 8.1 Where access control actually lives

Permissions are enforced **above** the log, at the FUSE and query layers, by the
class-based POSIX rule; the log carries ownership/permission *data* (as the payload
of ordinary records such as `INODE_CREATE`, `INODE_METADATA`, `INODE_SETATTR`, and
`PERMISSION_CHANGE`, §7.1) but authenticates no writer.

The single rule is `src/inode.rs::has_permission_grouped`:

```rust
pub fn has_permission_grouped(uid: u32, gid: u32, groups: &[u32], st: &InodeStat, mask: u32) -> bool {
    let perm = st.mode & 0o777;
    if uid == 0 {
        // Root bypasses read/write; execute needs at least one x bit set on a
        // regular file, and is always allowed on directories.
        if mask & 0o1 != 0 && st.kind == InodeType::File {
            return perm & 0o111 != 0;
        }
        return true;
    }
    let shift = perm_class_groups(uid, gid, groups, st); // 6 owner / 3 group / 0 other
    let class = (perm >> shift) & 0o7;
    (class & mask) == mask
}
```

(`src/inode.rs`; `perm_class_groups` selects the class: owner if `uid ==
st.uid`, else group if `gid == st.gid || groups.contains(&st.gid)`, else other.)
Both FUSE transports share this rule and supply the caller's supplementary groups
from `/proc/<pid>/status` (`docs/FUSE-SEMANTICS.md` §6/§6.1); the typed query API
carries them on its `Credential` (`docs/QUERY.md` §7); `docs/SECURITY.md` §3.7 and
`docs/THREAT-MODEL.md` §1 describe the model. There is **no** per-mount secret and
**no** cryptographic gate on the backing store (`docs/THREAT-MODEL.md` §1).

**Summary.** Integrity = CRC32C (framing) + BLAKE3 (derived content). Identity =
position, not hash. Authentication = none. Confidentiality = none. An implementer
must not add an AUTH record type to a parser and expect the reference reader to
accept it: an unknown mandatory code stops the reader (§7).

## 9. The manifestation catalogue (immutable, append-only)

Source: `src/manifestation.rs` (the Phase-42 `GenerationStore` catalogue,
`Catalogue` / `CatalogueEntry`), described in `docs/MANIFESTATION.md` §7.1 and §15.
The catalogue is **Plane C** (derived, non-authoritative): it accelerates
discovery of committed generations and never carries authoritative weight. The
same format, with a distinct family tag, backs the concealed trigram registry
(`.or_bloom/trigram/catalogue/`, family `CAT_FAMILY_TRIGRAM`; `src/trigram.rs`).

### 9.1 Directory and file naming

Catalogue root: `<volume>/.or_bloom/manifests/catalogue/`
(`BLOOM_DIR = ".or_bloom"`, `MANIFEST_DIR = "manifests"`, plus
`"catalogue"`; `GenerationStore::new`, `src/manifestation.rs`).

| File | Format | Role |
|---|---|---|
| `seg-<index:010>.cat` | append-only, fixed **128-byte** records | immutable once sealed |
| `CURRENT` | 24-byte pointer (§9.3) | names the active segment; rewritten **only** on a seal |
| `sum-<through:010>.sum` | immutable summary (§9.4) | folded *newest-per-inode* state at a seal |

`<index>` and `<through>` are 10-digit zero-padded decimal (`segment_path`,
`summary_path`). Related naming elsewhere in the store: generation manifests are
`<generation:020>.manifest` under `manifests/` (`GenerationStore::manifest_path`),
and payloads are `.or_bloom/ekbloom/<inode>-v<version>-r<root>-g<generation>.ekb`
(with region suffixes `-x<index>.ekb`; `payload_rel_path` / `region_payload_rel_path`).

### 9.2 Catalogue record (128 bytes each)

The body is **fixed-size**, so framing is unambiguous and an append is one small
write. Constants: `CAT_RECORD_BODY = 120`, `CAT_RECORD_BYTES = 128`
(`src/manifestation.rs`). All integers little-endian; arrays are raw bytes.

```text
[body_len:u32][ body:120 ][crc32c:u32]      total = 128
```

`crc32c` covers `body_len || body` (the first 124 bytes). The 120-byte body is
encoded by `CatalogueEntry::body` in exactly this order:

| Body offset | Width | Field | Type / endianness |
|------------:|------:|-------|-------------------|
| 0 | 4 | `family` | `u32` LE — `CAT_FAMILY_MANIFEST = 0x4F52_434D` (source label `"ORCM"`) |
| 4 | 4 | `schema` | `u32` LE — `CAT_SCHEMA = 1` |
| 8 | 8 | `generation` | `u64` LE — monotonic, unique per volume |
| 16 | 16 | `volume_uuid` | `[u8; 16]` |
| 32 | 8 | `inode` | `u64` LE |
| 40 | 8 | `inode_version` | `u64` LE |
| 48 | 8 | `root` | `u64` LE — the committed root at construction |
| 56 | 32 | `manifest_blake3` | `[u8; 32]` — the immutable manifest's self-digest |
| 88 | 32 | `payload_blake3` | `[u8; 32]` — the payload's BLAKE3 |

(Field order and widths are `CatalogueEntry::body`, `src/manifestation.rs`;
`CAT_RECORD_BODY = 4+4+8+16+8+8+8+32+32 = 120`.)

An entry **binds the generation number to the immutable manifest's self-digest**
(`manifest_blake3`), so a generation number that is later reused is detectable
(`CatalogueEntry` doc, `src/manifestation.rs`). The cited manifest's self-digest is
`BLAKE3(canonical_bytes())`, and the on-disk manifest file is
`canonical_bytes() || manifest_blake3` (`GenerationManifest::compute_digest` /
`encode`, `src/manifestation.rs`); its canonical encoding begins with
`MANIFEST_MAGIC = 0x3153_464D` (on-disk `4D 46 53 31` = `"MFS1"`) and the manifest
`schema` (`MANIFEST_SCHEMA = 2`).

**Reader recipe for one record.** Require ≥ 8 bytes; read `len = u32` at 0; require
`len == 120`; require ≥ `len + 8` bytes; require `crc32c(bytes[0..len+4]) == u32 at
[len+4, len+8)`; decode the body from `bytes[4, 4+len)` and require `family` and
`schema` to match; require that the body is consumed exactly
(`CatalogueEntry::decode_record`, `src/manifestation.rs`). Any failure yields
`None` (skip). A reader stops at the **first** torn/corrupt record, since an
append-only log's tail is the only place a tear can occur (`Catalogue::read_segment`).

### 9.3 `CURRENT` pointer (24 bytes)

Written atomically (`write_atomic`: `tmp → fsync → rename → dir fsync`). Body is
20 bytes, followed by a 4-byte CRC over the body (`encode_catalogue_pointer`,
`decode_catalogue_pointer`, `src/manifestation.rs`):

| Offset | Width | Field | Type / endianness |
|-------:|------:|-------|-------------------|
| 0 | 4 | `magic` | `u32` LE — `CAT_POINTER_MAGIC = 0x4F52_4350` (source label `"ORCP"`) |
| 4 | 4 | `schema` | `u32` LE — `CAT_SCHEMA = 1` |
| 8 | 4 | `family` | `u32` LE — must equal the catalogue's family |
| 12 | 8 | `index` | `u64` LE — the active segment index |
| 20 | 4 | `crc32c` | `u32` LE — CRC32C over bytes `[0, 20)` |

`active_segment`: if `CURRENT` reads and decodes, that index is authoritative;
otherwise (missing or torn) the next index after the highest existing segment is
used — **never** appending into a possibly-sealed segment (`Catalogue::active_segment`).

### 9.4 Summary `sum-<through>.sum`

Immutable, self-checksummed, atomically written. Header is 32 bytes; each folded
entry is 64 bytes; a 4-byte CRC over the whole body follows
(`encode_catalogue_summary` / `decode_catalogue_summary`, `src/manifestation.rs`):

| Offset | Width | Field | Type / endianness |
|-------:|------:|-------|-------------------|
| 0 | 4 | `magic` | `u32` LE — `CAT_SUMMARY_MAGIC = 0x4F52_4353` (source label `"ORCS"`) |
| 4 | 4 | `schema` | `u32` LE — `CAT_SCHEMA = 1` |
| 8 | 4 | `family` | `u32` LE |
| 12 | 8 | `through` | `u64` LE — the sealed segment index this summary covers (must equal the file's `<through>`) |
| 20 | 8 | `count` | `u64` LE — running record count folded through `through` |
| 28 | 4 | `n` | `u32` LE — number of folded entries |
| 32 | 64×`n` | entries | see below |
| 32+64·`n` | 4 | `crc32c` | `u32` LE — CRC32C over the body `[0, 32+64·n)` |

Each folded entry (64 bytes): `inode` `u64`, `inode_version` `u64`, `generation`
`u64`, `root` `u64`, `manifest_blake3` `[u8; 32]`. (The reference decoder guards
its allocation with a conservative 56-byte-per-entry lower bound and caps `n` at
`CAT_SUMMARY_MAX_INODES = 32768`; a stricter 64-byte bound is equally correct.)

A summary folds the **newest entry per inode** through `through`; on fold,
*newest* is ordered by `(inode_version, generation)` (`insert_newest`,
`src/manifestation.rs`).

### 9.5 Append and seal (the append-only protocol)

`Catalogue::append` (`src/manifestation.rs`):

1. `active_segment()` selects the target `index`; the record is written with
   `O_APPEND` and `fsync`ed; the resulting file size is read.
2. If `size >= CAT_SEGMENT_BYTES` (**131072** = 128 KiB), the segment is
   **sealed**.

`Catalogue::seal(index)`:

1. advance `CURRENT` to `index + 1` **first** (so later appends cannot land in the
   segment being summarised);
2. `fold_through(index)` and, if the fold is non-empty and
   `≤ CAT_SUMMARY_MAX_INODES`, write `sum-<index>.sum` atomically;
3. `fsync` the directory.

Appends are **O(1) amortised**: one small write plus an `fsync` per entry, and a
summary rewrite only at a seal. The caller holds the store's `append_lock` so a
segment is never appended to while it is being summarised (`src/manifestation.rs`).

### 9.6 The `HEAD` advertisement (legacy discovery)

`<volume>/.or_bloom/manifests/HEAD` (`GenerationStore::head_path`) is a legacy
advisory **list of generation numbers**, rewritten atomically. Layout
(`encode_head` / `decode_head`, `src/manifestation.rs`):

| Offset | Width | Field | Type / endianness |
|-------:|------:|-------|-------------------|
| 0 | 4 | `magic` | `u32` LE — `HEAD_MAGIC = 0x3144_484D` (on-disk `4D 48 44 31` = `"MHD1"`) |
| 4 | 4 | `schema` | `u32` LE — `MANIFEST_SCHEMA = 2` |
| 8 | 4 | `count` | `u32` LE — number of generation numbers |
| 12 | 8×`count` | `generation` | `u64` LE each |

`HEAD` has **no CRC**; validity is structural: `magic` and `schema` must match, the
length must be exactly `12 + 8·count`, and `count` is bounded (`count ≤
1_000_000` **and** `count ≤ remaining/8`) before allocation. A missing or
structurally invalid `HEAD` is simply `None`. `HEAD` is *not* the committed root:
the committed root is the `root` field carried by each manifest/entry; `HEAD` only
advertises which generation files to consider.

### 9.7 Recovery rule — reconstruct, never rewrite

`GenerationStore::latest_published` (fast path) and `recover` (full scan):

1. `Catalogue::latest` requires a **contiguous** run of segments starting at `0`
   (`segments.len() == active + 1`), an `active_segment` at or beyond the highest
   segment, and a non-empty fold; otherwise the catalogue is unusable and the caller
   falls back.
2. The fold reads the **newest usable summary at or below** the active segment
   (newest first; a corrupt summary is skipped), then replays only the segments
   **after** it — proportional to the suffix, not the whole history
   (`fold_through`).
3. Each newest candidate is validated: manifest self-digest binding
   (`manifest_blake3`), payload BLAKE3 (when the payload is present), and the
   overlay chain; if **any** candidate is missing or invalid, `latest_published`
   transparently falls back to the full validated `recover` scan, so the result
   always equals `recover().newest_per_inode()`.
4. `recover` itself prefers `HEAD` (a sorted-set union with the directory scan) and
   otherwise enumerates every `*.manifest`; each candidate is validated
   (self-digest, schema, payload BLAKE3) and an invalid candidate is **skipped**,
   never used, and never invalidates an earlier commit.

Properties (all `src/manifestation.rs`, `docs/MANIFESTATION.md` §7.1/§15):

* **Non-withdrawal** — a sealed segment, like a manifest, is never rewritten;
  publication only appends; the authoritative log is untouched.
* **Torn-safety** — every record is fixed-size and CRC32C-checksummed; a torn or
  truncated tail is detected and skipped, and a corrupt summary is ignored so
  recovery falls back to an earlier summary or a full segment replay.
* **Reconstructible** — the catalogue is *derived*; deleting it never changes the
  recoverable set. Recovery falls back to the `HEAD`/full-`*.manifest` scan, and
  the catalogue is re-seeded by the next publication or by the one-time
  `migrate_legacy_catalogue` (which folds existing manifests/`HEAD` into a fresh
  catalogue only when the catalogue is empty).
* **No number reuse** — `next_generation()` is `max(manifests, catalogue) + 1`, so a
  generation number is never reused even when a manifest write failed after its
  catalogue append.
* **Directory-fsync batching** — a manifest's directory entry is made durable for
  `generation <= MANIFEST_DIR_SYNC_INTERVAL (1024)` or at a seal; otherwise it is
  batched to the segment boundary. A manifest whose directory entry is not yet
  durable is rejected at recovery, and the fast path falls back to the previous,
  committed generation.

## 10. Versioning and forward-compatibility rules

### 10.1 Version fields

| Artifact | Field | Width | Current value | Source |
|---|---|---|---|---|
| Genesis payload (**authoritative-log identity**) | `format_version` | `u16` | `1` (`LOG_FORMAT_VERSION`); `0` = legacy, field absent | `src/volume.rs`, `src/lib.rs` |
| Record header | `format_version` | `u16` | `1` (`FORMAT_VERSION`) | `src/record.rs`, `src/lib.rs` |
| `volume.meta` | `format_version` | `u16` | `1` | `docs/ON_DISK.md` §4; `src/volume.rs` |
| `commit.watermark` | `format_version` | `u16` | `1` | `src/watermark.rs` |
| Generation manifest | `schema` | `u32` | `2` (`MANIFEST_SCHEMA`) | `src/manifestation.rs` |
| Manifest catalogue record / pointer / summary | `schema` | `u32` | `1` (`CAT_SCHEMA`) | `src/manifestation.rs` |
| `HEAD` advertisement | `schema` | `u32` | `2` (`MANIFEST_SCHEMA`) | `src/manifestation.rs` |
| Record type code | registry §7.1 | `u16` | version-qualified | `src/record.rs` |

`MANIFEST_SCHEMA = 2` adds the generational overlay fields (`base_generation`,
`base_manifest_blake3`, `overlay_depth`, `regions`); a schema-1 document still
decodes (its overlay fields default to a self-contained full base)
(`src/manifestation.rs`). The catalogue's `CAT_SCHEMA` is independent of the
manifest schema.

#### 10.1.1 The log format version registry

`LOG_FORMAT_VERSION` (`src/lib.rs`) is the current authoritative-log format
version, written into the genesis payload (§4.1). Only **explicitly known**
versions are accepted; a reader never guesses.

| Version | Meaning | Reader behaviour |
|---:|---|---|
| `0` | *legacy*: a genesis written before the field existed (24-byte payload, or an explicit zero) | **accept**, never reject |
| `1` | current: the versioned 26-byte genesis payload (`uuid ‖ segment_size ‖ format_version`) | **accept** |
| `> LOG_FORMAT_VERSION` | unknown future format | **refuse** with `OrfsError::UnsupportedFormatVersion { found, supported }` (`errno` `EPROTONOSUPPORT`) |

The same rule applies to `volume.meta`'s `format_version`: a known version `≤`
the current one is accepted; a higher one is refused with the typed error
(`VolumeMeta::decode`, `src/volume.rs`). The rule is enforced **at open**
(`Volume::open` reads and parses the genesis before returning), so a
future-format volume is never interpreted on a guess, and it is surfaced by
`orfs inspect` (`log_format_version`) and `orfs verify` (the `log_format_version`
check).

#### 10.1.2 Compatibility matrix (`or.log` v0 → v1 reader support)

| Frozen log | v0 (pre-versioning) reader | v1 (current) reader |
|---|---|---|
| `or.log` **v0** (24-byte genesis, version inferred `0`) | reads (it wrote it) | **reads** — replays, `verify --deep`s and reports `format_version = 0` |
| `or.log` **v1** (26-byte genesis, version `1`) | **must not guess** — the trailing 2 bytes are an unrecognised extension; a v0 reader may read the shared 24-byte prefix but must treat the format as newer and refuse | **reads** — reports `format_version = 1` |
| `or.log` **v>1** (unknown higher) | — | **refuses** with `UnsupportedFormatVersion` (never reinterprets) |

What a **v0 reader must never do**: interpret a versioned genesis as if the
trailing bytes were part of `segment_size` (or absent), silently truncate,
re-write, or “repair” the record, or mount on a guess. The frozen `legacy_v0`
and `current_v1` fixtures under `tests/fixtures/` pin both rows; the
`tests/format_compat.rs` court asserts them, and `docs/MIGRATION.md` gives the
field locations and the fixture-freezing procedure.

### 10.2 What a reader MUST do

* **Genesis `format_version`** (the authoritative-log identity, §4.1) and
  **`volume.meta` `format_version`**: accept every **known** version `≤` the
  current one (`0` and `1`); never reject an older known version; refuse an
  unknown **higher** version with `OrfsError::UnsupportedFormatVersion { found,
  supported }` (`errno` `EPROTONOSUPPORT`). Enforced at open in `Volume::open`
  (`parse_genesis_payload` / `GenesisIdentity`, `read_log_format_version`) and in
  `VolumeMeta::decode` (`src/volume.rs`).
* **Unknown record-header `format_version`** (a version this build does not
  implement) → `Compatibility` error; do **not** interpret the bytes.
  (`RecordHeader::decode`.)
* **Unknown `commit.watermark` `format_version`** → `Compatibility` error
  (`Watermark::decode`).
* **Unknown record type, bit 15 clear** → `Compatibility` error, and stop.
  (`classify_code`.) The scanner maps this to `OrfsError::Compatibility` and
  refuses the open with no silent repair (`docs/LOG-INVARIANTS.md` *No silent
  repair*; `docs/RECOVERY.md` §2.4).
* **Unknown record type, bit 15 set** (`0x8000 … 0xFFFF`) → may be skipped.
  (`classify_code`.)
* **Unknown catalogue `schema`** → the item is rejected: `schema` must equal
  `CAT_SCHEMA = 1` exactly, otherwise a record is skipped, and a pointer or summary
  is ignored (the pointer then falls back to the next fresh segment, the summary to
  an earlier summary or a full segment replay) (`decode_record`,
  `decode_catalogue_pointer`, `decode_catalogue_summary`).
* **Unknown `HEAD` `schema`** → `schema` must equal `MANIFEST_SCHEMA`, otherwise
  `HEAD` decodes to `None` and is treated as absent (the full `*.manifest` scan is
  used) (`decode_head`).
* **Manifest `schema`** → `GenerationManifest::decode` does **not** reject an
  unrecognised schema. It reads the overlay fields iff `schema >= 2` (so schema `0`
  or `1` decodes as a self-contained full base), and establishes validity from
  `MANIFEST_MAGIC`, exact consumption of the input, and the trailing BLAKE3
  self-digest; the `schema` value is carried forward verbatim. Forward
  compatibility therefore relies on **not** reusing the version-2 layout for an
  incompatible change; a reader must treat an unexpected (higher) schema
  conservatively. This is the one place the reference reader applies no explicit
  version gate (see the unknowns note at the end of this document).
* **Version-qualified identity** — a manifested generation is usable only for an
  **exact** `(inode, inode_version, root)` match, and its recorded
  `ekbloom_version` must match the build (currently `"0.3.0"`); otherwise the read
  falls back to the authoritative extent read (`docs/EKBLOOM-INTEGRATION.md` §3/§4).

### 10.3 New types and extensions

* New record types **must** claim previously unused codes. A new *mandatory* type
  takes a code with bit 15 clear; an *optional* extension sets bit 15
  (`0x8000`), so pre-existing readers skip it. An unknown mandatory code must halt
  a reader (`src/record.rs`).
* A new record format version is signalled by `format_version` (the log version
  registry §10.1.1, or the record header); a reader that does not implement it
  refuses rather than guessing (§10.2). A new **log** format version is registered
  by extending the registry and freezing a new fixture (`docs/MIGRATION.md`).
* The catalogue and `HEAD` carry explicit `schema` fields so a future layout change
  is detectable without reinterpreting old bytes.

### 10.4 Torn-tail quarantine rule

A physical tail beyond the committed root is never reinterpreted and never
rewritten. On a **writable** open (`OpenMode::ReadWrite`), if `physical_end >
committed_root`, every segment whose id is `>= committed_root` is **moved** (never
truncated) into `or.log/quarantine/` — a name collision is disambiguated by a
`.N` suffix — and a fresh, empty `<committed_root>.seg` continues the stream
(`quarantine_after` / `quarantine_segment`, `src/log.rs`; `Log::open_with_pins`).
A segment that also holds committed bytes (its id `< committed_root`) is left in
place, untouched. A **read-only** open classifies the tail but modifies **no byte**.
The classification is explicit (`RecoveryDisposition::RetainedTail { kind,
abandoned_bytes, quarantined }`, where `kind ∈ { TornRecord, Uncommitted }`;
`src/log.rs`, `docs/RECOVERY.md` §1–§2).

A **torn or malformed record in a non-final segment** is corruption, not a tail,
and a footer/header checksum failure in the final segment is the torn tail
(§6.3/§6.5; `scan_log`, `src/log.rs`).

### 10.5 Explicit unknowns

Facts this specification does **not** assert, because the source does not decide
them:

* There is no explicit "unsupported manifest schema" rejection in
  `GenerationManifest::decode` (§10.2): an unrecognised `schema` is parsed using
  the `schema >= 2` layout rather than refused. Whether a future higher schema
  would be safely rejected is therefore **not determined by the source** today.
* The `previous_inode_offset` (header bytes `[44, 52)`) is described in the source
  only as "offset of a previous record for the same inode, or `0`"; the framing
  layer itself does not use it, and no per-inode chain-walk is defined here.
* The typed payload layouts of the non-genesis record types are defined in
  `docs/TRANSACTIONS.md` and `docs/NAMESPACE.md`, not in this document (§2.2);
  this specification covers framing only.

---

## 11. The encrypted volume (Phase 85; length-preserving seal in Phase 86, opt-in)

An **encrypted volume** is a **distinct volume kind** created by
`orfs init --key-file <path>` and served by `orfs mount --key-file <path>`. It
**does not change the unencrypted `or.log` format**: an ordinary volume carries
`volume.meta` and no `crypto.meta`, while an encrypted volume carries
`crypto.meta` and no `volume.meta`, so the two layouts never overlap and a reader
can tell them apart without a key. Since Phase 86 the authoritative segment bytes
are an **offset-preserving** keystream ciphertext (ciphertext length == plaintext
length), so the encrypted store *is* a normal OrFS log underneath. See
`docs/ERASURE.md` for the design and `docs/MIGRATION.md` §6 for the compatibility
statement.

| Artifact | Field | Width | Current value | Source |
|---|---|---|---|---|
| `crypto.meta` | `crypto_format_version` | `u16` | `2` (`CRYPTO_FORMAT_VERSION`; `1` was the retired Phase-85 framed seal) | `src/encvol.rs` |
| `crypto.segments` | table schema | — | `"orfs.crypto-segments.v1"` | `src/encvol.rs` |
| Sealed blob | version byte | `u8` | `1` (`SEALED_VERSION`) | `src/keyring.rs` |

### 11.1 Directory layout

```text
   <volume>/crypto.meta          plaintext identity (schema + CRC32C); NO key bytes
   <volume>/crypto.segments      master-key-sealed per-segment authentication table
   <volume>/or.log/NNNN…seg      the real OrFS log, keystream-sealed per segment
   <operator>/<key-file>         master key + wrapped epoch keys (0600); never in the volume
```

`crypto.meta` is a JSON envelope `{schema, crc32c, meta}` with
`schema = "orfs.crypto-meta.v1"`; `crc32c` is the CRC32C of the canonical
re-serialization of `meta` (`{volume_uuid, segment_size, created_at_unix_secs,
crypto_format_version}`). It is a **plaintext** identity: a reader that does not
have the key can still discover that a volume is encrypted and check a key file's
UUID binding. A volume whose `crypto_format_version` is below `2` is the retired
Phase-85 framed seal and is refused with a typed `Compatibility` error, never
misread.

### 11.2 The seal (byte-exact)

The authoritative segment bytes are transformed **in place** at the existing
`Segment`/`ReadAt` I/O seam, so the file layout is exactly the unencrypted log's
(`docs/ON_DISK.md` §2–§3): segment file name `NNNNNNNNNNNNNNNN.seg` with the
segment id as its first logical offset. The transform is a **positional keystream**:

```text
   ciphertext[i] = plaintext[i] XOR stream(key(epoch), segment_id, i)

   stream(key, id, p) = BLAKE3_keyed(enc_subkey(key),
                          "orfs.seal.pos.v1" ‖ le64(id) ‖ le64(p / 512))[p % 512]
```

* It is **length preserving** (ciphertext length == plaintext length) and
  **random access** (a window is byte-identical to the whole stream), so every
  offset computation above the seam is unchanged.
* Integrity is a **per-segment keyed-BLAKE3 MAC** over the segment's ciphertext
  (with its authenticated length folded in last), recorded in the master-key-sealed
  table `crypto.segments` (schema `"orfs.crypto-segments.v1"`, JSON payload
  `{schema, table:{segments:{<id>:{epoch, authenticated_len, mac}}}}`), where
  `mac` is lowercase hex. The table is sealed under the master key and carries no
  key material; it is verified at open/scan and advanced by `seal_point` (the
  durability point) at each `fsync`.

A reader MUST refuse a volume whose `crypto_format_version` it does not implement
(`Compatibility`), and MUST return a typed fail-closed error
(`KeyUnavailable`/`KeyDestroyed`, `ENOKEY`) rather than any plaintext when a
segment's covering epoch key is unavailable or was destroyed. A segment whose
ciphertext does not match its recorded MAC is `CryptoAuthFailed` (`EBADMSG`);
bytes beyond the authenticated prefix are treated as an abandoned tail (retained,
never decrypted, never trusted). It MUST never fabricate a plaintext prefix.
