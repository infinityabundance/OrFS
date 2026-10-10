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

The codes `0x8001 … 0xFFFF` are reserved for optional extensions.

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

### 4.1 Genesis payload (24 bytes)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0      | 16   | volume `uuid` |
| 16     | 8    | `segment_size` u64 |

`volume.meta` and the genesis payload redundantly carry the UUID and segment
size so that `orfs verify` can cross-check identity against authoritative
content.

## 5. Integrity model

* `header_check` and `record_check` are **CRC32C**. They detect malformed or
  corrupted framing only; they are not authentication and do not define record
  identity (a root is a position, never a hash).
* `MAX_PAYLOAD_LEN` = 64 MiB bounds allocation from untrusted records.
* All length arithmetic is checked (`u64` overflow yields a controlled error).
