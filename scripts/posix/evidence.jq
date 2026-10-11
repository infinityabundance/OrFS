def rows($raw):
  ($raw | split("\n") | map(select(length > 0)) | map(split("\t")));

def num($s): ($s | tonumber);

# The reviewed allowlist, keyed by "file assertion" -> {class, reason}.
def expectedmap($raw):
  ($raw | split("\n")
       | map(select(length > 0 and (.[0:1] != "#")))
       | map(split("\t"))
       | map(select(length >= 4))
       | map({key: (.[0] + " " + .[1]), value: {class: .[2], reason: .[3]}})
       | from_entries);

def fsummary($rows):
  {
    files_total: ($rows | length),
    files_ok: ([$rows[] | select(.[3] == "ok")] | length),
    files_failed: ([$rows[] | select(.[3] == "fail")] | length),
    assertions_total: ([$rows[] | num(.[1])] | add // 0),
    assertions_failed: ([$rows[] | num(.[2])] | add // 0)
  };

def flist($rows):
  [$rows[] | {name: .[0], assertions: num(.[1]), failed: num(.[2]), verdict: .[3]}];

def is_unsupported($class): ($class | startswith("unsupported"));

(rows($orfs_raw)) as $orfs
| (rows($ref_raw)) as $ref
| (rows($orfs_fails_raw)) as $of
| (rows($ref_fails_raw)) as $rf
| (expectedmap($expected_raw)) as $ext
| {
    generated_by: "scripts/posix/pjdfstest.sh",
    suite: "pjdfstest",
    suite_repository: $suite_repo,
    suite_commit: $commit,
    image: {name: $image, digest: $image_digest, base: $base_image},
    environment: {
      uname: $uname,
      kernel: $kernel,
      uid: 0,
      orfs_transport: "fuse (traditional /dev/fuse)",
      orfs_durability: "ordered",
      orfs_backing_io: "sync",
      orfs_mount_options: ["allow-other", "entry-ttl-ms=0", "attr-ttl-ms=0"],
      orfs_fstype: $orfs_fstype,
      reference_fstype: $ref_fstype
    },
    orfs: {
      summary: fsummary($orfs),
      files: flist($orfs)
    },
    reference: {
      summary: fsummary($ref),
      files: flist($ref),
      failures: [$rf[] | {file: .[0], assertion: num(.[1]), tried: .[2], expected: .[3], got: .[4]}]
    },
    deviations: {
      note: $deviations_note,
      unsupported_node_types: {
        errno: "EOPNOTSUPP",
        rationale: $unsupported_note,
        files: ($unsupported_files | split("\n") | map(select(length > 0))),
        assertions_covered: ([$of[] | select(is_unsupported(.[5]))] | length)
      },
      documented_deviations: [
        $of[]
        | select((is_unsupported(.[5]) or .[5] == "shared_with_reference") | not)
        | {
            file: .[0],
            assertion: num(.[1]),
            tried: .[2],
            expected: .[3],
            got: .[4],
            class: .[5],
            reason: ($ext[.[0] + " " + .[1]].reason // "")
          }
      ],
      shared_with_reference: [
        $of[] | select(.[5] == "shared_with_reference")
        | {file: .[0], assertion: num(.[1]), expected: .[3], got: .[4], reason: ($ext[.[0] + " " + .[1]].reason // "")}
      ],
      class_counts: ([$of[][5]] | group_by(.) | map({class: .[0], count: length})),
      unclassified: [
        $of[] | select(.[5] == "unclassified")
        | {file: .[0], assertion: num(.[1]), tried: .[2], expected: .[3], got: .[4]}
      ]
    },
    gate: {
      documented_allowlist_present: ($documented_present == "1"),
      unclassified_failures: ($unclassified_count | tonumber),
      stale_allowlist_entries: ($stale_count | tonumber)
    },
    result: $result
  }
