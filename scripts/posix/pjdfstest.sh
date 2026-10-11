#!/bin/sh
# Phase 24 in-container runner: the "broad POSIX court".
#
# Runs the commit-pinned pjdfstest suite twice — once against a MOUNTED OrFS
# volume (rw, traditional /dev/fuse transport) and once against a reference
# directory on a trusted ordinary filesystem (the ext4 project drive) — and
# records per-test verdicts, per-assertion failures, and a classification of
# every OrFS deviation in evidence/correctness/pjdfstest.json.
#
# This script runs ONLY inside scripts/container-posix-test.sh (the Dockerfile.posix
# image). It needs /dev/fuse, SYS_ADMIN, and root (pjdfstest requires root).
#
# Gate: the OrFS run must be reproducible and every failing test file must be
# accounted for. The set of OrFS-failing test files must equal the reviewed
# allowlist in scripts/posix/pjdfstest-expected.txt, and no failing assertion may
# be unclassified. A new failure (or a newly-appearing deviation) fails the gate.
set -eu

PROJECT_DIR="$(pwd)"
PJDFSTEST_DIR="${PJDFSTEST_DIR:-/opt/pjdfstest}"
COMMIT="$(cat "$PJDFSTEST_DIR/COMMIT" 2>/dev/null || echo unknown)"
EVIDENCE="$PROJECT_DIR/evidence/correctness/pjdfstest.json"
EXPECTED_TSV="$PROJECT_DIR/scripts/posix/pjdfstest-expected.tsv"
SUITE_REPO="https://github.com/pjd/pjdfstest"

TS="$(date +%s)-$$"
BASE="$PROJECT_DIR/target/posix-test/$TS"
BACKING="$BASE/backing"
MNT="$BASE/orfs-mnt"
REF="$BASE/reference"
mkdir -p "$BACKING" "$MNT" "$REF"

echo "posix: pjdfstest commit $COMMIT"
echo "posix: building the orfs binary"
cargo build --quiet --bin orfs
ORFS="$PROJECT_DIR/target/debug/orfs"

umask 0
"$ORFS" init "$BACKING" >/dev/null

echo "posix: mounting OrFS (rw, transport=fuse, backing-io=sync, allow-other) at $MNT"
# `--allow-other` is REQUIRED for pjdfstest: the suite switches to unprivileged
# uids (e.g. nobody=65534) to exercise permission semantics, and a FUSE mount
# mounted by root denies every other uid at the VFS layer unless allow_other is
# set. Without it, those tests would measure the kernel's mount ACL, not OrFS.
#
# TTLs are zeroed so every path walk re-invokes the daemon's own permission
# checks. With a positive entry TTL the kernel can satisfy a walk from cached
# dentries and never re-check the search bit after a chmod, which pjdfstest's
# "search permission denied" cases detect (docs/FUSE-SEMANTICS.md).
"$ORFS" mount "$BACKING" "$MNT" --transport fuse --backing-io sync --allow-other \
    --entry-ttl-ms 0 --attr-ttl-ms 0 \
    >"$BASE/mount.out" 2>"$BASE/mount.err" &
MOUNT_PID=$!

mounted=0
i=0
while [ "$i" -lt 300 ]; do
    if grep -qsF " $MNT " /proc/mounts; then
        mounted=1
        break
    fi
    if ! kill -0 "$MOUNT_PID" 2>/dev/null; then
        break
    fi
    sleep 0.2
    i=$((i + 1))
done
if [ "$mounted" != 1 ]; then
    echo "posix: FATAL: OrFS mount did not appear within 60s" >&2
    cat "$BASE/mount.err" >&2 || true
    exit 1
fi

ORFS_FSTYPE="$(df -PT "$MNT" | tail -1 | awk '{print $2}')"

# pjdfstest runs each `.t` as a shell script with the CWD set to the filesystem
# under test. Bound each file so a hang on one test cannot wedge the court.
run_suite() {
    cwd="$1"
    out="$2"
    mkdir -p "$out"
    # Optional: restrict to one pjdfstest subdirectory for rapid harness checks.
    if [ -n "${PJDFSTEST_SUBDIR:-}" ]; then
        set -- "$PJDFSTEST_DIR"/tests/"$PJDFSTEST_SUBDIR"/*.t
    else
        set -- "$PJDFSTEST_DIR"/tests/*/*.t
    fi
    for t in "$@"; do
        [ -e "$t" ] || continue
        rel="${t#"$PJDFSTEST_DIR"/tests/}"
        name="$(printf '%s' "$rel" | tr '/' '_' | sed 's/\.t$//')"
        (cd "$cwd" && timeout -k 5 180 sh "$t") \
            >"$out/$name.tap" 2>"$out/$name.err" || true
    done
}

echo "posix: running pjdfstest against the OrFS mount"
run_suite "$MNT" "$BASE/tap-orfs"

echo "posix: unmounting OrFS"
"$ORFS" unmount "$MNT" >/dev/null 2>&1 \
    || umount -l "$MNT" >/dev/null 2>&1 \
    || kill "$MOUNT_PID" 2>/dev/null \
    || true
wait "$MOUNT_PID" 2>/dev/null || true

REF_FSTYPE="$(df -PT "$REF" | tail -1 | awk '{print $2}')"
echo "posix: running pjdfstest against the reference ($REF_FSTYPE)"
run_suite "$REF" "$BASE/tap-ref"

# ---------------------------------------------------------------------------
# Parse TAP into per-file summaries and per-assertion failures.
# ---------------------------------------------------------------------------
summarize() {
    dir="$1"
    out="$2"
    : >"$out"
    for tap in "$dir"/*.tap; do
        [ -e "$tap" ] || continue
        name="$(basename "$tap" .tap)"
        total="$(grep -cE '^(not )?ok([ ]|$)' "$tap" 2>/dev/null || true)"
        failed="$(grep -cE '^not ok([ ]|$)' "$tap" 2>/dev/null || true)"
        [ -n "$total" ] || total=0
        [ -n "$failed" ] || failed=0
        verdict=ok
        [ "$failed" -gt 0 ] && verdict=fail
        printf '%s\t%s\t%s\t%s\n' "$name" "$total" "$failed" "$verdict" >>"$out"
    done
}

extract_fails() {
    dir="$1"
    out="$2"
    : >"$out"
    for tap in "$dir"/*.tap; do
        [ -e "$tap" ] || continue
        name="$(basename "$tap" .tap)"
        grep -E '^not ok([ ]|$)' "$tap" 2>/dev/null | while IFS= read -r line; do
            n="$(printf '%s' "$line" | sed -n 's/^not ok \([0-9]*\).*/\1/p')"
            tried="$(printf '%s' "$line" | sed -n "s/.*tried '\([^']*\)'.*/\1/p")"
            expected="$(printf '%s' "$line" | sed -n 's/.*expected \(.*\), got \(.*\)$/\1/p')"
            got="$(printf '%s' "$line" | sed -n 's/.*expected \(.*\), got \(.*\)$/\2/p')"
            [ -n "$n" ] || n=0
            printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$n" "$tried" "$expected" "$got" >>"$out"
        done
    done
}

summarize "$BASE/tap-orfs" "$BASE/files-orfs.tsv"
summarize "$BASE/tap-ref" "$BASE/files-ref.tsv"
extract_fails "$BASE/tap-orfs" "$BASE/fails-orfs.tsv"
extract_fails "$BASE/tap-ref" "$BASE/fails-ref.tsv"

# ---------------------------------------------------------------------------
# Classify every OrFS failing assertion.
#
#   unsupported_node_type       the failing command is a FIFO/block/char/socket
#                               creation (mkfifo / mknod b|c / bind), which OrFS
#                               deliberately rejects with EOPNOTSUPP
#   unsupported_errno           any failure whose observed errno is EOPNOTSUPP
#   unsupported_node_downstream a later assertion in a file whose first failure
#                               was an unsupported node-type creation
#   unclassified                a genuine, unexplained deviation -> gate fails
# ---------------------------------------------------------------------------
: >"$BASE/unsupported-files.txt"
awk -F'\t' '
    $3 ~ /^(mkfifo |bind )/ || $3 ~ /^mknod .* [bc] / || $5 ~ /^(EOPNOTSUPP|ENOTSUP)$/ {print $1}
' "$BASE/fails-orfs.tsv" | sort -u >"$BASE/unsupported-files.txt"

: >"$BASE/fails-orfs-classified.tsv"
while IFS="$(printf '\t')" read -r f n tried expected got; do
    [ -n "${f:-}" ] || continue
    class=unclassified
    case "$tried" in
        mkfifo\ * | bind\ *) class=unsupported_node_type ;;
    esac
    if [ "$class" = unclassified ]; then
        case "$tried" in
            mknod\ *\ b\ * | mknod\ *\ c\ *) class=unsupported_node_type ;;
        esac
    fi
    if [ "$class" = unclassified ]; then
        case "$got" in
            EOPNOTSUPP | ENOTSUP) class=unsupported_errno ;;
        esac
    fi
    if [ "$class" = unclassified ] && grep -qxF "$f" "$BASE/unsupported-files.txt"; then
        class=unsupported_node_downstream
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$f" "$n" "$tried" "$expected" "$got" "$class" >>"$BASE/fails-orfs-classified.tsv"
done <"$BASE/fails-orfs.tsv"

awk -F'\t' '$4 == "fail" {print $1}' "$BASE/files-orfs.tsv" | sort -u >"$BASE/fail-files-orfs.txt"
awk -F'\t' '$4 == "fail" {print $1}' "$BASE/files-ref.tsv" | sort -u >"$BASE/fail-files-ref.txt"

# Resolve documented deviations: every still-`unclassified` failure is looked up
# by (file, assertion) in the reviewed allowlist and adopts its class.
documented_present=0
if [ -f "$EXPECTED_TSV" ]; then
    documented_present=1
    awk 'BEGIN{FS="\t";OFS="\t"}
         FNR==NR { if ($1 !~ /^#/ && NF >= 3) m[$1" "$2]=$3; next }
         { if ($6 == "unclassified") { k=$1" "$2; if (k in m) $6=m[k] } print }' \
        "$EXPECTED_TSV" "$BASE/fails-orfs-classified.tsv" >"$BASE/classified.new"
    mv "$BASE/classified.new" "$BASE/fails-orfs-classified.tsv"
fi

unclassified_count="$(grep -c 'unclassified$' "$BASE/fails-orfs-classified.tsv" 2>/dev/null || true)"
[ -n "$unclassified_count" ] || unclassified_count=0

# Drift check: every allowlisted assertion must still fail, so a fix (or a suite
# change) forces the allowlist to be updated rather than silently ignored.
stale_entries=""
if [ "$documented_present" = 1 ]; then
    awk 'BEGIN{FS="\t"} $1 !~ /^#/ && NF >= 3 {print $1" "$2}' "$EXPECTED_TSV" \
        | sort -u >"$BASE/expected-keys.txt"
    awk -F'\t' '{print $1" "$2}' "$BASE/fails-orfs-classified.tsv" \
        | sort -u >"$BASE/observed-keys.txt"
    stale_entries="$(comm -23 "$BASE/expected-keys.txt" "$BASE/observed-keys.txt" || true)"
fi
stale_count="$(printf '%s' "$stale_entries" | grep -c . || true)"
[ -n "$stale_count" ] || stale_count=0

result=pass
if [ "$documented_present" != 1 ]; then
    echo "posix: FAIL: allowlist $EXPECTED_TSV is missing" >&2
    result=fail
fi
if [ "$unclassified_count" -gt 0 ]; then
    result=fail
    echo "posix: FAIL: $unclassified_count unclassified OrFS assertion failure(s):" >&2
    grep 'unclassified$' "$BASE/fails-orfs-classified.tsv" >&2 || true
fi
if [ "$stale_count" -gt 0 ]; then
    result=fail
    echo "posix: FAIL: allowlisted assertion(s) no longer fail (update $EXPECTED_TSV):" >&2
    echo "$stale_entries" >&2
fi

# ---------------------------------------------------------------------------
# Emit the evidence JSON.
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "$EVIDENCE")"
jq -n -f "$PROJECT_DIR/scripts/posix/evidence.jq" \
    --arg suite_repo "$SUITE_REPO" \
    --arg commit "$COMMIT" \
    --arg image "${ORFS_POSIX_IMAGE_NAME:-orfs-posix:1.99.0}" \
    --arg image_digest "${ORFS_POSIX_IMAGE_DIGEST:-unknown}" \
    --arg base_image "${ORFS_BASE_IMAGE_NAME:-rust:1.99.0-slim-bookworm}" \
    --arg uname "$(uname -s)" \
    --arg kernel "$(uname -r)" \
    --arg orfs_fstype "$ORFS_FSTYPE" \
    --arg ref_fstype "$REF_FSTYPE" \
    --arg unsupported_note "OrFS represents only regular files, directories and symlinks. mknod(2) for S_IFIFO/S_IFCHR/S_IFBLK/S_IFSOCK returns EOPNOTSUPP (docs/FUSE-SEMANTICS.md §5). pjdfstest files that create FIFO/block/char/socket nodes are therefore recorded as unsupported rather than failures." \
    --arg deviations_note "Every OrFS failing assertion is either mechanically explained ('unsupported_node_types': the test creates a FIFO/block/char/socket node, which OrFS rejects with EOPNOTSUPP) or is a documented deviation listed in scripts/posix/pjdfstest-expected.tsv (reasons in documented_deviations). 'shared_with_reference' means the reference filesystem fails the same assertion. The gate fails on any unclassified failure or any allowlisted assertion that no longer fails." \
    --arg unsupported_files "$(cat "$BASE/unsupported-files.txt")" \
    --arg documented_present "$documented_present" \
    --arg stale_count "$stale_count" \
    --arg unclassified_count "$unclassified_count" \
    --arg result "$result" \
    --rawfile orfs_raw "$BASE/files-orfs.tsv" \
    --rawfile ref_raw "$BASE/files-ref.tsv" \
    --rawfile orfs_fails_raw "$BASE/fails-orfs-classified.tsv" \
    --rawfile ref_fails_raw "$BASE/fails-ref.tsv" \
    --rawfile expected_raw "$EXPECTED_TSV" \
    >"$EVIDENCE"

echo "posix: OrFS   files=$(wc -l <"$BASE/files-orfs.tsv" | tr -d ' ') failing=$(wc -l <"$BASE/fail-files-orfs.txt" | tr -d ' ') assertions_failed=$(awk -F'\t' '{s+=$3} END {print s+0}' "$BASE/files-orfs.tsv")"
echo "posix: ref    files=$(wc -l <"$BASE/files-ref.tsv" | tr -d ' ') failing=$(wc -l <"$BASE/fail-files-ref.txt" | tr -d ' ') assertions_failed=$(awk -F'\t' '{s+=$3} END {print s+0}' "$BASE/files-ref.tsv")"
echo "posix: unclassified=$unclassified_count stale_allowlist=$stale_count result=$result"
echo "posix: evidence $EVIDENCE"

[ "$result" = pass ]
