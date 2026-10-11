#!/bin/sh
# Phase 28: run the NATIVE FUSE path under valgrind memcheck.
#
# Scope: the in-crate unit tests for the native transport (`fuse_native`,
# `fuse_uring`, `buffers`) and the dedicated native-FUSE fuzzer
# (`tests/native_fuse_fuzz.rs`). These need no `/dev/fuse` mount and no
# `io_uring` ring, so they run in the ordinary unprivileged build image
# (`docker_run`), which now carries `valgrind` (see `Dockerfile`).
#
# Why not AddressSanitizer / Miri / ThreadSanitizer:
#   * ASan (`-Zsanitizer=address`) and Miri require a **nightly** toolchain; this
#     project is pinned to stable `1.99.0` and builds offline. Miri additionally
#     cannot execute the syscalls (mount/io_uring/ioctl) this code performs.
#   * TSan would need nightly too. So valgrind memcheck is the sanitizer that
#     actually runs here; its limits are recorded honestly in the receipt: it
#     instruments the process's own memory accesses, but it does not see the
#     kernel copying out of the registered ring buffers (that side is covered by
#     the layout/clamp assertions instead).
#
# A machine-generated receipt is written to `evidence/security/valgrind.json`
# from inside the container (bind-mounted tree), plus raw logs under
# `evidence/security/valgrind-logs/`.
set -eu
. "$(dirname "$0")/lib.sh"

docker_run sh -c '
    set -eu
    mkdir -p evidence/security/valgrind-logs

    if ! command -v valgrind >/dev/null 2>&1; then
        printf "%s\n" \
          "{\"schema\":\"orfs.evidence.valgrind.v1\",\"ran\":false," \
          "\"reason\":\"valgrind is not installed in $ORFS_IMAGE\"}" \
          > evidence/security/valgrind.json
        echo "container-valgrind: valgrind unavailable; wrote documented-unavailable receipt" >&2
        exit 0
    fi

    VG="valgrind --tool=memcheck --error-exitcode=1 --leak-check=full --errors-for-leak-kinds=definite"
    VGV="$(valgrind --version)"

    LIB_BIN=$(cargo test --lib --no-run --message-format=json 2>/dev/null \
        | sed -n "s/.*\"executable\":\"\([^\"]*\/deps\/[^\"]*\)\".*/\1/p" | head -n1)
    FUZZ_BIN=$(cargo test --test native_fuse_fuzz --no-run --message-format=json 2>/dev/null \
        | grep "\"name\":\"native_fuse_fuzz\"" \
        | sed -n "s/.*\"executable\":\"\([^\"]*\/deps\/[^\"]*\)\".*/\1/p" | head -n1)
    test -x "$LIB_BIN"
    test -x "$FUZZ_BIN"
    echo "container-valgrind: lib=$LIB_BIN" >&2
    echo "container-valgrind: fuzz=$FUZZ_BIN" >&2

    run_vg() {
        name=$1; bin=$2; shift 2
        log="evidence/security/valgrind-logs/$name.log"
        if $VG --log-file="$log" "$bin" "$@" >/dev/null 2>&1; then
            rc=0
        else
            rc=$?
        fi
        summary=$(sed -n "s/.*ERROR SUMMARY: \([0-9][0-9]*\) errors.*/\1/p" "$log" | tail -n1)
        : "${summary:=unknown}"
        printf "%s|%s|%s\n" "$name" "$rc" "$summary"
    }

    echo "container-valgrind: valgrind $VGV" >&2
    {
        run_vg lib_buffers "$LIB_BIN" buffers::tests --test-threads=1
        run_vg lib_fuse_uring "$LIB_BIN" fuse_uring::tests --test-threads=1
        run_vg lib_fuse_native "$LIB_BIN" fuse_native::tests --test-threads=1
        run_vg native_fuse_fuzz "$FUZZ_BIN" --test-threads=1
    } > evidence/security/valgrind-logs/summary.txt
    cat evidence/security/valgrind-logs/summary.txt >&2

    json_entry() {
        line=$1
        n=$(printf "%s" "$line" | cut -d"|" -f1)
        rc=$(printf "%s" "$line" | cut -d"|" -f2)
        errs=$(printf "%s" "$line" | cut -d"|" -f3)
        case "$errs" in
            "" | *[!0-9]*) errs="\"$errs\"" ;;
        esac
        printf "    {\"target\":\"%s\",\"exit_code\":%s,\"error_summary\":%s,\"log\":\"evidence/security/valgrind-logs/%s.log\"}" \
            "$n" "$rc" "$errs" "$n"
    }

    {
        printf "{\n"
        printf "  \"schema\":\"orfs.evidence.valgrind.v1\",\n"
        printf "  \"ran\":true,\n"
        printf "  \"tool\":\"%s\",\n" "$VGV"
        printf "  \"image_digest\":\"%s\",\n" "${ORFS_IMAGE_DIGEST:-unknown}"
        printf "  \"method\":\"valgrind --tool=memcheck --error-exitcode=1 --leak-check=full --errors-for-leak-kinds=definite on the native-path unit-test and fuzzer binaries\",\n"
        printf "  \"asan_miri_tsan\":{\"available\":false,\"reason\":\"nightly-only; the project is pinned to stable 1.99.0 and builds offline, and Miri cannot run mount/io_uring/ioctl\"},\n"
        printf "  \"targets\":[\n"
        first=1
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            [ "$first" = 1 ] || printf ",\n"
            first=0
            json_entry "$line"
        done < evidence/security/valgrind-logs/summary.txt
        printf "\n  ]\n}\n"
    } > evidence/security/valgrind.json

    # Fail the court if any target had a non-zero exit (memcheck error or a
    # failing test), so a red result can never be silently recorded as green.
    if cut -d"|" -f2 evidence/security/valgrind-logs/summary.txt | grep -qv "^0$"; then
        echo "container-valgrind: a valgrind target failed (see summary)" >&2
        exit 1
    fi
    echo "container-valgrind: OK (memcheck found 0 errors in every target)"
'
