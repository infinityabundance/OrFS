#!/bin/sh
# Build the OrFS images from the pinned base image.
# Run once (or after Dockerfile changes); the derived images are deterministic.
set -eu
. "$(dirname "$0")/lib.sh"

echo "building $ORFS_IMAGE from base $ORFS_BASE_IMAGE"
docker build -f "$ORFS_PROJECT_DIR/Dockerfile" -t "$ORFS_IMAGE" "$ORFS_PROJECT_DIR"

echo "building $ORFS_KMOUNT_IMAGE"
docker build -f "$ORFS_PROJECT_DIR/Dockerfile.kmount" -t "$ORFS_KMOUNT_IMAGE" "$ORFS_PROJECT_DIR"

echo "building $ORFS_POSIX_IMAGE (vendors commit-pinned pjdfstest)"
docker build -f "$ORFS_PROJECT_DIR/Dockerfile.posix" -t "$ORFS_POSIX_IMAGE" "$ORFS_PROJECT_DIR"

echo "building $ORFS_APP_IMAGE (end-to-end application workloads)"
docker build -f "$ORFS_PROJECT_DIR/Dockerfile.appworkload" -t "$ORFS_APP_IMAGE" "$ORFS_PROJECT_DIR"

echo "done:"
docker image ls
