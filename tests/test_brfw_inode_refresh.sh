#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Integration test: inode refresh via inotify.
#
# When a monitored binary is atomically replaced on disk (simulating a package
# manager rename-over), brfw must detect the inode change via inotify and update
# the eBPF map so the new binary is still enforced correctly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BRFW="$REPO_DIR/src/bin/brfw"
HELPER_SRC="$SCRIPT_DIR/helpers/simple_connect.c"
HELPER_BIN="$SCRIPT_DIR/helpers/simple_connect"
WATCHED_BIN="/tmp/brfw_test_inode_refresh"
BRFW_LOG="/tmp/brfw_test_inode_refresh.log"
BRFW_PID=""

cleanup() {
    if [ -n "$BRFW_PID" ] && kill -0 "$BRFW_PID" 2>/dev/null; then
        kill "$BRFW_PID" 2>/dev/null || true
        wait "$BRFW_PID" 2>/dev/null || true
    fi
    rm -f "$HELPER_BIN" "$WATCHED_BIN" "${WATCHED_BIN}.new" "$BRFW_LOG"
}
trap cleanup EXIT

# --- Preconditions ---

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: must run as root"
    exit 0
fi

if [ ! -x "$BRFW" ]; then
    echo "FAIL: brfw binary not found at $BRFW (run 'make' in src/ first)"
    exit 1
fi

# --- Build test helper ---

echo "  Building simple_connect helper..."
cc -Wall -o "$HELPER_BIN" "$HELPER_SRC"

# --- Place initial watched binary ---

cp "$HELPER_BIN" "$WATCHED_BIN"
chmod +x "$WATCHED_BIN"
ORIG_INO=$(stat -c '%i' "$WATCHED_BIN")

# --- Start brfw monitoring the temp binary ---

echo "  Starting brfw in allowlist mode watching $WATCHED_BIN..."
"$BRFW" -m allowlist -b "$WATCHED_BIN" >"$BRFW_LOG" 2>&1 &
BRFW_PID=$!

sleep 1

if ! kill -0 "$BRFW_PID" 2>/dev/null; then
    echo "FAIL: brfw exited prematurely"
    cat "$BRFW_LOG"
    exit 1
fi

# --- Verify original binary is allowed ---

echo "  Running watched binary before replacement (should be allowed)..."
set +e
"$WATCHED_BIN"
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -ne 0 ]; then
    echo "FAIL: original binary was not allowed (exit $EXIT_CODE) — check brfw setup"
    cat "$BRFW_LOG"
    exit 1
fi

# --- Atomically replace the binary ---

echo "  Atomically replacing binary (simulating package manager update)..."
cp "$HELPER_BIN" "${WATCHED_BIN}.new"
mv "${WATCHED_BIN}.new" "$WATCHED_BIN"

NEW_INO=$(stat -c '%i' "$WATCHED_BIN")

if [ "$ORIG_INO" -eq "$NEW_INO" ]; then
    echo "SKIP: mv did not change inode on this filesystem — cannot test inode refresh"
    exit 0
fi

echo "  Inode changed: $ORIG_INO -> $NEW_INO"

# Give brfw time to process the inotify event and update the eBPF map
sleep 1

if ! kill -0 "$BRFW_PID" 2>/dev/null; then
    echo "FAIL: brfw exited after binary replacement"
    cat "$BRFW_LOG"
    exit 1
fi

# --- Verify replaced binary is still allowed ---

echo "  Running replaced binary (should still be allowed after inode refresh)..."
set +e
"$WATCHED_BIN"
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -eq 0 ]; then
    echo "PASS: test_brfw_inode_refresh — replaced binary is still allowed after inode update"
    exit 0
elif [ "$EXIT_CODE" -eq 1 ]; then
    echo "FAIL: test_brfw_inode_refresh — replaced binary was blocked (inode refresh did not work)"
    if ! grep -q "Binary updated:" "$BRFW_LOG"; then
        echo "  (inotify event was not received by brfw)"
    fi
    cat "$BRFW_LOG"
    exit 1
else
    echo "FAIL: test_brfw_inode_refresh — unexpected exit code $EXIT_CODE"
    cat "$BRFW_LOG"
    exit 1
fi
