#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Integration test: in allowlist mode, an unlisted binary's connect() is blocked.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BRFW="$REPO_DIR/src/bin/brfw"
HELPER_SRC="$SCRIPT_DIR/helpers/simple_connect.c"
HELPER_BIN="$SCRIPT_DIR/helpers/simple_connect"
BRFW_PID=""

cleanup() {
    if [ -n "$BRFW_PID" ] && kill -0 "$BRFW_PID" 2>/dev/null; then
        kill "$BRFW_PID" 2>/dev/null || true
        wait "$BRFW_PID" 2>/dev/null || true
    fi
    rm -f "$HELPER_BIN"
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

# --- Run brfw in allowlist mode ---
# Allowlist only /bin/true — simple_connect is NOT listed, so its connect() should be blocked.

echo "  Starting brfw in allowlist mode..."
"$BRFW" -m allowlist -b /bin/true &
BRFW_PID=$!

# Give brfw time to attach BPF programs
sleep 1

if ! kill -0 "$BRFW_PID" 2>/dev/null; then
    echo "FAIL: brfw exited prematurely"
    exit 1
fi

# --- Test: unlisted binary should be blocked ---

echo "  Running simple_connect (should be blocked)..."
set +e
"$HELPER_BIN"
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -eq 1 ]; then
    echo "PASS: test_brfw_allowlist — unlisted binary was blocked (EPERM)"
    exit 0
elif [ "$EXIT_CODE" -eq 0 ]; then
    echo "FAIL: test_brfw_allowlist — connect was allowed (expected EPERM)"
    exit 1
else
    echo "FAIL: test_brfw_allowlist — unexpected exit code $EXIT_CODE"
    exit 1
fi
