#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Run all test_*.sh scripts and report results.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

passed=0
failed=0
skipped=0

for test_script in "$SCRIPT_DIR"/test_*.sh; do
    [ -f "$test_script" ] || continue
    name="$(basename "$test_script" .sh)"
    echo "--- $name ---"

    output=$("$test_script" 2>&1)
    rc=$?
    echo "$output"

    if echo "$output" | grep -q "^SKIP:"; then
        skipped=$((skipped + 1))
    elif [ "$rc" -eq 0 ]; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi
    echo ""
done

echo "=== Results: $passed passed, $failed failed, $skipped skipped ==="

if [ "$failed" -gt 0 ]; then
    exit 1
fi
exit 0
