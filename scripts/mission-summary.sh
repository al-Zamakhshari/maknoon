#!/bin/bash
# mission-summary.sh — reads mission-reports/*.jsonl and prints a pass/fail table.
# Usage: mission-summary.sh [reports-dir]
# Exits 0 if all missions passed, 1 if any failed.

set -euo pipefail

REPORTS_DIR="${1:-./mission-reports}"

if [ ! -d "$REPORTS_DIR" ]; then
    echo "No mission reports directory found at: $REPORTS_DIR"
    exit 1
fi

PASS=0
FAIL=0

printf "%-45s %-6s %s\n" "MISSION" "STATUS" "LAST MESSAGE"
printf '%0.s-' {1..80}; echo

for f in "$REPORTS_DIR"/*.jsonl; do
    [ -f "$f" ] || continue
    name=$(basename "$f" .jsonl)
    last=$(tail -n1 "$f")
    if [ -z "$last" ]; then
        printf "%-45s %-6s %s\n" "$name" "EMPTY" "(no entries)"
        FAIL=$((FAIL + 1))
        continue
    fi
    status=$(printf '%s' "$last" | jq -r '.status' 2>/dev/null || echo "UNKNOWN")
    msg=$(printf '%s' "$last" | jq -r '.message' 2>/dev/null | cut -c1-40 || echo "")
    printf "%-45s %-6s %s\n" "$name" "$status" "$msg"
    if [ "$status" = "PASS" ]; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
    fi
done

printf '%0.s-' {1..80}; echo
echo "Total: $PASS passed, $FAIL failed"

[ "$FAIL" -eq 0 ]
