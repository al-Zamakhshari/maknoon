#!/usr/bin/env bash
# lib.sh — shared helpers for maknoon smoke tests
# Source this file; do NOT execute it directly.
# Designed for local smoke tests (not Docker missions — those use common.sh).

# ── Counters ──────────────────────────────────────────────────────────────────
PASS=0
FAIL=0

# ── Formatting ────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

mission_start() {
    echo ""
    echo -e "${BOLD}━━━ $1 ━━━${RESET}"
}

pass() {
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}✓${RESET} $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}✗${RESET} $1"
}

mission_end() {
    local total=$((PASS + FAIL))
    echo ""
    if [ "$FAIL" -eq 0 ]; then
        echo -e "  ${GREEN}${BOLD}$PASS/$total passed${RESET}"
        return 0
    else
        echo -e "  ${RED}${BOLD}$PASS/$total passed, $FAIL failed${RESET}"
        return 1
    fi
}

# ── Assertions ────────────────────────────────────────────────────────────────

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        pass "$label"
    else
        fail "$label (expected: '$expected', got: '$actual')"
    fi
}

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        pass "$label"
    else
        fail "$label (expected to contain: '$needle')"
    fi
}

assert_not_contains() {
    local label="$1" needle="$2" haystack="$3"
    if ! echo "$haystack" | grep -qF "$needle"; then
        pass "$label"
    else
        fail "$label (expected NOT to contain: '$needle')"
    fi
}

assert_exits_nonzero() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        fail "$label (expected non-zero exit, got 0)"
    else
        pass "$label"
    fi
}

assert_exits_zero() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        pass "$label"
    else
        fail "$label (expected exit 0, command failed)"
    fi
}

assert_file_exists() {
    local label="$1" path="$2"
    if [ -f "$path" ]; then
        pass "$label"
    else
        fail "$label (file not found: '$path')"
    fi
}

assert_hashes_equal() {
    local label="$1" file_a="$2" file_b="$3"
    local hash_a hash_b
    hash_a=$(sha256sum "$file_a" | awk '{print $1}')
    hash_b=$(sha256sum "$file_b" | awk '{print $1}')
    if [ "$hash_a" = "$hash_b" ]; then
        pass "$label"
    else
        fail "$label (SHA-256 mismatch: $hash_a vs $hash_b)"
    fi
}

# assert_json_field LABEL FILE JQPATH EXPECTED
assert_json_field() {
    local label="$1" file="$2" jqpath="$3" expected="$4"
    local actual
    actual=$(jq -r "$jqpath" "$file" 2>/dev/null || echo "JQ_ERROR")
    assert_eq "$label" "$expected" "$actual"
}

# assert_json_output LABEL JSON JQPATH EXPECTED
assert_json_output() {
    local label="$1" json="$2" jqpath="$3" expected="$4"
    local actual
    actual=$(printf '%s' "$json" | jq -r "$jqpath" 2>/dev/null || echo "JQ_ERROR")
    assert_eq "$label" "$expected" "$actual"
}
