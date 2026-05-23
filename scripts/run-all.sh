#!/usr/bin/env bash
# run-all.sh — run all maknoon smoke tests and optionally Docker missions.
#
# Usage:
#   ./scripts/run-all.sh              # local smoke tests only
#   ./scripts/run-all.sh --missions   # smoke tests + Docker missions
#
# Must be run from the project root (where ./maknoon lives).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
RESET='\033[0m'

WITH_MISSIONS=false
for arg in "$@"; do
    case "$arg" in
        --missions) WITH_MISSIONS=true ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

# ── Pre-flight ────────────────────────────────────────────────────────────────

if [ ! -f "./maknoon" ]; then
    echo -e "${RED}✗ ./maknoon binary not found.${RESET}"
    echo "  Build it first:  make build"
    exit 1
fi

echo ""
echo -e "${BOLD}▶ maknoon smoke tests${RESET}"
echo "  binary : $(./maknoon --version 2>&1 | head -1 || echo 'unknown')"
echo "  date   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# ── Run smoke tests ───────────────────────────────────────────────────────────

SMOKE_SCRIPTS=(
    "$SCRIPT_DIR/smoke-audit.sh"
    "$SCRIPT_DIR/smoke-encrypt-decrypt.sh"
    "$SCRIPT_DIR/smoke-fragment-dispersal.sh"
    "$SCRIPT_DIR/smoke-governance.sh"
    "$SCRIPT_DIR/smoke-info.sh"
    "$SCRIPT_DIR/smoke-mcp-sse.sh"
    "$SCRIPT_DIR/smoke-reencrypt.sh"
    "$SCRIPT_DIR/smoke-resilience.sh"
    "$SCRIPT_DIR/smoke-threshold-sig.sh"
    "$SCRIPT_DIR/smoke-tpm.go.sh"
    "$SCRIPT_DIR/smoke-vault-safety.sh"
)

PASSED=0
FAILED=0
declare -a FAILED_NAMES=()

run_test() {
    local script="$1"
    local name
    name=$(basename "$script" .sh)

    if [ ! -f "$script" ]; then
        echo -e "  ${YELLOW}skip${RESET}  $name (not found)"
        return
    fi

    if bash "$script" 2>&1 | sed 's/^/  /'; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        FAILED_NAMES+=("$name")
    fi
}

echo ""
echo -e "${BOLD}── Smoke tests ──────────────────────────────────────────────${RESET}"
for script in "${SMOKE_SCRIPTS[@]}"; do
    run_test "$script"
done

# ── Optionally run Docker missions ────────────────────────────────────────────

if [ "$WITH_MISSIONS" = true ]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo -e "\n${YELLOW}⚠  --missions requested but docker not found — skipping.${RESET}"
    else
        echo ""
        echo -e "${BOLD}── Docker missions ──────────────────────────────────────────${RESET}"
        for mission in \
            "$SCRIPT_DIR/mission-pipeline-verify.sh" \
            "$SCRIPT_DIR/mission-quorum-verify.sh"; do
            run_test "$mission"
        done
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

TOTAL=$((PASSED + FAILED))
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ "$FAILED" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}  ALL $TOTAL tests passed ✓${RESET}"
    exit 0
else
    echo -e "${RED}${BOLD}  $PASSED/$TOTAL passed, $FAILED failed:${RESET}"
    for name in "${FAILED_NAMES[@]}"; do
        echo -e "  ${RED}✗${RESET} $name"
    done
    exit 1
fi
