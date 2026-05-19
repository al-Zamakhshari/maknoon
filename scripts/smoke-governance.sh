#!/bin/bash
set -e

# Maknoon Governance Smoke Test
# Verifies the Composable Policy Engine and FIPS Enforcement.

TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

export HOME="$TEST_DIR"

echo "🧪 Starting Mission: Governance Enforcement Verification..."

# 1. FIPS Mode Enforcement (Profile Restriction)
echo "🔍 Task 1: Verifying FIPS Profile Enforcement..."
# Attempt to use a non-compliant profile (e.g., 3: conservative) in FIPS mode
if ./maknoon encrypt - --profile 3 -s "pass" -o "$TEST_DIR/out.makn" --fips <<< "data" 2>&1 | grep -q "FIPS-140 compliance mandates Profile 1"; then
    echo "✅ Success: FIPS mode blocked non-compliant profile."
else
    echo "❌ FAILED: FIPS mode allowed Profile 3."
    exit 1
fi

# 2. File-Based Policy Enforcement (Capability Restriction)
echo "🔍 Task 3: Verifying File-Based Capability Restriction..."
cat > "$TEST_DIR/policy.json" <<EOF
{
  "name": "no-delete-policy",
  "rules": [
    { "type": "capability", "action": "deny", "values": ["vault_delete"] },
    { "type": "capability", "action": "allow", "values": ["vault_read", "vault_write", "protect", "unprotect", "identity", "config", "p2p", "crypto", "audit"] }
  ]
}
EOF

# Attempt to delete a vault with the restriction
if ./maknoon vault delete non-existent --policy "$TEST_DIR/policy.json" --json 2>&1 | grep -q "capability 'vault_delete' is prohibited"; then
    echo "✅ Success: File policy blocked restricted capability."
else
    echo "❌ FAILED: File policy allowed restricted capability."
    exit 1
fi

# 4. File-Based Policy Enforcement (Path Restriction)
echo "🔍 Task 4: Verifying File-Based Path Restriction..."
cat > "$TEST_DIR/path_policy.json" <<EOF
{
  "name": "restricted-path",
  "rules": [
    { "type": "path", "action": "deny", "values": ["secret_area"] },
    { "type": "capability", "action": "allow", "values": ["protect", "unprotect", "vault_read", "vault_write", "vault_delete", "identity", "config", "p2p", "crypto", "audit"] }
  ]
}
EOF

mkdir -p "$TEST_DIR/secret_area"
echo "sensitive" > "$TEST_DIR/secret_area/data.txt"

if ./maknoon encrypt "$TEST_DIR/secret_area/data.txt" -s "pass" --policy "$TEST_DIR/path_policy.json" 2>&1 | grep -q "path access explicitly denied"; then
    echo "✅ Success: File policy blocked restricted path."
else
    echo "❌ FAILED: File policy allowed access to restricted path."
    exit 1
fi

# 5. Composite Policy (Strictest-Wins)
echo "🔍 Task 5: Verifying Composite Policy (Strictest-Wins)..."
# Combine FIPS (blocks Profile 3) with another policy
if ./maknoon encrypt - --profile 3 -s "pass" -o "$TEST_DIR/out_composite.makn" --fips --policy "$TEST_DIR/policy.json" <<< "data" 2>&1 | grep -q "FIPS-140 compliance mandates Profile 1"; then
    echo "✅ Success: Composite policy correctly enforced the strictest rule (FIPS)."
else
    echo "❌ FAILED: Composite policy failed to enforce FIPS restriction when stacked."
    exit 1
fi

# 6. Administrative Quorum Enforcement (Phase 6.3)
echo "🔍 Task 6: Verifying Administrative Quorum Enforcement..."
cat > "$TEST_DIR/quorum_policy.json" <<EOF
{
  "name": "quorum-policy",
  "rules": [
    { "type": "capability", "action": "allow", "values": ["config"] },
    { "type": "quorum", "action": "config_admin", "values": ["threshold:3"] }
  ]
}
EOF

if ./maknoon config set perf.concurrency 4 --policy "$TEST_DIR/quorum_policy.json" 2>&1 | grep -q "administrative quorum required"; then
    echo "✅ Success: Engine mandated quorum for administrative action."
else
    # Check if it fails safely due to missing quorum
    if ./maknoon config set perf.concurrency 4 --policy "$TEST_DIR/quorum_policy.json" 2>&1 | grep -q "administrative quorum failed\|no authorized peers configured"; then
         echo "✅ Success: Engine correctly failed administrative action due to missing quorum."
    else
        echo "❌ FAILED: Engine allowed administrative change without quorum check."
        exit 1
    fi
fi

echo "🏆 Mission Accomplished: Governance Engine Verified."
