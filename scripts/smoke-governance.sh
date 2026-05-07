#!/bin/bash
set -e

# Maknoon Governance Smoke Test
# Verifies the Composable Policy Engine and FIPS Enforcement.

TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

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

# 2. FIPS Mode Enforcement (Insecure Tunnel Restriction)
echo "🔍 Task 2: Verifying FIPS Tunnel Enforcement..."
# Attempt to start an insecure tunnel in FIPS mode
if ./maknoon tunnel start --remote @peer --insecure --fips 2>&1 | grep -q "FIPS-140 compliance prohibits unverified/insecure tunnels"; then
    echo "✅ Success: FIPS mode blocked insecure tunnel."
else
    echo "❌ FAILED: FIPS mode allowed insecure tunnel."
    exit 1
fi

# 3. File-Based Policy Enforcement (Capability Restriction)
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

echo "🏆 Mission Accomplished: Governance Engine Verified."
