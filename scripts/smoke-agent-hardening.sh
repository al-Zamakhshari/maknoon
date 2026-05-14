#!/bin/bash
set -e

# Maknoon Industrial Smoke Suite: Agent Hardening & Auditing
# Verifies Workspace Auditing and Vault Blob logic via Engine integration.

echo "🧪 Starting Mission: Agent Hardening & Auditing Verification..."

# Setup clean environment
TEST_DIR=$(mktemp -d)
export HOME=$TEST_DIR
mkdir -p $HOME/.maknoon/keys
mkdir -p $HOME/.maknoon/vaults

export MAKNOON_PASSPHRASE="agent-smoke-pass"
export MAKNOON_AUDIT_ENABLED="true"
export MAKNOON_AUDIT_LOG_FILE="${TEST_DIR}/agent_audit.log"

echo "🔍 Task 1: Verifying Workspace Auditing..."

# We use a small Go script to trigger the workspace creation and shredding
# since we don't have a direct CLI for it yet, and we want to verify the AuditEngine wrapper.
cat << EOF > "${TEST_DIR}/verify_workspace.go"
package main

import (
	"context"
	"fmt"
	"os"
	"github.com/al-Zamakhshari/maknoon/cmd/maknoon/commands"
	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
)

func main() {
	os.Setenv("MAKNOON_PASSPHRASE", "agent-smoke-pass")
	if err := commands.InitEngine(); err != nil {
		fmt.Printf("InitEngine failed: %v\n", err)
		os.Exit(1)
	}
	engine := commands.GlobalContext.Engine
	ectx := &crypto.EngineContext{Context: context.Background()}

	path, err := engine.WorkspaceCreate(ectx, "smoke_session")
	if err != nil {
		fmt.Printf("WorkspaceCreate failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Created: %s\n", path)

	if err := engine.WorkspaceShred(ectx, path); err != nil {
		fmt.Printf("WorkspaceShred failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Shredded successfully")
}
EOF

go run "${TEST_DIR}/verify_workspace.go"

echo "📜 Checking Audit Log for Workspace Events..."
if grep -q "workspace_create" "${MAKNOON_AUDIT_LOG_FILE}" && grep -q "workspace_shred" "${MAKNOON_AUDIT_LOG_FILE}"; then
    echo "✅ Success: Workspace events correctly audited."
else
    echo "❌ Failure: Workspace events missing from audit log."
    cat "${MAKNOON_AUDIT_LOG_FILE}"
    exit 1
fi

echo "🔍 Task 2: Verifying Vault Blob (Agent Memory) Auditing..."
# We can use the vault_set mcp tool logic via our helper
cat << EOF > "${TEST_DIR}/verify_blob.go"
package main

import (
	"fmt"
	"os"
	"github.com/al-Zamakhshari/maknoon/cmd/maknoon/commands"
	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
)

func main() {
	os.Setenv("MAKNOON_PASSPHRASE", "agent-smoke-pass")
	commands.InitEngine()
	engine := commands.GlobalContext.Engine

	entry := &crypto.VaultEntry{
		Service: "agent_context",
		Blob: []byte("agent-state-data"),
	}
	err := engine.VaultSet(nil, "agent_memory", entry, []byte("agent-smoke-pass"), "", true)
	if err != nil {
		fmt.Printf("VaultSet failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Blob stored")
}
EOF

go run "${TEST_DIR}/verify_blob.go"

echo "📜 Checking Audit Log for Vault Blob Events..."
if grep -q "vault_set" "${MAKNOON_AUDIT_LOG_FILE}" && grep -q "agent_memory" "${MAKNOON_AUDIT_LOG_FILE}"; then
    echo "✅ Success: Vault Blob events correctly audited."
else
    echo "❌ Failure: Vault Blob events missing from audit log."
    cat "${MAKNOON_AUDIT_LOG_FILE}"
    exit 1
fi

echo "🏆 Mission Accomplished: Agent Hardening & Auditing Verified."
chmod -R +w "$TEST_DIR"
rm -rf "$TEST_DIR"
exit 0
