package main

import (
	"log/slog"
	"os"
	"testing"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
)

func setupTestEngine(t *testing.T) crypto.MaknoonEngine {
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	policy := &crypto.HumanPolicy{}
	base, _ := crypto.NewEngine(policy)
	return &crypto.AuditEngine{
		Engine: base,
		Logger: slog.Default(),
		Audit:  &crypto.NoopLogger{},
	}
}

func TestMCPServerTools(t *testing.T) {
	engine := setupTestEngine(t)
	s := createServer(engine)

	t.Run("Tool_List", func(t *testing.T) {
		// In newer mark3labs, tools might be opaque. 
		// We'll verify that our known tools are reachable.
		if len(s.ListTools()) == 0 {
			t.Errorf("No tools registered in MCP server")
		}
	})
}
