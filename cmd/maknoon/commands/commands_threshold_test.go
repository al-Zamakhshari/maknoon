package commands

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCLIThresholdSignatures(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "maknoon-cli-threshold-*")
	defer os.RemoveAll(tmpDir)

	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", oldHome)

	// Reset and Initialize Engine for the new HOME
	ResetGlobalContext()
	if err := InitEngine(); err != nil {
		t.Fatalf("Failed to initialize engine: %v", err)
	}

	// 1. Create 3 identities
	identities := []string{"alpha", "beta", "gamma"}
	for _, id := range identities {
		runCommand(t, KeygenCmd(), "-o", id, "--passphrase", "testpass")
	}

	// 2. Sign a file with each
	missionFile := filepath.Join(tmpDir, "mission.txt")
	os.WriteFile(missionFile, []byte("TOP SECRET MISSION CONTENT"), 0644)

	sigs := make([]string, 3)
	for i, id := range identities {
		sigPath := filepath.Join(tmpDir, fmt.Sprintf("mission.txt.%s.sig", id))
		runCommand(t, SignCmd(), missionFile, "-k", id+".sig.key", "--passphrase", "testpass")
		os.Rename(missionFile+".sig", sigPath)
		sigs[i] = sigPath
	}

	// 3. Aggregate signatures
	multiSigPath := filepath.Join(tmpDir, "multi.sig")
	args := append([]string{sigs[0]}, sigs[1:]...) // aggregate sig1 sig2 ...
	args = append(args, "-o", multiSigPath)
	runCommand(t, AggregateCmd(), args...)

	// 4. Verify with threshold
	// We need public keys. They are in ~/.maknoon/keys/alpha.sig.pub etc.
	pubKeys := make([]string, 3)
	for i, id := range identities {
		pubKeys[i] = id + ".sig.pub"
	}
	pubKeyList := strings.Join(pubKeys, ",")

	t.Run("Verify_3_of_3", func(t *testing.T) {
		output := runCommand(t, VerifyCmd(), missionFile, "--signature", multiSigPath, "--public-key", pubKeyList, "--threshold", "3")
		if !strings.Contains(output, "Verified") {
			t.Errorf("Expected verification success, got: %s", output)
		}
	})

	t.Run("Verify_2_of_3", func(t *testing.T) {
		output := runCommand(t, VerifyCmd(), missionFile, "--signature", multiSigPath, "--public-key", pubKeyList, "--threshold", "2")
		if !strings.Contains(output, "Verified") {
			t.Errorf("Expected verification success, got: %s", output)
		}
	})

	t.Run("Verify_Fail_Threshold", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected 4-of-3 to fail but it passed")
			}
		}()
		runCommand(t, VerifyCmd(), missionFile, "--signature", multiSigPath, "--public-key", pubKeyList, "--threshold", "4")
	})
}

func runCommand(t *testing.T, cmd *cobra.Command, args ...string) string {
	t.Helper()
	var buf bytes.Buffer

	// Setup UI for testing
	oldUI := GlobalContext.UI
	defer func() { GlobalContext.UI = oldUI }()

	GlobalContext.UI = &UIHandler{
		Stdout: &buf,
		Stderr: &buf,
	}

	cmd.SetArgs(args)
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := cmd.Execute()
	if err != nil {
		panic(fmt.Sprintf("Command %s failed: %v\nOutput: %s", cmd.Name(), err, buf.String()))
	}

	return buf.String()
}
