package commands

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestSecurePrintScenarios(t *testing.T) {
	// Setup: Save original env and reset
	origTestEnv := os.Getenv("GO_TEST")
	os.Unsetenv("GO_TEST")
	defer os.Setenv("GO_TEST", origTestEnv)

	tests := []struct {
		name       string
		jsonMode   bool
		envTest    string
		wantStdout string
		wantStderr string
	}{
		{
			name:       "Accidental Leak (Non-TTY, No JSON)",
			jsonMode:   false,
			envTest:    "",
			wantStdout: "",
			wantStderr: "Warning: Sensitive output suppressed",
		},
		{
			name:       "Agent Mode (Headless but JSON active)",
			jsonMode:   true,
			envTest:    "",
			wantStdout: "", // SecurePrint does nothing in JSON mode (it delegates to printJSON which we aren't calling here)
			wantStderr: "",
		},
		{
			name:       "Existing Test Capture (GO_TEST=1)",
			jsonMode:   false,
			envTest:    "1",
			wantStdout: "my-secret",
			wantStderr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock environment
			if tt.envTest != "" {
				os.Setenv("GO_TEST", tt.envTest)
			} else {
				os.Unsetenv("GO_TEST")
			}

			// Capture stdout/stderr
			JSONOutput = tt.jsonMode

			// We use a pipe for stdout in tests, so term.IsTerminal will always be false
			// which is perfect for testing the "Accidental Leak" scenario.

			var outBuf, errBuf bytes.Buffer
			// Note: fmt.Println/Printf use os.Stdout/os.Stderr directly.
			// To test SecurePrint, we need to temporarily swap them.
			oldOut := os.Stdout
			oldErr := os.Stderr
			r, w, _ := os.Pipe()
			re, we, _ := os.Pipe()
			os.Stdout = w
			os.Stderr = we

			SecurePrint("my-secret")

			w.Close()
			we.Close()
			outBuf.ReadFrom(r)
			errBuf.ReadFrom(re)

			os.Stdout = oldOut
			os.Stderr = oldErr

			if tt.wantStdout != "" && !strings.Contains(outBuf.String(), tt.wantStdout) {
				t.Errorf("Expected stdout containing %q, got %q", tt.wantStdout, outBuf.String())
			}
			if tt.wantStdout == "" && outBuf.Len() > 0 && !tt.jsonMode {
				t.Errorf("Expected empty stdout, got %q", outBuf.String())
			}
			if tt.wantStderr != "" && !strings.Contains(errBuf.String(), tt.wantStderr) {
				t.Errorf("Expected stderr containing %q, got %q", tt.wantStderr, errBuf.String())
			}
		})
	}
}
