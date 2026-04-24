package commands

import (
	"bytes"
	"strings"
	"testing"
)

func TestSecurePrintScenarios(t *testing.T) {
	tests := []struct {
		name        string
		jsonMode    bool
		interactive bool
		wantStdout  string
		wantStderr  string
	}{
		{
			name:        "Accidental Leak (Non-Interactive, No JSON)",
			jsonMode:    false,
			interactive: false,
			wantStdout:  "",
			wantStderr:  "Warning: Sensitive output suppressed",
		},
		{
			name:        "Agent Mode (JSON active)",
			jsonMode:    true,
			interactive: false,
			wantStdout:  "", // SecurePrint does nothing in JSON mode
			wantStderr:  "",
		},
		{
			name:        "Interactive Session",
			jsonMode:    false,
			interactive: true,
			wantStdout:  "my-secret",
			wantStderr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			
			handler := &UIHandler{
				Stdout:      &outBuf,
				Stderr:      &errBuf,
				Interactive: tt.interactive,
				JSON:        tt.jsonMode,
			}

			handler.SecurePrint("my-secret")

			if tt.wantStdout != "" && !strings.Contains(outBuf.String(), tt.wantStdout) {
				t.Errorf("Expected stdout containing %q, got %q", tt.wantStdout, outBuf.String())
			}
			if tt.wantStdout == "" && outBuf.Len() > 0 {
				t.Errorf("Expected empty stdout, got %q", outBuf.String())
			}
			if tt.wantStderr != "" && !strings.Contains(errBuf.String(), tt.wantStderr) {
				t.Errorf("Expected stderr containing %q, got %q", tt.wantStderr, errBuf.String())
			}
		})
	}
}
