package commands

import (
	"bytes"
	"io"
	"os"
)

// CaptureOutput captures the stdout and UIHandler output of a function.
func CaptureOutput(f func()) string {
	// 1. Swap OS Stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// 2. Setup a Test UI that writes to our pipe
	oldUI := GlobalContext.UI
	GlobalContext.UI = &UIHandler{
		Stdout:      w,
		Stderr:      w,
		Interactive: true, // Allow tests to see "sensitive" info
		JSON:        false,
	}

	// 3. Backup and swap legacy JSONWriter if needed
	oldJSONWriter := GlobalContext.JSONWriter
	GlobalContext.JSONWriter = w

	f()

	// Restore
	w.Close()
	os.Stdout = oldStdout
	GlobalContext.UI = oldUI
	GlobalContext.JSONWriter = oldJSONWriter

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}
