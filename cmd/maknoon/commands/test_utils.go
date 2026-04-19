package commands

import (
	"bytes"
	"io"
	"os"
)

// CaptureOutput captures the stdout and JSONWriter output of a function.
func CaptureOutput(f func()) string {
	oldStdout := os.Stdout
	oldJSONWriter := JSONWriter

	r, w, _ := os.Pipe()
	os.Stdout = w
	JSONWriter = w

	f()

	if err := w.Close(); err != nil {
		panic(err)
	}
	os.Stdout = oldStdout
	JSONWriter = oldJSONWriter

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		panic(err)
	}
	return buf.String()
}
