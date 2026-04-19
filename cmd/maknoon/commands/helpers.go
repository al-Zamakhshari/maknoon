package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
)

// Context encapsulates the execution state of the Maknoon CLI.
type Context struct {
	JSONOutput bool
	JSONWriter io.Writer
}

// GlobalContext is the default context for CLI execution.
var GlobalContext = &Context{
	JSONWriter: os.Stdout,
}

// printJSON outputs an interface as a JSON string to the context's writer.
func (c *Context) printJSON(v interface{}) {
	raw, _ := json.Marshal(v)
	fmt.Fprintln(c.JSONWriter, string(raw))
}

// printErrorJSON outputs an error as a JSON object to stderr.
func (c *Context) printErrorJSON(err error) {
	raw, _ := json.Marshal(map[string]string{"error": err.Error()})
	fmt.Fprintln(os.Stderr, string(raw))
}

// printJSON outputs an interface using the GlobalContext.
func printJSON(v interface{}) {
	GlobalContext.printJSON(v)
}

// printErrorJSON outputs an error using the GlobalContext.
func printErrorJSON(err error) {
	GlobalContext.printErrorJSON(err)
}

// JSONOutput is kept as a global shim for now, but will be phased out.
var JSONOutput bool = false

// JSONWriter is kept as a global shim for now.
var JSONWriter io.Writer = os.Stdout

// resolveKeyPath checks if a key exists locally, in ~/.maknoon/keys/, or in environment variables.
func resolveKeyPath(path string, envVar string) string {
	return crypto.ResolveKeyPath(path, envVar)
}

// SetJSONOutput enables or disables JSON mode across the application.
func SetJSONOutput(enabled bool) {
	JSONOutput = enabled
	GlobalContext.JSONOutput = enabled
}

// validatePath ensures a path is safe to use.
// In JSON mode, it restricts all file operations to the user's home directory.
func validatePath(path string) error {
	// If NOT in JSON/Agent mode, we allow all paths (traditional CLI behavior)
	if !JSONOutput {
		return nil
	}
	return crypto.ValidatePath(path, true)
}
