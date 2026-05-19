package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// ManCmd returns a command to verify or generate per-command man pages.
func ManCmd() *cobra.Command {
	var verify bool
	var generate bool
	var dir string

	cmd := &cobra.Command{
		Use:    "man",
		Short:  "Verify or generate man pages for all commands",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if generate {
				return generateManPages(cmd.Root(), dir)
			}
			if verify {
				return verifyManPages(cmd.Root(), dir)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&verify, "verify", false, "Verify all commands have man page files in --dir")
	cmd.Flags().BoolVar(&generate, "generate", false, "Generate man pages for all commands into --dir")
	cmd.Flags().StringVar(&dir, "dir", "man", "Directory for man page files")
	return cmd
}

func generateManPages(root *cobra.Command, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("cannot create man page directory %q: %w", dir, err)
	}
	header := &doc.GenManHeader{
		Title:   "MAKNOON",
		Section: "1",
		Source:  "Maknoon Post-Quantum Engine",
		Manual:  "Maknoon Manual",
	}
	if err := doc.GenManTree(root, header, dir); err != nil {
		return fmt.Errorf("generating man pages: %w", err)
	}
	fmt.Printf("✅ Man pages written to %s/\n", dir)
	return nil
}

// verifyManPages checks that every available command has a corresponding .1 file.
// It only verifies existence (not content) to avoid timestamp-diff false positives.
// To update content, run: maknoon man --generate --dir man/
func verifyManPages(root *cobra.Command, dir string) error {
	var missing []string
	total := 0

	var check func(c *cobra.Command)
	check = func(c *cobra.Command) {
		if !c.IsAvailableCommand() || c.IsAdditionalHelpTopicCommand() {
			return
		}
		total++
		filename := filepath.Join(dir, strings.ReplaceAll(c.CommandPath(), " ", "-")+".1")
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			missing = append(missing, c.CommandPath())
		}
		for _, sub := range c.Commands() {
			check(sub)
		}
	}

	// Check the root command itself.
	rootFile := filepath.Join(dir, "maknoon.1")
	if _, err := os.Stat(rootFile); os.IsNotExist(err) {
		missing = append(missing, "maknoon")
	}
	total++

	for _, sub := range root.Commands() {
		check(sub)
	}

	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "❌ %d man page(s) missing from %s/ — run: go run ./cmd/maknoon man --generate --dir %s\n",
			len(missing), dir, dir)
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "  missing: %s\n", m)
		}
		return fmt.Errorf("man page verification failed: %d/%d missing", len(missing), total)
	}

	fmt.Printf("✅ All %d man pages present in %s/\n", total, dir)
	return nil
}
