package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

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

// manPageDate returns a reproducible date for man page generation.
// It reads SOURCE_DATE_EPOCH (standard for reproducible builds) and falls
// back to a fixed project epoch so output is identical across runs.
func manPageDate() *time.Time {
	const projectEpoch = 1704067200 // 2024-01-01 00:00:00 UTC
	epoch := int64(projectEpoch)
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			epoch = n
		}
	}
	t := time.Unix(epoch, 0).UTC()
	return &t
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
		Date:    manPageDate(),
	}
	if err := doc.GenManTree(root, header, dir); err != nil {
		return fmt.Errorf("generating man pages: %w", err)
	}
	fmt.Printf("✅ Man pages written to %s/\n", dir)
	return nil
}

// verifyManPages regenerates man pages to a temp directory and diffs against
// the committed dir. Fails if any file is missing or has different content.
// Uses the same SOURCE_DATE_EPOCH / project-epoch logic as generateManPages
// so output is reproducible across runs and machines.
func verifyManPages(root *cobra.Command, dir string) error {
	tmp, err := os.MkdirTemp("", "maknoon-man-*")
	if err != nil {
		return fmt.Errorf("cannot create temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	if err := generateManPages(root, tmp); err != nil {
		return err
	}

	// Walk generated files and compare against committed dir.
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return err
	}

	var stale, missing []string
	for _, e := range entries {
		name := e.Name()
		committed := filepath.Join(dir, name)
		generated := filepath.Join(tmp, name)

		committedData, err := os.ReadFile(committed)
		if os.IsNotExist(err) {
			missing = append(missing, name)
			continue
		}
		if err != nil {
			return err
		}
		generatedData, _ := os.ReadFile(generated)
		if string(committedData) != string(generatedData) {
			stale = append(stale, name)
		}
	}

	if len(missing)+len(stale) > 0 {
		if len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "❌ %d man page(s) missing:\n", len(missing))
			for _, f := range missing {
				fmt.Fprintf(os.Stderr, "  missing: %s\n", f)
			}
		}
		if len(stale) > 0 {
			fmt.Fprintf(os.Stderr, "❌ %d man page(s) stale:\n", len(stale))
			for _, f := range stale {
				fmt.Fprintf(os.Stderr, "  stale:   %s\n", f)
			}
		}
		fmt.Fprintf(os.Stderr, "\nRun: make man && git add man/\n")
		return fmt.Errorf("man page sync failed: %d missing, %d stale", len(missing), len(stale))
	}

	fmt.Printf("✅ All %d man pages in %s/ are up to date.\n", len(entries), dir)
	return nil
}
