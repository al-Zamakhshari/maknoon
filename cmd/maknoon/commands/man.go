package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// ManCmd returns a command to verify or generate the man page integrity.
func ManCmd() *cobra.Command {
	var verify bool
	var generate bool

	cmd := &cobra.Command{
		Use:    "man",
		Short:  "Verify or generate the man page",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if verify {
				return verifyManPage(cmd.Root())
			}
			if generate {
				header := &doc.GenManHeader{
					Title:   "MAKNOON",
					Section: "1",
					Source:  "Maknoon Post-Quantum Engine",
					Manual:  "Maknoon Manual",
				}
				err := doc.GenMan(cmd.Root(), header, os.Stdout)
				if err != nil {
					return err
				}
				return nil
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&verify, "verify", false, "Verify that the man page is up to date with the CLI structure")
	cmd.Flags().BoolVar(&generate, "generate", false, "Generate the man page to stdout")
	return cmd
}

func verifyManPage(root *cobra.Command) error {
	manPath := "maknoon.1"
	content, err := os.ReadFile(manPath)
	if err != nil {
		return fmt.Errorf("failed to read man page: %w", err)
	}

	manContent := string(content)
	missing := []string{}

	// Helper to check command
	checkCmd := func(c *cobra.Command, depth int) {
		if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
			return
		}

		// Only check top-level commands (depth 1) for the main man page
		if depth == 1 {
			searchStr := "maknoon-" + c.Name()
			if !strings.Contains(manContent, searchStr) {
				missing = append(missing, c.CommandPath())
			}
		}

		// We don't recurse for verification if we only care about top-level in one file
	}

	// We start from the commands added to root
	for _, sub := range root.Commands() {
		checkCmd(sub, 1)
	}

	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "❌ Man page out of sync! The following commands are missing from %s:\n", manPath)
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "  - %s\n", m)
		}
		return fmt.Errorf("man page verification failed")
	}

	fmt.Println("✅ Man page is up to date.")
	return nil
}
