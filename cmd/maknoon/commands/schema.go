package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// CommandSchema defines the structure of a CLI command for AI consumption.
type CommandSchema struct {
	Name        string           `json:"name"`
	Path        string           `json:"path"`
	Description string           `json:"description"`
	Arguments   []ArgumentSchema `json:"arguments"`
	Flags       []FlagSchema     `json:"flags"`
	Subcommands []CommandSchema  `json:"subcommands,omitempty"`
}

type ArgumentSchema struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}

type FlagSchema struct {
	Name        string `json:"name"`
	Shorthand   string `json:"shorthand"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Default     string `json:"default"`
	Required    bool   `json:"required"`
}

func SchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "schema",
		Short: "Output the JSON Schema of all commands for AI Agent consumption",
		Run: func(cmd *cobra.Command, args []string) {
			root := cmd.Root()
			schemas := []CommandSchema{}

			for _, sub := range root.Commands() {
				if sub.Name() == "schema" || sub.Name() == "help" || sub.Name() == "completion" {
					continue
				}
				schemas = append(schemas, generateSchema(sub))
			}

			data, _ := json.MarshalIndent(schemas, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
		},
	}
}

func generateSchema(cmd *cobra.Command) CommandSchema {
	s := CommandSchema{
		Name:        cmd.Name(),
		Path:        cmd.CommandPath(),
		Description: cmd.Short,
	}

	// Parse Arguments from 'Use' string (e.g. "encrypt [file/dir]")
	parts := strings.Split(cmd.Use, " ")
	if len(parts) > 1 {
		for _, p := range parts[1:] {
			if strings.HasPrefix(p, "[") && strings.HasSuffix(p, "]") {
				s.Arguments = append(s.Arguments, ArgumentSchema{
					Name:     strings.Trim(p, "[]"),
					Required: false,
				})
			} else if strings.HasPrefix(p, "<") && strings.HasSuffix(p, ">") {
				s.Arguments = append(s.Arguments, ArgumentSchema{
					Name:     strings.Trim(p, "<>"),
					Required: true,
				})
			} else if !strings.HasPrefix(p, "-") {
				s.Arguments = append(s.Arguments, ArgumentSchema{
					Name:     p,
					Required: true,
				})
			}
		}
	}

	// Parse Flags
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Skip global flags to avoid noise in every command
		if f.Name == "help" || f.Name == "json" {
			return
		}

		required := false
		if annot, ok := f.Annotations[cobra.BashCompOneRequiredFlag]; ok && len(annot) > 0 && annot[0] == "true" {
			required = true
		}

		s.Flags = append(s.Flags, FlagSchema{
			Name:        f.Name,
			Shorthand:   f.Shorthand,
			Description: f.Usage,
			Type:        f.Value.Type(),
			Default:     f.DefValue,
			Required:    required,
		})
	})

	// Recurse into Subcommands
	for _, sub := range cmd.Commands() {
		if sub.Name() == "help" {
			continue
		}
		s.Subcommands = append(s.Subcommands, generateSchema(sub))
	}

	return s
}
