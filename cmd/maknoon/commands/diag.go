package commands

import (
	"github.com/spf13/cobra"
)

func DiagCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diag",
		Short: "Output a machine-readable engine state manifest",
		Long:  "Generates a JSON manifest containing system information, filesystem paths, active security policies, and cryptographic defaults.",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()

			// Gather diagnostic data from the engine
			res := GlobalContext.Engine.Diagnostic()

			// Always output as JSON if requested, otherwise pretty-print the manifest
			p.RenderSuccess(res)
			return nil
		},
	}

	return cmd
}
