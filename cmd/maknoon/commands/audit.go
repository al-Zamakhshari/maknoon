package commands

import (
	"github.com/spf13/cobra"
)

func AuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Manage and export cryptographic audit logs",
	}

	cmd.AddCommand(auditExportCmd())
	return cmd
}

func auditExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export a forensic summary of all cryptographic operations",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			res, err := GlobalContext.Engine.AuditExport(nil)
			if err != nil {
				p.RenderError(err)
				return err
			}
			p.RenderSuccess(res)
			return nil
		},
	}
	return cmd
}
