package commands

import (
	"fmt"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

func AuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Manage and export cryptographic audit logs",
	}

	cmd.AddCommand(auditExportCmd())
	cmd.AddCommand(auditVerifyCmd())
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

func auditVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the hash-chain integrity of the audit log (detect tampering)",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			conf := GlobalContext.Engine.GetConfig()
			logPath := conf.Audit.LogFile
			if logPath == "" {
				err := fmt.Errorf("audit log path not configured (set audit.logfile in config)")
				p.RenderError(err)
				return err
			}

			entries, _ := GlobalContext.Engine.AuditExport(nil)
			chainErr := crypto.VerifyChain(logPath)

			res := map[string]any{
				"valid":           chainErr == nil,
				"entries_checked": len(entries),
				"log_path":        logPath,
			}
			if chainErr != nil {
				res["error"] = chainErr.Error()
				p.RenderError(fmt.Errorf("chain integrity check FAILED: %w", chainErr))
				p.RenderSuccess(res)
				return chainErr
			}
			p.RenderSuccess(res)
			return nil
		},
	}
	return cmd
}
