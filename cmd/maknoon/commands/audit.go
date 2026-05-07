package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

func AuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Manage and export cryptographic audit logs",
	}

	cmd.AddCommand(auditExportCmd())
	cmd.AddCommand(auditEnrollCmd())
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

func auditEnrollCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Bind audit log integrity to a physical security key (FIDO2)",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()

			fmt.Println("🛡️  Industrial Hardening: Preparing FIDO2 enrollment for Audit Forensic Signing...")
			fmt.Println("👉 Please tap your Security Key when prompted.")

			pin, _ := getPIN()
			meta, _, err := crypto.Fido2Enroll("maknoon-audit", "audit-forensics", pin)
			if err != nil {
				p.RenderError(err)
				return err
			}

			home := crypto.GetUserHomeDir()
			fidoPath := filepath.Join(home, crypto.MaknoonDir, "audit_fido.json")

			data, _ := json.MarshalIndent(meta, "", "  ")
			if err := os.WriteFile(fidoPath, data, 0600); err != nil {
				p.RenderError(err)
				return err
			}

			// Automatically enable hardware signing in config
			conf := crypto.GetGlobalConfig()
			conf.Audit.HardwareSigning = true
			conf.Audit.Enabled = true
			_ = conf.Save()

			fmt.Printf("✅ Audit enrollment successful. Metadata saved to: %s\n", fidoPath)
			fmt.Println("🚀 Industrial forensic signing is now ACTIVE.")
			return nil
		},
	}
	return cmd
}
