package commands

import (
	"fmt"
	"strings"
	"time"

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
	var filterAction string
	var filterStatus string
	var filterFrom string
	var filterTo string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export cryptographic audit log entries, with optional filtering",
		Long: `Export the forensic audit log. Filters are ANDed together.

Examples:
  maknoon audit export
  maknoon audit export --action vault_get --status failure
  maknoon audit export --from 2026-01-01T00:00:00Z --to 2026-06-01T00:00:00Z`,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			entries, err := GlobalContext.Engine.AuditExport(nil)
			if err != nil {
				p.RenderError(err)
				return err
			}

			// Parse optional time bounds.
			var fromTime, toTime time.Time
			if filterFrom != "" {
				fromTime, err = time.Parse(time.RFC3339, filterFrom)
				if err != nil {
					return fmt.Errorf("--from: invalid RFC3339 time: %w", err)
				}
			}
			if filterTo != "" {
				toTime, err = time.Parse(time.RFC3339, filterTo)
				if err != nil {
					return fmt.Errorf("--to: invalid RFC3339 time: %w", err)
				}
			}

			// Apply filters.
			filtered := entries[:0]
			for _, e := range entries {
				if filterAction != "" && !strings.EqualFold(e.Action, filterAction) {
					continue
				}
				if filterStatus != "" && !strings.EqualFold(e.Status, filterStatus) {
					continue
				}
				if !fromTime.IsZero() {
					t, _ := time.Parse(time.RFC3339, e.Timestamp)
					if t.Before(fromTime) {
						continue
					}
				}
				if !toTime.IsZero() {
					t, _ := time.Parse(time.RFC3339, e.Timestamp)
					if t.After(toTime) {
						continue
					}
				}
				filtered = append(filtered, e)
			}

			p.RenderSuccess(filtered)
			return nil
		},
	}

	cmd.Flags().StringVar(&filterAction, "action", "", "Filter by action name (e.g. protect, vault_get, identity_info)")
	cmd.Flags().StringVar(&filterStatus, "status", "", "Filter by status: success or failure")
	cmd.Flags().StringVar(&filterFrom, "from", "", "Include entries at or after this RFC3339 timestamp")
	cmd.Flags().StringVar(&filterTo, "to", "", "Include entries at or before this RFC3339 timestamp")
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
