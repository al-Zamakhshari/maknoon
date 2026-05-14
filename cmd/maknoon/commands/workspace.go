package commands

import (
	"github.com/spf13/cobra"
)

// WorkspaceCmd returns the root command for ephemeral workspace operations.
func WorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "workspace",
		Short: "Manage ephemeral, forensically-audited sandbox environments",
		Long:  `Create and shred temporary directories for secure processing. On Linux, these utilize RAM-disks (/dev/shm) when available.`,
	}

	cmd.AddCommand(workspaceCreateCmd())
	cmd.AddCommand(workspaceShredCmd())

	return cmd
}

func workspaceCreateCmd() *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new ephemeral workspace",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitEngine(); err != nil {
				return err
			}

			path, err := GlobalContext.Engine.WorkspaceCreate(nil, name)
			if err != nil {
				return err
			}

			p := GlobalContext.UI.GetPresenter()
			res := map[string]string{
				"status": "success",
				"path":   path,
				"action": "workspace_create",
			}
			p.RenderSuccess(res)
			return nil
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "session", "Logical name for the workspace")
	return cmd
}

func workspaceShredCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shred [path]",
		Short: "Securely delete and zeroize an ephemeral workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitEngine(); err != nil {
				return err
			}

			path := args[0]
			err := GlobalContext.Engine.WorkspaceShred(nil, path)
			if err != nil {
				return err
			}

			p := GlobalContext.UI.GetPresenter()
			res := map[string]string{
				"status": "success",
				"path":   path,
				"action": "workspace_shred",
			}
			p.RenderSuccess(res)
			return nil
		},
	}

	return cmd
}
