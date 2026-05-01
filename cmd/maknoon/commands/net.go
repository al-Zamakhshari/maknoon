package commands

import (
	"github.com/spf13/cobra"
)

func NetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "net",
		Short: "Manage network and P2P connectivity",
	}

	cmd.AddCommand(netStatusCmd())
	return cmd
}

func netStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display P2P network health and tunnel status",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			res, err := GlobalContext.Engine.NetworkStatus(nil)
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
