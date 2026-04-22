package commands

import (
	"fmt"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

func ConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage Maknoon configuration (relays, defaults, etc.)",
	}

	cmd.AddCommand(configListCmd())
	cmd.AddCommand(configSetCmd())
	cmd.AddCommand(configInitCmd())

	return cmd
}

func configListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all active configuration settings",
		Run: func(cmd *cobra.Command, args []string) {
			checkJSONMode(cmd)
			conf, _ := crypto.LoadConfig()

			if JSONOutput {
				printJSON(conf)
			} else {
				fmt.Println("Maknoon Configuration:")
				fmt.Printf("  Default Identity: %s\n", conf.DefaultIdentity)
				fmt.Println("  Nostr:")
				fmt.Printf("    Relays: %s\n", strings.Join(conf.Nostr.Relays, ", "))
				fmt.Println("  IPFS:")
				fmt.Printf("    Gateway: %s\n", conf.IPFS.Gateway)
				fmt.Printf("    API:     %s\n", conf.IPFS.Api)
			}
		},
	}
}

func configSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set [key] [value]",
		Short: "Update a configuration setting",
		Long: `Update a configuration setting.
Keys:
  default_identity   - The name of the default identity to use
  nostr.relays       - Comma-separated list of Nostr relays
  ipfs.gateway       - IPFS gateway URL
  ipfs.api           - IPFS API URL`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkJSONMode(cmd)
			conf, _ := crypto.LoadConfig()
			key := args[0]
			val := args[1]

			switch key {
			case "default_identity":
				conf.DefaultIdentity = val
			case "nostr.relays":
				conf.Nostr.Relays = strings.Split(val, ",")
				for i := range conf.Nostr.Relays {
					conf.Nostr.Relays[i] = strings.TrimSpace(conf.Nostr.Relays[i])
				}
			case "ipfs.gateway":
				conf.IPFS.Gateway = val
			case "ipfs.api":
				conf.IPFS.Api = val
			default:
				return fmt.Errorf("unknown configuration key: %s", key)
			}

			if err := conf.Save(); err != nil {
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{"status": "success", "key": key, "value": val})
			} else {
				fmt.Printf("✅ Config updated: %s = %s\n", key, val)
			}
			return nil
		},
	}
}

func configInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize default configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			checkJSONMode(cmd)
			conf := crypto.DefaultConfig()
			if err := conf.Save(); err != nil {
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{"status": "success", "message": "config initialized"})
			} else {
				fmt.Println("✅ Maknoon configuration initialized with defaults.")
			}
			return nil
		},
	}
}
