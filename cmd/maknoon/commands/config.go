package commands

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

func ConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage Maknoon configuration (relays, security, performance)",
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
				fmt.Printf("  Default Identity:   %s\n", conf.DefaultIdentity)
				fmt.Println("  Security (KDF):")
				fmt.Printf("    Argon2 Time:      %d\n", conf.Security.ArgonTime)
				fmt.Printf("    Argon2 Memory:    %d KB\n", conf.Security.ArgonMemory)
				fmt.Printf("    Argon2 Threads:   %d\n", conf.Security.ArgonThreads)
				fmt.Println("  Performance:")
				fmt.Printf("    Concurrency:      %d (0=auto)\n", conf.Performance.Concurrency)
				fmt.Printf("    Zstd Level:       %d\n", conf.Performance.CompressionLevel)
				fmt.Printf("    Default Stealth:  %v\n", conf.Performance.DefaultStealth)
				fmt.Println("  Nostr:")
				fmt.Printf("    Relays:           %s\n", strings.Join(conf.Nostr.Relays, ", "))
				fmt.Printf("    Publish Metadata: %v\n", conf.Nostr.PublishMetadata)
				fmt.Println("  Paths:")
				fmt.Printf("    Keys:             %s\n", conf.Paths.KeysDir)
				fmt.Printf("    Vaults:           %s\n", conf.Paths.VaultsDir)
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
  default_identity   - Default identity name
  security.time      - Argon2id iterations
  security.memory    - Argon2id memory (KB)
  security.threads   - Argon2id threads
  perf.concurrency   - Default parallel workers
  perf.stealth       - Default stealth mode (true/false)
  nostr.relays       - Comma-separated list of Nostr relays
  nostr.metadata     - Toggle publishing Maknoon info in about field (true/false)
  paths.keys         - Custom keys directory
  paths.vaults       - Custom vaults directory`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkJSONMode(cmd)
			conf, _ := crypto.LoadConfig()
			key := args[0]
			val := args[1]

			switch key {
			case "default_identity":
				conf.DefaultIdentity = val
			case "security.time":
				v, _ := strconv.ParseUint(val, 10, 32)
				conf.Security.ArgonTime = uint32(v)
			case "security.memory":
				v, _ := strconv.ParseUint(val, 10, 32)
				conf.Security.ArgonMemory = uint32(v)
			case "security.threads":
				v, _ := strconv.ParseUint(val, 10, 8)
				conf.Security.ArgonThreads = uint8(v)
			case "perf.concurrency":
				v, _ := strconv.Atoi(val)
				conf.Performance.Concurrency = v
			case "perf.stealth":
				conf.Performance.DefaultStealth = (val == "true")
			case "nostr.relays":
				conf.Nostr.Relays = strings.Split(val, ",")
				for i := range conf.Nostr.Relays {
					conf.Nostr.Relays[i] = strings.TrimSpace(conf.Nostr.Relays[i])
				}
			case "nostr.metadata":
				conf.Nostr.PublishMetadata = (val == "true")
			case "paths.keys":
				conf.Paths.KeysDir = val
			case "paths.vaults":
				conf.Paths.VaultsDir = val
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
