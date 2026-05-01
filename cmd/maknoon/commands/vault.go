package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var vaultName string
var vaultPassphrase string
var useFido2 bool

// VaultCmd returns the cobra command for managing secure vaults.
func VaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage secure password vaults",
	}

	cmd.PersistentFlags().StringVarP(&vaultName, "vault", "v", "default", "Name or full path of the vault to use")
	cmd.PersistentFlags().StringVarP(&vaultPassphrase, "passphrase", "s", "", "Master passphrase for the vault")
	cmd.PersistentFlags().BoolVarP(&useFido2, "fido2", "f", false, "Use FIDO2 security key for authentication")
	cmd.PersistentFlags().BoolVar(&JSONOutput, "json", false, "Output results in JSON format")

	_ = cmd.RegisterFlagCompletionFunc("vault", completeVaults)

	cmd.AddCommand(vaultSetCmd())
	cmd.AddCommand(vaultGetCmd())
	cmd.AddCommand(vaultListCmd())
	cmd.AddCommand(vaultRenameCmd())
	cmd.AddCommand(vaultDeleteCmd())
	cmd.AddCommand(vaultSplitCmd())
	cmd.AddCommand(vaultRecoverCmd())

	return cmd
}

func vaultSplitCmd() *cobra.Command {
	var threshold, shares int
	cmd := &cobra.Command{
		Use:   "split",
		Short: "Shard the vault's master access key",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := GlobalContext.UI.GetPresenter()

			// Get the raw passphrase used for the vault
			var pass []byte
			var err error
			if vaultPassphrase != "" {
				pass = []byte(vaultPassphrase)
			} else {
				pass, _, err = getPassphrase("Enter Vault Master Passphrase to shard: ")
				if err != nil {
					p.RenderError(err)
					return err
				}
			}
			defer crypto.SafeClear(pass)

			// Resolve vault path
			path, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return err
			}

			shards, err := GlobalContext.Engine.VaultSplit(nil, path, threshold, shares, string(pass))
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(crypto.VaultResult{
					Vault:     vaultName,
					Threshold: threshold,
					Shares:    shards,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("🛡️  Vault '%s' access sharded into %d parts (Threshold: %d)", vaultName, shares, threshold))
				p.RenderMessage("CRITICAL: These shards represent the derived MASTER KEY. Keep them safe.")
				for i, s := range shards {
					p.RenderMessage(fmt.Sprintf("\nShare %d:\n%s", i+1, s))
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&threshold, "threshold", "m", 2, "Minimum shares required for reconstruction")
	cmd.Flags().IntVarP(&shares, "shares", "n", 3, "Total number of shares to generate")
	return cmd
}

func vaultRecoverCmd() *cobra.Command {
	var targetPath string
	cmd := &cobra.Command{
		Use:   "recover [shards...]",
		Short: "Recover vault contents using shards and optionally save to a new vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			if len(args) == 0 {
				err := fmt.Errorf("at least one shard mnemonic is required")
				p.RenderError(err)
				return err
			}

			// Resolve vault path
			path, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return err
			}

			passphrase, err := GlobalContext.Engine.VaultRecover(nil, args, path, targetPath, "")
			if err != nil {
				p.RenderError(err)
				return err
			}

			if targetPath != "" {
				p.RenderSuccess(crypto.VaultResult{
					Status: "success",
					Secret: passphrase,
					Output: targetPath,
				})
			} else {
				// Re-verify with recovered passphrase to list entries
				entries, err := GlobalContext.Engine.VaultList(nil, path, []byte(passphrase))
				if err != nil {
					p.RenderError(err)
					return err
				}

				if GlobalContext.UI.JSON {
					p.RenderSuccess(map[string]any{
						"secret":  passphrase,
						"entries": entries,
					})
				} else {
					p.RenderMessage(fmt.Sprintf("🛡️  Recovered %d entries from vault '%s':", len(entries), vaultName))
					for _, e := range entries {
						p.RenderMessage(fmt.Sprintf("  - %s (User: %s)", e.Service, e.Username))
					}
				}
			}

			return nil
		},
	}
	cmd.Flags().StringVarP(&targetPath, "output", "o", "", "Path to save recovered entries as a new vault")
	return cmd
}

func resolveVaultPath(name string) (string, error) {
	home := crypto.GetUserHomeDir()
	defaultDir := filepath.Join(home, crypto.MaknoonDir, crypto.VaultsDir)

	if strings.Contains(name, string(os.PathSeparator)) {
		if err := validatePath(name); err != nil {
			return "", err
		}
		return name, nil
	}
	return filepath.Join(defaultDir, name+".vault"), nil
}

func vaultSetCmd() *cobra.Command {
	var user, note string
	var overwrite bool
	cmd := &cobra.Command{
		Use:               "set [service]",
		Short:             "Store a secret in the vault",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeServices,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			service := args[0]
			var password []byte
			var err error

			if env := viper.GetString("password"); env != "" {
				password = []byte(env)
			} else {
				password, _, err = getPassphrase(fmt.Sprintf("Enter password for %s: ", service))
				if err != nil {
					p.RenderError(err)
					return err
				}
			}
			defer crypto.SafeClear(password)

			// Resolve vault path
			path, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return err
			}

			// Get vault passphrase (reusing existing logic if needed)
			// But wait, Engine.VaultSet takes raw passphrase.
			// I need to open the vault or at least get the passphrase.
			// Let's use a simpler approach: prompt for vault pass if not provided.
			var vPass []byte
			if vaultPassphrase != "" {
				vPass = []byte(vaultPassphrase)
			} else {
				vPass, _, err = getPassphrase("Enter Vault Master Passphrase: ")
				if err != nil {
					p.RenderError(err)
					return err
				}
			}
			defer crypto.SafeClear(vPass)

			entry := &crypto.VaultEntry{Service: service, Username: user, Password: password, Note: note}
			err = GlobalContext.Engine.VaultSet(nil, path, entry, vPass, "", overwrite)
			if err != nil {
				p.RenderError(err)
				return err
			}

			p.RenderSuccess(crypto.VaultResult{
				Status:  "success",
				Service: service,
			})
			return nil
		},
	}
	cmd.Flags().StringVarP(&user, "user", "u", "", "Username")
	cmd.Flags().StringVarP(&note, "note", "n", "", "Optional note")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing service without prompting")
	return cmd
}

func vaultGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "get [service]",
		Short:             "Retrieve a secret from the vault",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeServices,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			service := args[0]

			// Resolve vault path
			path, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return err
			}

			// Get vault passphrase
			var vPass []byte
			if vaultPassphrase != "" {
				vPass = []byte(vaultPassphrase)
			} else {
				vPass, _, err = getPassphrase("Enter Vault Master Passphrase: ")
				if err != nil {
					p.RenderError(err)
					return err
				}
			}
			defer crypto.SafeClear(vPass)

			entry, err := GlobalContext.Engine.VaultGet(nil, path, service, vPass, "")
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				type jsonEntry struct {
					Service  string `json:"service"`
					Username string `json:"username"`
					Password string `json:"password"`
					Note     string `json:"note"`
				}
				p.RenderSuccess(jsonEntry{
					Service:  entry.Service,
					Username: entry.Username,
					Password: string(entry.Password),
					Note:     entry.Note,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("Service:  %s\nUsername: %s\nPassword: %s", entry.Service, entry.Username, string(entry.Password)))
			}
			crypto.SafeClear(entry.Password)
			return nil
		},
	}
	return cmd
}

func vaultListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all services stored in the vault",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := GlobalContext.UI.GetPresenter()

			// Resolve vault path
			path, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return err
			}

			// Get vault passphrase
			var vPass []byte
			if vaultPassphrase != "" {
				vPass = []byte(vaultPassphrase)
			} else {
				vPass, _, err = getPassphrase("Enter Vault Master Passphrase: ")
				if err != nil {
					p.RenderError(err)
					return err
				}
			}
			defer crypto.SafeClear(vPass)

			services, err := GlobalContext.Engine.VaultList(nil, path, vPass)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(services)
			} else {
				for _, s := range services {
					p.RenderMessage(fmt.Sprintf(" - %s (%s)", s.Service, s.Username))
				}
			}
			return nil
		},
	}
	return cmd
}

func vaultRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename [old_name] [new_name]",
		Short: "Rename a local vault file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			err := GlobalContext.Engine.VaultRename(nil, args[0], args[1])
			if err != nil {
				p.RenderError(err)
				return err
			}

			p.RenderSuccess(crypto.VaultResult{
				Status: "success",
				Vault:  args[1], // New name
			})
			return nil
		},
	}
	return cmd
}

func vaultDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [name]",
		Short: "Permanently delete a vault file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()

			if !GlobalContext.UI.JSON {
				fmt.Printf("ARE YOU SURE you want to delete vault '%s'? This cannot be undone. (y/N): ", args[0])
				var confirm string
				fmt.Scanln(&confirm)
				if strings.ToLower(confirm) != "y" {
					err := fmt.Errorf("deletion cancelled")
					p.RenderError(err)
					return err
				}
			}

			if err := GlobalContext.Engine.VaultDelete(nil, args[0]); err != nil {
				p.RenderError(err)
				return err
			}

			p.RenderSuccess(crypto.VaultResult{
				Status:  "success",
				Deleted: args[0],
			})
			return nil
		},
	}
	return cmd
}
