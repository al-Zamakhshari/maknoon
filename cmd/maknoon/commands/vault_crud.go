package commands

import (
	"fmt"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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

			path, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return err
			}

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

			path, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return err
			}

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

			path, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return err
			}

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
				Vault:  args[1],
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
