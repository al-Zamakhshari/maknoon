package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
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
				// Don't force passphrase prompt if we're in agent mode and it might be an institutional vault.
				// The engine will handle the error if it's NOT institutional and passphrase is empty.
				isAgent := viper.GetString("agent_mode") == "1"
				if !isAgent {
					vPass, _, err = getPassphrase("Enter Vault Master Passphrase: ")
					if err != nil {
						p.RenderError(err)
						return err
					}
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
				isAgent := viper.GetString("agent_mode") == "1"
				if !isAgent {
					vPass, _, err = getPassphrase("Enter Vault Master Passphrase: ")
					if err != nil {
						p.RenderError(err)
						return err
					}
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

func vaultRotateCmd() *cobra.Command {
	var newPass string
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Change the master passphrase of a vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()

			var oldPass []byte
			var err error
			if vaultPassphrase != "" {
				oldPass = []byte(vaultPassphrase)
			} else {
				oldPass, _, err = getPassphrase("Enter Current Vault Master Passphrase: ")
				if err != nil {
					p.RenderError(err)
					return err
				}
			}
			defer crypto.SafeClear(oldPass)

			var newPassBytes []byte
			if newPass != "" {
				newPassBytes = []byte(newPass)
			} else {
				newPassBytes, _, err = getPassphrase("Enter NEW Vault Master Passphrase: ")
				if err != nil {
					p.RenderError(err)
					return err
				}
				confirm, _, err := getPassphrase("Confirm NEW Vault Master Passphrase: ")
				if err != nil {
					p.RenderError(err)
					return err
				}
				if string(newPassBytes) != string(confirm) {
					crypto.SafeClear(confirm)
					err := fmt.Errorf("passphrases do not match")
					p.RenderError(err)
					return err
				}
				crypto.SafeClear(confirm)
			}
			defer crypto.SafeClear(newPassBytes)

			path, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return err
			}

			err = GlobalContext.Engine.VaultRotate(nil, path, oldPass, newPassBytes)
			if err != nil {
				p.RenderError(err)
				return err
			}

			p.RenderSuccess(crypto.VaultResult{
				Status:  "success",
				Message: "Vault passphrase rotated successfully",
			})
			return nil
		},
	}
	cmd.Flags().StringVarP(&newPass, "new-passphrase", "n", "", "New master passphrase (unsafe for CLI history)")
	return cmd
}

func vaultSetBlobCmd() *cobra.Command {
	var user string
	var overwrite bool
	var data string

	cmd := &cobra.Command{
		Use:   "set-blob [key]",
		Short: "Store arbitrary encrypted data (blob) in the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			key := args[0]
			var blob []byte

			if data != "" {
				blob = []byte(data)
			} else {
				fmt.Print("Enter blob data: ")
				fmt.Scanln(&data)
				blob = []byte(data)
			}

			path, err := resolveVaultPath(vaultName)
			if err != nil {
				return err
			}

			var vPass []byte
			if vaultPassphrase != "" {
				vPass = []byte(vaultPassphrase)
			} else {
				vPass, _, err = getPassphrase("Enter Vault Master Passphrase: ")
				if err != nil {
					return err
				}
			}
			defer crypto.SafeClear(vPass)

			entry := &crypto.VaultEntry{
				Service:  key,
				Username: user,
				Blob:     crypto.SecretBytes(blob),
			}
			err = GlobalContext.Engine.VaultSet(nil, path, entry, vPass, "", overwrite)
			crypto.SafeClear(entry.Blob)
			if err != nil {
				return err
			}

			p.RenderSuccess(crypto.VaultResult{
				Status:  "success",
				Service: key,
			})
			return nil
		},
	}

	cmd.Flags().StringVarP(&user, "user", "u", "agent", "Owner/User for the blob")
	cmd.Flags().StringVarP(&data, "data", "d", "", "Blob data to store (direct string)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing key")
	return cmd
}

func vaultGetBlobCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get-blob [key]",
		Short: "Retrieve encrypted blob data from the vault",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			key := args[0]

			path, err := resolveVaultPath(vaultName)
			if err != nil {
				return err
			}

			var vPass []byte
			if vaultPassphrase != "" {
				vPass = []byte(vaultPassphrase)
			} else {
				vPass, _, err = getPassphrase("Enter Vault Master Passphrase: ")
				if err != nil {
					return err
				}
			}
			defer crypto.SafeClear(vPass)

			entry, err := GlobalContext.Engine.VaultGet(nil, path, key, vPass, "")
			if err != nil {
				return err
			}

			if GlobalContext.UI.JSON {
				res := map[string]string{
					"status": "success",
					"key":    key,
					"data":   string(entry.Blob),
				}
				p.RenderSuccess(res)
			} else {
				p.RenderMessage(string(entry.Blob))
			}
			crypto.SafeClear(entry.Blob)
			return nil
		},
	}
	return cmd
}

func vaultExportCmd() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export all vault entries as an encrypted .makn bundle",
		Long: `Exports every entry in a vault into a single encrypted .makn file using the
vault passphrase for symmetric encryption. The bundle can be decrypted with
'maknoon decrypt' and imported on another machine with 'maknoon vault import'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
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

			entries, err := GlobalContext.Engine.VaultList(nil, path, vPass)
			if err != nil {
				p.RenderError(err)
				return err
			}

			type exportEntry struct {
				Service  string `json:"service"`
				Username string `json:"username,omitempty"`
				Password string `json:"password,omitempty"`
				Blob     string `json:"blob,omitempty"`
				URL      string `json:"url,omitempty"`
				Note     string `json:"note,omitempty"`
			}
			var full []exportEntry
			for _, e := range entries {
				entry, err := GlobalContext.Engine.VaultGet(nil, path, e.Service, vPass, "")
				if err != nil || entry == nil {
					continue
				}
				full = append(full, exportEntry{
					Service:  entry.Service,
					Username: entry.Username,
					Password: string(entry.Password),
					Blob:     string(entry.Blob),
					URL:      entry.URL,
					Note:     entry.Note,
				})
				crypto.SafeClear(entry.Password)
				crypto.SafeClear(entry.Blob)
			}

			data, err := json.MarshalIndent(full, "", "  ")
			if err != nil {
				p.RenderError(err)
				return err
			}

			if output == "" {
				output = vaultName + ".vault.makn"
			}
			outFile, err := os.Create(output)
			if err != nil {
				p.RenderError(err)
				return err
			}
			defer outFile.Close()

			opts := crypto.Options{Passphrase: crypto.SecretBytes(vPass)}
			if _, err := GlobalContext.Engine.Protect(nil, "vault-export", bytes.NewReader(data), outFile, opts); err != nil {
				p.RenderError(err)
				return err
			}

			res := map[string]any{
				"status":           "success",
				"entries_exported": len(full),
				"output":           output,
			}
			p.RenderSuccess(res)
			if !GlobalContext.UI.JSON {
				p.RenderMessage(fmt.Sprintf("✅ %d entries exported to %s", len(full), output))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output path (default: <vault>.vault.makn)")
	return cmd
}

func vaultImportCmd() *cobra.Command {
	var input string
	var overwrite bool
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import vault entries from an encrypted .makn bundle",
		Long: `Decrypts a bundle created by 'maknoon vault export' and imports all entries
into the target vault. Skips entries that already exist unless --overwrite is set.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()

			if input == "" {
				err := fmt.Errorf("--input is required")
				p.RenderError(err)
				return err
			}

			inFile, err := os.Open(input)
			if err != nil {
				p.RenderError(err)
				return err
			}
			defer inFile.Close()

			var vPass []byte
			if vaultPassphrase != "" {
				vPass = []byte(vaultPassphrase)
			} else {
				vPass, _, err = getPassphrase("Enter Bundle Passphrase: ")
				if err != nil {
					p.RenderError(err)
					return err
				}
			}
			defer crypto.SafeClear(vPass)

			var buf bytes.Buffer
			opts := crypto.Options{Passphrase: crypto.SecretBytes(vPass)}
			if _, err := GlobalContext.Engine.Unprotect(nil, inFile, &buf, "", opts); err != nil {
				p.RenderError(err)
				return err
			}

			type exportEntry struct {
				Service  string `json:"service"`
				Username string `json:"username,omitempty"`
				Password string `json:"password,omitempty"`
				Blob     string `json:"blob,omitempty"`
				URL      string `json:"url,omitempty"`
				Note     string `json:"note,omitempty"`
			}
			var importedEntries []exportEntry
			if err := json.Unmarshal(buf.Bytes(), &importedEntries); err != nil {
				err = fmt.Errorf("invalid bundle format: %w", err)
				p.RenderError(err)
				return err
			}

			targetPath, err := resolveVaultPath(vaultName)
			if err != nil {
				p.RenderError(err)
				return err
			}

			vPassTarget := crypto.SecretBytes(vPass)
			imported, skipped := 0, 0
			for _, e := range importedEntries {
				entry := &crypto.VaultEntry{
					Service:  e.Service,
					Username: e.Username,
					Password: crypto.SecretBytes(e.Password),
					Blob:     crypto.SecretBytes(e.Blob),
					URL:      e.URL,
					Note:     e.Note,
				}
				if err := GlobalContext.Engine.VaultSet(nil, targetPath, entry, vPassTarget, "", overwrite); err != nil {
					skipped++
				} else {
					imported++
				}
				crypto.SafeClear(entry.Password)
				crypto.SafeClear(entry.Blob)
			}
			crypto.SafeClear(vPassTarget)

			res := map[string]any{
				"status":   "success",
				"vault":    vaultName,
				"imported": imported,
				"skipped":  skipped,
			}
			p.RenderSuccess(res)
			if !GlobalContext.UI.JSON {
				p.RenderMessage(fmt.Sprintf("✅ Imported %d entries into vault '%s' (%d skipped — use --overwrite to replace)", imported, vaultName, skipped))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&input, "input", "i", "", "Path to the encrypted .makn bundle (required)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite existing entries")
	return cmd
}
