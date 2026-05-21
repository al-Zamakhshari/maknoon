package commands

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

var vaultName string
var vaultPassphrase string

// VaultCmd returns the cobra command for managing secure vaults.
func VaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage secure password vaults",
	}

	cmd.PersistentFlags().StringVarP(&vaultName, "vault", "v", "default", "Name or full path of the vault to use")
	cmd.PersistentFlags().StringVarP(&vaultPassphrase, "passphrase", "s", "", "Master passphrase for the vault")
	cmd.PersistentFlags().BoolVar(&JSONOutput, "json", false, "Output results in JSON format")

	_ = cmd.RegisterFlagCompletionFunc("vault", completeVaults)

	cmd.AddCommand(vaultSetCmd())
	cmd.AddCommand(vaultGetCmd())
	cmd.AddCommand(vaultSetBlobCmd())
	cmd.AddCommand(vaultGetBlobCmd())
	cmd.AddCommand(vaultListCmd())
	cmd.AddCommand(vaultRenameCmd())
	cmd.AddCommand(vaultDeleteCmd())
	cmd.AddCommand(vaultInitInstitutionalCmd())
	cmd.AddCommand(vaultSplitCmd())
	cmd.AddCommand(vaultRecoverCmd())
	cmd.AddCommand(vaultRotateCmd())
	cmd.AddCommand(vaultCheckShardsCmd())
	cmd.AddCommand(vaultExportCmd())
	cmd.AddCommand(vaultImportCmd())
	cmd.AddCommand(vaultUnlockCmd())
	cmd.AddCommand(vaultLockCmd())

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

func vaultUnlockCmd() *cobra.Command {
	var passphrase string
	var ttl int

	cmd := &cobra.Command{
		Use:   "unlock [vault]",
		Short: "Derive the vault key once and cache it for the session TTL (default 5 min)",
		Long:  "Subsequent vault get/set/list calls skip Argon2id entirely until the TTL expires or 'vault lock' is called.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			vaultName := "default"
			if len(args) > 0 {
				vaultName = args[0]
			}
			pass, _, err := getPassphrase("Passphrase: ")
			if err != nil && passphrase == "" {
				p.RenderError(err)
				return err
			}
			if passphrase != "" {
				pass = []byte(passphrase)
			}
			defer crypto.SafeClear(pass)
			if err := GlobalContext.Engine.VaultUnlock(nil, vaultName, pass, ttl); err != nil {
				p.RenderError(err)
				return err
			}
			p.RenderSuccess(map[string]any{"status": "unlocked", "vault": vaultName, "ttl_seconds": ttl})
			return nil
		},
	}
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for the vault")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "Session lifetime in seconds (default: 300)")
	return cmd
}

func vaultLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock [vault]",
		Short: "Immediately wipe the cached session key for a vault",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			vaultName := "default"
			if len(args) > 0 {
				vaultName = args[0]
			}
			if err := GlobalContext.Engine.VaultLock(nil, vaultName); err != nil {
				p.RenderError(err)
				return err
			}
			p.RenderSuccess(map[string]any{"status": "locked", "vault": vaultName})
			return nil
		},
	}
}
