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
