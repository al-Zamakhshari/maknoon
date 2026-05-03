package commands

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var vaultName string
var vaultPassphrase string
var vaultBackend string
var useFido2 bool

// VaultCmd returns the cobra command for managing secure vaults.
func VaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage secure password vaults",
	}

	cmd.PersistentFlags().StringVarP(&vaultName, "vault", "v", "default", "Name or full path of the vault to use")
	cmd.PersistentFlags().StringVarP(&vaultPassphrase, "passphrase", "s", "", "Master passphrase for the vault")
	cmd.PersistentFlags().StringVar(&vaultBackend, "backend", "", "Storage backend (bbolt or badger, defaults to config)")
	cmd.PersistentFlags().BoolVarP(&useFido2, "fido2", "f", false, "Use FIDO2 security key for authentication")
	cmd.PersistentFlags().BoolVar(&JSONOutput, "json", false, "Output results in JSON format")

	_ = viper.BindPFlag("vault_backend", cmd.PersistentFlags().Lookup("backend"))

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
