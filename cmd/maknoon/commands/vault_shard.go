package commands

import (
	"fmt"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

func vaultSplitCmd() *cobra.Command {
	var threshold, shares int
	cmd := &cobra.Command{
		Use:   "split",
		Short: "Shard the vault's master access key",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p := GlobalContext.UI.GetPresenter()

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
