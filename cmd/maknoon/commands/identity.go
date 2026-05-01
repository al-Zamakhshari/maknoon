package commands

import (
	"fmt"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

var (
	identityName string
	passphrase   string
)

func IdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage Post-Quantum cryptographic identities",
	}

	cmd.PersistentFlags().StringVarP(&identityName, "name", "i", "default", "Identity name")
	cmd.PersistentFlags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for the identity")

	cmd.AddCommand(identityActiveCmd())
	cmd.AddCommand(identityPublishCmd())
	cmd.AddCommand(identitySplitCmd())
	cmd.AddCommand(identityCombineCmd())
	cmd.AddCommand(identityShardCmd())
	cmd.AddCommand(identityReconstructCmd())
	cmd.AddCommand(identityInfoCmd())
	cmd.AddCommand(identityRenameCmd())

	return cmd
}

// Shard a raw string/secret
func identityShardCmd() *cobra.Command {
	var threshold, shares int
	cmd := &cobra.Command{
		Use:   "shard [secret]",
		Short: "Split a generic secret into Shamir shards (SSS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			secret := []byte(args[0])

			shards, err := crypto.SplitSecret(secret, threshold, shares)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				var jsonShards []string
				for _, s := range shards {
					jsonShards = append(jsonShards, s.ToMnemonic())
				}
				p.RenderSuccess(crypto.IdentityResult{
					Status:    "success",
					Threshold: threshold,
					Shares:    jsonShards,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("🛡️  Secret split into %d shards (Threshold: %d)", shares, threshold))
				for i, s := range shards {
					p.RenderMessage(fmt.Sprintf("\nShard %d:\n%s", i+1, s.ToMnemonic()))
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVarP(&threshold, "threshold", "m", 2, "Threshold for recovery")
	cmd.Flags().IntVarP(&shares, "shares", "n", 3, "Total shares")
	return cmd
}

// Reconstruct a raw string/secret
func identityReconstructCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reconstruct [shards...]",
		Short: "Reconstruct a generic secret from Shamir shards",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			var shards []crypto.Share
			for _, m := range args {
				s, err := crypto.FromMnemonic(m)
				if err != nil {
					err = fmt.Errorf("invalid shard: %w", err)
					p.RenderError(err)
					return err
				}
				shards = append(shards, *s)
			}

			secret, err := crypto.CombineShares(shards)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(crypto.IdentityResult{
					Status: "success",
					Secret: string(secret),
				})
			} else {
				p.RenderMessage(fmt.Sprintf("✅ Secret Reconstructed: %s", string(secret)))
			}
			return nil
		},
	}
	return cmd
}

func identityPublishCmd() *cobra.Command {
	var useDNS bool
	var useDesec bool
	var useNostr bool
	var useLocal bool
	var desecToken string

	cmd := &cobra.Command{
		Use:   "publish [handle]",
		Short: "Anchor your active identity to a global registry (Nostr/DNS/dPKI)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			handle := args[0]
			if !strings.HasPrefix(handle, "@") {
				return fmt.Errorf("handle must start with @ (e.g., @alice.com or @nostr:<pubkey>)")
			}

			opts := crypto.IdentityPublishOptions{
				Name:       identityName,
				Passphrase: passphrase,
				Local:      useLocal,
				DNS:        useDNS,
				Desec:      useDesec,
				DesecToken: desecToken,
				Nostr:      useNostr,
			}

			if err := GlobalContext.Engine.IdentityPublish(nil, handle, opts); err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(crypto.IdentityResult{
					Status: "success",
					Handle: handle,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("🚀 Identity '%s' successfully published to requested registries.", handle))
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&useDNS, "dns", false, "Generate a DNS TXT record for decentralized discovery")
	cmd.Flags().BoolVar(&useDesec, "desec", false, "Automatically publish to deSEC.io (requires --desec-token or DESEC_TOKEN)")
	cmd.Flags().BoolVar(&useNostr, "nostr", false, "Automatically publish to Nostr relays (Default)")
	cmd.Flags().BoolVar(&useLocal, "local", false, "Pin identity to local contacts only")
	cmd.Flags().StringVar(&desecToken, "desec-token", "", "deSEC.io API token")

	return cmd
}

func identitySplitCmd() *cobra.Command {
	var threshold int
	var shares int
	var passphrase string

	cmd := &cobra.Command{
		Use:               "split [name]",
		Short:             "Shard an identity using Shamir's Secret Sharing",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeIdentities,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			name := args[0]

			shards, err := GlobalContext.Engine.IdentitySplit(nil, name, threshold, shares, passphrase)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(map[string]interface{}{
					"status": "success",
					"shares": shards,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("🛡️  Identity '%s' sharded into %d parts (Threshold: %d)", name, shares, threshold))
				p.RenderMessage("CRITICAL: Keep these mnemonics safe and separated.")
				for i, s := range shards {
					p.RenderMessage(fmt.Sprintf("\nShare %d:\n%s", i+1, s))
				}
			}
			return nil
		},
	}

	cmd.Flags().IntVarP(&threshold, "threshold", "m", 2, "Minimum shares required")
	cmd.Flags().IntVarP(&shares, "shares", "n", 3, "Total shares to generate")

	return cmd
}

func identityCombineCmd() *cobra.Command {
	var output string
	var protectPassphrase string
	var noPassword bool

	cmd := &cobra.Command{
		Use:   "combine [mnemonics...]",
		Short: "Recover an identity from mnemonic shards",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			basePath, err := GlobalContext.Engine.IdentityCombine(nil, args, output, protectPassphrase, noPassword)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(map[string]string{
					"status":    "success",
					"base_path": basePath,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("Successfully reconstructed and saved identity to %s", basePath))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "recovered", "Name for the recovered identity")
	cmd.Flags().StringVarP(&protectPassphrase, "passphrase", "s", "", "Passphrase to protect the restored identity")
	cmd.Flags().BoolVarP(&noPassword, "no-password", "n", false, "Do not protect the restored identity with a passphrase")

	return cmd
}

func identityInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "info [name]",
		Short:             "Show details about a local identity",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeIdentities,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			name := args[0]
			res, err := GlobalContext.Engine.IdentityInfo(nil, name)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(res)
			} else {
				msg := fmt.Sprintf("Identity: %s\n", res.Name)
				if res.KEMPub != "" {
					msg += fmt.Sprintf("  - KEM Public Key: %s\n", res.KEMPub)
				}
				if res.SIGPub != "" {
					msg += fmt.Sprintf("  - SIG Public Key: %s\n", res.SIGPub)
				}
				if res.NostrPub != "" {
					msg += fmt.Sprintf("  - Nostr Public Key: %s\n", res.NostrPub)
				}
				if res.PeerID != "" {
					msg += fmt.Sprintf("  - Peer ID:        %s\n", res.PeerID)
				}
				p.RenderMessage(msg)
			}
			return nil
		},
	}
}

func identityActiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "active",
		Short: "List absolute paths of available public keys for encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			keys, err := GlobalContext.Engine.IdentityActive(nil)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(map[string]interface{}{
					"active_keys": keys,
				})
			} else {
				p.RenderMessage("Available Public Keys:")
				for _, k := range keys {
					p.RenderMessage(fmt.Sprintf("  - %s", k))
				}
			}
			return nil
		},
	}
}

func identityRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "rename [old] [new]",
		Short:             "Rename a local identity",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeIdentities,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			oldName := args[0]
			newName := args[1]

			if err := GlobalContext.Engine.IdentityRename(nil, oldName, newName); err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(crypto.IdentityResult{
					Status: "success",
					From:   oldName,
					To:     newName,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("Successfully renamed identity '%s' to '%s'", oldName, newName))
			}
			return nil
		},
	}
	return cmd
}
