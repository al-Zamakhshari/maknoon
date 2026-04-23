package commands

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

func IdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage Post-Quantum cryptographic identities",
	}

	cmd.AddCommand(identityActiveCmd())
	cmd.AddCommand(identityPublishCmd())
	cmd.AddCommand(identitySplitCmd())
	cmd.AddCommand(identityCombineCmd())
	cmd.AddCommand(identityInfoCmd())
	cmd.AddCommand(identityRenameCmd())

	return cmd
}

func identityPublishCmd() *cobra.Command {
	var passphrase string
	var identityName string
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
			checkJSONMode(cmd)
			handle := args[0]
			if !strings.HasPrefix(handle, "@") {
				return fmt.Errorf("handle must start with @ (e.g., @alice.com or @nostr:<pubkey>)")
			}

			// 1. Get active identity
			name := "default"
			if identityName != "" {
				name = identityName
			}

			m := crypto.NewIdentityManager()

			// Check for FIDO2 and get PIN if needed
			basePath, _, _ := m.ResolveBaseKeyPath(name)
			var pin string
			if _, err := os.Stat(basePath + ".fido2"); err == nil {
				var err2 error
				pin, err2 = getPIN()
				if err2 != nil {
					return err2
				}
			}

			id, err := m.LoadIdentity(name, []byte(passphrase), pin, false)
			if err != nil {
				return err
			}
			defer id.Wipe()

			// 3. Create and sign the record
			record := &crypto.IdentityRecord{
				Handle:    handle,
				KEMPubKey: id.KEMPub,
				SIGPubKey: id.SIGPub,
				Timestamp: time.Now(),
			}

			if err := record.Sign(id.SIGPriv); err != nil {
				return fmt.Errorf("failed to sign identity record: %w", err)
			}

			domain := strings.TrimPrefix(handle, "@")

			// 4. Handle Local pinning to Contacts
			if useLocal {
				cm, err := crypto.NewContactManager()
				if err != nil {
					return err
				}
				defer cm.Close()

				err = cm.Add(&crypto.Contact{
					Petname:   handle,
					KEMPubKey: record.KEMPubKey,
					SIGPubKey: record.SIGPubKey,
					AddedAt:   time.Now(),
				})
				if err != nil {
					return err
				}

				if JSONOutput {
					printJSON(crypto.IdentityResult{
						Status:   "success",
						Handle:   handle,
						Registry: "contacts",
					})
				} else {
					fmt.Printf("🚀 Identity pinned to Local Contacts as %s\n", handle)
				}
				return nil
			}

			// 5. Handle Nostr publishing (Default)
			if useNostr || (!useDNS && !useDesec) {
				nostrReg := crypto.NewNostrRegistry()
				if len(id.NostrPriv) == 0 {
					return fmt.Errorf("nostr private key not found in identity")
				}
				if err := nostrReg.PublishWithKey(context.Background(), record, id.NostrPriv); err != nil {
					return fmt.Errorf("nostr publishing failed: %w", err)
				}

				pubHex := string(id.NostrPub)
				if JSONOutput {
					printJSON(map[string]string{
						"status":   "success",
						"registry": "nostr",
						"handle":   "@nostr:" + pubHex,
					})
				} else {
					fmt.Printf("🚀 Identity successfully published to Nostr relays!\n")
					fmt.Printf("Your Nostr handle is: @nostr:%s\n", pubHex)
				}
				return nil
			}

			// 6. Handle deSEC automation
			if useDesec {
				token := desecToken
				if token == "" {
					token = os.Getenv("DESEC_TOKEN")
				}
				if token == "" {
					return fmt.Errorf("deSEC token required for automated publishing")
				}

				dnsReg := crypto.NewDNSRegistry()
				if err := dnsReg.PublishWithKey(context.Background(), record, []byte(token)); err != nil {
					return fmt.Errorf("deSEC publishing failed: %w", err)
				}

				if JSONOutput {
					printJSON(map[string]string{
						"status":   "success",
						"registry": "desec",
						"handle":   handle,
					})
				} else {
					fmt.Printf("🚀 Identity successfully published to deSEC.io for %s\n", handle)
				}
				return nil
			}

			// 7. Handle DNS mode (Manual)
			if useDNS {
				txt, err := crypto.GetDNSRecordString(record)
				if err != nil {
					return err
				}

				if JSONOutput {
					printJSON(map[string]string{
						"status":   "success",
						"registry": "dns_manual",
						"hostname": "_maknoon." + domain,
						"value":    txt,
					})
				} else {
					fmt.Printf("🛡️  DNS Discovery Record for %s:\n\n", handle)
					fmt.Printf("Hostname: _maknoon.%s\n", domain)
					fmt.Printf("Type:     TXT\n")
					fmt.Printf("Value:    %s\n\n", txt)
					fmt.Printf("Add this record to your DNS provider to enable global discovery.\n")
				}
				return nil
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to unlock your signing key")
	cmd.Flags().StringVarP(&identityName, "name", "i", "", "Name of the local identity to publish")
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
		Use:   "split [name]",
		Short: "Shard an identity using Shamir's Secret Sharing",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkJSONMode(cmd)
			name := args[0]

			m := crypto.NewIdentityManager()

			// Check for FIDO2 and get PIN if needed
			basePath, _, _ := m.ResolveBaseKeyPath(name)
			var pin string
			if _, err := os.Stat(basePath + ".fido2"); err == nil {
				var err2 error
				pin, err2 = getPIN()
				if err2 != nil {
					return err2
				}
			}

			id, err := m.LoadIdentity(name, []byte(passphrase), pin, false)
			if err != nil {
				return err
			}
			defer id.Wipe()

			// Combine keys into a single blob: [len_kem_4][kem_priv][len_sig_4][sig_priv][len_nostr_4][nostr_priv]
			blob := make([]byte, 12+len(id.KEMPriv)+len(id.SIGPriv)+len(id.NostrPriv))
			offset := 0
			binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(id.KEMPriv)))
			copy(blob[offset+4:offset+4+len(id.KEMPriv)], id.KEMPriv)
			offset += 4 + len(id.KEMPriv)

			binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(id.SIGPriv)))
			copy(blob[offset+4:offset+4+len(id.SIGPriv)], id.SIGPriv)
			offset += 4 + len(id.SIGPriv)

			binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(id.NostrPriv)))
			copy(blob[offset+4:], id.NostrPriv)

			defer crypto.SafeClear(blob)

			shards, err := crypto.SplitSecret(blob, threshold, shares)
			if err != nil {
				return err
			}

			if JSONOutput {
				var shareStrings []string
				for _, s := range shards {
					shareStrings = append(shareStrings, s.ToMnemonic())
				}
				printJSON(map[string]interface{}{
					"status": "success",
					"shares": shareStrings,
				})
			} else {
				fmt.Printf("🛡️  Identity '%s' sharded into %d parts (Threshold: %d)\n", name, shares, threshold)
				fmt.Println("CRITICAL: Keep these mnemonics safe and separated.")
				for i, s := range shards {
					fmt.Printf("\nShare %d:\n%s\n", i+1, s.ToMnemonic())
				}
			}
			return nil
		},
	}

	cmd.Flags().IntVarP(&threshold, "threshold", "m", 2, "Minimum shares required")
	cmd.Flags().IntVarP(&shares, "shares", "n", 3, "Total shares to generate")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to unlock the identity")

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
			checkJSONMode(cmd)

			var shards []crypto.Share
			for _, mn := range args {
				s, err := crypto.FromMnemonic(mn)
				if err != nil {
					return fmt.Errorf("invalid mnemonic: %w", err)
				}
				shards = append(shards, *s)
			}

			blob, err := crypto.CombineShares(shards)
			if err != nil {
				return err
			}
			defer crypto.SafeClear(blob)

			if len(blob) < 8 {
				return fmt.Errorf("reconstructed blob too short")
			}

			kemLen := binary.BigEndian.Uint32(blob[0:4])
			if uint32(len(blob)) < 4+kemLen {
				return fmt.Errorf("reconstructed blob corrupted (invalid KEM length)")
			}
			kemPriv := blob[4 : 4+kemLen]
			offset := 4 + kemLen

			sigLen := binary.BigEndian.Uint32(blob[offset : offset+4])
			if uint32(len(blob)) < offset+4+sigLen {
				return fmt.Errorf("reconstructed blob corrupted (invalid SIG length)")
			}
			sigPriv := blob[offset+4 : offset+4+sigLen]
			offset += 4 + sigLen

			var nostrPriv []byte
			if uint32(len(blob)) >= offset+4 {
				nostrLen := binary.BigEndian.Uint32(blob[offset : offset+4])
				if uint32(len(blob)) == offset+4+nostrLen {
					nostrPriv = blob[offset+4:]
				}
			}

			// Derive public keys from private keys.
			kemPub, err := crypto.DeriveKEMPublic(kemPriv)
			if err != nil {
				return fmt.Errorf("failed to derive KEM public key: %w", err)
			}
			sigPub, err := crypto.DeriveSIGPublic(sigPriv)
			if err != nil {
				return fmt.Errorf("failed to derive SIG public key: %w", err)
			}
			var nostrPub []byte
			if len(nostrPriv) > 0 {
				nostrPub, _ = crypto.DeriveNostrPublic(nostrPriv)
			}

			m := crypto.NewIdentityManager()
			basePath, _, err := m.ResolveBaseKeyPath(output)
			if err != nil {
				return err
			}

			pass, err := getInitialPassphrase(noPassword, protectPassphrase)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}
			defer crypto.SafeClear(pass)

			if err := writeIdentityKeys(basePath, output, kemPub, kemPriv, sigPub, sigPriv, nostrPub, nostrPriv, pass, 1); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{
					"status":    "success",
					"base_path": basePath,
				})
			} else {
				fmt.Printf("Successfully reconstructed and saved identity to %s\n", basePath)
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
		Use:   "info [name]",
		Short: "Show details about a local identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkJSONMode(cmd)
			name := args[0]
			m := crypto.NewIdentityManager()
			basePath, _, err := m.ResolveBaseKeyPath(name)
			if err != nil {
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{
					"identity": name,
					"path":     basePath,
				})
			} else {
				fmt.Printf("Identity: %s\n", name)
				fmt.Printf("Path:     %s\n", basePath)
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
			checkJSONMode(cmd)
			m := crypto.NewIdentityManager()
			keys, err := m.ListActiveIdentities()
			if err != nil {
				return err
			}

			if JSONOutput {
				printJSON(map[string]interface{}{
					"active_keys": keys,
				})
			} else {
				fmt.Println("Available Public Keys:")
				for _, k := range keys {
					fmt.Printf("  - %s\n", k)
				}
			}
			return nil
		},
	}
}

func identityRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename [old] [new]",
		Short: "Rename a local identity",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkJSONMode(cmd)
			oldName := args[0]
			newName := args[1]

			m := crypto.NewIdentityManager()
			oldBase, _, err := m.ResolveBaseKeyPath(oldName)
			if err != nil {
				return err
			}
			newBase, _, err := m.ResolveBaseKeyPath(newName)
			if err != nil {
				return err
			}

			// 1. Rename Local Files
			suffixes := []string{".kem.key", ".kem.pub", ".sig.key", ".sig.pub", ".fido2", ".nostr.key", ".nostr.pub"}
			renamed := 0
			for _, s := range suffixes {
				oldPath := oldBase + s
				newPath := newBase + s
				if _, err := os.Stat(oldPath); err == nil {
					if err := os.Rename(oldPath, newPath); err != nil {
						return err
					}
					renamed++
				}
			}

			if renamed == 0 {
				return fmt.Errorf("identity '%s' not found", oldName)
			}

			// 2. Rename in Local Contacts
			cm, err := crypto.NewContactManager()
			if err == nil {
				contact, err := cm.Get(oldName)
				if err == nil {
					contact.Petname = newName
					cm.Add(contact)
					cm.Delete(oldName)
				}
				cm.Close()
			}

			if JSONOutput {
				printJSON(crypto.IdentityResult{
					Status: "success",
					From:   oldName,
					To:     newName,
				})
			} else {
				fmt.Printf("Successfully renamed identity '%s' to '%s'\n", oldName, newName)
			}
			return nil
		},
	}
	return cmd
}
