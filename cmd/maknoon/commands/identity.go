package commands

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// IdentityCmd returns the cobra command for managing cryptographic identities.
func IdentityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Manage Post-Quantum cryptographic identities",
	}

	cmd.AddCommand(identityListCmd())
	cmd.AddCommand(identityActiveCmd())
	cmd.AddCommand(identityShowCmd())
	cmd.AddCommand(identityRenameCmd())
	cmd.AddCommand(identitySplitCmd())
	cmd.AddCommand(identityCombineCmd())

	return cmd
}

func identitySplitCmd() *cobra.Command {
	var threshold, shares int
	var passphrase string

	cmd := &cobra.Command{
		Use:   "split [name]",
		Short: "Shard a private identity using Shamir's Secret Sharing",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			basePath, _, err := resolveBaseKeyPath(name)
			if err != nil {
				return err
			}

			kemKeyPath := basePath + ".kem.key"
			sigKeyPath := basePath + ".sig.key"

			unlockKey := func(path string) ([]byte, error) {
				keyBytes, err := os.ReadFile(path)
				if err != nil {
					return nil, err
				}
				if len(keyBytes) > 4 && string(keyBytes[:4]) == crypto.MagicHeader {
					pass, err := unlockPrivateKey([]byte(passphrase), path, false)
					if err != nil {
						return nil, err
					}
					var unlocked bytes.Buffer
					if _, err := crypto.DecryptStream(bytes.NewReader(keyBytes), &unlocked, pass, 1, false); err != nil {
						return nil, err
					}
					return unlocked.Bytes(), nil
				}
				return keyBytes, nil
			}

			kemPriv, err := unlockKey(kemKeyPath)
			if err != nil {
				return fmt.Errorf("failed to unlock KEM key: %w", err)
			}
			defer crypto.SafeClear(kemPriv)

			sigPriv, err := unlockKey(sigKeyPath)
			if err != nil {
				return fmt.Errorf("failed to unlock SIG key: %w", err)
			}
			defer crypto.SafeClear(sigPriv)

			// Combine keys into a single blob: [len_kem_4_bytes][kem_priv][len_sig_4_bytes][sig_priv]
			blob := make([]byte, 8+len(kemPriv)+len(sigPriv))
			binary.BigEndian.PutUint32(blob[0:4], uint32(len(kemPriv)))
			copy(blob[4:4+len(kemPriv)], kemPriv)
			binary.BigEndian.PutUint32(blob[4+len(kemPriv):8+len(kemPriv)], uint32(len(sigPriv)))
			copy(blob[8+len(kemPriv):], sigPriv)
			defer crypto.SafeClear(blob)

			shards, err := crypto.SplitSecret(blob, threshold, shares)
			if err != nil {
				return err
			}

			if JSONOutput {
				var jsonShards []string
				for _, s := range shards {
					jsonShards = append(jsonShards, s.ToMnemonic())
				}
				printJSON(map[string]interface{}{"identity": name, "threshold": threshold, "shares": jsonShards})
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

	cmd.Flags().IntVarP(&threshold, "threshold", "m", 2, "Minimum shares required for reconstruction")
	cmd.Flags().IntVarP(&shares, "shares", "n", 3, "Total number of shares to generate")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to unlock the identity")

	return cmd
}

func identityCombineCmd() *cobra.Command {
	var output string
	var protectPassphrase string
	var noPassword bool

	cmd := &cobra.Command{
		Use:   "combine [mnemonics...]",
		Short: "Reconstruct a private identity from shards",
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("at least one shard mnemonic is required")
			}

			var shards []crypto.Share
			for _, m := range args {
				s, err := crypto.FromMnemonic(m)
				if err != nil {
					return fmt.Errorf("invalid mnemonic: %w", err)
				}
				shards = append(shards, *s)
			}

			blob, err := crypto.CombineShares(shards)
			if err != nil {
				return fmt.Errorf("failed to reconstruct secret: %w", err)
			}
			defer crypto.SafeClear(blob)

			if len(blob) < 8 {
				return fmt.Errorf("reconstructed blob too short")
			}

			kemLen := binary.BigEndian.Uint32(blob[0:4])
			if uint32(len(blob)) < 8+kemLen {
				return fmt.Errorf("reconstructed blob corrupted (invalid KEM length)")
			}
			kemPriv := blob[4 : 4+kemLen]

			sigLen := binary.BigEndian.Uint32(blob[4+kemLen : 8+kemLen])
			if uint32(len(blob)) != 8+kemLen+sigLen {
				return fmt.Errorf("reconstructed blob corrupted (invalid SIG length)")
			}
			sigPriv := blob[8+kemLen:]

			// We need public keys too for a full identity.
			// ML-KEM and ML-DSA public keys can usually be derived from private keys,
			// but for now let's assume the user might want to re-provide them or we can derive them.
			// Actually, Maknoon keygen saves them separately.
			// Let's derive them using circl.
			kemPub, err := crypto.DeriveKEMPublic(kemPriv)
			if err != nil {
				return fmt.Errorf("failed to derive KEM public key: %w", err)
			}
			sigPub, err := crypto.DeriveSIGPublic(sigPriv)
			if err != nil {
				return fmt.Errorf("failed to derive SIG public key: %w", err)
			}

			basePath, baseName, err := resolveBaseKeyPath(output)
			if err != nil {
				return err
			}

			pass, err := getInitialPassphrase(noPassword, protectPassphrase)
			if err != nil {
				return err
			}
			defer crypto.SafeClear(pass)

			if err := writeIdentityKeys(basePath, baseName, kemPub, kemPriv, sigPub, sigPriv, pass, 1); err != nil {
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{"status": "success", "base_path": basePath})
			} else {
				fmt.Printf("Successfully reconstructed and saved identity to %s\n", basePath)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "restored_id", "Name for the restored identity")
	cmd.Flags().StringVarP(&protectPassphrase, "passphrase", "s", "", "Passphrase to protect the restored identity")
	cmd.Flags().BoolVarP(&noPassword, "no-password", "n", false, "Save unprotected (Automation Mode)")

	return cmd
}

func identityActiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "active",
		Short: "List absolute paths of available public keys for encryption",
		RunE: func(_ *cobra.Command, _ []string) error {
			home, _ := os.UserHomeDir()
			keysDir := filepath.Join(home, crypto.MaknoonDir, crypto.KeysDir)

			files, err := os.ReadDir(keysDir)
			if err != nil {
				if os.IsNotExist(err) {
					if JSONOutput {
						printJSON(map[string]interface{}{"active_keys": []string{}})
						return nil
					}
					fmt.Println("No identities found.")
					return nil
				}
				return err
			}

			var keys []string
			for _, f := range files {
				name := f.Name()
				if strings.HasSuffix(name, ".kem.pub") {
					keys = append(keys, filepath.Join(keysDir, name))
				}
			}

			if JSONOutput {
				printJSON(map[string]interface{}{
					"active_keys": keys,
				})
			} else {
				fmt.Println("🛡️  Active Public Keys (Absolute Paths):")
				for _, k := range keys {
					fmt.Printf("  - %s\n", k)
				}
			}
			return nil
		},
	}
	return cmd
}

func identityListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all local identities",
		RunE: func(_ *cobra.Command, _ []string) error {
			home, _ := os.UserHomeDir()
			keysDir := filepath.Join(home, crypto.MaknoonDir, crypto.KeysDir)

			files, err := os.ReadDir(keysDir)
			if err != nil {
				if os.IsNotExist(err) {
					if JSONOutput {
						printJSON([]string{})
						return nil
					}
					fmt.Println("No identities found.")
					return nil
				}
				return err
			}

			var identities []string
			seen := make(map[string]bool)
			for _, f := range files {
				name := f.Name()
				if strings.HasSuffix(name, ".kem.pub") {
					base := strings.TrimSuffix(name, ".kem.pub")
					if !seen[base] {
						identities = append(identities, base)
						seen[base] = true
					}
				}
			}

			if JSONOutput {
				printJSON(identities)
			} else {
				fmt.Println("🛡️  Maknoon Identities:")
				for _, id := range identities {
					fmt.Printf("  - %s\n", id)
				}
			}
			return nil
		},
	}
	return cmd
}

func identityShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show [name]",
		Short: "Show details for a specific identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			home, _ := os.UserHomeDir()
			keysDir := filepath.Join(home, crypto.MaknoonDir, crypto.KeysDir)

			var basePath string
			if strings.Contains(name, string(os.PathSeparator)) {
				if err := validatePath(name); err != nil {
					return err
				}
				basePath = name
			} else {
				bn := filepath.Base(name)
				if bn == ".." || bn == "." || bn == "/" {
					return fmt.Errorf("invalid identity name")
				}
				basePath = filepath.Join(keysDir, bn)
			}

			pubKeyPath := basePath + ".kem.pub"
			if _, err := os.Stat(pubKeyPath); err != nil {
				return fmt.Errorf("identity '%s' not found", name)
			}

			// Check for hardware binding
			hasFido2 := false
			if _, err := os.Stat(basePath + ".fido2"); err == nil {
				hasFido2 = true
			}

			if JSONOutput {
				printJSON(map[string]interface{}{
					"name":     name,
					"path":     basePath,
					"hardware": hasFido2,
				})
			} else {
				fmt.Printf("Identity: %s\n", name)
				fmt.Printf("Path:     %s\n", basePath)
				fmt.Printf("Hardware: %v\n", hasFido2)
			}
			return nil
		},
	}
	return cmd
}

func identityRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename [old_name] [new_name]",
		Short: "Rename an identity",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			oldName, newName := args[0], args[1]
			home, _ := os.UserHomeDir()
			keysDir := filepath.Join(home, crypto.MaknoonDir, crypto.KeysDir)

			var oldBase, newBase string
			if strings.Contains(oldName, string(os.PathSeparator)) {
				if err := validatePath(oldName); err != nil {
					return err
				}
				oldBase = oldName
			} else {
				ob := filepath.Base(oldName)
				if ob == ".." || ob == "." || ob == "/" {
					return fmt.Errorf("invalid old identity name")
				}
				oldBase = filepath.Join(keysDir, ob)
			}

			if strings.Contains(newName, string(os.PathSeparator)) {
				if err := validatePath(newName); err != nil {
					return err
				}
				newBase = newName
			} else {
				nb := filepath.Base(newName)
				if nb == ".." || nb == "." || nb == "/" {
					return fmt.Errorf("invalid new identity name")
				}
				newBase = filepath.Join(keysDir, nb)
			}

			suffixes := []string{".kem.key", ".kem.pub", ".sig.key", ".sig.pub", ".fido2"}
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

			if JSONOutput {
				printJSON(map[string]string{"status": "success", "from": oldName, "to": newName})
			} else {
				fmt.Printf("Successfully renamed identity '%s' to '%s'\n", oldName, newName)
			}
			return nil
		},
	}
	return cmd
}
