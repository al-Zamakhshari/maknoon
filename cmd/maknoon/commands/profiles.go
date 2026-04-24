package commands

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// ProfilesCmd returns the cobra command for managing cryptographic profiles.
func ProfilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "Manage and list cryptographic profiles",
		Run: func(cmd *cobra.Command, args []string) {
			// Default behavior: list built-in and custom profiles
			printProfiles()
		},
	}

	cmd.AddCommand(profilesListCmd())
	cmd.AddCommand(profilesGenCmd())
	cmd.AddCommand(profilesRmCmd())

	return cmd
}

func printProfiles() {
	fmt.Println("🛡️  Maknoon Cryptographic Profiles")
	fmt.Println("\nBuilt-in Profiles:")
	fmt.Println("  nist (1):         NIST PQC (Kyber1024 + Dilithium87) + XChaCha20-Poly1305 (Default)")
	fmt.Println("  aes (2):          NIST PQC (Kyber1024 + Dilithium87) + AES-256-GCM")
	fmt.Println("  conservative (3): FrodoKEM-640 + SLH-DSA-SHA2-128s (Non-Lattice)")

	conf := crypto.GetGlobalConfig()
	if len(conf.Profiles) > 0 {
		fmt.Println("\nCustom Profiles (Stored in Config):")
		var names []string
		for name := range conf.Profiles {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			p := conf.Profiles[name]
			cipherName := "XChaCha20"
			if p.CipherType == crypto.AlgoAES256GCM {
				cipherName = "AES-GCM"
			} else if p.CipherType == crypto.AlgoAES256GCMSIV {
				cipherName = "AES-GCM-SIV"
			}
			fmt.Printf("  %-15s (%d): %s + Argon2id\n", name, p.CustomID, cipherName)
		}
	}

	fmt.Println("\nUse 'maknoon profiles gen <name>' to create a new random, validated profile.")
}

func profilesListCmd() *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all available profiles with detailed parameters",
		Run: func(_ *cobra.Command, _ []string) {
			conf := crypto.GetGlobalConfig()

			if JSONOutput {
				type profileInfo struct {
					Name        string                 `json:"name"`
					ID          byte                   `json:"id"`
					Description string                 `json:"description,omitempty"`
					Details     *crypto.DynamicProfile `json:"details,omitempty"`
				}
				var list []profileInfo
				list = append(list, profileInfo{Name: "nist", ID: 1, Description: "NIST PQC (Lattice-based)"})
				list = append(list, profileInfo{Name: "aes", ID: 2, Description: "NIST PQC + AES-GCM"})
				list = append(list, profileInfo{Name: "conservative", ID: 3, Description: "Non-Lattice PQC"})

				for name, p := range conf.Profiles {
					list = append(list, profileInfo{Name: name, ID: p.CustomID, Details: p})
				}
				printJSON(list)
				return
			}

			fmt.Printf("%-20s %-5s %-15s %-30s\n", "NAME", "ID", "CIPHER", "KDF SETTINGS")
			fmt.Println("------------------------------------------------------------------------------------------")
			fmt.Printf("%-20s %-5d %-15s %-30s\n", "nist", 1, "XChaCha20", "Argon2id (Default)")
			fmt.Printf("%-20s %-5d %-15s %-30s\n", "aes", 2, "AES-GCM", "Argon2id (Default)")
			fmt.Printf("%-20s %-5d %-15s %-30s\n", "conservative", 3, "XChaCha20", "Argon2id (Default)")

			var names []string
			for name := range conf.Profiles {
				names = append(names, name)
			}
			sort.Strings(names)

			for _, name := range names {
				p := conf.Profiles[name]
				cipherName := "XChaCha20"
				if p.CipherType == crypto.AlgoAES256GCM {
					cipherName = "AES-GCM"
				} else if p.CipherType == crypto.AlgoAES256GCMSIV {
					cipherName = "AES-GCM-SIV"
				}

				kdfStr := fmt.Sprintf("Argon2id (t=%d, m=%dKB, p=%d)", p.ArgonTime, p.ArgonMem, p.ArgonThrd)
				fmt.Printf("%-20s %-5d %-15s %-30s\n", name, p.CustomID, cipherName, kdfStr)
			}
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed parameters")
	return cmd
}

func profilesGenCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gen <name>",
		Short: "Generate a new random, validated profile and save it to config",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			conf := crypto.GetGlobalConfig()

			// Check for reserved names
			reserved := map[string]bool{"nist": true, "aes": true, "conservative": true, "pq": true, "legacy": true, "hardened": true}
			if reserved[name] {
				return fmt.Errorf("name '%s' is reserved", name)
			}

			if _, exists := conf.Profiles[name]; exists {
				return fmt.Errorf("profile '%s' already exists", name)
			}

			// Find next available ID (4-127)
			usedIDs := make(map[byte]bool)
			usedIDs[1] = true
			usedIDs[2] = true
			usedIDs[3] = true
			for _, p := range conf.Profiles {
				usedIDs[p.CustomID] = true
			}

			var nextID byte = 0
			for i := byte(4); i < 128; i++ {
				if !usedIDs[i] {
					nextID = i
					break
				}
			}

			if nextID == 0 {
				return fmt.Errorf("no available profile IDs (4-127 reached limit)")
			}

			// Generate random profile via engine
			dp := GlobalContext.Engine.GenerateRandomProfile(nil, nextID)

			// Static & Policy Validation via engine
			if err := GlobalContext.Engine.ValidateProfile(nil, dp); err != nil {
				return fmt.Errorf("generated invalid profile: %w", err)
			}

			// 2. Runtime Smoke Test (Ultimate Validation)
			if err := verifyProfile(dp); err != nil {
				return fmt.Errorf("profile failed functional smoke test (impossible combination): %w", err)
			}

			if !GlobalContext.Engine.GetPolicy().AllowConfigModification() && !JSONOutput {
				return fmt.Errorf("saving profiles to config is prohibited under the active policy (%s) (use --json to generate an ephemeral profile)", GlobalContext.Engine.GetPolicy().Name())
			}

			// Register/Save to config (Engine handles policy check)
			if err := GlobalContext.Engine.RegisterProfile(nil, name, dp); err != nil {
				// If policy blocked it, we still want to output the ephemeral profile if in JSON mode
				if JSONOutput && crypto.As(err, new(*crypto.ErrPolicyViolation)) {
					printJSON(dp)
					return nil
				}
				return fmt.Errorf("failed to register profile: %w", err)
			}

			if JSONOutput {
				printJSON(dp)
			} else {
				fmt.Printf("Successfully generated and saved profile '%s' (ID: %d)\n", name, nextID)
				fmt.Println("Review the parameters in ~/.maknoon/config.json or using 'maknoon profiles list'.")
			}
			return nil
		},
	}
}

func profilesRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "rm <name>",
		Short:             "Remove a custom profile from config",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeProfiles,
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			if err := GlobalContext.Engine.RemoveProfile(nil, name); err != nil {
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{"status": "success", "removed": name})
			} else {
				fmt.Printf("Successfully removed profile '%s' from config.\n", name)
			}
			return nil
		},
	}
}

// verifyProfile performs an end-to-end encryption/decryption round-trip to ensure the profile is functional.
func verifyProfile(p *crypto.DynamicProfile) error {
	// Temporarily register the profile so the crypto engine can find it
	crypto.RegisterProfile(p)

	canary := []byte("ultimate-validation-canary-data")
	passphrase := []byte("smoke-test-pass")

	// 1. Encrypt
	var encrypted bytes.Buffer
	if err := crypto.EncryptStream(bytes.NewReader(canary), &encrypted, passphrase, crypto.FlagNone, 1, p.ID()); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// 2. Decrypt
	var decrypted bytes.Buffer
	if _, _, err := crypto.DecryptStream(bytes.NewReader(encrypted.Bytes()), &decrypted, passphrase, 1, false); err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// 3. Verify
	if !bytes.Equal(canary, decrypted.Bytes()) {
		return fmt.Errorf("data corruption detected during smoke test")
	}

	return nil
}
