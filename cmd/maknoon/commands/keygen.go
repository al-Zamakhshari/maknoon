package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// KeygenCmd returns the cobra command for generating Post-Quantum identities.
func KeygenCmd() *cobra.Command {
	var output string
	var noPassword bool
	var passphrase string
	var useFido2 bool
	var quiet bool
	var profileStr string
	var profileFile string

	// KDF overrides
	var argonTime uint32
	var argonMem uint32
	var argonThrd uint8

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a Post-Quantum (KEM & SIG) identity",
		RunE: func(_ *cobra.Command, _ []string) error {
			var fido2Meta *crypto.Fido2Metadata
			var password []byte
			var err error

			if profileFile != "" {
				dp, err := GlobalContext.Engine.LoadCustomProfile(nil, profileFile)
				if err != nil {
					if JSONOutput {
						printErrorJSON(err)
						return err
					}
					return err
				}
				profileStr = fmt.Sprintf("%d", dp.ID())
			}

			profileID := byte(1)
			if profileStr != "" {
				var err error
				profileID, err = resolveProfile(profileStr)
				if err != nil {
					if JSONOutput {
						printErrorJSON(err)
						return nil
					}
					return err
				}
			}

			// Apply KDF Overrides to default profile if requested
			if argonTime != 3 || argonMem != 64*1024 || argonThrd != 4 {
				if p1, err := crypto.GetProfile(1, nil); err == nil {
					if v1, ok := p1.(*crypto.ProfileV1); ok {
						v1.ArgonTime = argonTime
						v1.ArgonMem = argonMem
						v1.ArgonThrd = argonThrd
					}
				}
			}

			if useFido2 {
				pin, err := getPIN()
				if err != nil {
					return err
				}
				meta, secret, err := crypto.Fido2Enroll("maknoon.io", "keygen-user", pin)
				if err != nil {
					if JSONOutput {
						printErrorJSON(err)
						return err
					}
					return err
				}
				fido2Meta = meta
				password = secret
			} else {
				password, err = getInitialPassphrase(noPassword, passphrase)
				if err != nil {
					if JSONOutput {
						printErrorJSON(err)
						return err
					}
					return err
				}
			}

			if len(password) > 0 {
				defer crypto.SafeClear(password)
			}

			if err := crypto.EnsureMaknoonDirs(); err != nil {
				return err
			}

			if !JSONOutput && !quiet {
				pName := "Hybrid Post-Quantum"
				if profileID == 3 {
					pName = "Conservative (Non-Lattice)"
				}
				fmt.Printf("Generating bleeding-edge %s identity...\n", pName)
			}

			res, err := GlobalContext.Engine.CreateIdentity(nil, output, password, "", false, profileStr)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}

			if fido2Meta != nil {
				raw, err := json.Marshal(fido2Meta)
				if err != nil {
					err := fmt.Errorf("failed to marshal fido2 metadata: %w", err)
					if JSONOutput {
						printErrorJSON(err)
						return err
					}
					return err
				}
				if err := os.WriteFile(res.BasePath+".fido2", raw, 0644); err != nil {
					err := fmt.Errorf("failed to write fido2 metadata: %w", err)
					if JSONOutput {
						printErrorJSON(err)
						return err
					}
					return err
				}
			}

			if !JSONOutput && !quiet {
				fmt.Printf("Success! Identity generated in %s\n", filepath.Dir(res.BasePath))
				fmt.Printf("  - Encryption Keys: %s.kem.{key,pub}\n", res.BaseName)
				fmt.Printf("  - Signing Keys:    %s.sig.{key,pub}\n", res.BaseName)
				fmt.Printf("  - Nostr Keys:      %s.nostr.{key,pub}\n", res.BaseName)
			}

			if JSONOutput {
				printJSON(res)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Base name or path for the keys")
	cmd.Flags().BoolVarP(&noPassword, "no-password", "n", false, "Generate unprotected keys (automation mode)")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to protect the keys")
	cmd.Flags().BoolVarP(&useFido2, "fido2", "f", false, "Use FIDO2 security key to protect the private keys")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress informational output")
	cmd.Flags().StringVar(&profileStr, "profile", "nist", "Cryptographic profile (nist, aes, conservative)")
	cmd.Flags().StringVar(&profileFile, "profile-file", "", "Path to a custom profile JSON file to protect the keys")

	_ = cmd.RegisterFlagCompletionFunc("profile", completeProfiles)

	// KDF Flags
	cmd.Flags().Uint32Var(&argonTime, "argon-time", 3, "Argon2id iterations")
	cmd.Flags().Uint32Var(&argonMem, "argon-mem", 64*1024, "Argon2id memory in KB")
	cmd.Flags().Uint8Var(&argonThrd, "argon-threads", 4, "Argon2id parallel threads")

	return cmd
}

func getInitialPassphrase(noPassword bool, manual string) ([]byte, error) {
	if noPassword {
		return nil, nil
	}
	if manual != "" {
		return []byte(manual), nil
	}

	p, interactive, err := getPassphrase("Enter passphrase to protect your private keys: ")
	if err != nil {
		return nil, err
	}

	if interactive && len(p) > 0 {
		fmt.Print("Confirm passphrase: ")
		confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			crypto.SafeClear(p)
			return nil, err
		}
		defer crypto.SafeClear(confirm)

		if string(p) != string(confirm) {
			crypto.SafeClear(p)
			return nil, fmt.Errorf("passphrases do not match")
		}
	}
	return p, nil
}
