package commands

import (
	"bytes"
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
	var profile int
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
				if err := loadCustomProfile(profileFile, &profile); err != nil {
					if JSONOutput {
						printErrorJSON(err)
						return err
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
				meta, secret, err := crypto.Fido2Enroll("maknoon.io", "keygen-user")
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

			if !JSONOutput && !quiet {
				fmt.Println("Generating bleeding-edge Hybrid Post-Quantum identity (ML-KEM-768-X25519 + ML-DSA-87 + Nostr)...")
			}
			kemPub, kemPriv, sigPub, sigPriv, nostrPub, nostrPriv, err := crypto.GeneratePQKeyPair()
			if err != nil {
				err := fmt.Errorf("failed to generate keypairs: %w", err)
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}

			defer func() {
				crypto.SafeClear(kemPriv)
				crypto.SafeClear(sigPriv)
				crypto.SafeClear(nostrPriv)
			}()

			im := crypto.NewIdentityManager()
			basePath, baseName, err := im.ResolveBaseKeyPath(output)
			if err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return err
			}
			if err := writeIdentityKeys(basePath, baseName, kemPub, kemPriv, sigPub, sigPriv, nostrPub, nostrPriv, password, byte(profile)); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
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
				if err := os.WriteFile(basePath+".fido2", raw, 0644); err != nil {
					err := fmt.Errorf("failed to write fido2 metadata: %w", err)
					if JSONOutput {
						printErrorJSON(err)
						return err
					}
					return err
				}
			}

			if !JSONOutput && !quiet {
				fmt.Printf("Success! Identity generated in %s\n", filepath.Dir(basePath))
				fmt.Printf("  - Encryption Keys: %s.kem.{key,pub}\n", baseName)
				fmt.Printf("  - Signing Keys:    %s.sig.{key,pub}\n", baseName)
				fmt.Printf("  - Nostr Keys:      %s.nostr.{key,pub}\n", baseName)
			}

			if JSONOutput {
				printJSON(crypto.IdentityResult{
					Status:   "success",
					BasePath: basePath,
					BaseName: baseName,
				})
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Base name or path for the keys")
	cmd.Flags().BoolVarP(&noPassword, "no-password", "n", false, "Generate unprotected keys (automation mode)")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to protect the keys")
	cmd.Flags().BoolVarP(&useFido2, "fido2", "f", false, "Use FIDO2 security key to protect the private keys")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress informational output")
	cmd.Flags().IntVar(&profile, "profile", 1, "Cryptographic profile ID to protect the keys")
	cmd.Flags().StringVar(&profileFile, "profile-file", "", "Path to a custom profile JSON file to protect the keys")

	// KDF Flags
	cmd.Flags().Uint32Var(&argonTime, "argon-time", 3, "Argon2id iterations")
	cmd.Flags().Uint32Var(&argonMem, "argon-mem", 64*1024, "Argon2id memory in KB")
	cmd.Flags().Uint8Var(&argonThrd, "argon-threads", 4, "Argon2id parallel threads")

	return cmd
}

func getInitialPassphrase(noPassword bool, manual string) ([]byte, error) {
	if noPassword {
		if !JSONOutput {
			fmt.Println("Generating unprotected keypair (Automation Mode)...")
		}
		return nil, nil
	}
	if manual != "" {
		return []byte(manual), nil
	}
	if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
		return []byte(env), nil
	}

	if JSONOutput {
		return nil, fmt.Errorf("passphrase required via MAKNOON_PASSPHRASE or -s in JSON mode")
	}

	fmt.Print("Enter passphrase to protect your private keys: ")
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}

	if len(p) > 0 {
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

func writeIdentityKeys(basePath, baseName string, kemPub, kemPriv, sigPub, sigPriv, nostrPub, nostrPriv, password []byte, profileID byte) error {
	writeKey := func(path string, data []byte, isPrivate bool) error {
		if len(data) == 0 {
			return nil
		}
		finalData := data
		if isPrivate && len(password) > 0 {
			var b bytes.Buffer
			if err := crypto.EncryptStream(bytes.NewReader(data), &b, password, crypto.FlagNone, 1, profileID); err != nil {
				return err
			}
			finalData = b.Bytes()
		}
		mode := os.FileMode(0644)
		if isPrivate {
			mode = 0600
		}
		return os.WriteFile(path, finalData, mode)
	}

	if err := writeKey(basePath+".kem.key", kemPriv, true); err != nil {
		return err
	}
	if err := writeKey(basePath+".kem.pub", kemPub, false); err != nil {
		return err
	}
	if err := writeKey(basePath+".sig.key", sigPriv, true); err != nil {
		return err
	}
	if err := writeKey(basePath+".sig.pub", sigPub, false); err != nil {
		return err
	}
	if err := writeKey(basePath+".nostr.key", nostrPriv, true); err != nil {
		return err
	}
	if err := writeKey(basePath+".nostr.pub", nostrPub, false); err != nil {
		return err
	}
	return nil
}
