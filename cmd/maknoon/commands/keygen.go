package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/a-khallaf/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// KeygenCmd returns the cobra command for generating Post-Quantum identities.
func KeygenCmd() *cobra.Command {
	var output string
	var noPassword bool
	var passphrase string
	var useFido2 bool

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a Post-Quantum (KEM & SIG) identity",
		RunE: func(_ *cobra.Command, _ []string) error {
			var fido2Meta *crypto.Fido2Metadata
			var password []byte
			var err error

			if useFido2 {
				meta, secret, err := crypto.Fido2Enroll("maknoon.io", "keygen-user")
				if err != nil {
					return err
				}
				fido2Meta = meta
				password = secret
			} else {
				password, err = getInitialPassphrase(noPassword, passphrase)
				if err != nil {
					return err
				}
			}

			if len(password) > 0 {
				defer crypto.SafeClear(password)
			}

			fmt.Println("Generating bleeding-edge Post-Quantum identity (Kyber1024 + ML-DSA-87)...")
			kemPub, kemPriv, sigPub, sigPriv, err := crypto.GeneratePQKeyPair()
			if err != nil {
				return fmt.Errorf("failed to generate keypairs: %w", err)
			}

			defer func() {
				crypto.SafeClear(kemPriv)
				crypto.SafeClear(sigPriv)
			}()

			basePath, baseName := resolveBaseKeyPath(output)
			if err := writeIdentityKeys(basePath, baseName, kemPub, kemPriv, sigPub, sigPriv, password); err != nil {
				return err
			}

			if fido2Meta != nil {
				raw, _ := json.Marshal(fido2Meta)
				os.WriteFile(basePath+".fido2", raw, 0644)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Base name or path for the keys")
	cmd.Flags().BoolVarP(&noPassword, "no-password", "n", false, "Generate unprotected keys (automation mode)")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to protect the keys")
	cmd.Flags().BoolVarP(&useFido2, "fido2", "f", false, "Use FIDO2 security key to protect the private keys")
	return cmd
}

func getInitialPassphrase(noPassword bool, manual string) ([]byte, error) {
	if noPassword {
		fmt.Println("Generating unprotected keypair (Automation Mode)...")
		return nil, nil
	}
	if manual != "" {
		return []byte(manual), nil
	}
	if env := os.Getenv("MAKNOON_PASSPHRASE"); env != "" {
		return []byte(env), nil
	}

	fmt.Print("Enter passphrase to protect your private keys: ")
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return nil, err
	}

	if len(p) > 0 {
		fmt.Print("Confirm passphrase: ")
		confirm, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if string(p) != string(confirm) {
			return nil, fmt.Errorf("passphrases do not match")
		}
	}
	return p, nil
}

func resolveBaseKeyPath(output string) (string, string) {
	home, _ := os.UserHomeDir()
	keysDir := filepath.Join(home, ".maknoon", "keys")
	os.MkdirAll(keysDir, 0700)

	baseName := "id_maknoon"
	if output != "" {
		baseName = output
	}

	basePath := filepath.Join(keysDir, baseName)
	if output != "" && (filepath.IsAbs(output) || strings.Contains(output, string(os.PathSeparator))) {
		basePath = output
		baseName = filepath.Base(output)
	}
	return basePath, baseName
}

func writeIdentityKeys(basePath, baseName string, kemPub, kemPriv, sigPub, sigPriv, password []byte) error {
	writeKey := func(path string, data []byte, isPrivate bool) error {
		finalData := data
		if isPrivate && len(password) > 0 {
			var b bytes.Buffer
			if err := crypto.EncryptStream(bytes.NewReader(data), &b, password, crypto.FlagNone, 1); err != nil {
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

	fmt.Printf("Success! Identity generated in %s\n", filepath.Dir(basePath))
	fmt.Printf("  - Encryption Keys: %s.kem.{key,pub}\n", baseName)
	fmt.Printf("  - Signing Keys:    %s.sig.{key,pub}\n", baseName)
	return nil
}
