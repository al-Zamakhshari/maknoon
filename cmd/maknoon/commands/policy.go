package commands

import (
	"fmt"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// PolicyCmd returns the root command for governance policy management.
func PolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage and sign governance policy files",
	}

	cmd.AddCommand(policySignCmd())
	return cmd
}

func policySignCmd() *cobra.Command {
	var sigKeyPath string
	var passphrase string

	cmd := &cobra.Command{
		Use:   "sign [policy.json]",
		Short: "Sign a governance policy file using an ML-DSA private key",
		Long:  `Generates a detached cryptographic signature (.sig) for a JSON policy file to ensure its integrity and provenance.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitEngine(); err != nil {
				return err
			}
			p := GlobalContext.UI.GetPresenter()
			filePath := args[0]

			if err := validatePath(filePath); err != nil {
				p.RenderError(err)
				return err
			}

			data, err := os.ReadFile(filePath)
			if err != nil {
				p.RenderError(err)
				return err
			}

			// Validate that it's a valid policy JSON before signing
			if _, err := crypto.LoadPolicyFromBytes(data); err != nil {
				p.RenderError(fmt.Errorf("invalid policy JSON: %w", err))
				return err
			}

			// Load the signing key
			keyBytes, err := LoadPrivateKey(sigKeyPath, "MAKNOON_POLICY_SIGNING_KEY", []byte(passphrase))
			if err != nil {
				p.RenderError(err)
				return err
			}
			defer crypto.SafeClear(keyBytes)

			sig, err := GlobalContext.Engine.Sign(nil, data, keyBytes)
			if err != nil {
				p.RenderError(err)
				return err
			}

			sigFile := filePath + ".sig"
			if err := validatePath(sigFile); err != nil {
				p.RenderError(err)
				return err
			}
			if err := os.WriteFile(sigFile, sig, 0600); err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(map[string]string{
					"status":         "success",
					"policy":         filePath,
					"signature_path": sigFile,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("🛡️  Policy signed successfully.\n📄 Policy: %s\n🔏 Signature: %s", filePath, sigFile))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&sigKeyPath, "private-key", "k", "", "Path to the ML-DSA private key for governance signing")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to unlock the private key")
	return cmd
}
