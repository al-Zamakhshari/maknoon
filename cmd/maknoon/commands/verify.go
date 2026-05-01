package commands

import (
	"fmt"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// VerifyCmd returns the cobra command for verifying digital signatures.
func VerifyCmd() *cobra.Command {
	var pubKeyPath string
	var signaturePath string

	cmd := &cobra.Command{
		Use:   "verify [file]",
		Short: "Verify a file's integrity and signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
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

			if signaturePath == "" {
				signaturePath = filePath + ".sig"
			}
			sigBytes, err := os.ReadFile(signaturePath)
			if err != nil {
				err := fmt.Errorf("signature file not found: %w", err)
				p.RenderError(err)
				return err
			}

			pubKeyBytes, err := GlobalContext.Engine.ResolvePublicKey(nil, pubKeyPath, false)
			if err != nil {
				p.RenderError(err)
				return err
			}

			valid, err := GlobalContext.Engine.Verify(nil, data, sigBytes, pubKeyBytes)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if valid {
				if GlobalContext.UI.JSON {
					p.RenderSuccess(crypto.VerifyResult{Status: "success", Verified: true})
				} else {
					p.RenderMessage("✅ Signature Verified! The data is authentic and has not been tampered with.")
				}
			} else {
				err := fmt.Errorf("❌ Signature Verification FAILED! The data might be corrupted or from an untrusted source")
				p.RenderError(err)
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&pubKeyPath, "public-key", "p", "", "Path to the ML-DSA public key")
	cmd.Flags().StringVarP(&signaturePath, "signature", "g", "", "Path to the signature file (defaults to file.sig)")
	return cmd
}
