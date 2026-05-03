package commands

import (
	"fmt"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// SignCmd returns the cobra command for signing files.
func SignCmd() *cobra.Command {
	var sigKeyPath string
	var passphrase string

	cmd := &cobra.Command{
		Use:   "sign [file]",
		Short: "Sign a file using an ML-DSA private key",
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

			// Load the private key using the industrial helper
			keyBytes, err := LoadPrivateKey(sigKeyPath, "MAKNOON_PRIVATE_KEY", []byte(passphrase))
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
				p.RenderSuccess(crypto.SignResult{
					Status:        "success",
					SignaturePath: sigFile,
				})
			} else {
				p.RenderMessage(fmt.Sprintf("File signed successfully. Signature saved to %s", sigFile))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&sigKeyPath, "private-key", "k", "", "Path to the ML-DSA private key")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase to unlock the private key")
	return cmd
}
