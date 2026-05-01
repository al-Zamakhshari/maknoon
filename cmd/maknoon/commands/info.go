package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// InfoCmd returns the cobra command for inspecting Maknoon files.
func InfoCmd() *cobra.Command {
	var stealth bool
	cmd := &cobra.Command{
		Use:   "info [file]",
		Short: "Inspect a Maknoon encrypted file's metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			p := GlobalContext.UI.GetPresenter()
			filePath := args[0]
			if err := validatePath(filePath); err != nil {
				p.RenderError(err)
				return err
			}
			f, err := os.Open(filePath)
			if err != nil {
				p.RenderError(err)
				return err
			}
			defer f.Close()

			ectx := &crypto.EngineContext{
				Context: context.Background(),
				Policy:  &crypto.HumanPolicy{}, // Or appropriate policy
			}

			info, err := GlobalContext.Engine.Inspect(ectx, f, stealth)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(info)
				return nil
			}

			fmt.Printf("File: %s\n", filePath)
			fmt.Printf("----------------------------------------\n")

			switch info.Type {
			case "symmetric":
				fmt.Println("Type:           Symmetric (Passphrase Protected)")
			case "asymmetric":
				fmt.Println("Type:           Asymmetric (Public Key Protected)")
			case "stealth":
				fmt.Println("Type:           Stealth (Fingerprint Resistant)")
			default:
				fmt.Printf("Type:           %s\n", info.Type)
			}

			fmt.Printf("Profile ID:     %d\n", info.ProfileID)
			fmt.Printf("Compression:    %v\n", info.Compressed)
			fmt.Printf("Archive:        %v\n", info.IsArchive)
			fmt.Printf("Signed:         %v\n", info.IsSigned)

			if info.KEMAlgorithm != "" {
				fmt.Printf("KEM Algorithm:  %s\n", info.KEMAlgorithm)
			}
			if info.SIGAlgorithm != "" {
				fmt.Printf("SIG Algorithm:  %s\n", info.SIGAlgorithm)
			}
			if info.KDFDetails != "" {
				fmt.Printf("KDF Algorithm:  %s\n", info.KDFDetails)
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&stealth, "stealth", false, "Enable fingerprint resistance (headerless)")
	cmd.Flags().BoolVar(&JSONOutput, "json", false, "Output results in JSON format")
	return cmd
}
