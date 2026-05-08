package commands

import (
	"fmt"
	"io"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// FragmentCmd returns the root command for data fragmentation.
func FragmentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fragment [file]",
		Short: "Split a file into redundant erasure-coded fragments (RAID-for-Privacy)",
		Long:  `Breaks a file into multiple redundant shards using Reed-Solomon erasure coding. The original data can be reconstructed from a subset of the fragments.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitEngine(); err != nil {
				return err
			}
			p := GlobalContext.UI.GetPresenter()
			filePath := args[0]

			dataShards, _ := cmd.Flags().GetInt("data")
			parityShards, _ := cmd.Flags().GetInt("parity")
			outDir, _ := cmd.Flags().GetString("output")
			sigKeyPath, _ := cmd.Flags().GetString("sign-with")
			passphrase, _ := cmd.Flags().GetString("passphrase")

			if outDir == "" {
				outDir = filePath + "_fragments"
			}

			if err := validatePath(filePath); err != nil {
				p.RenderError(err)
				return err
			}

			fi, err := os.Stat(filePath)
			if err != nil {
				p.RenderError(err)
				return err
			}

			f, err := os.Open(filePath)
			if err != nil {
				p.RenderError(err)
				return err
			}
			defer f.Close()

			var sigKey []byte
			if sigKeyPath != "" {
				sigKey, err = LoadPrivateKey(sigKeyPath, "MAKNOON_FRAGMENT_SIGNING_KEY", []byte(passphrase))
				if err != nil {
					p.RenderError(err)
					return err
				}
				defer crypto.SafeClear(sigKey)
			}

			opts := crypto.FragmentOptions{
				DataShards:   dataShards,
				ParityShards: parityShards,
				TargetDir:    outDir,
				OriginalSize: fi.Size(),
				SigningKey:   sigKey,
			}

			fw, err := crypto.NewFragmentWriter(opts)
			if err != nil {
				p.RenderError(err)
				return err
			}
			defer fw.Close()

			if _, err := io.Copy(fw, f); err != nil {
				p.RenderError(err)
				return err
			}

			p.RenderMessage(fmt.Sprintf("✨ File fragmented successfully into %d shards (%d data + %d parity).\n📂 Output Directory: %s", dataShards+parityShards, dataShards, parityShards, outDir))
			return nil
		},
	}

	cmd.Flags().IntP("data", "d", 5, "Number of data shards")
	cmd.Flags().IntP("parity", "r", 3, "Number of parity shards (redundancy)")
	cmd.Flags().StringP("output", "o", "", "Output directory for fragments")
	cmd.Flags().String("sign-with", "", "ML-DSA private key to sign each fragment block")
	cmd.Flags().StringP("passphrase", "s", "", "Passphrase for the signing key")

	return cmd
}

// ReassembleCmd returns the root command for data reassembly.
func ReassembleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reassemble [dir]",
		Short: "Reconstruct a file from fragments",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitEngine(); err != nil {
				return err
			}
			p := GlobalContext.UI.GetPresenter()
			srcDir := args[0]
			outPath, _ := cmd.Flags().GetString("output")
			authKeyPath, _ := cmd.Flags().GetString("authorized-key")

			if outPath == "" {
				outPath = "restored.data"
			}

			var authKey []byte
			if authKeyPath != "" {
				var err error
				authKey, err = os.ReadFile(authKeyPath)
				if err != nil {
					p.RenderError(err)
					return err
				}
			}

			f, err := os.Create(outPath)
			if err != nil {
				p.RenderError(err)
				return err
			}
			defer f.Close()

			if err := crypto.ReassembleFragments(srcDir, f, authKey); err != nil {
				p.RenderError(err)
				return err
			}

			p.RenderMessage(fmt.Sprintf("✅ File reconstructed successfully.\n📄 Output: %s", outPath))
			return nil
		},
	}

	cmd.Flags().StringP("output", "o", "", "Path to save the reconstructed file")
	cmd.Flags().String("authorized-key", "", "ML-DSA public key to verify fragment integrity")

	return cmd
}
