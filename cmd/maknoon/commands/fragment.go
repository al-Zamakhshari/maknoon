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
		Short: "Split a file into erasure-coded fragments",
		Long: `Breaks a file into redundant shards using Reed-Solomon erasure coding.
The original data can be reconstructed from any N data shards out of N+M total.

Designed to compose with rclone for cloud distribution:

  # Fragment and upload shards to three different clouds
  maknoon fragment secret.makn --data 5 --parity 3 \
    --output /tmp/shards/ --output-manifest ~/manifests/secret.json

  rclone copy /tmp/shards/ s3:bucket/shards/
  rclone copy /tmp/shards/ gcs:bucket/shards/
  rclone copy /tmp/shards/ azure:container/shards/
  maknoon shred /tmp/shards/

  # Recovery: fetch any 5+ shards, reassemble, verify
  rclone copy s3:bucket/shards/ /tmp/recover/
  maknoon reassemble /tmp/recover/ --output secret.makn --verify`,
		Args: cobra.ExactArgs(1),
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
			manifestPath, _ := cmd.Flags().GetString("output-manifest")

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

			hash, _ := crypto.HashFile(filePath)
			opts := crypto.FragmentOptions{
				DataShards:   dataShards,
				ParityShards: parityShards,
				TargetDir:    outDir,
				OriginalSize: fi.Size(),
				OriginalName: fi.Name(),
				OriginalHash: hash,
				SigningKey:   sigKey,
				ManifestPath: manifestPath,
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

			msg := fmt.Sprintf("✨ Fragmented into %d shards (%d data + %d parity)\n📂 Shards: %s",
				dataShards+parityShards, dataShards, parityShards, outDir)
			if manifestPath != "" {
				msg += fmt.Sprintf("\n📋 Manifest: %s", manifestPath)
			} else {
				msg += fmt.Sprintf("\n📋 Manifest: %s/manifest.json", outDir)
			}
			p.RenderMessage(msg)
			return nil
		},
	}

	cmd.Flags().IntP("data", "d", 5, "Number of data shards")
	cmd.Flags().IntP("parity", "r", 3, "Number of parity shards (redundancy)")
	cmd.Flags().StringP("output", "o", "", "Output directory for shards")
	cmd.Flags().String("output-manifest", "", "Write manifest to this path instead of alongside shards (useful with rclone)")
	cmd.Flags().String("sign-with", "", "ML-DSA private key to sign each shard block")
	cmd.Flags().StringP("passphrase", "s", "", "Passphrase for the signing key")

	return cmd
}

// ReassembleCmd returns the root command for data reassembly.
func ReassembleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reassemble [dir]",
		Short: "Reconstruct a file from fragments",
		Long: `Reconstructs the original file from a directory of .maknf shard files.
Requires at least N data shards (as specified during fragmentation).

Use --verify to check the output SHA-256 against the hash stored in manifest.json,
confirming the reconstruction is byte-perfect:

  maknoon reassemble /tmp/recover/ --output secret.makn --verify`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitEngine(); err != nil {
				return err
			}
			p := GlobalContext.UI.GetPresenter()
			srcDir := args[0]
			outPath, _ := cmd.Flags().GetString("output")
			authKeyPath, _ := cmd.Flags().GetString("authorized-key")
			verify, _ := cmd.Flags().GetBool("verify")

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
			f.Close() // flush before hashing

			if verify {
				if err := crypto.VerifyReassembly(srcDir, outPath); err != nil {
					p.RenderError(err)
					return err
				}
				p.RenderMessage(fmt.Sprintf("✅ Reconstructed and verified.\n📄 Output: %s", outPath))
			} else {
				p.RenderMessage(fmt.Sprintf("✅ File reconstructed successfully.\n📄 Output: %s", outPath))
			}
			return nil
		},
	}

	cmd.Flags().StringP("output", "o", "", "Path to save the reconstructed file")
	cmd.Flags().String("authorized-key", "", "ML-DSA public key to verify shard integrity")
	cmd.Flags().Bool("verify", false, "Verify output SHA-256 against manifest.json (recommended)")

	return cmd
}
