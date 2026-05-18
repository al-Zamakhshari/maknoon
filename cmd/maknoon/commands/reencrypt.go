package commands

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

// ReencryptCmd returns the cobra command for in-place profile migration.
func ReencryptCmd() *cobra.Command {
	var outputPath string
	var targetProfile int
	var passFlag string

	cmd := &cobra.Command{
		Use:   "reencrypt <file>",
		Short: "Re-encrypt a file with a different cryptographic profile",
		Long: `Re-encrypt an existing .makn file using a different profile ID.

The file is decrypted using its current profile, then immediately re-encrypted
with the target profile. This enables migration from the default NIST profile (1)
to the conservative non-lattice profile (3) or any custom profile.

Example:
  maknoon reencrypt secret.makn --profile 3 --passphrase oldpass`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			checkJSONMode(cmd)
			p := GlobalContext.UI.GetPresenter()

			inputPath := args[0]

			// Peek at the header to show the current profile ID
			f, err := os.Open(inputPath)
			if err != nil {
				return fmt.Errorf("cannot open input file: %w", err)
			}
			_, currentProfile, _, _, err := crypto.ReadHeader(f, false)
			f.Close()
			if err != nil {
				return fmt.Errorf("cannot read file header: %w", err)
			}

			if int(currentProfile) == targetProfile {
				if JSONOutput {
					printJSON(map[string]any{
						"status":  "noop",
						"message": fmt.Sprintf("file is already using profile %d", targetProfile),
					})
				} else {
					fmt.Printf("ℹ️  File is already using profile %d — nothing to do.\n", targetProfile)
				}
				return nil
			}

			// Collect passphrase (flag or interactive prompt)
			var passphrase []byte
			if passFlag != "" {
				passphrase = []byte(passFlag)
			} else {
				var err2 error
				passphrase, _, err2 = getPassphrase("Enter passphrase: ")
				if err2 != nil {
					return fmt.Errorf("failed to read passphrase: %w", err2)
				}
			}
			defer crypto.SafeClear(passphrase)

			// Step 1: Decrypt to a memory buffer
			in, err := os.Open(inputPath)
			if err != nil {
				return fmt.Errorf("cannot open input file: %w", err)
			}
			defer in.Close()

			var plaintext bytes.Buffer
			if _, err := GlobalContext.Engine.Unprotect(nil, in, &plaintext, "", crypto.Options{
				Passphrase: passphrase,
			}); err != nil {
				return fmt.Errorf("decryption failed: %w", err)
			}
			in.Close()

			// Step 2: Determine output path
			dest := outputPath
			if dest == "" {
				dest = inputPath // overwrite in-place
			}
			// Write atomically via a temp file in the same directory
			dir := filepath.Dir(dest)
			tmpFile, err := os.CreateTemp(dir, ".reencrypt-*.tmp")
			if err != nil {
				return fmt.Errorf("cannot create temp file: %w", err)
			}
			tmpPath := tmpFile.Name()
			defer os.Remove(tmpPath) // cleaned up on error

			profileID := byte(targetProfile)
			_, err = GlobalContext.Engine.Protect(nil, inputPath, bytes.NewReader(plaintext.Bytes()), tmpFile, crypto.Options{
				Passphrase: passphrase,
				ProfileID:  &profileID,
			})
			tmpFile.Close()
			if err != nil {
				return fmt.Errorf("re-encryption failed: %w", err)
			}

			// Atomic rename
			if err := os.Rename(tmpPath, dest); err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}

			result := map[string]any{
				"status":       "success",
				"input":        inputPath,
				"output":       dest,
				"from_profile": currentProfile,
				"to_profile":   targetProfile,
			}

			p.RenderSuccess(result)

			if !JSONOutput {
				fmt.Printf("✅ Re-encrypted: profile %d → %d\n    Input:  %s\n    Output: %s\n",
					currentProfile, targetProfile, inputPath, dest)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file path (default: overwrite input in-place)")
	cmd.Flags().IntVarP(&targetProfile, "profile", "p", 3, "Target profile ID (1=NIST, 3=Conservative/FrodoKEM)")
	cmd.Flags().StringVar(&passFlag, "passphrase", "", "Passphrase (omit for interactive prompt)")

	return cmd
}

// reencryptReader is a helper used by the REST handler.
func reencryptReader(r io.Reader, passphrase []byte, targetProfileID byte) (io.Reader, error) {
	var plaintext bytes.Buffer
	if _, err := GlobalContext.Engine.Unprotect(nil, r, &plaintext, "", crypto.Options{
		Passphrase: passphrase,
	}); err != nil {
		return nil, err
	}

	var reenc bytes.Buffer
	if _, err := GlobalContext.Engine.Protect(nil, "reencrypt", bytes.NewReader(plaintext.Bytes()), &reenc, crypto.Options{
		Passphrase: passphrase,
		ProfileID:  &targetProfileID,
	}); err != nil {
		return nil, err
	}
	return &reenc, nil
}
