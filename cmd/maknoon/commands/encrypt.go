package commands

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/username/maknoon/pkg/crypto"
	"golang.org/x/term"
)

// resolveKeyPath checks if a key exists locally, and if not, looks in ~/.maknoon
func resolveKeyPath(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	// Check in ~/.maknoon
	home, _ := os.UserHomeDir()
	maknoonPath := filepath.Join(home, ".maknoon", path)
	if _, err := os.Stat(maknoonPath); err == nil {
		return maknoonPath
	}
	return path // Fallback to original
}

func EncryptCmd() *cobra.Command {
	var output string
	var pubKeyPath string
	var passphrase string
	var compress bool

	cmd := &cobra.Command{
		Use:   "encrypt [file/dir]",
		Short: "Encrypt a file or directory symmetrically or asymmetrically",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inputPath := args[0]
			
			stat, err := os.Stat(inputPath)
			if err != nil {
				return fmt.Errorf("failed to access input path: %w", err)
			}

			outPath := output
			if outPath == "" {
				outPath = inputPath + ".makn"
			}
			out, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer out.Close()

			flags := crypto.FlagNone
			if stat.IsDir() {
				flags |= crypto.FlagArchive
			}
			if compress {
				flags |= crypto.FlagCompress
			}

			// Prepare the data source
			var sourceReader io.Reader
			var totalSize int64

			if stat.IsDir() {
				totalSize = -1 // TAR overhead is unpredictable
				pr, pw := io.Pipe()
				sourceReader = pr
				go func() {
					tw := tar.NewWriter(pw)
					baseDir := filepath.Dir(filepath.Clean(inputPath))
					err := filepath.Walk(inputPath, func(path string, info os.FileInfo, err error) error {
						if err != nil { return err }
						rel, err := filepath.Rel(baseDir, path)
						if err != nil { return err }
						header, err := tar.FileInfoHeader(info, "")
						if err != nil { return err }
						header.Name = rel
						if err := tw.WriteHeader(header); err != nil { return err }
						if !info.IsDir() {
							f, err := os.Open(path)
							if err != nil { return err }
							defer f.Close()
							_, err = io.Copy(tw, f)
							return err
						}
						return nil
					})
					tw.Close()
					pw.CloseWithError(err)
				}()
			} else {
				f, err := os.Open(inputPath)
				if err != nil { return fmt.Errorf("failed to open input file: %w", err) }
				defer f.Close()
				sourceReader = f
				totalSize = stat.Size()
			}

			// Wrap sourceReader with Compression if requested
			var finalReader io.Reader = sourceReader
			if compress {
				pr, pw := io.Pipe()
				finalReader = pr
				go func() {
					zw, _ := zstd.NewWriter(pw)
					_, err := io.Copy(zw, sourceReader)
					zw.Close()
					pw.CloseWithError(err)
				}()
			}

			// Determine passphrase if needed
			var password []byte
			if pubKeyPath == "" {
				if passphrase != "" {
					password = []byte(passphrase)
				} else if envPass := os.Getenv("MAKNOON_PASSPHRASE"); envPass != "" {
					password = []byte(envPass)
				} else {
					fmt.Print("Enter passphrase: ")
					p, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil { return err }
					password = p

					fmt.Print("Confirm passphrase: ")
					confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil { return err }
					if string(password) != string(confirm) {
						return fmt.Errorf("passphrases do not match")
					}
				}
				defer func() {
					for i := range password { password[i] = 0 }
				}()
			}

			bar := progressbar.DefaultBytes(totalSize, "preserving")
			var encErr error
			if pubKeyPath != "" {
				resolvedPath := resolveKeyPath(pubKeyPath)
				pubKeyBytes, err := os.ReadFile(resolvedPath)
				if err != nil { return fmt.Errorf("failed to read public key: %w", err) }
				fmt.Printf("Encrypting '%s' using public key '%s'...\n", inputPath, resolvedPath)
				encErr = crypto.EncryptStreamWithPublicKey(io.TeeReader(finalReader, bar), out, pubKeyBytes, flags)
			} else {
				fmt.Printf("Encrypting '%s' using passphrase...\n", inputPath)
				encErr = crypto.EncryptStream(io.TeeReader(finalReader, bar), out, password, flags)
			}

			if encErr != nil { return fmt.Errorf("encryption failed: %w", encErr) }
			fmt.Println("\nEncryption successful! Data is now Maknoon (carefully preserved).")
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (default is input.makn)")
	cmd.Flags().StringVarP(&pubKeyPath, "public-key", "p", "", "Path to the recipient's public key for asymmetric encryption")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for symmetric encryption (Avoid for security!)")
	cmd.Flags().BoolVarP(&compress, "compress", "c", false, "Enable Zstd compression before encryption")
	return cmd
}
