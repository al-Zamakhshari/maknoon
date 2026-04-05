package commands

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/username/maknoon/pkg/crypto"
	"golang.org/x/term"
)

func DecryptCmd() *cobra.Command {
	var output string
	var keyPath string
	var passphrase string

	cmd := &cobra.Command{
		Use:   "decrypt [file]",
		Short: "Decrypt a .makn file or directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inputFile := args[0]
			
			in, err := os.Open(inputFile)
			if err != nil {
				return fmt.Errorf("failed to open input file: %w", err)
			}
			defer in.Close()

			info, err := in.Stat()
			if err != nil {
				return err
			}

			// Determine passphrase
			var password []byte
			if passphrase != "" {
				password = []byte(passphrase)
			} else if envPass := os.Getenv("MAKNOON_PASSPHRASE"); envPass != "" {
				password = []byte(envPass)
			}

			// Peek at the header to determine encryption type
			header := make([]byte, 4)
			if _, err := io.ReadFull(in, header); err != nil {
				return fmt.Errorf("failed to read file header: %w", err)
			}
			if _, err := in.Seek(0, 0); err != nil {
				return fmt.Errorf("failed to reset file pointer: %w", err)
			}

			magic := string(header)
			var flags byte
			var decryptErr error
			pr, pw := io.Pipe()
			bar := progressbar.DefaultBytes(info.Size(), "restoring")

			// Start decryption in a goroutine
			go func() {
				var dErr error
				var f byte
				if magic == crypto.MagicHeader {
					if len(password) == 0 {
						fmt.Print("Enter passphrase: ")
						p, err := term.ReadPassword(int(os.Stdin.Fd()))
						fmt.Println()
						if err != nil {
							pw.CloseWithError(err)
							return
						}
						password = p
					}
					f, dErr = crypto.DecryptStream(io.TeeReader(in, bar), pw, password)
				} else if magic == crypto.MagicHeaderAsym {
					if keyPath == "" {
						pw.CloseWithError(fmt.Errorf("file requires a private key for decryption (use --key)"))
						return
					}
					privKeyBytes, err := os.ReadFile(keyPath)
					if err != nil {
						pw.CloseWithError(err)
						return
					}
					if len(privKeyBytes) > 4 && string(privKeyBytes[:4]) == crypto.MagicHeader {
						privKeyPassword := password
						if len(privKeyPassword) == 0 {
							fmt.Print("Enter passphrase to unlock your private key: ")
							p, err := term.ReadPassword(int(os.Stdin.Fd()))
							fmt.Println()
							if err != nil {
								pw.CloseWithError(err)
								return
							}
							privKeyPassword = p
						}
						var unlockedKey bytes.Buffer
						if _, err := crypto.DecryptStream(bytes.NewReader(privKeyBytes), &unlockedKey, privKeyPassword); err != nil {
							pw.CloseWithError(fmt.Errorf("failed to unlock private key: %w", err))
							return
						}
						privKeyBytes = unlockedKey.Bytes()
					}
					f, dErr = crypto.DecryptStreamWithPrivateKey(io.TeeReader(in, bar), pw, privKeyBytes)
				} else {
					dErr = fmt.Errorf("unsupported or invalid maknoon file header: %s", magic)
				}
				
				// We need to pass the flags out somehow BEFORE the stream finishes
				// But our crypto functions only return them at the end.
				// For now, we rely on the caller to know that handleOutput will read from the pipe.
				flags = f 
				decryptErr = dErr
				pw.Close()
			}()

			// This is still problematic because flags are only known after crypto.DecryptStream returns.
			// Let's modify handleOutput to be a bit more "lazy".
			
			// Actually, the Flag byte is right after the Version byte in the header.
			// Let's just manually read it here to decide the output mode.
			peekBuf := make([]byte, 6)
			io.ReadFull(in, peekBuf)
			in.Seek(0, 0)
			flags = peekBuf[5]

			if flags == crypto.FlagArchive {
				// Directory Extraction
				if output != "" {
					if err := os.MkdirAll(output, 0755); err != nil {
						return err
					}
				}
				tr := tar.NewReader(pr)
				for {
					h, err := tr.Next()
					if err == io.EOF { break }
					if err != nil { return err }
					target := h.Name
					if output != "" { target = filepath.Join(output, h.Name) }
					
					switch h.Typeflag {
					case tar.TypeDir:
						os.MkdirAll(target, 0755)
					case tar.TypeReg:
						os.MkdirAll(filepath.Dir(target), 0755)
						f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(h.Mode))
						if err != nil { return err }
						io.Copy(f, tr)
						f.Close()
					}
				}
			} else {
				// Single File
				outPath := output
				if outPath == "" {
					if strings.HasSuffix(inputFile, ".makn") {
						outPath = strings.TrimSuffix(inputFile, ".makn")
					} else {
						outPath = inputFile + ".dec"
					}
				}
				out, err := os.Create(outPath)
				if err != nil { return err }
				defer out.Close()
				io.Copy(out, pr)
			}

			if decryptErr != nil { return decryptErr }
			fmt.Println("\nDecryption successful!")
			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path or directory")
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", "Path to your private key for asymmetric decryption")
	cmd.Flags().StringVarP(&passphrase, "passphrase", "s", "", "Passphrase for decryption (Avoid for security!)")
	return cmd
}
