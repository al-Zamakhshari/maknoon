package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/psanford/wormhole-william/wormhole"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	sendPassphrase string
	useStealth     bool
	quietSend      bool
)

// SendCmd returns the cobra command for sending files via ephemeral P2P.
func SendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send [file/dir]",
		Short: "Send a file or directory via secure ephemeral P2P",
		Long:  `Encrypts and transfers data directly to another peer. Data is never stored on a relay.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			isDir := info.IsDir()

			if JSONOutput {
				quietSend = true
			}

			if !quietSend {
				fmt.Printf("🚀 Preparing to send: %s\n", filepath.Base(path))
			}

			// 1. Create a temporary encrypted file (Zero-trace effort)
			tmpEnc, err := os.CreateTemp("", "maknoon-send-*.makn")
			if err != nil {
				return err
			}
			tmpPath := tmpEnc.Name()
			defer func() {
				_ = tmpEnc.Close()
				_ = os.Remove(tmpPath)
			}()

			opts := crypto.Options{
				Passphrase: []byte(sendPassphrase),
				Stealth:    useStealth,
				Compress:   true,
				IsArchive:  isDir,
			}

			// If no passphrase provided, generate a random one for this session
			if len(opts.Passphrase) == 0 {
				p, _ := crypto.GeneratePassphrase(4, "-")
				opts.Passphrase = []byte(p)
			}

			if !quietSend {
				fmt.Println("🔒 Encrypting...")
			}
			if _, err := crypto.Protect(path, nil, tmpEnc, opts); err != nil {
				return err
			}

			// Get size for progress bar
			tmpInfo, _ := tmpEnc.Stat()
			totalSize := tmpInfo.Size()

			// Seek back to start for wormhole
			if _, err := tmpEnc.Seek(0, 0); err != nil {
				return err
			}

			// 2. Initialize Wormhole Client
			var c wormhole.Client
			ctx := context.Background()

			if !quietSend {
				fmt.Println("🕳️  Opening wormhole...")
			}

			fileName := filepath.Base(path)
			if isDir {
				fileName += ".makn"
			}

			var reader io.Reader = tmpEnc
			if !quietSend {
				bar := progressbar.DefaultBytes(totalSize, "sending")
				reader = io.TeeReader(tmpEnc, bar)
			}

			code, status, err := c.SendFile(ctx, fileName, struct {
				io.Reader
				io.Seeker
			}{reader, tmpEnc})
			if err != nil {
				return err
			}

			if JSONOutput {
				printJSON(map[string]string{
					"code":       code,
					"passphrase": string(opts.Passphrase),
					"status":     "established",
				})
			} else {
				fmt.Printf("\n✅ Wormhole established!\n")
				fmt.Printf("🔑 Receiver Code: %s\n", code)
				fmt.Printf("👉 Session Passphrase: %s\n\n", string(opts.Passphrase))
				fmt.Printf("Share these with the recipient. The transfer will begin once they enter them.\n")
			}

			s := <-status
			if s.Error != nil {
				if JSONOutput {
					printErrorJSON(s.Error)
					return nil
				}
				return fmt.Errorf("transfer failed: %w", s.Error)
			}

			if s.OK {
				if JSONOutput {
					printJSON(map[string]string{"status": "success"})
				} else {
					fmt.Println("\n✨ Transfer complete! The wormhole has closed.")
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&sendPassphrase, "passphrase", "s", "", "Session passphrase (optional, one will be generated if omitted)")
	cmd.Flags().BoolVar(&useStealth, "stealth", false, "Use stealth mode (headerless)")
	cmd.Flags().BoolVarP(&quietSend, "quiet", "q", false, "Suppress informational messages")

	return cmd
}
