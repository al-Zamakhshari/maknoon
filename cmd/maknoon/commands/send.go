package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/psanford/wormhole-william/wormhole"
	"github.com/spf13/cobra"
)

var (
	sendPassphrase string
	useStealth     bool
)

// SendCmd returns the cobra command for sending files via ephemeral P2P.
func SendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send [file]",
		Short: "Send a file via secure ephemeral P2P (Magic Wormhole style)",
		Long:  `Encrypts and transfers a file directly to another peer. Data is never stored on a relay.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return fmt.Errorf("directories are not yet supported for P2P send")
			}

			fmt.Printf("🚀 Preparing to send: %s\n", filepath.Base(path))

			// 1. Create a temporary encrypted file (Zero-trace effort)
			// TODO: Optimize with memory-only ReadSeeker if possible.
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
			}

			// If no passphrase provided, generate a random one for this session
			if len(opts.Passphrase) == 0 {
				p, _ := crypto.GeneratePassphrase(4, "-")
				opts.Passphrase = []byte(p)
			}

			fmt.Println("🔒 Encrypting...")
			if err := crypto.Protect(path, nil, tmpEnc, opts); err != nil {
				return err
			}

			// Seek back to start for wormhole
			if _, err := tmpEnc.Seek(0, 0); err != nil {
				return err
			}

			// 2. Initialize Wormhole Client
			var c wormhole.Client
			ctx := context.Background()

			fmt.Println("🕳️  Opening wormhole...")
			code, status, err := c.SendFile(ctx, filepath.Base(path)+".makn", tmpEnc)
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
				fmt.Printf("🔑 Receiver Code: %s\n\n", code)
				fmt.Printf("Share this code with the recipient. The transfer will begin once they enter it.\n")
				fmt.Printf("The file is encrypted with the following session passphrase:\n")
				fmt.Printf("👉 %s\n\n", string(opts.Passphrase))
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

	return cmd
}
