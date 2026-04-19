package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/psanford/wormhole-william/wormhole"
	"github.com/spf13/cobra"
)

var (
	recvOutput     string
	recvPassphrase string
	recvStealth    bool
)

// ReceiveCmd returns the cobra command for receiving files via ephemeral P2P.
func ReceiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "receive [code]",
		Short: "Receive a file via secure ephemeral P2P",
		Long:  `Downloads and decrypts a file directly from a peer.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code := args[0]

			var c wormhole.Client
			ctx := context.Background()

			fmt.Println("🕳️  Connecting to wormhole...")
			msg, err := c.Receive(ctx, code)
			if err != nil {
				return err
			}

			if msg.Type != wormhole.TransferFile {
				return fmt.Errorf("unexpected message type from wormhole: %v", msg.Type)
			}

			if JSONOutput {
				printJSON(map[string]interface{}{
					"status":         "connected",
					"file_name":      msg.Name,
					"transfer_bytes": msg.TransferBytes,
				})
			} else {
				fmt.Printf("📥 Incoming file: %s (%d bytes)\n", msg.Name, msg.TransferBytes)
			}

			// 1. Download to a temporary file
			tmpFile, err := os.CreateTemp("", "maknoon-recv-*.makn")
			if err != nil {
				return err
			}
			tmpPath := tmpFile.Name()
			defer func() {
				_ = tmpFile.Close()
				_ = os.Remove(tmpPath)
			}()

			if !JSONOutput {
				fmt.Println("⏳ Downloading...")
			}
			if _, err := io.Copy(tmpFile, msg); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return fmt.Errorf("download failed: %w", err)
			}

			// 2. Decrypt
			if recvPassphrase == "" {
				if JSONOutput {
					printErrorJSON(fmt.Errorf("session passphrase required via --passphrase"))
					return nil
				}
				fmt.Printf("\n🔐 Enter session passphrase to decrypt: ")
				fmt.Scanln(&recvPassphrase)
			}

			// Set output name if not provided
			finalOut := recvOutput
			if finalOut == "" {
				finalOut = strings.TrimSuffix(msg.Name, ".makn")
			}

			if !JSONOutput {
				fmt.Println("🔓 Decrypting...")
			}

			// We need to read from the start of the temp file
			if _, err := tmpFile.Seek(0, 0); err != nil {
				return err
			}

			// Open output file
			outF, err := os.Create(finalOut)
			if err != nil {
				return err
			}
			defer outF.Close()

			// We need a profile or passphrase
			// For simplicity, we use the standard symmetric flow
			if _, err := crypto.DecryptStream(tmpFile, outF, []byte(recvPassphrase), 0, recvStealth); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return nil
				}
				return fmt.Errorf("decryption failed (check passphrase): %w", err)
			}

			if JSONOutput {
				printJSON(map[string]string{
					"status": "success",
					"path":   finalOut,
				})
			} else {
				fmt.Printf("\n✨ Success! File saved to: %s\n", finalOut)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&recvOutput, "output", "o", "", "Output path")
	cmd.Flags().StringVarP(&recvPassphrase, "passphrase", "s", "", "Session passphrase")
	cmd.Flags().BoolVar(&recvStealth, "stealth", false, "Decrypt as stealth mode")

	return cmd
}
