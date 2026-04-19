package commands

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/psanford/wormhole-william/wormhole"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	recvOutput     string
	recvPassphrase string
	recvStealth    bool
	quietRecv      bool
)

// ReceiveCmd returns the cobra command for receiving files via ephemeral P2P.
func ReceiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "receive [code]",
		Short: "Receive a file or directory via secure ephemeral P2P",
		Long:  `Downloads and decrypts a file directly from a peer.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code := args[0]

			var c wormhole.Client
			ctx := context.Background()

			if JSONOutput {
				quietRecv = true
			}

			if !quietRecv {
				fmt.Println("🕳️  Connecting to wormhole...")
			}
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
					"transfer_bytes": msg.TransferBytes64,
				})
			} else {
				fmt.Printf("📥 Incoming: %s (%d bytes)\n", msg.Name, msg.TransferBytes64)
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

			var proxyReader io.Reader = msg
			if !quietRecv {
				bar := progressbar.DefaultBytes(msg.TransferBytes64, "downloading")
				proxyReader = io.TeeReader(msg, bar)
			}

			if _, err := io.Copy(tmpFile, proxyReader); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return fmt.Errorf("download failed: %w", err)
			}

			// 2. Decrypt
			if recvPassphrase == "" {
				if JSONOutput {
					printErrorJSON(fmt.Errorf("session passphrase required via --passphrase"))
					return nil
				}
				fmt.Printf("\n🔐 Enter session passphrase: ")
				fmt.Scanln(&recvPassphrase)
			}

			// 1. Peek at the header to get flags (compression, etc)
			if _, err := tmpFile.Seek(0, 0); err != nil {
				return err
			}
			_, _, flags, err := crypto.ReadHeader(tmpFile, recvStealth)
			if err != nil {
				return fmt.Errorf("failed to read file header: %w", err)
			}

			// Seek back to start after peeking
			if _, err := tmpFile.Seek(0, 0); err != nil {
				return err
			}

			if !quietRecv {
				fmt.Println("🔓 Decrypting...")
			}

			// Set output name if not provided
			finalOut := recvOutput
			if finalOut == "" {
				finalOut = strings.TrimSuffix(msg.Name, ".makn")
			}

			if err := validatePath(finalOut); err != nil {
				return err
			}

			// Use pipe to bridge DecryptStream and finalizeDecryption
			pr, pw := io.Pipe()
			var dErr error
			go func() {
				defer pw.Close()
				_, dErr = crypto.DecryptStream(tmpFile, pw, []byte(recvPassphrase), 0, recvStealth)
				if dErr != nil {
					_ = pw.CloseWithError(dErr)
				}
			}()

			if finalOut == "-" {
				// If we are outputting to stdout, we MUST send JSON status to stderr
				// to avoid corrupting the raw data stream.
				oldWriter := GlobalContext.JSONWriter
				GlobalContext.JSONWriter = os.Stderr
				defer func() { GlobalContext.JSONWriter = oldWriter }()
			}

			if err := crypto.FinalizeRestoration(pr, flags, finalOut, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return fmt.Errorf("decryption failed (check passphrase): %w", err)
			}

			if JSONOutput {
				printJSON(map[string]string{
					"status": "success",
					"path":   finalOut,
				})
			} else {
				fmt.Printf("\n✨ Success! Data saved to: %s\n", finalOut)
			}
			return nil

		},
	}

	cmd.Flags().StringVarP(&recvOutput, "output", "o", "", "Output path or directory")
	cmd.Flags().StringVarP(&recvPassphrase, "passphrase", "s", "", "Session passphrase")
	cmd.Flags().BoolVar(&recvStealth, "stealth", false, "Decrypt as stealth mode")
	cmd.Flags().BoolVarP(&quietRecv, "quiet", "q", false, "Suppress informational messages")

	return cmd
}
