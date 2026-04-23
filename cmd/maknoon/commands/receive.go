package commands

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/psanford/wormhole-william/wormhole"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	recvOutput        string
	recvPassphrase    string
	recvStealth       bool
	quietRecv         bool
	recvPrivateKey    string
	recvRendezvousURL string
	recvTransitRelay  string
)

// ReceiveCmd returns the cobra command for receiving files via ephemeral P2P.
func ReceiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "receive [code]",
		Short: "Receive a file, directory, or text via secure ephemeral P2P",
		Long:  `Downloads and decrypts data directly from a peer.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			code := args[0]

			conf := crypto.GetGlobalConfig()
			if recvRendezvousURL == "" {
				recvRendezvousURL = conf.Wormhole.RendezvousURL
			}
			if recvTransitRelay == "" {
				recvTransitRelay = conf.Wormhole.TransitRelay
			}

			// Validate URLs if in Agent Mode
			if err := GlobalContext.Engine.ValidateWormholeURL(recvRendezvousURL); err != nil {
				return err
			}
			if err := GlobalContext.Engine.ValidateWormholeURL(recvTransitRelay); err != nil {
				return err
			}

			c := wormhole.Client{
				RendezvousURL: recvRendezvousURL,
			}
			if recvTransitRelay != "" {
				c.TransitRelayAddress = recvTransitRelay
			}
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

			// 2. Peek at the header to get type and flags
			if _, err := tmpFile.Seek(0, 0); err != nil {
				return err
			}
			magic, _, flags, _, err := crypto.ReadHeader(tmpFile, recvStealth)
			if err != nil {
				return fmt.Errorf("failed to read file header: %w", err)
			}

			// 3. Resolve key (Asymmetric or Symmetric)
			var passBytes []byte
			var privKeyBytes []byte

			if magic == crypto.MagicHeaderAsym {
				if !quietRecv {
					fmt.Println("🛡️  Detected Identity-based encryption.")
				}

				m := crypto.NewIdentityManager()
				resolvedPriv := m.ResolveKeyPath(recvPrivateKey, "MAKNOON_PRIVATE_KEY")
				if resolvedPriv == "" {
					return fmt.Errorf("private key required for identity-based P2P (use -k or MAKNOON_PRIVATE_KEY)")
				}

				// Check for FIDO2 and get PIN if needed
				var pin string
				if _, err := os.Stat(strings.TrimSuffix(resolvedPriv, ".key") + ".fido2"); err == nil {
					var err2 error
					pin, err2 = getPIN()
					if err2 != nil {
						return err2
					}
				}

				privKeyBytes, err = m.LoadPrivateKey(resolvedPriv, []byte(recvPassphrase), pin, false)
				if err != nil {
					return err
				}
				defer crypto.SafeClear(privKeyBytes)
			} else {
				if recvPassphrase == "" {
					var err error
					passBytes, _, err = getPassphrase("Enter P2P session passphrase: ")
					if err != nil {
						return err
					}
				} else {
					passBytes = []byte(recvPassphrase)
				}
				defer crypto.SafeClear(passBytes)
			}

			// Seek back to start after peeking/key resolution
			if _, err := tmpFile.Seek(0, 0); err != nil {
				return err
			}

			if !quietRecv {
				fmt.Println("🔓 Decrypting...")
			}

			// Set output name if not provided
			finalOut := recvOutput
			if finalOut == "" {
				// SECURITY: Sanitize the peer-provided filename to prevent path traversal
				safeName := filepath.Base(msg.Name)
				finalOut = strings.TrimSuffix(safeName, ".makn")
			}

			if err := validatePath(finalOut); err != nil {
				return err
			}

			if finalOut == "-" {
				oldWriter := GlobalContext.JSONWriter
				GlobalContext.JSONWriter = os.Stderr
				defer func() { GlobalContext.JSONWriter = oldWriter }()
			}

			// Use pipe to bridge DecryptStream and FinalizeRestoration
			pr, pw := io.Pipe()
			go func() {
				defer pw.Close()
				var dErr error
				if privKeyBytes != nil {
					_, _, dErr = crypto.DecryptStreamWithPrivateKeyAndEvents(tmpFile, pw, privKeyBytes, nil, 0, recvStealth, nil)
				} else {
					_, _, dErr = crypto.DecryptStreamWithEvents(tmpFile, pw, passBytes, 0, recvStealth, nil)
				}
				if dErr != nil {
					_ = pw.CloseWithError(dErr)
				}
			}()

			if err := crypto.FinalizeRestoration(pr, nil, flags, finalOut, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
				if JSONOutput {
					printErrorJSON(err)
					return err
				}
				return fmt.Errorf("restoration failed: %w", err)
			}

			if JSONOutput {
				printJSON(crypto.CommonResult{
					Status:  "success",
					Message: fmt.Sprintf("Data saved to: %s", finalOut),
				})
			} else {
				fmt.Printf("\n✨ Success! Data saved to: %s\n", finalOut)
			}
			return nil

		},
	}

	cmd.Flags().StringVarP(&recvOutput, "output", "o", "", "Output path or directory (use - for stdout)")
	cmd.Flags().StringVarP(&recvPassphrase, "passphrase", "s", "", "Session passphrase (for symmetric mode)")
	cmd.Flags().BoolVar(&recvStealth, "stealth", false, "Decrypt as stealth mode")
	cmd.Flags().BoolVarP(&quietRecv, "quiet", "q", false, "Suppress informational messages")
	cmd.Flags().StringVarP(&recvPrivateKey, "private-key", "k", "", "Path to your private key (for identity-based mode)")
	cmd.Flags().StringVar(&recvRendezvousURL, "rendezvous-url", "", "Custom Magic Wormhole rendezvous server URL")
	cmd.Flags().StringVar(&recvTransitRelay, "transit-relay", "", "Custom Magic Wormhole transit relay address (host:port)")

	return cmd
}
