package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/psanford/wormhole-william/wormhole"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	sendPassphrase string
	useStealth     bool
	quietSend      bool
	sendText       string
	sendPublicKey  string
	rendezvousURL  string
	transitRelay   string
	sendTofu       bool
)

// SendCmd returns the cobra command for sending files via ephemeral P2P.
func SendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send [file/dir]",
		Short: "Send a file, directory, or text via secure ephemeral P2P",
		Long:  `Encrypts and transfers data directly to another peer. Data is never stored on a relay.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var path string
			var isDir bool
			var inputReader io.Reader
			var inputName string

			if sendText != "" {
				inputReader = strings.NewReader(sendText)
				inputName = "text-message"
			} else if len(args) > 0 {
				path = args[0]
				if path == "-" {
					inputReader = os.Stdin
					inputName = "stdin"
				} else {
					if err := validatePath(path); err != nil {
						return err
					}
					info, err := os.Stat(path)
					if err != nil {
						return err
					}
					isDir = info.IsDir()
					inputName = filepath.Base(path)
				}
			} else {
				return fmt.Errorf("either a file path or --text must be provided")
			}

			if JSONOutput {
				quietSend = true
			}

			if !quietSend {
				fmt.Printf("🚀 Preparing to send: %s\n", inputName)
			}

			// 1. Encrypt (to RAM if small enough, otherwise to temp file)
			var tmpReader io.ReadSeeker
			var tmpFile *os.File
			var totalSize int64

			opts := crypto.Options{
				Passphrase: []byte(sendPassphrase),
				Stealth:    useStealth,
				Compress:   true,
				IsArchive:  isDir,
			}

			if sendPublicKey != "" {
				im := crypto.NewIdentityManager()
				pkBytes, err := im.ResolvePublicKey(sendPublicKey, sendTofu)
				if err != nil {
					return err
				}
				opts.PublicKey = pkBytes
				opts.Passphrase = nil // Clear passphrase for asymmetric mode
			} else if len(opts.Passphrase) == 0 {
				p, _ := crypto.GeneratePassphrase(4, "-")
				opts.Passphrase = []byte(p)
			}

			if !quietSend {
				fmt.Println("🔒 Encrypting...")
			}

			// For text and small stdin, use memory. For files and large stdin, use temp file.
			if sendText != "" {
				var encBuf bytes.Buffer
				if _, err := crypto.Protect(inputName, inputReader, &encBuf, opts); err != nil {
					return err
				}
				totalSize = int64(encBuf.Len())
				tmpReader = bytes.NewReader(encBuf.Bytes())
			} else {
				tmpEnc, err := os.CreateTemp("", "maknoon-send-*.makn")
				if err != nil {
					return err
				}
				tmpFile = tmpEnc
				defer func() {
					_ = tmpFile.Close()
					_ = os.Remove(tmpFile.Name())
				}()

				if _, err := crypto.Protect(path, inputReader, tmpFile, opts); err != nil {
					return err
				}
				stat, _ := tmpFile.Stat()
				totalSize = stat.Size()
				if _, err := tmpFile.Seek(0, 0); err != nil {
					return err
				}
				tmpReader = tmpFile
			}

			// 2. Initialize Wormhole Client
			conf := crypto.GetGlobalConfig()
			if rendezvousURL == "" {
				rendezvousURL = conf.Wormhole.RendezvousURL
			}
			if transitRelay == "" {
				transitRelay = conf.Wormhole.TransitRelay
			}

			// Validate URLs if in Agent Mode
			if err := GlobalContext.Engine.ValidateWormholeURL(rendezvousURL); err != nil {
				return err
			}
			if err := GlobalContext.Engine.ValidateWormholeURL(transitRelay); err != nil {
				return err
			}

			c := wormhole.Client{
				RendezvousURL: rendezvousURL,
			}
			if transitRelay != "" {
				c.TransitRelayAddress = transitRelay
			}
			ctx := context.Background()

			if !quietSend {
				fmt.Println("🕳️  Opening wormhole...")
			}

			fileName := inputName
			if isDir || !strings.HasSuffix(fileName, ".makn") {
				fileName += ".makn"
			}

			var wormholeReader io.Reader = tmpReader
			if !quietSend {
				bar := progressbar.DefaultBytes(totalSize, "sending")
				wormholeReader = io.TeeReader(tmpReader, bar)
			}

			code, status, err := c.SendFile(ctx, fileName, struct {
				io.Reader
				io.Seeker
			}{wormholeReader, tmpReader})
			if err != nil {
				return err
			}

			if JSONOutput {
				res := map[string]string{
					"code":   code,
					"status": "established",
				}
				if len(opts.Passphrase) > 0 {
					res["passphrase"] = string(opts.Passphrase)
				} else {
					res["type"] = "asymmetric"
				}
				printJSON(res)
			} else {
				fmt.Printf("\n✅ Wormhole established!\n")
				fmt.Printf("🔑 Receiver Code: %s\n", code)
				if len(opts.Passphrase) > 0 {
					fmt.Printf("👉 Session Passphrase: %s\n\n", string(opts.Passphrase))
					fmt.Printf("Share these with the recipient. The transfer will begin once they enter them.\n")
				} else {
					fmt.Printf("🛡️  Encrypted for recipient's identity. No passphrase required.\n\n")
					fmt.Printf("Share this code with the recipient. They will need their private key to decrypt.\n")
				}
			}

			s := <-status
			if s.Error != nil {
				if JSONOutput {
					printErrorJSON(s.Error)
					return s.Error
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
	cmd.Flags().StringVar(&sendText, "text", "", "Send raw text instead of a file")
	cmd.Flags().StringVarP(&sendPublicKey, "public-key", "p", "", "Encrypt for a specific recipient's identity (bypasses passphrase)")
	cmd.Flags().BoolVar(&sendTofu, "trust-on-first-use", false, "Automatically add unknown signers to contacts")
	cmd.Flags().StringVar(&rendezvousURL, "rendezvous-url", "", "Custom Magic Wormhole rendezvous server URL")
	cmd.Flags().StringVar(&transitRelay, "transit-relay", "", "Custom Magic Wormhole transit relay address (host:port)")

	return cmd
}
