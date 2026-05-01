package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

var (
	sendPassphrase string
	useStealth     bool
	quietSend      bool
	sendText       string
	sendPublicKey  string
	sendTofu       bool
	useP2PMode     bool
	sendTo         string
	sendIdentity   string
)

// SendCmd returns the cobra command for sending files via secure P2P.
func SendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send [file/dir]",
		Short: "Send a file, directory, or text via secure P2P",
		Long:  `Encrypts and transfers data directly to another peer via libp2p.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitEngine(); err != nil {
				return err
			}
			p := GlobalContext.UI.GetPresenter()

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
						p.RenderError(err)
						return err
					}
					info, err := os.Stat(path)
					if err != nil {
						p.RenderError(err)
						return err
					}
					isDir = info.IsDir()
					inputName = filepath.Base(path)
				}
			} else {
				err := fmt.Errorf("either a file path or --text must be provided")
				p.RenderError(err)
				return err
			}

			if GlobalContext.UI.JSON {
				quietSend = true
			}

			opts := crypto.P2PSendOptions{
				Passphrase:  crypto.SecretBytes(sendPassphrase),
				IsDirectory: isDir,
				P2PMode:     true,
				To:          sendTo,
			}

			if cmd.Flags().Changed("stealth") {
				opts.Stealth = crypto.BoolPtr(useStealth)
			}

			if sendPublicKey != "" {
				im := crypto.NewIdentityManager()
				pkBytes, err := im.ResolvePublicKey(sendPublicKey, sendTofu)
				if err != nil {
					p.RenderError(err)
					return err
				}
				opts.PublicKey = pkBytes
				opts.Passphrase = nil
			} else if len(opts.Passphrase) == 0 {
				pass, _ := crypto.GeneratePassphrase(4, "-")
				opts.Passphrase = crypto.SecretBytes(pass)
			}

			code, status, err := GlobalContext.Engine.P2PSend(&crypto.EngineContext{Context: context.Background()}, sendIdentity, inputName, inputReader, opts)
			if err != nil {
				p.RenderError(err)
				return err
			}

			if !quietSend {
				p.RenderMessage(fmt.Sprintf("🚀 P2P Transfer initiated to %s", sendTo))
				p.RenderMessage(fmt.Sprintf("🆔 Your PeerID: %s", code))
				if len(opts.Passphrase) > 0 {
					p.RenderMessage(fmt.Sprintf("👉 Session Passphrase: %s", string(opts.Passphrase)))
				}
			}

			if GlobalContext.UI.JSON {
				p.RenderSuccess(map[string]string{"status": "established", "code": code})
			}

			// Progress loop
			for s := range status {
				if s.Error != nil {
					p.RenderError(s.Error)
					return s.Error
				}
				if !quietSend && s.Phase == "transferring" && s.BytesTotal > 0 {
					// Single line status for human operators
					fmt.Fprintf(os.Stderr, "\r[*] Sending: %s / %s", formatBytes(s.BytesDone), formatBytes(s.BytesTotal))
				}
				if s.Phase == "success" {
					if !quietSend {
						fmt.Fprintln(os.Stderr)
						p.RenderMessage("✨ Transfer complete!")
					}
					if GlobalContext.UI.JSON {
						p.RenderSuccess(map[string]string{"status": "success"})
					}
					break
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&sendPassphrase, "passphrase", "s", "", "Session passphrase (optional)")
	cmd.Flags().BoolVar(&useStealth, "stealth", false, "Use stealth mode (headerless)")
	cmd.Flags().BoolVarP(&quietSend, "quiet", "q", false, "Suppress informational messages")
	cmd.Flags().StringVar(&sendText, "text", "", "Send raw text instead of a file")
	cmd.Flags().StringVarP(&sendPublicKey, "public-key", "p", "", "Encrypt for a specific recipient's identity")
	cmd.Flags().BoolVar(&sendTofu, "trust-on-first-use", false, "Automatically add unknown signers to contacts")
	cmd.Flags().BoolVar(&useP2PMode, "p2p", true, "Use identity-first P2P (libp2p)")
	cmd.Flags().StringVar(&sendTo, "to", "", "Recipient @petname or PeerID")
	cmd.Flags().StringVar(&sendIdentity, "identity", "", "Identity name to use (default: active identity)")

	return cmd
}
