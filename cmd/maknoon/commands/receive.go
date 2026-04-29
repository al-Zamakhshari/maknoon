package commands

import (
	"context"
	"fmt"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	recvOutput     string
	recvPassphrase string
	recvStealth    bool
	quietRecv      bool
	recvPrivateKey string
	recvP2PMode    bool
	recvIdentity   string
)

// ReceiveCmd returns the cobra command for receiving files via secure P2P.
func ReceiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "receive [peer_id]",
		Short: "Receive a file, directory, or text via secure P2P",
		Long:  `Downloads and decrypts data directly from a peer via libp2p.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitEngine(); err != nil {
				return err
			}

			var code string
			if len(args) > 0 {
				code = args[0]
			}

			if JSONOutput {
				quietRecv = true
			}

			opts := crypto.P2PReceiveOptions{
				Passphrase: []byte(recvPassphrase),
				Stealth:    recvStealth,
				OutputDir:  recvOutput,
				P2PMode:    true,
			}

			if recvPrivateKey != "" {
				m := crypto.NewIdentityManager()
				resolvedPriv := m.ResolveKeyPath(recvPrivateKey, "MAKNOON_PRIVATE_KEY")
				if resolvedPriv == "" {
					return fmt.Errorf("private key required for identity-based P2P")
				}
				privBytes, err := m.LoadPrivateKey(resolvedPriv, []byte(recvPassphrase), "", false)
				if err != nil {
					return err
				}
				opts.PrivateKey = privBytes
			}

			status, err := GlobalContext.Engine.P2PReceive(&crypto.EngineContext{Context: context.Background()}, recvIdentity, code, opts)
			if err != nil {
				return err
			}

			var bar *progressbar.ProgressBar
			for s := range status {
				if s.Error != nil {
					return s.Error
				}
				if !quietRecv {
					if s.Phase == "connecting" && s.Code != "" {
						fmt.Printf("🕳️  Waiting for peer. Share your PeerID: %s\n", s.Code)
					}
					if bar == nil && s.BytesTotal > 0 {
						bar = progressbar.DefaultBytes(s.BytesTotal, "receiving")
					}
					if bar != nil && s.BytesDone > 0 {
						_ = bar.Set64(s.BytesDone)
					}
				}
				if s.Phase == "success" {
					if !quietRecv {
						fmt.Printf("\n✨ Success! Data saved to: %s\n", s.FileName)
					}
					if JSONOutput {
						printJSON(map[string]string{"status": "success", "file": s.FileName})
					}
					break
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&recvOutput, "output", "o", "", "Output path or directory")
	cmd.Flags().StringVarP(&recvPassphrase, "passphrase", "s", "", "Session passphrase")
	cmd.Flags().BoolVar(&recvStealth, "stealth", false, "Decrypt as stealth mode")
	cmd.Flags().BoolVarP(&quietRecv, "quiet", "q", false, "Suppress informational messages")
	cmd.Flags().StringVarP(&recvPrivateKey, "private-key", "k", "", "Path to your private key")
	cmd.Flags().BoolVar(&recvP2PMode, "p2p", true, "Use identity-first P2P (libp2p)")
	cmd.Flags().StringVar(&recvIdentity, "identity", "", "Identity name to use (default: active identity)")

	return cmd
}
