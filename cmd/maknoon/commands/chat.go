package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"os"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/spf13/cobra"
)

var (
	chatPassphrase  string
	chatSignKey     string
	chatRendezvous  string
	chatTransitAddr string
)

const chatAppID = "maknoon.io/ghost-chat/v1"

// ChatCmd returns the cobra command for ghost chat.
func ChatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chat [code]",
		Short: "Start a secure, headless Ghost Chat session (Agent Mode)",
		Long:  `Opens a real-time, end-to-end encrypted P2P data pipe using JSON events. Optimized for AI agents and automation.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgentChat(args)
		},
	}

	cmd.Flags().StringVarP(&chatPassphrase, "passphrase", "s", "", "Shared secret for the chat (optional)")
	cmd.Flags().StringVar(&chatSignKey, "sign-key", "", "Path to your private key for message signing")
	cmd.Flags().StringVar(&chatRendezvous, "rendezvous-url", "", "Custom Magic Wormhole rendezvous server URL")
	cmd.Flags().StringVar(&chatTransitAddr, "transit-relay", "", "Custom Magic Wormhole transit relay address")

	return cmd
}

// --- Agent Mode (JSONL REPL) ---

func runAgentChat(args []string) error {
	conf := crypto.GetGlobalConfig()
	if chatRendezvous == "" {
		chatRendezvous = conf.Wormhole.RendezvousURL
	}
	if chatTransitAddr == "" {
		chatTransitAddr = conf.Wormhole.TransitRelay
	}

	// Validate URLs if in Agent Mode
	if err := GlobalContext.Engine.ValidateWormholeURL(chatRendezvous); err != nil {
		return err
	}
	if err := GlobalContext.Engine.ValidateWormholeURL(chatTransitAddr); err != nil {
		return err
	}

	sess := crypto.NewChatSession(chatAppID)
	sess.RendezvousURL = chatRendezvous
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var code string
	var err error
	if len(args) > 0 {
		code = args[0]
		err = sess.StartJoin(ctx, code)
	} else {
		code, err = sess.StartHost(ctx)
	}

	if err != nil {
		printErrorJSON(err)
		return err
	}

	printJSON(map[string]interface{}{
		"event": "status",
		"state": "established",
		"code":  code,
	})

	// Input loop
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			var cmd map[string]interface{}
			if err := json.Unmarshal(scanner.Bytes(), &cmd); err != nil {
				continue
			}
			if action, _ := cmd["action"].(string); action == "send" {
				if text, ok := cmd["text"].(string); ok {
					_ = sess.Send(ctx, text)
				}
			} else if action == "quit" {
				sess.Close()
				os.Exit(0)
			}
		}
	}()

	// Event loop
	for ev := range sess.Events {
		printJSON(ev)
	}

	return nil
}
