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
	chatSignKey string
)

// ChatCmd returns the cobra command for ghost chat.
func ChatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chat [id|@petname]",
		Short: "Start a secure, identity-bound Ghost Chat session (Agent Mode)",
		Long:  `Opens a real-time, end-to-end encrypted P2P data pipe using JSON events over libp2p.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgentChat(args)
		},
	}

	cmd.Flags().StringVar(&chatSignKey, "identity", "", "Local identity name to use for the session")

	return cmd
}

// --- Agent Mode (JSONL REPL) ---

func runAgentChat(args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := GlobalContext.UI.GetPresenter()

	var target string
	if len(args) > 0 {
		target = args[0]
	}

	sess, err := GlobalContext.Engine.ChatStart(&crypto.EngineContext{Context: ctx}, chatSignKey, target)
	if err != nil {
		p.RenderError(err)
		return nil
	}

	p.RenderSuccess(map[string]interface{}{
		"event":      "status",
		"state":      "established",
		"peer_id":    sess.Host.ID().String(),
		"multiaddrs": sess.Multiaddrs(),
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
		p.RenderSuccess(ev)
	}

	return nil
}
