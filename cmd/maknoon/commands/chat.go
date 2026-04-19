package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/charmbracelet/lipgloss"
	"github.com/chzyer/readline"
	"github.com/spf13/cobra"
)

var (
	chatPassphrase string
	chatSignKey    string
)

const chatAppID = "maknoon.io/ghost-chat/v1"

// ChatCmd returns the cobra command for ghost chat.
func ChatCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chat [code]",
		Short: "Start a secure, ephemeral Ghost Chat session",
		Long:  `Opens a real-time, end-to-end encrypted P2P chat room. Zero permanent logs.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if JSONOutput {
				return runAgentChat(args)
			}
			return runLineChat(args)
		},
	}

	cmd.Flags().StringVarP(&chatPassphrase, "passphrase", "s", "", "Shared secret for the chat (optional)")
	cmd.Flags().StringVar(&chatSignKey, "sign-key", "", "Path to your private key for message signing")

	return cmd
}

// --- Agent Mode (JSONL REPL) ---

func runAgentChat(args []string) error {
	sess := crypto.NewChatSession(chatAppID)
	ctx := context.Background()

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

// --- Human Mode (Line-Interactive REPL) ---

func runLineChat(args []string) error {
	sess := crypto.NewChatSession(chatAppID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("5")).Bold(true).Render("👻 GHOST CHAT: Secure & Ephemeral"))
	fmt.Println("Connecting to wormhole...")

	var code string
	var err error
	if len(args) > 0 {
		code = args[0]
		err = sess.StartJoin(ctx, code)
	} else {
		code, err = sess.StartHost(ctx)
	}

	if err != nil {
		return err
	}

	fmt.Printf("✅ Connected! Join Code: %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("13")).Render(code))
	fmt.Println("Type your message below. Press Ctrl+D or type /quit to exit.")
	fmt.Println("------------------------------------------------------------")

	// Initialize Readline
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "💬 > ",
		HistoryFile:     "", // Ephemeral!
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	// Receiver loop
	go func() {
		peerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
		systemStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("4")).Italic(true)
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-sess.Events:
				if !ok {
					return
				}
				if ev.Type == "status" && ev.State == "peer-joined" {
					fmt.Fprintf(rl.Stdout(), "\r\033[2K%s\n💬 > %s",
						systemStyle.Render("⚡ Peer joined the room."),
						rl.Line())
				} else if ev.Type == "message" {
					// Cleanly print message using readline's internal buffer handling
					fmt.Fprintf(rl.Stdout(), "\r\033[2K%s %s\n💬 > %s",
						peerStyle.Render("Peer:"),
						ev.Text,
						rl.Line())
				}
			}
		}
	}()

	// Sender loop
	myStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("5")).Bold(true)
	for {
		line, err := rl.Readline()
		if err != nil { // io.EOF (Ctrl+D) or Ctrl+C
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "/quit" || line == "/exit" {
			break
		}

		err = sess.Send(ctx, line)
		if err != nil {
			fmt.Fprintf(rl.Stdout(), "❌ Error sending: %v\n", err)
		} else {
			// Clear the line where the user typed and replace with a styled 'You:' line
			// \033[1A moves cursor up, \r moves to start, \033[2K clears line
			fmt.Fprintf(rl.Stdout(), "\033[1A\r\033[2K%s %s\n", myStyle.Render("You:"), line)
		}
	}

	sess.Close()
	fmt.Println("\n✨ Wormhole closed. History remained in your terminal, but no traces on disk.")
	return nil
}
