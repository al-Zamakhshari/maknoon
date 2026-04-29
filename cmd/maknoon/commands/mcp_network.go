package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/viper"
)

func registerNetworkTools(s *server.MCPServer, engine crypto.MaknoonEngine) {
	s.AddTool(mcp.NewTool("tunnel_start", mcp.WithDescription("Provision a Post-Quantum L4 tunnel and SOCKS5 gateway")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			remote := getString(args, "remote", "")
			portVal := args["port"]
			var port int
			switch v := portVal.(type) {
			case float64:
				port = int(v)
			case int64:
				port = int(v)
			case int:
				port = v
			default:
				port = 1080
			}

			useYamux, _ := args["use_yamux"].(bool)
			p2pMode, _ := args["p2p_mode"].(bool)
			p2pAddr := getString(args, "p2p_addr", "")

			opts := tunnel.TunnelOptions{
				RemoteEndpoint: remote,
				LocalProxyPort: port,
				UseYamux:       useYamux,
				P2PMode:        p2pMode,
				P2PAddr:        p2pAddr,
			}
			if p2pMode {
				opts.RemoteEndpoint = "p2p-virtual" // Bypass engine validation
			}

			status, err := engine.TunnelStart(&crypto.EngineContext{Context: ctx}, opts)
			if err != nil {
				return crypto.FormatMCPError(err, "tunnel_start")
			}
			res, _ := json.Marshal(status)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("tunnel_stop", mcp.WithDescription("Terminate the active PQC tunnel")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			err := engine.TunnelStop(&crypto.EngineContext{Context: ctx})
			if err != nil {
				return crypto.FormatMCPError(err, "tunnel_stop")
			}
			return mcp.NewToolResultText(`{"status":"stopped"}`), nil
		})

	s.AddTool(mcp.NewTool("tunnel_status", mcp.WithDescription("Retrieve status of the active tunnel")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			status, err := engine.TunnelStatus(&crypto.EngineContext{Context: ctx})
			if err != nil {
				return crypto.FormatMCPError(err, "tunnel_status")
			}
			res, _ := json.Marshal(status)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("p2p_send", mcp.WithDescription("Start a secure P2P file transfer")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			text := getString(args, "text", "")
			path := getString(args, "path", "")
			var r io.Reader
			var name string
			if text != "" {
				r = strings.NewReader(text)
				name = "text-message"
			} else {
				f, _ := os.Open(path)
				r = f
				name = filepath.Base(path)
			}
			opts := crypto.P2PSendOptions{
				Passphrase: []byte(viper.GetString("passphrase")),
				Stealth:    getBool(args, "stealth", false),
				P2PMode:    true,
				To:         getString(args, "to", ""),
			}
			identity := getString(args, "identity", "")
			code, _, err := engine.P2PSend(&crypto.EngineContext{Context: ctx}, identity, name, r, opts)
			if err != nil {
				return crypto.FormatMCPError(err, "p2p_send")
			}
			return mcp.NewToolResultText(fmt.Sprintf(`{"peer_id":"%s","status":"established"}`, code)), nil
		})

	s.AddTool(mcp.NewTool("p2p_receive", mcp.WithDescription("Wait for and receive a secure P2P file transfer")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			peerID := getString(args, "peer_id", "")
			output := getString(args, "output", "")

			opts := crypto.P2PReceiveOptions{
				Passphrase: []byte(viper.GetString("passphrase")),
				OutputDir:  output,
				P2PMode:    true,
			}
			identity := getString(args, "identity", "")

			statusChan, err := engine.P2PReceive(&crypto.EngineContext{Context: ctx}, identity, peerID, opts)
			if err != nil {
				return crypto.FormatMCPError(err, "p2p_receive")
			}

			var lastStatus crypto.P2PStatus
			for s := range statusChan {
				lastStatus = s
				if s.Phase == "success" || s.Phase == "error" {
					break
				}
			}

			if lastStatus.Error != nil {
				return crypto.FormatMCPError(lastStatus.Error, "p2p_receive")
			}

			return mcp.NewToolResultText(fmt.Sprintf(`{"status":"success","path":"%s"}`, lastStatus.FileName)), nil
		})

	s.AddTool(mcp.NewTool("chat_start", mcp.WithDescription("Initiate an identity-bound P2P Chat session")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			target := getString(args, "target", "")
			identity := getString(args, "identity", "")
			sess, err := engine.ChatStart(&crypto.EngineContext{Context: ctx}, identity, target)
			if err != nil {
				return crypto.FormatMCPError(err, "chat_start")
			}
			res := map[string]interface{}{
				"status":  "established",
				"peer_id": sess.Host.ID().String(),
				"addrs":   sess.Multiaddrs(),
			}
			raw, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(raw)), nil
		})
}
