package commands

import (
	"context"
	"encoding/json"
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

			status, err := engine.TunnelStart(&crypto.EngineContext{Context: ctx}, opts)
			if err != nil {
				return crypto.FormatMCPError(err, "tunnel_start")
			}
			res, _ := json.Marshal(status)
			return mcp.NewToolResultText(string(res)), nil
		})

	s.AddTool(mcp.NewTool("tunnel_listen", mcp.WithDescription("Start a Post-Quantum Tunnel Server (Gateway Receiver)")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := getArgs(request)
			addr := getString(args, "address", ":4001")
			mode := getString(args, "mode", "p2p")
			identity := getString(args, "identity", "")

			res, err := engine.TunnelListen(&crypto.EngineContext{Context: ctx}, addr, mode, identity)
			if err != nil {
				return crypto.FormatMCPError(err, "tunnel_listen")
			}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
		})

	s.AddTool(mcp.NewTool("tunnel_stop", mcp.WithDescription("Terminate the active PQC tunnel")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			err := engine.TunnelStop(&crypto.EngineContext{Context: ctx})
			if err != nil {
				return crypto.FormatMCPError(err, "tunnel_stop")
			}
			res := crypto.NetworkResult{Status: "stopped"}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
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

	s.AddTool(mcp.NewTool("network_status", mcp.WithDescription("Retrieve comprehensive P2P and tunnel network status")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			status, err := engine.NetworkStatus(&crypto.EngineContext{Context: ctx})
			if err != nil {
				return crypto.FormatMCPError(err, "network_status")
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
				P2PMode:    true,
				To:         getString(args, "to", ""),
			}
			if s, ok := args["stealth"].(bool); ok {
				opts.Stealth = crypto.BoolPtr(s)
			}

			identity := getString(args, "identity", "")
			code, _, err := engine.P2PSend(&crypto.EngineContext{Context: ctx}, identity, name, r, opts)
			if err != nil {
				return crypto.FormatMCPError(err, "p2p_send")
			}
			res := crypto.P2PResult{Status: "established", PeerID: code}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
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
			if s, ok := args["stealth"].(bool); ok {
				opts.Stealth = crypto.BoolPtr(s)
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

			res := crypto.P2PResult{Status: "success", Path: lastStatus.FileName}
			outData, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(outData)), nil
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
			res := crypto.ChatResult{
				Status: "established",
				PeerID: sess.Host.ID().String(),
				Addrs:  sess.Multiaddrs(),
			}
			raw, _ := json.Marshal(res)
			return mcp.NewToolResultText(string(raw)), nil
		})
}
