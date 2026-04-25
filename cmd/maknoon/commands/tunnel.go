package commands

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/spf13/cobra"
)

// TunnelCmd returns the root command for L4 gateway operations.
func TunnelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Post-Quantum L4 Tunnel Gateway",
		Long:  `Manage secure network perimeters via PQC-QUIC and user-space SOCKS5 gateways.`,
	}

	cmd.AddCommand(tunnelListenCmd())
	cmd.AddCommand(tunnelStartCmd())

	return cmd
}

func tunnelListenCmd() *cobra.Command {
	var addr string
	var useWormhole bool

	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Start a Post-Quantum Tunnel Server (Gateway Receiver)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitEngine(); err != nil {
				return err
			}

			code, statusCh, err := GlobalContext.Engine.TunnelListen(nil, addr, useWormhole)
			if err != nil {
				return err
			}

			if useWormhole {
				fmt.Printf("👻 Ghost Tunnel Initialized\n")
				fmt.Printf("🔑 Wormhole Code: %s\n", code)
				fmt.Println("⏳ Waiting for peer...")
			} else {
				fmt.Printf("🚀 PQC Tunnel Server listening on %s (UDP)\n", addr)
			}

			status := <-statusCh
			if status.Active {
				fmt.Printf("🔒 PQC Tunnel Established via %s\n", status.LocalAddress)
			}

			// Block until interrupt
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			<-sig
			return nil
		},
	}

	cmd.Flags().StringVar(&addr, "address", ":4433", "Address to listen on (UDP)")
	cmd.Flags().BoolVar(&useWormhole, "wormhole", false, "Use Magic Wormhole for NAT traversal")

	return cmd
}

func tunnelStartCmd() *cobra.Command {
	var remote string
	var localPort int
	var wormholeCode string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start a local Post-Quantum SOCKS5 Gateway",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := InitEngine(); err != nil {
				return err
			}

			opts := tunnel.TunnelOptions{
				RemoteEndpoint: remote,
				LocalProxyPort: localPort,
				WormholeCode:   wormholeCode,
			}

			status, err := GlobalContext.Engine.TunnelStart(nil, opts)
			if err != nil {
				return err
			}

			fmt.Printf("🔒 PQC L4 Tunnel Active\n")
			fmt.Printf("📡 Local Proxy: %s\n", status.LocalAddress)
			if status.RemoteEndpoint != "" {
				fmt.Printf("🌍 Remote Peer: %s\n", status.RemoteEndpoint)
			}

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			<-sig

			fmt.Println("\n🛑 Tearing down tunnel...")
			return GlobalContext.Engine.TunnelStop(nil)
		},
	}

	cmd.Flags().StringVar(&remote, "remote", "", "Remote PQC Tunnel endpoint (host:port)")
	cmd.Flags().IntVar(&localPort, "port", 1080, "Local SOCKS5 proxy port")
	cmd.Flags().StringVar(&wormholeCode, "code", "", "Magic Wormhole code for NAT traversal")

	return cmd
}
