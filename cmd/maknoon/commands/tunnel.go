package commands

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/libp2p/go-libp2p"
	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/cobra"
)

// TunnelCmd returns the root command for L4 gateway operations.
func TunnelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Post-Quantum L4 Tunnel Gateway",
		Long:  `Manage secure network perimeters via PQC-QUIC, TCP-Yamux, or libp2p P2P.`,
	}

	cmd.AddCommand(tunnelListenCmd())
	cmd.AddCommand(tunnelStartCmd())

	return cmd
}

func tunnelListenCmd() *cobra.Command {
	var addr string
	var certFile, keyFile string
	var useYamux bool
	var useP2P bool

	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Start a Post-Quantum Tunnel Server (Gateway Receiver)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var ln tunnel.MuxListener

			if useP2P {
				var opts []libp2p.Option
				if addr != "" {
					ma, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s", strings.TrimPrefix(addr, ":")))
					if err == nil {
						opts = append(opts, libp2p.ListenAddrs(ma))
					}
				}

				h, err := tunnel.NewLibp2pHost(opts...)
				if err != nil {
					return err
				}
				fmt.Printf("🚀 P2P Tunnel Server active!\n")
				fmt.Printf("🆔 Peer ID: %s\n", h.ID())
				fmt.Println("📍 Multiaddrs:")
				for _, addr := range h.Addrs() {
					fmt.Printf("  - %s/p2p/%s\n", addr, h.ID())
				}
				ln = tunnel.StartLibp2pListener(h)
			} else if useYamux {
				tlsConf := tunnel.GetPQCConfig()
				cert, err := tunnel.GenerateTestCertificate()
				if err != nil {
					return fmt.Errorf("failed to generate ephemeral cert: %w", err)
				}
				tlsConf.Certificates = []tls.Certificate{cert}

				tl, err := tls.Listen("tcp", addr, tlsConf)
				if err != nil {
					return fmt.Errorf("failed to start PQC-TCP listener: %w", err)
				}
				fmt.Printf("🚀 PQC-Yamux Tunnel Server listening on %s (TCP)\n", addr)
				ln = &tunnel.TCPListener{Listener: tl}
			} else {
				tlsConf := tunnel.GetPQCConfig()
				cert, err := tunnel.GenerateTestCertificate()
				if err != nil {
					return fmt.Errorf("failed to generate ephemeral cert: %w", err)
				}
				tlsConf.Certificates = []tls.Certificate{cert}

				ql, err := tunnel.Listen(addr, tlsConf, GlobalContext.Engine.GetConfig().Tunnel)
				if err != nil {
					return fmt.Errorf("failed to start listener: %w", err)
				}
				fmt.Printf("🚀 PQC Tunnel Server listening on %s (UDP)\n", addr)
				ln = ql
			}

			server := &tunnel.TunnelServer{}
			return server.Serve(cmd.Context(), ln)
		},
	}

	cmd.Flags().StringVar(&addr, "address", ":4433", "Address to listen on")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "Path to TLS certificate")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "Path to TLS private key")
	cmd.Flags().BoolVar(&useYamux, "yamux", false, "Use TCP+Yamux mode")
	cmd.Flags().BoolVar(&useP2P, "p2p", false, "Use libp2p for P2P/NAT traversal")

	return cmd
}

func tunnelStartCmd() *cobra.Command {
	var remote string
	var localPort int
	var useYamux bool
	var useP2P bool
	var p2pAddr string

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
				UseYamux:       useYamux,
				P2PMode:        useP2P,
				P2PAddr:        p2pAddr,
			}

			status, err := GlobalContext.Engine.TunnelStart(&crypto.EngineContext{Context: context.Background()}, opts)
			if err != nil {
				return err
			}

			fmt.Printf("🔒 PQC L4 Tunnel Active\n")
			fmt.Printf("📡 Local Proxy: %s\n", status.LocalAddress)
			fmt.Printf("🌍 Remote Peer: %s\n", status.RemoteEndpoint)

			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
			<-sig

			fmt.Println("\n🛑 Tearing down tunnel...")
			return GlobalContext.Engine.TunnelStop(&crypto.EngineContext{Context: context.Background()})
		},
	}

	cmd.Flags().StringVar(&remote, "remote", "", "Remote PQC Tunnel endpoint (host:port)")
	cmd.Flags().IntVar(&localPort, "port", 1080, "Local SOCKS5 proxy port")
	cmd.Flags().BoolVar(&useYamux, "yamux", false, "Use TCP+Yamux mode")
	cmd.Flags().BoolVar(&useP2P, "p2p", false, "Use libp2p for P2P mode")
	cmd.Flags().StringVar(&p2pAddr, "p2p-addr", "", "Remote P2P Multiaddr")

	return cmd
}
