package commands

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
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
	var certFile, keyFile string
	var useYamux bool

	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Start a Post-Quantum Tunnel Server (Gateway Receiver)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if useYamux {
				// Setup PQC TLS for Yamux
				tlsConf := tunnel.GetPQCConfig()
				cert, err := tunnel.GenerateTestCertificate()
				if err != nil {
					return fmt.Errorf("failed to generate ephemeral cert: %w", err)
				}
				tlsConf.Certificates = []tls.Certificate{cert}

				l, err := tls.Listen("tcp", addr, tlsConf)
				if err != nil {
					return fmt.Errorf("failed to start PQC-TCP listener: %w", err)
				}
				defer l.Close()

				fmt.Printf("🚀 PQC-Yamux Tunnel Server listening on %s (TCP)\n", addr)
				for {
					conn, err := l.Accept()
					if err != nil {
						return err
					}
					sess, err := tunnel.WrapYamux(conn, true)
					if err != nil {
						conn.Close()
						continue
					}
					server := &tunnel.TunnelServer{Session: sess}
					go server.StartYamux(cmd.Context())
				}
			}

			// 1. Setup PQC TLS
			tlsConf := tunnel.GetPQCConfig()

			if certFile != "" && keyFile != "" {
				// In v3.0, loading custom certs would happen here
				return fmt.Errorf("loading custom certificates not yet implemented in CLI")
			} else {
				fmt.Println("⚠️  Warning: Using ephemeral self-signed certificate for tunnel")
				cert, err := tunnel.GenerateTestCertificate()
				if err != nil {
					return fmt.Errorf("failed to generate ephemeral cert: %w", err)
				}
				tlsConf.Certificates = []tls.Certificate{cert}
			}

			// 2. Start Listener
			srv, err := tunnel.Listen(addr, tlsConf, GlobalContext.Engine.GetConfig().Tunnel)
			if err != nil {
				return fmt.Errorf("failed to start listener: %w", err)
			}
			defer srv.Listener.Close()

			server := &tunnel.TunnelServer{Listener: srv.Listener}
			fmt.Printf("🚀 PQC Tunnel Server listening on %s (UDP)\n", addr)

			return server.Start(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&addr, "address", ":4433", "Address to listen on")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "Path to TLS certificate")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "Path to TLS private key")
	cmd.Flags().BoolVar(&useYamux, "yamux", false, "Use TCP+Yamux (Foundation for Ghost Tunneling)")

	return cmd
}

func tunnelStartCmd() *cobra.Command {
	var remote string
	var localPort int
	var useYamux bool

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
	cmd.MarkFlagRequired("remote")

	return cmd
}
