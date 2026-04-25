package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICClient manages a post-quantum QUIC tunnel.
type QUICClient struct {
	Session *quic.Conn
}

// QUICServer represents the receiving end of a post-quantum tunnel.
type QUICServer struct {
	Listener *quic.Listener
}

// Listen starts a post-quantum QUIC listener with governed settings.
func Listen(address string, tlsConf *tls.Config, conf TunnelConfig) (*QUICServer, error) {
	// Enforce hard cap
	if conf.MaxStreams > 2000 {
		conf.MaxStreams = 2000
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:         time.Duration(conf.IdleTimeout) * time.Second,
		KeepAlivePeriod:        10 * time.Second,
		MaxIncomingStreams:     int64(conf.MaxStreams),
		MaxIncomingUniStreams:  int64(conf.MaxStreams),
		HandshakeIdleTimeout:   time.Duration(conf.HandshakeTimeout) * time.Second,
	}

	ln, err := quic.ListenAddr(address, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("failed to start QUIC listener: %w", err)
	}

	return &QUICServer{Listener: ln}, nil
}

// GenerateTestCertificate creates a self-signed TLS certificate for testing purposes.
func GenerateTestCertificate() (tls.Certificate, error) {
	// Standard RSA 2048 for the outer TLS layer (Handshake uses ML-KEM/X25519 hybrid curves)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Maknoon Ephemeral PQC"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// GetPQCConfig returns a TLS configuration optimized for Strict Post-Quantum Hybrid security.
func GetPQCConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// STRICT MODE: Only allow ML-KEM hybrid key exchange.
		// If a client does not support this, the handshake must fail.
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // The only permitted exchange
		},
		NextProtos: []string{"maknoon-pqc-tunnel"},
	}
}

// Dial establishes a secure QUIC connection with governed settings.
func Dial(ctx context.Context, address string, tlsConf *tls.Config, conf TunnelConfig) (*QUICClient, error) {
	// Enforce hard cap
	if conf.MaxStreams > 2000 {
		conf.MaxStreams = 2000
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:         time.Duration(conf.IdleTimeout) * time.Second,
		KeepAlivePeriod:        10 * time.Second,
		MaxIncomingStreams:     int64(conf.MaxStreams),
		MaxIncomingUniStreams:  int64(conf.MaxStreams),
		HandshakeIdleTimeout:   time.Duration(conf.HandshakeTimeout) * time.Second,
	}

	conn, err := quic.DialAddr(ctx, address, tlsConf, quicConf)
	if err != nil {
		return nil, fmt.Errorf("failed to dial QUIC endpoint: %w", err)
	}

	return &QUICClient{Session: conn}, nil
}

// OpenStream initiates a new multiplexed stream through the tunnel.
func (c *QUICClient) OpenStream(ctx context.Context) (*quic.Stream, error) {
	return c.Session.OpenStreamSync(ctx)
}

// Close gracefully shuts down the tunnel.
func (c *QUICClient) Close() error {
	return c.Session.CloseWithError(0, "graceful shutdown")
}
