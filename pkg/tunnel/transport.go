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
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICClient manages a post-quantum QUIC tunnel.
type QUICClient struct {
	Session *quic.Conn
}

// QUICListener represents the receiving end of a post-quantum tunnel.
type QUICListener struct {
	Listener *quic.Listener
}

func (l *QUICListener) Accept() (MuxSession, error) {
	conn, err := l.Listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	return &QUICClient{Session: conn}, nil
}

func (l *QUICListener) Addr() net.Addr {
	return l.Listener.Addr()
}

func (l *QUICListener) Close() error {
	return l.Listener.Close()
}

// Listen starts a post-quantum QUIC listener with governed settings.
func Listen(address string, tlsConf *tls.Config, conf TunnelConfig) (*QUICListener, error) {
	return ListenWithConn(nil, address, tlsConf, conf)
}

// ListenWithConn starts a QUIC listener over a specific PacketConn.
func ListenWithConn(pconn net.PacketConn, address string, tlsConf *tls.Config, conf TunnelConfig) (*QUICListener, error) {
	// Enforce hard cap
	if conf.MaxStreams > 2000 {
		conf.MaxStreams = 2000
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:        time.Duration(conf.IdleTimeout) * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    int64(conf.MaxStreams),
		MaxIncomingUniStreams: int64(conf.MaxStreams),
		HandshakeIdleTimeout:  time.Duration(conf.HandshakeTimeout) * time.Second,
	}

	var ln *quic.Listener
	var err error

	if pconn != nil {
		ln, err = quic.Listen(pconn, tlsConf, quicConf)
	} else {
		ln, err = quic.ListenAddr(address, tlsConf, quicConf)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to start QUIC listener: %w", err)
	}

	return &QUICListener{Listener: ln}, nil
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

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
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

// GetPQCConfig returns a TLS 1.3 configuration that mandates ML-KEM-768 hybrid exchange.
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
	return DialWithConn(ctx, nil, address, tlsConf, conf)
}

// DialWithConn establishes a QUIC connection over a specific PacketConn.
func DialWithConn(ctx context.Context, pconn net.PacketConn, address string, tlsConf *tls.Config, conf TunnelConfig) (*QUICClient, error) {
	// Enforce hard cap
	if conf.MaxStreams > 2000 {
		conf.MaxStreams = 2000
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:        time.Duration(conf.IdleTimeout) * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    int64(conf.MaxStreams),
		MaxIncomingUniStreams: int64(conf.MaxStreams),
		HandshakeIdleTimeout:  time.Duration(conf.HandshakeTimeout) * time.Second,
	}

	var conn *quic.Conn
	var err error

	if pconn != nil {
		// Dial over specific virtual packet connection
		addr, _ := net.ResolveUDPAddr("udp", address)
		if addr == nil {
			// Virtual addresses like WormholeAddr aren't real UDP addrs
			// We pass a dummy addr if the pconn handles routing
			addr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		}
		conn, err = quic.Dial(ctx, pconn, addr, tlsConf, quicConf)
	} else {
		// Standard UDP dial
		conn, err = quic.DialAddr(ctx, address, tlsConf, quicConf)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to establish QUIC session: %w", err)
	}

	return &QUICClient{Session: conn}, nil
}

// OpenStream initiates a new multiplexed stream through the tunnel.
func (c *QUICClient) OpenStream(ctx context.Context) (net.Conn, error) {
	stream, err := c.Session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &quicConn{rawStream: stream, session: c.Session}, nil
}

// Close gracefully shuts down the tunnel.
func (c *QUICClient) Close() error {
	return c.Session.CloseWithError(0, "graceful shutdown")
}
