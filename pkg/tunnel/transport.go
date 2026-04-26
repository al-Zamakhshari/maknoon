package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/quic-go/quic-go"
)

// Dial establishes a secure direct QUIC connection and returns a multiplexer.
func Dial(ctx context.Context, address string, tlsConf *tls.Config, conf TunnelConfig) (TunnelMux, error) {
	quicConf := &quic.Config{
		MaxIdleTimeout:         time.Duration(conf.IdleTimeout) * time.Second,
		KeepAlivePeriod:        10 * time.Second,
		MaxIncomingStreams:     int64(conf.MaxStreams),
		MaxIncomingUniStreams:  int64(conf.MaxStreams),
		HandshakeIdleTimeout:   time.Duration(conf.HandshakeTimeout) * time.Second,
	}
	conn, err := quic.DialAddr(ctx, address, tlsConf, quicConf)
	if err != nil { return nil, err }
	return &QUICMux{Session: conn}, nil
}

// DialWithConn establishes a QUIC connection over a virtual packet connection.
func DialWithConn(ctx context.Context, pconn net.PacketConn, address string, tlsConf *tls.Config, conf TunnelConfig) (TunnelMux, error) {
	quicConf := &quic.Config{
		MaxIdleTimeout:         time.Duration(conf.IdleTimeout) * time.Second,
		KeepAlivePeriod:        10 * time.Second,
		MaxIncomingStreams:     int64(conf.MaxStreams),
		MaxIncomingUniStreams:  int64(conf.MaxStreams),
		HandshakeIdleTimeout:   time.Duration(conf.HandshakeTimeout) * time.Second,
	}
	addr, _ := net.ResolveUDPAddr("udp", address)
	if addr == nil { addr = &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
	conn, err := quic.Dial(ctx, pconn, addr, tlsConf, quicConf)
	if err != nil { return nil, err }
	return &QUICMux{Session: conn}, nil
}

// Listen starts a post-quantum QUIC listener.
func Listen(address string, tlsConf *tls.Config, conf TunnelConfig) (TunnelListener, error) {
	quicConf := &quic.Config{
		MaxIdleTimeout:         time.Duration(conf.IdleTimeout) * time.Second,
		KeepAlivePeriod:        10 * time.Second,
		MaxIncomingStreams:     int64(conf.MaxStreams),
		MaxIncomingUniStreams:  int64(conf.MaxStreams),
		HandshakeIdleTimeout:   time.Duration(conf.HandshakeTimeout) * time.Second,
	}
	ln, err := quic.ListenAddr(address, tlsConf, quicConf)
	if err != nil { return nil, err }
	return &QUICListener{ln: ln}, nil
}

// QUICListener wraps quic.Listener to implement TunnelListener.
type QUICListener struct {
	ln *quic.Listener
}

func (l *QUICListener) Accept(ctx context.Context) (TunnelMux, error) {
	conn, err := l.ln.Accept(ctx)
	if err != nil { return nil, err }
	return &QUICMux{Session: conn}, nil
}
func (l *QUICListener) Close() error { return l.ln.Close() }
func (l *QUICListener) Addr() string { return l.ln.Addr().String() }

// ListenWithConn starts a post-quantum QUIC listener over an existing PacketConn.
func ListenWithConn(pconn net.PacketConn, address string, tlsConf *tls.Config, conf TunnelConfig) (TunnelListener, error) {
	quicConf := &quic.Config{
		MaxIdleTimeout:         time.Duration(conf.IdleTimeout) * time.Second,
		KeepAlivePeriod:        10 * time.Second,
		MaxIncomingStreams:     int64(conf.MaxStreams),
		MaxIncomingUniStreams:  int64(conf.MaxStreams),
		HandshakeIdleTimeout:   time.Duration(conf.HandshakeTimeout) * time.Second,
	}
	ln, err := quic.Listen(pconn, tlsConf, quicConf)
	if err != nil { return nil, err }
	return &QUICListener{ln: ln}, nil
}

// WrapStreamWithYamux upgrades a reliable stream with PQC-TLS and Yamux multiplexing.
func WrapStreamWithYamux(ctx context.Context, stream io.ReadWriteCloser, tlsConf *tls.Config, isServer bool) (TunnelMux, error) {
	var tlsConn *tls.Conn
	if isServer {
		tlsConn = tls.Server(streamToConn(stream), tlsConf)
	} else {
		tlsConn = tls.Client(streamToConn(stream), tlsConf)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil { return nil, err }

	var session *yamux.Session
	var err error
	if isServer {
		session, err = yamux.Server(tlsConn, nil)
	} else {
		session, err = yamux.Client(tlsConn, nil)
	}
	if err != nil { return nil, err }
	return &YamuxMux{Session: session}, nil
}

// GetPQCConfig returns a TLS configuration optimized for Strict Post-Quantum Hybrid security.
func GetPQCConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		NextProtos: []string{"maknoon-pqc-tunnel"},
	}
}

// GenerateTestCertificate creates a self-signed TLS certificate.
func GenerateTestCertificate() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { return tls.Certificate{}, err }
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{Organization: []string{"Maknoon Ephemeral PQC"}},
		NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil { return tls.Certificate{}, err }
	return tls.Certificate{Certificate: [][]byte{derBytes}, PrivateKey: priv}, nil
}

type streamConn struct{ io.ReadWriteCloser }
func (c *streamConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (c *streamConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (c *streamConn) SetDeadline(t time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return nil }
func streamToConn(s io.ReadWriteCloser) net.Conn         { return &streamConn{s} }
