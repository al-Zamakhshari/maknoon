package tunnel

import (
	"context"
	"io"
	"net"
	"strconv"
)

// TunnelGateway implements a SOCKS5 proxy that routes traffic through a multiplexed tunnel.
type TunnelGateway struct {
	Port    int
	Session MuxSession
	ln      net.Listener
}

// Start launches the SOCKS5 gateway on the local address.
func (g *TunnelGateway) Start() error {
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(g.Port))
	if err != nil {
		return err
	}
	g.ln = l

	// Update port if 0 was used
	if g.Port == 0 {
		_, portStr, _ := net.SplitHostPort(l.Addr().String())
		g.Port, _ = strconv.Atoi(portStr)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go g.handleConnection(conn)
		}
	}()

	return nil
}

func (g *TunnelGateway) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Use a standard buffer for the handshake (non-sensitive control data)
	buf := make([]byte, 256)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00})

	if _, err := io.ReadFull(conn, buf[:4]); err != nil || buf[1] != 0x01 {
		return
	}

	var address string
	switch buf[3] {
	case 0x01: // IPv4
		io.ReadFull(conn, buf[:4])
		address = net.IP(buf[:4]).String()
	case 0x03: // Domain
		io.ReadFull(conn, buf[:1])
		dLen := int(buf[0])
		io.ReadFull(conn, buf[:dLen])
		address = string(buf[:dLen])
	case 0x04: // IPv6
		io.ReadFull(conn, buf[:16])
		address = net.IP(buf[:16]).String()
	}
	io.ReadFull(conn, buf[:2])
	port := int(buf[0])<<8 | int(buf[1])
	dest := net.JoinHostPort(address, strconv.Itoa(port))

	stream, err := g.Session.OpenStream(context.Background())
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	if _, err := stream.Write([]byte{byte(len(dest))}); err != nil {
		return
	}
	if _, err := stream.Write([]byte(dest)); err != nil {
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// HARDENED PIPE: Use GlobalPool enclaves for traffic processing
	pipe := func(dst io.Writer, src io.Reader, done chan struct{}) {
		// Get a locked buffer from the pool
		lb := GlobalPool.Get()
		defer GlobalPool.Put(lb)

		for {
			n, err := src.Read(lb.Bytes())
			if n > 0 {
				if _, werr := dst.Write(lb.Bytes()[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}

	done := make(chan struct{}, 2)
	go pipe(stream, conn, done)
	go pipe(conn, stream, done)
	<-done
}

// Stop shuts down the gateway listener.
func (g *TunnelGateway) Stop() error {
	if g.ln != nil {
		return g.ln.Close()
	}
	return nil
}
