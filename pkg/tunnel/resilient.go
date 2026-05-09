package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
)

// ResilientMuxSession implements MuxSession by striping data across multiple underlying sessions
// using Reed-Solomon erasure coding. This provides RAID-for-Networking resilience.
type ResilientMuxSession struct {
	SubSessions []MuxSession
	DataLanes   int
	ParityLanes int
	mu          sync.Mutex
	closed      bool
}

// NewResilientMuxSession creates a session that stripes data across N sub-sessions.
func NewResilientMuxSession(subs []MuxSession, data, parity int) (*ResilientMuxSession, error) {
	if len(subs) < data+parity {
		return nil, fmt.Errorf("insufficient sub-sessions: have %d, need %d", len(subs), data+parity)
	}
	return &ResilientMuxSession{
		SubSessions: subs,
		DataLanes:   data,
		ParityLanes: parity,
	}, nil
}

// OpenStream initiates a new resilient stream by opening underlying streams on all sub-sessions.
func (s *ResilientMuxSession) OpenStream(ctx context.Context) (net.Conn, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("session closed")
	}
	s.mu.Unlock()

	total := s.DataLanes + s.ParityLanes
	lanes := make([]net.Conn, total)
	var wg sync.WaitGroup

	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Round-robin or mapping logic for sub-sessions
			sessIdx := idx % len(s.SubSessions)
			conn, err := s.SubSessions[sessIdx].OpenStream(ctx)
			if err == nil {
				lanes[idx] = conn
			}
		}(i)
	}

	wg.Wait()

	activeLanes := 0
	for _, l := range lanes {
		if l != nil {
			activeLanes++
		}
	}

	if activeLanes < s.DataLanes {
		for _, l := range lanes {
			if l != nil {
				_ = l.Close()
			}
		}
		return nil, fmt.Errorf("failed to open sufficient lanes: %d/%d", activeLanes, s.DataLanes)
	}

	return NewResilientConn(lanes, s.DataLanes, s.ParityLanes)
}

func (s *ResilientMuxSession) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	var firstErr error
	for _, sub := range s.SubSessions {
		if err := sub.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ResilientConn implements net.Conn using erasure coding across multiple lanes.
type ResilientConn struct {
	Lanes       []net.Conn
	DataLanes   int
	ParityLanes int

	reader *io.PipeReader
	writer *io.PipeWriter

	mu     sync.Mutex
	closed bool
}

func NewResilientConn(lanes []net.Conn, data, parity int) (*ResilientConn, error) {
	c := &ResilientConn{
		Lanes:       lanes,
		DataLanes:   data,
		ParityLanes: parity,
	}

	pr, pw := io.Pipe()
	c.reader = pr
	c.writer = pw

	// Start background reassembler
	go c.runReassembler()

	return c, nil
}

func (c *ResilientConn) runReassembler() {
	defer c.Close()

	totalShards := c.DataLanes + c.ParityLanes
	enc, err := reedsolomon.New(c.DataLanes, c.ParityLanes)
	if err != nil {
		return
	}

	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		shardData := make([][]byte, totalShards)
		var shardLen int

		type readResult struct {
			idx  int
			data []byte
			err  error
		}
		resChan := make(chan readResult, totalShards)

		for i := 0; i < totalShards; i++ {
			go func(idx int, conn net.Conn) {
				if conn == nil {
					resChan <- readResult{idx, nil, fmt.Errorf("lane dead")}
					return
				}
				// Header: Len(4)
				var length uint32
				if err := binary.Read(conn, binary.LittleEndian, &length); err != nil {
					resChan <- readResult{idx, nil, err}
					return
				}
				buf := make([]byte, length)
				if _, err := io.ReadFull(conn, buf); err != nil {
					resChan <- readResult{idx, nil, err}
					return
				}
				resChan <- readResult{idx, buf, nil}
			}(i, c.Lanes[i])
		}

		successCount := 0
		for i := 0; i < totalShards; i++ {
			res := <-resChan
			if res.err == nil {
				shardData[res.idx] = res.data
				if len(res.data) > shardLen {
					shardLen = len(res.data)
				}
				successCount++
			} else {
				// Mark lane as potentially failed
				c.Lanes[res.idx] = nil
			}
		}

		if successCount < c.DataLanes {
			return // Connection lost
		}

		// Normalize shards
		for i := 0; i < totalShards; i++ {
			if shardData[i] == nil {
				continue
			}
			if len(shardData[i]) < shardLen {
				padded := make([]byte, shardLen)
				copy(padded, shardData[i])
				shardData[i] = padded
			}
		}

		// Reconstruct and join
		if err := enc.Reconstruct(shardData); err != nil {
			continue
		}

		var buf bytes.Buffer
		_ = enc.Join(&buf, shardData, shardLen*c.DataLanes)

		// For now, write everything (TODO: handle original data length if needed)
		_, _ = c.writer.Write(buf.Bytes())
	}
}

func (c *ResilientConn) Write(b []byte) (n int, err error) {
	totalShards := c.DataLanes + c.ParityLanes
	enc, err := reedsolomon.New(c.DataLanes, c.ParityLanes)
	if err != nil {
		return 0, err
	}

	shards, err := enc.Split(b)
	if err != nil {
		return 0, err
	}

	if err := enc.Encode(shards); err != nil {
		return 0, err
	}

	var wg sync.WaitGroup
	for i := 0; i < totalShards; i++ {
		wg.Add(1)
		go func(idx int, shard []byte) {
			defer wg.Done()
			if c.Lanes[idx] == nil {
				return
			}
			_ = binary.Write(c.Lanes[idx], binary.LittleEndian, uint32(len(shard)))
			_, errWrite := c.Lanes[idx].Write(shard)
			if errWrite != nil {
				c.Lanes[idx] = nil
			}
		}(i, shards[i])
	}
	wg.Wait()

	return len(b), nil
}

func (c *ResilientConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *ResilientConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	_ = c.reader.Close()
	_ = c.writer.Close()

	for _, l := range c.Lanes {
		if l != nil {
			_ = l.Close()
		}
	}
	return nil
}

func (c *ResilientConn) LocalAddr() net.Addr  { return c.Lanes[0].LocalAddr() }
func (c *ResilientConn) RemoteAddr() net.Addr { return c.Lanes[0].RemoteAddr() }

func (c *ResilientConn) SetDeadline(t time.Time) error {
	for _, l := range c.Lanes {
		if l != nil {
			_ = l.SetDeadline(t)
		}
	}
	return nil
}

func (c *ResilientConn) SetReadDeadline(t time.Time) error {
	for _, l := range c.Lanes {
		if l != nil {
			_ = l.SetReadDeadline(t)
		}
	}
	return nil
}

func (c *ResilientConn) SetWriteDeadline(t time.Time) error {
	for _, l := range c.Lanes {
		if l != nil {
			_ = l.SetWriteDeadline(t)
		}
	}
	return nil
}
