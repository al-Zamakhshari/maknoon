package crypto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestP2PFragmentDispersalAndRetrieval(t *testing.T) {
	// Skip if it's too heavy for standard CI, but here we want it.

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	policy := &HumanPolicy{}
	conf := DefaultConfig()
	e, _ := NewEngine(policy, nil, conf, nil, nil)
	ectx := &EngineContext{Context: ctx, Policy: policy}

	// 1. Setup 3 storage nodes
	nodes := make([]host.Host, 3)
	nodeDirs := make([]string, 3)
	for i := 0; i < 3; i++ {
		h, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
		if err != nil {
			t.Fatalf("Failed to create host %d: %v", i, err)
		}
		nodes[i] = h

		dir, _ := os.MkdirTemp("", fmt.Sprintf("node-storage-%d-*", i))
		nodeDirs[i] = dir
		defer os.RemoveAll(dir)

		e.RegisterFragmentHandler(h, dir)
	}

	// 2. Prepare data to shard
	originalData := []byte("Post-Quantum RAID for the Distributed Web. Fragmentation is Key.")
	inputName := "test-mission.txt"

	// Shard: 2 data + 1 parity = 3 shards

	// Manual fragmentation for simulation since runLibp2pFragmentSend handles connection
	fOpts := FragmentOptions{
		DataShards:   2,
		ParityShards: 1,
		TargetDir:    "", // We'll provide writers
		OriginalSize: int64(len(originalData)),
	}

	writers := make([]io.WriteCloser, 3)
	shardFiles := make([]string, 3)
	for i := 0; i < 3; i++ {
		path := filepath.Join(nodeDirs[i], fmt.Sprintf("%s.shard_%03d.maknf", inputName, i))
		f, _ := os.Create(path)
		writers[i] = f
		shardFiles[i] = path
	}

	fw, _ := NewFragmentWriterWithWriters(fOpts, writers)
	fw.Write(originalData)
	fw.Close()

	// 3. Retrieve using Automated Retrieval
	recvOpts := P2PReceiveOptions{
		From:         "", // Will build from node Addrs
		IsFragmented: true,
		FragmentName: inputName,
		OutputDir:    "recovered-mission.txt",
	}

	targets := make([]string, 3)
	for i := 0; i < 3; i++ {
		targets[i] = fmt.Sprintf("%s/p2p/%s", nodes[i].Addrs()[0], nodes[i].ID())
	}
	recvOpts.From = strings.Join(targets, ",")

	// Client node
	clientHost, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		t.Fatalf("Failed to create client host: %v", err)
	}
	defer clientHost.Close()

	// Ensure peers are connected/known
	for i := 0; i < 3; i++ {
		info := peer.AddrInfo{
			ID:    nodes[i].ID(),
			Addrs: nodes[i].Addrs(),
		}
		if err := clientHost.Connect(ctx, info); err != nil {
			t.Fatalf("Failed to connect client to node %d: %v", i, err)
		}
	}

	status := make(chan P2PStatus, 10)
	go e.runLibp2pFragmentReceive(ectx, inputName, clientHost, recvOpts, status)

	var finalFile string
	success := false
	for s := range status {
		if s.Error != nil {
			t.Errorf("Fragment retrieval phase %s failed: %v", s.Phase, s.Error)
			break
		}
		if s.Phase == "success" {
			finalFile = s.FileName
			success = true
		}
	}

	if !success {
		t.Fatal("Retrieval did not reach success phase")
	}

	// 4. Verify Content
	recovered, err := os.ReadFile(finalFile)
	if err != nil {
		t.Fatalf("Failed to read recovered file: %v", err)
	}
	defer os.Remove(finalFile)

	if !bytes.Equal(recovered, originalData) {
		t.Errorf("Recovered data mismatch.\nGot:  %s\nWant: %s", string(recovered), string(originalData))
	}
}
