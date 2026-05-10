package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/al-Zamakhshari/maknoon/pkg/crypto"
)

type adminPolicy struct {
	crypto.HumanPolicy
	threshold int
	peers     []string
}

func (p *adminPolicy) QuorumRequirement(action string) (int, []string) {
	if action == string(crypto.ActionConfigAdmin) {
		return p.threshold, p.peers
	}
	return 0, nil
}

func main() {
	tmpDir, _ := os.MkdirTemp("", "maknoon-admin-quorum-*")
	defer os.RemoveAll(tmpDir)

	vaultsDir := filepath.Join(tmpDir, "vaults")
	os.MkdirAll(vaultsDir, 0700)

	// 1. Initialize Engine with Admin Quorum requirement
	conf := crypto.DefaultConfig()
	conf.Paths.VaultsDir = vaultsDir
	conf.Paths.KeysDir = filepath.Join(tmpDir, "keys")
	os.MkdirAll(conf.Paths.KeysDir, 0700)

	// Set an authorized admin peer (using a dummy PeerID)
	conf.Governance.AdminPeers = []string{"12D3KooWDummyAdminPeerID"}

	policy := &adminPolicy{threshold: 1, peers: conf.Governance.AdminPeers}
	eng, _ := crypto.NewEngine(policy, nil, conf, nil, slog.Default())
	defer eng.Close()

	ectx := crypto.NewEngineContext(context.Background(), nil, policy)

	fmt.Println("--- Testing Unauthorized Config Update ---")
	newConf := crypto.DefaultConfig()
	newConf.Security.ArgonTime = 10

	err := eng.UpdateConfig(ectx, newConf)
	if err != nil {
		fmt.Printf("Expected failure (Quorum required): %v\n", err)
	}

	fmt.Println("Verification script complete.")
}
