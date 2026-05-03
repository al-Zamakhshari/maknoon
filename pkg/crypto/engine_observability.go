package crypto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
)

func (e *Engine) NetworkStatus(ectx *EngineContext) (NetStatusResult, error) {
	res := NetStatusResult{}

	// 1. Check active tunnel
	e.tunnelMu.RLock()
	if e.activeTunnel != nil {
		// Use type assertion since e.activeTunnel is interface{} in the new engine.go
		if at, ok := e.activeTunnel.(*tunnel.TunnelStatus); ok {
			res.Tunnel.Active = true
			res.Tunnel.LocalAddress = at.LocalAddress
			res.Tunnel.RemoteEndpoint = at.RemoteEndpoint
			res.Tunnel.HandshakeTime = at.HandshakeTime
		}
	}
	e.tunnelMu.RUnlock()

	// 2. Create a temporary host to check P2P environment (if no persistent host)
	h, err := tunnel.NewLibp2pHost()
	if err != nil {
		return res, fmt.Errorf("failed to initialize diagnostic host: %w", err)
	}
	defer h.Close()

	res.PeerID = h.ID().String()
	for _, addr := range h.Addrs() {
		res.Addresses = append(res.Addresses, addr.String())
	}
	for _, p := range h.Mux().Protocols() {
		res.Protocols = append(res.Protocols, string(p))
	}

	return res, nil
}

func (e *Engine) Diagnostic() DiagnosticResult {
	res := DiagnosticResult{}
	res.Timestamp = time.Now().Format(time.RFC3339)

	// System Info
	res.System.OS = runtime.GOOS
	res.System.Arch = runtime.GOARCH
	res.System.Go = runtime.Version()
	res.System.Version = "v1.3.x"

	// User Info
	if u, err := user.Current(); err == nil {
		res.User.UID = u.Uid
		res.User.GID = u.Gid
		res.User.Username = u.Username
		res.User.Home = u.HomeDir
	} else {
		res.User.Home = GetUserHomeDir()
	}

	// Path Info
	home := res.User.Home
	res.Paths.MaknoonDir = filepath.Join(home, MaknoonDir)
	res.Paths.Config = filepath.Join(home, MaknoonDir, ConfigFileName)
	res.Paths.Keys = filepath.Join(home, MaknoonDir, KeysDir)
	res.Paths.Vaults = filepath.Join(home, MaknoonDir, VaultsDir)

	// Engine Info
	res.Engine.Policy = e.Policy.Name()
	res.Engine.AgentMode = e.Policy.IsAgent()
	res.Engine.DefaultProfile = e.Config.Performance.DefaultProfile
	if profile, err := GetProfile(res.Engine.DefaultProfile, nil); err == nil {
		res.Engine.ProfileName = profile.Name()
	}
	res.Engine.AuditEnabled = e.Config.Audit.Enabled

	res.Performance = e.Config.Performance

	return res
}

func (e *Engine) AuditExport(ectx *EngineContext) ([]AuditEntry, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapAudit); err != nil {
		return nil, err
	}

	f, err := os.Open(e.Config.Audit.LogFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []AuditEntry{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []AuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err == nil {
			entries = append(entries, entry)
		}
	}

	return entries, scanner.Err()
}
