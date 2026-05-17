package crypto

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/al-Zamakhshari/maknoon/pkg/tunnel"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
)

const (
	// P2PQuorumProtocol is the protocol for consensus-based quorum operations.
	P2PQuorumProtocol = "/maknoon/quorum/1.0.0"
)

// QuorumAction defines the type of consensus being requested.
type QuorumAction string

const (
	ActionVaultUnlock QuorumAction = "vault_unlock"
	ActionConfigAdmin QuorumAction = "config_admin"
)

// QuorumRequest is sent by an initiator to request approval for a sensitive operation.
type QuorumRequest struct {
	TraceID   string       `json:"trace_id"`
	Action    QuorumAction `json:"action"`
	Resource  string       `json:"resource"`  // e.g., Vault Name or Config Key
	Requester string       `json:"requester"` // PeerID of the initiator
	Purpose   string       `json:"purpose"`   // Human-readable reason
	Timestamp int64        `json:"timestamp"`
	Signature []byte       `json:"signature"` // ML-DSA signature of the request body
}

// QuorumResponse is sent by a peer to approve or deny a quorum request.
type QuorumResponse struct {
	TraceID  string `json:"trace_id"`
	Approved bool   `json:"approved"`
	Reason   string `json:"reason,omitempty"`

	// Payload contains the protected material (e.g., encrypted SSS shard)
	// only if Approved is true and the requester is authorized.
	Payload []byte `json:"payload,omitempty"`

	// Forensic signature of the response
	Signature []byte `json:"signature"`
}

// EncodeQuorumRequest serializes a request for P2P transmission.
func EncodeQuorumRequest(w io.Writer, req QuorumRequest) error {
	return json.NewEncoder(w).Encode(req)
}

// DecodeQuorumRequest deserializes a request from a P2P stream.
func DecodeQuorumRequest(r io.Reader) (*QuorumRequest, error) {
	var req QuorumRequest
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		return nil, fmt.Errorf("failed to decode quorum request: %w", err)
	}
	return &req, nil
}

// EncodeQuorumResponse serializes a response for P2P transmission.
func EncodeQuorumResponse(w io.Writer, resp QuorumResponse) error {
	return json.NewEncoder(w).Encode(resp)
}

// DecodeQuorumResponse deserializes a response from a P2P stream.
func DecodeQuorumResponse(r io.Reader) (*QuorumResponse, error) {
	var resp QuorumResponse
	if err := json.NewDecoder(r).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode quorum response: %w", err)
	}
	return &resp, nil
}

// RegisterQuorumHandler enables this node to participate in consensus operations.
func (e *Engine) RegisterQuorumHandler(h host.Host) {
	h.SetStreamHandler(P2PQuorumProtocol, func(stream network.Stream) {
		defer stream.Close()

		req, err := DecodeQuorumRequest(stream)
		if err != nil {
			e.Logger.Warn("Quorum handler failed to decode request", "err", err)
			return
		}

		e.Logger.Debug("Processing quorum request", "requester", req.Requester, "action", req.Action)

		ectx := e.context(nil)
		resp := QuorumResponse{
			TraceID:  req.TraceID,
			Approved: false,
		}

		// 1. Verify Request Signature (ML-DSA)
		// We need to resolve the requester's PeerID to their Public Key
		var sigPub []byte
		reg := NewIdentityRegistry(e.Config)
		record, err := reg.Resolve(ectx.Context, "@"+req.Requester)
		if err == nil && record != nil {
			sigPub = record.SIGPubKey
		} else {
			// Fallback: Check if they are in our local contacts
			if err := e.ensureContacts(); err == nil {
				if c, err2 := e.contacts.manager.GetByPeerID(req.Requester); err2 == nil {
					sigPub = c.SIGPubKey
				}
			}
		}

		if len(sigPub) > 0 {
			sigData := []byte(fmt.Sprintf("%s:%s:%s:%d", req.Action, req.Resource, req.Requester, req.Timestamp))
			valid, err := e.Verify(ectx, sigData, req.Signature, sigPub)
			if !valid {
				e.Logger.Warn("Quorum request signature invalid", "requester", req.Requester, "action", req.Action, "err", err)
				resp.Reason = "Forensic failure: invalid request signature"
				EncodeQuorumResponse(stream, resp)
				return
			}
		} else {
			e.Logger.Warn("Quorum request rejected: requester not found", "requester", req.Requester)
			resp.Reason = "Forensic failure: requester identity not found in registry or contacts"
			EncodeQuorumResponse(stream, resp)
			return
		}

		// 2. Resource Matching & Consensus Logic
		e.Logger.Info("Processing quorum request", "action", req.Action, "resource", req.Resource, "requester", req.Requester)
		switch req.Action {
		case ActionVaultUnlock:
			shardPattern := fmt.Sprintf("%s.shard_*.maknf", filepath.Base(req.Resource))
			matches, _ := filepath.Glob(filepath.Join(e.Config.Paths.VaultsDir, shardPattern))
			if len(matches) == 0 {
				e.Logger.Warn("Quorum request: no shards found", "pattern", shardPattern, "dir", e.Config.Paths.VaultsDir)
				resp.Reason = "Resource mismatch: no governance shards found for requested vault"
			} else {
				if ectx.Policy.AllowAutoQuorum(req.Requester, string(req.Action)) {
					shardData, _ := os.ReadFile(matches[0])
					resp.Approved = true
					resp.Payload = shardData
					e.Logger.Info("Quorum request AUTO-APPROVED", "requester", req.Requester)
				} else {
					e.Logger.Warn("Quorum request DENIED by policy", "requester", req.Requester)
					resp.Reason = "Policy restriction: manual approval required or requester not authorized"
				}
			}

		case ActionConfigAdmin:
			// For administrative consensus, we check if the requester is in our local AdminPeers list
			// and if the local policy permits auto-approval of administrative actions.
			isAdmin := false
			for _, peer := range e.Config.Governance.AdminPeers {
				if peer == req.Requester {
					isAdmin = true
					break
				}
			}

			if !isAdmin {
				resp.Reason = "Security failure: requester is not an authorized administrator"
			} else if ectx.Policy.AllowAutoQuorum(req.Requester, string(req.Action)) {
				resp.Approved = true
			} else {
				resp.Reason = "Policy restriction: manual administrative approval required"
			}

		default:
			resp.Reason = "Unsupported quorum action"
		}

		// 3. Sign Response
		id, _ := e.Identities.LoadIdentity(e.Config.DefaultIdentity, nil, "", false)
		if id != nil {
			respSig, _ := e.Sign(ectx, []byte(resp.TraceID+fmt.Sprint(resp.Approved)), id.SIGPriv)
			resp.Signature = respSig
		}

		EncodeQuorumResponse(stream, resp)
	})
}

// QuorumRequest initiates a consensus-based operation request to a set of peers.
func (e *Engine) QuorumRequest(ectx *EngineContext, identityName string, targets []string, action QuorumAction, resource string, purpose string) ([]QuorumResponse, error) {
	ectx = e.context(ectx)
	if err := e.enforce(ectx, CapP2P); err != nil {
		return nil, err
	}

	id, err := e.Identities.LoadIdentity(identityName, nil, "", false)
	if err != nil {
		return nil, err
	}

	priv, err := id.AsLibp2pKey()
	if err != nil {
		return nil, err
	}

	h, err := tunnel.NewLibp2pHost(libp2p.Identity(priv))
	if err != nil {
		return nil, err
	}
	defer h.Close()

	req := QuorumRequest{
		TraceID:   GenerateTraceID(),
		Action:    action,
		Resource:  resource,
		Requester: h.ID().String(),
		Purpose:   purpose,
		Timestamp: time.Now().Unix(),
	}

	// Sign the request with ML-DSA
	sigData := []byte(fmt.Sprintf("%s:%s:%s:%d", req.Action, req.Resource, req.Requester, req.Timestamp))
	sig, err := e.Sign(ectx, sigData, id.SIGPriv)
	if err != nil {
		return nil, err
	}
	req.Signature = sig

	var responses []QuorumResponse
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			stream, err := e.connectToPeer(ectx, h, target, P2PQuorumProtocol)
			if err != nil {
				e.Logger.Warn("QuorumRequest failed to connect to peer", "target", target, "err", err)
				return
			}
			defer stream.Close()

			if err := EncodeQuorumRequest(stream, req); err != nil {
				return
			}

			resp, err := DecodeQuorumResponse(stream)
			if err == nil {
				mu.Lock()
				responses = append(responses, *resp)
				mu.Unlock()
			}
		}(t)
	}

	wg.Wait()
	return responses, nil
}
