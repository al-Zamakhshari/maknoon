# Changelog

All notable changes to Maknoon are documented here. Releases follow [semantic versioning](https://semver.org/). Starting from v1.3.107, GoReleaser auto-generates release notes from conventional commits — this file tracks cumulative highlights.

---

## [Unreleased]

### Added
- 19-point improvement plan: docs, audit split, REST roundtrip tests, benchmarks, libp2p-kad-dht removal, cosign/SLSA provenance, `reencrypt` command, minimal build tags, K8s probes + Helm chart, audit log rotation, MCP schema CI
- `RUNBOOK.md` — on-call procedures for mission failures, govulncheck, CI triage
- `HARDWARE-HARDENING.md` — SSD wear-leveling limitation documentation and ATA Secure Erase guidance
- ML-DSA-87 key size note added to threat model

---

## [v1.3.106] — 2026-05-18

### Fixed
- P0/P1 security hardening: complete SSRF domain validation in Nostr registry, path traversal guards in REST API, nil panic in `p2p_send.go`
- Interface completeness: `VaultStatus`, `IdentityDelete`, `IdentityCombine` added to `MaknoonEngine`
- Removed deprecated profile 2 (AES-only) code path from identity generation

### Added
- `isValidDomain` unit tests covering RFC1918, loopback, link-local, ULA, multicast ranges
- `govulncheck` step in CI with `GO-2024-3218` allowlisted (libp2p-kad-dht; unfixed upstream)

---

## [v1.3.104] — 2026-05-18

### Fixed
- `FuzzSequencer` false positive on byzantine out-of-bounds shard indices

### Added
- Identity registry restored: Nostr as fallback, secp256k1 key derived ephemerally via HKDF-SHA256
- libp2p DHT resolve timeout + contacts nil guard
- `--nostr` flag restored on `identity publish` command

---

## [v1.3.103] — 2026-05-17

### Changed
- Architectural hardening: complete engine service decomposition (`VaultService`, `IdentityService`, `NetworkService`, `CryptoService`, `WorkspaceService`)
- Observability improvements: structured slog throughout, event emitter for telemetry

### Added
- Audit log: console logger discarded in JSON mode to prevent stdout pollution
- CI: race detector, fuzz seed corpus, build-tag matrix (linux/darwin/windows)

---

## [v1.3.102] — 2026-05-16

### Fixed
- `TestIntegrationVerbose` JSON mode inheritance
- Orchestrated quorum test: missing identity registration before peer discovery

---

## [v1.3.101] — 2026-05-16

### Fixed
- Vault blob MCP tool names now match CLI schema (`vault_set_blob`, `vault_get_blob`)
- P2P data transfer resilience improvements
- Mesh orchestration timeout handling

---

## [v1.3.100] — 2026-05-15

### Added
- Enhanced P2P data transfer: chunked streaming with Reed-Solomon parity
- Mesh orchestration resilience: automatic retry on peer disconnect
- BEP-44 registry: identity handles stored as BitTorrent mutable items

---

## Older Releases

For releases prior to v1.3.100, refer to the [GitHub releases page](https://github.com/al-Zamakhshari/maknoon/releases) and git log:

```bash
git log --oneline --decorate v1.3.99 --no-walk
git log --oneline v1.3.0..v1.3.99 | head -50
```
