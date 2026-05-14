# Post-Quantum L4 Tunnel Gateway
> **Programmable User-Space Secure Perimeters with Phase 7.4 Resilience**

## Overview
The Maknoon L4 Gateway provides a mechanism for AI Agents and human operators to establish secure, post-quantum network tunnels without administrative privileges. 

### Phase 7.4: Resilient Striping (RAID-for-Networking)
Unlike standard tunnels that fail if the underlying session drops, Maknoon's **Resilient Mode** stripes data across multiple parallel "lanes" (sub-sessions) using **Reed-Solomon erasure coding**. 

*   **Survivability**: If a tunnel is configured with `N` data lanes and `M` parity lanes, it can survive the total failure of up to `M` parallel connections with zero packet loss or connection drops at the application layer.
*   **Performance**: Data is processed in parallel across lanes, utilizing multi-core hardware to maximize throughput.
*   **Anonymity**: Traffic is fragmented across multiple network paths (if configured), complicating traffic analysis.

---

## Configuration & Usage

### 1. Simple PQC Tunnel
A standard point-to-point tunnel secured by ML-KEM.
```bash
maknoon tunnel start --remote "target.host:4433" --port 1080
```

### 2. Resilient Resilient Gateway (Data=2, Parity=2)
The strongest mode, surviving 50% lane failure.
```bash
maknoon tunnel start --remote "target.host:4433" \
  --data-lanes 2 \
  --parity-lanes 2 \
  --port 1080
```

### 3. P2P Mesh Tunnel
Uses libp2p DHT for discovery and NAT traversal.
```bash
maknoon tunnel start --p2p --p2p-addr "/ip4/1.2.3.4/tcp/4433/p2p/PEER_ID" --port 1080
```

---

## Technical Architecture

### Component Stack
1.  **SOCKS5 Gateway**: A concurrent proxy listener that accepts local TCP connections.
2.  **Resilient MuxER**: The Phase 7.4 engine that handles Reed-Solomon striping and reassembly.
3.  **PQ-TLS 1.3 Handshake**: A secure handshake utilizing **ML-KEM-1024 + X25519** hybrid key exchange.
4.  **Enclave Buffer Pool**: Hardware-locked memory (`memguard`) for packet processing.

### Performance Tuning
The tunnel performance is governed by:
*   `--data-lanes` / `--parity-lanes`: Higher parity increases reliability but also CPU overhead.
*   `MAKNOON_PERF_CONCURRENCY`: Controls the internal worker pool for cryptographic transformations.
*   **Chunk Size**: Optimized at **64KB** for ideal balance between latency and RS efficiency.

---

## Security Posture

### Post-Quantum Resistance
Handshakes prioritize `X25519MLKEM768`. This ensures that traffic captured today cannot be decrypted by future quantum computers (Harvest Now, Decrypt Later protection).

### Memory Hygiene
Maknoon utilizes a specialized memory pipeline:
*   **Locked Buffers**: All network I/O uses `memguard.LockedBuffer`.
*   **Deterministic Zeroization**: Every buffer is explicitly wiped using `SafeClear` before being returned to the pool.

---

## AI Agent Integration (MCP)
Agents manage the tunnel lifecycle using:

| Tool | Action |
| :--- | :--- |
| `mcp_maknoon_tunnel_start` | Initializes the tunnel with optional `--data-lanes`. |
| `mcp_maknoon_tunnel_status` | Returns throughput, lane health, and handshake metadata. |
| `mcp_maknoon_tunnel_stop` | Tears down the tunnel and clears memory. |
