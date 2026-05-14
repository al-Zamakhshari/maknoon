# Architectural Specification
> **Streaming-First Post-Quantum Cryptographic Engine**

## Executive Summary
Maknoon is architected as a high-performance, constant-memory cryptographic engine designed to mitigate both classical and quantum computational risks.

```mermaid
graph TD
    User[Human Operator] -- CLI / Ghost Chat --> Maknoon
    Agent[AI Agent] -- MCP stdio/sse --> Maknoon
    
    subgraph Maknoon [Maknoon Platform]
        Engine[Engine Core]
    end
    
    Maknoon -- PQC Keys --> Nostr[Nostr DHT / DNS]
    Maknoon -- Tunnel --> Wormhole[Magic Wormhole Relay]
    Maknoon -- Audit --> Logs[Compliance Logs]
    Maknoon -- Storage --> FS[Local Filesystem / Cloud Sidecar]
```

The system utilizes a modular streaming pipeline that decouples I/O operations from cryptographic transformations.

---

## Unified Binary Architecture
Starting with V3, Maknoon implements a **Unified Binary** design. A single statically linked binary hosts the CLI, the cryptographic engine, and the native Model Context Protocol (MCP) server.

```mermaid
graph TD
    Entry[Binary Entry Point] --> Parse{Command Resolution}
    Parse -- "encrypt/decrypt/..." --> CLI[CLI Controller]
    Parse -- "mcp" --> MCP{Transport Selection}
    
    CLI --> Engine[Central Engine Core]
    
    MCP -- "--transport stdio" --> Stdio[Stdio Transport]
    MCP -- "--transport sse" --> SSE[Secure SSE Transport]
    
    Stdio --> Engine
    SSE --> Engine
    
    Engine --> Policy{AgentPolicy?}
    Policy -- Yes --> Sandbox[Restricted OS View]
    Policy -- No --> OS[Standard OS View]
```

*   **Logic Consolidation**: The core logic resides in `pkg/crypto/engine.go`, which is consumed by both the CLI and MCP layers.
*   **Reduced Attack Surface**: By eliminating external dependencies and shared libraries, the binary provides a consistent security posture across all operational modes.
*   **Mode Selection**: The mode of operation is determined by the command-line entry point (e.g., `maknoon mcp` for server mode vs. `maknoon encrypt` for CLI mode).

---

## Dual-Transport MCP
Maknoon supports the Model Context Protocol (MCP) via two distinct transport mechanisms, enabling both local and remote agent orchestration.

| Transport | Implementation | Use Case |
| :--- | :--- | :--- |
| **Stdio** | Standard Input/Output pipe. | Local integration with IDEs (Cursor, VS Code) and desktop agents. |
| **SSE** | Server-Sent Events over HTTPS. | Remote gateways and cloud-native agentic microservices. |

### Post-Quantum Transport Security
Remote SSE sessions are secured via **PQ-TLS 1.3**. The server utilizes Go 1.23's native support for the `X25519MLKEM768` hybrid key exchange, ensuring the transport layer itself is resilient against "harvest now, decrypt later" attacks.

---

## Core Streaming Pipeline
The architecture centers on a **Parallel Sequencer Model** that processes data in discrete segments.

```mermaid
graph LR
    Input[Data Stream] --> Reader[64KB Chunk Reader]
    Reader --> W1[Worker 1]
    Reader --> W2[Worker 2]
    Reader --> Wn[Worker N]
    
    subgraph Transformation [Transformations]
        W1 -- Encrypt --> S1[Segment 1]
        W2 -- Encrypt --> S2[Segment 2]
        Wn -- Encrypt --> Sn[Segment N]
    end
    
    S1 --> Seq[Sequencer]
    S2 --> Seq
    Sn --> Seq
    
    Seq --> Output[Authenticated Ciphertext]
```

| Component | Technical Function |
| :--- | :--- |
| **I/O Reader** | Ingests data in 64KB atomic blocks to maintain $O(1)$ memory complexity. |
| **Worker Pool** | Executes cryptographic transformations in parallel across available CPU cores. |
| **Sequencer** | Reassembles processed segments in deterministic order, ensuring strict file integrity. |
| **Transformer Middleware** | Modular layer for on-the-fly archival (TAR), compression, and encryption. |

---

## Industrial Sandbox Layout
For containerized deployments, Maknoon utilizes a zero-OS `scratch` build. This environment enforces a minimal filesystem layout required for secure operation.

```mermaid
graph TD
    subgraph Host [Host Machine]
        direction TB
        subgraph Docker [Docker / K8s Node]
            direction LR
            Bin[maknoon binary]
            Config[config.json]
        end
    end
    
    subgraph Sandbox [Isolated Container Sandbox]
        direction TB
        Proc[Running Process UID 1000]
        Policy{AgentPolicy}
        
        Proc -- Validates --> Policy
        Policy -- "Allow (~/)" --> Workspace[Persistent Workspace]
        Policy -- "Block (/etc/)" --> Denied[Host Access DENIED]
    end
    
    Docker -- "volume mount" --> Workspace
    Docker -- "immutable" --> Bin
```

| Path | Purpose | Permissions |
| :--- | :--- | :--- |
| `/usr/local/bin/maknoon` | The immutable unified binary. | Read-Only (Root) |
| `/home/maknoon` | Primary working directory and persistent storage. | Read/Write (UID 1000) |
| `/tmp/maknoon` | Ephemeral storage for transient operations. | Read/Write (UID 1000) |

---

## Cryptographic Design
Maknoon implements a hybrid cryptographic stack that combines NIST-standardized lattice-based algorithms with battle-tested elliptic curve cryptography.

### Hybrid Key Encapsulation (HPKE)
The system utilizes **HPKE (RFC 9180)** to wrap File Encryption Keys (FEKs). This implementation employs a composite KEM:
*   **Lattice Component**: ML-KEM-1024 (Kyber) providing quantum resistance.
*   **Elliptic Curve Component**: X25519 for classical security and performance.

### Context-Aware Security
All cryptographic operations are bound to the file's metadata via the HPKE `info` parameter. This binding includes `ProfileID` and `Header Flags`, effectively mitigating "Recipient Transplantation" and metadata-tampering attacks.

---

## Post-Quantum L4 Tunnel Gateway
Maknoon implements a user-space **Post-Quantum L4 Tunnel** that allows AI Agents and human operators to provision secure network perimeters without requiring kernel-level modifications or root privileges.

```mermaid
graph TD
    Client[SOCKS5 Client] --> Proxy[SOCKS5 Gateway]
    Proxy -- Encapsulate --> QUIC[QUIC Stream]
    
    subgraph Tunnel [PQC Transport Layer]
        QUIC -- PQ-TLS 1.3 --> UDP[UDP Socket]
    end
    
    UDP -- ML-KEM Hybrid --> Peer[Remote Maknoon Peer]
```

*   **QUIC Transport**: Uses `github.com/quic-go/quic-go` for native user-space multiplexing and congestion control.
*   **Encapsulation Protocol**: Local TCP connections are bridged into independent QUIC streams. The destination address is transmitted as a post-quantum-secured metadata header during stream initiation.
*   **Memory Hygiene**: Plaintext network data is processed exclusively within hardware-locked **memguard enclaves**, with deterministic zeroization of buffers after every packet transmission.
*   **Zero-Trust Identity**: Tunnel handshakes utilize the platform's **ML-KEM-1024 + X25519** hybrid posture, neutralizing "harvest now, decrypt later" transport threats.

---

## Configuration Management (Viper)
V3 standardizes configuration using the **Viper** framework, providing a strict hierarchy for parameter resolution.

1.  **CLI Flags**: Immediate overrides provided during execution.
2.  **Environment Variables**: Prefixed with `MAKNOON_` (e.g., `MAKNOON_AGENT_MODE`).
3.  **Config File**: `config.json` or `.maknoon.yaml` in the user's home directory.
4.  **Defaults**: Hardcoded safe defaults within the engine.

---

## Testing Strategy
The V3 suite introduces a **Transport-Agnostic Mission** testing model.

*   **Mission Suites**: Tests verify engine behavior through high-level missions that run identically over CLI, Stdio-MCP, and SSE-MCP transports.
*   **Short Standardization**: Use of `testing.Short()` to skip network-intensive or hardware-bound (FIDO2) tests during rapid local iteration, while ensuring full coverage in CI/CD pipelines.
