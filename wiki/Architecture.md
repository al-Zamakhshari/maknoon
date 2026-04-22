# Maknoon Architecture

Maknoon is built around a centralized, high-performance streaming engine designed for constant memory usage and massive scalability.

## 🏗 Core Pipeline
The tool utilizes a **64KB Chunk Streaming** model. Whether you are encrypting a 10KB text file or a 100GB database, Maknoon maintains a stable memory footprint of approximately 64KB per parallel worker.

### The Sequencer Model
1.  **Reader**: Reads the input stream in 64KB blocks.
2.  **Worker Pool**: Encrypts/Decrypts chunks in parallel across all available CPU cores.
3.  **Sequencer**: Reassembles the processed chunks in the correct order to ensure file integrity.

## 🛡 Hybrid KEM Integration (V3)
In version 3, Maknoon solidified the **Hybrid Key Encapsulation Mechanism** via HPKE (RFC 9180) and introduced **Stealth Mode**.
*   **Encapsulation**: The File Encryption Key (FEK) is wrapped using a composite of ML-KEM-768 (lattice-based) and X25519 (elliptic curve).
*   **Context Binding**: Every encryption is mathematically bound to the file's `ProfileID` and `Header Flags` via the HPKE `info` parameter. This prevents "Recipient Transplantation" attacks.

## 📦 Directory Streaming
When a directory is provided as input, Maknoon streams it through an internal **TAR encoder** on-the-fly. This allows for seamless encryption of entire file structures into a single `.makn` file without creating temporary archives on disk.

## 🛡 Global Identity & Recovery (v1.5)
The architecture includes a decentralized discovery and recovery layer:
*   **dPKI Bridge**: An abstract registry interface that maps human-readable handles (`@name`) to PQC public keys. It enforces local **Petname** overrides for zero-server trust.
*   **Self-Signed Records**: All identity records are signed using **ML-DSA-87**, providing cryptographic proof of ownership that persists even on untrusted discovery layers.
*   **Nostr Discovery**: Maknoon leverages the global **Nostr** relay network as its primary decentralized discovery layer. Because PQC keys are large (~5KB), Nostr's metadata events (Kind 0) provide a much more robust transport than traditional DHTs.
## 📜 The Maknoon Philosophy (Modern Unix)

Maknoon is designed as a **Modern Unix Utility**. We apply the Unix philosophy where it enhances security and efficiency, but we consciously deviate where modern requirements (like PQC and AI Agents) demand more structure.

### 1. Unix Alignment
*   **The Rule of Composition**: Almost every core function in `pkg/crypto` takes an `io.Reader` and `io.Writer`. Maknoon can stream a 100GB file through a 64KB RAM window.
*   **The Rule of Separability**: Core cryptographic logic is strictly isolated in `pkg/crypto`, while CLI policy is managed in `cmd/maknoon`.
*   **The Rule of Representation**: Knowledge is folded into data. CLI capabilities are described via `maknoon schema`, and file metadata is bound into headers.

### 2. Modern Deviations
*   **Structured Output (JSON)**: While classic Unix favors raw text, Maknoon treats **JSON** as the "universal text" for AI Agents and automated pipelines.
*   **Post-Quantum Payload Scale**: PQC keys and signatures are physically large (~5KB). We deviate from "small is beautiful" to ensure nation-state level security.
*   **Decentralized Discovery**: We break the "hermetic filter" model of Unix by integrating **Nostr** for global, serverless identity discovery, acknowledging that modern identity is global, not local.
