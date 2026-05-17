# Security Rationale
> **Defense-in-Depth for the Post-Quantum Era**

## Executive Summary
Maknoon is engineered as a zero-trust cryptographic utility designed to provide long-term data confidentiality and integrity. The system mitigates emerging threats from quantum computation and advanced memory forensics through a combination of hybrid cryptographic models, deterministic memory hygiene, and decentralized identity verification.

---

## Cryptographic Architecture

### Hybrid Key Encapsulation (KEM)
To safeguard against potential mathematical weaknesses in nascent lattice-based algorithms, Maknoon employs a **Hybrid Security Model** for data-at-rest. This approach ensures that an adversary must compromise two distinct mathematical primitives to gain access to the underlying data.

| Component | Primitive | Security Basis |
| :--- | :--- | :--- |
| **Classical Layer** | X25519 (Curve25519) | Discrete Logarithm Problem (Elliptic Curve). |
| **Quantum Layer** | ML-KEM-768 (Kyber) | Module Learning With Errors (Lattice-Based). |
| **Integration** | X-Wing hybrid KEM (IETF draft-connolly-cfrg-xwing-kem) via Go's `crypto/hpke` | Combines X25519 and ML-KEM-768 shared secrets with domain separation. |

---

## Transport Layer PQC (PQ-TLS 1.3)
V3 introduces native support for **Post-Quantum TLS 1.3** to secure remote agent communications (MCP SSE transport). This ensures that even the transmission of encrypted assets is resilient against "Harvest Now, Decrypt Later" (SNDL) attacks.

*   **Hybrid Key Exchange**: Remote sessions prioritize the `X25519MLKEM768` curve preference. This uses a hybrid handshake where the session key is derived from both a classical Elliptic Curve Diffie-Hellman (ECDH) exchange and an ML-KEM (Kyber) encapsulation.
*   **Security ROI**: By securing the transport layer with PQC, Maknoon provides an additional layer of protection for metadata and command parameters that are processed before the engine's primary file encryption is applied.
*   **Protocol Compliance**: The implementation adheres to the latest IETF drafts for PQC in TLS 1.3, ensuring interoperability with modern secure gateways.

---

## Cryptographic Primitives
Maknoon utilizes a selection of high-performance, NIST-standardized primitives for symmetric encryption, authentication, and key derivation.

| Function | Algorithm | Specification |
| :--- | :--- | :--- |
| **Symmetric Cipher** | AES-256-GCM | 256-bit key, 12-byte nonce, hardware-accelerated. |
| **Digital Signatures** | ML-DSA-87 (Dilithium) | NIST-standardized quantum-resistant signatures. |
| **Non-Lattice KEM** | FrodoKEM-640 | High-security hedging against lattice cryptanalysis. |
| **Key Derivation** | Argon2id | Industrial Standard (3 iterations, 64MB RAM). |
| **Hashing** | SHA-3 / SHA-256 | High-performance, collision-resistant digests. |

### Cryptographic Agility: Non-Lattice Hedging
To protect against the theoretical risk of breakthroughs in structured lattice cryptanalysis (which would affect ML-KEM), Maknoon provides a **Conservative Profile**. This profile utilizes **FrodoKEM-640** (based on un-structured LWE) and **SLH-DSA** (Stateless Hash-Based Signatures), providing a fallback that does not rely on lattice assumptions.

---

## Memory Hygiene and Forensics
The engine prioritizes "Safe-in-Memory" operation to prevent the leakage of sensitive keys via operating system swap files or memory-scraping attacks.

> **Technical Safeguard:** Maknoon utilizes the `mlock()` system call to pin sensitive memory buffers, preventing them from being paged to disk. Upon completion of any cryptographic operation, these buffers are explicitly zeroed using deterministic patterns to ensure no residual data remains in RAM.

*   **Guard Pages**: Implementation of unauthorized-access boundaries around sensitive memory allocations.
*   **Safe-Clear Patterns**: Manual memory management for all File Encryption Keys (FEKs) and private key material.
*   **Forensic Resistance**: Minimization of the tool's memory footprint to reduce the attack surface for RAM-based extraction.

---

## Threshold Security and Identity Recovery
Maknoon implements **M-of-N Shamir’s Secret Sharing (SSS)** over $GF(2^8)$ to enable robust identity recovery without centralized escrow.

### Recovery Implementation
1.  **Mnemonic Encoding**: Shards are converted into BIP-39 style mnemonics for human-centric "break-glass" recovery.
2.  **Deterministic Validation**: The reconstruction engine validates share uniqueness and integrity (via SHA-256 checksums) before attempting reconstruction.
3.  **Fault Tolerance**: The system provides descriptive error reporting for duplicate or corrupted shards, preventing mathematical instabilities during recovery.

---

## Data Integrity and Shredding
While Maknoon provides tools for secure data disposal, it adheres to a factual assessment of modern storage hardware limitations.

| Mechanism | Capability | Limitation |
| :--- | :--- | :--- |
| **Bit-Level Overwrite** | Replaces file contents with high-entropy noise. | May be bypassed by SSD wear-leveling controllers. |
| **Fsync Integration** | Forces physical I/O writes to the storage medium. | Does not guarantee physical block erasure on COW filesystems. |
| **Header Stealth** | Removes magic bytes to ensure indistinguishability. | Does not hide file existence or size. |

> **Operational Recommendation:** While the `--shred` flag provides an initial layer of local data hygiene, organizations should utilize **Full Disk Encryption (FDE)** as the primary defense against physical forensics and unauthorized hardware access.

---

## Security Compliance and Auditability
Maknoon supports enterprise-level governance through its pluggable audit decorator architecture.

*   **Structured Auditing**: Every cryptographic event can be logged as a structured JSON record containing non-sensitive metadata (e.g., algorithm used, timestamp, success/fail status).
*   **Privacy-Preserving Logs**: The audit system automatically masks PII, such as home directory paths and specific filenames, to comply with privacy regulations like GDPR and CCPA.
*   **Immutability**: Once an identity is published to a decentralized registry (e.g., Nostr), the record is signed with ML-DSA-87, providing immutable proof of ownership.
