# Maknoon Documentation Suite
> **Enterprise-Grade Post-Quantum Cryptographic Engine**

## Executive Summary
Maknoon (مكنون) is a high-performance cryptographic engine designed to secure data against classical and quantum computational threats. By implementing NIST-standardized Post-Quantum Cryptography (PQC) within a **Unified Binary** architecture, Maknoon provides a scalable solution for data protection in both automated (MCP) and interactive (CLI) environments.

---

## V1.x Platform Architecture (Industrial Agility)

| Capability | Technical Specification |
| :--- | :--- |
| **PQC Encryption** | Hybrid HPKE utilizing ML-KEM-1024 (Kyber) and X25519. |
| **Unified Binary** | Single statically linked binary hosting both CLI and MCP server. |
| **Dual-Transport MCP**| Native support for local `stdio` and remote `sse` (HTTPS). |
| **Transport Security**| **Post-Quantum TLS 1.3** prioritization (ML-KEM hybrid). |
| **Industrial Agility** | Live cryptographic profile migration via MCP runtime management. |
| **Secret Sharding** | Shamir Secret Sharing (SSS) for decentralized vault governance. |
| **Streaming Engine** | Parallel sequencer model with 64KB constant-memory chunking. |
| **Memory Hygiene** | Deterministic buffer zeroization and RAM pinning via `mlock()`. |

---

## Documentation Index

### 1. [[Architecture]]
Technical specification of the **Unified Binary** design, the streaming pipeline, and the industrial sandbox filesystem layout.

### 2. [[Security Rationale]]
Analysis of the cryptographic primitives, the **Transport-Layer PQC** integration, and the hybrid security model.

### 3. [[CLI Command Reference]]
Comprehensive guide to the command-line interface, including the new `mcp` orchestration commands and **Viper** configuration.

### 4. [[AI Agent and Automation Integration]]
Documentation for the **Dual-Transport MCP** implementation, automated agent handshakes, and secure SSE gateways.

### 5. [[Post-Quantum Cryptographic Hardening Roadmap]]
Strategic engineering objectives for future enhancements, including hardware security module (HSM) integration and side-channel hardening.

---

> **V1.3 Industrial Milestone:** Maknoon has successfully passed four high-impact "Red-Team" missions (Blind Proxy, Multi-Bridge, Dead Man, and Agility), validating its readiness for enterprise autonomous orchestration.
