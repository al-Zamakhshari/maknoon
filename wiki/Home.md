# Welcome to the Maknoon Wiki

Maknoon (مكنون) is a premier, high-performance security suite designed for the post-quantum era. It provides robust file protection using bleeding-edge hybrid cryptography and hardware-locked memory safety.

## 🌟 Key Features
*   **Hybrid Post-Quantum Cryptography**: Combines NIST-standardized ML-KEM-768 with classical X25519.
*   **Absolute Memory Safety**: Utilizes `memguard` to pin secrets to RAM, defeating Go's GC and preventing disk swapping.
*   **Fingerprint Resistance (Stealth Mode)**: New in V3! Optional headerless encryption to make ciphertext indistinguishable from random noise.
*   **Native AI Agent Integration**: Includes an MCP server and automated discovery tools for seamless LLM integration.
*   **High Performance**: Efficient 64KB chunk streaming pipeline with multi-core parallelism.

## 📖 Table of Contents
1.  [[Architecture]] - Deep dive into the V3 streaming engine.
2.  [[Security Rationale]] - Why we chose Hybrid PQC and RAM pinning.
3.  [[CLI Reference]] - Exhaustive guide to commands and flags.
4.  [[Agent Integration]] - How to use Maknoon with AI assistants.
