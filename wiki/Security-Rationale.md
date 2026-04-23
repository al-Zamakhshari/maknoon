# Security Rationale

Maknoon is engineered to be a "Zero-Trust" CLI tool, focusing on modern threats like quantum computing and memory-based forensics.

## 1. Why Hybrid PQC?
Pure lattice-based cryptography (like Kyber/ML-KEM) is quantum-resistant but relatively new. To mitigate the risk of hidden mathematical weaknesses, Maknoon implements a **Hybrid Model**:
*   **X25519**: Provides a rock-solid classical foundation.
*   **ML-KEM-768**: Provides NIST-standardized quantum resistance.
*   **Outcome**: An attacker must break **BOTH** mathematical problems to compromise the data.

## 2. Hardware-Locked Memory Safety
Go is a garbage-collected language, which often leaves sensitive keys in RAM for indeterminate periods. Maknoon addresses this via `memguard`:
*   **RAM Pinning**: Uses the `mlock()` syscall to prevent secrets from being written to the OS swap file on disk.
*   **Deterministic Zeroization**: Secrets are manually zeroed out in RAM as soon as their operation completes.
*   **Guard Pages**: Protects against buffer overflow and unauthorized memory access.

## 3. Fingerprint Resistance (Stealth Mode)
Standard encrypted files often contain "Magic Bytes" (e.g., `MAKN`) that identify the tool used. Maknoon's `--stealth` mode removes these identifiers, making the file indistinguishable from random data. This provides **deniability** and resistance against traffic analysis.

## 4. Cryptographic Primitives
*   **AEAD**: XChaCha20-Poly1305 (192-bit extended nonces).
*   **KDF**: Argon2id (Memory-hard key derivation).
*   **Signatures**: ML-DSA-87 (Quantum-resistant authentication).

## 5. Threshold Security (SSS)
Maknoon provides M-of-N secret sharding for identities and vaults using Shamir's Secret Sharing (SSS) over $GF(2^8)$.

### Implementation Details:
*   **Mnemonic Encoding**: Shares are converted to BIP-39 style mnemonics for human-friendly "break-glass" scenarios.
*   **Checksum Verification**: Each share includes a SHA-256 based checksum to detect accidental word transposition or corruption.
*   **Panic-Free Reconstruction**: The reconstruction engine rigorously validates share uniqueness. Providing duplicate shares (e.g., the same mnemonic twice) returns a descriptive error rather than triggering a mathematical panic (division by zero), ensuring robust operation in automated environments.

## 6. File Lifecycle & Secure Deletion
Encryption only protects the ciphertext. To protect the original plaintext, Maknoon provides an optional `--shred` flag during encryption.

### The Shredding Reality
On modern storage media, "Secure Deletion" is a best-effort operation:
*   **SSD Wear Leveling**: SSD controllers remap writes to different physical cells to ensure even wear. Overwriting a file may not touch the original physical blocks.
*   **Copy-on-Write (COW)**: Filesystems like APFS, ZFS, and Btrfs create new versions of files instead of overwriting in place.
*   **TRIM/UNMAP**: While Maknoon overwrites data and calls `sync`, the actual physical erasure depends on the OS and hardware implementing TRIM commands.

**Recommendation**: Use `--shred` for immediate local hygiene, but rely on **Full Disk Encryption (FDE)** as your primary defense against physical forensics.
