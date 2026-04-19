# CLI Reference

## Core Commands

### `maknoon encrypt [file/dir]`
Encrypts a single file or an entire directory.
-   `--compress`, `-c`: Enable Zstd compression.
-   `--public-key`, `-p`: Encrypt for specific Post-Quantum recipients.
-   `--sign-key`: Integrated digital signature.
-   `--stealth`: Omit magic header bytes.

### `maknoon decrypt [file]`
Decrypts and restores data.
-   `--output`, `-o`: Specify target path (supports `-` for stdout).
-   `--overwrite`: Bypass safety check for existing files.
-   `--private-key`, `-k`: Path to your identity key.

### `maknoon send [file/dir]`
Sends data via secure ephemeral P2P (Magic Wormhole style).
-   Generates a human-readable **Code** and a **Session Passphrase**.
-   Works across networks and NATs.
-   `--stealth`: Enable stealth mode for the transfer.

### `maknoon receive [code]`
Receives data from a peer using a wormhole code.
-   Prompts for the **Session Passphrase** provided by the sender.
-   `--output`, `-o`: Specify where to save the data.

### `maknoon info [file]`
Displays deep cryptographic metadata.
-   Outputs: Profile ID, Type (Symmetric/Asymmetric), KEM, SIG, and KDF details.
-   Use `--json` for automated parsing.

## Identity Management

### `maknoon keygen`
Generates a NIST-standard Post-Quantum identity.
-   Creates `.kem` and `.sig` key pairs.
-   Keys are protected by Argon2id.

### `maknoon identity active`
Lists all public keys available on the system. Optimized for AI agent discovery.

## Secret Management (Vault)

### `maknoon vault set [service]`
Securely stores a secret.
-   `--user`: Associate a username with the secret.
-   `--vault`: Specify a named vault database.

### `maknoon vault get [service]`
Retrieves a secret.

### `maknoon vault list`
Lists all stored services.
