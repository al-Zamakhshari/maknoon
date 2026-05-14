# Hardware Hardening Guide (Phase 8)
> **Binding Maknoon Identities to Silicon Trust (TPM 2.0 & FIDO2)**

Maknoon's Phase 8 introduces industrial-grade hardware hardening, ensuring that private cryptographic material never exists in plain-text within host memory. This guide covers the integration of TPM 2.0 (for platform binding) and FIDO2 (for human-presence verification).

---

## 🛡️ TPM 2.0: Platform Configuration Binding

TPM hardening allows you to seal keys to the specific state of your hardware. If the bootloader is tampered with or Secure Boot is disabled, the TPM will refuse to unseal the keys.

### 1. Requirements
*   A Linux environment with `/dev/tpmrm0` (TPM Resource Manager).
*   `go-tpm` compliant hardware (TPM 2.0).

### 2. Basic Sealing
Generate an identity where the private keys are encrypted by the TPM's Storage Root Key (SRK).
```bash
maknoon keygen corporate-id --tpm
```

### 3. PCR-Bound Sealing (Advanced)
You can bind keys to specific **Platform Configuration Registers (PCRs)**. Common PCRs include:
*   **PCR 0**: Core System Firmware.
*   **PCR 7**: Secure Boot State.
*   **PCR 14**: Kernel Measurement.

To generate a key that only unlocks if Secure Boot is active and the Kernel hasn't changed:
```bash
maknoon keygen secure-id --tpm --tpm-pcrs 7,14
```

### 4. Usage
When performing any operation (encryption, signing, vault access), simply pass the `--tpm` flag:
```bash
maknoon encrypt sensitive.pdf --identity secure-id --tpm
```

---

## 🔑 FIDO2: Human-Presence Verification

FIDO2 hardening binds key unlocking to a physical gesture (tapping a YubiKey or Nitrokey). This prevents "headless" malware from using your keys even if your machine is compromised.

### 1. Enrollment
Enroll your physical security key during identity generation. You will be prompted for your FIDO2 PIN.
```bash
maknoon keygen personal-id --fido2
```
*Note: This creates a `.fido2` metadata file alongside your `.key` file.*

### 2. Multi-Factor Unlocking
When using a FIDO2-protected identity, Maknoon will require:
1.  Your **Passphrase** (Something you know).
2.  Your **FIDO2 PIN** (Something you have/know).
3.  A **Physical Touch** (Something you do).

```bash
maknoon sign critical-manifest.json --identity personal-id
```

---

## 🏗️ Technical Architecture

Maknoon uses a **Layered KeyStore Wrapper** pattern:
1.  **Base Layer**: Filesystem (Encrypted Blobs).
2.  **Middle Layer**: TPM Wrapper (Seals/Unseals the blobs using hardware-protected policy sessions).
3.  **App Layer**: The Engine interacts with the standard `KeyStore` interface, remaining agnostic to the hardware complexity.

```mermaid
graph LR
    A[Engine] --> B[TPMKeyStore Wrapper]
    B --> C[PCR Policy Check]
    C --> D[Hardware Unseal]
    D --> E[FileSystemKeyStore]
    E --> F[(.key Blob)]
```

### Forensic Integrity
All hardware access attempts (success or failure) are recorded in the **Chained Forensic Audit Log**.
*   **Action**: `load_identity`
*   **Meta**: `tpm: true, pcrs: [7,14]`
