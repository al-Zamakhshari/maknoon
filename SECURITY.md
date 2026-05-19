# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| Latest  | ✅ Yes    |
| < 1.0   | ❌ No     |

## Reporting a Vulnerability

Maknoon is a security-critical tool. We treat all vulnerability reports seriously and aim to respond within **48 hours**.

**Please do not open a public GitHub issue for security vulnerabilities.**

### How to report

Send a report to **akhallaf@gmail.com** with:

1. A clear description of the vulnerability
2. Steps to reproduce
3. The version of Maknoon affected
4. Your assessment of severity (critical / high / medium / low)
5. Any proof-of-concept code (if applicable)

Encrypt your report with our ML-DSA-87 signing key if the content is sensitive:

```bash
maknoon encrypt report.txt -p @maknoon-security@al-zamakhshari.com -o report.txt.makn
```

### What to expect

- **48 hours**: Initial acknowledgement
- **7 days**: Severity assessment and remediation timeline
- **90 days**: Public disclosure (coordinated with reporter)

We follow [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure). Reporters who follow this process will be credited in the release notes unless they prefer anonymity.

## Scope

### In scope

- Cryptographic weaknesses in the encryption, signing, or key derivation pipeline
- Authentication or authorization bypasses in the vault or MCP server
- SSRF or path traversal vulnerabilities
- Memory safety issues (use-after-free, buffer overflows)
- Insecure defaults that could lead to key or data exposure
- Supply chain vulnerabilities in the build or release pipeline

### Out of scope

- Theoretical attacks without a practical exploit
- Issues requiring physical access to the machine
- Vulnerabilities in dependencies that are already publicly known and tracked upstream
- Social engineering

## Security design

Maknoon's security architecture is documented in [`docs/architecture/threat-model.md`](docs/architecture/threat-model.md).

Key properties:
- **Post-quantum cryptography**: ML-KEM-768 + X25519 hybrid KEM, ML-DSA-87 signatures (NIST-standardized)
- **Memory safety**: All private key material held in `memguard`-locked buffers, zeroed on release
- **No external key servers**: Private keys never leave the local machine; identity discovery uses HTTPS or DNS
- **Audit trail**: All cryptographic operations logged with hash-chained, ML-DSA-87 signed entries
