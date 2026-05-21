# Maknoon — 5-Minute Quick Start

Two paths: **symmetric** (one person, passphrase) and **asymmetric** (Alice → Bob, public key).

---

## Path A — Symmetric (single user)

```bash
# 1. Generate your identity (ML-KEM-768 + ML-DSA-87 keypair, ~500 ms)
maknoon keygen -o alice

# 2. Encrypt a file
maknoon encrypt report.pdf -s "my-passphrase" -o report.pdf.makn

# 3. Decrypt it
maknoon decrypt report.pdf.makn -s "my-passphrase" -o report.pdf

# 4. Inspect without decrypting
maknoon info report.pdf.makn
```

**Encrypting many files at once (one KDF call, not N):**
```bash
maknoon encrypt logs/ --recursive -s "my-passphrase"
maknoon decrypt logs/ --recursive -s "my-passphrase"
```

---

## Path B — Asymmetric (Alice sends to Bob)

```bash
# Alice generates her identity
maknoon keygen -o alice

# Alice publishes her public key (WKD — requires a web server)
maknoon identity publish @alice@example.com --wkd

# Bob encrypts a file to Alice (resolves her key from WKD/DNS)
maknoon encrypt secret.txt -p @alice@example.com -o secret.makn
# Prints: » encrypting to mk1a2b3c4d5e6f7890 (@alice@example.com)

# Alice decrypts using her private key
maknoon decrypt secret.makn -k alice.kem.key -o secret.txt
```

---

## Passphrase tips

| Method | Command |
|---|---|
| Environment variable | `MAKNOON_PASSPHRASE=secret maknoon encrypt file.txt` |
| From file | `maknoon encrypt file.txt --passphrase-file /run/secrets/pass` |
| From fd (no stdin conflict) | `maknoon encrypt - --passphrase-fd 3  3<<<mypass` |

---

## Vault (secret storage)

```bash
# Store a credential
maknoon vault set github --vault myapp -s "vault-pass"

# Retrieve it
maknoon vault get github --vault myapp -s "vault-pass"

# Unlock once for a session (skips per-operation KDF)
maknoon vault unlock myapp -s "vault-pass"
maknoon vault get github --vault myapp   # instant — no KDF
maknoon vault lock myapp
```

---

## Bulk encryption with session keys (fastest)

```bash
# Derive once — pay Argon2id one time
KEY=$(maknoon session derive --passphrase mypass)

# Encrypt hundreds of files at AES speed
maknoon encrypt *.log --session-key "$KEY"

# Decrypt at the same speed
maknoon decrypt *.log.makn --session-key "$KEY"
```

---

## Back up your identity

```bash
# Split your private key into 3 shares (any 2 recover it)
maknoon identity backup alice --shares 3 --threshold 2

# Store each share in a separate secure location.
# Recover with:
maknoon identity combine <share1> <share2> --output alice-restored
```

---

## Next steps

- [`docs/user-guides/session-keys.md`](../user-guides/session-keys.md) — bulk encryption patterns
- [`docs/user-guides/fragment-distribution.md`](../user-guides/fragment-distribution.md) — RAID-for-Privacy
- [`docs/integration/mcp-server.md`](../integration/mcp-server.md) — AI agent integration
- [`docs/architecture/threat-model.md`](../architecture/threat-model.md) — what Maknoon protects against
