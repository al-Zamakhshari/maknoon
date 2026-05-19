# Session Keys — Bulk Encryption Without Per-File KDF Cost

## Overview

Every symmetric encryption in Maknoon runs Argon2id to derive a file encryption key from your passphrase. Argon2id is deliberately slow (~26ms at default settings) to resist brute-force attacks. For a single file, this is imperceptible. For thousands of files, it dominates.

**Session keys** solve this by running Argon2id once, then reusing the derived key across all files in the same operation. The KDF cost is paid once; every subsequent file encrypts at hardware memory bandwidth.

---

## Performance Impact

| Files | Per-file KDF | Session key | Savings |
|-------|-------------|-------------|---------|
| 100   | ~2.6s       | ~26ms       | ~99%    |
| 1,000 | ~26s        | ~26ms       | ~99.9%  |
| 10,000| ~4.3 min    | ~26ms       | ~99.99% |

---

## Basic Usage

```bash
# Derive a session key (prints 64-char hex = 32 bytes)
KEY=$(maknoon session derive -s "my-passphrase")

# Use it to encrypt multiple files without per-file KDF
for f in documents/*.pdf; do
  maknoon encrypt "$f" --session-key "$KEY" -o "${f}.makn"
done
```

The session key can be passed to both `encrypt` and `decrypt`:

```bash
# Decrypt with the same session key
KEY=$(maknoon session derive -s "my-passphrase")
maknoon decrypt archive.makn --session-key "$KEY" -o archive/
```

---

## JSON Output Mode

For scripting and pipeline integration, use `--json` to get both the key and its salt:

```bash
maknoon session derive -s "my-passphrase" --json
# {
#   "key":  "a3f2...c1b0",
#   "salt": "9e4d...7a12"
# }
```

The `salt` is used internally to record the KDF parameters in the file header, so decryption works without re-deriving.

---

## Interactive Passphrase Entry

Omit `-s` and Maknoon will prompt securely (no echo):

```bash
KEY=$(maknoon session derive)
# Passphrase: [hidden input]
```

---

## Security Notes

- **Keep session keys in memory only.** Never write a raw session key to disk or include it in logs.
- Use environment variables to pass keys between commands in scripts rather than command-line arguments (which appear in shell history):
  ```bash
  export MAKNOON_SESSION_KEY=$(maknoon session derive -s "$PASS")
  maknoon encrypt file.txt --session-key "$MAKNOON_SESSION_KEY"
  ```
- Session keys have the same security as a full passphrase — treat them with the same care.
- The key is derived from the passphrase using Argon2id with the same parameters as normal encryption, so cryptographic strength is identical.

---

## When Not to Use Session Keys

- **Interactive, one-file operations** — the 26ms overhead is invisible to a human.
- **When you want unique KDF salts per file** — normal encryption derives a fresh key for each file, which is marginally stronger. Session keys share the same derived key across all files.
- **When passphrases change per file** — session keys only make sense when all files share the same passphrase.
