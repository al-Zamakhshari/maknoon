# Maknoon — Project Evaluation

*Evaluated May 2026, v1.3.x. Revisit after each major release or audit.*

---

## Landscape comparison

| Tool | Encryption | Signatures | Vault | PQC | MCP | Audit | Fragment |
|---|---|---|---|---|---|---|---|
| **age** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **gpg** | ✅ | ✅ | ❌ | partial | ❌ | ❌ | ❌ |
| **pass/gopass** | via gpg | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **sops** | via KMS | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **HCP Vault** | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ |
| **Maknoon** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Scores

### Cryptographic soundness — 8/10

ML-KEM-768 + X25519 (X-Wing) is the NIST/IETF recommended hybrid. ML-DSA-87 is the
correct signature scheme. Argon2id at well-tuned parameters. CIRCL is maintained by
Cloudflare with serious scrutiny. AES-256-GCM is standard. The choices are correct and
conservative.

**Gap (−2):** No independent security audit. For a tool making security claims, that
matters. age, signify, and libsodium have been audited. Maknoon hasn't. The
implementation could be correct and still have subtle bugs a third party would catch.

### Unique value — 8/10

Two things nothing else does:

**MCP gateway.** No other crypto tool has a native MCP server. 45 PQC tools available
to AI agents via stdio or SSE is genuinely novel and well-timed. As agents handle
increasingly sensitive operations, having a purpose-built crypto gateway is real value.

**Integrated stack in one binary.** The combination of PQC encryption, threshold
signatures, an audited encrypted vault, identity publishing, and Reed-Solomon fragment
dispersal — in a single static binary with no runtime dependencies — doesn't exist
elsewhere.

**Gap (−2):** The `.makn` format is proprietary. No interoperability with age, gpg, or
any other tool. Significant adoption barrier for files that need to reach someone not
running Maknoon.

### Production readiness — 6/10

**Good:** 77% test coverage with a hard CI gate, 12 mission tests, man pages, native
packages (.deb/.rpm/.apk), goreleaser, audit chain verification, TPM 2.0 support.

**Missing:** No stable API contract (breaking changes between versions could silently
corrupt archived files), single maintainer (long-term maintenance risk), no formal
security audit, no independent key transparency, Windows is a second-class citizen.

### Usability — 7/10

One-liner friendly: variadic args, `--passphrase-fd`, `--dry-run`, `--recursive`,
session keys, NO_COLOR, `mkn` alias.

**Gap:** First-run experience is rough. Key distribution via WKD requires a web server.
The tool has too many entry points — a new user doesn't know whether to start with
`keygen`, `encrypt`, or `vault`. Compare with age: you generate a key in one command,
encrypt in one command, the key is just a string you can paste anywhere.

### Ecosystem fit — 8/10

Timing is right. NIST finalised FIPS 203 (ML-KEM) in 2024. The "harvest now, decrypt
later" threat is real for long-lived sensitive data. AI agent adoption is accelerating
and agents genuinely need crypto primitives. The MCP integration positions Maknoon
correctly for the next 3–5 years.

**Gap:** No entry in any Linux distribution's package manager yet, no keyserver
integration (keys can't be found by email the way gpg keys can), 48h identity TTL is
aggressively short for production use.

---

## Overall: 7.4 / 10

### Where counterparts win

| Use case | Better choice | Why |
|---|---|---|
| Simple file encryption between humans | **age** | Simpler, audited, key is a plain string |
| Existing PGP ecosystem | **gpg** | Interoperability, keyservers, signing infrastructure |
| Enterprise secrets | **HCP Vault** | Dynamic secrets, PKI CA, audit integrations |
| Personal passwords | **pass** | Simpler, battle-tested, gpg-backed |

### Where Maknoon wins clearly

- **PQC encryption today** — not waiting for a plugin or an experimental flag
- **AI agents that need crypto primitives** — MCP gateway is purpose-built for this
- **All-in-one without orchestrating four tools** — encryption + signing + secrets + audit in one binary
- **RAID-for-Privacy** — Reed-Solomon fragment dispersal; nothing else does this at CLI level
- **Crypto audit trail as a compliance requirement** — hash-chained, ML-DSA-87 signed log

### Risk factors

1. **Single maintainer** — the biggest structural risk for long-term adoption
2. **No formal audit** — required before recommending for regulated environments
3. **Proprietary format** — limits interoperability and therefore addressable market
4. **Key distribution UX** — WKD is correct but complex; needs a simpler path for non-technical users

### When to re-evaluate

- After a third-party security audit is completed
- When a second maintainer or organisation adopts the project
- If a major PQC-capable competitor (age with PQC plugin, gpg 2.6+) matures
- At each NIST algorithm revision that could affect ML-KEM or ML-DSA
