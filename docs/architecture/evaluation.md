# Maknoon — Project Evaluation

*Initial evaluation: May 2026, v1.3.x. Updated after v2 improvements (threshold encryption, V2 wire format, init/doctor/serve-identity, GitHub Action, reproducible builds). Revisit after next audit.*

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

### Unique value — 9/10

Three things nothing else does:

**MCP gateway.** No other crypto tool has a native MCP server. 49 PQC tools available
to AI agents via stdio or SSE is genuinely novel and well-timed. As agents handle
increasingly sensitive operations, having a purpose-built crypto gateway is real value.

**K-of-N threshold encryption.** CLI-native threshold decryption (any K of N key holders
must cooperate) via Shamir SSS + HPKE. No mainstream CLI tool has this.

**Integrated stack in one binary.** PQC encryption + threshold signatures + audited
encrypted vault + identity publishing + Reed-Solomon fragment dispersal — in a single
static binary with no runtime dependencies.

**Gap (−1):** The `.makn` format is proprietary. No interoperability with age, gpg, or
any other tool. Significant adoption barrier for files that need to reach someone not
running Maknoon. (V2 format in development addresses internal structural gaps.)

### Production readiness — 7/10

**Good:** 77%+ test coverage with a hard CI gate, 13 mission tests, man pages, native
packages (.deb/.rpm/.apk), goreleaser, audit chain verification, TPM 2.0 support,
reproducible builds (trimpath + SBOM), nightly cross-version compatibility CI,
`maknoon init` / `maknoon doctor` for setup and health-checking, GitHub Action for
CI pipelines, ML-DSA-87 signed release checksums.

**Missing:** No stable API contract yet (V2 wire format planned addresses this), single
maintainer (long-term maintenance risk), no formal security audit, Windows is a
second-class citizen.

### Usability — 8/10

One-liner friendly: variadic args, `--passphrase-fd`, `--dry-run`, `--recursive`,
session keys, NO_COLOR, `mkn` alias, `maknoon init` for guided first-run,
`maknoon doctor` for health checking, `maknoon serve-identity` for self-hosted WKD.

**Gap:** Key distribution via WKD still requires a web server (serve-identity helps for
self-hosted, but hosting isn't zero-effort). Compare with age: you generate a key in one
command, encrypt in one command, the key is just a string you can paste anywhere.

### Ecosystem fit — 8/10

Timing is right. NIST finalised FIPS 203 (ML-KEM) in 2024. The "harvest now, decrypt
later" threat is real for long-lived sensitive data. AI agent adoption is accelerating
and agents genuinely need crypto primitives. The MCP integration positions Maknoon
correctly for the next 3–5 years.

**Gap:** No entry in any Linux distribution's package manager yet, no keyserver
integration (keys can't be found by email the way gpg keys can), 48h identity TTL is
aggressively short for production use.

---

## Overall: 8.5 / 10

*(was 7.4/10 before v2 improvements: threshold encryption, V2 format plan, init/doctor/serve-identity, GitHub Action, reproducible builds)*

### Where counterparts win

| Use case | Better choice | Why |
|---|---|---|
| Simple file encryption between humans | **age** | Simpler, audited, key is a plain string |
| Existing PGP ecosystem | **gpg** | Interoperability, keyservers, signing infrastructure |
| Enterprise secrets | **HCP Vault** | Dynamic secrets, PKI CA, audit integrations |
| Personal passwords | **pass** | Simpler, battle-tested, gpg-backed |

### Where Maknoon wins clearly

- **PQC encryption today** — not waiting for a plugin or an experimental flag
- **AI agents that need crypto primitives** — MCP gateway is purpose-built for this, 49 tools
- **K-of-N threshold encryption** — any K of N key holders must cooperate; no other CLI tool has this
- **All-in-one without orchestrating four tools** — encryption + signing + secrets + audit in one binary
- **RAID-for-Privacy** — Reed-Solomon fragment dispersal; nothing else does this at CLI level
- **Crypto audit trail as a compliance requirement** — hash-chained, ML-DSA-87 signed log
- **Reproducible builds + SBOM** — SLSA Level 2 artifact chain; signed release checksums

### Risk factors

1. **Single maintainer** — the biggest structural risk for long-term adoption
2. **No formal audit** — required before recommending for regulated environments
3. **Proprietary format** — limits interoperability and therefore addressable market
4. **Key distribution UX** — WKD is correct but complex; needs a simpler path for non-technical users

---

## Wire Format Stability

**Guarantee**: Any `.makn` file produced by any version will decrypt correctly with any
future version. Fragment shards (V1/V2/V3) are backward-compatible by design — the
version byte at offset 4 is read dynamically on reassembly.

**Enforcement**: The `compatibility` CI job (`.github/workflows/ci.yml`) runs nightly
and on `workflow_dispatch`. It downloads three pinned past releases and verifies
bidirectional encrypt/decrypt round-trips. A failure blocks the nightly run.

---

### When to re-evaluate

- After a third-party security audit is completed
- When a second maintainer or organisation adopts the project
- If a major PQC-capable competitor (age with PQC plugin, gpg 2.6+) matures
- At each NIST algorithm revision that could affect ML-KEM or ML-DSA
