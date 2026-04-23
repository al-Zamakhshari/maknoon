# Implementation Plan: Maknoon v3.0 (Industrial-Grade Architecture)

## Background & Motivation
While the recent "Policy-Driven Service" refactoring established a robust security perimeter (the Agent Sandbox) and decoupled CLI state from business logic, the core library still relies on string-matched errors, tightly coupled progress tracking, and monolithic pipeline functions. 

To elevate Maknoon to an industrial-grade library suitable for broad programmatic integration (via MCP, REST APIs, or Go imports), we will implement a series of structural design patterns.

## Overall Strategy & Phasing
This refactoring will be executed in four distinct phases, ordered to minimize disruption and build upon each foundational improvement.

---

### Phase 1: Strong Error Typing (The Foundation)
Currently, agents and external callers must rely on fragile substring matching (e.g., `strings.Contains(err.Error(), "security policy")`) to determine failure reasons.

**Objective:** Implement a typed error hierarchy in `pkg/crypto`.

**Implementation Steps:**
1.  Create `pkg/crypto/errors.go`.
2.  Define specific error structs implementing the `error` interface:
    *   `ErrPolicyViolation` (Path access denied, resource limit exceeded).
    *   `ErrAuthentication` (Wrong passphrase, bad FIDO2 PIN, invalid signature).
    *   `ErrCrypto` (Decryption failed, MAC mismatch).
    *   `ErrState` (Missing keys, uninitialized vaults).
3.  Refactor `pkg/crypto/policy.go` and `identity.go` to return these typed errors using `%w` wrapping where appropriate.
4.  Update the MCP Server (`integrations/mcp/main.go`) to use `errors.As()` to inspect the error type and return structured JSON-RPC responses (e.g., setting a specific `code` or `is_security_violation` flag).

---

### Phase 2: The Observer Pattern (Decoupling Telemetry)
The `Options` struct currently accepts a `ProgressReader` (an `io.Writer` masquerading as a reader for progress bars), which loosely couples the core crypto pipeline to UI rendering concepts.

**Objective:** Implement a clean Event/Telemetry stream emitted by the `Engine`.

**Implementation Steps:**
1.  Define an `EngineEvent` interface and concrete event types in `pkg/crypto/engine.go` (e.g., `EventEncryptionStarted`, `EventChunkProcessed`, `EventHandshakeComplete`).
2.  Add an `EventStream chan<- EngineEvent` to the `Options` struct or the `Engine` configuration.
3.  Refactor `EncryptStream` and `DecryptStream` to emit events to this channel (if provided) rather than wrapping an `io.TeeReader` blindly.
4.  In the CLI layer (`cmd/maknoon`), launch a goroutine that consumes this event stream and drives the `progressbar` or `slog` output, completely isolating the UI from the crypto loop.

---

### Phase 3: The Decorator Pattern (Pipeline Middleware)
The `Protect` and `Unprotect` functions handle everything: path resolution, archiving, compression, symmetric/asymmetric switching, and file writing. This makes them difficult to test in isolation and hard to extend.

**Objective:** Refactor the core processing loops into a chain of interchangeable `Transformer` interfaces.

**Implementation Steps:**
1.  Define a `Transformer` interface in `pkg/crypto`:
    ```go
    type Transformer interface {
        Wrap(r io.Reader, w io.Writer) (io.Reader, io.Writer, error)
    }
    ```
2.  Implement concrete decorators:
    *   `ArchiveTransformer` (handles `tar` creation/extraction).
    *   `CompressTransformer` (handles `zstd`).
    *   `EncryptTransformer` (handles the actual AEAD/HPKE stream).
3.  Refactor `Engine.Protect` to act as an orchestrator that chains these decorators together based on the provided `Options.Flags`.

---

### Phase 4: Registry Factory (Extensibility)
The `NewIdentityRegistry` function is hardcoded to return a `MultiRegistry` containing only DNS and Nostr.

**Objective:** Implement a plugin-like factory pattern for Identity Discovery.

**Implementation Steps:**
1.  Create a package-level registry map: `var registries = make(map[string]func() IdentityRegistry)`.
2.  Implement a `RegisterRegistry(name string, factory func() IdentityRegistry)` function.
3.  Have the `DNS` and `Nostr` implementations self-register during `init()`.
4.  Update the `Config` to allow users to specify which registries to query and in what order, allowing external developers to import `maknoon` and inject custom registries (e.g., LDAP, Active Directory) without forking the codebase.

## Verification Strategy
Each phase will be verified by running the full integration test suite (`go test ./...`). Because these are structural refactorings, the core behavioral guarantees (sandbox limits, wire formats, cryptographic agility) must remain identical. We will add specific unit tests for the new Error types and Event streams.
