# Contributing to Maknoon

Thank you for your interest in contributing. Maknoon is a security-critical tool — we hold contributions to a high bar.

## Before you start

- **Security issues**: Do not open a public issue. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.
- **Large changes**: Open an issue first to discuss the approach before writing code.
- **Dependencies**: New dependencies require explicit justification. Run `go mod tidy` and explain why the dep is necessary.

## Development setup

```bash
git clone https://github.com/al-Zamakhshari/maknoon
cd maknoon
go build ./...          # verify the build
make test               # run unit tests
make smoke              # run smoke suite (requires a built binary)
make install-hooks      # install the pre-commit hook (auto-regenerates man pages)
```

## Code standards

### Go style
- Standard `gofmt` + `go vet` + `staticcheck` — the CI enforces all three
- No `fmt.Println` in library code; use `log/slog`
- No `panic` without an unrecoverable reason documented in a comment
- Explicit error handling — do not swallow errors with `_`

### Security requirements
- All private key bytes must be held in `memguard` buffers and cleared with `crypto.SafeClear()` after use
- No new cryptographic primitives — use only what is already in the stack (`cloudflare/circl`, `golang.org/x/crypto`)
- All file path operations must use `filepath.Clean` and check for `..` traversal
- New network-facing code must include SSRF mitigation (see `registry_util.go`)
- Any new capability that agents can invoke must be gated by the policy system

### Tests
- Unit tests for all new exported functions
- If you add a CLI command, add it to `commands_*_test.go` in the mission coverage suite
- Fuzz targets for any new parser or binary format

## Pull request process

1. Branch from `main` — name your branch `feat/`, `fix/`, or `chore/` prefixed
2. Keep PRs focused — one logical change per PR
3. Fill in the PR template completely
4. All CI checks must pass before review
5. For cryptographic changes, tag a reviewer with crypto expertise

### Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(vault): add export command
fix(registry): correct SSRF guard for IPv6 literals
chore(deps): upgrade circl to v1.7.0
docs(fragment): add rclone integration guide
```

## What we're looking for

Good contributions include:
- Bug fixes with a test that reproduces the issue
- Documentation improvements (especially examples)
- Performance improvements with benchmarks showing the improvement
- New registry backends implementing `IdentityRegistry`
- New cloud backends for fragment distribution

We are cautious about:
- New dependencies (binary size and supply chain)
- Changes to the wire format of `.makn` files (backward compat)
- Changes to the vault schema (migration required)
- New MCP tools without typed argument schemas

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
