## Summary

<!-- What does this PR do? One or two sentences. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change (flag, wire format, vault schema, or MCP tool API)
- [ ] Documentation / chore

## Changes

<!-- Bullet-point the significant changes. -->

## Testing

- [ ] `make test` passes
- [ ] `make smoke` passes (if touching crypto, vault, or MCP)
- [ ] Added / updated tests for the changed behaviour
- [ ] Man pages regenerated (`make man && git add man/`)

## Security checklist (for crypto / vault / network changes)

- [ ] Private key bytes are held in `memguard` buffers and cleared with `crypto.SafeClear()`
- [ ] New file paths are validated with `filepath.Clean` + `..` traversal check
- [ ] New network calls include SSRF mitigation
- [ ] No new external dependencies introduced without justification

## Breaking changes

<!-- If this is a breaking change, describe the migration path. -->

## Related issues

<!-- Closes #... -->
