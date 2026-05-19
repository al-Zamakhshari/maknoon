# Operations Runbook

Procedures for the Maknoon on-call engineer. Keep this updated as the system evolves.

---

## 1. Nightly Mission Failure

Nightly Docker missions run at 02:00 UTC via GitHub Actions schedule. If the `missions` job fails:

### Quick triage

```bash
# Download the artifact from the failed run
gh run download <run-id> --name mission-reports-<run-id> --dir /tmp/mission-reports

# Print the pass/fail summary
bash scripts/mission-summary.sh /tmp/mission-reports
```

### Re-run a single mission locally

```bash
# Ensure Docker is running
docker info

# Run one mission (example: quorum)
MISSION_REPORT_FILE=/tmp/quorum-report.jsonl bash scripts/mission-quorum-verify.sh

# Check result
cat /tmp/quorum-report.jsonl
```

### Capture container logs from a failed mission

```bash
# After a failure the fail_trap captures logs automatically.
# To manually inspect after the fact:
docker compose -f deploy/docker/mission-quorum.yml logs --tail 200

# For a specific service
docker compose -f deploy/docker/mission-quorum.yml logs guardian-1 --tail 50
```

### Common failure causes

| Symptom | Likely cause | Fix |
| :--- | :--- | :--- |
| `wait_for_condition` timeout on identity | Container startup too slow | Increase `wait_for_condition` timeout in the script |
| `checked_exec FAILED` on vault set | Wrong passphrase in test | Check test passphrase in docker-compose YAML |
| Shard is null | `jq` path mismatch after CLI change | Verify `maknoon vault split --json` output structure |

---

## 2. Govulncheck New Vulnerability

If the `Check Vulnerabilities` CI step fails with `new vulnerabilities detected: GO-XXXX-YYYY`:

### Step 1 — Assess

```bash
# Install govulncheck locally
go install golang.org/x/vuln/cmd/govulncheck@latest

# Get the full report
govulncheck ./... 2>&1 | grep -A 20 "GO-XXXX-YYYY"
```

Check whether the vulnerability is:
- **In a direct import** you call — must fix or replace the dep
- **In a transitive dep, call path reachable** — upgrade the dep or add a finding filter
- **Informational / no call path** — govulncheck will not flag it as a finding

### Step 2 — Fix options (in order of preference)

1. **Upgrade the dep**: `go get github.com/affected/pkg@latest && go mod tidy`
2. **Replace the dep** with an equivalent that isn't affected
3. **Accept it** (only if no upstream fix exists and the call path is unexploitable):
   - Add it to the allowlist in `.github/workflows/ci.yml`:
     ```bash
     grep -vF "GO-2024-3218" → grep -vF "GO-2024-3218" | grep -vF "GO-XXXX-YYYY"
     ```
   - Document the acceptance in `docs/architecture/threat-model.md` under "Accepted Risks"

### Step 3 — Verify

```bash
go test -short ./... && govulncheck ./...
```

---

## 3. CI Failure Triage Map

| Job | Step failing | First action |
| :--- | :--- | :--- |
| `quality` | Go Vet | Run `go vet ./...` locally, fix reported issues |
| `quality` | gofmt | Run `gofmt -w .` locally, commit the formatting |
| `quality` | Staticcheck | Run `staticcheck ./...`, address each warning |
| `quality` | Check Vulnerabilities | See Section 2 above |
| `docs` | Verify Man Page Sync | Run `go run ./cmd/maknoon man --verify` locally |
| `docs` | Verify Doc Links | Check that all `docs/*.md` links resolve to existing files |
| `test` | Run Tests | Run `go test -race -short ./...` locally with `-v` to isolate |
| `test` | Fuzz | Re-run the specific fuzz target with `-fuzz=... -fuzztime=60s` |
| `test` | Go Mission Tests | Run `make mission-tests` — check output per test name |
| `test` | Smoke Tests | Run the failing `scripts/smoke-*.sh` script directly |
| `test` | Build-Tag Matrix | Run `GOOS=linux go build -tags minimal ./...` locally |
| `docker` | Build and Push | Check Dockerfile for syntax errors; verify base image availability |
| `release` | GoReleaser | Ensure tags are present: `git tag -l | tail -5` |
| `missions` | Any mission | See Section 1 above |

---

## 4. GoReleaser Manual Release

If automatic tagging fails:

```bash
# Tag manually
git tag -a v1.X.Y -m "release v1.X.Y"
git push origin v1.X.Y

# Trigger release workflow manually
gh workflow run ci.yml --ref v1.X.Y
```

---

## 5. Escalation

For issues not covered here, open a GitHub issue with:
- The failing CI run URL
- Output of `go env`
- Output of `govulncheck ./...` if security-related
- The `mission-reports/` artifact if a Docker mission failed
