.PHONY: build test bench docker-build clean completion man build-matrix

# Build parameters
BINARY_NAME=maknoon
PKG=./cmd/maknoon
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-s -w \
  -X main.version=$(VERSION) \
  -X github.com/al-Zamakhshari/maknoon/pkg/crypto.Version=$(VERSION)

# Standard Production Build (Statically linked, Stripped symbols)
build:
	@echo "🛠️  Building production-grade binary..."
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) $(PKG)
	@ls -lh $(BINARY_NAME)

# Fast local test suite (Skips network/flaky tests)
test:
	@echo "🧪  Running optimized test suite..."
	go test -v -short ./...

# Full containerized sandbox build using BuildKit
docker-build:
	@echo "📦  Building secure scratch container..."
	docker buildx build -t maknoon-sandbox --load .

# Generate shell completions for the current session
completion:
	@echo "🐚  Generating bash completions..."
	./$(BINARY_NAME) completion bash > maknoon.completion
	@echo "Source 'maknoon.completion' to enable."

# Verify and update the manual page
man:
	@echo "📖  Verifying manual page integrity..."
	go run $(PKG) man --verify

# Launch local documentation server (Industrial API browsing)
serve-docs:
	@echo "📚  Launching professional API documentation server..."
	@echo "👉  Open: http://localhost:6060/github.com/al-Zamakhshari/maknoon"
	go install golang.org/x/pkgsite/cmd/pkgsite@latest
	$(shell go env GOPATH)/bin/pkgsite -http localhost:6060

# Generate dynamic call graph (Visual code audit)
map-calls:
	@echo "🎨  Generating interactive call graph (SVG)..."
	go install github.com/ofabry/go-callvis@latest
	$(shell go env GOPATH)/bin/go-callvis -format svg -file engine_map ./cmd/maknoon
	@echo "✅  Call graph generated: engine_map.svg"

# High-fidelity L4 Gateway smoke test (Docker required)
test-gateway: build
	@echo "🛡️  Executing High-Fidelity Forensic Smoke Test..."
	@chmod +x scripts/test-gateway.sh
	@./scripts/test-gateway.sh

# Run all industrial smoke tests
# Run crypto benchmarks — KDF, chunk pipeline, parallel encrypt/decrypt, data sizes
bench:
	go test -bench=. -benchmem -benchtime=10s ./pkg/crypto/

smoke: build
	@echo "🔥 Running Maknoon Industrial Smoke Suite..."
	@chmod +x scripts/smoke-audit.sh scripts/smoke-resilience.sh scripts/smoke-vault-safety.sh scripts/smoke-governance.sh scripts/mission-orchestrated-quorum.sh
	@./scripts/smoke-audit.sh
	@./scripts/smoke-resilience.sh
	@./scripts/smoke-vault-safety.sh
	@./scripts/smoke-governance.sh
	@./scripts/mission-orchestrated-quorum.sh
	@echo "✅ All smoke tests passed. Industrial Grade verified."

# Go mission tests — in-process, no Docker required, fast (< 30s)
mission-tests:
	go test -v -run 'TestMission' -timeout 120s ./cmd/maknoon/commands/ ./cmd/maknoon/

# Run all 9 Docker-based missions + print structured summary
missions: build
	@mkdir -p mission-reports
	@FAILED=""; \
	for s in \
	    scripts/mission-pipeline-verify.sh \
	    scripts/mission-quorum-verify.sh \
	    scripts/mission-deadmans-verify.sh \
	    scripts/mission-orchestrated-quorum.sh \
	    scripts/mission-blind-proxy-verify.sh \
	    scripts/mission-bridge-verify.sh \
	    scripts/mission-mesh-verify.sh \
	    scripts/mission-global-verify.sh \
	    scripts/mission-agility-verify.sh; do \
	    echo ""; echo "═══ $$(basename $$s) ═══"; \
	    MISSION_REPORT_FILE="mission-reports/$$(basename $$s .sh).jsonl" \
	        bash "$$s" || FAILED="$$FAILED $$s"; \
	done; \
	bash scripts/mission-summary.sh mission-reports; \
	[ -z "$$FAILED" ] || { echo "❌ Failed:$$FAILED"; exit 1; }

# Run all smoke scripts (25+), not just the 5 in 'smoke'
smoke-full: build
	@FAILED=""; \
	for s in scripts/smoke-*.sh; do \
	    echo "--- $$s ---"; \
	    bash "$$s" || FAILED="$$FAILED $$s"; \
	done; \
	[ -z "$$FAILED" ] || { echo "❌ Failed:$$FAILED"; exit 1; }
	@echo "✅ All smoke scripts passed."

# Build minimal binary without BEP-44 DHT (anacrolix deps excluded)
build-minimal:
	@echo "🛠️  Building minimal binary (no BEP-44 DHT)..."
	CGO_ENABLED=0 go build -tags minimal -ldflags="$(LDFLAGS)" -o maknoon-minimal $(PKG)
	@ls -lh maknoon-minimal

# Build-tag matrix: verify all conditional compilation paths compile cleanly.
# Platform tags (linux/!linux) gate the TPM backend.
# Feature tags (minimal) gate optional dependencies.
build-matrix:
	@echo "🔬 Verifying build-tag matrix..."
	@echo "  [1/4] linux (TPM backend enabled)..."
	@GOOS=linux CGO_ENABLED=0 go build ./... || (echo "❌ linux build failed"; exit 1)
	@echo "  [2/4] darwin (!linux stub)..."
	@GOOS=darwin CGO_ENABLED=0 go build ./... || (echo "❌ darwin build failed"; exit 1)
	@echo "  [3/4] windows (!linux stub)..."
	@GOOS=windows CGO_ENABLED=0 go build ./... || (echo "❌ windows build failed"; exit 1)
	@echo "  [4/4] linux minimal (no BEP-44 DHT)..."
	@GOOS=linux CGO_ENABLED=0 go build -tags minimal ./... || (echo "❌ minimal build failed"; exit 1)
	@echo "✅ All platform build paths verified."

# Cleanup build artifacts
clean:
	@echo "🧹  Cleaning up..."
	rm -f $(BINARY_NAME) maknoon_lean maknoon.completion
	go clean
