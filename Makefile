.PHONY: build test docker-build clean completion man build-matrix

# Build parameters
BINARY_NAME=maknoon
PKG=./cmd/maknoon
LDFLAGS=-s -w

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
smoke: build
	@echo "🔥 Running Maknoon Industrial Smoke Suite..."
	@chmod +x scripts/smoke-audit.sh scripts/smoke-resilience.sh scripts/smoke-vault-safety.sh scripts/smoke-governance.sh scripts/mission-orchestrated-quorum.sh
	@./scripts/smoke-audit.sh
	@./scripts/smoke-resilience.sh
	@./scripts/smoke-vault-safety.sh
	@./scripts/smoke-governance.sh
	@./scripts/mission-orchestrated-quorum.sh
	@echo "✅ All smoke tests passed. Industrial Grade verified."

# Build-tag matrix: verify all conditional compilation paths compile cleanly.
# Platform tags (linux/!linux) gate the TPM backend.
# Feature tags (nostr, fido2, minimal) gate optional dependencies when they land.
build-matrix:
	@echo "🔬 Verifying build-tag matrix..."
	@echo "  [1/3] linux (TPM backend enabled)..."
	@GOOS=linux CGO_ENABLED=0 go build ./... || (echo "❌ linux build failed"; exit 1)
	@echo "  [2/3] darwin (!linux stub)..."
	@GOOS=darwin CGO_ENABLED=0 go build ./... || (echo "❌ darwin build failed"; exit 1)
	@echo "  [3/3] windows (!linux stub)..."
	@GOOS=windows CGO_ENABLED=0 go build ./... || (echo "❌ windows build failed"; exit 1)
	@echo "✅ All platform build paths verified."

# Cleanup build artifacts
clean:
	@echo "🧹  Cleaning up..."
	rm -f $(BINARY_NAME) maknoon_lean maknoon.completion
	go clean
