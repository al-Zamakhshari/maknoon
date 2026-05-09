#!/bin/bash
# Maknoon Mission Verification: MCP SSE Transport Resilience

set -e

# Cleanup on exit
cleanup() {
    echo "🧹 Cleaning up..."
    kill $SERVER_PID 2>/dev/null || true
    chmod -R +w "$TEST_DIR" 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

echo "🧪 Starting Mission: MCP SSE Transport Verification..."

# Kill any existing maknoon processes
killall maknoon 2>/dev/null || true

# Setup clean environment
TEST_DIR=$(mktemp -d)
export HOME=$TEST_DIR
mkdir -p $HOME/.maknoon/keys

# Ensure binary is built
make build > /dev/null 2>&1

# 1. Generate Certificates for SSE (PQ-TLS 1.3)
echo "🔐 Generating Certificates..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" -sha256 -days 1 -nodes -subj "/CN=localhost" > /dev/null 2>&1

# 2. Start MCP SSE Server
echo "🚀 Starting MCP SSE Server on 127.0.0.1:8085..."
./maknoon mcp --transport sse --address "127.0.0.1:8085" --tls-cert "$TEST_DIR/cert.pem" --tls-key "$TEST_DIR/key.pem" > "$TEST_DIR/sse.log" 2>&1 &
SERVER_PID=$!

echo "⏳ Waiting for server to bind..."
sleep 5

# 3. Verify tool execution via Maknoon 'call' command (SSE Client)
echo "🔍 Task: Verifying MCP Tool Execution via SSE transport..."
set +e
CALL_RESP=$(./maknoon call profiles_list --addr "127.0.0.1:8085" --insecure 2>&1)
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -eq 0 ] && echo "$CALL_RESP" | grep -q "nist"; then
    echo "✅ Success: MCP Tool executed successfully via SSE transport."
else
    echo "❌ Failure: MCP 'call' command failed."
    echo "Exit Code: $EXIT_CODE"
    echo "Response: $CALL_RESP"
    echo "--- SSE Server Log ---"
    cat "$TEST_DIR/sse.log"
    exit 1
fi

echo "🏆 Mission Accomplished: MCP SSE Transport Verified."
exit 0
