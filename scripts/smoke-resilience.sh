#!/bin/bash

# Maknoon Mission Verification: API Resilience

echo "🧪 Starting Mission: API Resilience Verification..."

# Setup clean environment
TEST_DIR=$(mktemp -d)
export HOME=$TEST_DIR
mkdir -p $HOME/.maknoon/keys
mkdir -p $HOME/.maknoon/vaults

# 1. Verify Global Rate Limiting
echo "🔍 Task 1: Verifying Global Rate Limiting..."

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" -sha256 -days 365 -nodes -subj "/CN=localhost" > /dev/null 2>&1

./maknoon serve --address "127.0.0.1:8082" --tls-cert "$TEST_DIR/cert.pem" --tls-key "$TEST_DIR/key.pem" > "$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 3

echo "🚀 Bombarding API server with requests..."
HIT_429=false
for i in {1..50}; do
    CODE=$(curl -k -s -o /dev/null -w "%{http_code}" https://127.0.0.1:8082/v1/health)
    if [ "$CODE" -eq 429 ]; then
        HIT_429=true
        break
    fi
done

if [ "$HIT_429" = true ]; then
    echo "✅ Success: Rate limiter engaged (429 detected)."
else
    echo "❌ Failure: Rate limiter did not engage."
    exit 1
fi

# 2. Verify Dynamic Certificate Reloading
echo "🔍 Task 2: Verifying Dynamic Certificate Reloading..."

OLD_SERIAL=$(openssl x509 -in "$TEST_DIR/cert.pem" -serial -noout)
sleep 1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout "$TEST_DIR/key.pem" -out "$TEST_DIR/cert.pem" -sha256 -days 365 -nodes -subj "/CN=new-localhost" > /dev/null 2>&1
NEW_SERIAL=$(openssl x509 -in "$TEST_DIR/cert.pem" -serial -noout)

echo "📡 Sending SIGHUP to Maknoon (PID: $SERVER_PID)..."
kill -HUP $SERVER_PID
sleep 2

if grep -q "reloaded successfully" "$TEST_DIR/server.log"; then
    echo "✅ Success: SIGHUP triggered certificate reload."
else
    echo "❌ Failure: SIGHUP did not trigger reload."
    cat "$TEST_DIR/server.log"
    exit 1
fi

S_CODE=$(openssl s_client -connect 127.0.0.1:8082 -servername localhost </dev/null 2>/dev/null | openssl x509 -serial -noout)

if [ "$S_CODE" == "$NEW_SERIAL" ]; then
    echo "✅ Success: API server is serving the NEW certificate."
else
    echo "❌ Failure: API server is still serving the OLD certificate."
    echo "Expected: $NEW_SERIAL"
    echo "Got:      $S_CODE"
    exit 1
fi

echo "🏆 Mission Accomplished: API Resilience Verified."
kill $SERVER_PID 2>/dev/null
rm -rf "$TEST_DIR"
exit 0