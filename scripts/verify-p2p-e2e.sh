#!/bin/bash
set -e

# Maknoon L4 - P2P E2E Verification (libp2p specific)
# Guaranteed isolation using explicit HOME export

export MAKNOON_PASSPHRASE=p2p-test-secret
export MAKNOON_JSON=1
MAKNOON_BIN=$(pwd)/maknoon

# Fresh directories for this specific run
TEST_BASE="/tmp/maknoon_e2e_$(date +%s)"
HOME1="$TEST_BASE/node1"
HOME2="$TEST_BASE/node2"
mkdir -p "$HOME1" "$HOME2"

cleanup() {
    echo "🧹 Cleaning up..."
    killall maknoon 2>/dev/null || true
    rm -rf "$TEST_BASE"
    rm -f original.hash received.hash
}

trap cleanup EXIT

echo "🚀 Starting P2P E2E Test..."

echo "🔑 Generating Identity 1..."
bash -c "export HOME=$HOME1 && $MAKNOON_BIN keygen -o id1 --no-password > /dev/null 2>&1"
NODE1_ID=$(bash -c "export HOME=$HOME1 && $MAKNOON_BIN identity info id1 --json" | grep -oE "12D3KooW[a-zA-Z0-9]+")

echo "🔑 Generating Identity 2..."
bash -c "export HOME=$HOME2 && $MAKNOON_BIN keygen -o id2 --no-password > /dev/null 2>&1"
NODE2_ID=$(bash -c "export HOME=$HOME2 && $MAKNOON_BIN identity info id2 --json" | grep -oE "12D3KooW[a-zA-Z0-9]+")

echo "🆔 Node 1: $NODE1_ID"
echo "🆔 Node 2: $NODE2_ID"

if [ -z "$NODE1_ID" ] || [ -z "$NODE2_ID" ]; then
    echo "❌ Failed to retrieve PeerIDs"
    exit 1
fi

# 1. Test File Transfer
echo "📦 Testing File Transfer..."
dd if=/dev/urandom of="$TEST_BASE/test_p2p.bin" bs=1k count=10 > /dev/null 2>&1
sha256sum "$TEST_BASE/test_p2p.bin" | awk '{print $1}' > original.hash

# Receiver (Node 2)
bash -c "export HOME=$HOME2 && $MAKNOON_BIN receive --p2p --output $TEST_BASE/received.bin > $TEST_BASE/recv.log 2>&1" &
sleep 5

# Sender (Node 1)
bash -c "export HOME=$HOME1 && $MAKNOON_BIN send --p2p --to $NODE2_ID $TEST_BASE/test_p2p.bin > $TEST_BASE/send.log 2>&1"

sleep 15
if [ -f "$TEST_BASE/received.bin" ]; then
    sha256sum "$TEST_BASE/received.bin" | awk '{print $1}' > received.hash
    if diff -q original.hash received.hash > /dev/null; then
        echo "✅ P2P Transfer: SUCCESS"
    else
        echo "❌ P2P Transfer: FAILED (Hash mismatch)"
        exit 1
    fi
else
    echo "❌ P2P Transfer: FAILED (Output file not found)"
    echo "--- SEND LOG ---"
    cat "$TEST_BASE/send.log"
    echo "--- RECV LOG ---"
    cat "$TEST_BASE/recv.log"
    exit 1
fi

# 2. Test Chat
echo "💬 Testing Identity-bound Chat..."
bash -c "export HOME=$HOME1 && $MAKNOON_BIN chat > $TEST_BASE/chat_host.log 2>&1" &
sleep 5

bash -c "export HOME=$HOME2 && echo '{\"action\":\"send\",\"text\":\"P2P_FINAL_STABILITY_VERIFIED\"}' | $MAKNOON_BIN chat $NODE1_ID > $TEST_BASE/chat_join.log 2>&1" &
sleep 15

if grep -q "P2P_FINAL_STABILITY_VERIFIED" "$TEST_BASE/chat_host.log"; then
    echo "✅ P2P Chat: SUCCESS"
else
    echo "❌ P2P Chat: FAILED"
    cat "$TEST_BASE/chat_host.log"
    exit 1
fi

echo -e "\n🏆 P2P E2E SUITE PASSED."
