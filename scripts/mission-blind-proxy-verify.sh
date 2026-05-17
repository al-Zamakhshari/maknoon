#!/bin/bash
set -euo pipefail

# Mission 1: The "Blind" Cryptographic Proxy
# Verification of Double-Ciphertext hygiene and secure routing.

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-blind-proxy.yml"
MISSION_REPORT_FILE="${MISSION_REPORT_FILE:-./mission-reports/mission-blind-proxy-verify.jsonl}"
mkdir -p "$(dirname "$MISSION_REPORT_FILE")"

trap 'fail_trap "Blind Cryptographic Proxy" "$COMPOSE_FILE"' EXIT

echo "🏗️  Provisioning Blind Proxy Infrastructure..."
docker compose -f "$COMPOSE_FILE" up -d --build

# Wait for all node identities to be ready
for node in sink relay producer; do
    wait_for_condition "$node identity ready" 60 \
        docker compose -f "$COMPOSE_FILE" exec -T "$node" \
            test -f /home/maknoon/.maknoon/keys/${node}-id.kem.pub
done

# Step 1: Discover Public Keys
echo "🔑 Discovering Public Keys..."
SINK_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q sink)
RELAY_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q relay)
PRODUCER_CONTAINER=$(docker compose -f "$COMPOSE_FILE" ps -q producer)

docker cp "$SINK_CONTAINER":/home/maknoon/.maknoon/keys/sink-id.kem.pub sink.pub
docker cp "$RELAY_CONTAINER":/home/maknoon/.maknoon/keys/relay-id.kem.pub relay.pub

# Step 2: Producer generates and encrypts L1 for Sink
echo "🚀 Producer: Generating and Encrypting Layer 1 (for Sink)..."
docker cp sink.pub "$PRODUCER_CONTAINER":/home/maknoon/sink.pub
checked_exec "$PRODUCER_CONTAINER" sh -c "dd if=/dev/urandom of=data.bin bs=1M count=5"
ORIG_HASH=$(docker exec "$PRODUCER_CONTAINER" sha256sum data.bin | awk '{print $1}')

checked_exec "$PRODUCER_CONTAINER" \
    maknoon encrypt data.bin -o L1.makn --public-key sink.pub --trace

# Step 3: Producer sends L1 to Relay (encrypted for Relay)
echo "📡 Producer -> Relay: Transmitting L1..."
docker cp relay.pub "$PRODUCER_CONTAINER":/home/maknoon/relay.pub

NET_PRODUCER=$(docker network ls --filter name=net-producer --format "{{.Name}}")
RELAY_IP_PROD=$(docker inspect -f \
    "{{with index .NetworkSettings.Networks \"$NET_PRODUCER\"}}{{.IPAddress}}{{end}}" \
    "$RELAY_CONTAINER")

wait_for_condition "relay multiaddr in logs" 30 \
    docker compose -f "$COMPOSE_FILE" logs relay \| grep -q "/ip4/$RELAY_IP_PROD.*tcp"
RELAY_ADDR=$(docker compose -f "$COMPOSE_FILE" logs relay \
    | grep "/ip4/$RELAY_IP_PROD" | grep "/tcp/" | head -n 1 | awk '{print $NF}' | tr -d '\r')
echo "🆔 Relay Multiaddr: $RELAY_ADDR"

checked_exec "$PRODUCER_CONTAINER" \
    maknoon send L1.makn --to "$RELAY_ADDR" --public-key relay.pub --identity producer-id --trace

# Step 4: Relay receives L1, wraps in L2, sends to Sink
wait_for_condition "relay received L1" 30 \
    docker exec "$RELAY_CONTAINER" find /home/maknoon -name "L1.makn"
RELAY_L1_PATH=$(docker exec "$RELAY_CONTAINER" find /home/maknoon -name "L1.makn" | head -n 1)

echo "🔄 Relay: Wrapping in Layer 2 (Blind Encryption)..."
docker cp sink.pub "$RELAY_CONTAINER":/home/maknoon/sink.pub
checked_exec "$RELAY_CONTAINER" \
    maknoon encrypt "$RELAY_L1_PATH" -o L2.makn --public-key sink.pub --trace

echo "📡 Relay -> Sink: Transmitting L2..."
NET_SINK=$(docker network ls --filter name=net-sink --format "{{.Name}}")
SINK_IP_SINK=$(docker inspect -f \
    "{{with index .NetworkSettings.Networks \"$NET_SINK\"}}{{.IPAddress}}{{end}}" \
    "$SINK_CONTAINER")

wait_for_condition "sink multiaddr in logs" 30 \
    docker compose -f "$COMPOSE_FILE" logs sink \| grep -q "/ip4/$SINK_IP_SINK.*tcp"
SINK_ADDR=$(docker compose -f "$COMPOSE_FILE" logs sink \
    | grep "/ip4/$SINK_IP_SINK" | grep "/tcp/" | head -n 1 | awk '{print $NF}' | tr -d '\r')
echo "🆔 Sink Multiaddr: $SINK_ADDR"

checked_exec "$RELAY_CONTAINER" \
    maknoon send L2.makn --to "$SINK_ADDR" --public-key sink.pub --identity relay-id --trace

# Step 5: Sink receives and decrypts twice
wait_for_condition "sink received L2" 30 \
    docker exec "$SINK_CONTAINER" find /home/maknoon -name "L2.makn"
SINK_L2_PATH=$(docker exec "$SINK_CONTAINER" find /home/maknoon -name "L2.makn" | head -n 1)

echo "🔓 Sink: Decrypting Layer 2..."
checked_exec "$SINK_CONTAINER" \
    maknoon decrypt "$SINK_L2_PATH" -o L1_recovered.makn -k sink-id.kem.key --overwrite --trace

echo "🔓 Sink: Decrypting Layer 1..."
checked_exec "$SINK_CONTAINER" \
    maknoon decrypt L1_recovered.makn -o recovered.bin -k sink-id.kem.key --overwrite --trace

# Step 6: Verification
echo "🧪 Verifying E2E Integrity..."
RECOV_HASH=$(docker exec "$SINK_CONTAINER" sha256sum recovered.bin | awk '{print $1}')

if [ "$ORIG_HASH" = "$RECOV_HASH" ]; then
    print_result PASS "Blind Proxy verified — original data recovered through double-encryption"
else
    print_result FAIL "Data corruption: orig=$ORIG_HASH recov=$RECOV_HASH"
    exit 1
fi

echo "🛡️  Verifying Relay Zero-Knowledge State..."
if docker exec "$RELAY_CONTAINER" find /home/maknoon -name "recovered.bin" | grep -q "."; then
    print_result FAIL "Relay has access to raw data — zero-knowledge property violated"
    exit 1
fi
echo "✅ Relay Integrity: No unauthorized decryptions detected."

echo "🧹 Tearing down Blind Proxy..."
docker compose -f "$COMPOSE_FILE" down
rm -f sink.pub relay.pub
