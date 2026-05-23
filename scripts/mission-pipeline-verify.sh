#!/bin/bash
set -euo pipefail

# Mission: Crypto-Processing Pipeline (Phase 3)
# Verification of Scalable Transformer Architecture (Shared Volume Mode)

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-pipeline.yml"
MISSION_REPORT_FILE="${MISSION_REPORT_FILE:-./mission-reports/mission-pipeline-verify.jsonl}"
mkdir -p "$(dirname "$MISSION_REPORT_FILE")"

trap 'fail_trap "Crypto-Processing Pipeline" "$COMPOSE_FILE"' EXIT

echo "🏗️  Provisioning Crypto Pipeline (Shared Volume)..."

docker compose -f "$COMPOSE_FILE" up -d --build

# Wait for Ingestor data
wait_for_condition "ingestor data ready" 60 \
    docker compose -f "$COMPOSE_FILE" exec -T ingestor \
        ls /home/maknoon/data/large_data.bin

# Step 1: Compressor Stage (Zstd — built into maknoon via --compress flag)
# Previously this was a no-op `cp`; now it actually compresses+encrypts in one pass.
echo "🚀 Stage 1: Compressor+Encryptor (Zstd → ML-KEM)..."
checked_compose_exec "$COMPOSE_FILE" compressor \
    maknoon encrypt --compress /home/maknoon/data/large_data.bin \
    -o /home/maknoon/data/large_data.bin.makn -s pipe-pass

# Step 2: Encryptor Stage — verify the artifact and inspect its header
echo "🚀 Stage 2: Encryptor (Header Verification)..."
checked_compose_exec "$COMPOSE_FILE" encryptor \
    maknoon info /home/maknoon/data/large_data.bin.makn

# Step 3: Sink Stage (Archival Verification)
echo "🚀 Stage 3: Sink (Archival Verification)..."
checked_compose_exec "$COMPOSE_FILE" sink \
    ls -l /home/maknoon/data/large_data.bin.makn

# Final Integrity Check: Decrypt and Compare
echo "🧪 Verifying Pipeline Integrity..."
checked_compose_exec "$COMPOSE_FILE" sink \
    maknoon decrypt /home/maknoon/data/large_data.bin.makn \
    -o /home/maknoon/data/recovered.bin -s pipe-pass --overwrite

ORIG_HASH=$(docker compose -f "$COMPOSE_FILE" exec -T ingestor sha256sum /home/maknoon/data/large_data.bin | awk '{print $1}')
RECOV_HASH=$(docker compose -f "$COMPOSE_FILE" exec -T sink sha256sum /home/maknoon/data/recovered.bin | awk '{print $1}')

if [ "$ORIG_HASH" = "$RECOV_HASH" ]; then
    print_result PASS "Crypto-Processing Pipeline verified — data transformed across 4 nodes via shared PQC storage"
else
    print_result FAIL "Pipeline integrity compromised: orig=$ORIG_HASH recov=$RECOV_HASH"
    echo "❌ FAILED: Pipeline integrity compromised."
    echo "Original:  $ORIG_HASH"
    echo "Recovered: $RECOV_HASH"
    exit 1
fi

echo "🧹 Tearing down Pipeline..."
docker compose -f "$COMPOSE_FILE" down
