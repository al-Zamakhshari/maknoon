#!/bin/bash
set -e

# Mission: Crypto-Processing Pipeline (Phase 3)
# Verification of Scalable Transformer Architecture (Shared Volume Mode)

source "$(dirname "$0")/common.sh"
COMPOSE_FILE="deploy/docker/mission-pipeline.yml"

trap 'fail_trap "Crypto-Processing Pipeline" "$COMPOSE_FILE"' EXIT

echo "🏗️  Provisioning Crypto Pipeline (Shared Volume)..."

docker compose -f $COMPOSE_FILE up -d --build

# Wait for Ingestor data (with timeout)
echo "⏳ Waiting for Ingestor to generate dummy data..."
MAX_RETRIES=30
COUNT=0
while ! docker compose -f $COMPOSE_FILE exec ingestor ls /home/maknoon/data/large_data.bin >/dev/null 2>&1; do
    if [ $COUNT -ge $MAX_RETRIES ]; then
        echo "❌ TIMEOUT: Ingestor failed to generate data."
        docker compose -f $COMPOSE_FILE logs ingestor
        docker compose -f $COMPOSE_FILE down
        exit 1
    fi
    sleep 1
    COUNT=$((COUNT + 1))
done

# Step 1: Compressor Stage (Zstd)
echo "🚀 Stage 1: Compressor (Zstd)..."
# In a real pipeline, this would be 'maknoon protect --compress'
# For this demo, we simulate a transformation
docker compose -f $COMPOSE_FILE exec compressor sh -c \
    "cp /home/maknoon/data/large_data.bin /home/maknoon/data/large_data.bin.zst"

# Step 2: Encryptor Stage (ML-KEM)
echo "🚀 Stage 2: Encryptor (ML-KEM)..."
# Provision identity and encrypt
docker compose -f $COMPOSE_FILE exec encryptor maknoon keygen --no-password -o encryptor-id
docker compose -f $COMPOSE_FILE exec encryptor maknoon encrypt /home/maknoon/data/large_data.bin.zst \
    -o /home/maknoon/data/large_data.bin.makn -s pipe-pass

# Step 3: Sink Stage (Verification)
echo "🚀 Stage 3: Sink (Archival Verification)..."
docker compose -f $COMPOSE_FILE exec sink ls -l /home/maknoon/data/large_data.bin.makn

# Final Integrity Check: Decrypt and Compare
echo "🧪 Verifying Pipeline Integrity..."
docker compose -f $COMPOSE_FILE exec sink maknoon decrypt /home/maknoon/data/large_data.bin.makn \
    -o /home/maknoon/data/recovered.bin -s pipe-pass --overwrite

ORIG_HASH=$(docker compose -f $COMPOSE_FILE exec ingestor sha256sum /home/maknoon/data/large_data.bin | awk '{print $1}')
RECOV_HASH=$(docker compose -f $COMPOSE_FILE exec sink sha256sum /home/maknoon/data/recovered.bin | awk '{print $1}')

if [ "$ORIG_HASH" == "$RECOV_HASH" ]; then
    echo "✅ SUCCESS: Crypto-Processing Pipeline verified! Data transformed across 4 nodes via shared PQC storage."
else
    echo "❌ FAILED: Pipeline integrity compromised."
    echo "Original: $ORIG_HASH"
    echo "Recovered: $RECOV_HASH"
    exit 1
fi

echo "🧹 Tearing down Pipeline..."
docker compose -f $COMPOSE_FILE down
