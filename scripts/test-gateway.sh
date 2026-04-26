#!/bin/bash
set -e

# Maknoon L4 Gateway - High-Fidelity Forensic Smoke Test Suite
# This script executes a multi-transport forensic audit:
# 1. Byte-perfect data integrity (SHA256)
# 2. Cryptographic PQC enforcement (ML-KEM)
# 3. Network isolation (Source-IP attribution)

export MAKNOON_PASSPHRASE=smoke-test-secret
export TARGET_IP="172.20.0.5"
export QUIC_GW_IP="172.20.0.10"
export YAMUX_GW_IP="172.20.0.11"

setup_env() {
    echo "🏗️  Starting PQC DMZ Environment..."
    docker compose -f docker-compose.test.yml up -d --build
    sleep 5
}

cleanup() {
    echo "🧹 Cleaning up..."
    kill -9 $TUNNEL_PID 2>/dev/null || true
    docker compose -f docker-compose.test.yml down
    rm -f *.tmp *.hash *.sha256
}

create_asset() {
    echo "🟢 Creating 20MB forensic asset..."
    docker compose -f docker-compose.test.yml exec -T target sh -c "dd if=/dev/urandom of=/usr/share/nginx/html/smoke.bin bs=1M count=20 && sha256sum /usr/share/nginx/html/smoke.bin" | awk '{print $1}' | tr -d '\r\n' > target.hash
    TARGET_HASH=$(cat target.hash)
}

run_transfer() {
    local port=$1
    local mode=$2
    echo "🔵 Executing $mode Transfer (20MB)..."
    curl -s --proxy socks5h://127.0.0.1:$port http://$TARGET_IP/smoke.bin -o local_smoke.tmp
}

verify_integrity() {
    sha256sum local_smoke.tmp | awk '{print $1}' | tr -d '\r\n' > local.hash
    if diff -q target.hash local.hash > /dev/null; then
        echo "✅ INTEGRITY: Byte-perfect transfer confirmed."
    else
        echo "❌ INTEGRITY: SHA256 mismatch detected!"
        exit 1
    fi
}

verify_isolation() {
    local gw_ip=$1
    if docker compose -f docker-compose.test.yml logs target | grep "GET /smoke.bin" | grep -q "$gw_ip"; then
        echo "✅ ISOLATION: Host identity hidden. Gateway attribution confirmed ($gw_ip)."
    else
        echo "❌ ISOLATION: Source-IP attribution failed! Expected $gw_ip."
        exit 1
    fi
}

test_direct() {
    echo -e "\n🛡️  Running Test Case: Direct PQC Tunnel (QUIC)..."
    
    ./maknoon tunnel start --remote 127.0.0.1:4433 --port 1080 > tunnel_direct.log 2>&1 &
    TUNNEL_PID=$!

    # Wait for local SOCKS5 gateway
    for i in {1..20}; do nc -z 127.0.0.1 1080 && break; sleep 1; done

    run_transfer 1080 "Direct"
    verify_integrity
    
    # Cryptographic Enforcement Audit
    if docker compose -f docker-compose.test.yml logs gateway-quic | grep -q "curve_id=0x5832353531394d4c4b454d373638"; then
        echo "✅ CRYPTO: Strict PQC Handshake (ML-KEM-768) verified."
    else
        echo "❌ CRYPTO: PQC Enforcement log not found!"
        exit 1
    fi
    
    verify_isolation "$QUIC_GW_IP"
    kill -9 $TUNNEL_PID 2>/dev/null || true
    echo "✅ Direct PQC Tunnel test passed."
}

test_yamux() {
    echo -e "\n🔀 Running Test Case: TCP+Yamux Tunnel..."
    
    ./maknoon tunnel start --remote 127.0.0.1:4434 --port 1081 --yamux > tunnel_yamux.log 2>&1 &
    TUNNEL_PID=$!

    # Wait for local SOCKS5 gateway
    for i in {1..20}; do nc -z 127.0.0.1 1081 && break; sleep 1; done

    run_transfer 1081 "Yamux"
    verify_integrity
    verify_isolation "$YAMUX_GW_IP"
    kill -9 $TUNNEL_PID 2>/dev/null || true
    echo "✅ TCP+Yamux Tunnel test passed."
}

# Main Execution
trap cleanup EXIT
setup_env
create_asset
test_direct
test_yamux

echo -e "\n🏆 ALL SMOKE TESTS PASSED: Maknoon L4 Suite is Mission-Ready."
