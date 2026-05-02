#!/bin/bash

# Maknoon CI Common Helpers

# fail_trap captures logs and teardown on failure
fail_trap() {
    local exit_code=$?
    local mission_name=$1
    local compose_file=$2
    local project_name=$3

    if [ $exit_code -ne 0 ]; then
        echo ""
        echo "❌ ERROR: Mission '$mission_name' failed with exit code $exit_code"
        echo "🔍 Capturing container logs for diagnostic..."
        if [ ! -z "$compose_file" ]; then
            local p_flag=""
            if [ ! -z "$project_name" ]; then
                p_flag="-p $project_name"
            fi
            docker compose $p_flag -f "$compose_file" logs --tail 200
            echo "🧹 Tearing down failed mission infrastructure..."
            docker compose $p_flag -f "$compose_file" down
        fi
        exit $exit_code
    fi
}

# generate_test_certs creates a self-signed certificate for testing
generate_test_certs() {
    local dir=$1
    mkdir -p "$dir"
    if [ ! -f "$dir/server.crt" ]; then
        echo "🔐 Generating self-signed test certificates in $dir..."
        openssl req -x509 -newkey rsa:4096 -keyout "$dir/server.key" -out "$dir/server.crt" -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
    fi
}
# wait_for_port waits for a specific port to be open in a container
wait_for_port() {
    local container=$1
    local port=$2
    local timeout=${3:-15}
    
    echo "⏳ Waiting for port $port in $container..."
    for i in $(seq 1 $timeout); do
        if docker exec "$container" netstat -tln | grep ":$port " > /dev/null; then
            echo "✅ Port $port is active."
            return 0
        fi
        sleep 1
    done
    echo "❌ TIMEOUT: Port $port never became active in $container."
    return 1
}
