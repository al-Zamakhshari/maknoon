#!/bin/bash

# Maknoon CI Common Helpers

# fail_trap captures logs and teardown on failure
fail_trap() {
    local exit_code=$?
    local mission_name=$1
    local compose_file=$2
    local project_name=${3:-""}

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
            docker compose $p_flag -f "$compose_file" down --remove-orphans
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
        chmod 644 "$dir/server.key" "$dir/server.crt"
    fi
}

# setup_mission_logs prepares a shared directory for container logs
setup_mission_logs() {
    local dir="mission_logs"
    mkdir -p "$dir"
    chmod 777 "$dir"
    rm -f "$dir"/*.log
    echo "📂 Mission logs directory prepared: $PWD/$dir"
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

# wait_for_condition polls COMMAND every second (gentle backoff) until it exits 0.
# Usage: wait_for_condition "description" MAX_WAIT_SECONDS COMMAND [ARGS...]
wait_for_condition() {
    local description="$1"
    local max_wait="$2"
    shift 2
    local count=0 delay=1
    echo "⏳ Waiting for: $description (max ${max_wait}s)..."
    while ! "$@" >/dev/null 2>&1; do
        if [ "$count" -ge "$max_wait" ]; then
            echo "❌ TIMEOUT: $description not ready after ${max_wait}s"
            return 1
        fi
        sleep "$delay"
        count=$((count + delay))
        [ "$delay" -lt 4 ] && delay=$((delay + 1))
    done
    echo "✅ Ready: $description"
}

# assert_json_field validates a specific jq field in JSON output.
# Usage: assert_json_field "$JSON_OUTPUT" ".field.path" "expected_value"
assert_json_field() {
    local output="$1"
    local field="$2"
    local expected="$3"
    local actual
    actual=$(printf '%s' "$output" | jq -r "$field" 2>/dev/null)
    if [ -z "$actual" ] || [ "$actual" = "null" ]; then
        echo "❌ ASSERT FAILED: field '$field' is null or missing"
        echo "   Raw output: $output"
        return 1
    fi
    if [ "$actual" != "$expected" ]; then
        echo "❌ ASSERT FAILED: expected '$expected', got '$actual' (field: $field)"
        return 1
    fi
    echo "✅ Assert OK: $field = $actual"
}

# checked_exec runs docker exec and fails immediately if the command exits non-zero.
# Usage: checked_exec CONTAINER COMMAND [ARGS...]
checked_exec() {
    local container="$1"
    shift
    local out
    out=$(docker exec "$container" "$@" 2>&1)
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo "❌ checked_exec FAILED (exit $rc): docker exec $container $*"
        echo "   Output: $out"
        return $rc
    fi
    printf '%s' "$out"
}

# checked_compose_exec runs docker compose exec and fails immediately on non-zero exit.
# Usage: checked_compose_exec COMPOSE_FILE SERVICE COMMAND [ARGS...]
checked_compose_exec() {
    local compose_file="$1"
    local service="$2"
    shift 2
    local out
    out=$(docker compose -f "$compose_file" exec -T "$service" "$@" 2>&1)
    local rc=$?
    if [ $rc -ne 0 ]; then
        echo "❌ checked_compose_exec FAILED (exit $rc): $service $*"
        echo "   Output: $out"
        return $rc
    fi
    printf '%s' "$out"
}

# print_result emits a structured JSON line to MISSION_REPORT_FILE (if set) and stdout.
# Usage: print_result PASS|FAIL "Human-readable message"
print_result() {
    local status="$1"
    local message="$2"
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    local line
    line=$(printf '{"ts":"%s","status":"%s","message":"%s"}' "$ts" "$status" "$message")
    echo "$line"
    if [ -n "${MISSION_REPORT_FILE:-}" ]; then
        echo "$line" >> "$MISSION_REPORT_FILE"
    fi
}
