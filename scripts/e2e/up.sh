#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> Building svc-auth (release)..."
cargo build --release --locked

echo "==> Starting NATS..."
docker compose -f docker-compose.e2e.yml up -d --wait

echo "==> Starting svc-auth..."
export NATS_URL="nats://localhost:4222"
export JWT_SECRET="e2e-test-secret-key-at-least-32-chars!"
export JWT_ISSUER="svc-auth"
export ENVIRONMENT="local"
export PORT="8002"
export SECURE_COOKIES="false"
export AUTH_CHECK_SILENT_REFRESH="false"
export RUST_LOG="info"

target/release/svc-auth &
SVC_AUTH_PID=$!
echo "$SVC_AUTH_PID" > "$REPO_ROOT/.e2e-svc-auth.pid"

echo "==> Waiting for /health..."
for _ in $(seq 1 30); do
    if curl -sf http://localhost:8002/health > /dev/null 2>&1; then
        echo "==> svc-auth is healthy (pid $SVC_AUTH_PID)."
        exit 0
    fi
    sleep 0.5
done

echo "==> ERROR: svc-auth did not become healthy within 15s"
kill "$SVC_AUTH_PID" 2>/dev/null || true
exit 1
