#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> Building svc-auth (release)..."
cargo build --release --locked

echo "==> Starting NATS + OIDC test IdPs..."
docker compose -f docker-compose.e2e.yml up -d --wait

echo "==> Waiting for the OIDC test IdPs (RSA pool generation)..."
for port in 9100 9101; do
    healthy=false
    for _ in $(seq 1 60); do
        if curl -sf "http://localhost:${port}/health" > /dev/null 2>&1; then
            healthy=true
            break
        fi
        sleep 0.5
    done
    if [ "$healthy" != "true" ]; then
        echo "==> ERROR: OIDC test IdP on :${port} did not become healthy within 30s"
        exit 1
    fi
done

echo "==> Starting svc-auth..."
export NATS_URL="nats://localhost:4222"
export JWT_SECRET="e2e-test-secret-key-at-least-32-chars!"
export JWT_ISSUER="svc-auth"
export ENVIRONMENT="local"
export PORT="8002"
export SECURE_COOKIES="false"
export AUTH_CHECK_SILENT_REFRESH="false"
export RUST_LOG="info"

# OIDC: two real providers backed by the pilotable test IdPs. Provider B
# uses a custom email claim (Entra-shaped) on purpose.
export OIDC_E2EA_DISCOVERY_URL="http://localhost:9100"
export OIDC_E2EA_CLIENT_ID="e2e-client"
export OIDC_E2EB_DISCOVERY_URL="http://localhost:9101"
export OIDC_E2EB_CLIENT_ID="e2e-client-b"
export OIDC_E2EB_EMAIL_CLAIM="preferred_username"

# Short cooldown so the e2e suite can prove cooldown semantics (suppressed
# re-fetch, then allowed again) without stalling. Production default is 60s.
# The e2e cooldown test waits 2.5x this value (it reads the same env var).
export JWKS_REFRESH_COOLDOWN_SECONDS="${JWKS_REFRESH_COOLDOWN_SECONDS:-1}"

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
