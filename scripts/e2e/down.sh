#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

echo "==> Stopping svc-auth..."
if [ -f .e2e-svc-auth.pid ]; then
    kill "$(cat .e2e-svc-auth.pid)" 2>/dev/null || true
    rm -f .e2e-svc-auth.pid
fi

echo "==> Stopping NATS..."
docker compose -f docker-compose.e2e.yml down -v --remove-orphans

echo "==> Done."
