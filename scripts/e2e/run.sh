#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

export SVC_AUTH_URL="${SVC_AUTH_URL:-http://localhost:8002}"

echo "==> Running e2e tests against ${SVC_AUTH_URL}"
cargo test --test e2e -- --ignored "$@"
