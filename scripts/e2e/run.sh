#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v nats-server > /dev/null 2>&1; then
    echo "==> ERROR: nats-server not found on PATH."
    echo "    The e2e suite spawns its own nats-server (br_test_harness::FabricTestNats)."
    echo "    Install it: https://github.com/nats-io/nats-server/releases"
    exit 1
fi

echo "==> Running the self-hosted e2e suite (real nats-server + in-process OIDC IdPs + real svc-auth)"
cargo test --test e2e "$@"
