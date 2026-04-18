#!/usr/bin/env bash
# Unit tests. REST-only service — no schema export.
#
# Usage (sourced by publish.sh):
#   source scripts/lib/test.sh
#   run_crate_tests

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

run_crate_tests() {
    cd "$REPO_ROOT"

    info "[${CRATE_NAME}] Running unit tests"
    cargo test --lib
}
