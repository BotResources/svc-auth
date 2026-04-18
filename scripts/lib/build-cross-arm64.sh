#!/usr/bin/env bash
# Cross-compile for linux/arm64 (aarch64-unknown-linux-gnu).
#
# Prerequisites:
#   cargo install cross --git https://github.com/cross-rs/cross --locked
#   Docker running
#
# Usage:
#   source scripts/lib/build-cross-arm64.sh
#   build_cross_arm64

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

build_cross_arm64() {
    local target="aarch64-unknown-linux-gnu"
    cd "$REPO_ROOT"

    info "Cross-compiling ${CRATE_NAME} for $target"
    cross build --release --target "$target"

    local bin="target/$target/release/${CRATE_NAME}"
    if [ ! -f "$bin" ]; then
        error "${CRATE_NAME}: binary not found at $bin"
    fi
    info "[${CRATE_NAME}] Built $bin"
}
