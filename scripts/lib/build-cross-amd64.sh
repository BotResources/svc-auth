#!/usr/bin/env bash
# Native cross-compile for linux/amd64 (x86_64-unknown-linux-gnu).
#
# Uses the host's `cargo` directly. We deliberately avoid `cross` here:
# `cross build` spins up a Docker container that bind-mounts the host's
# rustup toolchain, which silently fails in Docker-in-Docker setups
# (ARC self-hosted runners on Kubernetes). See cross-rs/cross#260.
#
# Prerequisites (CI: pre-baked into br-arc-runner; local: install via
# rustup + a working amd64 linker on non-Linux hosts):
#   rustup target add x86_64-unknown-linux-gnu
#
# Usage:
#   source scripts/lib/build-cross-amd64.sh
#   build_cross_amd64

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

build_cross_amd64() {
    local target="x86_64-unknown-linux-gnu"
    cd "$REPO_ROOT"

    info "Native cross-compiling ${CRATE_NAME} for $target"
    cargo build --release --locked --target "$target"

    local bin="target/$target/release/${CRATE_NAME}"
    if [ ! -f "$bin" ]; then
        error "${CRATE_NAME}: binary not found at $bin"
    fi
    info "[${CRATE_NAME}] Built $bin"
}
