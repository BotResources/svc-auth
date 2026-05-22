#!/usr/bin/env bash
# Native cross-compile for linux/arm64 (aarch64-unknown-linux-gnu).
#
# Uses the host's `cargo` with an explicit arm64 C cross-compiler. We
# deliberately avoid `cross` here: `cross build` runs Docker-in-Docker
# against the DinD sidecar and the bind-mount fails on ARC runners
# (cross-rs/cross#260).
#
# `ring` (pulled by rustls → reqwest/jsonwebtoken/async-nats) compiles C
# during build, so the arm64 build needs `aarch64-linux-gnu-gcc` plus
# the matching libc headers (`libc6-dev-arm64-cross`). Both are
# pre-baked into the `br-arc-runner` image apt layer. If `ring` ever
# trips on `bits/libc-header-start.h`, the headers are missing — fix
# the runner image rather than re-apt-installing here.
#
# Prerequisites (CI: pre-baked into br-arc-runner; local Linux:
# `apt install gcc-aarch64-linux-gnu libc6-dev-arm64-cross`; macOS:
# install via brew/cross/docker as you prefer):
#   rustup target add aarch64-unknown-linux-gnu
#
# Usage:
#   source scripts/lib/build-cross-arm64.sh
#   build_cross_arm64

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

build_cross_arm64() {
    local target="aarch64-unknown-linux-gnu"
    cd "$REPO_ROOT"

    info "Native cross-compiling ${CRATE_NAME} for $target"
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        cargo build --release --locked --target "$target"

    local bin="target/$target/release/${CRATE_NAME}"
    if [ ! -f "$bin" ]; then
        error "${CRATE_NAME}: binary not found at $bin"
    fi
    info "[${CRATE_NAME}] Built $bin"
}
