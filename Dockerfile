# Runtime-only image for svc-auth.
#
# The binary is compiled OUTSIDE Docker (by scripts/publish.sh or CI) and
# copied in. This image contains only the runtime dependencies — no Rust
# toolchain, no source code, no build artifacts.
#
# Build args:
#   BIN_PATH — path to the pre-compiled binary (default: target/release/svc-auth)
#
# Usage (direct):
#   cargo build --release
#   docker build -t br-svc-auth .
#
# Usage (multi-arch via scripts/publish.sh):
#   ./scripts/publish.sh

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ARG BIN_PATH=target/release/svc-auth

COPY ${BIN_PATH} /usr/local/bin/svc-auth

WORKDIR /app
EXPOSE 8002
ENTRYPOINT ["/usr/local/bin/svc-auth"]
