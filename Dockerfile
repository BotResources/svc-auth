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

# No `RUN` instructions: keeps the Dockerfile cross-arch buildable without
# QEMU emulation. ca-certificates is intentionally NOT installed — every
# outbound HTTPS call goes through rustls + webpki-roots (Mozilla CA store
# bundled into the binary at compile time): see reqwest's `rustls-tls`
# feature in Cargo.toml, and async-nats which also uses rustls. curl was
# only used by the docker-compose dev healthcheck; production k8s probes
# are native httpGet/tcpSocket.

ARG BIN_PATH=target/release/svc-auth

COPY ${BIN_PATH} /usr/local/bin/svc-auth

WORKDIR /app
EXPOSE 8002
ENTRYPOINT ["/usr/local/bin/svc-auth"]
