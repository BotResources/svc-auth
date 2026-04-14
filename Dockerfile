# --- Builder stage ---
FROM rust:1.94-bookworm AS builder

WORKDIR /build

COPY Cargo.toml Cargo.loc[k] ./
COPY src/ src/

RUN cargo build --release

# --- Runtime stage ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/svc-auth /usr/local/bin/svc-auth

# Change this port to match your project's PORT env var
EXPOSE 8002

ENTRYPOINT ["/usr/local/bin/svc-auth"]
