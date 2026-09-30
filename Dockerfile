# syntax=docker/dockerfile:1

############################
# Builder image
############################
FROM rust:1-bookworm AS builder

WORKDIR /app

# Pre-copy manifests to leverage Docker layer caching for dependencies
COPY ../Cargo.toml Cargo.lock ./
COPY ../src ./src
COPY ../benches ./benches
# Build the server binary in release mode, caching the cargo registry and
# incremental build artifacts across runs (per-platform, since buildx builds
# amd64/arm64 in separate BuildKit sessions)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    cp /app/target/release/TTKServer /app/TTKServer

############################
# Runtime image
############################
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled server binary
COPY --from=builder /app/TTKServer /app/TTKServer

# The server listens for QUIC / HTTP/3 directly on vsock port 5000 (length-framed datagrams from
# the parent-side relay). Set TTK_USE_UDP=1 to listen on UDP TTK_LISTEN_ADDR (0.0.0.0:4433) instead.
ENTRYPOINT ["/bin/sh", "-c", "ip link set lo up; exec /app/TTKServer"]
