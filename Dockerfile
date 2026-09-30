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
    apt-get install -y --no-install-recommends socat iproute2 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled server binary
COPY --from=builder /app/TTKServer /app/TTKServer

# The server listens for QUIC / HTTP/3 on UDP 4433
EXPOSE 4433/udp

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 iproute2 && \
    rm -rf /var/lib/apt/lists/*

COPY relay.py /app/relay.py

ENTRYPOINT ["/bin/sh", "-c", "ip link set lo up; /app/TTKServer & sleep 1; exec python3 -u /app/relay.py"]

# Entrypoint runs the TLS server
#ENTRYPOINT ["/bin/sh", "-c", "ip link set lo up; /app/TTKServer & sleep 1; exec socat VSOCK-LISTEN:5000,fork,reuseaddr UDP:127.0.0.1:4433"]
