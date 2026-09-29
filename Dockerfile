# syntax=docker/dockerfile:1

############################
# Builder image
############################
FROM rust:1-bookworm AS builder

WORKDIR /app

# Pre-copy manifests to leverage Docker layer caching for dependencies
COPY ../Cargo.toml Cargo.lock ./
COPY ../src ./src

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

WORKDIR /app

# Copy the compiled server binary
COPY --from=builder /app/TTKServer /app/TTKServer

# The server listens for QUIC / HTTP/3 on UDP 4433
EXPOSE 4433/udp

# Entrypoint runs the TLS server
ENTRYPOINT ["/app/TTKServer"]
