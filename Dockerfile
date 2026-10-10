# syntax=docker/dockerfile:1

############################
# Builder image
############################
FROM rust:1-bookworm AS builder

WORKDIR /app

# The enclave node to build: `relay` (forwards /faf requests), `terminal` (the last hop),
# `s3-server` (a terminal storing files in S3, crate ttk-terminal with feature `s3`) or `root`
# (serves the accepted enclave image checksums at /root-attestation).
ARG NODE=relay

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Build the node binary in release mode, caching the cargo registry and
# incremental build artifacts across runs (per-platform, since buildx builds
# amd64/arm64 in separate BuildKit sessions)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    case "$NODE" in \
        s3-server) package=ttk-terminal features="--features s3" ;; \
        *) package="ttk-$NODE" features="" ;; \
    esac && \
    cargo build --release --locked -p "$package" --bin "$NODE" $features && \
    cp "/app/target/release/$NODE" /app/node

############################
# Runtime image
############################
FROM debian:bookworm-slim AS runtime

# s3-server also needs the CA certificates its TLS connections to S3 are verified against.
ARG NODE=relay
RUN apt-get update && \
    apt-get install -y --no-install-recommends iproute2 \
        $([ "$NODE" = s3-server ] && echo ca-certificates) && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled node binary
COPY --from=builder /app/node /app/node

# An enclave gets no environment from `nitro-cli run-enclave`: the node only sees what is baked
# in here. Debug builds (scripts/build-eif.sh with TTK_DEBUG=1) log at info and accept mock and
# debug-mode next hops; never deploy those for production.
#
# s3-server: the bucket and its region are baked in too (so they are part of the measurements),
# and S3 is reached over vsock port TTK_S3_VSOCK_PORT through the parent's vsock-proxy-tcp.
# Other nodes ignore these.
ARG RUST_LOG=error
ARG TTK_ALLOW_MOCK_ATTESTATION=0
ARG TTK_S3_BUCKET=
ARG AWS_REGION=
ARG TTK_S3_VSOCK_PORT=8001
ENV RUST_LOG=$RUST_LOG \
    TTK_ALLOW_MOCK_ATTESTATION=$TTK_ALLOW_MOCK_ATTESTATION \
    TTK_S3_BUCKET=$TTK_S3_BUCKET \
    AWS_REGION=$AWS_REGION \
    TTK_S3_VSOCK_PORT=$TTK_S3_VSOCK_PORT

# The node listens for QUIC / HTTP/3 directly on vsock port 5000 (length-framed datagrams from
# the parent-side vsock-proxy). Set TTK_USE_UDP=1 to listen on UDP TTK_LISTEN_ADDR (0.0.0.0:4433) instead.
ENTRYPOINT ["/bin/sh", "-c", "ip link set lo up; exec /app/node"]
