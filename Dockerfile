# syntax=docker/dockerfile:1

# Reproducible builds: PCR0 is the SHA-384 of the EIF, so the same commit must always produce
# the same image. Base images are pinned by digest (bump tag and digest together), Debian
# packages come from a fixed snapshot.debian.org date, and file timestamps are clamped to
# SOURCE_DATE_EPOCH (scripts/build-eif.sh passes the commit time and rewrites layer timestamps).

############################
# Builder image
############################
FROM rust:1.99.0-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6 AS builder

WORKDIR /app

# The enclave node to build: `relay` (forwards /faf requests), `s3-server` (the last hop, a
# terminal storing files in S3, feature `s3`), `root` (serves the accepted enclave image
# checksums at /root-attestation) or `echo` (a terminal replying with each decrypted message).
ARG NODE=relay

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# Build the node binary in release mode (Nitro only: no mock attestation fallback), caching the
# cargo registry and incremental build artifacts across runs (per-platform, since buildx builds
# amd64/arm64 in separate BuildKit sessions). SOURCE_DATE_EPOCH is exported to the build.
ARG SOURCE_DATE_EPOCH
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    case "$NODE" in \
        s3-server) features="nitro,s3" ;; \
        *) features="nitro" ;; \
    esac && \
    cargo build --release --locked -p ttk-executables --bin "$NODE" \
        --no-default-features --features "$features" && \
    cp "/app/target/release/$NODE" /app/node

############################
# Runtime image
############################
# Debian 12.15 (bookworm-slim), whose packages match the snapshot below.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime

# Packages are installed from a fixed snapshot of the Debian archive (still signature-checked),
# so the same versions are installed on every build. Bump it together with the image digest.
ARG DEBIAN_SNAPSHOT=20261005T000000Z
ARG SOURCE_DATE_EPOCH
# s3-server also needs the CA certificates its TLS connections to S3 are verified against.
ARG NODE=relay
RUN sed -i \
        -e "s|^URIs: http://deb.debian.org/debian-security|URIs: http://snapshot.debian.org/archive/debian-security/$DEBIAN_SNAPSHOT|" \
        -e "s|^URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/$DEBIAN_SNAPSHOT|" \
        /etc/apt/sources.list.d/debian.sources && \
    apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --no-install-recommends iproute2 \
        $([ "$NODE" = s3-server ] && echo ca-certificates) && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/cache/ldconfig/aux-cache \
        /var/log/apt /var/log/dpkg.log /var/log/alternatives.log

WORKDIR /app

# Copy the compiled node binary
COPY --from=builder /app/node /app/node

# An enclave gets no environment from `nitro-cli run-enclave`: the node only sees what is baked
# in here. Debug builds (scripts/build-eif.sh with TTK_DEBUG=1) log at info and accept mock and
# debug-mode next hops; never deploy those for production.
#
# s3-server: the bucket and its region are baked in too (so they are part of the measurements),
# and S3 is reached over vsock port TTK_S3_VSOCK_PORT through the parent's vsock-proxy-tcp.
# Credentials come from the parent's instance role, through the instance metadata service over
# vsock port TTK_IMDS_VSOCK_PORT (the parent's vsock-proxy-imds); empty = the standard AWS chain.
# Other nodes ignore these.
ARG RUST_LOG=error
ARG TTK_ALLOW_MOCK_ATTESTATION=0
ARG TTK_S3_BUCKET=
ARG AWS_REGION=
ARG TTK_S3_VSOCK_PORT=8001
ARG TTK_IMDS_VSOCK_PORT=8002
ENV RUST_LOG=$RUST_LOG \
    TTK_ALLOW_MOCK_ATTESTATION=$TTK_ALLOW_MOCK_ATTESTATION \
    TTK_S3_BUCKET=$TTK_S3_BUCKET \
    AWS_REGION=$AWS_REGION \
    TTK_S3_VSOCK_PORT=$TTK_S3_VSOCK_PORT \
    TTK_IMDS_VSOCK_PORT=$TTK_IMDS_VSOCK_PORT

# The node listens for QUIC / HTTP/3 directly on vsock port 5000 (length-framed datagrams from
# the parent-side vsock-proxy). Set TTK_USE_UDP=1 to listen on UDP TTK_LISTEN_ADDR (0.0.0.0:4433) instead.
ENTRYPOINT ["/bin/sh", "-c", "ip link set lo up; exec /app/node"]
