# syntax=docker/dockerfile:1

############################
# Builder image
############################
FROM rust:1-bookworm AS builder

WORKDIR /app

# Pre-copy manifests to leverage Docker layer caching for dependencies
COPY ../Cargo.toml Cargo.lock ./
COPY ../src ./src

# Build the server binary in release mode
RUN cargo build --release --bin server

############################
# Runtime image
############################
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Copy the compiled server binary
COPY --from=builder /app/target/release/server /app/server

# The server listens on 8443
EXPOSE 8443

# Entrypoint runs the TLS server
ENTRYPOINT ["/app/server"]
