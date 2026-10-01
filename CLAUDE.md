# TTKServer

Rust HTTP/3 (QUIC) server meant to run inside an AWS Nitro Enclave. It acts as a RATS (RFC 9334) **Attester**: it generates an ephemeral TLS key, gets an NSM Attestation Document whose `user_data` is bound to that key, embeds the evidence in a self-signed X.509 cert (custom extension), and serves the evidence over HTTP/3. Two enclave nodes are built on it: the **relay** (forwards onion-routed `POST /faf` requests) and the **terminal** (the last hop, decrypts the message). A companion `client` binary attests the nodes and sends a `/faf` message through a relay to a terminal. Appraisal against reference values (PCRs) happens outside this repo.

## Context & File Access Rules
- **Do NOT read or search inside:** `docs/`, `target/`, or `data/raw_datasets/`.
- Only inspect the crates' `src/`, `tests/` and `benches/` unless explicitly instructed otherwise.

## Layout (Cargo workspace, members in `crates/`; root `Cargo.toml` holds `[workspace.package]` version/metadata and `[workspace.dependencies]`)
- `crates/core/` — crate `ttk-core` (lib `ttk_core`), **library only, server only**: no relay/message logic, no client.
  - `src/lib.rs` — declares `attestation`, `router`, `server`, `vsock` (Linux); re-exports `eat`, `EatClaimsSet`, `EatClaimKey`, `generate_identity`, `AttestationParams`.
  - `src/identity.rs` — `generate_identity()` and the `AttestationParams` builder.
  - `src/attestation/` — providers (`nitro`, `sev_snp`, `tdx`, `mock`, `tsm`), `nitro_doc` (COSE parsing, mock docs), `eat.rs` (RFC 9711 `EatClaimsSet`), `submod` labels.
  - `src/server.rs` — attestation at startup, RA-TLS cert (`ATTESTATION_OID`, `create_cert_with_attestation`), QUIC/h3 accept loop; `Server::{bind, bind_vsock, listen, serve, serve_with(Router), private_key_der}`; `Listener::from_env()` (vsock `TTK_VSOCK_PORT` default `5000`, or `TTK_USE_UDP=1` UDP `TTK_LISTEN_ADDR` default `0.0.0.0:4433`); `PARENT_CID`, `MAX_REQUEST_BODY` (else 413), `env_u32`.
  - `src/router.rs` — base routes only: `GET /`, `GET /evidence.eat` (base64 EAT); `Evidence`.
  - `src/vsock.rs` (Linux) — quinn `AsyncUdpSocket`s over vsock, datagrams framed `[u16 BE len][payload]`: `VsockUdpSocket` (inbound) and `VsockOutboundSocket` (outbound via parent `3:5001`, `[4|6][ip][u16 port]` destination header); framing helpers reused by `vsock-proxy`.
- `crates/client/` — crate `ttk-client` (lib `ttk_client` + bin `client`): everything client-side.
  - `src/client.rs` (re-exported at the crate root) — `TtkClient`, `ClientTransport` (UDP / vsock), `EnclaveCertVerifier` (accepts self-signed cert, records it), `extract_attestation_doc`, `hex_encode`.
  - `src/verifier/` — evidence appraisal (`nitro`, `sev_snp`, `dcap`), `TrustStore`, `Policy`.
  - `src/faf.rs` — `FafRequest` JSON `{relays: [{address, encrypted}], body: {key, message}}`, `parse_relay_address` (`"<server> <10-digit salt>"`), `parse_relay_server`, `connect_to_node`, `FAF_PATH`.
  - `src/seal.rs` — onion encryption: RFC 9180 HPKE (DHKEM(P-256), HKDF-SHA256, AES-256-GCM) to a node's RA-TLS cert key (`NodePublicKey` / `NodeSecretKey`); `seal_address`/`open_address`, `seal_body`/`open_body`.
  - `src/main.rs` — **test-only** bin `client` (never in enclave images): attests the terminal (`--relay`), seals to it, sends `/faf` via the relay (`--addr`). E2E tests in `tests/client_bin_tests.rs`.
  - `benches/client.rs` — Criterion benches.
- `crates/relay/` — crate `ttk-relay` (lib `ttk_relay`): `Relay` (wraps a core `Server`, adds `POST /faf` forwarding with a verified connection pool; empty `relays` = 400), `run()` (env config, `TTK_PARENT_CID`/`TTK_OUTBOUND_VSOCK_PORT`, `TTK_ALLOW_MOCK_ATTESTATION=1` for mock next hops). Bins: `relay` (`src/main.rs`, enclave) and `vsock-proxy` (`src/bin/vsock-proxy.rs`, Linux, parent instance: public UDP `:443` to enclave vsock `5000`, and outbound vsock `5001` to UDP).
- `crates/terminal/` — crate `ttk-terminal` (lib `ttk_terminal`): `Terminal` (wraps a core `Server`, adds `POST /faf` last hop: non-empty `relays` = 400, must decrypt `body` or 400), `run()`. Bin `terminal` (enclave).

## Features (`ttk-core`; `ttk-relay` / `ttk-terminal` forward them)
- `nitro` and `mock` are default; `sev-snp`, `tdx` optional; all additive. `mock` is the fallback when no TEE hardware is detected.
- `ttk-client` depends on `ttk-core` with no features (it needs only EAT, the cert OID and vsock); its tests enable `mock`, `sev-snp`, `tdx` via dev-dependencies.
- `tokio-vsock` is only pulled in on Linux.
- `ttk-client` dev-depends on `ttk-relay`/`ttk-terminal` (a dev-dependency cycle): in client tests, don't pass `ttk_client` types into relay/terminal APIs (use `Relay::allow_mock()`, not `with_verifier`).

## Commands
```bash
cargo build --workspace
cargo test --workspace                        # nitro tests fall back to mock docs off-enclave
cargo test --workspace --all-features
TTK_USE_UDP=1 cargo run --bin relay           # relay node on UDP :4433 (TTK_LISTEN_ADDR overrides; RUST_LOG=info for logs)
TTK_USE_UDP=1 TTK_LISTEN_ADDR=127.0.0.1:4444 cargo run --bin terminal
cargo run --bin client -- <args>              # see parse_client_args() in crates/client/src/main.rs
cargo run --bin vsock-proxy -- --cid <CID>    # parent-side UDP :443 -> enclave vsock relay (Linux)
cargo bench -p ttk-client --bench client      # client library benchmarks
cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check                              # config in deny.toml
scripts/build-eif.sh [amd64|arm64] [relay|terminal]   # EIF via Docker (Dockerfile ARG NODE) -> out/ttk-<node>_v<ver>_<arch>.eif + .json (PCRs)
deploy/systemd/ttk-relay.service              # systemd unit for `vsock-proxy` on the parent (installed as ttk-relay; steps in its header)
deploy/ec2/user-data.sh                       # EC2 user data: installs nitro-cli, downloads EIF/vsock-proxy/units over HTTP, starts both
deploy/systemd/ttkserver-enclave.service      # systemd unit running the EIF via nitro-cli (CID 16, 2 vCPU, 1024 MiB; /etc/default/ttkserver-enclave)
```

## Conventions
- Rust 2021; run `cargo fmt` and clippy before finishing. Keep `//!`/`///` doc comments on public items, in the existing RATS/RFC-referencing style.
- Logging via `log` + `env_logger` in library/server code; the server accept loop currently uses `eprintln!` for per-connection errors.
- Crypto: rustls 0.23 with the `ring` provider (installed explicitly when attesting / connecting); quinn 0.11 + h3 0.0.7 / h3-quinn 0.0.9 — versions are tightly coupled, upgrade together.
- The attestation OID `1.3.6.1.4.1.99999.1` (`ttk_core::server::ATTESTATION_OID`) is a placeholder (not a registered PEN).
- Releases use conventional commits (`feat:`, `fix:`, `chore(release):`) and version bumps of `[workspace.package]` in the root `Cargo.toml`.
- **STRICT commit message rule:** every commit message MUST start with one of these prefixes, no exceptions:
  - `fix:` — bug fixes
  - `feat:` — new features (minor version bump)
  - `major:` — breaking changes (major version bump)

  Never write an unprefixed commit message. (`chore(release):` is reserved for the automated release bump.)

## Gotchas
- `EnclaveCertVerifier` intentionally skips CA validation; trust comes from checking the attestation doc and that its `user_data` matches the cert/key hash. Don't reuse it outside RA-TLS flows.
- `Evidence.nitro` and `Evidence.eat` hold the same EAT-wrapped bytes; only `eat` is served (`/evidence.eat`).
- Server has no nonce/freshness input: evidence is generated once at startup.
