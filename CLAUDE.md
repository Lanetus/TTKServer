# TTKServer

Rust HTTP/3 (QUIC) server meant to run inside an AWS Nitro Enclave. It acts as a RATS (RFC 9334) **Attester**: it generates an ephemeral TLS key, gets an NSM Attestation Document whose `user_data` is bound to that key, embeds the evidence in a self-signed X.509 cert (custom extension), and serves the evidence over HTTP/3. Two enclave nodes are built on it: the **relay** (forwards onion-routed `POST /faf` requests) and the **terminal** (the last hop, decrypts the message). A companion `client` binary attests the nodes and sends a `/faf` message through a relay to a terminal. Appraisal against reference values (PCRs) happens outside this repo.

## Context & File Access Rules
- **Do NOT read or search inside:** `docs/`, `target/`, or `data/raw_datasets/`.
- Only inspect the crates' `src/` and `tests/` unless explicitly instructed otherwise.

## Layout (Cargo workspace, members in `crates/`; root `Cargo.toml` holds `[workspace.package]` version/metadata and `[workspace.dependencies]`)
- `crates/core/` — crate `ttk-core` (lib `ttk_core` + bin `vsock-proxy`): what server and client share, so `ttk-ra-client` does not depend on `ttk-ra-server`. Re-exported by `ttk-ra-server` at its old paths (`attestation::{eat, submod, MOCK_NITRO_ROOT_CERT}`, `server::{ATTESTATION_OID, PARENT_CID}`, `egress`, `vsock`).
  - `src/lib.rs` — `submod` labels, `ATTESTATION_OID`, `PARENT_CID` (3), `MOCK_NITRO_ROOT_CERT` (`mock_nitro_root.der`; its key stays in `ttk-ra-server`); re-exports `EatClaimsSet`, `EatClaimKey`, `ImageTrustStore`.
  - `src/eat.rs` — RFC 9711 `EatClaimsSet` / `EatClaimKey`.
  - `src/image_trust.rs` — trait `ImageTrustStore` (also at the crate root): `builtin()`, `nitro_image_allowlist()`, `nitro_pcr_index()` (default 0; 8 pins the EIF signing cert). Implemented by `ttk_root::FileImageTrustStore` (txt file) and `ttk_ra_client::RootImageTrustStore` (fetched from the root servers). Also `parse_image_allowlist` and the `/root-attestation` wire format (`RootAttestation`, `ROOT_ATTESTATION_PATH`). Re-exported by `ttk_ra_client::trust` (and the `ttk_ra_client` root).
  - `src/egress.rs` — `classify_hop_address` / `HopAddressClass` (Public / Private / Forbidden): egress policy for peer-chosen destinations (relay next hops, `vsock-proxy` outbound); re-exported by `ttk_ra_client::faf`.
  - `src/vsock.rs` (Linux) — quinn `AsyncUdpSocket`s over vsock, datagrams framed `[u16 BE len][payload]`: `VsockUdpSocket` (inbound) and `VsockOutboundSocket` (outbound via parent `3:5001`, `[4|6][ip][u16 port]` destination header); framing helpers reused by `vsock-proxy`.
  - `src/vsock_proxy.rs` — `vsock-proxy` config: `RELAY_USAGE`, defaults, `RelayConfig`, `parse_relay_args` (in the lib so `tests/` can reach it).
  - `src/bin/vsock-proxy.rs` — bin `vsock-proxy` (Linux, parent instance: public UDP `:443` to enclave vsock `5000`, and outbound vsock `5001` to UDP, egress policy via `egress`, `--allow-private`).
- `crates/ra-server/` — crate `ttk-ra-server` (lib `ttk_ra_server`), **server only**: no relay/message logic, no client.
  - `src/lib.rs` — declares `attestation`, `router`, `server`; re-exports `ttk_core::{egress, vsock}`; re-exports `eat`, `EatClaimsSet`, `EatClaimKey`, `generate_identity`, `AttestationParams`.
  - `src/identity.rs` — `generate_identity()` and the `AttestationParams` struct (plain pub fields, `Default`).
  - `src/attestation/` — providers (`nitro`, `sev_snp`, `tdx`, `mock`, `tsm`), `nitro_doc` (COSE parsing, mock docs, mock root key `mock_nitro_root_key.pk8`).
  - `src/server.rs` — attestation at startup, RA-TLS cert (`ATTESTATION_OID`, `create_cert_with_attestation`), QUIC/h3 accept loop; `Server::{bind, bind_vsock, listen, serve, serve_with(Router), private_key_der}`; `Listener::from_env()` (vsock `TTK_VSOCK_PORT` default `5000`, or `TTK_USE_UDP=1` UDP `TTK_LISTEN_ADDR` default `0.0.0.0:4433`); `PARENT_CID`, `MAX_REQUEST_BODY` (else 413), `REQUEST_BODY_TIMEOUT` (else 408), `MAX_REQUEST_HEADERS`, `MAX_CONNECTIONS`, `MAX_STREAMS_PER_CONNECTION`, `CONNECTION_RECEIVE_WINDOW`, `env_u32`.
  - `src/router.rs` — base routes only: `GET /`, `GET /evidence.eat` (base64 EAT, generated at startup), `POST /evidence` (body = raw nonce, 1..=`MAX_NONCE_LEN` 512 bytes; fresh base64 EAT with the nonce in the Nitro doc, via `server::Attester`; `MAX_CONCURRENT_ATTESTATIONS` else 503; TDX/SEV-SNP answer 500); `Evidence`.
- `crates/ra-client/` — crate `ttk-ra-client` (lib `ttk_ra_client` + bin `client`): everything client-side.
  - `src/client.rs` (re-exported at the crate root) — `TtkClient`, `ClientTransport` (UDP / vsock), `EnclaveCertVerifier` (accepts self-signed cert, records it), `extract_attestation_doc`, `hex_encode`, `MAX_RESPONSE_BODY` / `MAX_RESPONSE_HEADERS`.
  - `src/verifier/` — evidence appraisal (`nitro`, `sev_snp`, `dcap`), `Policy`; `verify_evidence`/`nitro::verify` take `&dyn ImageTrustStore`; re-exports `crate::trust::{TrustStore, ImageTrustStore}` (and `AmdRoots`/`AmdProduct` in `sev_snp`, `parse_image_allowlist` in `nitro`).
  - `src/trust/` — `TrustStore` (also at the crate root; vendor roots in `certs/`, mock root `ttk_ra_server::attestation::MOCK_NITRO_ROOT_CERT`), `RootSignerTrustStore` (PCR8 pinned for the root servers, `root_signer_pcr8.txt`, empty until filled = no genuine root accepted), re-exported `ttk_core::image_trust::{ImageTrustStore, parse_image_allowlist}`, `AmdRoots`/`AmdProduct`. Data only; verification lives in `verifier`.
  - `src/images.rs` — `RootImageTrustStore` (also at the crate root): `builtin()` blocks, fetching `GET /root-attestation` from `ROOT_SERVERS` (`a.ttk-server.net:443`, `b.ttk-server.net:443`, in order) with each root attested via `RootSignerTrustStore` (PCR8); fails closed (empty list). `fetch(roots, transport, verifier)` / `fetch_builtin(transport)` async; `set_root_transport` (relay sets vsock). `EnclaveCertVerifier` without `with_image_trust_store` uses a lazy process-wide fetch (only when non-debug Nitro evidence needs it; failures retried after `ROOT_FETCH_RETRY_INTERVAL`).
  - `src/faf.rs` — `FafRequest` JSON `{relays: [{address, encrypted}], body: {key, message}}`, `parse_relay_address` (`"<server> <10-digit salt>"`), `parse_relay_server`, `connect_to_node`, `FAF_PATH`.
  - `src/seal.rs` — onion encryption: RFC 9180 HPKE (DHKEM(P-256), HKDF-SHA256, AES-256-GCM) to a node's RA-TLS cert key (`NodePublicKey` / `NodeSecretKey`); `seal_address`/`open_address`, `seal_body`/`open_body` (`_with_key` variants return the `MessageKey`), `seal_response`/`open_response` (terminal reply under the message key).
  - `src/main.rs` — **test-only** bin `client` (never in enclave images): routes `/faf` through two relays to a terminal: connects to the entry relay (`--addr`), attests the second relay (`--relay`, default `127.0.0.1:4434`) and the terminal (`--terminal`, default `127.0.0.1:4444`), seals each hop address to the relay reading it and the body to the terminal. E2E tests in `tests/client_bin_tests.rs`.
- `crates/relay/` — crate `ttk-relay` (lib `ttk_relay`): `Relay` (wraps a `ttk-ra-server` `Server`, adds `POST /faf` forwarding with a verified connection pool; empty `relays` = 400), `run()` (env config, `TTK_PARENT_CID`/`TTK_OUTBOUND_VSOCK_PORT`, `TTK_ALLOW_MOCK_ATTESTATION=1` for mock next hops, `TTK_ALLOW_PRIVATE_NEXT_HOPS=1` / `allow_private_next_hops()` for loopback/private next hops — needed locally and in relay tests). Egress policy via `ttk_core::egress::classify_hop_address` (link-local/multicast/broadcast/unspecified always refused), `MAX_RELAYS` (8), `MAX_CONCURRENT_FORWARDS` (256, else 503), every forwarding failure = uniform `502 relay failed`. Bin: `relay` (`src/main.rs`, enclave).
- `crates/root/` — crate `ttk-root` (lib `ttk_root`): `Root` (wraps a `ttk-ra-server` `Server`, adds `GET /root-attestation`: JSON `RootAttestation` `{hash_algorithm: "SHA384", pcr0: [hex…]}`, the accepted enclave image checksums from `FileImageTrustStore` (`src/nitro_image_allowlist.txt`); `with_image_trust_store` overrides), `run()`. Bin `root` (enclave). Depends on `ttk-core` (not `ttk-ra-client`); `ttk-ra-client` dev-depends on it (`tests/images_tests.rs`); `tests/root_tests.rs` has its own minimal h3 client.
- `crates/terminal/` — crate `ttk-terminal` (lib `ttk_terminal`): `Terminal` (wraps a `ttk-ra-server` `Server`, adds `POST /faf` last hop: non-empty `relays` = 400, must decrypt `body` or 400; answers `hello:<message>` sealed under the body's message key via `seal::seal_response`, which relays pass back unchanged), `run()`. Bin `terminal` (enclave).

## Features (`ttk-ra-server`; `ttk-relay` / `ttk-terminal` forward them)
- `nitro` and `mock` are default; `sev-snp`, `tdx` optional; all additive. `mock` is the fallback when no TEE hardware is detected.
- `ttk-ra-client` depends on `ttk-core`, not `ttk-ra-server` (only its tests do, dev-dependency with `mock`, `sev-snp`, `tdx`). `ttk-core` has no features.
- `tokio-vsock` is only pulled in on Linux.
- `ttk-ra-client` dev-depends on `ttk-relay`/`ttk-terminal` (a dev-dependency cycle): in client tests, don't pass `ttk_ra_client` types into relay/terminal APIs (use `Relay::allow_mock()`, not `with_verifier`).

## Commands
```bash
cargo build --workspace
cargo test --workspace                        # nitro tests fall back to mock docs off-enclave
cargo test --workspace --all-features
TTK_USE_UDP=1 cargo run --bin relay           # relay node on UDP :4433 (TTK_LISTEN_ADDR overrides; RUST_LOG=info for logs)
TTK_USE_UDP=1 TTK_LISTEN_ADDR=127.0.0.1:4444 cargo run --bin terminal
TTK_USE_UDP=1 TTK_LISTEN_ADDR=127.0.0.1:4455 cargo run --bin root   # GET /root-attestation
cargo run --bin client -- <args>              # see parse_client_args() in crates/ra-client/src/main.rs
cargo run --bin vsock-proxy -- --cid <CID>    # parent-side UDP :443 -> enclave vsock relay (Linux)
cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check                              # config in deny.toml
mdbook build docs                             # book -> docs/book; needs `cargo install mdbook-mermaid` (```mermaid blocks)
scripts/build-eif.sh [amd64|arm64] [relay|terminal|root]   # EIF via Docker (Dockerfile ARG NODE) -> out/ttk-<node>_v<ver>_<arch>.eif + .json (PCRs)
deploy/systemd/vsock-proxy.service            # systemd unit for `vsock-proxy` on the parent (steps in its header)
deploy/ec2/user-data.sh                       # EC2 user data: installs nitro-cli, downloads EIF/vsock-proxy/units over HTTP, starts both
deploy/systemd/ttk-{relay,terminal}-enclave.service  # systemd units running the node EIF via nitro-cli (CID 16 / 17, 2 vCPU, 1024 MiB; /etc/default/ttk-<node>-enclave)
```

## Conventions
- Tests live in each crate's `tests/` (no inline `#[cfg(test)]` modules); items they need must be `pub`.
- Rust 2021; run `cargo fmt` and clippy before finishing. Keep `//!`/`///` doc comments on public items, in the existing RATS/RFC-referencing style.
- Logging via `log` + `env_logger` in library/server code; the server accept loop currently uses `eprintln!` for per-connection errors.
- Crypto: rustls 0.23 with the `ring` provider (installed explicitly when attesting / connecting); quinn 0.11 + h3 0.0.7 / h3-quinn 0.0.9 — versions are tightly coupled, upgrade together.
- The attestation OID `1.3.6.1.4.1.99999.1` (`ttk_core::ATTESTATION_OID`) is a placeholder (not a registered PEN).
- Releases use conventional commits (`feat:`, `fix:`, `chore(release):`) and version bumps of `[workspace.package]` in the root `Cargo.toml`.
- **STRICT commit message rule:** every commit message MUST start with one of these prefixes, no exceptions:
  - `fix:` — bug fixes
  - `feat:` — new features (minor version bump)
  - `major:` — breaking changes (major version bump)

  Never write an unprefixed commit message. (`chore(release):` is reserved for the automated release bump.)

## Gotchas
- `EnclaveCertVerifier` intentionally skips CA validation; trust comes from checking the attestation doc and that its `user_data` matches the cert/key hash. Don't reuse it outside RA-TLS flows.
- `Evidence.nitro` and `Evidence.eat` hold the same EAT-wrapped bytes; only `eat` is served (`/evidence.eat`).
- The RA-TLS cert and `/evidence.eat` carry evidence generated once at startup (no nonce); freshness only via `POST /evidence`.
