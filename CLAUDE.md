# TTKServer

Rust HTTP/3 (QUIC) server meant to run inside an AWS Nitro Enclave. It acts as a RATS (RFC 9334) **Attester**: it generates an ephemeral TLS key, gets an NSM Attestation Document whose `user_data` is bound to that key, embeds the evidence in a self-signed X.509 cert (custom extension), and serves the evidence over HTTP/3. A companion `client` binary connects, captures the server cert fingerprint, and extracts/parses the attestation doc. Appraisal against reference values (PCRs) happens outside this repo.

## Context & File Access Rules
- **Do NOT read or search inside:** `docs/`, `target/`, or `data/raw_datasets/`.
- Only inspect `src/` and `tests/` unless explicitly instructed otherwise.

## Layout
- `src/lib.rs` — crate root of `ttk_server`: only declares `attestation`, `service`, `verifier` and re-exports (`client`, `server`, `eat`, `EatClaimsSet`, `EatClaimKey`, `generate_identity`, `AttestationParams`) at the top level.
- `src/service/mod.rs` — declares `client`/`server`; holds the `AttestationParams` builder (user_data / nonce / public_key) and `generate_identity()`.
- `src/main.rs` — bin `TTKServer`: thin entry point calling `ttk_server::server::run()`.
- `src/service/server.rs` — attestation at startup, RA-TLS cert, QUIC/h3 accept loop on vsock port `TTK_VSOCK_PORT` (default `5000`, Linux only), or with `TTK_USE_UDP=1` on UDP `TTK_LISTEN_ADDR` (default `0.0.0.0:4433`); in vsock mode `/faf` relays go out via `ClientTransport::Vsock` to `TTK_PARENT_CID`:`TTK_OUTBOUND_VSOCK_PORT` (default `3:5001`); reads request bodies up to `MAX_REQUEST_BODY` (else 413). Relay policy: `Server::with_relay_verifier` (default strict; `run()` allows mock with `TTK_ALLOW_MOCK_ATTESTATION=1`).
- `src/service/vsock.rs` (Linux only) — quinn `AsyncUdpSocket`s over vsock, datagrams framed `[u16 BE len][payload]`: `VsockUdpSocket` (inbound, server; each parent connection is one peer) and `VsockOutboundSocket` (outbound, `/faf` relaying from the enclave; one connection per destination to parent `3:5001`, opened with a `[4|6][ip][u16 port]` destination header). Also the framing/header helpers the `relay` bin reuses.
- `src/service/router.rs` — all HTTP routes (`build_router`): `GET /`, `GET /evidence.eat` (base64 EAT), `POST /faf` (`FafRequest` JSON: forwards `message`+`key` to `relay_server`'s `/faf` over verified RA-TLS; no `relay_server` = last hop, 200). Also `Evidence` (re-exported from `server`), `parse_relay_server`, relay timeouts.
- `src/service/client.rs` — lib module `ttk_server::client`: `TtkClient`, `EnclaveCertVerifier` (accepts self-signed cert, records it), `extract_attestation_doc`, `hex_encode`.
- `src/bin/client.rs` — **test-only** bin `client` (`test-client` feature, never in production): `main` plus CLI parsing (`parse_client_args`, `ClientTarget`, `CLIENT_USAGE`, private to the bin) over `ttk_server::client`. Its e2e tests live in `tests/client_bin_tests.rs`.
- `src/bin/relay.rs` — bin `relay` (Linux only): bidirectional parent-instance daemon. Inbound: public UDP (default `0.0.0.0:443`) to the enclave over vsock (`--cid`, port `5000`), one vsock connection per client. Outbound: accepts vsock port `5001` (`--outbound-port`, `0` disables) from the enclave CID only and sends each connection's datagrams to the UDP destination in its header.
- `benches/client.rs` — Criterion benches for `ttk_server::client` (hex encoding, attestation extraction, handshake + GET against an in-process mock server; needs `mock`).
- `src/attestation/eat.rs` (`ttk_server::attestation::eat`, also re-exported as `ttk_server::eat`) — RFC 9711 EAT claim keys (`EatClaimKey`) and `EatClaimsSet` (CBOR).
- `src/nitro.rs` — real NSM session (`NsmSession`, `/dev/nsm`), COSE parsing, mock-doc fallback when no hardware, `wrap_as_eat`.
- `src/mock.rs` — `MockSession` for the `mock` feature.
- `tests/` — `nitro_tests.rs`, `client_tests.rs`, `integration_test.rs` (note: the latter duplicates helper fns locally rather than importing from the lib).

## Features (mutually exclusive in practice)
- `nitro` (default): `AttestationProcess = nitro::NsmSession`.
- `mock`: `AttestationProcess = mock::MockSession`; use for local runs without an enclave: `--no-default-features --features mock`.
- Enabling both makes `AttestationProcess` ambiguous — pick one.
- `test-client`: builds the test-only `client` binary. Not in `default`; never enable for production/enclave builds.
- `tokio-vsock` is only pulled in on Linux.

## Commands
```bash
cargo build                                   # nitro (default)
cargo build --no-default-features --features mock
cargo test                                    # nitro tests fall back to mock docs off-enclave
cargo test --no-default-features --features mock
TTK_USE_UDP=1 cargo run                       # server on UDP :4433 (TTK_LISTEN_ADDR overrides; default is vsock :5000; RUST_LOG=info for logs)
cargo bench --bench client                    # client library benchmarks
cargo test --features test-client             # also builds + tests the test-only client binary
cargo run --features test-client --bin client -- <args>   # see parse_args() in src/bin/client.rs
cargo run --bin relay -- --cid <CID>         # parent-side UDP :443 -> enclave vsock relay (Linux)
cargo fmt && cargo clippy --all-targets -- -D warnings
cargo deny check                              # config in deny.toml
scripts/build-eif.sh [amd64|arm64]            # build the EIF locally with Docker -> out/TTKServer_v<ver>_<arch>.eif + .json (PCRs)
deploy/systemd/ttk-relay.service              # systemd unit for `relay` on the parent (install steps in its header)
deploy/ec2/user-data.sh                       # EC2 user data: installs nitro-cli, downloads EIF/relay/units over HTTP, starts both
deploy/systemd/ttkserver-enclave.service      # systemd unit running the EIF via nitro-cli (CID 16, 2 vCPU, 1024 MiB; /etc/default/ttkserver-enclave)
```

## Conventions
- Rust 2021; run `cargo fmt` and clippy before finishing. Keep `//!`/`///` doc comments on public items, in the existing RATS/RFC-referencing style.
- Logging via `log` + `env_logger` in library/server code; the server accept loop currently uses `eprintln!` for per-connection errors.
- Crypto: rustls 0.23 with the `ring` provider (installed explicitly in `main`); quinn 0.11 + h3 0.0.7 / h3-quinn 0.0.9 — versions are tightly coupled, upgrade together.
- The attestation OID `1.3.6.1.4.1.99999.1` in `main.rs` is a placeholder (not a registered PEN).
- Releases use conventional commits (`feat:`, `fix:`, `chore(release):`) and version bumps in `Cargo.toml`.
- **STRICT commit message rule:** every commit message MUST start with one of these prefixes, no exceptions:
  - `fix:` — bug fixes
  - `feat:` — new features (minor version bump)
  - `major:` — breaking changes (major version bump)

  Never write an unprefixed commit message. (`chore(release):` is reserved for the automated release bump.)

## Gotchas
- `EnclaveCertVerifier` intentionally skips CA validation; trust comes from checking the attestation doc and that its `user_data` matches the cert/key hash. Don't reuse it outside RA-TLS flows.
- `Evidence.nitro` and `Evidence.eat` hold the same EAT-wrapped bytes; only `eat` is served (`/evidence.eat`).
- Server has no nonce/freshness input: evidence is generated once at startup.
