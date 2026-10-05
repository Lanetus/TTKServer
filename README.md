[![Documentation](https://docs.rs/ttk-core/badge.svg)](https://lanetus.github.io/TTKServer/api/ttk_core/index.html)
[![Crates.io](https://img.shields.io/crates/v/ttk-core.svg)](https://crates.io/crates/ttk-core)
[![codecov](https://codecov.io/gh/Lanetus/TTKServer/graph/badge.svg?token=G4380O9RMS)](https://codecov.io/gh/Lanetus/TTKServer)
[![CI](https://github.com/Lanetus/TTKServer/actions/workflows/CI.yml/badge.svg)](https://github.com/Lanetus/TTKServer/actions/workflows/CI.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/Lanetus/TTKServer/blob/main/LICENSE)


# TTKServer

An HTTP/3 (QUIC) **RA-TLS** server in Rust, meant to run inside a Trusted Execution Environment (TEE). It plays the RATS ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)) **Attester** role:

1. At startup it generates an ephemeral TLS key pair.
2. It asks the TEE hardware for attestation Evidence whose report data is bound to the SHA-256 of that key.
3. It wraps the Evidence as an [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711) Entity Attestation Token (EAT) and embeds it in a self-signed X.509 certificate (custom extension, OID `1.3.6.1.4.1.99999.1`, placeholder).
4. It serves HTTP/3 over QUIC with that certificate on `0.0.0.0:4433` (UDP), and also exposes the Evidence over HTTP.

A client can verify the TLS certificate's embedded Evidence during the handshake, so the connection itself is bound to the attested TEE.

The project is a Cargo workspace of four crates:

| Crate (directory)         | Kind        | Contents                                                                                 |
|---------------------------|-------------|------------------------------------------------------------------------------------------|
| `ttk-core` (`crates/core/`)      | library     | The attested server only: TEE attestation providers, EAT, RA-TLS identity and certificate, QUIC / HTTP/3 serving (`GET /`, `GET /evidence.eat`), vsock transport |
| `ttk-client` (`crates/client/`)  | lib + `client` bin | The RA-TLS client (`TtkClient`, `EnclaveCertVerifier`), the Evidence verifier for all supported TEEs, the `POST /faf` request format and its HPKE sealing; the test `client` binary |
| `ttk-relay` (`crates/relay/`)    | lib + `relay`, `vsock-proxy` bins | The **relay node** (enclave): forwards `POST /faf` to the next hop; and the parent-instance UDP <-> vsock proxy |
| `ttk-terminal` (`crates/terminal/`) | lib + `terminal` bin | The **terminal node** (enclave): the last hop of `POST /faf`, decrypting the message |

Supported TEEs:

| TEE          | Cargo feature | Evidence                                                              |
|--------------|---------------|-----------------------------------------------------------------------|
| AWS Nitro    | `nitro`       | NSM Attestation Document (COSE_Sign1) from `/dev/nsm`                 |
| AMD SEV-SNP  | `sev-snp`     | Attestation report + VCEK certificate, via Linux configfs-tsm         |
| Intel TDX    | `tdx`         | DCAP quote v4/v5, via Linux configfs-tsm                              |
| Mock         | `mock`        | A locally signed, **untrusted** Nitro-style document for development  |

The verifier also accepts Intel SGX DCAP quotes.

## Getting Started

### Prerequisites

*   [Rust](https://www.rust-lang.org/tools/install) (stable, edition 2021)

### Build

```sh
git clone https://github.com/Lanetus/TTKServer.git
cd TTKServer
cargo build --release              # all crates
cargo build --release -p ttk-relay # one crate
```

### Cargo features

| Feature       | Default | Purpose                                                                                  |
|---------------|:-------:|------------------------------------------------------------------------------------------|
| `nitro`       | ✓       | AWS Nitro Enclaves provider                                                              |
| `mock`        | ✓       | Mock provider; used as a fallback when no TEE hardware is detected                        |
| `sev-snp`     |         | AMD SEV-SNP provider                                                                     |
| `tdx`         |         | Intel TDX provider                                                                       |

These features belong to `ttk-core`; `ttk-relay` and `ttk-terminal` forward them. Features are additive, so one binary can support several TEEs, e.g. `cargo build --release -p ttk-terminal --features sev-snp,tdx`.

The test `client` binary lives in its own crate (`ttk-client`), so the enclave images, which build only `relay` or `terminal`, never include it.

## Usage

### Running the nodes

```sh
TTK_USE_UDP=1 TTK_LISTEN_ADDR=127.0.0.1:4433 cargo run --release --bin relay
TTK_USE_UDP=1 TTK_LISTEN_ADDR=127.0.0.1:4444 cargo run --release --bin terminal
```

Both listen on vsock port `TTK_VSOCK_PORT` (default `5000`, Linux only) unless `TTK_USE_UDP=1`, in which case they listen on UDP `TTK_LISTEN_ADDR` (default `0.0.0.0:4433`). From an enclave, the relay reaches next hops through the parent's `vsock-proxy` at vsock `TTK_PARENT_CID`:`TTK_OUTBOUND_VSOCK_PORT` (default `3:5001`).

At startup a node picks an attestation provider: it probes the compiled-in hardware backends (Nitro, then SEV-SNP, then TDX) and falls back to `mock` if none is found. The mock fallback only exists when the `mock` feature is enabled, and it logs a warning because its Evidence is **not trustworthy**.

Logging is via [`env_logger`](https://docs.rs/env_logger); set `RUST_LOG` to control verbosity (no output by default):

```sh
RUST_LOG=info cargo run --release --bin terminal
```

### Endpoints

| Route            | Response                                                             |
|------------------|----------------------------------------------------------------------|
| `GET /`          | Greeting text                                                        |
| `GET /evidence.eat` | Base64-encoded EAT carrying the Evidence                          |
| `POST /faf`      | Relay: forwards a sealed message to its next hop. Terminal: receives it (see below) |

### `POST /faf`: onion-routing a sealed message

The request body is JSON (`Content-Type: application/json`):

```json
{
  "relays": [
    { "address": "https://relay-1.example:443 0123456789", "encrypted": false },
    { "address": "<base64 HPKE ciphertext>", "encrypted": true }
  ],
  "body": { "key": "<base64 HPKE ciphertext>", "message": "<base64 AES-256-GCM ciphertext>" }
}
```

The route is made of relay nodes and ends at a terminal node. A relay node that receives a request:

1. removes the first entry from `relays` and reads the next hop from it. With `encrypted: true`, the address was sealed to **this node's** RA-TLS key, and only this node can open it;
2. connects to the next hop over QUIC / HTTP/3 and **verifies its RA-TLS attestation**;
3. posts the rest of the request (the remaining `relays` and the unchanged `body`) to the next hop's `POST /faf`, and answers `200 OK` once that hop has.

A relay node never acts as the last hop: it answers `400` to a request with no relays left. The terminal node is always the last hop: it accepts only an empty `relays` (`400` otherwise), is the only node that can decrypt `body`, and answers `200 OK` (`delivered`) if it can.

An opened address has the form `"<server> <salt>"`, e.g. `"https://server.com:443 0123456789"`. `<server>` is `host[:port]` or `https://host[:port]`, and the port defaults to `4433`. The salt is 10 random decimal digits. It is required in encrypted addresses and optional in plain ones.

Encryption uses the nodes' attested RA-TLS keys (ECDSA P-256), so a client seals only to nodes it has attested. It uses RFC 9180 HPKE in base mode with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM:

- `relays[i].address` (encrypted) is sealed to the node that reads it;
- `body.message` is encrypted with a fresh AES-256-GCM key (base64 of a 12-byte nonce followed by the ciphertext), and `body.key` is that key sealed to the last hop. `body.key` is required and never null.

HPKE values are base64 of the encapsulated key (65 bytes) followed by the ciphertext. Clients build requests with `ttk_client::faf` and `ttk_client::seal` (`NodePublicKey::from_certificate`, `seal_address`, `seal_body`). Other responses:

| Status | When                                                                         |
|--------|------------------------------------------------------------------------------|
| `400`  | Relay: no relays left, or the first relay entry can't be opened or parsed (e.g. an `http://` URL or a bad salt). Terminal: relays left, or `body` can't be decrypted |
| `413`  | The request body is over 1 MiB                                               |
| `415` / `422` | The body isn't JSON, or a field is missing or null                    |
| `502`  | The next hop can't be reached, fails attestation, or answers anything but `200` |
| `504`  | The next hop doesn't answer within 10 seconds                                |

By default next hops must present genuine TEE evidence. For local development with mock attestation, start the relay with `TTK_ALLOW_MOCK_ATTESTATION=1`.

### Environment variables

| Variable                     | Used by  | Meaning                                                                                   |
|------------------------------|----------|-------------------------------------------------------------------------------------------|
| `RUST_LOG`                   | all      | Log level (`info`, `debug`, …)                                                            |
| `TTK_USE_UDP` / `TTK_LISTEN_ADDR` | nodes | Listen on UDP (`1`) at this address (default `0.0.0.0:4433`) instead of vsock         |
| `TTK_VSOCK_PORT`             | nodes    | vsock port to listen on (default `5000`)                                                  |
| `TTK_PARENT_CID` / `TTK_OUTBOUND_VSOCK_PORT` | relay | The parent's `vsock-proxy` for outbound connections (default `3` / `5001`)   |
| `TTK_ATTESTATION`            | nodes    | Force a provider instead of probing: `aws-nitro`, `sev-snp`, `tdx` or `mock`             |
| `TTK_SEV_SNP_VCEK`           | nodes    | Path to a VCEK certificate (DER or PEM) when the SEV-SNP host doesn't supply one          |
| `TTK_SERVER_ADDR`            | client   | Default server address (default `127.0.0.1:4433`)                                         |
| `TTK_SERVER_NAME`            | client   | Default SNI server name (default `localhost`)                                             |
| `TTK_ALLOW_MOCK_ATTESTATION` | client, relay | Set to `1` to accept mock Evidence from the nodes (client) or from `/faf` next hops (relay). Development only |

### Test client

The `client` binary (crate `ttk-client`) is for testing only. It attests the terminal node and seals a message to it, connects to the relay node over HTTP/3 verifying its certificate's embedded Evidence, sends the message through the relay to the terminal with `POST /faf` and prints the response:

```sh
# Relay and terminal nodes as above (they fall back to mock attestation off-TEE), with
# TTK_ALLOW_MOCK_ATTESTATION=1 on the relay; then the client, accepting mock Evidence:
TTK_ALLOW_MOCK_ATTESTATION=1 cargo run --bin client -- --addr 127.0.0.1:4433 --relay 127.0.0.1:4444
```

Run `cargo run --bin client -- --help` for all options.

### Using the libraries

To embed the client in your own Relying Party, use `ttk_client`:

```rust
use ttk_client::{EnclaveCertVerifier, TtkClient};

let verifier = EnclaveCertVerifier::new()
    .with_expected_pcr(0, expected_pcr0); // reference values for your enclave image
let mut client = TtkClient::connect_with_verifier(addr, "localhost", verifier).await?;
let resp = client.get("/evidence.eat").await?;
```

To build another kind of attested node, use `ttk_core` and add routes to the base server:

```rust
use ttk_core::server::{Listener, Server};

let server = Server::listen(Listener::from_env()?)?;
server.serve_with(axum::Router::new().route("/ping", axum::routing::get(|| async { "pong" }))).await;
```

## Project layout

```
Cargo.toml              workspace manifest (shared package metadata and dependency versions)
crates/core/src/
  lib.rs                crate root of `ttk_core`
  attestation/          TEE providers (nitro, sev_snp, tdx, mock) and the EAT data model (eat.rs)
  identity.rs           generate_identity() / AttestationParams
  server.rs             attestation, RA-TLS certificate, QUIC / HTTP/3 serving, Listener
  router.rs             base routes (GET /, GET /evidence.eat)
  vsock.rs              QUIC datagram sockets over vsock (Linux)
crates/client/src/
  lib.rs, client.rs     `ttk_client`: TtkClient, EnclaveCertVerifier
  verifier/             Evidence verification for Nitro, SEV-SNP and TDX/SGX (DCAP)
  faf.rs, seal.rs       the POST /faf request format and its HPKE sealing
  main.rs               test `client` binary
crates/client/benches/  Criterion benchmarks for the client
crates/relay/src/
  lib.rs, main.rs       `ttk_relay` and the `relay` binary: forwards POST /faf
  bin/vsock-proxy.rs    parent-instance UDP <-> vsock proxy (Linux)
crates/terminal/src/
  lib.rs, main.rs       `ttk_terminal` and the `terminal` binary: last hop of POST /faf
crates/*/tests/         each crate's integration and end-to-end tests
```

## Development

```sh
cargo test --workspace                        # default features
cargo test --workspace --all-features         # everything
cargo bench -p ttk-client --bench client      # client benchmarks
cargo fmt --all && cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check                              # licences / advisories, config in deny.toml
```

Commit messages must start with `fix:` (patch), `feat:` (minor) or `major:` (major); the release workflow derives the version bump from this prefix.

## CI/CD

This project uses GitHub Actions:

*   **CI (`CI.yml`):** runs on every pull request. It runs the tests with coverage (`cargo llvm-cov nextest --all-features`, uploaded to Codecov), checks formatting, runs clippy on the workspace with `--all-features`, and runs `cargo audit` and `cargo deny`.
*   **CD (`main.yml`):** runs on pushes to `main`. It bumps the workspace version in `Cargo.toml` according to the commit prefix, commits it as `chore(release): version X.Y.Z` with a tag, and runs the tests with coverage. The manual Build workflow (`build.yml`) builds `linux/amd64` and `linux/arm64` Docker images and EIFs for both the relay and the terminal node, pushes the images to Amazon ECR, and publishes the crates.

## RATS Architecture (RFC 9334)

This server implements the **Attester** role from [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334) (Remote ATtestation procedureS Architecture). The table below uses AWS Nitro as the example; SEV-SNP and TDX map the same way with their own Evidence and vendor roots.

| RATS concept       | Concrete artifact in this server                                                               |
|---------------------|--------------------------------------------------------------------------------------------------|
| Attester            | This process, running inside the TEE (e.g. a Nitro Enclave)                                     |
| Evidence            | The NSM Attestation Document, with `user_data` bound to the SHA-256 of the server's ephemeral TLS key, carried in an EAT in the TLS certificate and served over `GET /evidence.eat` |
| Endorsements        | The AWS Nitro certificate chain embedded in the Attestation Document, rooted at the AWS Nitro Enclaves root CA |
| Reference Values    | Expected PCR measurements for this enclave image, held out-of-band by whoever verifies the Evidence |
| Verifier / Relying Party | A client (such as `ttk_server::client`) that checks the Evidence against Endorsements and Reference Values and, if it trusts the result, proceeds with the TLS session bound to that Evidence |

The server only produces and serves Evidence. Appraisal against Reference Values and issuance of an Attestation Result happen on the client side.

### EAT export (RFC 9711)

`GET /evidence.eat` serves the Evidence as a base64-encoded [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711) Entity Attestation Token claims-set (CBOR). The same bytes are embedded in the TLS certificate.

The TEE Evidence is already signed by a hardware-rooted key, and this server holds no other key a Relying Party would trust more. So rather than minting a new signature, the claims-set nests the original signed Evidence verbatim under the `submods` claim (key `266`), the nested-token form defined in RFC 9711. Trust comes from that nested Evidence, not from the outer claims-set, which is unsigned.

| TEE         | `submods` label | Nested Evidence                   | `eat_profile`                                       |
|-------------|-----------------|-----------------------------------|-----------------------------------------------------|
| AWS Nitro   | `aws_nitro`     | Raw NSM Attestation Document      | `tag:aws.amazon.com,2024:nitro-enclave-nested-eat`  |
| AMD SEV-SNP | `sev_snp`       | `{ "report": bstr, "vcek": bstr }` | `tag:lanetus.github.io,2026:sev-snp-nested-eat`     |
| Intel TDX   | `tdx`           | Raw DCAP quote                    | `tag:lanetus.github.io,2026:tdx-nested-eat`         |

The profiles are private tag URIs, not registered values. For Nitro, the outer claims-set also carries a best-effort standard mapping:

| EAT claim      | Key   | Value                                                              |
|-----------------|-------|---------------------------------------------------------------------|
| `iat`           | 6     | The Nitro document's `timestamp`, in seconds                       |
| `ueid`          | 256   | Type `0x01` (RAND) + SHA-256 of the Nitro document's `module_id`    |
| `eat_profile`   | 265   | `tag:aws.amazon.com,2024:nitro-enclave-nested-eat`                  |
| `submods`       | 266   | `{ "aws_nitro": <raw NSM Attestation Document bytes> }`             |

Claim keys are from the IANA ["CBOR Web Token (CWT) Claims"](https://www.iana.org/assignments/cwt) registry, as registered by RFC 9711. See `crates/core/src/attestation/eat.rs`.

## Docker

The `Dockerfile` builds one enclave node, `relay` (default) or `terminal` (`--build-arg NODE=terminal`), in release mode with the default features and packages it in a `debian:bookworm-slim` image. The test-only `client` binary is not included. `scripts/build-eif.sh [amd64|arm64] [relay|terminal]` turns the image into an EIF. The CD pipeline builds and pushes the image to a private Amazon ECR repository.

## License

[MIT](LICENSE)

