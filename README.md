[![Documentation](https://docs.rs/TTKServer/badge.svg)](https://docs.rs/TTKServer/)
[![Crates.io](https://img.shields.io/crates/v/TTKServer.svg)](https://crates.io/crates/TTKServer)
[![codecov](https://codecov.io/gh/Lanetus/TTKServer/graph/badge.svg?token=G4380O9RMS)](https://codecov.io/gh/Lanetus/TTKServer)
[![CI](https://github.com/Lanetus/TTKServer/actions/workflows/CI.yml/badge.svg)](https://github.com/Lanetus/TTKServer/actions/workflows/CI.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)


# TTKServer

An HTTP/3 (QUIC) **RA-TLS** server in Rust, meant to run inside a Trusted Execution Environment (TEE). It plays the RATS ([RFC 9334](https://www.rfc-editor.org/rfc/rfc9334)) **Attester** role:

1. At startup it generates an ephemeral TLS key pair.
2. It asks the TEE hardware for attestation Evidence whose report data is bound to the SHA-256 of that key.
3. It wraps the Evidence as an [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711) Entity Attestation Token (EAT) and embeds it in a self-signed X.509 certificate (custom extension, OID `1.3.6.1.4.1.99999.1`, placeholder).
4. It serves HTTP/3 over QUIC with that certificate on `0.0.0.0:4433` (UDP), and also exposes the Evidence over HTTP.

A client can verify the TLS certificate's embedded Evidence during the handshake, so the connection itself is bound to the attested TEE. The library ships such a client (`ttk_server::client`) and a verifier for all supported TEEs.

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
cargo build --release
```

### Cargo features

| Feature       | Default | Purpose                                                                                  |
|---------------|:-------:|------------------------------------------------------------------------------------------|
| `nitro`       | ✓       | AWS Nitro Enclaves provider                                                              |
| `mock`        | ✓       | Mock provider; used as a fallback when no TEE hardware is detected                        |
| `sev-snp`     |         | AMD SEV-SNP provider                                                                     |
| `tdx`         |         | Intel TDX provider                                                                       |
| `test-client` |         | Builds the **test-only** `client` binary. Never enable it for production builds.         |

Features are additive, so one binary can support several TEEs, e.g. `cargo build --release --features sev-snp,tdx`.

## Usage

### Running the server

```sh
cargo run --release
```

At startup the server picks an attestation provider: it probes the compiled-in hardware backends (Nitro, then SEV-SNP, then TDX) and falls back to `mock` if none is found. The mock fallback only exists when the `mock` feature is enabled, and it logs a warning because its Evidence is **not trustworthy**.

Logging is via [`env_logger`](https://docs.rs/env_logger); set `RUST_LOG` to control verbosity (no output by default):

```sh
RUST_LOG=info cargo run --release
```

### Endpoints

| Route            | Response                                                             |
|------------------|----------------------------------------------------------------------|
| `GET /`          | Greeting text                                                        |
| `GET /evidence.eat` | Base64-encoded EAT carrying the Evidence                          |
| `POST /faf`      | Onion-routes a sealed message through attested relays (see below)    |

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

Every node on the route runs this same server. A node that receives a request with relays left:

1. removes the first entry from `relays` and reads the next hop from it. With `encrypted: true`, the address was sealed to **this node's** RA-TLS key, and only this node can open it;
2. connects to the next hop over QUIC / HTTP/3 and **verifies its RA-TLS attestation**;
3. posts the rest of the request (the remaining `relays` and the unchanged `body`) to the next hop's `POST /faf`, and answers `200 OK` once that hop has.

A node that receives an empty `relays` is the last hop. It is the only node that can decrypt `body`, and it answers `200 OK` (`delivered`) if it can.

An opened address has the form `"<server> <salt>"`, e.g. `"https://server.com:443 0123456789"`. `<server>` is `host[:port]` or `https://host[:port]`, and the port defaults to `4433`. The salt is 10 random decimal digits. It is required in encrypted addresses and optional in plain ones.

Encryption uses the nodes' attested RA-TLS keys (ECDSA P-256), so a client seals only to nodes it has attested. It uses RFC 9180 HPKE in base mode with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-256-GCM:

- `relays[i].address` (encrypted) is sealed to the node that reads it;
- `body.message` is encrypted with a fresh AES-256-GCM key (base64 of a 12-byte nonce followed by the ciphertext), and `body.key` is that key sealed to the last hop. `body.key` is required and never null.

HPKE values are base64 of the encapsulated key (65 bytes) followed by the ciphertext. Clients build requests with `ttk_server::seal` (`NodePublicKey::from_certificate`, `seal_address`, `seal_body`). Other responses:

| Status | When                                                                         |
|--------|------------------------------------------------------------------------------|
| `400`  | The first relay entry can't be opened or parsed (e.g. an `http://` URL or a bad salt), or, at the last hop, `body` can't be decrypted |
| `413`  | The request body is over 1 MiB                                               |
| `415` / `422` | The body isn't JSON, or a field is missing or null                    |
| `502`  | The next hop can't be reached, fails attestation, or answers anything but `200` |
| `504`  | The next hop doesn't answer within 10 seconds                                |

By default relays must present genuine TEE evidence. For local development with mock attestation, start the server with `TTK_ALLOW_MOCK_ATTESTATION=1`.

### Environment variables

| Variable                     | Used by  | Meaning                                                                                   |
|------------------------------|----------|-------------------------------------------------------------------------------------------|
| `RUST_LOG`                   | server   | Log level (`info`, `debug`, …)                                                            |
| `TTK_ATTESTATION`            | server   | Force a provider instead of probing: `aws-nitro`, `sev-snp`, `tdx` or `mock`             |
| `TTK_SEV_SNP_VCEK`           | server   | Path to a VCEK certificate (DER or PEM) when the SEV-SNP host doesn't supply one          |
| `TTK_SERVER_ADDR`            | client   | Default server address (default `127.0.0.1:4433`)                                         |
| `TTK_SERVER_NAME`            | client   | Default SNI server name (default `localhost`)                                             |
| `TTK_ALLOW_MOCK_ATTESTATION` | both     | Set to `1` to accept mock Evidence from the server (client) or from `/faf` relays (server). Development only |

### Test client

The `client` binary is for testing only and is built only with the `test-client` feature. It connects over HTTP/3, verifies the server certificate's embedded Evidence and prints the responses:

```sh
# Terminal 1: server (falls back to mock attestation off-TEE)
cargo run
# Terminal 2: client, accepting mock Evidence
TTK_ALLOW_MOCK_ATTESTATION=1 cargo run --features test-client --bin client -- --path /evidence.eat
```

Run `cargo run --features test-client --bin client -- --help` for all options.

### Using the library

The crate is also a library, `ttk_server`. To embed the client in your own Relying Party:

```rust
use ttk_server::client::{EnclaveCertVerifier, TtkClient};

let verifier = EnclaveCertVerifier::new()
    .with_expected_pcr(0, expected_pcr0); // reference values for your enclave image
let mut client = TtkClient::connect_with_verifier(addr, "localhost", verifier).await?;
let resp = client.get("/evidence.eat").await?;
```

## Project layout

```
src/
  lib.rs            crate root: declares the modules and re-exports common items
  main.rs           `TTKServer` binary (calls `ttk_server::server::run()`)
  bin/client.rs     test-only `client` binary (`test-client` feature)
  attestation/      TEE providers (nitro, sev_snp, tdx, mock) and the EAT data model (eat.rs)
  service/          server.rs (QUIC / HTTP/3), router.rs (routes incl. /faf), client.rs,
                    plus generate_identity() / AttestationParams
  verifier/         Evidence verification for Nitro, SEV-SNP and TDX/SGX (DCAP)
tests/              integration and end-to-end tests
benches/client.rs   Criterion benchmarks for the client
```

## Development

```sh
cargo test                                    # default features
cargo test --all-features                     # everything, including the client binary tests
cargo bench --bench client                    # client benchmarks (needs `mock`)
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
cargo deny check                              # licences / advisories, config in deny.toml
```

Commit messages must start with `fix:` (patch), `feat:` (minor) or `major:` (major); the release workflow derives the version bump from this prefix.

## CI/CD

This project uses GitHub Actions:

*   **CI (`CI.yml`):** runs on every pull request. It runs the tests with coverage (`cargo llvm-cov nextest --all-features`, uploaded to Codecov), checks formatting, runs clippy with `--all-features`, and runs `cargo audit` and `cargo deny`.
*   **CD (`main.yml`):** runs on pushes to `main`. It bumps the version in `Cargo.toml` according to the commit prefix, commits it as `chore(release): version X.Y.Z` with a tag, builds `linux/amd64` and `linux/arm64` Docker images and pushes them to Amazon ECR, and runs the tests with coverage.

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

Claim keys are from the IANA ["CBOR Web Token (CWT) Claims"](https://www.iana.org/assignments/cwt) registry, as registered by RFC 9711. See `src/attestation/eat.rs`.

## Docker

The `Dockerfile` builds the `TTKServer` binary in release mode with the default features and packages it in a `debian:bookworm-slim` image. The test-only `client` binary is not included. The CD pipeline builds and pushes the image to a private Amazon ECR repository.

## License

[MIT](LICENSE)

