# TTKServer

This is a Rust-based server application.

## Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

*   [Rust](https://www.rust-lang.org/tools/install)

### Installation

1.  Clone the repo
    ```sh
    git clone https://github.com/your_username/TTKServer.git
    ```
2.  Build the project
    ```sh
    cargo build --release
    ```

## Usage

To run the server, use the following command:

```sh
cargo run --release
```

Logging is via [`env_logger`](https://docs.rs/env_logger); set `RUST_LOG` to control verbosity (no output by default):

```sh
RUST_LOG=info cargo run --release
```

## Running Tests

To run the test suite, use the following command:

```sh
cargo test
```

## CI/CD

This project uses GitHub Actions for CI/CD:

*   **Main Workflow (`main.yml`):** Triggered on pushes to the `main` branch. This workflow builds the Docker image, bumps the version in `Cargo.toml`, and pushes the image to Amazon ECR with `latest` and version tags.
*   **Test and Lint Workflow (`test-and-lint.yml`):** Triggered on pushes to any branch except `main`. This workflow runs tests and lints the code, automatically committing any formatting changes.

## RATS Architecture (RFC 9334)

This server implements the **Attester** role from [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334) (Remote ATtestation procedureS Architecture) by running inside an AWS Nitro Enclave and producing hardware-rooted Evidence via the Nitro Security Module (NSM).

| RATS concept       | Concrete artifact in this server                                                               |
|---------------------|--------------------------------------------------------------------------------------------------|
| Attester            | This process, running inside the Nitro Enclave                                                   |
| Evidence            | The NSM Attestation Document (`GET /evidence`, aliased as `GET /attestation`), with `user_data` bound to the SHA-256 hash of the server's ephemeral TLS certificate |
| Endorsements        | The AWS Nitro certificate chain embedded in the Attestation Document, rooted at the AWS Nitro Enclaves root CA |
| Reference Values    | Expected PCR measurements for this enclave image, held out-of-band by whoever verifies the Evidence |
| Verifier / Relying Party | An external client that fetches Evidence over `/evidence`, checks it against Endorsements and Reference Values, and (if it trusts the result) proceeds with the TLS session bound to that Evidence |

Appraisal of Evidence and issuance of an Attestation Result happen outside this server — it only produces and serves Evidence.

### EAT export (RFC 9711)

`GET /evidence.eat` serves the same Evidence as a base64-encoded [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711) Entity Attestation Token claims-set (CBOR).

The NSM Attestation Document is already signed (COSE_Sign1) by the enclave's hardware-rooted key, and this server holds no other key a Relying Party would trust more. So rather than minting a new signature, the claims-set nests the original signed document verbatim under the `submods` claim (key `266`, submodule name `aws_nitro`) — the nested-token form defined in RFC 9711. Trust comes from that nested document, not from the outer claims-set, which is unsigned. The outer claims-set also carries a best-effort standard mapping:

| EAT claim      | Key   | Value                                                              |
|-----------------|-------|---------------------------------------------------------------------|
| `iat`           | 6     | The Nitro document's `timestamp`, in seconds                       |
| `ueid`          | 256   | Type `0x01` (RAND) + SHA-256 of the Nitro document's `module_id`    |
| `eat_profile`   | 265   | `tag:aws.amazon.com,2024:nitro-enclave-nested-eat` (private, unregistered) |
| `submods`       | 266   | `{ "aws_nitro": <raw NSM Attestation Document bytes> }`             |

Claim keys are from the IANA ["CBOR Web Token (CWT) Claims"](https://www.iana.org/assignments/cwt) registry, as registered by RFC 9711. See `src/eat.rs`.

## Docker

This project includes a `Dockerfile` to build a containerized version of the application. The CI/CD pipeline automatically builds and pushes the image to a private ECR repository.

