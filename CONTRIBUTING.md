# Contributing to TTKServer

Thanks for your interest in improving TTKServer! This guide covers how to set up the workspace, the checks your change must pass, and how commits and releases work.

Everyone participating in this project is expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting set up

You need stable [Rust](https://www.rust-lang.org/tools/install) (edition 2021). Optional tools, depending on what you touch:

| Tool                                   | Needed for                                  |
|----------------------------------------|---------------------------------------------|
| `cargo-deny`, `cargo-audit`            | Dependency changes (license / advisory checks) |
| `cargo-nextest`, `cargo-llvm-cov`      | Running tests with coverage the way CI does |
| `mdbook`, `mdbook-mermaid`             | Editing the book in `docs/`                 |
| Docker                                 | Building enclave images (`scripts/build-eif.sh`) |

```sh
git clone https://github.com/Lanetus/TTKServer.git
cd TTKServer
cargo build --workspace
cargo test --workspace
```

No TEE hardware is required for development: the `mock` attestation provider is used when none is detected, and Nitro tests fall back to mock documents off-enclave.

## Workspace layout

| Crate (directory)                   | Contents                                                                 |
|-------------------------------------|--------------------------------------------------------------------------|
| `ttk-core` (`crates/core/`)         | Library, server only: attestation providers, EAT, RA-TLS cert, QUIC/HTTP/3 serving, vsock transport. No relay/message logic, no client code. |
| `ttk-client` (`crates/client/`)     | Client library (`TtkClient`, `EnclaveCertVerifier`, evidence verifier, `/faf` format, HPKE sealing) and the **test-only** `client` binary. |
| `ttk-relay` (`crates/relay/`)       | Relay node (`relay` bin) and the parent-instance `vsock-proxy` bin.       |
| `ttk-terminal` (`crates/terminal/`) | Terminal node (`terminal` bin), the last hop of `POST /faf`.              |

Please keep code in the crate it belongs to — for example, client-side logic goes in `ttk-client`, not `ttk-core`.

Shared dependency versions live in `[workspace.dependencies]` in the root `Cargo.toml`; reference them from crates with `{ workspace = true }`. Note that `quinn`, `h3`, `h3-quinn` and `rustls` are tightly coupled and must be upgraded together.

## Running locally

```sh
TTK_USE_UDP=1 RUST_LOG=info cargo run --bin relay                              # UDP :4433
TTK_USE_UDP=1 TTK_LISTEN_ADDR=127.0.0.1:4444 RUST_LOG=info cargo run --bin terminal
cargo run --bin client -- <args>                                             # see parse_client_args() in crates/client/src/main.rs
```

## Before opening a pull request

CI runs the following on every pull request; please run them locally first:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check --all-features     # if you changed dependencies
```

CI additionally runs `cargo audit` and collects coverage with `cargo llvm-cov nextest --all-features --workspace --profile ci`.

Also:

- **Test your change.** Add unit tests next to the code, or integration tests under the crate's `tests/` (end-to-end client/relay/terminal tests live in `crates/client/tests/client_bin_tests.rs`).
- **Check every feature combination you affect.** `nitro` and `mock` are default; `sev-snp` and `tdx` are optional. Features are additive, so code must build with any subset.
- **Document public items** with `//!` / `///` comments, in the existing style that references the relevant RFCs (RFC 9334 RATS, RFC 9711 EAT, RFC 9180 HPKE).
- **Update `CHANGELOG.md`** under `## [Unreleased]` for user-visible changes, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
- **Update the book** in `docs/` if you change behavior it describes (`mdbook build docs` to check it renders).

### Dev-dependency cycle

`ttk-client` dev-depends on `ttk-relay` and `ttk-terminal`, which depend on `ttk-client`. In client tests, don't pass `ttk_client` types into relay/terminal APIs — they are distinct types from the dev-dependency's copy. Use e.g. `Relay::allow_mock()` rather than `with_verifier(...)`.

## Commit messages

Releases are automated from commit messages on `main`, so **every commit message must start with one of these prefixes**:

| Prefix   | Use for                | Version bump |
|----------|------------------------|--------------|
| `fix:`   | Bug fixes, chores, docs | patch       |
| `feat:`  | New features           | minor        |
| `major:` | Breaking changes       | major        |

Example: `feat: verify SEV-SNP evidence in the client`

Don't use `chore(release):` — it is reserved for the automated version-bump commit, and CI skips releasing on it. Don't bump the version in `Cargo.toml` yourself; the CD workflow does it (with `cargo set-version --workspace`) and tags the release when your change lands on `main`. When a pull request is squash-merged, the squash commit's title must follow the same rule.

## Security-sensitive changes

TTKServer is attestation and RA-TLS code, so please take extra care with changes to TLS/QUIC setup, certificate generation, attestation providers, the client verifier, or dependencies, and call them out in your pull request description. In particular:

- `EnclaveCertVerifier` deliberately skips CA validation; trust comes from verifying the attestation evidence and its binding to the certificate key. Don't reuse it outside RA-TLS flows.
- The attestation OID `1.3.6.1.4.1.99999.1` is a placeholder, not a registered PEN.
- The `mock` provider and `TTK_ALLOW_MOCK_ATTESTATION` are for development only and must never be trusted in production.
- The `client` binary is test-only and must not be included in enclave images.

### Reporting vulnerabilities

Please **do not** open a public issue for a security vulnerability. See [SECURITY.md](SECURITY.md) for how to report it privately.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
