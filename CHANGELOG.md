# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0] - 2026-09-29

### Added
- `EnclaveCertVerifier::with_expected_pcr` to require specific PCR values in the server's attestation document.
- `EnclaveCertVerifier::allow_mock` for local development, enabled in the `client` binary with `TTK_ALLOW_MOCK_ATTESTATION=1`.
- `EnclaveCertVerifier::verified_attestation` returning the accepted attestation document, and `TtkClient::connect_with_verifier` to connect with a custom verification policy.
- Doc comments across the public API.

### Changed
- **BREAKING:** The server binds the attestation `user_data` to the SHA-256 of the TLS public key (SubjectPublicKeyInfo) instead of the private key DER. Verifiers must hash the certificate's public key.
- **BREAKING:** `TtkClient::connect` and the `client` binary reject mock evidence by default. Set `TTK_ALLOW_MOCK_ATTESTATION=1` to connect to a server built with the `mock` feature.
- Removed the `aws-nitro-enclaves-cose` dependency, which drops `openssl` from the dependency tree.

### Fixed
- `EnclaveCertVerifier::received_certificate` now returns the server certificate after a successful handshake; previously it was never set.

### Security
- The `client` now verifies the server's RA-TLS certificate (validity period and self-signature) and its embedded Nitro attestation document: COSE ES384 signature, certificate chain up to the pinned AWS Nitro root CA, and binding of `user_data` to the certificate's public key. Previously any certificate was accepted.
- The `client` now verifies TLS 1.2/1.3 handshake signatures against the server certificate. Previously all handshake signatures were accepted.

## [0.10.3] - 2026-09-29

No user-facing changes.

## [0.10.2] - 2026-09-29

No user-facing changes.

## [0.10.1] - 2026-09-29

No user-facing changes.

## [0.10.0] - 2026-09-29

### Added
- MIT license.

### Changed
- PEM parsing uses `rustls-pki-types` instead of `rustls-pemfile`, and the `hyper` dependency was removed.

## [0.9.2] - 2026-09-29

No user-facing changes.

## [0.9.1] - 2026-09-29

No user-facing changes.

## [0.9.0] - 2026-09-29

### Added
- Runtime attestation provider selection: the server detects the TEE hardware it runs on (AWS Nitro, AMD SEV-SNP, Intel TDX) and falls back to the mock provider when none is found. `TTK_ATTESTATION=<name>` forces a provider.
- Additive Cargo features `nitro`, `mock`, `sev-snp` and `tdx` (default: `nitro`, `mock`). SEV-SNP and TDX currently only detect their hardware; evidence generation is not implemented.
- The attestation evidence is embedded in the server's TLS certificate as a custom X.509 extension (OID `1.3.6.1.4.1.99999.1`), and the `client` extracts it during the handshake.
- CBOR decoding of EAT claims-sets (`EatClaimsSet::from_cbor_bytes`).

### Changed
- **BREAKING:** `/evidence` and `/attestation` now return the RFC 9711 EAT token (base64 CBOR), the same as `/evidence.eat`, instead of the raw Nitro attestation document.
- **BREAKING:** The library's attestation API moved to the `ttk_server::attestation` module (`detect`, `by_name`, `AttestationProvider`); the `ttk_server::nitro` module and `generate_attestation_for_cert_or_mock` were removed.
- Server startup and request handling moved from `main.rs` into the `ttk_server::server` module.

## [0.8.0] - 2026-09-27

No user-facing changes.

## [0.7.0] - 2026-09-27

### Added
- `client` binary: an HTTP/3 client that connects to the server over QUIC and prints the server certificate fingerprint and responses.
- `ttk_server` library crate exposing the EAT, Nitro attestation and client modules.
- `/` route.
- Mock attestation document when `/dev/nsm` is unavailable, so the server runs outside a Nitro Enclave.

### Changed
- **BREAKING:** The server now serves HTTP/3 over QUIC on UDP `0.0.0.0:4433` instead of HTTPS over VSOCK.
- Upgraded to rustls 0.23 and rcgen 0.13.

## [0.6.0] - 2026-09-16

No user-facing changes.

## [0.5.0] - 2026-09-16

### Fixed
- The startup message is logged at `info` level instead of `error`.

## [0.4.0] - 2026-09-16

### Changed
- Docker image builds cache the cargo registry and build artifacts between builds.

## [0.3.0] - 2026-09-16

### Added
- `/evidence` route serving the attestation document (RFC 9334 naming); `/attestation` is kept as an alias.
- `/evidence.eat` route serving the attestation document wrapped as an RFC 9711 Entity Attestation Token (base64 CBOR).
- Logging via `env_logger`, configured with `RUST_LOG`.

## [0.2.0] - 2025-11-29

No user-facing changes.

## [0.1.3] - 2025-11-29

No user-facing changes.

## [0.1.2] - 2025-11-29

No user-facing changes.

## [0.1.1] - 2025-11-29

### Added
- Initial release: HTTPS server over VSOCK for AWS Nitro Enclaves with an ephemeral self-signed TLS certificate.
- NSM attestation document bound to the SHA-256 of the TLS certificate, served base64-encoded at `/attestation`.
- `/hello` route.
- Dockerfile for building the server image.

[Unreleased]: https://github.com/Lanetus/TTKServer/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/Lanetus/TTKServer/compare/v0.10.3...v0.11.0
[0.10.3]: https://github.com/Lanetus/TTKServer/compare/v0.10.2...v0.10.3
[0.10.2]: https://github.com/Lanetus/TTKServer/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/Lanetus/TTKServer/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/Lanetus/TTKServer/compare/v0.9.2...v0.10.0
[0.9.2]: https://github.com/Lanetus/TTKServer/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/Lanetus/TTKServer/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/Lanetus/TTKServer/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/Lanetus/TTKServer/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Lanetus/TTKServer/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Lanetus/TTKServer/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Lanetus/TTKServer/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Lanetus/TTKServer/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Lanetus/TTKServer/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Lanetus/TTKServer/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/Lanetus/TTKServer/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Lanetus/TTKServer/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Lanetus/TTKServer/releases/tag/v0.1.1
