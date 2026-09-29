# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- The server can attest with AMD SEV-SNP (`sev-snp` feature): inside an SEV-SNP guest it obtains an attestation report through configfs-tsm (Linux 6.7+), binding the TLS key hash in `REPORT_DATA`, and embeds it with the VCEK certificate in the EAT under the `sev_snp` submodule. The VCEK comes from the certificate table the host attaches to the report, or from the file named by `TTK_SEV_SNP_VCEK` when the host supplies none. Detected automatically via `/dev/sev-guest`, or forced with `TTK_ATTESTATION=sev-snp`.
- The server can attest with Intel TDX (`tdx` feature): inside a TDX guest it obtains a DCAP quote through the Linux configfs-tsm interface (`/sys/kernel/config/tsm/report`, Linux 6.7+), binding the TLS key hash in `REPORTDATA`, and embeds it in the EAT under the `tdx` submodule. Detected automatically via `/dev/tdx_guest`, or forced with `TTK_ATTESTATION=tdx`.
- The `client` verifies AMD SEV-SNP, Intel TDX and Intel SGX evidence in addition to AWS Nitro. The server's EAT carries exactly one of the `submods` `aws_nitro`, `sev_snp` (`{report, vcek}`), `tdx` or `sgx` (DCAP quote).
  - SEV-SNP: ARK → ASK → VCEK chain against pinned Milan, Genoa and Turin roots, VCEK `hwID` and TCB matched to the report, and the report's ECDSA P-384 signature.
  - TDX and SGX: DCAP quote v3/v4/v5 with the embedded PCK chain verified against the pinned Intel SGX Root CA, the Quoting Enclave report signature and attestation-key binding, and the quote signature.
- `ttk_server::verifier` module with `verify_evidence`, `TrustStore`, `Policy` and `VerifiedEvidence`.
- `EnclaveCertVerifier::with_expected_measurement` for TEE measurements (e.g. `mrtd`, `rtmr0`, `mrenclave`, `measurement`), `allow_debug`, `with_trust_store` and `verified_evidence`.

### Changed
- Mock attestation documents are now signed: the `mock` provider issues a signing certificate from a published TTKServer mock root CA and signs the document with ES384, so the `client` verifies mock evidence exactly like Nitro evidence (signature, certificate chain, key binding) instead of skipping those checks. `TTK_ALLOW_MOCK_ATTESTATION=1` / `EnclaveCertVerifier::allow_mock()` now means "also trust the mock root CA".
- A client that does not allow mock evidence now explains how to opt in, instead of failing with `attestation cabundle is empty`.
- **BREAKING:** Unsigned mock documents from servers built before this change are rejected even with mock evidence allowed; rebuild and restart the server.
- **BREAKING:** The `client` rejects evidence from debug-mode TEEs (including Nitro enclaves with all-zero PCRs) unless `EnclaveCertVerifier::allow_debug` or `allow_mock` is set.
- The AWS Nitro root is pinned by its full certificate instead of its SHA-256 fingerprint.

### Security
- SEV-SNP VCEK revocation, and Intel TCB status and QE identity (PCS collateral), are not yet evaluated: genuine but out-of-date or revoked platforms are accepted.

## [0.11.1] - 2026-09-29

No user-facing changes.

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

[Unreleased]: https://github.com/Lanetus/TTKServer/compare/v0.11.1...HEAD
[0.11.1]: https://github.com/Lanetus/TTKServer/compare/v0.11.0...v0.11.1
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
