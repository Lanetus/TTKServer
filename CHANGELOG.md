# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **BREAKING:** Evidence is wrapped in a RATS Conceptual Message Wrapper (CMW, `draft-ietf-rats-msg-wrap`, CBOR) instead of an RFC 9711 EAT claims-set, in the RA-TLS certificate extension, `GET /evidence.cmw` and `POST /evidence`. Nitro, TDX and SGX evidence are CMW records typed by `ttk_core::media_type`; SEV-SNP evidence is a collection of the report (Evidence) and the VCEK (Endorsement). The unsigned outer EAT claims (`iat`, `ueid`, `eat_profile`) are gone. Old clients cannot verify new servers and vice versa.
- **BREAKING:** `GET /evidence.eat` is renamed `GET /evidence.cmw`.
- **BREAKING:** `AttestationProvider::generate_document` returns a `Cmw`; `nitro_doc::wrap_as_eat`, `tdx::wrap_quote_as_eat` and `sev_snp::wrap_evidence_as_eat` are replaced by `wrap_as_cmw`, `wrap_quote_as_cmw` and `wrap_evidence_as_cmw`. `router::Evidence` has a single `cmw` field (`nitro` and `eat` are removed).
- **BREAKING:** `ttk_ra_client::verifier::sev_snp::verify` takes the report and VCEK bytes instead of a CBOR map; `TeeKind::from_submod` is replaced by `TeeKind::from_cmw`.

### Removed
- **BREAKING:** `ttk_core::eat` (`EatClaimsSet`, `EatClaimKey`) and the `submod` labels, with their re-exports from `ttk_ra_server`; use `ttk_core::cmw` and `ttk_core::media_type`.

## [5.0.0] - 2026-10-07

### Changed
- **BREAKING:** `ttk_ra_server::server::Attester` is removed; `Server` and `router::build_router` now take the `AttestationProvider` directly. `POST /evidence` now returns Evidence carrying only the request's nonce (no longer also the RA-TLS key binding in `user_data`); the startup Evidence in the RA-TLS cert and `/evidence.eat` stays bound to the key.

### Removed
- **BREAKING:** `ttk_ra_server::generate_identity()` (unused) is removed.

## [4.0.0] - 2026-10-07

### Changed
- **BREAKING:** `ttk_ra_server::AttestationParams` is now a plain struct with public fields and `Default`; the builder methods (`new`, `with_user_data`, `with_user_data_hash`, `with_nonce`, `with_public_key`) and the accessors (`user_data()`, `nonce()`, `public_key()`) are removed.

## [3.0.3] - 2026-10-07

No user-facing changes.

## [3.0.2] - 2026-10-07

### Added
- `POST /evidence` route on `ttk-ra-server` nodes: the body is a raw nonce (1 to 512 bytes) and the response is fresh base64 EAT evidence carrying that nonce in the Nitro attestation document. Requests beyond the concurrent-attestation limit get 503; TDX and SEV-SNP nodes answer 500.

## [3.0.1] - 2026-10-07

No user-facing changes.

## [3.0.0] - 2026-10-07

### Changed
- **BREAKING:** `ImageTrustStore` is now a trait (`builtin()`, `nitro_image_allowlist()`, `nitro_pcr_index()`) in `ttk-core`, and `verify_evidence`/`nitro::verify` take `&dyn ImageTrustStore`. Clients (`RootImageTrustStore` in `ttk-ra-client`) now fetch accepted enclave images from the root servers (`a.ttk-server.net:443`, `b.ttk-server.net:443`), each attested by its pinned PCR8 (`RootSignerTrustStore`), and fail closed when none can be reached.
- The `root` node's accepted-image list moved to `crates/root/src/nitro_image_allowlist.txt` (`FileImageTrustStore`).

## [2.9.0] - 2026-10-07

### Changed
- **BREAKING:** The crates are renamed and split: shared code (`EatClaimsSet`, `ATTESTATION_OID`, `PARENT_CID`, egress policy, vsock sockets, the `vsock-proxy` binary) now lives in `ttk-core`; the server library is `ttk-ra-server` (`ttk_ra_server`) and the client library and `client` binary are `ttk-ra-client` (`ttk_ra_client`). `ttk-ra-server` re-exports the shared items at their old paths. `vsock-proxy` is now built from `ttk-core`.

## [2.8.0] - 2026-10-07

### Changed
- Moved `TrustStore` and the vendor root certificates out of the `client` verifier, and `ttk-root` no longer depends on the client crate.

## [2.7.1] - 2026-10-07

### Fixed
- The `client` binary prints its usage text to stdout again.

## [2.7.0] - 2026-10-07

### Changed
- Server, client and `vsock-proxy` log through `log` macros (`RUST_LOG`) instead of printing directly.

## [2.6.0] - 2026-10-06

### Changed
- The terminal's `POST /faf` reply (`hello:<message>`) is now sealed under the message key and passed back unchanged through the relays; the `client` binary opens it.

## [2.5.0] - 2026-10-06

### Added
- Per-node enclave systemd units (`ttk-relay-enclave.service`, `ttk-terminal-enclave.service`), debug EIF builds, and an updated EC2 user data script.

### Changed
- The parent-instance unit is renamed to `vsock-proxy.service`; the old `ttkserver-enclave.service` is replaced by the per-node units.

## [2.4.3] - 2026-10-06

No user-facing changes.

## [2.4.2] - 2026-10-05

### Security
- Hardened relay egress (next-hop and `vsock-proxy` outbound destination policy, limits on relays per request and concurrent forwards), server and client resource limits (connections, streams, headers, request and response bodies), and terminal logging.

## [2.4.1] - 2026-10-05

### Added
- `ttk-root` crate and `root` node binary serving the accepted enclave image checksums (`GET /root-attestation`), with EIF build support (`scripts/build-eif.sh ... root`).

## [2.4.0] - 2026-10-05

### Added
- The test-only `client` binary sends its `POST /faf` request through two relays and a terminal: an entry relay (`--addr`), a second relay (`--relay`, default `127.0.0.1:4434`) and a terminal (`--terminal`, default `127.0.0.1:4444`).

### Changed
- **BREAKING:** The `client` binary's `--relay` option now names the second relay instead of the terminal; use the new `--terminal` option to name the terminal.
- Hop addresses in the `/faf` request are now HPKE-sealed to the relay that reads them; previously the single hop address was sent in the clear.

## [2.3.5] - 2026-10-05

No user-facing changes.

## [2.3.4] - 2026-10-05

### Security
- **BREAKING:** The `client` verifier (`ttk_client::verifier`) rejects non-debug AWS Nitro evidence unless the enclave's PCR0 (the SHA-384 of the EIF) is listed in the built-in allowlist `crates/client/src/verifier/nitro_image_allowlist.txt` (`TrustStore::nitro_image_allowlist`, parsed by `nitro::parse_image_allowlist`). Deployments whose enclave images are not listed are no longer accepted. Debug and mock enclaves (all-zero PCRs) remain governed by the debug policy.

## [2.3.3] - 2026-10-04

### Changed
- Updated `p256` to 0.14 and reverted `tokio-vsock` to 0.3.

## [2.3.2] - 2026-10-04

### Changed
- Updated `sha2` to 0.11 and `tokio-vsock` to 0.7.

## [2.3.1] - 2026-10-01

No user-facing changes.

## [2.3.0] - 2026-10-01

No user-facing changes.

## [2.2.0] - 2026-10-01

No user-facing changes.

## [2.1.0] - 2026-10-01

No user-facing changes.

## [2.0.0] - 2026-10-01

### Changed
- **BREAKING:** The project is split into a `crates/` workspace: `ttk-core` (library-only attested RA-TLS HTTP/3 server: attestation, EAT, identity, certificate, `/` and `/evidence.eat`, vsock), `ttk-client` (client, verifier, `/faf` request format, HPKE sealing, and the `client` binary), `ttk-relay` and `ttk-terminal`. The `ttk_server` crate no longer exists.
- **BREAKING:** The server is now run as the `relay` or `terminal` enclave node binaries (`ttk-relay`, `ttk-terminal`); the `TTKServer` binary is gone. The parent-instance proxy formerly called `relay` is now `vsock-proxy`.
- **BREAKING:** The `test-client` feature is removed; the `client` binary is built with `ttk-client`.

## [1.0.0] - 2026-10-01

### Changed
- **BREAKING:** `POST /faf` is onion-routed. The request body changes from `{relay_server, message, key}` to `{relays: [{address, encrypted}], body: {key, message}}`. Each node pops the first relay entry, opens it with its own RA-TLS key if `encrypted`, and forwards the rest to the address it names (`"<server> <10-digit salt>"`). The last hop must decrypt `body`: the message is AES-256-GCM encrypted under a key sealed to the last hop. Old-format requests get 422.

### Added
- `ttk_server::seal`: RFC 9180 HPKE (DHKEM(P-256), HKDF-SHA256, AES-256-GCM) sealing of relay addresses and message keys to a node's attested RA-TLS key, so clients only seal to nodes they have attested.

## [0.25.0] - 2026-10-01

### Added
- `deploy/ec2/user-data.sh`: EC2 user data that installs the Nitro Enclaves CLI, downloads the EIF, `vsock-proxy` binary and systemd units (optional SHA-256 checks), and starts the enclave and relay so they also come up on reboot.

## [0.24.0] - 2026-09-30

### Added
- `deploy/systemd/ttkserver-enclave.service`: systemd unit that runs the enclave EIF with `nitro-cli run-enclave`, configured from `/etc/default/ttkserver-enclave`.
- `deploy/systemd/ttk-relay.service`: hardened systemd unit for the parent-side relay (binds UDP 443, configured from `/etc/default/ttk-relay`).

## [0.23.0] - 2026-09-30

### Added
- `scripts/build-eif.sh` builds the Nitro Enclave EIF locally with Docker.

## [0.22.7] - 2026-09-30

### Added
- The server listens for QUIC directly on vsock port 5000 (datagrams framed as `[u16 BE length][payload]`), replacing the in-enclave `relay.py`. `TTK_USE_UDP=1` switches back to a UDP socket on `TTK_LISTEN_ADDR`.
- In vsock mode, `POST /faf` relay connections leave the enclave through the parent at vsock `3:5001` (`TTK_PARENT_CID`, `TTK_OUTBOUND_VSOCK_PORT`).
- Linux-only `relay` binary for the parent instance: forwards public UDP (default `0.0.0.0:443`) into the enclave and the enclave's outbound connections to their UDP destinations (renamed `vsock-proxy` in 2.0.0).
- `TtkClient` gains `ClientTransport` and `connect_over` for connecting over vsock.

## [0.22.6] - 2026-09-30

### Changed
- `POST /faf` reuses verified connections to relays (pooled per host and port) and closes them off the request path, cutting relayed request latency from about 90 ms to a few ms.

## [0.22.5] - 2026-09-30

### Fixed
- The vsock bridge in the enclave image preserves datagram boundaries by length-framing each datagram, instead of `socat` merging or splitting QUIC packets.

## [0.22.4] - 2026-09-30

### Fixed
- The enclave image bridges vsock port 5000 to the QUIC listener, so the server is reachable from the parent instance.

## [0.22.3] - 2026-09-29

No user-facing changes.

## [0.22.2] - 2026-09-29

No user-facing changes.

## [0.22.1] - 2026-09-29

No user-facing changes.

## [0.22.0] - 2026-09-29

### Added
- The build workflow builds the Nitro Enclave EIF.

## [0.21.2] - 2026-09-29

### Fixed
- Docker image build includes the `benches` directory.

## [0.21.1] - 2026-09-29

No user-facing changes.

## [0.21.0] - 2026-09-29

### Added
- The listen address is configurable with `TTK_LISTEN_ADDR` (default `0.0.0.0:4433`); an unparsable value fails startup.

### Changed
- The test-only `client` binary POSTs a `FafRequest` to `/faf` instead of issuing a GET, relaying to `127.0.0.1:4444` by default. Adds `--relay`, `--message` and `--key`; `--path` is removed.

## [0.20.0] - 2026-09-29

### Changed
- **BREAKING:** `parse_client_args`, `ClientTarget` and `CLIENT_USAGE` are no longer part of `ttk_server::client`; argument parsing now lives in the `client` binary.

## [0.19.0] - 2026-09-29

### Added
- `POST /faf` relay endpoint taking `FafRequest` JSON `{relay_server, message, key}`. The server connects to `relay_server` over QUIC/HTTP/3, verifies its RA-TLS attestation, and posts `{message, key}` to the relay's own `/faf`; a request without `relay_server` is the last hop and is accepted with 200. Answers 400 for an unparsable `relay_server`, 502 if the relay is unreachable, fails attestation or answers non-200, and 504 after 10 s. Relays with mock attestation are accepted only with `TTK_ALLOW_MOCK_ATTESTATION=1`.
- Request bodies are read (up to 1 MiB, else 413); previously they were discarded.
- `TtkClient::post_json`.

### Changed
- **BREAKING:** The `/hello`, `/evidence` and `/attestation` routes are removed; only `/` and `/evidence.eat` (plus `POST /faf`) are served.
- **BREAKING:** HTTP routes, `FafRequest`, `parse_relay_server` and `Evidence` moved into the new `ttk_server::router` module (`ttk_server::server::Evidence` still works).

## [0.18.1] - 2026-09-29

### Fixed
- The Dockerfile exposes the correct server port.

## [0.18.0] - 2026-09-29

### Added
- crates.io package metadata for publishing.

## [0.17.4] - 2026-09-29

No user-facing changes.

## [0.17.3] - 2026-09-29

### Changed
- The `client` is split into the `ttk_server::client` library and a test-only `client` binary that requires the new non-default `test-client` feature, so release and enclave builds no longer include it.

## [0.17.2] - 2026-09-29

No user-facing changes.

## [0.17.1] - 2026-09-29

No user-facing changes.

## [0.17.0] - 2026-09-29

### Changed
- Mock attestation documents are now signed: the `mock` provider issues a signing certificate from a published TTKServer mock root CA and signs the document with ES384, so the `client` verifies mock evidence exactly like Nitro evidence (signature, certificate chain, key binding) instead of skipping those checks. `TTK_ALLOW_MOCK_ATTESTATION=1` / `EnclaveCertVerifier::allow_mock()` now means "also trust the mock root CA".
- A client that does not allow mock evidence now explains how to opt in, instead of failing with `attestation cabundle is empty`.
- **BREAKING:** Unsigned mock documents from servers built before this change are rejected even with mock evidence allowed; rebuild and restart the server.
- **BREAKING:** The `client` rejects evidence from debug-mode TEEs (including Nitro enclaves with all-zero PCRs) unless `EnclaveCertVerifier::allow_debug` or `allow_mock` is set.
- The AWS Nitro root is pinned by its full certificate instead of its SHA-256 fingerprint.

## [0.16.0] - 2026-09-29

### Added
- The server can attest with AMD SEV-SNP (`sev-snp` feature): inside an SEV-SNP guest it obtains an attestation report through configfs-tsm (Linux 6.7+), binding the TLS key hash in `REPORT_DATA`, and embeds it with the VCEK certificate in the EAT under the `sev_snp` submodule. The VCEK comes from the certificate table the host attaches to the report, or from the file named by `TTK_SEV_SNP_VCEK` when the host supplies none. Detected automatically via `/dev/sev-guest`, or forced with `TTK_ATTESTATION=sev-snp`.

## [0.15.0] - 2026-09-29

### Added
- The server can attest with Intel TDX (`tdx` feature): inside a TDX guest it obtains a DCAP quote through the Linux configfs-tsm interface (`/sys/kernel/config/tsm/report`, Linux 6.7+), binding the TLS key hash in `REPORTDATA`, and embeds it in the EAT under the `tdx` submodule. Detected automatically via `/dev/tdx_guest`, or forced with `TTK_ATTESTATION=tdx`.

## [0.14.1] - 2026-09-29

No user-facing changes.

## [0.14.0] - 2026-09-29

No user-facing changes.

## [0.13.0] - 2026-09-29

No user-facing changes.

## [0.12.0] - 2026-09-29

### Added
- The `client` verifies AMD SEV-SNP, Intel TDX and Intel SGX evidence in addition to AWS Nitro. The server's EAT carries exactly one of the `submods` `aws_nitro`, `sev_snp` (`{report, vcek}`), `tdx` or `sgx` (DCAP quote).
  - SEV-SNP: ARK → ASK → VCEK chain against pinned Milan, Genoa and Turin roots, VCEK `hwID` and TCB matched to the report, and the report's ECDSA P-384 signature.
  - TDX and SGX: DCAP quote v3/v4/v5 with the embedded PCK chain verified against the pinned Intel SGX Root CA, the Quoting Enclave report signature and attestation-key binding, and the quote signature.
- `ttk_server::verifier` module with `verify_evidence`, `TrustStore`, `Policy` and `VerifiedEvidence`.
- `EnclaveCertVerifier::with_expected_measurement` for TEE measurements (e.g. `mrtd`, `rtmr0`, `mrenclave`, `measurement`), `allow_debug`, `with_trust_store` and `verified_evidence`.

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

[Unreleased]: https://github.com/Lanetus/TTKServer/compare/v5.0.0...HEAD
[5.0.0]: https://github.com/Lanetus/TTKServer/compare/v4.0.0...v5.0.0
[4.0.0]: https://github.com/Lanetus/TTKServer/compare/v3.0.3...v4.0.0
[3.0.3]: https://github.com/Lanetus/TTKServer/compare/v3.0.2...v3.0.3
[3.0.2]: https://github.com/Lanetus/TTKServer/compare/v3.0.1...v3.0.2
[3.0.1]: https://github.com/Lanetus/TTKServer/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/Lanetus/TTKServer/compare/v2.9.0...v3.0.0
[2.9.0]: https://github.com/Lanetus/TTKServer/compare/v2.8.0...v2.9.0
[2.8.0]: https://github.com/Lanetus/TTKServer/compare/v2.7.1...v2.8.0
[2.7.1]: https://github.com/Lanetus/TTKServer/compare/v2.7.0...v2.7.1
[2.7.0]: https://github.com/Lanetus/TTKServer/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/Lanetus/TTKServer/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/Lanetus/TTKServer/compare/v2.4.3...v2.5.0
[2.4.3]: https://github.com/Lanetus/TTKServer/compare/v2.4.2...v2.4.3
[2.4.2]: https://github.com/Lanetus/TTKServer/compare/v2.4.1...v2.4.2
[2.4.1]: https://github.com/Lanetus/TTKServer/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/Lanetus/TTKServer/compare/v2.3.5...v2.4.0
[2.3.5]: https://github.com/Lanetus/TTKServer/compare/v2.3.4...v2.3.5
[2.3.4]: https://github.com/Lanetus/TTKServer/compare/v2.3.3...v2.3.4
[2.3.3]: https://github.com/Lanetus/TTKServer/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/Lanetus/TTKServer/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/Lanetus/TTKServer/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/Lanetus/TTKServer/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/Lanetus/TTKServer/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/Lanetus/TTKServer/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/Lanetus/TTKServer/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/Lanetus/TTKServer/compare/v0.25.0...v1.0.0
[0.25.0]: https://github.com/Lanetus/TTKServer/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/Lanetus/TTKServer/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/Lanetus/TTKServer/compare/v0.22.7...v0.23.0
[0.22.7]: https://github.com/Lanetus/TTKServer/compare/v0.22.6...v0.22.7
[0.22.6]: https://github.com/Lanetus/TTKServer/compare/v0.22.5...v0.22.6
[0.22.5]: https://github.com/Lanetus/TTKServer/compare/v0.22.4...v0.22.5
[0.22.4]: https://github.com/Lanetus/TTKServer/compare/v0.22.3...v0.22.4
[0.22.3]: https://github.com/Lanetus/TTKServer/compare/v0.22.2...v0.22.3
[0.22.2]: https://github.com/Lanetus/TTKServer/compare/v0.22.1...v0.22.2
[0.22.1]: https://github.com/Lanetus/TTKServer/compare/v0.22.0...v0.22.1
[0.22.0]: https://github.com/Lanetus/TTKServer/compare/v0.21.2...v0.22.0
[0.21.2]: https://github.com/Lanetus/TTKServer/compare/v0.21.1...v0.21.2
[0.21.1]: https://github.com/Lanetus/TTKServer/compare/v0.21.0...v0.21.1
[0.21.0]: https://github.com/Lanetus/TTKServer/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/Lanetus/TTKServer/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/Lanetus/TTKServer/compare/v0.18.1...v0.19.0
[0.18.1]: https://github.com/Lanetus/TTKServer/compare/v0.18.0...v0.18.1
[0.18.0]: https://github.com/Lanetus/TTKServer/compare/v0.17.4...v0.18.0
[0.17.4]: https://github.com/Lanetus/TTKServer/compare/v0.17.3...v0.17.4
[0.17.3]: https://github.com/Lanetus/TTKServer/compare/v0.17.2...v0.17.3
[0.17.2]: https://github.com/Lanetus/TTKServer/compare/v0.17.1...v0.17.2
[0.17.1]: https://github.com/Lanetus/TTKServer/compare/v0.17.0...v0.17.1
[0.17.0]: https://github.com/Lanetus/TTKServer/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/Lanetus/TTKServer/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/Lanetus/TTKServer/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/Lanetus/TTKServer/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/Lanetus/TTKServer/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/Lanetus/TTKServer/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/Lanetus/TTKServer/compare/v0.11.1...v0.12.0
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
