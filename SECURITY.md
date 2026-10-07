# Security Policy

TTKServer is attestation and RA-TLS code: its purpose is to let a client trust that it is talking to a specific, unmodified program inside a Trusted Execution Environment (TEE). We take reports of anything that undermines that guarantee seriously.

## Supported versions

Only the latest release receives security fixes. Releases are cut automatically from `main`, so a fix ships as a new patch (or higher) version.

| Version          | Supported |
|------------------|:---------:|
| Latest `2.x`     | ✓         |
| Older releases   | ✗         |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions or pull requests.**

Report them privately through GitHub's [security advisories](https://github.com/Lanetus/TTKServer/security/advisories/new) for this repository.

Please include as much of the following as you can:

- The affected crate(s) (`ttk-core`, `ttk-ra-server`, `ttk-ra-client`, `ttk-relay`, `ttk-terminal`), version or commit, and enabled Cargo features
- The TEE involved (AWS Nitro, AMD SEV-SNP, Intel TDX / SGX, or none)
- A description of the issue and its impact: what an attacker can do, and from what position (network, parent instance, malicious host, compromised enclave, ...)
- Steps to reproduce, or a proof of concept
- Any suggested fix

We will acknowledge your report, keep you informed as we investigate, and credit you in the advisory and `CHANGELOG.md` unless you prefer to stay anonymous. Please give us a reasonable time to release a fix before disclosing the issue publicly.

## Scope

In scope — anything that breaks the attestation, confidentiality or integrity guarantees, for example:

- **Evidence appraisal** (`ttk-ra-client` verifier): accepting forged, tampered, replayed-across-keys or wrongly-chained Nitro, SEV-SNP, TDX or SGX evidence; bypassing measurement, debug or TCB policy checks.
- **Key binding**: a TLS connection being accepted whose certificate key is not the one bound in the evidence's report / user data.
- **RA-TLS and transport**: flaws in certificate generation, `EnclaveCertVerifier`, rustls / QUIC configuration, or the vsock transport and `vsock-proxy`.
- **Onion routing (`POST /faf`)**: a relay or observer learning a sealed address or message it should not, HPKE misuse, or a relay forwarding to an unattested next hop.
- **Server robustness**: crashes or resource exhaustion reachable by an unauthenticated remote peer (e.g. bypassing `MAX_REQUEST_BODY`).
- **Dependencies**: a vulnerable dependency that is actually reachable from TTKServer code.

Out of scope — known, documented limitations:

- **Mock attestation.** The `mock` provider, the TTKServer mock root CA, `TTK_ALLOW_MOCK_ATTESTATION=1` and `EnclaveCertVerifier::allow_mock()` are for development only and provide no security.
- **`EnclaveCertVerifier` skips CA validation by design.** Trust comes from the attestation evidence and its binding to the certificate key; using it outside an RA-TLS flow is a misuse.
- **No freshness.** Evidence is generated once at startup and the server takes no nonce, so evidence is not proof of liveness.
- **The attestation OID** `1.3.6.1.4.1.99999.1` is a placeholder, not a registered PEN.
- **The `client` binary** is a test tool and is never shipped in enclave images.
- **Reference values.** Choosing and distributing the expected PCRs / measurements happens outside this repository.
- **TEE hardware and firmware** vulnerabilities themselves (report those to the vendor), and attacks requiring physical access to the host.

If you are unsure whether something is in scope, please report it anyway.
