# `ttk-root` Architecture

Crate reference for `crates/root`. For the system-level picture, see the [workspace architecture](ARCHITECTURE.md#5-accepted-enclave-images-root-servers).

Other crates: [`ttk-core`](core.md) · [`ttk-ra-server`](ra-server.md) · [`ttk-ra-client`](ra-client.md) · [`ttk-relay`](relay.md) · [`ttk-storage`](storage.md) · [`ttk-executables`](executables.md)

> **Role:** an attested node that publishes the **reference values**: the image measurements of the accepted enclave images, for every TEE (Nitro PCR0, SEV-SNP `MEASUREMENT`, TDX SHA-384(`MRTD` ‖ `RTMR0..2`), SGX `MRENCLAVE`). Clients and relays fetch them over RA-TLS (so the list is bound to an attested enclave) and reject non-debug evidence from any other image. The crate also holds `auth`, a **test certificate authority** that appraises a node (startup and fresh evidence) and installs a CA-issued RA-TLS certificate for it; it is what the `certify-server` binary runs.

## 1. Files

| File | Responsibility |
|---|---|
| `crates/root/src/lib.rs` | `Root`, `FileImageTrustStore`, `run()`, `GET /root-attestation` handler |
| `crates/root/src/auth.rs` | Test CA: `CertificateAuthority`, `authorize`, `verify_fresh_evidence` |
| `crates/root/src/image_allowlist.txt` | The accepted image measurements, compiled in: one 64- or 96-hex-char digest per line, `#` comments, each labelled `# ttk-<node> v<version> <tee> <arch> <commit>`; all-zero refused |

Library only: the `root` binary (`env_logger::init()` + `ttk_root::run()`) and `certify-server` live in [`ttk-executables`](executables.md).

Dependencies: `ttk-core`, `ttk-ra-server`, and (for `auth`, which is always built) `ttk-ra-client`, `rcgen`, `rand_core`, `x509-parser`. `ttk-ra-client` in turn dev-depends on `ttk-root` for its image-fetch tests.

## 2. Public API

| Item | Kind | Description |
|---|---|---|
| `run()` | async fn | `Root::new(Server::listen(Listener::from_env()?))` then serve |
| `Root::new(server)` | fn | Wrap a `ttk-ra-server` `Server`, serving the built-in allowlist |
| `Root::with_image_trust_store(server, images)` | fn | Serve the images of any `ImageTrustStore` |
| `Root::bind(addr)` | fn | Attest and bind UDP |
| `Root::local_addr()` / `server()` / `serve()` | fn | Bound address; the wrapped `Server`; serve base routes + `GET /root-attestation` |
| `FileImageTrustStore { image_allowlist }` | struct | `ImageTrustStore` (`ImageMeasurement::Image`) from allowlist text; `parse(text)`, `builtin()` |
| `RootAttestation`, `ROOT_ATTESTATION_PATH` | re-exports | From `ttk_core::image_trust` |

## 3. `GET /root-attestation`

```json
{
  "measurements": ["915c59cef3572aaa…", "10ca146d569c40c6…"]
}
```

The response is built once at startup from the image trust store and served as JSON (`200`): lowercase hex, SHA-256 or SHA-384 digests, whatever the TEE. Clients decode it with `RootAttestation::measurement_values()`, which checks every entry; an empty list is treated as a failure.

Like every route, it answers `404` until the root node has a CA-issued certificate (and then only on connections that negotiated it). **Root nodes must therefore be authorized before the nodes and clients that fetch from them.**

```mermaid
sequenceDiagram
    participant V as Verifier (ttk-ra-client)
    participant R as Root node (authorized)
    V->>R: RA-TLS handshake (CA-issued cert), root image checked against its signer pins<br/>(RootSignerTrustStore: Nitro PCR8)
    V->>R: GET /root-attestation
    R-->>V: 200 RootAttestation JSON
    Note over V: RootImageTrustStore ← measurements
```

## 4. Releasing a new image

1. From a tagged commit, `scripts/build-eif.sh <arch> <relay|s3-server|echo>` prints the image's PCR0 (`out/ttk-<node>_v<ver>_<arch>.json`). Builds are reproducible, so anyone can rebuild the commit and get the same PCR0. Never list a `_debug` image.
2. Add it to `crates/root/src/image_allowlist.txt` with its label (`# ttk-<node> v<version> nitro <arch> <commit>`); remove images no longer deployed. Other TEEs list their own measurement (see the file header).
3. Rebuild and redeploy the root EIF (`scripts/build-eif.sh <arch> root`), signed with `TTK_EIF_SIGNING_CERT` / `TTK_EIF_SIGNING_KEY`: its PCR8 (the signing certificate's SHA-384) must be in `crates/core/src/certs/root_signer_allowlist.txt`. Deploy it with `deploy/nitro/ec2/user-data.sh` (`TTK_NODE=root`, `ttk-root-enclave.service`, CID 18).
4. After every (re)start, authorize the root node first, then the others (the RA-TLS key is ephemeral, so each start needs a new CA-issued certificate).

## 5. `auth`: the test certificate authority

```mermaid
sequenceDiagram
    autonumber
    participant CA as authorize() (CertificateAuthority)
    participant N as Node (self-signed)

    CA->>N: RA-TLS connect (EnclaveCertVerifier, images = FileImageTrustStore)
    Note over CA: certificate Evidence appraised and bound to the TLS key
    CA->>N: POST /evidence (random 32-byte nonce)
    N-->>CA: base64 CBOR FreshEvidence { evidence, certificate }
    Note over CA: verify_fresh_evidence:<br/>1. certificate == TLS handshake cert (byte for byte)<br/>2. Evidence genuine, bound to that cert's key, carries our nonce<br/>(verify_evidence_with_nonce)<br/>3. same TEE and measurements as the cert's Evidence
    Note over CA: issue(): leaf for the same SPKI,<br/>same attestation extension, same validity,<br/>SAN enclave.internal (+ CA cert unless it is a root)
    CA->>N: POST /certificate (PEM chain)
    N-->>CA: 204 → node unlocked for new connections
```

| Item | Description |
|---|---|
| `CertificateAuthority::generate(cn)` | New self-signed root CA (`CA_VALIDITY_DAYS` = 3650) |
| `CertificateAuthority::from_pem(cert, key)` | Load any CA (root or intermediate); the subject is rebuilt for `rcgen` |
| `cert_pem()` / `key_pem()` / `cert_der()` | Export |
| `issue(ra_tls_cert)` | Leaf for the node's RA-TLS key with its attestation extension, `CERT_DNS_NAME`, `ServerAuth`; chain = leaf (+ CA cert unless self-signed) |
| `authorize(addr, server_name, ca, options)` | The full flow above; returns the installed chain |
| `AuthorizeOptions { allow_mock, images }` | Mock attestation (dev only); accepted images (default `FileImageTrustStore::builtin()`) |
| `verify_fresh_evidence(cmw, nonce, ra_tls_cert, cert_evidence, images, policy)` | The three checks above. The nonce is in the Nitro (and mock) document's `nonce` field, or hashed into the second half of the TDX / SEV-SNP report data, so nodes on any of these TEEs can be authorized |
| `pem(chain)` | PEM encoding |
| `EVIDENCE_PATH` / `CERTIFICATE_PATH` / `NONCE_LEN` / `DEFAULT_CA_NAME` | `"/evidence"` / `"/certificate"` / `32` / `"TTK auth-test CA"` |

Nodes trust only the built-in TTK root CA (`ttk_core::TTK_ROOT_CA_PEM`), so in practice `authorize` must run with that CA's key (or an intermediate it issued); a freshly generated CA is refused (`403`) by real nodes and only works against test nodes that call `Server::set_trusted_roots`.

## 6. Configuration, features and tests

| Variable | Default | Effect |
|---|---|---|
| `TTK_USE_UDP` / `TTK_LISTEN_ADDR` / `TTK_VSOCK_PORT` | vsock `5000` | Listener |
| `TTK_ATTESTATION` | auto-detect | Force a provider |

Features forward to `ttk-ra-server`. The root node makes no outbound connections. Local run: `TTK_USE_UDP=1 TTK_LISTEN_ADDR=127.0.0.1:4455 cargo run --bin root`.

| File | Covers |
|---|---|
| `crates/root/tests/root_tests.rs` | Built-in and custom allowlists served as `{measurements}`, base routes, built-in allowlist valid (minimal h3 client, no RA-TLS verification) |
| `crates/root/tests/auth_tests.rs` | Issuing certificates for RA-TLS keys (root and intermediate CAs), appraising fresh Evidence (wrong cert, nonce, measurements), end-to-end `POST /evidence` + `POST /certificate` against a root node with mock attestation |
| `crates/ra-client/tests/images_tests.rs` | The client side: fetching from local root nodes, fallback, failure, root attestation |
