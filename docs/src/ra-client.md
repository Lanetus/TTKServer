# `ttk-ra-client` Architecture

Crate reference for `crates/ra-client`. For the system-level picture, see the [workspace architecture](ARCHITECTURE.md).

Other crates: [`ttk-core`](core.md) · [`ttk-ra-server`](ra-server.md) · [`ttk-relay`](relay.md) · [`ttk-terminal`](terminal.md) · [`ttk-root`](root.md)

> **Role:** the RATS **Verifier / Relying Party**. Connects to nodes over HTTP/3, verifies their evidence during the TLS handshake (including the enclave image, against the list fetched from the root servers), and builds and seals `/faf` requests. Relay and terminal reuse it. Depends on `ttk-core`, never on `ttk-ra-server`.

## 1. Modules

```mermaid
flowchart LR
    lib["lib.rs"]
    client["client.rs<br/>TtkClient,<br/>EnclaveCertVerifier"]
    subgraph ver["verifier/"]
        vmod["mod.rs<br/>verify_evidence,<br/>TeeKind, Policy"]
        vn["nitro.rs"]
        vs["sev_snp.rs"]
        vd["dcap.rs<br/>(TDX + SGX)"]
    end
    subgraph tr["trust/"]
        tmod["mod.rs<br/>TrustStore,<br/>RootSignerTrustStore"]
        certs["certs/*.der<br/>pinned roots"]
        pcr8["root_signer_pcr8.txt"]
    end
    images["images.rs<br/>RootImageTrustStore"]
    faf["faf.rs<br/>FafRequest, connect_to_node"]
    seal["seal.rs<br/>HPKE + AES-GCM"]
    main["main.rs<br/>bin client"]

    lib --> client & faf & seal & ver & tr & images
    client --> vmod
    client --> images
    vmod --> vn & vs & vd
    vmod --> tmod
    tmod --> certs & pcr8
    images --> faf
    images --> tmod
    faf --> client
    main --> client & faf & seal
```

| File | Responsibility |
|---|---|
| `crates/ra-client/src/lib.rs` | Declares modules; re-exports `client.rs` at the crate root, plus `RootImageTrustStore`, `ImageTrustStore`, `TrustStore` |
| `crates/ra-client/src/client.rs` | `TtkClient`, `ClientTransport`, `ClientResponse`, `EnclaveCertVerifier`, `extract_attestation_doc`, `hex_encode`, response limits |
| `crates/ra-client/src/verifier/mod.rs` | `verify_evidence` (CMW dispatch), `VerifiedEvidence`, `TeeKind`, `Policy`, `is_bound_to` |
| `crates/ra-client/src/verifier/nitro.rs` | NSM document: COSE_Sign1 (ES384), cert chain to AWS Nitro root, image allowlist |
| `crates/ra-client/src/verifier/sev_snp.rs` | SEV-SNP: ARK → ASK → VCEK chain, VCEK/report match, report signature |
| `crates/ra-client/src/verifier/dcap.rs` | TDX/SGX DCAP quote: PCK chain to Intel root, QE report, quote signature |
| `crates/ra-client/src/trust/mod.rs` | `TrustStore`, `AmdRoots`/`AmdProduct`, `RootSignerTrustStore`; re-exports `ImageTrustStore`, `parse_image_allowlist`. Data only |
| `crates/ra-client/src/trust/certs` | Pinned roots: AWS Nitro G1, Intel SGX Root CA, AMD Milan/Genoa/Turin ARK+ASK (mock root from `ttk-core`) |
| `crates/ra-client/src/trust/root_signer_pcr8.txt` | PCR8 pins for the root servers (empty: no genuine root accepted yet) |
| `crates/ra-client/src/images.rs` | `RootImageTrustStore`: fetching `GET /root-attestation` from `ROOT_SERVERS`; lazy process-wide cache |
| `crates/ra-client/src/faf.rs` | `/faf` JSON types, relay-address parsing, `connect_to_node(_filtered)` |
| `crates/ra-client/src/seal.rs` | Onion encryption to a node's RA-TLS key; sealed terminal reply |
| `crates/ra-client/src/main.rs` | Test-only `client` binary |

## 2. `TtkClient`

| Method | Description |
|---|---|
| `connect(addr, sni)` | Connect with the default strict verifier |
| `connect_with_verifier(addr, sni, verifier)` | Connect with a custom `EnclaveCertVerifier` |
| `connect_over(transport, addr, sni, verifier)` | Same, over `ClientTransport::Udp` or `Vsock { cid, port }` |
| `get(path)` / `post(path, body)` / `post_json(path, &T)` / `send(...)` | HTTP/3 requests; each is its own stream, so one client can be shared via `Arc`. Responses over `MAX_RESPONSE_BODY` (1 MiB) fail; headers capped at `MAX_RESPONSE_HEADERS` (16 KiB) |
| `server_addr()` / `server_name()` | Connection target |
| `peer_cert()` / `peer_cert_sha256()` / `peer_cert_sha256_hex()` | The attested certificate |
| `is_closed()` | `true` after idle timeout or peer close |
| `close()` | Graceful shutdown |

## 3. `EnclaveCertVerifier`

A rustls `ServerCertVerifier` that replaces CA validation with attestation checks.

| Builder | Effect |
|---|---|
| `new()` | Strict: genuine TEE only, no debug, built-in roots, accepted images from the root servers (fetched on first need) |
| `with_expected_measurement(name, value)` | Pin a measurement (e.g. `pcr0`, `measurement`, `mrtd`) |
| `with_expected_pcr(index, value)` | Shortcut for `pcr{index}` |
| `with_trust_store(store)` | Custom vendor roots |
| `with_image_trust_store(images)` / `with_shared_image_trust_store(arc)` | Replace the fetched image list (tests, private deployments, root-server attestation) |
| `allow_mock()` | Trust the mock root (implies `allow_debug`). Dev only |
| `allow_debug()` | Accept debug-mode TEEs |
| `received_certificate()` / `verified_evidence()` / `verified_attestation()` | Results after a handshake |

```mermaid
flowchart TD
    A["Leaf cert from handshake"] --> B{"Validity + self-signature OK?"}
    B -- no --> X["Handshake fails"]
    B -- yes --> C["extract_attestation_doc() → CMW bytes"]
    C --> D["verify_evidence()<br/>TeeKind::from_cmw (type only)"]
    D --> E{"Vendor chain to TrustStore root?"}
    E -- no --> X
    E -- yes --> I{"Nitro, non-debug:<br/>PCR in ImageTrustStore?"}
    I -- no --> X
    I -- yes --> F{"Debug TEE and not allowed?"}
    F -- yes --> X
    F -- no --> G{"report_data == SHA-256(cert SPKI)?"}
    G -- no --> X
    G -- yes --> H{"Expected measurements match?"}
    H -- no --> X
    H -- yes --> OK["Verified. Evidence and cert recorded."]
```

## 4. Evidence verifiers

| TEE | Module | Checks | Not checked |
|---|---|---|---|
| AWS Nitro | `verifier::nitro` | COSE_Sign1 ES384 signature, `cabundle` chain to AWS Nitro root (or mock root if allowed), timestamp ≤ now + 5 min, PCR0 (or PCR`nitro_pcr_index`) in the image allowlist unless debug; debug = all-zero PCR0 | — |
| AMD SEV-SNP | `verifier::sev_snp` | ARK → ASK → VCEK (RSA-PSS), VCEK validity, VCEK `hwID`/TCB match report, report ECDSA P-384 signature | VLEK-signed reports, CRLs |
| Intel TDX / SGX | `verifier::dcap` | PCK chain to Intel SGX Root CA, QE report signed by PCK and not debug, QE binds the attestation key, quote signature | TCB status, QE identity, PCK CRLs |

`verify_evidence(cmw, binding, now, trust, images, policy)` returns `VerifiedEvidence { tee, report_data, measurements, debug, nitro }`.

| TEE | Measurement names |
|---|---|
| Nitro | `pcr0` … `pcrN` |
| SEV-SNP | `measurement`, `host_data`, `id_key_digest`, `author_key_digest` |
| TDX | `mrtd`, `rtmr0`–`rtmr3`, `mrseam`, `mrconfigid`, `mrowner`, `mrownerconfig` |
| SGX | `mrenclave`, `mrsigner` |

## 5. Trust stores and accepted images

| Item | Module | Description |
|---|---|---|
| `TrustStore { aws_nitro_root, mock_nitro_root, intel_sgx_root, amd }` | `trust` | Vendor roots; `builtin()` / `Default` |
| `AmdRoots { product, ark, ask }`, `AmdProduct` | `trust` | Milan, Genoa, Turin |
| `RootSignerTrustStore { pcr8_allowlist }` | `trust` | `ImageTrustStore` for the root servers: PCR8 from `root_signer_pcr8.txt` |
| `RootImageTrustStore { nitro_image_allowlist }` | `images` | `ImageTrustStore` with the PCR0 list fetched from the root servers |
| `RootImageTrustStore::fetch(roots, transport, verifier)` | `images` | First root that answers, `ROOT_FETCH_TIMEOUT` (10 s) each; empty list is an error |
| `RootImageTrustStore::fetch_builtin(transport)` | `images` | `ROOT_SERVERS`, attested against `RootSignerTrustStore` |
| `RootImageTrustStore::builtin()` | `images` | Blocking fetch on its own thread (safe inside Tokio); **fails closed** to an empty list |
| `set_root_transport(transport)` | `images` | Process-wide transport for `builtin()` (relay sets vsock) |
| `ROOT_SERVERS` | `images` | `a.ttk-server.net:443`, `b.ttk-server.net:443` |
| `ROOT_FETCH_RETRY_INTERVAL` | `images` | 60 s before a failed fetch is retried |

A verifier built without `with_image_trust_store` uses a lazy handle: the process-wide list is fetched only the first time an allowlist is actually needed (non-debug Nitro evidence), then shared by every verifier.

## 6. `faf` and `seal`

| Item | Module | Description |
|---|---|---|
| `FafRequest { relays, body }` | `faf` | The `POST /faf` JSON body |
| `FafRelay { address, encrypted }` | `faf` | One hop: `"<server> <salt>"`, plaintext or sealed |
| `FafBody { key, message }` | `faf` | Sealed message key and AES-GCM ciphertext |
| `FAF_PATH` / `DEFAULT_RELAY_PORT` | `faf` | `"/faf"` / `4433` |
| `RELAY_CONNECT_TIMEOUT` | `faf` | 3 s per resolved address |
| `parse_relay_address(addr, salt_required)` | `faf` | Strip and validate the 10-digit salt |
| `parse_relay_server(server)` | `faf` | `host[:port]` / `https://host[:port]` → `(host, port)`; rejects other schemes and user info |
| `connect_to_node(transport, host, port, verifier)` | `faf` | Resolve, try each address until one attests |
| `connect_to_node_filtered(..., allow)` | `faf` | Same, skipping addresses `allow` refuses (relay egress policy) |
| `classify_hop_address`, `HopAddressClass` | `faf` | Re-exported from `ttk_core::egress` |
| `NodePublicKey::from_certificate(der)` / `from_sec1_bytes` | `seal` | Encryption key from an attested node's cert |
| `NodeSecretKey::from_pkcs8_der(der)` / `public_key()` | `seal` | A node's own key, for opening |
| `seal_address` / `open_address` | `seal` | HPKE seal of `"<server> <salt>"` to the reading node |
| `seal_body` / `open_body` | `seal` | Fresh AES-256-GCM message key; key HPKE-sealed to the terminal |
| `seal_body_with_key` / `open_body_with_key` | `seal` | Same, also returning the `MessageKey` |
| `seal_response` / `open_response` | `seal` | Terminal's reply under the message key |
| `random_salt()` / `SALT_DIGITS` | `seal` | 10 random decimal digits |
| `SealError` | `seal` | Intentionally vague on open (no decryption oracle) |

## 7. `client` binary (test only)

Never included in enclave images. Routes a message through two relays to a terminal.

```mermaid
sequenceDiagram
    autonumber
    participant CLI as client
    participant R1 as Entry relay (--addr)
    participant R2 as Second relay (--relay)
    participant T as Terminal (--terminal)

    CLI->>R1: connect_with_verifier (RA-TLS)
    CLI->>R2: connect_to_node (RA-TLS), read cert key, close
    CLI->>T: connect_to_node (RA-TLS), read cert key, close
    Note over CLI: seal_body_with_key(T, --message)<br/>seal_address(R2, T)
    CLI->>R1: POST /faf { relays: [R2 (plain), T (sealed to R2)], body }
    R1-->>CLI: 200 sealed reply
    Note over CLI: open_response → hello: + message
```

| Flag | Env | Default |
|---|---|---|
| `-a, --addr` (or positional URL) | `TTK_SERVER_ADDR` | `127.0.0.1:4433` (entry relay) |
| `-s, --server-name` | `TTK_SERVER_NAME` | `localhost` |
| `-r, --relay` | — | `127.0.0.1:4434` (second relay) |
| `-t, --terminal` | — | `127.0.0.1:4444` (terminal) |
| `-m, --message` | — | `hello` |
| — | `TTK_ALLOW_MOCK_ATTESTATION=1` | strict |

## 8. Features and tests

No features of its own. Tests dev-depend on `ttk-ra-server` (with `mock`, `sev-snp`, `tdx`), `ttk-relay`, `ttk-terminal` and `ttk-root`. In tests, don't pass `ttk_ra_client` types into relay/terminal APIs (the dev-dependency cycle makes them distinct types); use `Relay::allow_mock()`, not `with_verifier`.

| File | Covers |
|---|---|
| `crates/ra-client/tests/client_tests.rs` | Helpers, `EnclaveCertVerifier` against mock evidence (binding, PCRs, validity, missing extension, TLS 1.2/1.3 signatures) |
| `crates/ra-client/tests/client_e2e_tests.rs` | `TtkClient` against an in-process `ttk-ra-server` server |
| `crates/ra-client/tests/client_bin_tests.rs` | The `client` binary against real relay and terminal nodes |
| `crates/ra-client/tests/verifier_tests.rs` | Evidence verification with real vendor fixtures and synthetic PKIs |
| `crates/ra-client/tests/images_tests.rs` | Fetching accepted images from local root nodes: success, fallback, failure, root attestation |
| `crates/ra-client/tests/faf_tests.rs` | `/faf` format and sealing |
| `crates/ra-client/tests/sev_snp_provider_tests.rs` | Server SEV-SNP provider against emulated configfs-tsm |
| `crates/ra-client/tests/tdx_provider_tests.rs` | Server TDX provider against emulated configfs-tsm |
