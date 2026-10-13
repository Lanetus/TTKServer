# TTKServer Architecture

TTKServer is a Rust **HTTP/3 (QUIC) server that runs inside a Trusted Execution Environment** (primarily an AWS Nitro Enclave). Every node proves what code it runs through **remote attestation**, and clients only talk to nodes whose proof checks out.

Three node types are built on the attested server:

- **Relay**: forwards an onion-routed message one hop closer to its destination.
- **Terminal**: the last hop. It is the only node that can decrypt the message; an *evaluator* turns it into a reply only the sender can read. The deployed terminal is `s3-server`, a **file service** storing files in Amazon S3.
- **Root**: publishes the checksums (PCR0) of the accepted enclave images, which clients and relays check every other node against.

A node starts with a self-signed RA-TLS certificate and serves only its bootstrap routes. A **certificate authority** first appraises it (including fresh evidence) and installs a CA-issued certificate for the same attested key; only then does the node serve anything else.

> **In one sentence:** a CA authorizes each attested node; a client attests the nodes, encrypts a message so only the terminal can read it, and sends it through attested relays over HTTP/3. Which enclave images count as "attested" comes from the root servers.

---

## Contents

1. [Big picture](#1-big-picture)
2. [Workspace layout](#2-workspace-layout)
3. [Remote attestation (RA-TLS)](#3-remote-attestation-ra-tls)
4. [Node authorization (CA-issued certificate)](#4-node-authorization-ca-issued-certificate)
5. [Accepted enclave images (root servers)](#5-accepted-enclave-images-root-servers)
6. [Onion-routed messages (`POST /faf`)](#6-onion-routed-messages-post-faf)
7. [The file service (terminal)](#7-the-file-service-terminal)
8. [Networking inside an enclave (vsock)](#8-networking-inside-an-enclave-vsock)
9. [Deployment](#9-deployment)
10. [Configuration reference](#10-configuration-reference)
11. [Security model](#11-security-model)

---

## 1. Big picture

```mermaid
flowchart LR
    C["Client<br/>(client / client-m)"]
    CA["CA<br/>(certify-server,<br/>TTK root CA key)"]

    subgraph ROOTS["Root servers (a / b.ttk-server.net:443)"]
        RT["Root node<br/>(ttk-root)<br/>GET /root-attestation"]
    end

    subgraph EC2A["EC2 parent A"]
        PA["vsock-proxy"]
        subgraph ENA["Nitro Enclave"]
            R1["Entry relay<br/>(ttk-relay)"]
        end
    end

    subgraph EC2B["EC2 parent B"]
        PB["vsock-proxy"]
        subgraph ENB["Nitro Enclave"]
            R2["Second relay<br/>(ttk-relay)"]
        end
    end

    subgraph EC2C["EC2 parent C"]
        PC["vsock-proxy"]
        PT["vsock-proxy-tcp<br/>+ vsock-proxy-imds"]
        subgraph ENC["Nitro Enclave"]
            T["Terminal: s3-server<br/>(Terminal + FileService)"]
        end
    end

    S3[("Amazon S3")]

    C -- "QUIC / HTTP/3, RA-TLS" --> PA
    PA -- "vsock 5000" --> R1
    R1 -- "vsock 5001 (outbound)" --> PA
    PA -- "RA-TLS" --> PB
    PB -- "vsock 5000" --> R2
    R2 -- "vsock 5001" --> PB
    PB -- "RA-TLS" --> PC
    PC -- "vsock 5000" --> T
    T -- "vsock 8001 / 8002 (TCP)" --> PT
    PT -- "HTTPS (TLS from the enclave)" --> S3

    C -. "image allowlist (PCR0)" .-> RT
    R1 -. "image allowlist (PCR0)" .-> RT
    R2 -. "image allowlist (PCR0)" .-> RT
    CA == "POST /evidence + POST /certificate<br/>(once per node start)" ==> RT & R1 & R2 & T
```

TLS ends **inside** each enclave. The parent instances and their proxies only move encrypted QUIC datagrams (and, for S3, TLS bytes), so they never see plaintext and cannot impersonate a node.

### Roles (RFC 9334 RATS)

| RATS role | Who plays it in TTKServer |
|---|---|
| **Attester** | Every node (relay, terminal, root), running inside the TEE |
| **Evidence** | The TEE's evidence (e.g. Nitro NSM attestation document), wrapped in a RATS **CMW** (Conceptual Message Wrapper, `draft-ietf-rats-msg-wrap`) |
| **Endorsements** | The vendor certificate chain inside the evidence (AWS Nitro root, Intel PCK chain, AMD VCEK) |
| **Verifier** | `EnclaveCertVerifier` in `ttk-ra-client`, used by the clients, by relays, and by the CA (`ttk_root::auth`) |
| **Relying Party** | The client; each relay when it picks its next hop; the CA before it issues a certificate |
| **Reference values** | The accepted enclave images (Nitro PCR0), published by the root nodes; the root nodes themselves are pinned by PCR8 (their signing certificate). Callers may pin further measurements. |

---

## 2. Workspace layout

```mermaid
flowchart TB
    core["<b>ttk-core</b><br/>CMW, media types, FreshEvidence, image trust,<br/>/faf format + HPKE sealing, file messages,<br/>egress policy, vsock, proxy configs"]
    server["<b>ttk-ra-server</b><br/>attested HTTP/3 server, cert replacement,<br/>route gating, Terminal + Evaluator"]
    client["<b>ttk-ra-client</b><br/>RA-TLS client, verifier,<br/>root image fetch, /faf routing"]
    relay["<b>ttk-relay</b><br/>Relay"]
    root["<b>ttk-root</b><br/>Root, auth (test CA)"]
    storage["<b>ttk-storage</b><br/>FileService, BlobStore,<br/>MemoryStore, S3Store"]
    exe["<b>ttk-executables</b><br/>every binary"]

    server --> core
    client --> core
    relay --> server
    relay --> client
    root --> server
    root --> client
    root --> core
    storage --> server
    storage --> core
    exe --> relay & root & storage & server & client & core
    client -. "dev-dependency (tests)" .-> server
    client -. "dev-dependency (tests)" .-> relay
    client -. "dev-dependency (tests)" .-> storage
    client -. "dev-dependency (tests)" .-> root
```

`ttk-core` holds what the server and the client share, so `ttk-ra-client` does not depend on `ttk-ra-server` (only its tests do), and `ttk-ra-server` does not depend on `ttk-ra-client` (its terminal takes the `/faf` format and sealing from `ttk-core`). All binaries live in `ttk-executables`; the other crates are libraries only.

| Crate | Responsibility | Key items |
|---|---|---|
| [`ttk-core`](core.md) (`crates/core`) | Shared formats and transport: CMW, media types, RA-TLS constants, TTK root CA, fresh-evidence format, image-trust format, `/faf` format and onion sealing, file service messages, egress policy, vsock sockets, proxy configuration | `Cmw`, `media_type`, `ATTESTATION_OID`, `TTK_ROOT_CA_PEM`, `FreshEvidence`, `ImageTrustStore`, `FafRequest`, `seal::*`, `FileRequest`, `classify_hop_address`, `vsock` |
| [`ttk-ra-server`](ra-server.md) (`crates/ra-server`) | Attestation providers, RA-TLS certificate and its one-time replacement, QUIC/HTTP/3 accept loop, base routes and route gating, the terminal node | `Server`, `Listener`, `CertificateStore`, `CertificatePhase`, `Terminal`, `Evaluator`, `attestation::detect` |
| [`ttk-ra-client`](ra-client.md) (`crates/ra-client`) | Connecting to nodes, verifying evidence, accepted images from the root servers, `/faf` route connection | `TtkClient`, `EnclaveCertVerifier`, `TrustStore`, `RootImageTrustStore`, `connect_to_node` |
| [`ttk-relay`](relay.md) (`crates/relay`) | Forwards `/faf` to the next attested hop, with a connection pool and an egress policy | `Relay`, `run()`, `MAX_RELAYS`, `MAX_POOLED_RELAYS`, `RELAY_TIMEOUT` |
| [`ttk-root`](root.md) (`crates/root`) | Publishes the accepted enclave images at `GET /root-attestation`; test CA that authorizes nodes | `Root`, `FileImageTrustStore`, `auth::{CertificateAuthority, authorize}` |
| [`ttk-storage`](storage.md) (`crates/storage`) | The terminal's file service evaluator and its blob stores | `FileService`, `BlobStore`, `MemoryStore`, `S3Store` |
| [`ttk-executables`](executables.md) (`crates/executables`) | Every binary, plus the shared `faf_client` | `faf_client::send`, bins below |

| | `ttk-ra-server` | `ttk-ra-client` | `ttk-relay` | Terminal (`Terminal` + `ttk-storage`) | `ttk-root` |
|---|---|---|---|---|---|
| RATS role | Attester | Verifier / Relying Party | Attester + Relying Party | Attester | Attester (+ reference-value provider) |
| Runs in TEE | yes (as a library) | no (library also used inside relays) | yes | yes | yes |
| Routes (after authorization) | `GET /`, `GET /evidence.cmw` | — | + `POST /faf` (forward) | + `POST /faf` (deliver) | + `GET /root-attestation` |
| Bootstrap routes (before) | `POST /evidence`, `POST /certificate` | — | same | same | same |
| Uses its RA-TLS private key for | TLS | — | TLS + `open_address` | TLS + `open_body` | TLS |
| Outbound connections | — | yes | yes (pooled, attested, egress-filtered) + root servers | `s3-server`: S3 + instance metadata, over vsock TCP | — |
| Cargo features | `nitro`, `mock`, `sev-snp`, `tdx` | — | forwards ra-server's | forwards ra-server's (+ `s3`) | forwards ra-server's |

### Binaries (`ttk-executables`)

| Binary | Runs where | Purpose |
|---|---|---|
| `relay` | Inside the enclave | Relay node |
| `s3-server` | Inside the enclave | Terminal node: file service on S3 (feature `s3`) |
| `root` | Inside the enclave | Root node (accepted images) |
| `local-mem-server` | Dev machine / tests | Terminal node: file service in memory |
| `echo` | Dev machine / tests | Terminal node replying with the message itself |
| `vsock-proxy` | Parent EC2 instance (Linux) | Bridges UDP ↔ vsock, both directions, with an egress policy |
| `vsock-proxy-tcp` | Parent EC2 instance (Linux) | Enclave vsock → one fixed TCP remote (S3; with `--allow-imds`, the instance metadata service) |
| `client` | Dev machine / tests only | Uploads / downloads a file through two relays to a file service terminal |
| `client-m` | Dev machine / tests only | Sends a text message through two relays (e.g. to `echo`) |
| `certify-server` | Dev machine / tests only | Test CA: authorizes a node (fresh evidence + CA-issued certificate) |

### Cargo features (`ttk-ra-server`)

| Feature | Default | Provider | Hardware |
|---|:---:|---|---|
| `nitro` | ✅ | `aws-nitro` | AWS Nitro Enclaves (`/dev/nsm`) |
| `mock` | ✅ | `mock` | None. Fallback when no TEE is found; **not trustworthy** |
| `sev-snp` | — | `sev-snp` | AMD SEV-SNP (via configfs-tsm) |
| `tdx` | — | `tdx` | Intel TDX (via configfs-tsm) |

All features are additive. `ttk-relay`, `ttk-storage`, `ttk-root` and `ttk-executables` forward them; `ttk-storage` and `ttk-executables` add `s3`. `ttk-core` and `ttk-ra-client` have no features.

---

## 3. Remote attestation (RA-TLS)

### 3.1 What a node does at startup

Evidence is generated **once, at startup**, and bound to a fresh TLS key.

```mermaid
flowchart TD
    A["Generate ephemeral<br/>ECDSA P-256 key pair"] --> B["user_data = SHA-256(public key SPKI)"]
    B --> C["attestation::detect()<br/>pick provider (Nitro, SEV-SNP, TDX, mock)"]
    C --> D["provider.generate_document()<br/>evidence wrapped in a CMW"]
    D --> E["CBOR-encode the CMW"]
    E --> F["Self-signed X.509 cert (30 days, SAN enclave.internal)<br/>+ extension OID 1.3.6.1.4.1.99999.1 = CMW"]
    F --> G["CertificateStore (replaceable chain)<br/>trusted roots = built-in TTK root CA"]
    G --> H["QUIC server config<br/>ALPN h3, per-connection limits"]
    H --> I["Serve HTTP/3<br/>(bootstrap routes only until authorized)"]
```

| Step | Code |
|---|---|
| Key generation, key binding, evidence request | `crates/ra-server/src/server.rs` (`attest`, `key_binding`) |
| Provider selection (`TTK_ATTESTATION` overrides probing) | `crates/ra-server/src/attestation/mod.rs` (`detect`, `by_name`) |
| CMW wrapping | `nitro_doc::wrap_as_cmw`, `sev_snp::wrap_evidence_as_cmw`, `tdx::wrap_quote_as_cmw`; encoding in `crates/core/src/cmw.rs` |
| Certificate with evidence extension | `crates/ra-server/src/server.rs` (`create_cert_with_attestation`) |
| Presented chain, trusted roots | `crates/ra-server/src/certificate.rs` (`CertificateStore`) |

### 3.2 The CMW envelope

The evidence is wrapped, verbatim, in a CBOR **Conceptual Message Wrapper**: either a record `[type, value, ind]` or a collection `{ "__cmwc_t": type, label: CMW, ... }`. The wrapper is **unsigned** and adds no claims: trust comes only from the wrapped TEE evidence. The verifier picks the TEE from the CMW type alone (`TeeKind::from_cmw`).

| CMW | Type (`ttk_core::media_type`) | TEE | Evidence | Verified by |
|---|---|---|---|---|
| record, `ind` = Evidence | `application/vnd.ttk.aws-nitro-attestation-document` | AWS Nitro | NSM document (COSE_Sign1) | `verifier::nitro` |
| collection | `tag:lanetus.github.io,2026:sev-snp-evidence` with `report` (`application/vnd.ttk.amd-sev-snp-report`, Evidence) + `vcek` (`application/pkix-cert`, Endorsement) | AMD SEV-SNP | report + VCEK | `verifier::sev_snp` |
| record | `application/vnd.ttk.intel-tdx-quote` | Intel TDX | DCAP quote v4/v5 | `verifier::dcap` |
| record | `application/vnd.ttk.intel-sgx-quote` | Intel SGX | DCAP quote v3/v4/v5 | `verifier::dcap` |
| collection | `tag:lanetus.github.io,2026:fresh-evidence` with `evidence` (one of the above) + `certificate` (`application/pkix-cert`) | any | `POST /evidence` response ([3.4](#34-freshness-post-evidence)) | `ttk_root::auth::verify_fresh_evidence` |

The `vnd.ttk.*` media types and the collection tag URIs are this project's own; none are IANA-registered.

### 3.3 How a client verifies a node

Verification happens **during the TLS handshake**, inside `EnclaveCertVerifier` (a rustls `ServerCertVerifier`). No CA is trusted by the client: the node is trusted because of its attestation, whether it presents its self-signed certificate or the CA-issued one (same key, same evidence extension).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (EnclaveCertVerifier)
    participant N as Node (in TEE)

    C->>N: QUIC handshake (ALPN h3)
    N-->>C: RA-TLS cert (self-signed or CA-issued) carrying the CMW extension
    Note over C: 1. Cert is in its validity window,<br/>if self-issued, correctly self-signed (CA signature not checked)
    Note over C: 2. Decode CMW, verify the vendor signature chain<br/>up to a root in the TrustStore
    Note over C: 3. Nitro: image PCR0 is in the accepted-images list<br/>(fetched from the root servers)
    Note over C: 4. Policy: no debug / no mock unless allowed
    Note over C: 5. Evidence report data == SHA-256(cert public key)
    Note over C: 6. Expected measurements (if pinned)
    C->>N: Handshake completes (TLS signature checked with the attested key)
```

| Check | Fails if… |
|---|---|
| Certificate validity (and self-signature if self-issued) | Expired, not yet valid, or bad self-signature |
| CMW | Not CBOR, unknown type, wrong form, or a record not marked as Evidence |
| Vendor chain | Evidence not signed by a trusted root (AWS Nitro G1, Intel SGX Root CA, AMD Milan/Genoa/Turin ARK+ASK); Nitro document timestamp more than 5 min in the future |
| Accepted image (Nitro, non-debug) | PCR0 not in the `ImageTrustStore` (see [section 5](#5-accepted-enclave-images-root-servers)) |
| Policy | TEE in debug mode, or mock evidence, unless `allow_debug` / `allow_mock` |
| Key binding | Evidence `user_data` / `REPORT_DATA` is not the cert's public key hash (zero-padded) |
| Reference values | A measurement set with `with_expected_measurement` / `with_expected_pcr` differs or is missing |

### 3.4 Freshness: `POST /evidence`

The certificate and `GET /evidence.cmw` carry the startup evidence, which has no nonce. A Verifier that needs freshness (RFC 9334 §10) posts a nonce. It is a **bootstrap** route: served only while the certificate is self-signed (see [section 4](#4-node-authorization-ca-issued-certificate)).

```mermaid
sequenceDiagram
    participant V as Verifier
    participant N as Node
    V->>N: POST /evidence (body = raw nonce, 1..512 bytes)
    Note over N: provider.generate_document(user_data = SHA-256(cert SPKI), nonce)<br/>(at most 4 at once)
    N-->>V: 200 base64 CBOR FreshEvidence { evidence, certificate }
    Note over V: certificate == the one from my handshake?<br/>evidence genuine, bound to its key, carries my nonce?
```

The response is a `FreshEvidence` CMW collection: the new Evidence (bound to the RA-TLS key like the startup Evidence, with the nonce in the Nitro document's `nonce` field) and the DER certificate the node currently presents. Since the wrapper is unsigned, the Verifier compares that certificate with the one from its own TLS handshake.

| Status | When |
|---|---|
| `200` | `FreshEvidence`, nonce in the attestation document's `nonce` field |
| `400` | Empty nonce, or longer than `MAX_NONCE_LEN` (512) |
| `404` | Certificate already replaced (bootstrap route locked) |
| `503` | `MAX_CONCURRENT_ATTESTATIONS` (4) already in progress |
| `500` | Generation failed; TDX and SEV-SNP always (they can't carry a separate nonce) |

### 3.5 HTTP routes and server limits

| Route | Served by | Served when | Response |
|---|---|---|---|
| `POST /evidence` | all nodes | self-signed | Fresh `FreshEvidence` with the body as nonce |
| `POST /certificate` | all nodes | self-signed | Install a CA-issued certificate (`204`) |
| `GET /` | all nodes | CA-issued | Greeting text |
| `GET /evidence.cmw` | all nodes | CA-issued | Base64 CBOR CMW (same bytes as in the cert) |
| `POST /faf` | relay | CA-issued | Forward to the next hop |
| `POST /faf` | terminal | CA-issued | Decrypt the body (last hop), answer the evaluator's sealed reply |
| `GET /root-attestation` | root | CA-issued | JSON list of accepted image PCR0s |

A route that is not served answers `404` for every method.

| Limit (`ttk_ra_server::server`) | Value | Effect |
|---|---|---|
| `MAX_REQUEST_BODY` | 1 MiB | Larger bodies get `413` |
| `REQUEST_BODY_TIMEOUT` | 10 s | Slower bodies get `408` |
| `MAX_REQUEST_HEADERS` | 16 KiB | HTTP/3 `SETTINGS_MAX_FIELD_SECTION_SIZE` |
| `MAX_CONNECTIONS` | 1024 | Further QUIC connections are refused |
| `MAX_STREAMS_PER_CONNECTION` | 16 | Concurrent requests per connection |
| `CONNECTION_RECEIVE_WINDOW` | 4 MiB | Request data one connection can have buffered |

---

## 4. Node authorization (CA-issued certificate)

Attestation proves *what* runs in a node; authorization decides that it may serve. A freshly started node presents its self-signed RA-TLS certificate and serves only `POST /evidence` and `POST /certificate`. A certificate authority appraises it and installs a certificate it issues for the **same key and the same evidence extension**; from then on the node serves its routes.

```mermaid
sequenceDiagram
    autonumber
    participant CA as CA (certify-server → ttk_root::auth::authorize)
    participant N as Node (self-signed)

    CA->>N: RA-TLS connect: startup Evidence appraised, bound to the TLS key
    CA->>N: POST /evidence (random 32-byte nonce)
    N-->>CA: FreshEvidence { evidence, certificate }
    Note over CA: certificate == handshake cert (byte for byte)<br/>evidence genuine + bound to its key + carries the nonce<br/>same TEE + measurements as the cert's Evidence
    Note over CA: issue: same SPKI, same attestation extension,<br/>same validity, SAN enclave.internal
    CA->>N: POST /certificate (PEM chain, leaf first)
    Note over N: same SPKI + extension? chains to TTK root CA?<br/>valid, names enclave.internal? first replacement?
    N-->>CA: 204
    Note over N: new connections get the CA-issued cert:<br/>all routes served on them, bootstrap routes → 404
```

| Rule | Detail |
|---|---|
| Trusted root | Only the built-in **TTK root CA** (`ttk_core::TTK_ROOT_CA_PEM`, `crates/core/src/TTK_Root_CA.pem`); intermediates it issued may be sent after the leaf. `Server::set_trusted_roots` overrides it (tests, private CAs) |
| Same identity | The new leaf must have the current SubjectPublicKeyInfo and attestation extension byte for byte, so the evidence binding still holds and RA-TLS clients verify the node exactly as before |
| One time | The certificate is replaced at most once; then `POST /evidence` and `POST /certificate` answer `404`, so no further evidence is generated |
| Per connection | `CertificatePhase` is read before each TLS handshake; only connections that negotiated the CA-issued certificate are served. Connections opened before the replacement stay locked |
| Every route | The gate is in `build_router`, so it also covers the routes nodes add (`/faf`, `/root-attestation`) |
| Every start | The RA-TLS key is ephemeral: each enclave (re)start needs a new authorization. Authorize **root nodes first**, since every other node and client fetches the image list from them |
| Refusals | `400` malformed, `422` not the current certificate, `403` not chaining to a trusted root, `503` no trusted roots, `404` already replaced |

In tests, `sign_for_tests()` (`crates/ra-server/tests/support/test_ca.rs`) does the same with a throwaway CA. Details: [ra-server](ra-server.md#3-certificate-replacement-and-route-gating), [root `auth`](root.md#5-auth-the-test-certificate-authority).

---

## 5. Accepted enclave images (root servers)

Verifying the vendor chain proves the evidence comes from *some* genuine enclave. To know it runs *our* code, the verifier also checks the enclave image's **PCR0** (SHA-384 of the EIF) against a list of accepted images. That list is published by the **root nodes** and fetched at runtime, so new releases can be accepted without rebuilding clients.

```mermaid
sequenceDiagram
    autonumber
    participant V as EnclaveCertVerifier<br/>(client or relay)
    participant L as RootImageTrustStore<br/>(process-wide)
    participant R as Root node (authorized)<br/>(a / b.ttk-server.net:443)

    V->>L: first non-debug Nitro evidence: need the allowlist
    L->>R: RA-TLS connect, root attested against PCR8 pins<br/>(RootSignerTrustStore)
    L->>R: GET /root-attestation
    R-->>L: RootAttestation JSON (SHA384, pcr0 list)
    L-->>V: PCR0 allowlist (cached for the process)
    Note over V: evidence PCR0 must be in the list
```

| Aspect | Behaviour |
|---|---|
| Root servers | `ROOT_SERVERS` = `a.ttk-server.net:443`, then `b.ttk-server.net:443`; first that answers wins |
| Root's own attestation | Checked against **PCR8** (hash of the EIF signing certificate) in `crates/ra-client/src/trust/root_signer_pcr8.txt`, since the PCR0 list is what is being fetched |
| Root authorization | `GET /root-attestation` is gated like every route: an unauthorized root answers `404`, which counts as a failed fetch |
| What the root serves | `crates/root/src/nitro_image_allowlist.txt` (`FileImageTrustStore`), as `RootAttestation` JSON |
| When it's fetched | Lazily, the first time a verifier without `with_image_trust_store` sees non-debug Nitro evidence; debug and mock evidence never triggers a fetch |
| Timeouts | `ROOT_FETCH_TIMEOUT` = 10 s per root server (handshake included) |
| Failure | **Fails closed**: empty list, so every non-debug Nitro image is rejected; retried after `ROOT_FETCH_RETRY_INTERVAL` (60 s) |
| Transport | UDP by default; a relay on vsock calls `set_root_transport(Vsock)` so the fetch goes through `vsock-proxy` |
| Override | `EnclaveCertVerifier::with_image_trust_store` / `with_shared_image_trust_store` (tests, private deployments, the CA, which uses `FileImageTrustStore::builtin()`) |

The `ImageTrustStore` trait (`ttk_core::image_trust`) has three implementations: `FileImageTrustStore` (root node and CA, from the built-in file), `RootImageTrustStore` (client, fetched) and `RootSignerTrustStore` (client, PCR8 pins for the root servers; `nitro_pcr_index()` = 8).

---

## 6. Onion-routed messages (`POST /faf`)

`faf` = *forward-and-forget*. The client builds a request with an ordered list of hops and a body only the last hop can open. The format (`ttk_core::faf`) and its sealing (`ttk_core::seal`) are shared by clients, relays and the terminal.

### 6.1 Request format

```json
{
  "relays": [
    { "address": "https://relay-2.example:443",  "encrypted": false },
    { "address": "<base64 HPKE ciphertext>",     "encrypted": true }
  ],
  "body": {
    "key":     "<base64 HPKE ciphertext of the AES key>",
    "message": "<base64 nonce ‖ AES-256-GCM ciphertext>"
  }
}
```

| Field | Meaning |
|---|---|
| `relays[]` | Remaining hops, in order. The **first** entry is read by the node currently holding the request. Empty at the terminal. At most `MAX_RELAYS` (8) at a relay. |
| `relays[].address` | `"<server> <10-digit salt>"`, where `<server>` is `host[:port]` or `https://host[:port]` (default port `4433`). |
| `relays[].encrypted` | `true`: the address is HPKE-sealed to the node that reads it (salt required). `false`: plaintext (salt optional). |
| `body.key` | Random AES-256 message key, HPKE-sealed to the terminal. |
| `body.message` | The message, encrypted with that key. Its content is up to the terminal's evaluator (e.g. a CBOR `FileRequest`). |

### 6.2 Encryption

Each node's RA-TLS key (ECDSA P-256) is bound to its evidence, so once a client has attested a node it can encrypt to that key.

| Item | Algorithm | HPKE `info` / AAD |
|---|---|---|
| Sealed relay address | RFC 9180 HPKE base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM | `ttk-faf/v1 relay address` |
| Sealed message key | same HPKE suite | `ttk-faf/v1 message key` |
| Message | AES-256-GCM under the message key, random 12-byte nonce | — |
| Terminal's reply | AES-256-GCM under the **same** message key (`seal_response`) | AAD `ttk-faf/v1 response` |

Wire encoding: base64 of `enc (65 bytes) ‖ ciphertext` for HPKE values, `nonce (12 bytes) ‖ ciphertext` for the message and the reply. Decryption errors are deliberately vague so they can't be used as an oracle.

### 6.3 End-to-end flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant R1 as Entry relay
    participant R2 as Second relay
    participant T as Terminal

    Note over R1,T: all three already authorized (CA-issued certificates)
    C->>R1: RA-TLS connect, verify attestation
    C->>R2: RA-TLS connect, verify, take R2's key
    C->>T: RA-TLS connect, verify, take T's key
    Note over C: seal_body_with_key(T, message) → body, message key<br/>seal_address(R2, "T salt")
    C->>R1: POST /faf { relays: [R2 (plain), T (sealed to R2)], body }
    Note over R1: pop relays[0] → R2
    R1->>R2: RA-TLS (pooled, egress-checked), POST /faf { relays: [T (sealed)], body }
    Note over R2: pop relays[0], open_address → T
    R2->>T: RA-TLS (pooled, egress-checked), POST /faf { relays: [], body }
    Note over T: last hop: open_body_with_key → message, key<br/>reply = Evaluator::eval(message)
    T-->>R2: 200 seal_response(key, reply)
    R2-->>R1: 200 same sealed body
    R1-->>C: 200 same sealed body
    Note over C: open_response(key) → reply
```

The entry relay learns only the second relay; the second relay learns only the terminal; only the terminal reads the message, and only the sender reads the reply.

### 6.4 What each node does

```mermaid
flowchart TD
    subgraph Relay["Relay: POST /faf"]
        r1{"relays empty<br/>or > 8?"} -- yes --> r400["400"]
        r1 -- no --> rb{"forward permit<br/>(≤ 256)?"}
        rb -- no --> r503["503 relay busy"]
        rb -- yes --> r2["Pop relays[0]<br/>open if encrypted, parse host:port"]
        r2 -- bad --> r400b["400 invalid relay"]
        r2 --> r3["Pooled connection to host:port?<br/>else resolve, egress-filter, connect + attest, pool"]
        r3 --> r4["Forward rest of request<br/>(10 s, handshake included)"]
        r4 -- "next hop 200" --> r200["200 + next hop's body"]
        r4 -- "any failure" --> r502["502 relay failed"]
    end

    subgraph Terminal["Terminal: POST /faf"]
        t1{"relays empty?"} -- no --> t400["400"]
        t1 -- yes --> t2["open_body_with_key() with own key"]
        t2 -- fail --> t400b["400 invalid body"]
        t2 -- ok --> t3["Evaluator::eval(message)"]
        t3 -- error --> t500["500 (no detail)"]
        t3 -- reply --> t200["200 seal_response(key, reply)"]
    end
```

| Status | Relay | Terminal |
|---|---|---|
| `200` | Next hop answered `200`; its body is passed back unchanged | Body decrypted and evaluated; sealed reply |
| `400` | No relays left, more than 8, or bad/undecryptable relay entry | Relays left, or body can't be decrypted |
| `404` | Node not authorized, or connection opened with the self-signed cert | same |
| `408` / `413` | Body too slow / > 1 MiB (server) | same |
| `500` | — | Evaluator failed, or reply couldn't be sealed |
| `502` | `relay failed` for **every** forwarding failure: refused address, unresolvable, unreachable, failed attestation, non-`200` (incl. an unauthorized next hop's `404`), non-UTF-8 body, or timeout. The reason is only logged. | — |
| `503` | `MAX_CONCURRENT_FORWARDS` (256) already in flight | — |

### 6.5 Relay connection pool

| Property | Value |
|---|---|
| Key | `(host, port)` from the relay address |
| Capacity | `MAX_POOLED_RELAYS` = 64 open connections; extra hops get a one-off connection, closed in the background |
| Connect timeout per resolved address | `RELAY_CONNECT_TIMEOUT` = 3 s |
| Eviction | Closed connections are dropped on next lookup; a pooled connection that fails after closing is retried once on a new one |
| Benefit | RA-TLS handshake and attestation happen once per next hop, not once per request |

### 6.6 Egress policy

Next hops come from the request, so they are attacker-chosen. `ttk_core::egress::classify_hop_address` classifies every resolved address before any packet is sent: in the relay (`connect_to_node_filtered`), in `vsock-proxy` (outbound destinations) and in `vsock-proxy-tcp` (its fixed remote). IPv4-mapped IPv6 is classified as IPv4.

| Class | Addresses | Relay | `vsock-proxy` | `vsock-proxy-tcp` |
|---|---|---|---|---|
| `Public` | Globally routable unicast | allowed | allowed | allowed |
| `Private` | Loopback, `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `::1`, `fc00::/7` | only with `TTK_ALLOW_PRIVATE_NEXT_HOPS=1` | only with `--allow-private` | only with `--allow-private` |
| `Forbidden` | Unspecified, `0/8`, link-local (`169.254/16` incl. instance metadata, `fe80::/10`), multicast, broadcast | always refused | always refused | refused, except the instance metadata service (`169.254.169.254`, `fd00:ec2::254`) with `--allow-imds` |

---

## 7. The file service (terminal)

What the terminal does with a decrypted message is its `Evaluator` (`ttk_ra_server::Evaluator`). The deployed terminal, `s3-server`, uses `ttk_storage::FileService`: a content-addressed file store whose messages and replies are CBOR maps with byte-string values (`ttk_core::file_message`).

| Message (CBOR) | Reply (CBOR) |
|---|---|
| `{"type": "upload", "body": h'<file>'}` | `{"response": h'<SHA-256 of the file>'}` |
| `{"type": "download", "body": h'<SHA-256>'}` | `{"response": h'<file>'}` |
| `{"type": "download", "body": h'<unknown SHA-256>'}` | `{"error": "not_found"}` |

| Terminal binary | Evaluator | Store |
|---|---|---|
| `s3-server` | `FileService` | `S3Store`: one bucket, reached over vsock (`vsock-proxy-tcp`) with instance-role credentials (`vsock-proxy-imds`) |
| `local-mem-server` | `FileService` | `MemoryStore`: in memory, nothing persisted |
| `echo` | `Echo`: the message itself | — |

Blobs are named by the lowercase hex of their SHA-256. A missing file is a sealed `200` reply like any other, so relays can't tell it from a found one. Message size is bounded by `MAX_REQUEST_BODY` (1 MiB, including encryption and base64 overhead). Details: [storage](storage.md).

---

## 8. Networking inside an enclave (vsock)

A Nitro Enclave has **no network interface**. It can only talk to its parent instance over **vsock**, which is a stream transport, while QUIC needs datagrams. `ttk_core::vsock` adapts vsock into quinn datagram sockets, and `vsock-proxy` on the parent does the other half. For S3, which speaks TCP, `vsock-proxy-tcp` forwards whole TCP connections to one fixed remote.

```mermaid
flowchart LR
    subgraph Internet
        P["Peer (client, other node, root server)"]
        S3["S3 endpoint / instance metadata"]
    end

    subgraph Parent["Parent EC2 instance"]
        VP["vsock-proxy<br/>(egress policy)"]
        VT["vsock-proxy-tcp<br/>(fixed remote)"]
    end

    subgraph Enclave["Nitro Enclave (CID 16 / 17)"]
        IN["VsockUdpSocket<br/>(inbound, port 5000)"]
        OUT["VsockOutboundSocket<br/>(outbound)"]
        Node["quinn endpoint<br/>relay / terminal / root"]
        TCP["forward_tcp_to_vsock<br/>(127.0.0.1:443 / :80)"]
    end

    P -- "UDP :443" --> VP
    VP -- "vsock CID:5000<br/>one stream per peer" --> IN
    IN --> Node
    Node --> OUT
    OUT -- "vsock 3:5001<br/>dest header + frames" --> VP
    VP -- "UDP to destination" --> P
    Node -. "s3-server: S3Store" .-> TCP
    TCP -- "vsock 3:8001 / 3:8002" --> VT
    VT -- "TCP" --> S3
```

### Framing

| Where | Format |
|---|---|
| Every datagram on a vsock stream | `[u16 big-endian length][payload]` |
| Start of each outbound stream | Destination header: `[4 or 6][IP bytes][u16 port]` |
| TCP over vsock (`vsock-proxy-tcp`) | None: raw bytes, the destination is fixed on the parent |

| Direction | Enclave side | Parent side |
|---|---|---|
| **Inbound** | `VsockUdpSocket` listens on vsock `5000`. Each parent connection appears to quinn as its own peer address. | Listens on UDP `0.0.0.0:443`, opens one vsock stream per client address to the enclave CID. |
| **Outbound** (relay: next hops and root servers) | `VsockOutboundSocket` connects to the parent at `3:5001`, once per destination. | Accepts vsock `5001` (only from the enclave CID), reads the destination header (5 s), applies the egress policy, sends datagrams from a UDP socket of its own, frames replies back. |
| **TCP** (`s3-server`: S3 and credentials) | `S3Store` resolves every host to loopback; `forward_tcp_to_vsock` pipes `127.0.0.1:443` to `3:8001` and `127.0.0.1:80` to `3:8002`. TLS to S3 runs in the enclave. | `vsock-proxy-tcp` accepts only the enclave CID, resolves its `--remote` on each connection, applies the egress policy, pipes bytes (≤ 1024 connections, 10 s connect). |

| `vsock-proxy` limit | Value |
|---|---|
| Idle peer dropped after | 120 s |
| Peers per direction | 4096 (further datagrams dropped) |
| Datagrams queued per peer toward the enclave | 256 |

Outside an enclave (development), set `TTK_USE_UDP=1` and nodes use plain UDP instead; without `TTK_S3_VSOCK_PORT`, `S3Store` uses the network directly.

---

## 9. Deployment

```mermaid
flowchart LR
    src["Source"] -- "scripts/build-eif.sh<br/>[amd64|arm64] [relay|s3-server|root]" --> docker["Docker build<br/>(ARG NODE)"]
    docker --> eif["out/ttk-&lt;node&gt;_v&lt;ver&gt;_&lt;arch&gt;.eif<br/>+ .json (PCRs)"]
    eif --> allow["PCR0 → crates/root/src/<br/>nitro_image_allowlist.txt"]
    eif --> ec2["EC2 parent<br/>deploy/ec2/user-data.sh"]
    ec2 --> u1["systemd: ttk-relay-enclave /<br/>ttk-terminal-enclave<br/>(nitro-cli run-enclave)"]
    ec2 --> u2["systemd: vsock-proxy"]
    ec2 --> u3["s3-server only:<br/>vsock-proxy-tcp, vsock-proxy-imds"]
    u1 --> auth["certify-server<br/>(TTK root CA key)<br/>after every enclave start"]
```

| Artifact | Purpose |
|---|---|
| `Dockerfile` | Builds the `relay`, `s3-server` (with `--features s3`) or `root` binary from `ttk-executables` (`ARG NODE`) into a slim runtime image; brings up `lo`, runs the node. Bakes `RUST_LOG` (default `error`) and `TTK_ALLOW_MOCK_ATTESTATION` (default `0`), since an enclave gets no environment from `nitro-cli`. For `s3-server` also bakes `TTK_S3_BUCKET`, `AWS_REGION`, `TTK_S3_VSOCK_PORT` (`8001`), `TTK_IMDS_VSOCK_PORT` (`8002`) and installs `ca-certificates` |
| `scripts/build-eif.sh` | Produces the EIF and its PCR measurements. `s3-server` requires `TTK_S3_BUCKET` and `AWS_REGION` (part of the measurements). `TTK_DEBUG=1` builds a `_debug` image (logs at `info`, accepts mock next hops); never deploy it |
| `crates/root/src/nitro_image_allowlist.txt` | PCR0 of each released relay/terminal image, served by the root nodes |
| `crates/ra-client/src/trust/root_signer_pcr8.txt` | PCR8 pins for the root servers' images |
| `crates/core/src/TTK_Root_CA.pem` | The TTK root CA every node trusts for `POST /certificate` (its key is kept outside the repository) |
| `deploy/ec2/user-data.sh` | EC2 bootstrap: installs `nitro-cli`, downloads the EIF / `vsock-proxy` / units (with optional SHA-256 checks), starts them. `TTK_NODE` = `relay` or `s3-server` (the latter also installs `vsock-proxy-tcp` to `s3.<TTK_S3_REGION>.amazonaws.com:443` and `vsock-proxy-imds`, and runs under `ttk-terminal-enclave.service`) |
| `deploy/systemd/ttk-relay-enclave.service` | Runs the relay EIF via `nitro-cli` (CID 16, 2 vCPU, 1024 MiB; overrides in `/etc/default/ttk-relay-enclave`) |
| `deploy/systemd/ttk-terminal-enclave.service` | Runs the terminal (`s3-server`) EIF (CID 17; `/etc/default/ttk-terminal-enclave`) |
| `deploy/systemd/vsock-proxy.service` | Runs `vsock-proxy` on the parent (`DynamicUser`, only `CAP_NET_BIND_SERVICE`; `/etc/default/vsock-proxy`) |
| `deploy/systemd/vsock-proxy-tcp.service` | Runs `vsock-proxy-tcp`: vsock `8001` → the bucket's regional S3 endpoint (`/etc/default/vsock-proxy-tcp`) |
| `deploy/systemd/vsock-proxy-imds.service` | Second `vsock-proxy-tcp`: vsock `8002` → `169.254.169.254:80` with `--allow-imds`, for the instance role's credentials (`/etc/default/vsock-proxy-imds`). Scope the role to the bucket: the parent sees these credentials |
| `.github/workflows/main.yml` | On `main`: version bump, tests, EIFs and Docker images for `relay` and `root` × `amd64`, `arm64`; mdBook + `cargo doc` |

After an enclave starts it serves only `POST /evidence` and `POST /certificate`: run `certify-server` against it with the TTK root CA's certificate and key (root nodes first). There is no systemd unit or user-data option for the root node yet, and CI does not build the `s3-server` EIF (it needs a bucket and region baked in).

---

## 10. Configuration reference

### Nodes (relay / terminal / root)

| Variable | Default | Effect |
|---|---|---|
| `TTK_USE_UDP` | unset | `1` = listen on UDP instead of vsock |
| `TTK_LISTEN_ADDR` | `0.0.0.0:4433` | UDP listen address (with `TTK_USE_UDP=1`) |
| `TTK_VSOCK_PORT` | `5000` | vsock listen port |
| `TTK_ATTESTATION` | auto-detect | Force a provider: `aws-nitro`, `sev-snp`, `tdx`, `mock` |
| `TTK_SEV_SNP_VCEK` | unset | SEV-SNP: VCEK file (DER or PEM) if the host supplies none |
| `TTK_PARENT_CID` | `3` | Relay: parent CID for outbound traffic |
| `TTK_OUTBOUND_VSOCK_PORT` | `5001` | Relay: parent vsock port for outbound traffic |
| `TTK_ALLOW_MOCK_ATTESTATION` | unset | Relay: `1` = accept mock-attested next hops (dev only) |
| `TTK_ALLOW_PRIVATE_NEXT_HOPS` | unset | Relay: `1` = allow loopback/private next hops (local dev, private networks) |
| `TTK_S3_BUCKET` | required (`s3-server`) | Bucket |
| `TTK_S3_ENDPOINT` | unset | `s3-server`: endpoint URL override (path-style) |
| `AWS_REGION`, AWS credential variables | — | `s3-server`: standard AWS chain |
| `TTK_S3_VSOCK_PORT` | unset (`8001` in EIFs) | `s3-server` (Linux): reach S3 over vsock via `vsock-proxy-tcp` |
| `TTK_IMDS_VSOCK_PORT` | unset (`8002` in EIFs) | `s3-server` (Linux): instance-role credentials over vsock via `vsock-proxy-imds`; empty = unset |
| `RUST_LOG` | — | e.g. `info` to enable logs |

### `vsock-proxy` (flags override env)

| Flag | Env | Default |
|---|---|---|
| `-c, --cid` | `TTK_ENCLAVE_CID` | required (e.g. `16`) |
| `-l, --listen` | `TTK_RELAY_LISTEN` | `0.0.0.0:443` |
| `-p, --vsock-port` | `TTK_VSOCK_PORT` | `5000` |
| `-o, --outbound-port` | `TTK_OUTBOUND_VSOCK_PORT` | `5001` (`0` disables) |
| `-P, --allow-private` | `TTK_ALLOW_PRIVATE_NEXT_HOPS=1` | off |

### `vsock-proxy-tcp` (flags override env)

| Flag | Env | Default |
|---|---|---|
| `-c, --cid` | `TTK_ENCLAVE_CID` | required (e.g. `17`) |
| `-r, --remote` | `TTK_TCP_REMOTE` | required (e.g. `s3.eu-west-1.amazonaws.com:443`) |
| `-p, --vsock-port` | `TTK_TCP_VSOCK_PORT` | `8001` |
| `-P, --allow-private` | `TTK_ALLOW_PRIVATE_NEXT_HOPS=1` | off |
| `-I, --allow-imds` | `TTK_TCP_ALLOW_IMDS=1` | off |

### Test tools

`client` / `client-m`: `-a, --addr` (or positional URL; `TTK_SERVER_ADDR`, default `127.0.0.1:4433`), `-s, --server-name` (`TTK_SERVER_NAME`, default `localhost`), `-r, --relay` (`127.0.0.1:4434`), `-t, --terminal` (`127.0.0.1:4444`); `client` takes `--upload <PATH>` or `--download <SHA256> [--out PATH]`, `client-m` takes `--message <TEXT>`. `certify-server`: `--addr`, `--server-name`, `--ca-cert`, `--ca-key`, `--out`. All accept `TTK_ALLOW_MOCK_ATTESTATION=1`. See [executables](executables.md).

### Local run

Off-enclave, nodes use mock attestation and talk over loopback, so relays need both opt-ins. Every node must then be authorized before it serves `/faf`; since nodes trust only the built-in TTK root CA, this needs that CA's certificate and key.

```bash
TTK_USE_UDP=1 TTK_ALLOW_MOCK_ATTESTATION=1 TTK_ALLOW_PRIVATE_NEXT_HOPS=1 cargo run --bin relay
```

```bash
TTK_USE_UDP=1 TTK_LISTEN_ADDR=127.0.0.1:4434 TTK_ALLOW_MOCK_ATTESTATION=1 TTK_ALLOW_PRIVATE_NEXT_HOPS=1 cargo run --bin relay
```

```bash
TTK_USE_UDP=1 TTK_LISTEN_ADDR=127.0.0.1:4444 cargo run --bin local-mem-server
```

```bash
for addr in 127.0.0.1:4433 127.0.0.1:4434 127.0.0.1:4444; do TTK_ALLOW_MOCK_ATTESTATION=1 cargo run --bin certify-server -- --addr $addr --ca-cert TTK_Root_CA.pem --ca-key TTK_Root_CA.key; done
```

```bash
TTK_ALLOW_MOCK_ATTESTATION=1 cargo run --bin client -- --upload ./report.pdf
```

Use `echo` instead of `local-mem-server` and `client-m -- --message "hello"` instead of `client` for a plain text round trip. Optionally a root node: `TTK_USE_UDP=1 TTK_LISTEN_ADDR=127.0.0.1:4455 cargo run --bin root`, authorized the same way, then `GET /root-attestation`. (Mock evidence never needs the image list, so the flow above works without one.)

---

## 11. Security model

| Property | How it is achieved |
|---|---|
| **Node identity** | Ephemeral TLS key whose hash is inside hardware-signed evidence. Clients trust no CA: the CA-issued certificate keeps the same key and evidence. |
| **Code integrity** | Nitro PCR0 must be in the accepted-images list from the root servers; the root servers are pinned by PCR8. Callers may pin further measurements. |
| **Authorization** | A node serves nothing but its bootstrap routes until a certificate chaining to the TTK root CA is installed for its attested key, after the CA checked fresh evidence. Once only, per enclave start. |
| **Freshness** | `POST /evidence` returns evidence carrying the caller's nonce (Nitro / mock), with the certificate it is bound to; used by the CA before issuing. |
| **Transport confidentiality** | TLS 1.3 over QUIC terminates inside the enclave; the parent only relays ciphertext. TLS to S3 also runs in the enclave. |
| **Hop-by-hop trust** | Relays verify every next hop's attestation (and image) before forwarding; an unauthorized next hop's routes are locked. |
| **Message confidentiality** | Body is HPKE/AES-GCM encrypted to the terminal's attested key; relays can't read it. |
| **Reply confidentiality** | The terminal's reply (including a file-service `not_found`) is sealed under the sender's message key; relays pass it back unread. |
| **Route privacy** | Encrypted relay entries are readable only by the node they are sealed to, and each carries a fresh random salt. |
| **No network probing** | Egress policy on next hops (relay and `vsock-proxy`) and on `vsock-proxy-tcp`'s fixed remote; every forwarding failure is the same `502 relay failed`. |
| **Resource limits** | Body size/time, header size, connections, streams, receive window, concurrent forwards and attestations, proxy peers and connections are all capped. |
| **Key custody** | Node private keys are generated in the TEE and never leave it. |

### Known limitations

| Limitation | Notes |
|---|---|
| Startup evidence has no nonce | Cert and `/evidence.cmw` evidence is produced once; freshness only via `POST /evidence`, and only Nitro/mock support it (so the CA can only authorize Nitro / mock nodes). |
| Root signer pins are empty | Until `root_signer_pcr8.txt` is filled, no genuine root server is accepted, so strict verifiers reject all non-debug Nitro nodes. |
| Image allowlist is Nitro-only | SEV-SNP / TDX / SGX evidence is chain-verified, but their measurements are only checked if the caller pins them. |
| Manual re-authorization | Every enclave restart generates a new key and needs a new CA-issued certificate; nothing automates this yet. |
| S3 credentials pass through the parent | `vsock-proxy-imds` exposes the instance role's credentials to the (untrusted) parent, which holds the role anyway; scope it to the bucket. |
| Placeholder identifiers | OID `1.3.6.1.4.1.99999.1` is not a registered PEN; the `vnd.ttk.*` media types and tag URIs are not registered. |
| `mock` is a default feature | Without TEE hardware, nodes fall back to mock evidence. Verifiers reject it unless `allow_mock` is set. |
| Partial vendor checks | DCAP: no TCB status, QE identity or PCK CRLs. SEV-SNP: no VLEK reports or CRLs. |
| `EnclaveCertVerifier` skips CA validation | By design for RA-TLS (it also accepts the CA-issued certificate without checking its issuer). Do not reuse it for ordinary TLS. |
