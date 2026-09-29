//! RATS (RFC 9334) role mapping for this server:
//!
//! - **Attester**: this process, running inside a Nitro Enclave. It holds a
//!   hardware-rooted identity via the Nitro Security Module (NSM).
//! - **Evidence**: the NSM Attestation Document produced by [`attestation::detect`],
//!   with `user_data` bound to the SHA-256 hash of the ephemeral TLS key's
//!   SubjectPublicKeyInfo so a Relying Party can tie the Evidence to the TLS session.
//! - **Endorsements**: the AWS Nitro certificate chain embedded in the Attestation
//!   Document, rooted at the AWS Nitro Enclaves root certificate.
//! - **Verifier** / **Relying Party**: the external client fetching Evidence as an
//!   RFC 9711 EAT over `/evidence.eat` (or from the RA-TLS certificate). Appraisal against
//!   Reference Values (expected PCR measurements) and issuance of an Attestation Result
//!   happen outside this server.
//!
//! When forwarding a [`FafRequest`] over `POST /faf`, this server is itself the Relying
//! Party: it only sends the message and key to a relay whose RA-TLS attestation verifies.
//!
//! Routes:
//!
//! | Route               | Response                                                        |
//! |---------------------|-----------------------------------------------------------------|
//! | `GET /`             | Greeting text                                                   |
//! | `GET /evidence.eat` | Base64-encoded EAT carrying this server's Evidence              |
//! | `POST /faf`         | Forwards a [`FafRequest`] to its relay; see [`FafRequest`]      |

use crate::client::{EnclaveCertVerifier, TtkClient};
use crate::{attestation, AttestationParams};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::{Buf, Bytes, BytesMut};
use log::{info, warn};
use quinn::{Endpoint, ServerConfig};
use rcgen::{CertificateParams, CustomExtension, KeyPair, SanType};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tower_service::Service;

/// OID of the X.509 extension carrying the attestation document (placeholder, not a registered PEN).
const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

/// Evidence for this instance, in the formats served over HTTP.
#[derive(Clone, Debug)]
pub struct Evidence {
    /// Raw NSM Attestation Document (COSE_Sign1).
    pub nitro: Vec<u8>,
    /// The same document, wrapped as an RFC 9711 EAT claims-set.
    pub eat: Vec<u8>,
}

/// Creates a self-signed certificate for `key_pair` with `attestation_doc` embedded as a
/// non-critical X.509 extension, and returns it PEM-encoded.
pub fn create_cert_with_attestation(
    key_pair: &KeyPair,
    common_name: &str,
    attestation_doc: &[u8], // <--- Attestation document passed as a parameter
    validity_days: i64,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut params = CertificateParams::default();

    // Set Subject Name
    // let mut dn = DistinguishName::new();
    // dn.push(DnType::CommonName, common_name);
    // params.distinguished_name = dn;

    // Set Validity Period
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(validity_days);

    // Subject Alternative Name
    params.subject_alt_names = vec![SanType::DnsName(common_name.try_into()?)];

    // --------------------------------------------------------------------
    // WRAP AND ATTACH ATTESTATION DOCUMENT AS X.509 EXTENSION
    // --------------------------------------------------------------------
    // Wrap the raw attestation bytes into an ASN.1 OCTET STRING header
    let der_encoded_payload = wrap_in_asn1_octet_string(attestation_doc);

    let mut attestation_ext =
        CustomExtension::from_oid_content(ATTESTATION_OID, der_encoded_payload);

    // Set to false unless you want parsers to fail if they don't recognize the OID
    attestation_ext.set_criticality(false);

    params.custom_extensions.push(attestation_ext);

    // Sign the certificate
    let cert = params.self_signed(key_pair)?;
    Ok(cert.pem())
}

/// Helper to wrap raw binary bytes in an ASN.1 OCTET STRING TLV header
fn wrap_in_asn1_octet_string(data: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.push(0x04); // ASN.1 Tag for OCTET STRING

    let len = data.len();
    if len < 128 {
        encoded.push(len as u8);
    } else if len <= 0xFF {
        encoded.push(0x81);
        encoded.push(len as u8);
    } else if len <= 0xFFFF {
        encoded.push(0x82);
        encoded.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        encoded.push(0x84);
        encoded.extend_from_slice(&(len as u32).to_be_bytes());
    }

    encoded.extend_from_slice(data);
    encoded
}

/// Boxed error type used by the server functions.
type BoxError = Box<dyn std::error::Error>;

/// Boxed error type that can cross task boundaries.
type SendError = Box<dyn std::error::Error + Send + Sync>;

/// Address the QUIC endpoint binds to.
const LISTEN_ADDR: &str = "0.0.0.0:4433";

/// Port assumed for a `relay_server` that does not name one.
pub const DEFAULT_RELAY_PORT: u16 = 4433;

/// Time allowed for forwarding a `/faf` request to its relay, RA-TLS handshake included.
pub const RELAY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Time allowed for the RA-TLS handshake with each resolved address of a relay.
pub const RELAY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Largest request body the server reads; larger requests get `413 Payload Too Large`.
pub const MAX_REQUEST_BODY: usize = 1024 * 1024;

/// Environment variable that makes [`run`] accept mock attestation from relay servers.
pub const ALLOW_MOCK_RELAY_ENV: &str = "TTK_ALLOW_MOCK_ATTESTATION";

/// Builds the verifier used to attest a relay server. Called once per forwarded request, so
/// each connection gets its own verifier state.
pub type RelayVerifierFactory = Arc<dyn Fn() -> EnclaveCertVerifier + Send + Sync>;

/// Body of `POST /faf`: a message and key to hand to `relay_server`.
///
/// The relay runs this same server. The message and key are forwarded to its `POST /faf`
/// without `relay_server`, which tells the relay it is the last hop: it accepts the request and
/// answers `200 OK`. This server answers `200 OK` once the relay has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FafRequest {
    /// Relay to forward to, as `host[:port]` or `https://host[:port]` (default port
    /// [`DEFAULT_RELAY_PORT`]). Absent when this server is the last hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_server: Option<String>,
    /// The message to transmit.
    pub message: String,
    /// The key to transmit alongside the message.
    pub key: String,
}

/// Runs the server: attests, builds the RA-TLS identity, then serves HTTP/3 on
/// `0.0.0.0:4433` until the endpoint closes.
///
/// Relays must present genuine TEE attestation unless `TTK_ALLOW_MOCK_ATTESTATION=1`.
pub async fn run() -> Result<(), BoxError> {
    let mut server = Server::bind(LISTEN_ADDR.parse()?)?;
    if std::env::var(ALLOW_MOCK_RELAY_ENV).is_ok_and(|v| v == "1") {
        warn!("Accepting MOCK attestation from relay servers ({ALLOW_MOCK_RELAY_ENV}=1)");
        server = server.with_relay_verifier(|| EnclaveCertVerifier::new().allow_mock());
    }
    info!("Server listening on {} (QUIC/HTTP/3)", server.local_addr()?);
    server.serve().await;
    Ok(())
}

/// An attested HTTP/3 server bound to a QUIC endpoint.
pub struct Server {
    endpoint: Endpoint,
    evidence: Arc<Evidence>,
    relay_verifier: RelayVerifierFactory,
}

/// Setup and serving.
impl Server {
    /// Attests, builds the RA-TLS identity and binds the QUIC endpoint to `addr`.
    ///
    /// Must be called within a Tokio runtime. Binding port 0 picks a free port; see
    /// [`local_addr`](Self::local_addr).
    pub fn bind(addr: SocketAddr) -> Result<Self, BoxError> {
        info!("Initializing Nitro Enclave HTTP/3 Server...");

        // Install the default cryptographic provider for rustls 0.23
        let _ = rustls::crypto::ring::default_provider().install_default();

        let key_pair = KeyPair::generate()?;
        info!("Generated ephemeral TLS certificate.");

        let eat_bytes = generate_evidence(&key_pair)?;
        let tls_config = build_tls_config(&key_pair, &eat_bytes)?;
        let evidence = Arc::new(Evidence {
            nitro: eat_bytes.clone(),
            eat: eat_bytes,
        });

        let quic_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
        ));
        let endpoint = Endpoint::server(quic_config, addr)?;
        Ok(Self {
            endpoint,
            evidence,
            relay_verifier: Arc::new(EnclaveCertVerifier::new),
        })
    }

    /// Sets the policy for attesting relay servers in `POST /faf`.
    ///
    /// Defaults to [`EnclaveCertVerifier::new`], which accepts only genuine TEE evidence.
    pub fn with_relay_verifier(
        mut self,
        verifier: impl Fn() -> EnclaveCertVerifier + Send + Sync + 'static,
    ) -> Self {
        self.relay_verifier = Arc::new(verifier);
        self
    }

    /// Returns the address the endpoint is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Accepts QUIC connections and serves HTTP/3 until the endpoint closes.
    pub async fn serve(self) {
        let app = build_router(self.evidence, self.relay_verifier);
        while let Some(incoming) = self.endpoint.accept().await {
            tokio::spawn(handle_connection(incoming, app.clone()));
        }
    }
}

/// Requests evidence from the detected attestation provider, bound to the TLS public key,
/// and returns it as CBOR-encoded RFC 9711 EAT bytes.
fn generate_evidence(key_pair: &KeyPair) -> Result<Vec<u8>, BoxError> {
    let params = AttestationParams::new().with_user_data_hash(&key_pair.public_key_der());

    let provider = attestation::detect()?;
    info!("Using attestation provider: {}", provider.name());
    let eat_bytes = provider.generate_document(&params)?.to_cbor_bytes()?;
    info!(
        "Wrapped Attestation Document as RFC 9711 EAT token ({} bytes).",
        eat_bytes.len()
    );
    Ok(eat_bytes)
}

/// Builds the rustls config using a self-signed RA-TLS certificate carrying `eat_bytes`.
fn build_tls_config(
    key_pair: &KeyPair,
    eat_bytes: &[u8],
) -> Result<rustls::ServerConfig, BoxError> {
    let cert_pem = create_cert_with_attestation(key_pair, "enclave.internal", eat_bytes, 30)?;
    let key_pem = key_pair.serialize_pem();

    let certs =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    // Enable ALPN for HTTP/3 ("h3")
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(config)
}

/// Builds the Axum router: the greeting, the evidence endpoint and the `/faf` relay.
fn build_router(evidence: Arc<Evidence>, relay_verifier: RelayVerifierFactory) -> Router {
    let eat_b64 = STANDARD.encode(&evidence.eat);

    Router::new()
        .route("/", get(|| async { "Hello from Enclave over HTTP/3!" }))
        .route("/evidence.eat", get(move || async move { eat_b64 }))
        .route("/faf", post(faf))
        .with_state(relay_verifier)
}

/// `POST /faf`: forwards the message and key to the relay and answers `200 OK` once the relay
/// has; with no `relay_server`, this server is the last hop and accepts the request directly.
///
/// Answers `400` for an unparsable `relay_server`, `502` if the relay can't be reached, fails
/// attestation or answers anything but `200`, and `504` if it doesn't answer within
/// [`RELAY_TIMEOUT`].
async fn faf(
    State(relay_verifier): State<RelayVerifierFactory>,
    Json(request): Json<FafRequest>,
) -> (StatusCode, String) {
    let FafRequest {
        relay_server,
        message,
        key,
    } = request;

    let Some(relay_server) = relay_server else {
        // Never log the key or the message itself.
        info!(
            "/faf: accepted a {}-byte message as the last hop",
            message.len()
        );
        return (StatusCode::OK, "delivered".to_string());
    };

    let (host, port) = match parse_relay_server(&relay_server) {
        Ok(target) => target,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid relay_server: {e}"),
            )
        }
    };
    let forward = FafRequest {
        relay_server: None,
        message,
        key,
    };

    let relayed = tokio::time::timeout(
        RELAY_TIMEOUT,
        forward_to_relay(&host, port, relay_verifier(), &forward),
    )
    .await;
    match relayed {
        Ok(Ok(StatusCode::OK)) => {
            info!("/faf: relayed to {host}:{port}");
            (StatusCode::OK, "relayed".to_string())
        }
        Ok(Ok(status)) => {
            warn!("/faf: relay {host}:{port} answered {status}");
            (StatusCode::BAD_GATEWAY, format!("relay answered {status}"))
        }
        Ok(Err(e)) => {
            warn!("/faf: relaying to {host}:{port} failed: {e}");
            (StatusCode::BAD_GATEWAY, format!("relay failed: {e}"))
        }
        Err(_) => {
            warn!("/faf: relay {host}:{port} timed out");
            (StatusCode::GATEWAY_TIMEOUT, "relay timed out".to_string())
        }
    }
}

/// Splits a `relay_server` value (`host[:port]` or `https://host[:port][/...]`) into its host
/// (without IPv6 brackets) and port.
pub fn parse_relay_server(relay_server: &str) -> Result<(String, u16), String> {
    let uri: axum::http::Uri = relay_server
        .trim()
        .parse()
        .map_err(|e| format!("{relay_server:?}: {e}"))?;
    if let Some(scheme) = uri.scheme_str() {
        if scheme != "https" {
            return Err(format!(
                "unsupported scheme {scheme:?}; the relay speaks HTTP/3"
            ));
        }
    }
    let authority = uri
        .authority()
        .ok_or_else(|| format!("{relay_server:?} has no host"))?;
    if authority.as_str().contains('@') {
        return Err("user info is not allowed".to_string());
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("{relay_server:?} has no host"));
    }
    let port = authority.port_u16().unwrap_or(DEFAULT_RELAY_PORT);
    Ok((host.to_string(), port))
}

/// Resolves `host` and connects to the first of its addresses that completes an RA-TLS
/// handshake within [`RELAY_CONNECT_TIMEOUT`], e.g. falling back from `::1` to `127.0.0.1`
/// for `localhost`.
async fn connect_to_relay(
    host: &str,
    port: u16,
    verifier: EnclaveCertVerifier,
) -> Result<TtkClient, SendError> {
    let mut last_error: SendError = format!("{host} did not resolve").into();
    for addr in tokio::net::lookup_host((host, port)).await? {
        let connecting = TtkClient::connect_with_verifier(addr, host, verifier.clone());
        match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, connecting).await {
            Ok(Ok(client)) => return Ok(client),
            Ok(Err(e)) => last_error = e,
            Err(_) => last_error = format!("connecting to {addr} timed out").into(),
        }
    }
    Err(last_error)
}

/// Resolves the relay, connects over RA-TLS (verified by `verifier`), posts `request` to its
/// `/faf` and returns the relay's status.
async fn forward_to_relay(
    host: &str,
    port: u16,
    verifier: EnclaveCertVerifier,
    request: &FafRequest,
) -> Result<StatusCode, SendError> {
    let mut client = connect_to_relay(host, port, verifier).await?;
    let response = client.post_json("/faf", request).await;
    let _ = client.close().await;
    Ok(response?.status)
}

/// Drives a single QUIC connection, dispatching each HTTP/3 request to `app`.
async fn handle_connection(incoming: quinn::Incoming, app: Router) {
    let conn = match incoming.await {
        Ok(conn) => conn,
        Err(err) => return eprintln!("Handshake failed: {err}"),
    };

    let mut h3_conn =
        match h3::server::Connection::<_, axum::body::Bytes>::new(h3_quinn::Connection::new(conn))
            .await
        {
            Ok(h3) => h3,
            Err(e) => return eprintln!("H3 setup failed: {e}"),
        };

    while let Ok(Some((req, stream))) = h3_conn.accept().await {
        let app = app.clone();
        tokio::spawn(respond(app, req, stream));
    }
}

/// HTTP/3 request stream on the server side.
type ServerStream =
    h3::server::RequestStream<h3_quinn::BidiStream<axum::body::Bytes>, axum::body::Bytes>;

/// Reads the request body from `stream`. Returns `None` if it exceeds [`MAX_REQUEST_BODY`].
async fn read_body(stream: &mut ServerStream) -> Result<Option<Bytes>, SendError> {
    let mut body = BytesMut::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        if body.len() + chunk.remaining() > MAX_REQUEST_BODY {
            return Ok(None);
        }
        while chunk.has_remaining() {
            let slice = chunk.chunk();
            body.extend_from_slice(slice);
            let len = slice.len();
            chunk.advance(len);
        }
    }
    Ok(Some(body.freeze()))
}

/// Reads the body of `req`, runs it through `app` and streams the response back over the
/// HTTP/3 `stream`.
async fn respond(mut app: Router, req: axum::http::Request<()>, mut stream: ServerStream) {
    let response = match read_body(&mut stream).await {
        Ok(Some(body)) => match app.call(req.map(|()| axum::body::Body::from(body))).await {
            Ok(response) => response,
            Err(e) => return eprintln!("App call error: {e}"),
        },
        Ok(None) => (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response(),
        Err(e) => return eprintln!("Failed to read request body: {e}"),
    };

    let (parts, body) = response.into_parts();
    if let Err(e) = stream
        .send_response(axum::http::Response::from_parts(parts, ()))
        .await
    {
        return eprintln!("Failed to send response headers: {e}");
    }
    match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) if !bytes.is_empty() => {
            if let Err(e) = stream.send_data(bytes).await {
                return eprintln!("Failed to send response body: {e}");
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!("Failed to read response body: {e}"),
    }
    if let Err(e) = stream.finish().await {
        eprintln!("Failed to finish stream: {e}");
    }
}
