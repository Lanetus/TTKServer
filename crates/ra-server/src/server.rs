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
//! This module owns attestation, the RA-TLS certificate and the QUIC / HTTP/3 transport; the
//! base HTTP routes live in [`super::router`], and nodes add their own with
//! [`Server::serve_with`].

use super::router::build_router;
use crate::{attestation, AttestationParams};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Router;
use bytes::{Buf, Bytes, BytesMut};
use log::{error, info, warn};
use quinn::{Endpoint, ServerConfig, TransportConfig, VarInt};
use rcgen::{CertificateParams, CustomExtension, KeyPair, SanType};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::sync::Semaphore;
use tower_service::Service;

pub use super::router::Evidence;

pub use ttk_core::ATTESTATION_OID;

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
pub type BoxError = Box<dyn std::error::Error>;

/// Boxed error type that can cross task boundaries.
type SendError = Box<dyn std::error::Error + Send + Sync>;

/// Default address the QUIC endpoint binds to over UDP, unless [`LISTEN_ADDR_ENV`] overrides it.
const LISTEN_ADDR: &str = "0.0.0.0:4433";

/// Environment variable that overrides the default UDP listen address `0.0.0.0:4433`
/// (a socket address such as `127.0.0.1:4444`). Only used with [`USE_UDP_ENV`].
pub const LISTEN_ADDR_ENV: &str = "TTK_LISTEN_ADDR";

/// Environment variable that, set to `1`, makes [`Listener::from_env`] pick a regular UDP
/// socket instead of vsock (for running outside an enclave).
pub const USE_UDP_ENV: &str = "TTK_USE_UDP";

/// Default vsock port the QUIC endpoint listens on, unless [`VSOCK_PORT_ENV`] overrides it.
const VSOCK_PORT: u32 = 5000;

/// Environment variable that overrides the default vsock port `5000`.
pub const VSOCK_PORT_ENV: &str = "TTK_VSOCK_PORT";

pub use ttk_core::PARENT_CID;

/// Largest request body the server reads; larger requests get `413 Payload Too Large`.
pub const MAX_REQUEST_BODY: usize = 1024 * 1024;

/// Largest request header section (HTTP/3 `SETTINGS_MAX_FIELD_SECTION_SIZE`) the server
/// accepts, in bytes.
pub const MAX_REQUEST_HEADERS: u64 = 16 * 1024;

/// Time allowed for a request's body to arrive; slower requests get `408 Request Timeout`.
pub const REQUEST_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Most QUIC connections served at once; further connection attempts are refused.
pub const MAX_CONNECTIONS: usize = 1024;

/// Most concurrent requests (bidirectional streams) per connection.
pub const MAX_STREAMS_PER_CONNECTION: u32 = 16;

/// Flow-control window for all streams of one connection together, in bytes: bounds the request
/// data a connection can have buffered at once.
pub const CONNECTION_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;

/// Where the server's QUIC endpoint listens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// A regular UDP socket (for running outside an enclave).
    Udp(SocketAddr),
    /// vsock `port` (any CID), with datagrams relayed by the parent's `vsock-proxy`. Linux only.
    Vsock(u32),
}

/// Configuration from the environment.
impl Listener {
    /// Reads the listener from the environment: vsock port `TTK_VSOCK_PORT` (default `5000`),
    /// or with `TTK_USE_UDP=1` UDP `TTK_LISTEN_ADDR` (default `0.0.0.0:4433`).
    pub fn from_env() -> Result<Self, BoxError> {
        if std::env::var(USE_UDP_ENV).is_ok_and(|v| v == "1") {
            let listen_addr =
                std::env::var(LISTEN_ADDR_ENV).unwrap_or_else(|_| LISTEN_ADDR.to_string());
            let listen_addr: SocketAddr = listen_addr
                .parse()
                .map_err(|e| format!("invalid {LISTEN_ADDR_ENV} {listen_addr:?}: {e}"))?;
            Ok(Self::Udp(listen_addr))
        } else {
            Ok(Self::Vsock(env_u32(VSOCK_PORT_ENV, VSOCK_PORT)?))
        }
    }
}

/// Reads a `u32` from environment variable `name`, or `default` if unset.
pub fn env_u32(name: &str, default: u32) -> Result<u32, BoxError> {
    match std::env::var(name) {
        Ok(value) => Ok(value
            .parse()
            .map_err(|e| format!("invalid {name} {value:?}: {e}"))?),
        Err(_) => Ok(default),
    }
}

#[cfg(target_os = "linux")]
fn bind_vsock(port: u32) -> Result<Server, BoxError> {
    Server::bind_vsock(port)
}

#[cfg(not(target_os = "linux"))]
fn bind_vsock(_port: u32) -> Result<Server, BoxError> {
    Err(format!("vsock is only available on Linux; set {USE_UDP_ENV}=1 to listen on UDP").into())
}

/// An attested HTTP/3 server bound to a QUIC endpoint.
pub struct Server {
    endpoint: Endpoint,
    evidence: Arc<Evidence>,
    private_key: Vec<u8>,
}

/// Setup and serving.
impl Server {
    /// Attests, builds the RA-TLS identity and binds the QUIC endpoint to `addr`.
    ///
    /// Must be called within a Tokio runtime. Binding port 0 picks a free port; see
    /// [`local_addr`](Self::local_addr).
    pub fn bind(addr: SocketAddr) -> Result<Self, BoxError> {
        let (quic_config, evidence, private_key) = attest()?;
        let endpoint = Endpoint::server(quic_config, addr)?;
        Ok(Self::new(endpoint, evidence, private_key))
    }

    /// Attests, builds the RA-TLS identity and listens on `listener`, logging where.
    ///
    /// Must be called within a Tokio runtime.
    pub fn listen(listener: Listener) -> Result<Self, BoxError> {
        let server = match listener {
            Listener::Udp(addr) => Self::bind(addr)?,
            Listener::Vsock(port) => bind_vsock(port)?,
        };
        match listener {
            Listener::Udp(_) => info!(
                "Server listening on UDP {} (QUIC/HTTP/3)",
                server.local_addr()?
            ),
            Listener::Vsock(port) => info!("Server listening on vsock port {port} (QUIC/HTTP/3)"),
        }
        Ok(server)
    }

    /// Attests, builds the RA-TLS identity and listens on vsock `port` (any CID), with
    /// datagrams framed as described in [`super::vsock`].
    ///
    /// Must be called within a Tokio runtime.
    #[cfg(target_os = "linux")]
    pub fn bind_vsock(port: u32) -> Result<Self, BoxError> {
        let (quic_config, evidence, private_key) = attest()?;
        let socket = super::vsock::VsockUdpSocket::bind(port)?;
        let runtime = quinn::default_runtime().ok_or("no async runtime found")?;
        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(quic_config),
            Arc::new(socket),
            runtime,
        )?;
        Ok(Self::new(endpoint, evidence, private_key))
    }

    /// Wraps a bound endpoint.
    fn new(endpoint: Endpoint, evidence: Arc<Evidence>, private_key: Vec<u8>) -> Self {
        Self {
            endpoint,
            evidence,
            private_key,
        }
    }

    /// Returns the address the endpoint is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Returns the Evidence this server presents.
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// Returns the RA-TLS private key (PKCS#8 DER, ECDSA P-256), e.g. to open values sealed to
    /// this node. It never leaves the TEE.
    pub fn private_key_der(&self) -> &[u8] {
        &self.private_key
    }

    /// Accepts QUIC connections and serves the base routes over HTTP/3 until the endpoint
    /// closes.
    pub async fn serve(self) {
        self.serve_with(Router::new()).await
    }

    /// Accepts QUIC connections and serves the base routes merged with `routes` over HTTP/3
    /// until the endpoint closes. Beyond [`MAX_CONNECTIONS`] open connections, new ones are
    /// refused.
    pub async fn serve_with(self, routes: Router) {
        let app = build_router(&self.evidence, routes);
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        while let Some(incoming) = self.endpoint.accept().await {
            let Ok(permit) = connections.clone().try_acquire_owned() else {
                warn!("Refusing connection: {MAX_CONNECTIONS} already open");
                incoming.refuse();
                continue;
            };
            let app = app.clone();
            tokio::spawn(async move {
                handle_connection(incoming, app).await;
                drop(permit);
            });
        }
    }
}

/// Attests and builds the RA-TLS identity: an ephemeral key pair, Evidence bound to it, the
/// QUIC server config presenting the certificate that embeds the Evidence, and the key pair's
/// private key (PKCS#8 DER).
fn attest() -> Result<(ServerConfig, Arc<Evidence>, Vec<u8>), BoxError> {
    info!("Initializing Nitro Enclave HTTP/3 Server...");

    // Install the default cryptographic provider for rustls 0.23
    let _ = rustls::crypto::ring::default_provider().install_default();

    let key_pair = KeyPair::generate()?;
    let private_key = key_pair.serialize_der();
    info!("Generated ephemeral TLS certificate.");

    let eat_bytes = generate_evidence(&key_pair)?;
    let tls_config = build_tls_config(&key_pair, &eat_bytes)?;
    let evidence = Arc::new(Evidence {
        nitro: eat_bytes.clone(),
        eat: eat_bytes,
    });

    let mut quic_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));
    quic_config.transport_config(Arc::new(transport_config()));
    Ok((quic_config, evidence, private_key))
}

/// QUIC limits for each connection: [`MAX_STREAMS_PER_CONNECTION`] concurrent requests sharing
/// a [`CONNECTION_RECEIVE_WINDOW`], so one peer can't make the server buffer unbounded data.
fn transport_config() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_STREAMS_PER_CONNECTION))
        .receive_window(VarInt::from_u32(CONNECTION_RECEIVE_WINDOW));
    transport
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

/// Drives a single QUIC connection, dispatching each HTTP/3 request to `app`.
async fn handle_connection(incoming: quinn::Incoming, app: Router) {
    let conn = match incoming.await {
        Ok(conn) => conn,
        Err(err) => return warn!("Handshake failed: {err}"),
    };

    let mut h3_conn = match h3::server::builder()
        .max_field_section_size(MAX_REQUEST_HEADERS)
        .build::<_, axum::body::Bytes>(h3_quinn::Connection::new(conn))
        .await
    {
        Ok(h3) => h3,
        Err(e) => return warn!("H3 setup failed: {e}"),
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
    let body = tokio::time::timeout(REQUEST_BODY_TIMEOUT, read_body(&mut stream)).await;
    let response = match body {
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "request body timed out").into_response(),
        Ok(Ok(Some(body))) => match app.call(req.map(|()| axum::body::Body::from(body))).await {
            Ok(response) => response,
            Err(e) => return error!("App call error: {e}"),
        },
        Ok(Ok(None)) => (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response(),
        Ok(Err(e)) => return warn!("Failed to read request body: {e}"),
    };

    let (parts, body) = response.into_parts();
    if let Err(e) = stream
        .send_response(axum::http::Response::from_parts(parts, ()))
        .await
    {
        return warn!("Failed to send response headers: {e}");
    }
    match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) if !bytes.is_empty() => {
            if let Err(e) = stream.send_data(bytes).await {
                return warn!("Failed to send response body: {e}");
            }
        }
        Ok(_) => {}
        Err(e) => error!("Failed to read response body: {e}"),
    }
    if let Err(e) = stream.finish().await {
        warn!("Failed to finish stream: {e}");
    }
}
