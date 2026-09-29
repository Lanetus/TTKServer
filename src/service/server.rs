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
//! HTTP routes, including the `POST /faf` relay, live in [`super::router`].

use super::router::{build_router, RelayVerifierFactory, ALLOW_MOCK_RELAY_ENV};
use crate::client::EnclaveCertVerifier;
use crate::{attestation, AttestationParams};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Router;
use bytes::{Buf, Bytes, BytesMut};
use log::{info, warn};
use quinn::{Endpoint, ServerConfig};
use rcgen::{CertificateParams, CustomExtension, KeyPair, SanType};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tower_service::Service;

pub use super::router::Evidence;

/// OID of the X.509 extension carrying the attestation document (placeholder, not a registered PEN).
const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

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

/// Default address the QUIC endpoint binds to, unless [`LISTEN_ADDR_ENV`] overrides it.
const LISTEN_ADDR: &str = "0.0.0.0:4433";

/// Environment variable that overrides [`LISTEN_ADDR`] (a socket address such as
/// `127.0.0.1:4444`).
pub const LISTEN_ADDR_ENV: &str = "TTK_LISTEN_ADDR";

/// Largest request body the server reads; larger requests get `413 Payload Too Large`.
pub const MAX_REQUEST_BODY: usize = 1024 * 1024;

/// Runs the server: attests, builds the RA-TLS identity, then serves HTTP/3 on
/// `TTK_LISTEN_ADDR` (default `0.0.0.0:4433`) until the endpoint closes.
///
/// Relays must present genuine TEE attestation unless `TTK_ALLOW_MOCK_ATTESTATION=1`.
pub async fn run() -> Result<(), BoxError> {
    let listen_addr = std::env::var(LISTEN_ADDR_ENV).unwrap_or_else(|_| LISTEN_ADDR.to_string());
    let listen_addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| format!("invalid {LISTEN_ADDR_ENV} {listen_addr:?}: {e}"))?;
    let mut server = Server::bind(listen_addr)?;
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
