//! RATS (RFC 9334) role mapping for this server:
//!
//! - **Attester**: this process, running inside a Nitro Enclave. It holds a
//!   hardware-rooted identity via the Nitro Security Module (NSM).
//! - **Evidence**: the NSM Attestation Document returned by [`get_attestation_doc`],
//!   with `user_data` bound to the SHA-256 hash of the ephemeral TLS certificate so a
//!   Relying Party can tie the Evidence to the specific TLS session it negotiates.
//! - **Endorsements**: the AWS Nitro certificate chain embedded in the Attestation
//!   Document, rooted at the AWS Nitro Enclaves root certificate.
//! - **Verifier** / **Relying Party**: the external client fetching Evidence over
//!   `/evidence` (RATS-standard name; `/attestation` kept as an alias), or as an
//!   RFC 9711 EAT over `/evidence.eat`. Appraisal against Reference Values (expected
//!   PCR measurements) and issuance of an Attestation Result happen outside this
//!   server.

use crate::{attestation, AttestationParams};
use axum::{routing::get, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hyper::service::Service;
use log::info;
use quinn::{Endpoint, ServerConfig};
use rcgen::{CertificateParams, CustomExtension, KeyPair, SanType};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

/// Evidence for this instance, in the formats served over HTTP.
#[derive(Clone, Debug)]
pub struct Evidence {
    /// Raw NSM Attestation Document (COSE_Sign1).
    pub nitro: Vec<u8>,
    /// The same document, wrapped as an RFC 9711 EAT claims-set.
    pub eat: Vec<u8>,
}

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

type BoxError = Box<dyn std::error::Error>;

const LISTEN_ADDR: &str = "0.0.0.0:4433";

/// Runs the server: attests, builds the RA-TLS identity, then serves HTTP/3 until the endpoint closes.
pub async fn run() -> Result<(), BoxError> {
    info!("Initializing Nitro Enclave HTTP/3 Server...");

    // Install the default cryptographic provider for rustls 0.23
    let _ = rustls::crypto::ring::default_provider().install_default();

    let key_pair = KeyPair::generate()?;
    info!("Generated ephemeral TLS certificate.");

    let eat_bytes = generate_evidence(&key_pair)?;
    let tls_config = build_tls_config(&key_pair, &eat_bytes)?;
    let app = build_router(Arc::new(Evidence {
        nitro: eat_bytes.clone(),
        eat: eat_bytes,
    }));

    serve(app, tls_config).await
}

/// Requests evidence from the detected attestation provider, bound to the TLS key,
/// and returns it as CBOR-encoded RFC 9711 EAT bytes.
fn generate_evidence(key_pair: &KeyPair) -> Result<Vec<u8>, BoxError> {
    let params = AttestationParams::new().with_user_data_hash(&key_pair.serialized_der());

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

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?.ok_or("Missing key")?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    // Enable ALPN for HTTP/3 ("h3")
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(config)
}

/// Builds the Axum router serving the evidence endpoints.
fn build_router(evidence: Arc<Evidence>) -> Router {
    let nitro_b64 = STANDARD.encode(&evidence.nitro);
    let eat_b64 = STANDARD.encode(&evidence.eat);

    let text = |body: String| get(move || async move { body });

    Router::new()
        .route("/", get(|| async { "Hello from Enclave over HTTP/3!" }))
        .route("/hello", get(|| async { "Hello from inside the Enclave!" }))
        .route("/evidence", text(nitro_b64.clone()))
        .route("/attestation", text(nitro_b64))
        .route("/evidence.eat", text(eat_b64))
}

/// Accepts QUIC connections and serves `app` over HTTP/3.
async fn serve(app: Router, tls_config: rustls::ServerConfig) -> Result<(), BoxError> {
    let quic_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));

    let endpoint = Endpoint::server(quic_config, LISTEN_ADDR.parse()?)?;
    info!("Server listening on {LISTEN_ADDR} (QUIC/HTTP/3)");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(handle_connection(incoming, app.clone()));
    }
    Ok(())
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
        tokio::spawn(async move {
            let req = req.map(|_| axum::body::Body::empty());
            respond(app, req, stream).await;
        });
    }
}

/// Runs `req` through `app` and streams the response back over the HTTP/3 `stream`.
async fn respond(
    mut app: Router,
    req: axum::http::Request<axum::body::Body>,
    mut stream: h3::server::RequestStream<
        h3_quinn::BidiStream<axum::body::Bytes>,
        axum::body::Bytes,
    >,
) {
    let response = match app.call(req).await {
        Ok(response) => response,
        Err(e) => return eprintln!("App call error: {e}"),
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
