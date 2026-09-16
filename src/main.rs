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
mod eat;

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hyper::service::service_fn; // Removed make_service_fn
use hyper::{Body, Method, Request as HyperRequest, Response as HyperResponse, StatusCode};
use log::{error, info};
use rcgen::generate_simple_self_signed;
use rustls::{Certificate, PrivateKey, ServerConfig};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_vsock::VsockListener;

// Standard constant for "Listen on any CID"
const CID_ANY: u32 = libc::VMADDR_CID_ANY;
const PORT: u32 = 5005;

/// Evidence for this instance, in the formats served over HTTP.
struct Evidence {
    /// Raw NSM Attestation Document (COSE_Sign1).
    nitro: Vec<u8>,
    /// The same document, wrapped as an RFC 9711 EAT claims-set.
    eat: Vec<u8>,
}

/// Generates a self-signed certificate and private key.
fn generate_identity() -> (Vec<Certificate>, PrivateKey, Vec<u8>) {
    let subject_alt_names = vec!["localhost".to_string(), "enclave.local".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();

    let cert_der = cert.serialize_der().unwrap();
    let private_key_der = cert.serialize_private_key_der();

    let rustls_cert = Certificate(cert_der.clone());
    let rustls_key = PrivateKey(private_key_der);

    (vec![rustls_cert], rustls_key, cert_der)
}

/// Requests an Attestation Document (RATS Evidence) from the Nitro Security Module,
/// binding it to this instance's TLS certificate.
fn get_attestation_doc(cert_der: &[u8]) -> Vec<u8> {
    let nsm_fd = nsm_init();

    // Calculate SHA256 hash of the Certificate
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let cert_hash = hasher.finalize();

    let request = Request::Attestation {
        public_key: None,
        user_data: Some(cert_hash.to_vec().into()),
        nonce: None,
    };

    match nsm_process_request(nsm_fd, request) {
        Response::Attestation { document } => document,
        _ => panic!("NSM did not return an attestation document!"),
    }
}

/// HTTP Request Handler
async fn handle_request(
    req: HyperRequest<Body>,
    evidence: Arc<Evidence>,
) -> Result<HyperResponse<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // RATS Evidence endpoint (RFC 9334 terminology). `/attestation` is kept
        // as an alias for existing clients.
        (&Method::GET, "/evidence") | (&Method::GET, "/attestation") => {
            let b64_doc = STANDARD.encode(&evidence.nitro);
            Ok(HyperResponse::new(Body::from(b64_doc)))
        }
        // Same Evidence, wrapped as an RFC 9711 Entity Attestation Token claims-set
        // (base64-encoded CBOR; see src/eat.rs for the exact construction).
        (&Method::GET, "/evidence.eat") => {
            let b64_eat = STANDARD.encode(&evidence.eat);
            Ok(HyperResponse::new(Body::from(b64_eat)))
        }
        (&Method::GET, "/hello") => Ok(HyperResponse::new(Body::from(
            "Hello from inside the VSOCK Enclave!",
        ))),
        _ => {
            let mut not_found = HyperResponse::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    error!("Initializing Nitro Enclave VSOCK Server...");

    // 1. Generate TLS Identity
    let (certs, key, cert_der_bytes) = generate_identity();
    info!("Generated ephemeral TLS certificate.");

    // 2. Get Attestation Document
    let nitro_doc = get_attestation_doc(&cert_der_bytes);
    info!("Retrieved Attestation Document.");

    // 2b. Wrap it as an RFC 9711 EAT claims-set
    let eat_doc = eat::wrap_as_eat(&nitro_doc)?;
    info!("Wrapped Attestation Document as an EAT claims-set.");

    let evidence = Arc::new(Evidence {
        nitro: nitro_doc,
        eat: eat_doc,
    });

    // 3. Configure TLS
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // 4. Bind to VSOCK
    let mut listener = VsockListener::bind(CID_ANY, PORT).expect("Failed to bind VSOCK listener");
    info!("Listening on VSOCK CID: Any, Port: {}", PORT);

    // 5. Server Loop
    loop {
        // Fix from the previous step: Destructure the tuple (stream, addr)
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let acceptor = acceptor.clone();
                let evidence = evidence.clone();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            // FIX: Use service_fn directly.
                            // We don't need make_service_fn because we already have the connection.
                            let service =
                                service_fn(move |req| handle_request(req, evidence.clone()));

                            // serve_connection takes the IO stream and the service directly
                            if let Err(e) = hyper::server::conn::Http::new()
                                .serve_connection(tls_stream, service)
                                .await
                            {
                                error!("Error serving connection: {}", e);
                            }
                        }
                        Err(e) => error!("TLS Handshake failed: {}", e),
                    }
                });
            }
            Err(e) => error!("VSOCK accept error: {}", e),
        }
    }
}
