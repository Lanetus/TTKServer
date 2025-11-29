use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request};
use hyper::service::service_fn; // Removed make_service_fn
use hyper::{Body, Method, Request as HyperRequest, Response as HyperResponse, StatusCode};
use rcgen::generate_simple_self_signed;
use rustls::{Certificate, PrivateKey, ServerConfig};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tokio_rustls::TlsAcceptor;
use tokio_vsock::VsockListener;

// Standard constant for "Listen on any CID"
const CID_ANY: u32 = libc::VMADDR_CID_ANY;
const PORT: u32 = 5005;

/// Generates a self-signed certificate and private key.
fn generate_identity() -> (Vec<Certificate>, PrivateKey, Vec<u8>) {
    let subject_alt_names = vec!["localhost".to_string(), "enclave.local".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();

    let cert_der = cert.serialize_der().unwrap();
    let priv_key_der = cert.serialize_private_key_der();

    let rustls_cert = Certificate(cert_der.clone());
    let rustls_key = PrivateKey(priv_key_der);

    (vec![rustls_cert], rustls_key, cert_der)
}

/// Requests an Attestation Document from the Nitro Security Module
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
    attestation_doc: Arc<Vec<u8>>,
) -> Result<HyperResponse<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/attestation") => {
            let b64_doc = STANDARD.encode(&*attestation_doc);
            Ok(HyperResponse::new(Body::from(b64_doc)))
        }
        (&Method::GET, "/hello") => {
            Ok(HyperResponse::new(Body::from("Hello from inside the VSOCK Enclave!")))
        }
        _ => {
            let mut not_found = HyperResponse::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing Nitro Enclave VSOCK Server...");

    // 1. Generate TLS Identity
    let (certs, key, cert_der_bytes) = generate_identity();
    println!("Generated ephemeral TLS certificate.");

    // 2. Get Attestation Document
    let attestation_doc = get_attestation_doc(&cert_der_bytes);
    let attestation_doc = Arc::new(attestation_doc);
    println!("Retrieved Attestation Document.");

    // 3. Configure TLS
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    // 4. Bind to VSOCK
    let mut listener = VsockListener::bind(CID_ANY, PORT).expect("Failed to bind VSOCK listener");
    println!("Listening on VSOCK CID: Any, Port: {}", PORT);

    // 5. Server Loop
    loop {
        // Fix from previous step: Destructure the tuple (stream, addr)
        match listener.accept().await {
            Ok((stream, _addr)) => {

                let acceptor = acceptor.clone();
                let doc = attestation_doc.clone();

                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            // FIX: Use service_fn directly.
                            // We don't need make_service_fn because we already have the connection.
                            let service = service_fn(move |req| {
                                handle_request(req, doc.clone())
                            });

                            // serve_connection takes the IO stream and the service directly
                            if let Err(e) = hyper::server::conn::Http::new()
                                .serve_connection(tls_stream, service)
                                .await
                            {
                                eprintln!("Error serving connection: {}", e);
                            }
                        }
                        Err(e) => eprintln!("TLS Handshake failed: {}", e),
                    }
                });
            }
            Err(e) => eprintln!("VSOCK accept error: {}", e),
        }
    }
}
