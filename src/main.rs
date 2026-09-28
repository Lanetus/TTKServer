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

use axum::{routing::get, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hyper::service::Service;
use log::info;
use quinn::{Endpoint, ServerConfig};
use std::sync::Arc;
use ttk_server::{generate_identity, Attestation, AttestationParams, AttestationProcess};

/// Evidence for this instance, in the formats served over HTTP.
#[derive(Clone, Debug)]
pub struct Evidence {
    /// Raw NSM Attestation Document (COSE_Sign1).
    pub nitro: Vec<u8>,
    /// The same document, wrapped as an RFC 9711 EAT claims-set.
    pub eat: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("Initializing Nitro Enclave HTTP/3 Server...");

    // Install the default cryptographic provider for rustls 0.23
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Generate RA-TLS ephemeral certificate and private key
    let (certs, private_key, cert_der_bytes) = generate_identity();
    info!("Generated ephemeral TLS certificate.");

    let params = AttestationParams::new().with_user_data_hash(&cert_der_bytes);

    // 2b. Wrap as an RFC 9711 EAT claims-set
    let eat_doc = AttestationProcess::generate_document(&params);
    let eat_byte = eat_doc.to_cbor_bytes()?;
    info!(
        "Wrapped Attestation Document as RFC 9711 EAT token ({} bytes).",
        eat_byte.len()
    );

    let evidence = Arc::new(Evidence {
        nitro: eat_byte.clone(),
        eat: eat_byte.clone(),
    });

    let nitro_b64 = STANDARD.encode(&evidence.nitro);
    let eat_b64 = STANDARD.encode(&evidence.eat);

    // 3. Build Axum router serving HTTP/3 endpoints
    let app: Router = Router::new()
        .route("/", get(|| async { "Hello from Enclave over HTTP/3!" }))
        .route("/hello", get(|| async { "Hello from inside the Enclave!" }))
        .route("/evidence", {
            let b64 = nitro_b64.clone();
            get(move || {
                let b64 = b64.clone();
                async move { b64 }
            })
        })
        .route("/attestation", {
            let b64 = nitro_b64.clone();
            get(move || {
                let b64 = b64.clone();
                async move { b64 }
            })
        })
        .route("/evidence.eat", {
            let b64 = eat_b64.clone();
            get(move || {
                let b64 = b64.clone();
                async move { b64 }
            })
        });

    // 4. Configure Rustls with RA-TLS cert
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;

    // Enable ALPN for HTTP/3 ("h3")
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];

    // 5. Wrap Rustls config into Quinn (QUIC)
    let quic_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    let endpoint = Endpoint::server(quic_config, "0.0.0.0:4433".parse()?)?;
    info!("Server listening on 0.0.0.0:4433 (QUIC/HTTP/3)");

    // 6. Drive incoming QUIC connections and HTTP/3 streams
    while let Some(incoming) = endpoint.accept().await {
        let app = app.clone();

        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(err) => return eprintln!("Handshake failed: {err}"),
            };

            let mut h3_conn = match h3::server::Connection::<_, axum::body::Bytes>::new(
                h3_quinn::Connection::new(conn),
            )
            .await
            {
                Ok(h3) => h3,
                Err(e) => return eprintln!("H3 setup failed: {e}"),
            };

            while let Ok(Some((req, mut stream))) = h3_conn.accept().await {
                let mut app = app.clone();
                tokio::spawn(async move {
                    let req = req.map(|_| axum::body::Body::empty());
                    match app.call(req).await {
                        Ok(response) => {
                            let (parts, body) = response.into_parts();
                            let h3_response = axum::http::Response::from_parts(parts, ());
                            if let Err(e) = stream.send_response(h3_response).await {
                                eprintln!("Failed to send response headers: {e}");
                                return;
                            }
                            match axum::body::to_bytes(body, usize::MAX).await {
                                Ok(bytes) => {
                                    if !bytes.is_empty() {
                                        if let Err(e) = stream.send_data(bytes).await {
                                            eprintln!("Failed to send response body: {e}");
                                            return;
                                        }
                                    }
                                }
                                Err(e) => eprintln!("Failed to read response body: {e}"),
                            }
                            if let Err(e) = stream.finish().await {
                                eprintln!("Failed to finish stream: {e}");
                            }
                        }
                        Err(e) => eprintln!("App call error: {e}"),
                    }
                });
            }
        });
    }

    Ok(())
}
