//! Tests of the root node's `GET /root-attestation`, on a free local port with mock attestation.
//!
//! The root node does not depend on `ttk-ra-client`, so these tests use a minimal HTTP/3 client
//! that skips RA-TLS verification: they check the routes, not the attestation.

use axum::http::{HeaderMap, Request, StatusCode};
use bytes::{Buf, Bytes};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::DigitallySignedStruct;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::net::SocketAddr;
use std::sync::Arc;
use ttk_core::image_trust::ImageTrustStore;
use ttk_ra_server::server::Server;
use ttk_root::{FileImageTrustStore, Root, RootAttestation, ROOT_ATTESTATION_PATH};

const PCR0_A: &str = "7807833a90cc86f5a853a1f49043a568f3428f6b03eb983aed99899fbfa77d6b86b34fa934e318dd3741debca32c0aba";
const PCR0_B: &str = "1de927770d7a1c250ba364440947226ed9af7250ae25fdad391c3cd87d0044b1e4a4e96810bc8f2dfc9160fcf0742c8d";

/// Starts `root` on a free local port and returns its address.
fn start(root: Root) -> SocketAddr {
    let addr = root.local_addr().unwrap();
    tokio::spawn(async move { root.serve().await.unwrap() });
    addr
}

/// Accepts any server certificate. Test-only: the node's RA-TLS cert is self-signed.
#[derive(Debug)]
struct AcceptAnyCert;

/// Skips certificate validation but still checks handshake signatures.
impl ServerCertVerifier for AcceptAnyCert {
    /// Accepts the certificate unconditionally.
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// Verifies a TLS 1.2 handshake signature.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &algorithms())
    }

    /// Verifies a TLS 1.3 handshake signature.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &algorithms())
    }

    /// The `ring` provider's signature schemes.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        algorithms().supported_schemes()
    }
}

/// Signature algorithms of the `ring` provider.
fn algorithms() -> rustls::crypto::WebPkiSupportedAlgorithms {
    rustls::crypto::ring::default_provider().signature_verification_algorithms
}

/// A response: status, headers and body.
struct Response {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// Sends `GET path` over HTTP/3 to the node at `addr` on a fresh connection.
async fn get(addr: SocketAddr, path: &str) -> Response {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    )));
    let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driver =
        tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

    let request = Request::get(format!("https://localhost{path}"))
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        let bytes: Bytes = chunk.copy_to_bytes(chunk.remaining());
        body.extend_from_slice(&bytes);
    }

    drop(send_request);
    driver.abort();
    endpoint.close(0u32.into(), b"done");
    Response {
        status: response.status(),
        headers: response.headers().clone(),
        body,
    }
}

/// Fetches and decodes `GET /root-attestation` from the node at `addr`.
async fn fetch(addr: SocketAddr) -> RootAttestation {
    let response = get(addr, ROOT_ATTESTATION_PATH).await;
    assert_eq!(response.status, 200);
    assert_eq!(response.headers["content-type"], "application/json");
    serde_json::from_slice(&response.body).unwrap()
}

/// Formats `bytes` as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn root_attestation_serves_the_builtin_accepted_images() {
    let addr = start(Root::bind("127.0.0.1:0".parse().unwrap()).unwrap());

    let expected: Vec<String> = FileImageTrustStore::builtin()
        .nitro_image_allowlist()
        .iter()
        .map(|pcr0| hex_encode(pcr0))
        .collect();
    let body = fetch(addr).await;
    assert_eq!(body.hash_algorithm, "SHA384");
    assert!(!body.pcr0.is_empty());
    assert_eq!(body.pcr0, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn root_attestation_serves_a_custom_image_trust_store() {
    let images = FileImageTrustStore::parse(&format!("{PCR0_A}\n{PCR0_B}")).unwrap();
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = start(Root::with_image_trust_store(server, &images));

    let body = fetch(addr).await;
    assert_eq!(body.pcr0, vec![PCR0_A, PCR0_B]);
}

#[tokio::test(flavor = "multi_thread")]
async fn base_routes_are_still_served() {
    let addr = start(Root::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    assert_eq!(get(addr, "/evidence.cmw").await.status, 200);
    assert_eq!(get(addr, "/").await.status, 200);
}

#[test]
fn builtin_nitro_image_allowlist_is_valid_and_not_empty() {
    assert!(!FileImageTrustStore::builtin()
        .nitro_image_allowlist()
        .is_empty());
}
