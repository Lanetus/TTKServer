//! Tests for the base routes ([`ttk_ra_server::router`]), `POST /evidence` over the mock provider.
#![cfg(feature = "mock")]

#[path = "support/nitro_doc.rs"]
mod nitro_doc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nitro_doc::parse_attestation_document;
use rcgen::KeyPair;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tower_service::Service;
use ttk_core::FreshEvidence;
use ttk_ra_server::attestation::{self, media_type};
use ttk_ra_server::certificate::{CertificateStore, CERT_DNS_NAME};
use ttk_ra_server::router::{build_router, Evidence, MAX_NONCE_LEN};
use ttk_ra_server::server::create_cert_with_attestation;
use ttk_ra_server::Cmw;
use x509_parser::prelude::{FromDer, X509Certificate};

/// A router over the mock provider, and the certificate it presents.
fn router() -> (Router, CertificateDer<'static>) {
    let evidence = Evidence { cmw: Vec::new() };
    let key = KeyPair::generate().unwrap();
    let cert = create_cert_with_attestation(&key, CERT_DNS_NAME, b"evidence", 30).unwrap();
    let cert = CertificateDer::from_pem_slice(cert.as_bytes()).unwrap();
    let certificates = CertificateStore::new(
        cert.clone(),
        &PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap(),
    )
    .unwrap();
    let router = build_router(
        &evidence,
        attestation::by_name("mock").unwrap().into(),
        Arc::new(certificates),
        Router::new(),
    );
    (router, cert)
}

/// Sends `POST /evidence` with `body`, returning the status, the response body and the
/// certificate the server presents.
async fn post_evidence(body: Vec<u8>) -> (StatusCode, Vec<u8>, CertificateDer<'static>) {
    let request = Request::post("/evidence").body(Body::from(body)).unwrap();
    let (mut router, cert) = router();
    let response = router.call(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, body.to_vec(), cert)
}

#[tokio::test]
async fn evidence_carries_the_nonce() {
    let nonce = b"client-nonce-0123456789".to_vec();
    let (status, body, cert) = post_evidence(nonce.clone()).await;
    assert_eq!(status, StatusCode::OK);

    let fresh = FreshEvidence::from_cbor_bytes(&STANDARD.decode(body).unwrap()).unwrap();
    assert_eq!(fresh.certificate, cert.to_vec());
    let Cmw::Record(record) = fresh.evidence else {
        panic!("Nitro evidence should be a CMW record");
    };
    assert_eq!(record.media_type(), Some(media_type::AWS_NITRO));
    let doc = parse_attestation_document(&record.value).unwrap();
    assert_eq!(doc.nonce.unwrap().to_vec(), nonce);

    // Bound, like the startup Evidence, to the certificate's key.
    let (_, parsed) = X509Certificate::from_der(&cert).unwrap();
    assert_eq!(
        doc.user_data.unwrap().to_vec(),
        Sha256::digest(parsed.public_key().raw).to_vec()
    );
}

#[tokio::test]
async fn evidence_rejects_empty_and_oversized_nonces() {
    assert_eq!(post_evidence(Vec::new()).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        post_evidence(vec![0; MAX_NONCE_LEN + 1]).await.0,
        StatusCode::BAD_REQUEST
    );
}
