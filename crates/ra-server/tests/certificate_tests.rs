//! Tests for replacing the RA-TLS certificate with a CA-issued one (`POST /certificate`,
//! [`ttk_ra_server::certificate`]).
#![cfg(feature = "mock")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, IsCa, KeyPair, SanType,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use std::sync::Arc;
use tower_service::Service;
use ttk_ra_server::attestation;
use ttk_ra_server::certificate::{CertificateStore, CERT_DNS_NAME};
use ttk_ra_server::router::{build_router, Evidence};
use ttk_ra_server::server::{create_cert_with_attestation, ATTESTATION_OID};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Evidence embedded in the test RA-TLS certificate.
const EVIDENCE: &[u8] = b"mock evidence";

/// A certificate authority: its certificate and key.
struct Ca {
    cert: Certificate,
    key: KeyPair,
}

impl Ca {
    /// A self-signed root CA.
    fn root() -> Self {
        let key = KeyPair::generate().unwrap();
        let cert = ca_params().self_signed(&key).unwrap();
        Self { cert, key }
    }

    /// An intermediate CA issued by `self`.
    fn intermediate(&self) -> Self {
        let key = KeyPair::generate().unwrap();
        let cert = ca_params().signed_by(&key, &self.cert, &self.key).unwrap();
        Self { cert, key }
    }

    /// Issues a leaf for `key` naming `dns_name` and carrying `evidence` as the attestation
    /// extension.
    fn issue(&self, key: &KeyPair, dns_name: &str, evidence: &[u8]) -> CertificateDer<'static> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::DnsName(dns_name.try_into().unwrap())];
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                ATTESTATION_OID,
                octet_string(evidence),
            ));
        params
            .signed_by(key, &self.cert, &self.key)
            .unwrap()
            .der()
            .clone()
    }

    /// A trust store holding only this CA.
    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.cert.der().clone()).unwrap();
        roots
    }
}

/// Parameters of a CA certificate.
fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
}

/// DER OCTET STRING wrapping `data` (short form, as the server encodes small evidence).
fn octet_string(data: &[u8]) -> Vec<u8> {
    let mut der = vec![0x04, data.len() as u8];
    der.extend_from_slice(data);
    der
}

/// The RA-TLS key, its certificate store presenting the self-signed certificate, and a router
/// serving it.
fn setup() -> (KeyPair, Arc<CertificateStore>, Router) {
    let key = KeyPair::generate().unwrap();
    let pem = create_cert_with_attestation(&key, CERT_DNS_NAME, EVIDENCE, 30).unwrap();
    let cert = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
    let private_key = PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap();
    let store = Arc::new(CertificateStore::new(cert, &private_key).unwrap());
    let router = build_router(
        &Evidence { cmw: Vec::new() },
        attestation::by_name("mock").unwrap().into(),
        store.clone(),
        Router::new(),
    );
    (key, store, router)
}

/// PEM encoding of `chain`.
fn pem(chain: &[CertificateDer<'_>]) -> Vec<u8> {
    chain
        .iter()
        .map(|cert| {
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                STANDARD.encode(cert)
            )
        })
        .collect::<String>()
        .into_bytes()
}

/// Sends `POST /certificate` with `body`, returning the status.
async fn post_certificate(router: &mut Router, body: Vec<u8>) -> StatusCode {
    let request = Request::post("/certificate")
        .body(Body::from(body))
        .unwrap();
    router.call(request).await.unwrap().status()
}

#[test]
fn self_signed_certificate_carries_the_evidence_extension() {
    let (_, store, _) = setup();
    let chain = store.current_chain();
    let (_, cert) = X509Certificate::from_der(&chain[0]).unwrap();
    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid.to_id_string() == "1.3.6.1.4.1.99999.1")
        .unwrap();
    assert_eq!(ext.value, octet_string(EVIDENCE));
}

#[tokio::test]
async fn accepts_the_current_certificate_issued_by_a_trusted_root() {
    let (key, store, mut router) = setup();
    let ca = Ca::root();
    store.set_trusted_roots(ca.roots()).unwrap();

    let leaf = ca.issue(&key, CERT_DNS_NAME, EVIDENCE);
    let status = post_certificate(&mut router, leaf.to_vec()).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(store.current_chain(), vec![leaf]);
}

#[tokio::test]
async fn accepts_a_pem_chain_through_an_intermediate() {
    let (key, store, mut router) = setup();
    let root = Ca::root();
    let intermediate = root.intermediate();
    store.set_trusted_roots(root.roots()).unwrap();

    let chain = vec![
        intermediate.issue(&key, CERT_DNS_NAME, EVIDENCE),
        intermediate.cert.der().clone(),
    ];
    let status = post_certificate(&mut router, pem(&chain)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(store.current_chain(), chain);
}

#[tokio::test]
async fn refuses_a_chain_missing_its_intermediate() {
    let (key, store, mut router) = setup();
    let root = Ca::root();
    let intermediate = root.intermediate();
    store.set_trusted_roots(root.roots()).unwrap();

    let leaf = intermediate.issue(&key, CERT_DNS_NAME, EVIDENCE);
    assert_eq!(
        post_certificate(&mut router, leaf.to_vec()).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn refuses_a_certificate_from_an_untrusted_root() {
    let (key, store, mut router) = setup();
    let before = store.current_chain();
    store.set_trusted_roots(Ca::root().roots()).unwrap();

    let leaf = Ca::root().issue(&key, CERT_DNS_NAME, EVIDENCE);
    assert_eq!(
        post_certificate(&mut router, leaf.to_vec()).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(store.current_chain(), before);
}

#[tokio::test]
async fn refuses_a_certificate_for_another_name() {
    let (key, store, mut router) = setup();
    let ca = Ca::root();
    store.set_trusted_roots(ca.roots()).unwrap();

    let leaf = ca.issue(&key, "other.internal", EVIDENCE);
    assert_eq!(
        post_certificate(&mut router, leaf.to_vec()).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn refuses_a_certificate_for_another_key() {
    let (_, store, mut router) = setup();
    let ca = Ca::root();
    store.set_trusted_roots(ca.roots()).unwrap();

    let leaf = ca.issue(&KeyPair::generate().unwrap(), CERT_DNS_NAME, EVIDENCE);
    assert_eq!(
        post_certificate(&mut router, leaf.to_vec()).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn refuses_a_certificate_with_other_evidence() {
    let (key, store, mut router) = setup();
    let ca = Ca::root();
    store.set_trusted_roots(ca.roots()).unwrap();

    let leaf = ca.issue(&key, CERT_DNS_NAME, b"other evidence");
    assert_eq!(
        post_certificate(&mut router, leaf.to_vec()).await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn refuses_everything_without_trusted_roots() {
    let (key, _, mut router) = setup();
    let leaf = Ca::root().issue(&key, CERT_DNS_NAME, EVIDENCE);
    assert_eq!(
        post_certificate(&mut router, leaf.to_vec()).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn refuses_a_malformed_body() {
    let (_, store, mut router) = setup();
    store.set_trusted_roots(Ca::root().roots()).unwrap();
    assert_eq!(
        post_certificate(&mut router, b"not a certificate".to_vec()).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_certificate(&mut router, Vec::new()).await,
        StatusCode::BAD_REQUEST
    );
}
