//! Tests of the test certificate authority ([`ttk_root::auth`], bin `auth-test`): issuing
//! certificates for RA-TLS keys, appraising fresh Evidence, and the end-to-end
//! `POST /evidence` + `POST /certificate` flow against a root node with mock attestation.
#![cfg(feature = "auth-test")]

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, DnValue, IsCa, KeyPair,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, UnixTime};
use rustls::RootCertStore;
use std::net::SocketAddr;
use std::sync::Arc;
use ttk_ra_client::verifier::{nitro, Policy, VerifiedEvidence};
use ttk_ra_client::{ImageTrustStore, TrustStore};
use ttk_ra_server::certificate::{CertificateError, CertificateStore, CERT_DNS_NAME};
use ttk_ra_server::server::{create_cert_with_attestation, Server};
use ttk_ra_server::{attestation, AttestationParams};
use ttk_root::auth::{
    authorize, pem, verify_fresh_evidence, AuthorizeOptions, CertificateAuthority,
};
use ttk_root::{FileImageTrustStore, Root};

/// Options accepting mock attestation.
fn mock_options() -> AuthorizeOptions {
    AuthorizeOptions {
        allow_mock: true,
        images: None,
    }
}

/// A trust store holding only `ca`.
fn roots(ca: &CertificateAuthority) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    roots
}

/// A certificate store presenting a fresh self-signed RA-TLS certificate carrying `evidence`.
fn ra_tls_store(evidence: &[u8]) -> CertificateStore {
    let key = KeyPair::generate().unwrap();
    let pem = create_cert_with_attestation(&key, CERT_DNS_NAME, evidence, 30).unwrap();
    let cert = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
    let private_key = PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).unwrap();
    CertificateStore::new(cert, &private_key).unwrap()
}

/// Starts a root node on a free local port trusting `ca` (if any); returns its address.
fn start_node(ca: Option<&CertificateAuthority>) -> SocketAddr {
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    if let Some(ca) = ca {
        server.set_trusted_roots(roots(ca)).unwrap();
    }
    let root = Root::new(server);
    let addr = root.local_addr().unwrap();
    tokio::spawn(async move { root.serve().await.unwrap() });
    addr
}

/// Completes a QUIC handshake with the node at `addr`, validating its certificate against `ca`
/// for [`CERT_DNS_NAME`], and returns the chain it presented.
async fn presented_chain(
    addr: SocketAddr,
    ca: &CertificateAuthority,
) -> Vec<CertificateDer<'static>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots(ca))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    ));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect(addr, CERT_DNS_NAME)
        .unwrap()
        .await
        .unwrap();
    let chain = connection
        .peer_identity()
        .unwrap()
        .downcast::<Vec<CertificateDer<'static>>>()
        .unwrap();
    connection.close(0u32.into(), b"done");
    *chain
}

/// Mock Nitro Evidence (CBOR CMW) carrying `params`.
fn mock_evidence(params: &AttestationParams) -> Vec<u8> {
    attestation::by_name("mock")
        .unwrap()
        .generate_document(params)
        .unwrap()
        .to_cbor_bytes()
}

/// Appraises the mock Nitro document in `cmw` as the RA-TLS certificate's Evidence.
fn appraise(cmw: &[u8]) -> VerifiedEvidence {
    let ttk_core::Cmw::Record(record) = ttk_core::Cmw::from_cbor_bytes(cmw).unwrap() else {
        panic!("not a record");
    };
    nitro::verify(
        &record.value,
        UnixTime::now(),
        &TrustStore::builtin(),
        &FileImageTrustStore::builtin(),
        mock_policy(),
    )
    .unwrap()
}

/// Policy accepting mock attestation.
fn mock_policy() -> Policy {
    Policy {
        allow_mock: true,
        allow_debug: false,
    }
}

#[test]
fn issued_certificate_replaces_the_ra_tls_certificate() {
    let ca = CertificateAuthority::generate("Test CA").unwrap();
    let store = ra_tls_store(b"evidence");
    store.set_trusted_roots(roots(&ca)).unwrap();

    let chain = ca.issue(&store.current_chain()[0]).unwrap();
    assert_eq!(chain.len(), 1, "a root CA is not sent in the chain");
    store.replace(chain.clone()).unwrap();
    assert_eq!(store.current_chain(), chain);
}

#[test]
fn issued_certificate_for_another_key_is_refused() {
    let ca = CertificateAuthority::generate("Test CA").unwrap();
    let store = ra_tls_store(b"evidence");
    store.set_trusted_roots(roots(&ca)).unwrap();

    let other = ra_tls_store(b"evidence").current_chain();
    let chain = ca.issue(&other[0]).unwrap();
    assert!(matches!(
        store.replace(chain),
        Err(CertificateError::Mismatch(_))
    ));
}

#[test]
fn issuing_requires_the_attestation_extension() {
    let ca = CertificateAuthority::generate("Test CA").unwrap();
    let key = KeyPair::generate().unwrap();
    let plain = CertificateParams::new(vec![CERT_DNS_NAME.to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    assert!(ca.issue(plain.der()).is_err());
}

#[test]
fn ca_round_trips_through_pem() {
    let generated = CertificateAuthority::generate("Test CA").unwrap();
    let ca = CertificateAuthority::from_pem(&generated.cert_pem(), &generated.key_pem()).unwrap();
    let store = ra_tls_store(b"evidence");
    store.set_trusted_roots(roots(&generated)).unwrap();
    store
        .replace(ca.issue(&store.current_chain()[0]).unwrap())
        .unwrap();
}

#[test]
fn ca_key_must_match_its_certificate() {
    let a = CertificateAuthority::generate("A").unwrap();
    let b = CertificateAuthority::generate("B").unwrap();
    assert!(CertificateAuthority::from_pem(&a.cert_pem(), &b.key_pem()).is_err());
}

#[test]
fn intermediate_ca_with_its_own_subject_sends_its_certificate() {
    // A root and an intermediate with a multi-attribute, PrintableString subject.
    let root_key = KeyPair::generate().unwrap();
    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = root_params.self_signed(&root_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CountryName,
        DnValue::PrintableString("GR".try_into().unwrap()),
    );
    params
        .distinguished_name
        .push(DnType::OrganizationName, "TTK");
    params
        .distinguished_name
        .push(DnType::CommonName, "TTK Intermediate");
    let intermediate = params.signed_by(&key, &root, &root_key).unwrap();

    let ca = CertificateAuthority::from_pem(&intermediate.pem(), &key.serialize_pem()).unwrap();
    let store = ra_tls_store(b"evidence");
    let mut trusted = RootCertStore::empty();
    trusted.add(root.der().clone()).unwrap();
    store.set_trusted_roots(trusted).unwrap();

    let chain = ca.issue(&store.current_chain()[0]).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(&chain[1], intermediate.der());
    store.replace(chain).unwrap();
}

#[test]
fn pem_chain_parses_back() {
    let ca = CertificateAuthority::generate("Test CA").unwrap();
    let chain = vec![ca.cert_der().clone(), ca.cert_der().clone()];
    let parsed = CertificateDer::pem_slice_iter(pem(&chain).as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(parsed, chain);
}

#[test]
fn fresh_evidence_must_carry_the_nonce() {
    let cert_evidence = appraise(&mock_evidence(&AttestationParams::default()));
    let images = FileImageTrustStore::builtin();
    let fresh = mock_evidence(&AttestationParams {
        nonce: Some(b"nonce".to_vec()),
        ..AttestationParams::default()
    });

    verify_fresh_evidence(&fresh, b"nonce", &cert_evidence, &images, mock_policy()).unwrap();
    let err = verify_fresh_evidence(&fresh, b"other", &cert_evidence, &images, mock_policy())
        .unwrap_err();
    assert!(err.contains("nonce"), "{err}");
}

#[test]
fn fresh_mock_evidence_is_refused_without_allow_mock() {
    let cert_evidence = appraise(&mock_evidence(&AttestationParams::default()));
    let fresh = mock_evidence(&AttestationParams {
        nonce: Some(b"nonce".to_vec()),
        ..AttestationParams::default()
    });
    let images: &dyn ImageTrustStore = &FileImageTrustStore::builtin();
    assert!(
        verify_fresh_evidence(&fresh, b"nonce", &cert_evidence, images, Policy::default()).is_err()
    );
}

#[test]
fn fresh_evidence_must_match_the_certificate_measurements() {
    let mut cert_evidence = appraise(&mock_evidence(&AttestationParams::default()));
    cert_evidence
        .measurements
        .insert("pcr0".into(), vec![1u8; 48]);
    let fresh = mock_evidence(&AttestationParams {
        nonce: Some(b"nonce".to_vec()),
        ..AttestationParams::default()
    });
    let err = verify_fresh_evidence(
        &fresh,
        b"nonce",
        &cert_evidence,
        &FileImageTrustStore::builtin(),
        mock_policy(),
    )
    .unwrap_err();
    assert!(err.contains("measurements"), "{err}");
}

#[tokio::test]
async fn authorize_installs_the_issued_certificate() {
    let ca = CertificateAuthority::generate("Test CA").unwrap();
    let addr = start_node(Some(&ca));

    let chain = authorize(addr, "localhost", &ca, &mock_options())
        .await
        .unwrap();

    // New connections get the CA-issued chain, valid under Web PKI rules for the CA.
    assert_eq!(presented_chain(addr, &ca).await, chain);
}

#[tokio::test]
async fn authorize_fails_when_the_node_does_not_trust_the_ca() {
    let trusted = CertificateAuthority::generate("Trusted CA").unwrap();
    let other = CertificateAuthority::generate("Other CA").unwrap();
    let addr = start_node(Some(&trusted));

    let err = authorize(addr, "localhost", &other, &mock_options())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("403"), "{err}");
}

#[tokio::test]
async fn authorize_fails_when_the_node_trusts_no_ca() {
    let ca = CertificateAuthority::generate("Test CA").unwrap();
    let addr = start_node(None);

    let err = authorize(addr, "localhost", &ca, &mock_options())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("503"), "{err}");
}

#[tokio::test]
async fn authorize_refuses_mock_attestation_by_default() {
    let ca = CertificateAuthority::generate("Test CA").unwrap();
    let addr = start_node(Some(&ca));

    assert!(
        authorize(addr, "localhost", &ca, &AuthorizeOptions::default())
            .await
            .is_err()
    );
}
