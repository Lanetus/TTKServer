use axum::http::{HeaderMap, StatusCode};
use rustls::client::danger::ServerCertVerifier;
use ttk_server::client::{hex_encode, ClientResponse, EnclaveCertVerifier};

#[test]
fn test_hex_encode() {
    let bytes = [0x00, 0x12, 0xab, 0xff];
    assert_eq!(hex_encode(&bytes), "0012abff");
}

#[test]
fn test_client_response_text() {
    let resp = ClientResponse {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
        body: b"Hello World".to_vec(),
    };
    assert_eq!(resp.text().unwrap(), "Hello World");
}

#[test]
fn test_enclave_cert_verifier() {
    let verifier = EnclaveCertVerifier::new();
    assert!(verifier.received_certificate().is_none());
    assert!(!verifier.supported_verify_schemes().is_empty());
}

#[test]
fn test_extract_attestation_doc() {
    use rcgen::{CertificateParams, CustomExtension, KeyPair};
    use ttk_server::client::extract_attestation_doc;

    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();

    let expected_payload = b"test_attestation_payload_data";
    // Wrap in ASN.1 octet string header (tag 0x04, length 30)
    let mut wrapped = vec![0x04, expected_payload.len() as u8];
    wrapped.extend_from_slice(expected_payload);

    let ext = CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], wrapped);
    params.custom_extensions.push(ext);

    let cert = params.self_signed(&key_pair).unwrap();
    let extracted = extract_attestation_doc(cert.der()).unwrap();
    assert_eq!(extracted, expected_payload);
}

#[cfg(feature = "mock")]
mod attestation_verification {
    use rcgen::KeyPair;
    use rustls::client::danger::ServerCertVerifier;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
    use ttk_server::attestation::by_name;
    use ttk_server::attestation::nitro_doc::{
        create_mock_attestation_document, parse_attestation_document, wrap_as_eat,
    };
    use ttk_server::client::EnclaveCertVerifier;
    use ttk_server::server::create_cert_with_attestation;
    use ttk_server::AttestationParams;

    /// Builds an RA-TLS certificate for `cert_key` carrying mock evidence bound to `bound_key`.
    fn ra_tls_cert(cert_key: &KeyPair, bound_key: &KeyPair) -> CertificateDer<'static> {
        let params = AttestationParams::new().with_user_data_hash(&bound_key.public_key_der());
        let eat = by_name("mock")
            .unwrap()
            .generate_document(&params)
            .unwrap()
            .to_cbor_bytes()
            .unwrap();
        let pem = create_cert_with_attestation(cert_key, "enclave.internal", &eat, 1).unwrap();
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    fn verify(
        verifier: &EnclaveCertVerifier,
        cert: &CertificateDer<'_>,
    ) -> Result<(), rustls::Error> {
        let name = ServerName::try_from("localhost").unwrap();
        verifier
            .verify_server_cert(cert, &[], &name, &[], UnixTime::now())
            .map(|_| ())
    }

    #[test]
    fn accepts_bound_mock_evidence_when_allowed() {
        let key = KeyPair::generate().unwrap();
        let cert = ra_tls_cert(&key, &key);
        let verifier = EnclaveCertVerifier::new().allow_mock();

        verify(&verifier, &cert).expect("mock evidence bound to the cert key should verify");
        assert_eq!(verifier.received_certificate().as_ref(), Some(&cert));
        let doc = verifier.verified_attestation().unwrap();
        assert_eq!(doc.module_id, "aws-nitro-enclaves-mock");
    }

    #[test]
    fn strict_verifier_rejects_mock_evidence() {
        let key = KeyPair::generate().unwrap();
        let cert = ra_tls_cert(&key, &key);
        let verifier = EnclaveCertVerifier::new();

        let err = verify(&verifier, &cert).unwrap_err();
        assert!(
            err.to_string().contains("TTK_ALLOW_MOCK_ATTESTATION"),
            "the error should explain how to accept mock evidence: {err}"
        );
        assert!(verifier.received_certificate().is_none());
    }

    #[test]
    fn mock_evidence_is_signed_through_the_mock_root() {
        let params = AttestationParams::new().with_user_data(vec![1; 32]);
        let doc = parse_attestation_document(&create_mock_attestation_document(&params).unwrap())
            .unwrap();
        assert_eq!(doc.cabundle.len(), 1);
        assert_eq!(
            doc.cabundle[0],
            ttk_server::verifier::TrustStore::builtin().mock_nitro_root
        );
    }

    #[test]
    fn tampered_mock_evidence_is_rejected_even_when_allowed() {
        let key = KeyPair::generate().unwrap();
        let params = AttestationParams::new().with_user_data_hash(&key.public_key_der());
        let mut doc = create_mock_attestation_document(&params).unwrap();
        let last = doc.len() - 1;
        doc[last] ^= 1; // last byte of the COSE signature
        let eat = wrap_as_eat(&doc).unwrap().to_cbor_bytes().unwrap();
        let pem = create_cert_with_attestation(&key, "enclave.internal", &eat, 1).unwrap();
        let cert = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();

        let err = verify(&EnclaveCertVerifier::new().allow_mock(), &cert).unwrap_err();
        assert!(err.to_string().contains("signature is invalid"), "{err}");
    }

    #[test]
    fn rejects_evidence_bound_to_another_key() {
        let key = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let cert = ra_tls_cert(&key, &other);

        let err = verify(&EnclaveCertVerifier::new().allow_mock(), &cert).unwrap_err();
        assert!(err.to_string().contains("report data"), "{err}");
    }

    #[test]
    fn rejects_unexpected_pcr() {
        let key = KeyPair::generate().unwrap();
        let cert = ra_tls_cert(&key, &key);
        let verifier = EnclaveCertVerifier::new()
            .allow_mock()
            .with_expected_pcr(0, vec![0xff; 48]);

        let err = verify(&verifier, &cert).unwrap_err();
        assert!(err.to_string().contains("PCR0"), "{err}");
    }

    #[test]
    fn rejects_certificate_without_attestation() {
        let key = KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();

        let err = verify(&EnclaveCertVerifier::new().allow_mock(), cert.der()).unwrap_err();
        assert!(err.to_string().contains("attestation extension"), "{err}");
    }
}
