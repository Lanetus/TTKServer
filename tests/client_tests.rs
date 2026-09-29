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
