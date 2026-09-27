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
