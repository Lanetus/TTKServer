use aws_nitro_enclaves_nsm_api::api::Digest;
use sha2::{Digest as ShaDigest, Sha256};
use ttk_server::nitro::{
    create_mock_attestation_document, extract_cose_payload, generate_attestation_for_cert_or_mock,
    parse_attestation_document, AttestationParams, NitroError, NsmSession,
};

#[test]
fn test_attestation_params_builder() {
    let cert_data = b"ephemeral-cert-data";
    let expected_hash = Sha256::digest(cert_data).to_vec();

    let params = AttestationParams::new()
        .with_user_data_hash(cert_data)
        .with_nonce(b"random-nonce-123".to_vec())
        .with_public_key(b"public-key-der".to_vec());

    assert_eq!(params.user_data(), Some(expected_hash.as_slice()));
    assert_eq!(params.nonce(), Some(b"random-nonce-123".as_slice()));
    assert_eq!(params.public_key(), Some(b"public-key-der".as_slice()));
}

#[test]
fn test_create_and_parse_mock_attestation_doc() {
    let user_data = b"test-user-data".to_vec();
    let nonce = b"test-nonce-123".to_vec();
    let pubkey = b"test-public-key".to_vec();

    let params = AttestationParams::new()
        .with_user_data(user_data.clone())
        .with_nonce(nonce.clone())
        .with_public_key(pubkey.clone());

    let raw_cose = create_mock_attestation_document(&params)
        .expect("Mock attestation doc creation should succeed");

    assert!(!raw_cose.is_empty());

    // Extract payload
    let payload = extract_cose_payload(&raw_cose).expect("Payload extraction should succeed");
    assert!(!payload.is_empty());

    // Parse into AttestationDoc
    let parsed_doc =
        parse_attestation_document(&raw_cose).expect("Parsing attestation document should succeed");

    assert_eq!(parsed_doc.module_id, "aws-nitro-enclaves-mock");
    assert_eq!(parsed_doc.digest, Digest::SHA384);
    assert_eq!(
        parsed_doc.user_data.as_deref().map(|v| v.as_slice()),
        Some(user_data.as_slice())
    );
    assert_eq!(
        parsed_doc.nonce.as_deref().map(|v| v.as_slice()),
        Some(nonce.as_slice())
    );
    assert_eq!(
        parsed_doc.public_key.as_deref().map(|v| v.as_slice()),
        Some(pubkey.as_slice())
    );
    assert_eq!(parsed_doc.pcrs.len(), 16);
}

#[test]
fn test_generate_attestation_or_mock() {
    let cert_data = b"self-signed-ra-tls-cert";
    let doc = generate_attestation_for_cert_or_mock(cert_data)
        .expect("Should generate mock or real attestation");

    let parsed = parse_attestation_document(&doc).expect("Must be valid attestation document");
    let expected_hash = Sha256::digest(cert_data);
    assert_eq!(
        parsed.user_data.as_deref().map(|v| v.as_slice()),
        Some(expected_hash.as_slice())
    );
}

#[test]
fn test_from_invalid_raw_fd() {
    let result = NsmSession::from_raw_fd(-1);
    assert!(result.is_err());
    match result {
        Err(NitroError::DeviceOpenFailed(_)) => {}
        _ => panic!("Expected DeviceOpenFailed error"),
    }
}

#[test]
fn test_extract_cose_payload_invalid_data() {
    let invalid = b"not a cbor data";
    assert!(extract_cose_payload(invalid).is_err());
}
