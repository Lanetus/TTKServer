use aws_nitro_enclaves_nsm_api::api::Digest;
use sha2::{Digest as ShaDigest, Sha256};
#[path = "support/nitro_doc.rs"]
mod nitro_doc;
use nitro_doc::parse_attestation_document;
use ttk_ra_server::attestation::nitro_doc::create_mock_attestation_document;
use ttk_ra_server::attestation::{by_name, cmw, media_type, AttestationError, NsmSession};
use ttk_ra_server::{AttestationParams, Cmw};

#[test]
fn test_create_and_parse_mock_attestation_doc() {
    let user_data = b"test-user-data".to_vec();
    let nonce = b"test-nonce-123".to_vec();
    let pubkey = b"test-public-key".to_vec();

    let params = AttestationParams {
        user_data: Some(user_data.clone()),
        nonce: Some(nonce.clone()),
        public_key: Some(pubkey.clone()),
    };

    let raw_cose = create_mock_attestation_document(&params)
        .expect("Mock attestation doc creation should succeed");

    assert!(!raw_cose.is_empty());

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
    let params = AttestationParams {
        user_data: Some(Sha256::digest(cert_data).to_vec()),
        ..Default::default()
    };
    let doc = create_mock_attestation_document(&params).expect("Should generate mock attestation");

    let parsed = parse_attestation_document(&doc).expect("Must be valid attestation document");
    let expected_hash = Sha256::digest(cert_data);
    assert_eq!(
        parsed.user_data.as_deref().map(|v| v.as_slice()),
        Some(expected_hash.as_slice())
    );
}

#[test]
fn test_mock_provider_by_name() {
    let provider = by_name("mock").expect("mock provider is compiled in by default");
    assert_eq!(provider.name(), "mock");

    let params = AttestationParams {
        user_data: Some(Sha256::digest(b"cert").to_vec()),
        ..Default::default()
    };
    let cmw = provider
        .generate_document(&params)
        .expect("mock provider should produce a CMW");
    let Cmw::Record(record) = cmw else {
        panic!("mock evidence should be a CMW record");
    };
    assert_eq!(record.media_type(), Some(media_type::AWS_NITRO));
    assert_eq!(record.ind, Some(cmw::ind::EVIDENCE));
    assert!(parse_attestation_document(&record.value).is_ok());
}

#[test]
fn test_unknown_provider_is_rejected() {
    assert!(matches!(
        by_name("no-such-tee"),
        Err(AttestationError::Unsupported(_))
    ));
}

#[test]
fn nsm_open_fails_without_the_nsm_device() {
    use ttk_ra_server::attestation::AttestationProvider;

    if NsmSession::is_available() {
        return; // running inside a Nitro Enclave
    }
    assert!(matches!(
        NsmSession::open(),
        Err(AttestationError::DeviceOpenFailed(_))
    ));
    assert!(matches!(
        by_name("aws-nitro"),
        Err(AttestationError::DeviceOpenFailed(_))
    ));
}

// ---------------------------------------------------------------------------
// CMW wrapping
// ---------------------------------------------------------------------------

fn cbor(value: &ciborium::Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

/// A tagged COSE_Sign1 whose payload is `payload`.
fn cose_with_payload(payload: Vec<u8>) -> Vec<u8> {
    use ciborium::Value;
    cbor(&Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(vec![]),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(vec![]),
        ])),
    ))
}

#[test]
fn wrap_as_cmw_keeps_the_document_verbatim() {
    use ttk_ra_server::attestation::nitro_doc::wrap_as_cmw;

    let doc = cose_with_payload(vec![0xff]);
    let cmw = wrap_as_cmw(doc.clone());
    assert_eq!(cmw, Cmw::evidence(media_type::AWS_NITRO, doc));
}
