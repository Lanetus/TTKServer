use aws_nitro_enclaves_nsm_api::api::Digest;
use sha2::{Digest as ShaDigest, Sha256};
use ttk_server::attestation::nitro_doc::{
    create_mock_attestation_document, extract_cose_payload, parse_attestation_document,
};
use ttk_server::attestation::{by_name, AttestationError, NsmSession};
use ttk_server::AttestationParams;

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
    let params = AttestationParams::new().with_user_data_hash(cert_data);
    let doc = create_mock_attestation_document(&params).expect("Should generate mock attestation");

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
        Err(AttestationError::DeviceOpenFailed(_)) => {}
        _ => panic!("Expected DeviceOpenFailed error"),
    }
}

#[test]
fn test_extract_cose_payload_invalid_data() {
    let invalid = b"not a cbor data";
    assert!(extract_cose_payload(invalid).is_err());
}

#[test]
fn test_mock_provider_by_name() {
    let provider = by_name("mock").expect("mock provider is compiled in by default");
    assert_eq!(provider.name(), "mock");

    let params = AttestationParams::new().with_user_data_hash(b"cert");
    let claims = provider
        .generate_document(&params)
        .expect("mock provider should produce an EAT claims-set");
    assert!(claims.submods.is_some());
    assert!(claims.eat_profile.is_some());
}

#[test]
fn test_unknown_provider_is_rejected() {
    assert!(matches!(
        by_name("no-such-tee"),
        Err(AttestationError::Unsupported(_))
    ));
}

// ---------------------------------------------------------------------------
// NsmSession without Nitro hardware
// ---------------------------------------------------------------------------

/// Opens a session on `/dev/null`: every NSM request then fails in the driver's `ioctl`, which
/// exercises each operation's error path. The session owns (and closes) the descriptor.
#[cfg(unix)]
fn session_on_dev_null() -> NsmSession {
    use std::os::fd::IntoRawFd;
    let fd = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
    let session = NsmSession::from_raw_fd(fd).expect("a valid descriptor is accepted");
    assert_eq!(session.raw_fd(), fd);
    session
}

#[cfg(unix)]
#[test]
fn nsm_requests_on_a_non_nsm_device_fail_with_driver_errors() {
    use ttk_server::attestation::AttestationProvider;

    let session = session_on_dev_null();
    let params = AttestationParams::new().with_user_data(vec![1; 32]);
    let is_driver_error = |e: &AttestationError| matches!(e, AttestationError::Driver(_));

    assert!(is_driver_error(
        &session.create_attestation(&params).unwrap_err()
    ));
    assert!(is_driver_error(
        &session.create_attestation_for_cert(b"cert").unwrap_err()
    ));
    assert!(is_driver_error(&session.describe_nsm().unwrap_err()));
    assert!(is_driver_error(&session.get_random().unwrap_err()));
    assert!(is_driver_error(&session.describe_pcr(0).unwrap_err()));
    assert!(is_driver_error(
        &session.extend_pcr(16, vec![1; 48]).unwrap_err()
    ));
    assert!(is_driver_error(&session.lock_pcr(16).unwrap_err()));
    assert!(is_driver_error(
        &session.generate_document(&params).unwrap_err()
    ));
    assert_eq!(session.name(), "aws-nitro");
}

#[test]
fn nsm_open_fails_without_the_nsm_device() {
    use ttk_server::attestation::AttestationProvider;

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
// Malformed documents
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

fn decoding_error(result: Result<impl std::fmt::Debug, AttestationError>) -> String {
    match result {
        Err(AttestationError::DocumentDecodingFailed(msg)) => msg,
        other => panic!("expected DocumentDecodingFailed, got {other:?}"),
    }
}

#[test]
fn malformed_cose_structures_are_rejected() {
    use ciborium::Value;

    let tag_without_array = cbor(&Value::Tag(18, Box::new(Value::Integer(1.into()))));
    assert!(decoding_error(extract_cose_payload(&tag_without_array)).contains("tag 18"));

    let not_cose = cbor(&Value::Integer(1.into()));
    assert!(decoding_error(extract_cose_payload(&not_cose)).contains("not a COSE_Sign1"));

    let too_short = cbor(&Value::Array(vec![Value::Bytes(vec![]); 3]));
    assert!(decoding_error(extract_cose_payload(&too_short)).contains("only 3 elements"));

    let text_payload = cbor(&Value::Array(vec![
        Value::Bytes(vec![]),
        Value::Map(vec![]),
        Value::Text("payload".into()),
        Value::Bytes(vec![]),
    ]));
    assert!(decoding_error(extract_cose_payload(&text_payload)).contains("not a byte string"));

    // Untagged 4-element arrays are accepted.
    let untagged = cbor(&Value::Array(vec![
        Value::Bytes(vec![]),
        Value::Map(vec![]),
        Value::Bytes(vec![7]),
        Value::Bytes(vec![]),
    ]));
    assert_eq!(extract_cose_payload(&untagged).unwrap(), vec![7]);
}

#[test]
fn payload_that_is_not_an_attestation_doc_is_rejected() {
    let doc = cose_with_payload(cbor(&ciborium::Value::Integer(1.into())));
    assert!(decoding_error(parse_attestation_document(&doc)).contains("Failed to parse"));
}

#[test]
fn wrap_as_eat_rejects_payloads_without_module_id_or_timestamp() {
    use ciborium::Value;
    use ttk_server::attestation::nitro_doc::wrap_as_eat;

    let field = |k: &str, v: Value| (Value::Text(k.into()), v);

    let invalid_cbor = cose_with_payload(vec![0xff]);
    assert!(decoding_error(wrap_as_eat(&invalid_cbor)).contains("Invalid CBOR payload"));

    let not_a_map = cose_with_payload(cbor(&Value::Array(vec![])));
    assert!(decoding_error(wrap_as_eat(&not_a_map)).contains("not a CBOR map"));

    let no_module_id = cose_with_payload(cbor(&Value::Map(vec![field(
        "timestamp",
        Value::Integer(1.into()),
    )])));
    assert!(decoding_error(wrap_as_eat(&no_module_id)).contains("missing module_id"));

    let no_timestamp = cose_with_payload(cbor(&Value::Map(vec![field(
        "module_id",
        Value::Text("i-123".into()),
    )])));
    assert!(decoding_error(wrap_as_eat(&no_timestamp)).contains("missing timestamp"));

    let minimal = cose_with_payload(cbor(&Value::Map(vec![
        field("module_id", Value::Text("i-123".into())),
        field("timestamp", Value::Integer(5_000.into())),
    ])));
    let claims = wrap_as_eat(&minimal).unwrap();
    assert_eq!(claims.iat, Some(5));
    assert_eq!(claims.ueid.map(|u| u.len()), Some(33));
}
