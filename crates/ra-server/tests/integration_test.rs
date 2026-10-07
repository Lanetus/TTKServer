// It's common to bring the module you're testing into scope.
// However, since `main.rs` is a binary crate, we can't directly import functions from it
// as if it were a library. To make functions testable, you would typically extract
// the logic into a library crate that the `main.rs` binary and the tests can both depend on.

// For this example, we'll assume the functions were moved to a library crate named `ttk_ra_server`.
// In a real-world scenario, you would need to refactor your project structure.

// Let's simulate this by moving the function definitions here for the sake of the example.
// In a real project, you would:
// 1. Create a `src/lib.rs` and move the functions there.
// 2. In `main.rs`, you would use `use ttk_ra_server::*`.
// 3. In this test file, you would use `use ttk_ra_server::*`.

use axum::body::{to_bytes, Body};
use axum::http::{Method, Request as HyperRequest, Response as HyperResponse, StatusCode};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::generate_simple_self_signed;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;

// --- Duplicated function definitions for demonstration ---
// In a real project, these would be in `src/lib.rs`.

pub fn generate_identity() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    Vec<u8>,
) {
    let subject_alt_names = vec!["localhost".to_string(), "enclave.local".to_string()];
    let certified_key = generate_simple_self_signed(subject_alt_names).unwrap();

    let cert_der = certified_key.cert.der().to_vec();
    let rustls_cert = certified_key.cert.der().clone();
    let rustls_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified_key.key_pair.serialize_der(),
    ));

    (vec![rustls_cert], rustls_key, cert_der)
}

pub async fn handle_request(
    req: HyperRequest<Body>,
    attestation_doc: Arc<Vec<u8>>,
) -> Result<HyperResponse<Body>, std::convert::Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/attestation") => {
            let b64_doc = STANDARD.encode(&*attestation_doc);
            Ok(HyperResponse::new(Body::from(b64_doc)))
        }
        (&Method::GET, "/hello") => Ok(HyperResponse::new(Body::from(
            "Hello from inside the VSOCK Enclave!",
        ))),
        _ => {
            let mut not_found = HyperResponse::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

// --- Tests ---

#[test]
fn test_generate_identity() {
    let (certs, key, cert_der) = generate_identity();
    assert_eq!(certs.len(), 1);
    assert!(!key.secret_der().is_empty());
    assert!(!cert_der.is_empty());
}

#[tokio::test]
async fn test_handle_request_attestation() {
    let attestation_doc = Arc::new(b"test_attestation_doc".to_vec());
    let req = HyperRequest::builder()
        .method(Method::GET)
        .uri("/attestation")
        .body(Body::empty())
        .unwrap();

    let response = handle_request(req, attestation_doc).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let expected_b64 = STANDARD.encode(b"test_attestation_doc");
    assert_eq!(body_bytes, expected_b64.as_bytes());
}

#[tokio::test]
async fn test_handle_request_hello() {
    let attestation_doc = Arc::new(vec![]);
    let req = HyperRequest::builder()
        .method(Method::GET)
        .uri("/hello")
        .body(Body::empty())
        .unwrap();

    let response = handle_request(req, attestation_doc).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        body_bytes,
        "Hello from inside the VSOCK Enclave!".as_bytes()
    );
}

#[tokio::test]
async fn test_handle_request_not_found() {
    let attestation_doc = Arc::new(vec![]);
    let req = HyperRequest::builder()
        .method(Method::GET)
        .uri("/not_a_real_path")
        .body(Body::empty())
        .unwrap();

    let response = handle_request(req, attestation_doc).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[test]
fn test_ttk_ra_server_nitro_and_cmw_integration() {
    use sha2::{Digest as ShaDigest, Sha256};
    use ttk_ra_server::attestation::nitro_doc::{
        create_mock_attestation_document, parse_attestation_document, wrap_as_cmw,
    };
    use ttk_ra_server::AttestationParams;

    // 1. Generate RA-TLS identity
    let (_certs, _key, cert_der) = generate_identity();

    // 2. Generate attestation document bound to certificate
    let params = AttestationParams {
        user_data: Some(Sha256::digest(&cert_der).to_vec()),
        ..Default::default()
    };
    let nitro_doc = create_mock_attestation_document(&params)
        .expect("Should generate nitro attestation document");

    // 3. Parse and verify attestation document
    let parsed = parse_attestation_document(&nitro_doc)
        .expect("Should parse generated attestation document");

    let expected_cert_hash = Sha256::digest(&cert_der);
    assert_eq!(
        parsed.user_data.as_deref().map(|v| v.as_slice()),
        Some(expected_cert_hash.as_slice())
    );

    // 4. Wrap as a CMW record
    let cmw = wrap_as_cmw(nitro_doc);
    let cmw_bytes = cmw.to_cbor_bytes();
    assert!(!cmw_bytes.is_empty());

    // 5. Round-trip from CBOR bytes
    let deserialized = ttk_ra_server::Cmw::from_cbor_bytes(&cmw_bytes)
        .expect("Should deserialize the CMW from CBOR bytes");
    assert_eq!(deserialized, cmw);
}
