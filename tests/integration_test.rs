// It's common to bring the module you're testing into scope.
// However, since `main.rs` is a binary crate, we can't directly import functions from it
// as if it were a library. To make functions testable, you would typically extract
// the logic into a library crate that the `main.rs` binary and the tests can both depend on.

// For this example, we'll assume the functions were moved to a library crate named `ttk_server`.
// In a real-world scenario, you would need to refactor your project structure.

// Let's simulate this by moving the function definitions here for the sake of the example.
// In a real project, you would:
// 1. Create a `src/lib.rs` and move the functions there.
// 2. In `main.rs`, you would use `use ttk_server::*`.
// 3. In this test file, you would use `use ttk_server::*`.

use rustls::{Certificate, PrivateKey};
use rcgen::generate_simple_self_signed;
use hyper::{Body, Method, Request as HyperRequest, Response as HyperResponse, StatusCode};
use std::sync::Arc;
use base64::{engine::general_purpose::STANDARD, Engine as _};

// --- Duplicated function definitions for demonstration ---
// In a real project, these would be in `src/lib.rs`.

pub fn generate_identity() -> (Vec<Certificate>, PrivateKey, Vec<u8>) {
    let subject_alt_names = vec!["localhost".to_string(), "enclave.local".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names).unwrap();

    let cert_der = cert.serialize_der().unwrap();
    let priv_key_der = cert.serialize_private_key_der();

    let rustls_cert = Certificate(cert_der.clone());
    let rustls_key = PrivateKey(priv_key_der);

    (vec![rustls_cert], rustls_key, cert_der)
}

pub async fn handle_request(
    req: HyperRequest<Body>,
    attestation_doc: Arc<Vec<u8>>,
) -> Result<HyperResponse<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/attestation") => {
            let b64_doc = STANDARD.encode(&*attestation_doc);
            Ok(HyperResponse::new(Body::from(b64_doc)))
        }
        (&Method::GET, "/hello") => {
            Ok(HyperResponse::new(Body::from("Hello from inside the VSOCK Enclave!")))
        }
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
    assert!(!key.0.is_empty());
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

    let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
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

    let body_bytes = hyper::body::to_bytes(response.into_body()).await.unwrap();
    assert_eq!(body_bytes, "Hello from inside the VSOCK Enclave!".as_bytes());
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
