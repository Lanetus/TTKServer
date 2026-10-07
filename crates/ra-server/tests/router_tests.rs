//! Tests for the base routes ([`ttk_ra_server::router`]), `POST /evidence` over the mock provider.
#![cfg(feature = "mock")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ciborium::Value;
use tower_service::Service;
use ttk_ra_server::attestation::{self, nitro_doc::parse_attestation_document, submod};
use ttk_ra_server::router::{build_router, Evidence, MAX_NONCE_LEN};
use ttk_ra_server::EatClaimsSet;

/// A router over the mock provider.
fn router() -> Router {
    let evidence = Evidence {
        nitro: Vec::new(),
        eat: Vec::new(),
    };
    build_router(
        &evidence,
        attestation::by_name("mock").unwrap().into(),
        Router::new(),
    )
}

/// Sends `POST /evidence` with `body`, returning the status and response body.
async fn post_evidence(body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let request = Request::post("/evidence").body(Body::from(body)).unwrap();
    let response = router().call(request).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, body.to_vec())
}

#[tokio::test]
async fn evidence_carries_the_nonce() {
    let nonce = b"client-nonce-0123456789".to_vec();
    let (status, body) = post_evidence(nonce.clone()).await;
    assert_eq!(status, StatusCode::OK);

    let eat = EatClaimsSet::from_cbor_bytes(&STANDARD.decode(body).unwrap()).unwrap();
    let Some(Value::Map(submods)) = eat.submods else {
        panic!("EAT has no submods map");
    };
    let doc = submods
        .iter()
        .find(|(k, _)| k.as_text() == Some(submod::AWS_NITRO))
        .and_then(|(_, v)| v.as_bytes())
        .expect("no Nitro submodule");
    let doc = parse_attestation_document(doc).unwrap();
    assert_eq!(doc.nonce.unwrap().to_vec(), nonce);
    assert!(doc.user_data.is_none());
}

#[tokio::test]
async fn evidence_rejects_empty_and_oversized_nonces() {
    assert_eq!(post_evidence(Vec::new()).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        post_evidence(vec![0; MAX_NONCE_LEN + 1]).await.0,
        StatusCode::BAD_REQUEST
    );
}
