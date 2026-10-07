//! Tests for the base routes ([`ttk_ra_server::router`]), `POST /evidence` over the mock provider.
#![cfg(feature = "mock")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tower_service::Service;
use ttk_ra_server::attestation::{self, media_type, nitro_doc::parse_attestation_document};
use ttk_ra_server::router::{build_router, Evidence, MAX_NONCE_LEN};
use ttk_ra_server::Cmw;

/// A router over the mock provider.
fn router() -> Router {
    let evidence = Evidence { cmw: Vec::new() };
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

    let cmw = Cmw::from_cbor_bytes(&STANDARD.decode(body).unwrap()).unwrap();
    let Cmw::Record(record) = cmw else {
        panic!("Nitro evidence should be a CMW record");
    };
    assert_eq!(record.media_type(), Some(media_type::AWS_NITRO));
    let doc = parse_attestation_document(&record.value).unwrap();
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
