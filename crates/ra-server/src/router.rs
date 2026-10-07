//! Base HTTP routes of the RA-TLS server, served over HTTP/3 by [`super::server`]:
//!
//! | Route               | Response                                                        |
//! |---------------------|-----------------------------------------------------------------|
//! | `GET /`             | Greeting text                                                   |
//! | `GET /evidence.eat` | Base64-encoded EAT carrying this server's [`Evidence`]          |
//! | `POST /evidence`    | Base64-encoded EAT with fresh Evidence carrying the body as nonce |
//!
//! `POST /evidence` gives a Verifier freshness (RFC 9334 §10): the request body is the raw
//! nonce (1 to [`MAX_NONCE_LEN`] bytes, else `400`), and the server asks the TEE for new Evidence
//! bound, like the startup Evidence, to the RA-TLS key, with the nonce in the attestation
//! document's `nonce` field. At most [`MAX_CONCURRENT_ATTESTATIONS`] requests are attested at
//! once; further ones get `503`. Providers that cannot carry a nonce (TDX, SEV-SNP) answer `500`.
//!
//! Nodes built on the server add their own routes with
//! [`Server::serve_with`](super::server::Server::serve_with).

use super::server::Attester;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::error;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Largest nonce `POST /evidence` accepts, in bytes (the NSM's limit for `nonce`).
pub const MAX_NONCE_LEN: usize = 512;

/// Most `POST /evidence` requests attested at once; further ones get `503 Service Unavailable`.
pub const MAX_CONCURRENT_ATTESTATIONS: usize = 4;

/// Evidence for this instance, in the formats served over HTTP.
#[derive(Clone, Debug)]
pub struct Evidence {
    /// Raw NSM Attestation Document (COSE_Sign1).
    pub nitro: Vec<u8>,
    /// The same document, wrapped as an RFC 9711 EAT claims-set.
    pub eat: Vec<u8>,
}

/// Builds the Axum router serving the greeting and the evidence endpoints, merged with `routes`.
pub(crate) fn build_router(evidence: &Evidence, attester: Arc<Attester>, routes: Router) -> Router {
    let eat_b64 = STANDARD.encode(&evidence.eat);
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_ATTESTATIONS));

    Router::new()
        .route("/", get(|| async { "Hello from Enclave over HTTP/3!" }))
        .route("/evidence.eat", get(move || async move { eat_b64 }))
        .route(
            "/evidence",
            post(move |nonce: Bytes| evidence_with_nonce(attester, permits, nonce)),
        )
        .merge(routes)
}

/// Handles `POST /evidence`: generates fresh Evidence carrying `nonce` and returns it as
/// base64-encoded EAT.
async fn evidence_with_nonce(
    attester: Arc<Attester>,
    permits: Arc<Semaphore>,
    nonce: Bytes,
) -> Response {
    if nonce.is_empty() || nonce.len() > MAX_NONCE_LEN {
        return (
            StatusCode::BAD_REQUEST,
            format!("nonce must be 1 to {MAX_NONCE_LEN} bytes"),
        )
            .into_response();
    }
    let Ok(_permit) = permits.try_acquire_owned() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "attestation busy").into_response();
    };
    match tokio::task::spawn_blocking(move || attester.evidence(Some(&nonce))).await {
        Ok(Ok(eat)) => STANDARD.encode(eat).into_response(),
        Ok(Err(e)) => {
            error!("Evidence generation with nonce failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence generation failed",
            )
                .into_response()
        }
        Err(e) => {
            error!("Evidence generation task failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence generation failed",
            )
                .into_response()
        }
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use crate::attestation::{self, nitro_doc::parse_attestation_document, submod};
    use crate::EatClaimsSet;
    use axum::body::Body;
    use axum::http::Request;
    use ciborium::Value;
    use sha2::{Digest, Sha256};
    use tower_service::Service;

    const PUBLIC_KEY: &[u8] = b"test-public-key";

    /// A router over a mock [`Attester`] for [`PUBLIC_KEY`].
    fn router() -> Router {
        let attester = Arc::new(Attester::new(
            attestation::by_name("mock").unwrap(),
            PUBLIC_KEY,
        ));
        let evidence = Evidence {
            nitro: Vec::new(),
            eat: Vec::new(),
        };
        build_router(&evidence, attester, Router::new())
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
    async fn evidence_carries_the_nonce_and_key_binding() {
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
        assert_eq!(
            doc.user_data.unwrap().to_vec(),
            Sha256::digest(PUBLIC_KEY).to_vec()
        );
    }

    #[tokio::test]
    async fn evidence_rejects_empty_and_oversized_nonces() {
        assert_eq!(post_evidence(Vec::new()).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            post_evidence(vec![0; MAX_NONCE_LEN + 1]).await.0,
            StatusCode::BAD_REQUEST
        );
    }
}
