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

use crate::attestation::AttestationProvider;
use crate::AttestationParams;
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
///
/// `POST /evidence` asks `provider` for Evidence carrying only the request's nonce.
pub fn build_router(
    evidence: &Evidence,
    provider: Arc<dyn AttestationProvider>,
    routes: Router,
) -> Router {
    let eat_b64 = STANDARD.encode(&evidence.eat);
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_ATTESTATIONS));

    Router::new()
        .route("/", get(|| async { "Hello from Enclave over HTTP/3!" }))
        .route("/evidence.eat", get(move || async move { eat_b64 }))
        .route(
            "/evidence",
            post(move |nonce: Bytes| evidence_with_nonce(provider, permits, nonce)),
        )
        .merge(routes)
}

/// Handles `POST /evidence`: generates fresh Evidence carrying `nonce` and returns it as
/// base64-encoded EAT.
async fn evidence_with_nonce(
    provider: Arc<dyn AttestationProvider>,
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
    let params = AttestationParams {
        nonce: Some(nonce.to_vec()),
        ..AttestationParams::default()
    };
    let generate = move || -> Result<Vec<u8>, String> {
        let eat = provider
            .generate_document(&params)
            .map_err(|e| e.to_string())?;
        eat.to_cbor_bytes().map_err(|e| e.to_string())
    };
    match tokio::task::spawn_blocking(generate).await {
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
