//! Base HTTP routes of the RA-TLS server, served over HTTP/3 by [`super::server`]:
//!
//! | Route               | Response                                                        |
//! |---------------------|-----------------------------------------------------------------|
//! | `GET /`             | Greeting text                                                   |
//! | `GET /evidence.eat` | Base64-encoded EAT carrying this server's [`Evidence`]          |
//!
//! Nodes built on the server add their own routes with
//! [`Server::serve_with`](super::server::Server::serve_with).

use axum::routing::get;
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Evidence for this instance, in the formats served over HTTP.
#[derive(Clone, Debug)]
pub struct Evidence {
    /// Raw NSM Attestation Document (COSE_Sign1).
    pub nitro: Vec<u8>,
    /// The same document, wrapped as an RFC 9711 EAT claims-set.
    pub eat: Vec<u8>,
}

/// Builds the Axum router serving the greeting and the evidence endpoint, merged with `routes`.
pub(crate) fn build_router(evidence: &Evidence, routes: Router) -> Router {
    let eat_b64 = STANDARD.encode(&evidence.eat);

    Router::new()
        .route("/", get(|| async { "Hello from Enclave over HTTP/3!" }))
        .route("/evidence.eat", get(move || async move { eat_b64 }))
        .merge(routes)
}
