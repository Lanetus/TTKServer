//! The terminal node: an attested [`Server`] that is the last hop of onion-routed `POST /faf`
//! requests.
//!
//! | Route               | Response                                                        |
//! |---------------------|-----------------------------------------------------------------|
//! | `GET /`             | Greeting text (base route)                               |
//! | `GET /evidence.cmw` | Base64-encoded CMW carrying this node's Evidence (base route) |
//! | `POST /faf`         | Receives a [`FafRequest`], decrypts its message and answers its [`Evaluator`]'s reply, encrypted |
//!
//! Every route above answers `404` until the node's self-signed RA-TLS certificate has been
//! replaced by a CA-issued one (`POST /evidence` + `POST /certificate`),
//! and then only on connections that negotiated the CA-issued certificate; see
//! [`router`](crate::router).
//!
//! A terminal never forwards: it accepts only requests with no relays left, and is the only node
//! that can decrypt their body, which is sealed to its RA-TLS key.
//!
//! What the terminal does with a message is its [`Evaluator`], such as `ttk-storage`'s
//! `FileService` (bin `s3-server`) storing and retrieving files.

use crate::evaluator::Evaluator;
use crate::server::{BoxError, Server};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use log::{debug, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use ttk_ra_client::faf::{FafRequest, FAF_PATH};
use ttk_ra_client::seal::{self, NodeSecretKey};

/// A terminal node: an attested [`Server`] that also receives `POST /faf`, answered by its
/// [`Evaluator`] `E`.
pub struct Terminal<E> {
    server: Server,
    evaluator: E,
}

/// The `/faf` handler state: the node's RA-TLS key and the evaluator.
struct FafState<E> {
    node_key: NodeSecretKey,
    evaluator: E,
}

/// Setup and serving.
impl<E: Evaluator> Terminal<E> {
    /// Wraps `server`, answering `/faf` messages with `evaluator`.
    pub fn new(server: Server, evaluator: E) -> Self {
        Self { server, evaluator }
    }

    /// Attests, builds the RA-TLS identity and binds a terminal node answering with `evaluator`
    /// to UDP `addr`.
    ///
    /// Must be called within a Tokio runtime. Binding port 0 picks a free port; see
    /// [`local_addr`](Self::local_addr).
    pub fn bind(addr: SocketAddr, evaluator: E) -> Result<Self, BoxError> {
        Ok(Self::new(Server::bind(addr)?, evaluator))
    }

    /// Returns the address the endpoint is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.server.local_addr()
    }

    /// Returns the wrapped attested server (e.g. its presented certificate chain).
    pub fn server(&self) -> &Server {
        &self.server
    }

    /// Serves the base routes and `POST /faf` over HTTP/3 until the endpoint closes.
    pub async fn serve(self) -> Result<(), BoxError> {
        let node_key = NodeSecretKey::from_pkcs8_der(self.server.private_key_der())?;
        let routes = Router::new()
            .route(FAF_PATH, post(faf::<E>))
            .with_state(Arc::new(FafState {
                node_key,
                evaluator: self.evaluator,
            }));
        self.server.serve_with(routes).await;
        Ok(())
    }
}

/// `POST /faf`: as the last hop, decrypts the body and answers `200 OK` with the [`Evaluator`]'s
/// reply, encrypted under the body's message key ([`seal::seal_response`]) so only the sender
/// can read it.
///
/// Answers `400` for a request with relays left (a terminal never forwards) or a body that
/// can't be decrypted, and `500` if the evaluator fails.
async fn faf<E: Evaluator>(
    State(state): State<Arc<FafState<E>>>,
    Json(request): Json<FafRequest>,
) -> (StatusCode, String) {
    if !request.relays.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "relays left: a terminal node is always the last hop".to_string(),
        );
    }

    // Never log the key or the message itself, only its size.
    let (key, message) = match seal::open_body_with_key(&state.node_key, &request.body) {
        Ok(opened) => opened,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid body: {e}")),
    };
    debug!("/faf: delivered a {}-byte message", message.len());

    let response = match state.evaluator.eval(message).await {
        Ok(r) => r,
        Err(e) => {
            warn!("/faf: can't evaluate the response: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response evaluation failed".to_string(),
            );
        }
    };

    match seal::seal_response(&key, &response) {
        Ok(sealed) => (StatusCode::OK, sealed),
        Err(e) => {
            warn!("/faf: can't seal the response: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "response sealing failed".to_string(),
            )
        }
    }
}
