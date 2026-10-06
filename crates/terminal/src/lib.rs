//! TTKServer terminal node: an attested [`ttk_core`] server that is the last hop of
//! onion-routed `POST /faf` requests.
//!
//! | Route               | Response                                                        |
//! |---------------------|-----------------------------------------------------------------|
//! | `GET /`             | Greeting text (from [`ttk_core`])                               |
//! | `GET /evidence.eat` | Base64-encoded EAT carrying this node's Evidence (from [`ttk_core`]) |
//! | `POST /faf`         | Receives a [`FafRequest`], decrypts its message and answers `hello:<message>`, encrypted |
//!
//! A terminal never forwards: it accepts only requests with no relays left, and is the only node
//! that can decrypt their body, which is sealed to its RA-TLS key.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use log::{info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use ttk_client::faf::{FafRequest, FAF_PATH};
use ttk_client::seal::{self, NodeSecretKey};
use ttk_core::server::{BoxError, Listener, Server};

/// Runs the terminal node: attests, builds the RA-TLS identity, then serves HTTP/3 until the
/// endpoint closes. Listens as configured by [`Listener::from_env`].
pub async fn run() -> Result<(), BoxError> {
    Terminal::new(Server::listen(Listener::from_env()?)?)
        .serve()
        .await
}

/// A terminal node: an attested [`Server`] that also receives `POST /faf`.
pub struct Terminal {
    server: Server,
}

/// Setup and serving.
impl Terminal {
    /// Wraps `server`.
    pub fn new(server: Server) -> Self {
        Self { server }
    }

    /// Attests, builds the RA-TLS identity and binds a terminal node to UDP `addr`.
    ///
    /// Must be called within a Tokio runtime. Binding port 0 picks a free port; see
    /// [`local_addr`](Self::local_addr).
    pub fn bind(addr: SocketAddr) -> Result<Self, BoxError> {
        Ok(Self::new(Server::bind(addr)?))
    }

    /// Returns the address the endpoint is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.server.local_addr()
    }

    /// Serves the base routes and `POST /faf` over HTTP/3 until the endpoint closes.
    pub async fn serve(self) -> Result<(), BoxError> {
        let node_key = NodeSecretKey::from_pkcs8_der(self.server.private_key_der())?;
        let routes = Router::new()
            .route(FAF_PATH, post(faf))
            .with_state(Arc::new(node_key));
        self.server.serve_with(routes).await;
        Ok(())
    }
}

/// `POST /faf`: as the last hop, decrypts the body and answers `200 OK` with `hello:` followed
/// by the message, encrypted under the body's message key ([`seal::seal_response`]) so only the
/// sender can read it.
///
/// Answers `400` for a request with relays left (a terminal never forwards) or a body that
/// can't be decrypted.
async fn faf(
    State(node_key): State<Arc<NodeSecretKey>>,
    Json(request): Json<FafRequest>,
) -> (StatusCode, String) {
    if !request.relays.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "relays left: a terminal node is always the last hop".to_string(),
        );
    }

    // Never log the key or the message itself, only its size.
    let (key, message) = match seal::open_body_with_key(&node_key, &request.body) {
        Ok(opened) => opened,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid body: {e}")),
    };
    info!("/faf: delivered a {}-byte message", message.len());

    let mut response = b"hello:".to_vec();
    response.extend_from_slice(&message);
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
