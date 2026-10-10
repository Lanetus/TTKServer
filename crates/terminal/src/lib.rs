//! TTKServer terminal node: an attested [`ttk_ra_server`] server that is the last hop of
//! onion-routed `POST /faf` requests.
//!
//! | Route               | Response                                                        |
//! |---------------------|-----------------------------------------------------------------|
//! | `GET /`             | Greeting text (from [`ttk_ra_server`])                               |
//! | `GET /evidence.cmw` | Base64-encoded CMW carrying this node's Evidence (from [`ttk_ra_server`]) |
//! | `POST /faf`         | Receives a [`FafRequest`], decrypts its message and answers its [`Evaluator`]'s reply, encrypted |
//!
//! A terminal never forwards: it accepts only requests with no relays left, and is the only node
//! that can decrypt their body, which is sealed to its RA-TLS key.
//!
//! What the terminal does with a message is its [`Evaluator`]: [`Echo`] by default, or
//! [`file_service::FileService`] (bin `s3-server`) storing and retrieving files.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use log::{debug, warn};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use ttk_ra_client::faf::{FafRequest, FAF_PATH};
use ttk_ra_client::seal::{self, NodeSecretKey};
use ttk_ra_server::server::{BoxError, Listener, Server};

pub mod file_service;
pub mod storage;

/// Runs the terminal node with the [`Echo`] evaluator. See [`run_with`].
pub async fn run() -> Result<(), BoxError> {
    run_with(Echo).await
}

/// Runs a terminal node answering `/faf` messages with `evaluator`: attests, builds the RA-TLS
/// identity, then serves HTTP/3 until the endpoint closes. Listens as configured by
/// [`Listener::from_env`].
pub async fn run_with<E: Evaluator>(evaluator: E) -> Result<(), BoxError> {
    Terminal::new(Server::listen(Listener::from_env()?)?)
        .with_evaluator(evaluator)
        .serve()
        .await
}

/// Error of an [`Evaluator`] or a [`storage::BlobStore`]: unlike [`BoxError`], `Send + Sync`,
/// so it can be held across `.await` in their `Send` futures.
pub type EvalError = Box<dyn std::error::Error + Send + Sync>;

/// What a terminal does with a delivered `/faf` message: turns the decrypted message into the
/// reply, which the terminal then seals to the sender.
///
/// An error answers `500` without detail, so relays learn nothing about the message.
pub trait Evaluator: Send + Sync + 'static {
    /// Evaluates the decrypted `message` into the (plaintext) reply.
    fn eval(&self, message: Vec<u8>) -> impl Future<Output = Result<Vec<u8>, EvalError>> + Send;
}

/// The default [`Evaluator`]: replies with the message itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct Echo;

impl Evaluator for Echo {
    async fn eval(&self, message: Vec<u8>) -> Result<Vec<u8>, EvalError> {
        Ok(message)
    }
}

/// A terminal node: an attested [`Server`] that also receives `POST /faf`, answered by its
/// [`Evaluator`] `E`.
pub struct Terminal<E = Echo> {
    server: Server,
    evaluator: E,
}

/// The `/faf` handler state: the node's RA-TLS key and the evaluator.
struct FafState<E> {
    node_key: NodeSecretKey,
    evaluator: E,
}

/// Setup with the default [`Echo`] evaluator.
impl Terminal {
    /// Wraps `server`, answering with [`Echo`]; see [`with_evaluator`](Self::with_evaluator).
    pub fn new(server: Server) -> Self {
        Self {
            server,
            evaluator: Echo,
        }
    }

    /// Attests, builds the RA-TLS identity and binds a terminal node to UDP `addr`.
    ///
    /// Must be called within a Tokio runtime. Binding port 0 picks a free port; see
    /// [`local_addr`](Self::local_addr).
    pub fn bind(addr: SocketAddr) -> Result<Self, BoxError> {
        Ok(Self::new(Server::bind(addr)?))
    }
}

/// Serving.
impl<E: Evaluator> Terminal<E> {
    /// Replaces the evaluator answering `/faf` messages.
    pub fn with_evaluator<F: Evaluator>(self, evaluator: F) -> Terminal<F> {
        Terminal {
            server: self.server,
            evaluator,
        }
    }

    /// Returns the address the endpoint is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.server.local_addr()
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
