//! TTKServer root node: an attested [`ttk_ra_server`] server that publishes the checksums of the
//! accepted enclave images, the reference values a Verifier appraises Nitro Evidence against
//! (RFC 9334).
//!
//! | Route                    | Response                                                        |
//! |--------------------------|-----------------------------------------------------------------|
//! | `GET /`                  | Greeting text (from [`ttk_ra_server`])                               |
//! | `GET /evidence.eat`      | Base64-encoded EAT carrying this node's Evidence (from [`ttk_ra_server`]) |
//! | `GET /root-attestation`  | JSON [`RootAttestation`]: the accepted enclave image checksums  |
//!
//! The checksums are the built-in Nitro image allowlist of [`ttk_ra_client::trust`]
//! ([`TrustStore::nitro_image_allowlist`]), the same trust store the client verifier checks
//! Evidence against, so the root node serves exactly the images the client accepts. Clients reach it over RA-TLS, so the list is bound to an attested
//! enclave.

use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use ttk_ra_client::TrustStore;
use ttk_ra_server::server::{BoxError, Listener, Server};

/// Path of the accepted-images endpoint.
pub const ROOT_ATTESTATION_PATH: &str = "/root-attestation";

/// Body of `GET /root-attestation`.
///
/// ```json
/// {
///   "hash_algorithm": "SHA384",
///   "pcr0": ["7807833a90cc86f5…"]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootAttestation {
    /// Hash algorithm of the checksums: always `SHA384` (Nitro PCRs).
    pub hash_algorithm: String,
    /// PCR0 of each accepted enclave image (the SHA-384 of its EIF), as lowercase hex.
    pub pcr0: Vec<String>,
}

/// Construction from a trust store.
impl RootAttestation {
    /// The accepted enclave images of `trust`.
    pub fn from_trust_store(trust: &TrustStore) -> Self {
        Self {
            hash_algorithm: "SHA384".to_string(),
            pcr0: trust
                .nitro_image_allowlist
                .iter()
                .map(|pcr0| hex_encode(pcr0))
                .collect(),
        }
    }
}

/// Runs the root node: attests, builds the RA-TLS identity, then serves HTTP/3 until the
/// endpoint closes. Listens as configured by [`Listener::from_env`].
pub async fn run() -> Result<(), BoxError> {
    Root::new(Server::listen(Listener::from_env()?)?)
        .serve()
        .await
}

/// A root node: an attested [`Server`] that also serves `GET /root-attestation`.
pub struct Root {
    server: Server,
    attestation: RootAttestation,
}

/// Setup and serving.
impl Root {
    /// Wraps `server`, serving the built-in accepted images ([`TrustStore::builtin`]).
    pub fn new(server: Server) -> Self {
        Self::with_trust_store(server, &TrustStore::builtin())
    }

    /// Wraps `server`, serving the accepted images of `trust`.
    pub fn with_trust_store(server: Server, trust: &TrustStore) -> Self {
        Self {
            server,
            attestation: RootAttestation::from_trust_store(trust),
        }
    }

    /// Attests, builds the RA-TLS identity and binds a root node to UDP `addr`.
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

    /// Serves the base routes and `GET /root-attestation` over HTTP/3 until the endpoint
    /// closes.
    pub async fn serve(self) -> Result<(), BoxError> {
        let routes = Router::new()
            .route(ROOT_ATTESTATION_PATH, get(root_attestation))
            .with_state(Arc::new(self.attestation));
        self.server.serve_with(routes).await;
        Ok(())
    }
}

/// `GET /root-attestation`: the accepted enclave image checksums as JSON.
async fn root_attestation(
    axum::extract::State(attestation): axum::extract::State<Arc<RootAttestation>>,
) -> Json<RootAttestation> {
    Json(attestation.as_ref().clone())
}

/// Formats `bytes` as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
