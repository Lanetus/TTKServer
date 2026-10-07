//! TTKServer root node: an attested [`ttk_ra_server`] server that publishes the checksums of the
//! accepted enclave images, the reference values a Verifier appraises Nitro Evidence against
//! (RFC 9334).
//!
//! | Route                    | Response                                                        |
//! |--------------------------|-----------------------------------------------------------------|
//! | `GET /`                  | Greeting text (from [`ttk_ra_server`])                               |
//! | `GET /evidence.cmw`      | Base64-encoded CMW carrying this node's Evidence (from [`ttk_ra_server`]) |
//! | `GET /root-attestation`  | JSON [`RootAttestation`]: the accepted enclave image checksums  |
//!
//! The checksums are the Nitro image allowlist built into this crate
//! (`nitro_image_allowlist.txt`, served by [`FileImageTrustStore`]); clients fetch them into
//! their own [`ImageTrustStore`] and check Evidence against them. Clients reach the root node
//! over RA-TLS, so the list is bound to an attested enclave.

use axum::routing::get;
use axum::{Json, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use ttk_core::image_trust::{parse_image_allowlist, ImageTrustStore};
pub use ttk_core::image_trust::{RootAttestation, ROOT_ATTESTATION_PATH};
use ttk_ra_server::server::{BoxError, Listener, Server};

/// PCR0 values (enclave image checksums) of the verified Nitro enclave images.
const NITRO_IMAGE_ALLOWLIST: &str = include_str!("nitro_image_allowlist.txt");

/// The accepted enclave images, read from an allowlist file (see [`parse_image_allowlist`]).
#[derive(Debug, Clone)]
pub struct FileImageTrustStore {
    /// PCR0 values (SHA-384 of the enclave image file) of the verified Nitro enclave images.
    pub nitro_image_allowlist: Vec<Vec<u8>>,
}

/// Construction from allowlist text.
impl FileImageTrustStore {
    /// Parses allowlist `text` (one PCR0 per line).
    pub fn parse(text: &str) -> Result<Self, String> {
        Ok(Self {
            nitro_image_allowlist: parse_image_allowlist(text)?,
        })
    }
}

/// The allowlist file built into this crate.
impl ImageTrustStore for FileImageTrustStore {
    /// The images of the built-in `nitro_image_allowlist.txt`.
    fn builtin() -> Self {
        Self::parse(NITRO_IMAGE_ALLOWLIST).expect("built-in nitro_image_allowlist.txt is invalid")
    }

    /// The parsed PCR0 values.
    fn nitro_image_allowlist(&self) -> &[Vec<u8>] {
        &self.nitro_image_allowlist
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
    /// Wraps `server`, serving the built-in accepted images ([`FileImageTrustStore`]).
    pub fn new(server: Server) -> Self {
        Self::with_image_trust_store(server, &FileImageTrustStore::builtin())
    }

    /// Wraps `server`, serving the accepted images of `images`.
    pub fn with_image_trust_store(server: Server, images: &dyn ImageTrustStore) -> Self {
        Self {
            server,
            attestation: RootAttestation::from_image_trust_store(images),
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
