//! TTKServer root node: an attested [`ttk_ra_server`] server that publishes the checksums of the
//! accepted enclave images, the reference values a Verifier appraises Evidence against
//! (RFC 9334).
//!
//! | Route                    | Response                                                        |
//! |--------------------------|-----------------------------------------------------------------|
//! | `GET /`                  | Greeting text (from [`ttk_ra_server`])                               |
//! | `GET /evidence.cmw`      | Base64-encoded CMW carrying this node's Evidence (from [`ttk_ra_server`]) |
//! | `GET /root-attestation`  | JSON [`RootAttestation`]: the accepted enclave image checksums  |
//!
//! Every route above answers `404` until the node's self-signed RA-TLS certificate has been
//! replaced by a CA-issued one (`POST /evidence` + `POST /certificate`, from [`ttk_ra_server`]),
//! and then only on connections that negotiated the CA-issued certificate; see
//! [`ttk_ra_server::router`].
//! Root nodes must therefore be authorized before the nodes and clients fetching their images.
//!
//! The checksums are the image allowlist built into this crate (`image_allowlist.txt`, served
//! by [`FileImageTrustStore`]); clients fetch them into
//! their own [`ImageTrustStore`] and check Evidence against them. Clients reach the root node
//! over RA-TLS, so the list is bound to an attested enclave.

pub mod auth;

use axum::routing::get;
use axum::{Json, Router};
use std::sync::Arc;
use ttk_core::image_trust::{parse_image_allowlist, ImageTrustStore};
use ttk_core::image_trust::{RootAttestation, ROOT_ATTESTATION_PATH};
use ttk_ra_server::server::{BoxError, Listener, Server};

/// Image measurements (enclave image checksums) of the verified enclave images.
const IMAGE_ALLOWLIST: &str = include_str!("image_allowlist.txt");

/// The accepted enclave images, read from an allowlist file (see [`parse_image_allowlist`]).
#[derive(Debug, Clone)]
pub struct FileImageTrustStore {
    /// Image measurements of the verified enclave images.
    image_allowlist: Vec<Vec<u8>>,
}

/// Construction from allowlist text.
impl FileImageTrustStore {
    /// Parses allowlist `text` (one image measurement per line).
    pub fn parse(text: &str) -> Result<Self, String> {
        Ok(Self {
            image_allowlist: parse_image_allowlist(text)?,
        })
    }
}

/// The allowlist file built into this crate.
impl ImageTrustStore for FileImageTrustStore {
    /// The images of the built-in `image_allowlist.txt`.
    fn builtin() -> Self {
        Self::parse(IMAGE_ALLOWLIST).expect("built-in image_allowlist.txt is invalid")
    }

    /// The parsed image measurements.
    fn image_allowlist(&self) -> &[Vec<u8>] {
        &self.image_allowlist
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
