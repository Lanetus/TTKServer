//! The accepted enclave images (RFC 9334 reference values), fetched from the root servers.
//!
//! The root nodes (`ttk_root`, at [`ROOT_SERVERS`]) publish the PCR0 values of the verified
//! enclave images at [`ROOT_ATTESTATION_PATH`]. [`RootImageTrustStore`] fetches that list over
//! RA-TLS; each root server's own attestation is checked against the PCR8 values pinned in
//! [`RootSignerTrustStore`], since the PCR0 allowlist is not known yet.
//!
//! An [`EnclaveCertVerifier`] without an explicit image trust store fetches the list lazily,
//! the first time it appraises non-debug Nitro Evidence, and shares it process-wide.

use crate::faf::{connect_to_node, parse_relay_server};
use crate::trust::{ImageTrustStore, RootSignerTrustStore};
use crate::{ClientTransport, EnclaveCertVerifier};
use log::{error, info, warn};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
pub use ttk_core::image_trust::{RootAttestation, ROOT_ATTESTATION_PATH};

/// Boxed error type that can cross task boundaries.
type SendError = Box<dyn std::error::Error + Send + Sync>;

/// The root servers publishing the accepted enclave images, tried in order.
pub const ROOT_SERVERS: &[&str] = &["a.ttk-server.net:443", "b.ttk-server.net:443"];

/// Time allowed for fetching the image list from one root server, RA-TLS handshake included.
pub const ROOT_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How [`RootImageTrustStore::builtin`] reaches the root servers; see [`set_root_transport`].
static ROOT_TRANSPORT: Mutex<ClientTransport> = Mutex::new(ClientTransport::Udp);

/// Sets how [`RootImageTrustStore::builtin`] reaches the root servers, process-wide. Defaults
/// to [`ClientTransport::Udp`]; from inside an enclave, use [`ClientTransport::Vsock`] to go
/// through the parent's `vsock-proxy`.
pub fn set_root_transport(transport: ClientTransport) {
    *ROOT_TRANSPORT.lock().unwrap_or_else(|e| e.into_inner()) = transport;
}

/// The accepted enclave images (PCR0 values), as published by a root server.
#[derive(Debug, Clone, Default)]
pub struct RootImageTrustStore {
    /// PCR0 values (SHA-384 of the enclave image file) of the verified Nitro enclave images.
    pub nitro_image_allowlist: Vec<Vec<u8>>,
}

/// Fetching from the root servers.
impl RootImageTrustStore {
    /// Fetches the list from the first of `roots` (`host[:port]`) that answers, reached over
    /// `transport` and attested by `verifier`.
    pub async fn fetch(
        roots: &[&str],
        transport: ClientTransport,
        verifier: EnclaveCertVerifier,
    ) -> Result<Self, SendError> {
        let mut last_error: SendError = "no root servers configured".into();
        for root in roots {
            let fetching = Self::fetch_from(root, transport, verifier.clone());
            match tokio::time::timeout(ROOT_FETCH_TIMEOUT, fetching).await {
                Ok(Ok(images)) => {
                    info!(
                        "Fetched {} accepted enclave images from root server {root}",
                        images.nitro_image_allowlist.len()
                    );
                    return Ok(images);
                }
                Ok(Err(e)) => last_error = format!("root server {root}: {e}").into(),
                Err(_) => last_error = format!("root server {root}: timed out").into(),
            }
            warn!("{last_error}");
        }
        Err(last_error)
    }

    /// Fetches the list from the built-in [`ROOT_SERVERS`] over `transport`, attesting each
    /// root against the pinned [`RootSignerTrustStore`].
    pub async fn fetch_builtin(transport: ClientTransport) -> Result<Self, SendError> {
        let verifier =
            EnclaveCertVerifier::new().with_image_trust_store(RootSignerTrustStore::builtin());
        Self::fetch(ROOT_SERVERS, transport, verifier).await
    }

    /// Fetches the list from one root server.
    async fn fetch_from(
        root: &str,
        transport: ClientTransport,
        verifier: EnclaveCertVerifier,
    ) -> Result<Self, SendError> {
        let (host, port) = parse_relay_server(root)?;
        let client = connect_to_node(transport, &host, port, verifier).await?;
        let response = client.get(ROOT_ATTESTATION_PATH).await?;
        if !response.status.is_success() {
            return Err(format!("{ROOT_ATTESTATION_PATH} answered {}", response.status).into());
        }
        let body: RootAttestation = serde_json::from_slice(&response.body)?;
        let nitro_image_allowlist = body.pcr0_values()?;
        if nitro_image_allowlist.is_empty() {
            return Err("the root server lists no accepted images".into());
        }
        Ok(Self {
            nitro_image_allowlist,
        })
    }
}

/// The list published by the root servers.
impl ImageTrustStore for RootImageTrustStore {
    /// Fetches the list from [`ROOT_SERVERS`] (over the transport of [`set_root_transport`]),
    /// blocking the calling thread; the fetch runs on a thread of its own, so this may be
    /// called from within a Tokio runtime.
    ///
    /// Fails closed: if no root server answers, returns an empty list, which rejects every
    /// non-debug Nitro image.
    fn builtin() -> Self {
        let transport = *ROOT_TRANSPORT.lock().unwrap_or_else(|e| e.into_inner());
        let fetched = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(SendError::from)?
                .block_on(Self::fetch_builtin(transport))
        })
        .join();
        match fetched {
            Ok(Ok(images)) => images,
            Ok(Err(e)) => {
                error!("Could not fetch the accepted enclave images: {e}");
                Self::default()
            }
            Err(_) => {
                error!("Fetching the accepted enclave images panicked");
                Self::default()
            }
        }
    }

    /// The fetched PCR0 values.
    fn nitro_image_allowlist(&self) -> &[Vec<u8>] {
        &self.nitro_image_allowlist
    }
}

/// Time after a failed fetch before an [`EnclaveCertVerifier`] tries the root servers again; until
/// then, the empty list rejects every non-debug Nitro image.
pub const ROOT_FETCH_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The process-wide list fetched by [`RootImageTrustStore::builtin`], and when it was fetched.
static FETCHED: Mutex<Option<(Arc<RootImageTrustStore>, Instant)>> = Mutex::new(None);

/// Returns the process-wide fetched list, fetching it if no fetch has succeeded yet and the
/// last failed one is older than [`ROOT_FETCH_RETRY_INTERVAL`].
fn fetched() -> Arc<RootImageTrustStore> {
    let mut cached = FETCHED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((images, at)) = cached.as_ref() {
        if !images.nitro_image_allowlist.is_empty() || at.elapsed() < ROOT_FETCH_RETRY_INTERVAL {
            return images.clone();
        }
    }
    let images = Arc::new(RootImageTrustStore::builtin());
    *cached = Some((images.clone(), Instant::now()));
    images
}

/// The default image trust store of an [`EnclaveCertVerifier`]: the process-wide
/// [`RootImageTrustStore`], fetched only when an allowlist is first needed (debug and mock
/// Evidence never needs one).
#[derive(Debug, Default)]
pub(crate) struct LazyRootImages(OnceLock<Arc<RootImageTrustStore>>);

/// Defers to the process-wide fetched list.
impl ImageTrustStore for LazyRootImages {
    /// An empty handle; nothing is fetched yet.
    fn builtin() -> Self {
        Self::default()
    }

    /// The fetched PCR0 values, fetching them on first use.
    fn nitro_image_allowlist(&self) -> &[Vec<u8>] {
        self.0.get_or_init(fetched).nitro_image_allowlist()
    }
}
