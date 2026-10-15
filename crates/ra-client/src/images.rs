//! The accepted enclave images (RFC 9334 reference values), fetched from the root servers.
//!
//! The root nodes (`ttk_root`, at `ROOT_SERVERS`) publish the image measurements of the
//! verified enclave images at [`ROOT_ATTESTATION_PATH`]. [`RootImageTrustStore`] fetches that
//! list over RA-TLS; each root server's own attestation is checked against the signers pinned in
//! [`RootSignerTrustStore`], since the image allowlist is not known yet.
//!
//! An [`EnclaveCertVerifier`] without an explicit image trust store uses a process-wide copy of
//! the list, fetched the first time non-debug Evidence is appraised (or at startup with
//! [`prefetch_root_images`]) and refreshed in the background every
//! [`ROOT_IMAGES_REFRESH_INTERVAL`]; appraisals never hold a lock across a fetch.

use crate::{connect_to_node, parse_relay_server};
use crate::{ClientTransport, EnclaveCertVerifier};
use crate::{ImageTrustStore, RootSignerTrustStore};
use log::{error, info, warn};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use ttk_core::image_trust::{RootAttestation, ROOT_ATTESTATION_PATH};

/// Boxed error type that can cross task boundaries.
type SendError = Box<dyn std::error::Error + Send + Sync>;

/// The root servers publishing the accepted enclave images, tried in order.
const ROOT_SERVERS: &[&str] = &["a.root.ttk-servers.net:443", "b.root.ttk-servers.net:443"];

/// Time allowed for fetching the image list from one root server, RA-TLS handshake included.
const ROOT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// How [`RootImageTrustStore::builtin`] reaches the root servers; see [`set_root_transport`].
static ROOT_TRANSPORT: Mutex<ClientTransport> = Mutex::new(ClientTransport::Udp);

/// Sets how [`RootImageTrustStore::builtin`] reaches the root servers, process-wide. Defaults
/// to [`ClientTransport::Udp`]; from inside an enclave, use [`ClientTransport::Vsock`] to go
/// through the parent's `vsock-proxy`.
pub fn set_root_transport(transport: ClientTransport) {
    *ROOT_TRANSPORT.lock().unwrap_or_else(|e| e.into_inner()) = transport;
}

/// The accepted enclave images (image measurements), as published by a root server.
#[derive(Debug, Clone, Default)]
pub struct RootImageTrustStore {
    /// Image measurements of the verified enclave images.
    pub image_allowlist: Vec<Vec<u8>>,
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
                        images.image_allowlist.len()
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

    /// Fetches the list from the built-in `ROOT_SERVERS` over `transport`, attesting each
    /// root against the pinned [`RootSignerTrustStore`].
    async fn fetch_builtin(transport: ClientTransport) -> Result<Self, SendError> {
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
        let image_allowlist = body.measurement_values()?;
        if image_allowlist.is_empty() {
            return Err("the root server lists no accepted images".into());
        }
        Ok(Self { image_allowlist })
    }
}

/// The list published by the root servers.
impl ImageTrustStore for RootImageTrustStore {
    /// Fetches the list from `ROOT_SERVERS` (over the transport of [`set_root_transport`]),
    /// blocking the calling thread; the fetch runs on a thread of its own, so this may be
    /// called from within a Tokio runtime.
    ///
    /// Fails closed: if no root server answers, returns an empty list, which rejects every
    /// non-debug image.
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

    /// The fetched image measurements.
    fn image_allowlist(&self) -> &[Vec<u8>] {
        &self.image_allowlist
    }
}

/// Time after a failed fetch before the root servers are tried again; until then, the last
/// fetched list stays in use while it is younger than [`ROOT_IMAGES_MAX_AGE`] (otherwise the empty
/// list rejects every non-debug image).
const ROOT_FETCH_RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// Age after which the fetched list is refreshed in the background, so that an image removed from
/// the root servers' allowlist stops being accepted without restarting the process.
pub const ROOT_IMAGES_REFRESH_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Age after which a fetched list that could not be refreshed is no longer used: the verifier
/// then fails closed (empty list) until a fetch succeeds again.
const ROOT_IMAGES_MAX_AGE: Duration = Duration::from_secs(60 * 60);

/// Longest an appraisal waits for an in-flight fetch when no usable list is held yet (cold
/// start, or past [`ROOT_IMAGES_MAX_AGE`]). Relays avoid even this wait with
/// [`prefetch_root_images`] at startup.
const ROOT_FETCH_WAIT: Duration = Duration::from_secs(2 * ROOT_FETCH_TIMEOUT.as_secs());

/// The process-wide state of the list fetched from the root servers.
#[derive(Debug)]
struct RootImagesCache {
    /// The last successfully fetched list, and when it was fetched.
    images: Option<(Arc<RootImageTrustStore>, Instant)>,
    /// Whether a background fetch is running.
    refreshing: bool,
    /// When the last fetch was started.
    last_attempt: Option<Instant>,
}

/// The process-wide fetched list. The lock is never held across a fetch.
static CACHE: Mutex<RootImagesCache> = Mutex::new(RootImagesCache {
    images: None,
    refreshing: false,
    last_attempt: None,
});

/// Signalled when a background fetch ends.
static FETCH_DONE: Condvar = Condvar::new();

/// Locks [`CACHE`], ignoring poisoning (the state stays consistent at every unlock).
fn lock_cache() -> MutexGuard<'static, RootImagesCache> {
    CACHE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Returns the list held in `cache` if it is younger than [`ROOT_IMAGES_MAX_AGE`].
fn usable(cache: &RootImagesCache) -> Option<Arc<RootImageTrustStore>> {
    match &cache.images {
        Some((images, at)) if at.elapsed() < ROOT_IMAGES_MAX_AGE => Some(images.clone()),
        _ => None,
    }
}

/// Starts a background fetch if the held list is missing or older than
/// [`ROOT_IMAGES_REFRESH_INTERVAL`], no fetch is running, and the last one started at least
/// [`ROOT_FETCH_RETRY_INTERVAL`] ago.
fn refresh_if_due(cache: &mut RootImagesCache) {
    let stale = cache
        .images
        .as_ref()
        .is_none_or(|(_, at)| at.elapsed() >= ROOT_IMAGES_REFRESH_INTERVAL);
    let may_retry = cache
        .last_attempt
        .is_none_or(|at| at.elapsed() >= ROOT_FETCH_RETRY_INTERVAL);
    if !stale || cache.refreshing || !may_retry {
        return;
    }
    cache.refreshing = true;
    cache.last_attempt = Some(Instant::now());
    let spawned = std::thread::Builder::new()
        .name("ttk-root-images".into())
        .spawn(|| {
            let fetched = RootImageTrustStore::builtin();
            let mut cache = lock_cache();
            cache.refreshing = false;
            if fetched.image_allowlist.is_empty() {
                warn!("Keeping the previously fetched accepted enclave images, if any");
            } else {
                cache.images = Some((Arc::new(fetched), Instant::now()));
            }
            FETCH_DONE.notify_all();
        });
    if let Err(e) = spawned {
        error!("Could not start fetching the accepted enclave images: {e}");
        cache.refreshing = false;
    }
}

/// Starts fetching the accepted enclave images from the root servers in the background (over
/// the transport of [`set_root_transport`]), so that the first appraisal does not wait for it.
/// Never blocks; does nothing if a fresh list is held or a fetch is already running.
pub fn prefetch_root_images() {
    refresh_if_due(&mut lock_cache());
}

/// Returns the process-wide fetched list without blocking on the root servers while one is
/// held: a list older than [`ROOT_IMAGES_REFRESH_INTERVAL`] is still returned while it is
/// refreshed in the background. Only with no usable list (cold start, or every refresh failed
/// for [`ROOT_IMAGES_MAX_AGE`]) does it wait, at most [`ROOT_FETCH_WAIT`], for a running fetch;
/// it then fails closed with an empty list.
fn fetched() -> Arc<RootImageTrustStore> {
    let mut cache = lock_cache();
    refresh_if_due(&mut cache);
    if let Some(images) = usable(&cache) {
        return images;
    }
    if cache.refreshing {
        // Waiting releases the lock, so the fetch and other appraisals are not held up.
        cache = FETCH_DONE
            .wait_timeout_while(cache, ROOT_FETCH_WAIT, |cache| cache.refreshing)
            .unwrap_or_else(|e| e.into_inner())
            .0;
    }
    usable(&cache).unwrap_or_default()
}

/// The default image trust store of an [`EnclaveCertVerifier`]: a snapshot of the process-wide
/// [`RootImageTrustStore`], taken only when an allowlist is first needed (debug and mock
/// Evidence never needs one). Each appraisal uses a new handle, so it sees the latest list.
#[derive(Debug, Default)]
pub(crate) struct LazyRootImages(OnceLock<Arc<RootImageTrustStore>>);

/// Defers to the process-wide fetched list.
impl ImageTrustStore for LazyRootImages {
    /// An empty handle; nothing is fetched yet.
    fn builtin() -> Self {
        Self::default()
    }

    /// The fetched image measurements, taking the snapshot on first use.
    fn image_allowlist(&self) -> &[Vec<u8>] {
        self.0.get_or_init(fetched).image_allowlist()
    }
}
