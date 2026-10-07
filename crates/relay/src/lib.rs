//! TTKServer relay node: an attested [`ttk_ra_server`] server that forwards onion-routed
//! `POST /faf` requests toward their terminal node.
//!
//! | Route               | Response                                                        |
//! |---------------------|-----------------------------------------------------------------|
//! | `GET /`             | Greeting text (from [`ttk_ra_server`])                               |
//! | `GET /evidence.eat` | Base64-encoded EAT carrying this node's Evidence (from [`ttk_ra_server`]) |
//! | `POST /faf`         | Forwards a [`FafRequest`] to its next hop                       |
//!
//! When forwarding a [`FafRequest`], the relay is itself a RATS (RFC 9334) Relying Party: it
//! only sends the request to a next hop whose RA-TLS attestation verifies. Verified connections
//! are kept open and reused (see [`MAX_POOLED_RELAYS`]), so the RA-TLS handshake and attestation
//! check happen once per next hop rather than once per request.
//!
//! Because the next hop comes from the request, a relay also limits where it may send traffic:
//! never to link-local, multicast, broadcast or unspecified addresses, and to loopback or private
//! addresses only with [`Relay::allow_private_next_hops`] (see
//! [`classify_hop_address`]). It caps the hops left in a
//! request at [`MAX_RELAYS`] and the requests it forwards at once at [`MAX_CONCURRENT_FORWARDS`],
//! and answers every forwarding failure with the same `502 relay failed`, so a client can't use
//! it to probe the network.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use ttk_ra_client::faf::{classify_hop_address, connect_to_node_filtered, HopAddressClass};
use ttk_ra_client::faf::{parse_relay_address, parse_relay_server};
use ttk_ra_client::faf::{FafRelay, FafRequest, FAF_PATH};
use ttk_ra_client::seal::{self, NodeSecretKey};
use ttk_ra_client::{ClientResponse, ClientTransport, EnclaveCertVerifier, TtkClient};
use ttk_ra_server::server::{env_u32, BoxError, Listener, Server, PARENT_CID};

/// Boxed error type that can cross task boundaries.
type SendError = Box<dyn std::error::Error + Send + Sync>;

/// Time allowed for forwarding a `/faf` request to its next hop, RA-TLS handshake included.
pub const RELAY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Environment variable that makes [`run`] accept mock attestation from next hops.
pub const ALLOW_MOCK_RELAY_ENV: &str = "TTK_ALLOW_MOCK_ATTESTATION";

/// Default vsock port of the parent's `vsock-proxy` for outbound connections, unless
/// [`OUTBOUND_VSOCK_PORT_ENV`] overrides it.
const OUTBOUND_VSOCK_PORT: u32 = 5001;

/// Environment variable that makes [`run`] accept loopback and private next-hop addresses (see
/// [`Relay::allow_private_next_hops`]).
pub const ALLOW_PRIVATE_NEXT_HOPS_ENV: &str = "TTK_ALLOW_PRIVATE_NEXT_HOPS";

/// Most relay entries a `/faf` request may carry; longer routes are answered `400`.
pub const MAX_RELAYS: usize = 8;

/// Most `/faf` requests a relay forwards at once; beyond it, requests are answered
/// `503 Service Unavailable`.
pub const MAX_CONCURRENT_FORWARDS: usize = 256;

/// Body of every `502` answer: forwarding failures are not told apart, so that a client can't
/// learn from them whether an address resolves, listens or attests.
const RELAY_FAILED: &str = "relay failed";

/// Environment variable that overrides the default outbound vsock port `5001`.
pub const OUTBOUND_VSOCK_PORT_ENV: &str = "TTK_OUTBOUND_VSOCK_PORT";

/// Environment variable that overrides the parent's CID (default [`PARENT_CID`], `3`) for
/// outbound connections.
pub const PARENT_CID_ENV: &str = "TTK_PARENT_CID";

/// Builds the verifier used to attest a next hop. Called once per new connection, so each
/// connection gets its own verifier state.
pub type RelayVerifierFactory = Arc<dyn Fn() -> EnclaveCertVerifier + Send + Sync>;

/// Most next-hop connections kept open for reuse at once. Next hops beyond this limit are still
/// served, over a one-off connection closed after the request.
pub const MAX_POOLED_RELAYS: usize = 64;

/// Runs the relay node: attests, builds the RA-TLS identity, then serves HTTP/3 until the
/// endpoint closes.
///
/// Listens as configured by [`Listener::from_env`]. On vsock it forwards `/faf` requests out
/// through the parent's `vsock-proxy` at vsock `TTK_PARENT_CID`:`TTK_OUTBOUND_VSOCK_PORT`
/// (default `3:5001`); on UDP (`TTK_USE_UDP=1`) it forwards over UDP.
///
/// Next hops must present genuine TEE attestation unless `TTK_ALLOW_MOCK_ATTESTATION=1`, and
/// must have public addresses unless `TTK_ALLOW_PRIVATE_NEXT_HOPS=1`.
pub async fn run() -> Result<(), BoxError> {
    let listener = Listener::from_env()?;
    let mut relay = Relay::new(Server::listen(listener)?);
    if let Listener::Vsock(_) = listener {
        let cid = env_u32(PARENT_CID_ENV, PARENT_CID)?;
        let port = env_u32(OUTBOUND_VSOCK_PORT_ENV, OUTBOUND_VSOCK_PORT)?;
        info!("Relaying out via vsock {cid}:{port}");
        relay = relay.with_transport(ClientTransport::Vsock { cid, port });
    }
    if std::env::var(ALLOW_MOCK_RELAY_ENV).is_ok_and(|v| v == "1") {
        warn!("Accepting MOCK attestation from next hops ({ALLOW_MOCK_RELAY_ENV}=1)");
        relay = relay.allow_mock();
    }
    if std::env::var(ALLOW_PRIVATE_NEXT_HOPS_ENV).is_ok_and(|v| v == "1") {
        warn!("Accepting loopback and private next hops ({ALLOW_PRIVATE_NEXT_HOPS_ENV}=1)");
        relay = relay.allow_private_next_hops();
    }
    relay.serve().await
}

/// A relay node: an attested [`Server`] that also forwards `POST /faf`.
pub struct Relay {
    server: Server,
    verifier: RelayVerifierFactory,
    transport: ClientTransport,
    allow_private_next_hops: bool,
}

/// Setup and serving.
impl Relay {
    /// Wraps `server` with the default (strict) next-hop policy and UDP transport.
    pub fn new(server: Server) -> Self {
        Self {
            server,
            verifier: Arc::new(EnclaveCertVerifier::new),
            transport: ClientTransport::Udp,
            allow_private_next_hops: false,
        }
    }

    /// Attests, builds the RA-TLS identity and binds a relay node to UDP `addr`.
    ///
    /// Must be called within a Tokio runtime. Binding port 0 picks a free port; see
    /// [`local_addr`](Self::local_addr).
    pub fn bind(addr: SocketAddr) -> Result<Self, BoxError> {
        Ok(Self::new(Server::bind(addr)?))
    }

    /// Sets the policy for attesting next hops.
    ///
    /// Defaults to [`EnclaveCertVerifier::new`], which accepts only genuine TEE evidence.
    pub fn with_verifier(
        mut self,
        verifier: impl Fn() -> EnclaveCertVerifier + Send + Sync + 'static,
    ) -> Self {
        self.verifier = Arc::new(verifier);
        self
    }

    /// Accepts mock attestation from next hops (for local development only).
    pub fn allow_mock(self) -> Self {
        self.with_verifier(|| EnclaveCertVerifier::new().allow_mock())
    }

    /// Also accepts next hops on loopback and private addresses (`127.0.0.0/8`, `10/8`,
    /// `172.16/12`, `192.168/16`, `100.64/10`, `::1`, `fc00::/7`): for local development, or
    /// relays that reach each other over a private network. Link-local, multicast, broadcast and
    /// unspecified addresses are refused regardless.
    pub fn allow_private_next_hops(mut self) -> Self {
        self.allow_private_next_hops = true;
        self
    }

    /// Sets how next hops are reached. Defaults to [`ClientTransport::Udp`]; from inside an
    /// enclave, use [`ClientTransport::Vsock`] to go through the parent's `vsock-proxy`.
    pub fn with_transport(mut self, transport: ClientTransport) -> Self {
        self.transport = transport;
        self
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
            .with_state(FafState {
                verifier: self.verifier,
                transport: self.transport,
                pool: Arc::default(),
                node_key: Arc::new(node_key),
                allow_private_next_hops: self.allow_private_next_hops,
                forwards: Arc::new(Semaphore::new(MAX_CONCURRENT_FORWARDS)),
            });
        self.server.serve_with(routes).await;
        Ok(())
    }
}

/// Verified next-hop connections, keyed by `(host, port)` as given in the relay address.
///
/// Entries are not kept alive: a connection closed by the QUIC idle timeout (or the peer) is
/// dropped the next time the pool is consulted.
#[derive(Default)]
struct RelayPool {
    clients: Mutex<HashMap<(String, u16), Arc<TtkClient>>>,
}

/// Lookup, insertion and eviction of pooled next-hop connections.
impl RelayPool {
    /// Returns the open connection to `host:port`, evicting it if it has closed.
    fn get(&self, host: &str, port: u16) -> Option<Arc<TtkClient>> {
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        let key = (host.to_string(), port);
        match clients.get(&key) {
            Some(client) if !client.is_closed() => Some(client.clone()),
            Some(_) => {
                clients.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Pools `client` as the connection to `host:port`, replacing any previous one. Returns
    /// `false` (and pools nothing) if the pool is full of open connections to other hops.
    fn insert(&self, host: &str, port: u16, client: Arc<TtkClient>) -> bool {
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        clients.retain(|_, c| !c.is_closed());
        let key = (host.to_string(), port);
        if clients.len() >= MAX_POOLED_RELAYS && !clients.contains_key(&key) {
            return false;
        }
        clients.insert(key, client);
        true
    }

    /// Evicts `client` from `host:port`, unless it has already been replaced by another one.
    fn remove(&self, host: &str, port: u16, client: &Arc<TtkClient>) {
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        let key = (host.to_string(), port);
        if clients.get(&key).is_some_and(|c| Arc::ptr_eq(c, client)) {
            clients.remove(&key);
        }
    }
}

/// State shared by the `/faf` handler.
#[derive(Clone)]
struct FafState {
    verifier: RelayVerifierFactory,
    /// How next-hop connections leave this node: UDP, or vsock to the parent from an enclave.
    transport: ClientTransport,
    pool: Arc<RelayPool>,
    /// This node's RA-TLS private key, opening relay addresses sealed to it.
    node_key: Arc<NodeSecretKey>,
    /// Whether next hops may have loopback or private addresses.
    allow_private_next_hops: bool,
    /// Permits for requests being forwarded, at most [`MAX_CONCURRENT_FORWARDS`].
    forwards: Arc<Semaphore>,
}

/// Egress policy for next hops.
impl FafState {
    /// Returns whether a next hop may be contacted at `addr`, logging why not.
    fn may_contact(&self, addr: &SocketAddr) -> bool {
        match classify_hop_address(addr.ip()) {
            HopAddressClass::Public => true,
            HopAddressClass::Private if self.allow_private_next_hops => true,
            HopAddressClass::Private => {
                warn!(
                    "/faf: refusing next hop {addr}: loopback/private address \
                     (set {ALLOW_PRIVATE_NEXT_HOPS_ENV}=1 to allow)"
                );
                false
            }
            HopAddressClass::Forbidden => {
                warn!("/faf: refusing next hop {addr}: link-local, multicast or unspecified");
                false
            }
        }
    }
}

/// `POST /faf`: removes the first relay entry, forwards the rest of the request to the address
/// it names and answers `200 OK` with that hop's response body once it has: the terminal's
/// sealed response (see [`seal::seal_response`]) travels back along the route unchanged.
///
/// Answers `400` for a request without relays (only a terminal node is a last hop), with more
/// than [`MAX_RELAYS`], or with a relay entry that can't be opened or parsed; `503` while
/// [`MAX_CONCURRENT_FORWARDS`] requests are already being forwarded; and `502 relay failed` if
/// the next hop has a refused address, can't be reached, fails attestation, answers anything
/// but `200` (or a non-UTF-8 body) or doesn't answer within [`RELAY_TIMEOUT`]. The reason is
/// only logged.
async fn faf(
    State(state): State<FafState>,
    Json(request): Json<FafRequest>,
) -> (StatusCode, String) {
    let FafRequest { mut relays, body } = request;

    if relays.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "no relays left: a relay node is never the last hop".to_string(),
        );
    }

    if relays.len() > MAX_RELAYS {
        return (
            StatusCode::BAD_REQUEST,
            format!("too many relays: at most {MAX_RELAYS}"),
        );
    }
    let Ok(_permit) = state.forwards.clone().try_acquire_owned() else {
        warn!("/faf: {MAX_CONCURRENT_FORWARDS} requests already being forwarded");
        return (StatusCode::SERVICE_UNAVAILABLE, "relay busy".to_string());
    };

    let (host, port) = match next_hop(&state.node_key, &relays.remove(0)) {
        Ok(target) => target,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid relay: {e}")),
    };
    let forward = FafRequest { relays, body };

    let relayed =
        tokio::time::timeout(RELAY_TIMEOUT, forward_to_hop(&state, &host, port, &forward)).await;
    match relayed {
        Ok(Ok(response)) if response.status == StatusCode::OK => {
            match String::from_utf8(response.body) {
                Ok(body) => {
                    info!("/faf: relayed to {host}:{port}");
                    (StatusCode::OK, body)
                }
                Err(_) => {
                    warn!("/faf: relay {host}:{port} answered a non-UTF-8 body");
                    (StatusCode::BAD_GATEWAY, RELAY_FAILED.to_string())
                }
            }
        }
        Ok(Ok(response)) => {
            warn!("/faf: relay {host}:{port} answered {}", response.status);
            (StatusCode::BAD_GATEWAY, RELAY_FAILED.to_string())
        }
        Ok(Err(e)) => {
            warn!("/faf: relaying to {host}:{port} failed: {e}");
            (StatusCode::BAD_GATEWAY, RELAY_FAILED.to_string())
        }
        Err(_) => {
            warn!("/faf: relay {host}:{port} timed out");
            (StatusCode::BAD_GATEWAY, RELAY_FAILED.to_string())
        }
    }
}

/// Reads the next hop's host and port from `relay`, opening it with `node_key` if encrypted.
fn next_hop(node_key: &NodeSecretKey, relay: &FafRelay) -> Result<(String, u16), String> {
    if relay.encrypted {
        let address = seal::open_address(node_key, &relay.address).map_err(|e| e.to_string())?;
        parse_relay_server(parse_relay_address(&address, true)?)
    } else {
        parse_relay_server(parse_relay_address(&relay.address, false)?)
    }
}

/// Posts `request` to the next hop's `/faf` and returns its response.
///
/// Reuses the pooled connection to the hop if there is one; otherwise resolves the hop,
/// connects over RA-TLS (verified by a fresh verifier from `state`) to one of its addresses the
/// egress policy permits, and pools the connection.
/// A pooled connection that fails the request after it has closed (e.g. it idled out as the
/// request was sent) is evicted and the request is retried once over a new connection.
async fn forward_to_hop(
    state: &FafState,
    host: &str,
    port: u16,
    request: &FafRequest,
) -> Result<ClientResponse, SendError> {
    if let Some(client) = state.pool.get(host, port) {
        match client.post_json(FAF_PATH, request).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                state.pool.remove(host, port, &client);
                if !client.is_closed() {
                    return Err(e);
                }
                debug!("/faf: pooled connection to {host}:{port} closed ({e}); reconnecting");
            }
        }
    }

    let client = Arc::new(
        connect_to_node_filtered(state.transport, host, port, (state.verifier)(), |addr| {
            state.may_contact(addr)
        })
        .await?,
    );
    let pooled = state.pool.insert(host, port, client.clone());
    let response = client.post_json(FAF_PATH, request).await;
    if !pooled {
        close_in_background(client);
    } else if response.is_err() {
        state.pool.remove(host, port, &client);
    }
    response
}

/// Closes `client` gracefully without delaying the caller: waiting for the QUIC connection to
/// drain takes about three probe timeouts (tens of milliseconds even on loopback).
fn close_in_background(client: Arc<TtkClient>) {
    if let Ok(client) = Arc::try_unwrap(client) {
        tokio::spawn(async move {
            let _ = client.close().await;
        });
    }
}
