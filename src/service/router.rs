//! HTTP routes of the RA-TLS server, served over HTTP/3 by [`super::server`]:
//!
//! | Route               | Response                                                        |
//! |---------------------|-----------------------------------------------------------------|
//! | `GET /`             | Greeting text                                                   |
//! | `GET /evidence.eat` | Base64-encoded EAT carrying this server's [`Evidence`]          |
//! | `POST /faf`         | Relays a [`FafRequest`] to its next hop; see [`FafRequest`]     |
//!
//! When forwarding a [`FafRequest`], this server is itself a RATS (RFC 9334) Relying Party: it
//! only sends the request to a relay whose RA-TLS attestation verifies. Verified relay
//! connections are kept open and reused (see [`MAX_POOLED_RELAYS`]), so the RA-TLS handshake
//! and attestation check happen once per relay rather than once per request.

use super::seal::{self, NodeSecretKey, SALT_DIGITS};
use crate::client::{ClientTransport, EnclaveCertVerifier, TtkClient};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Boxed error type that can cross task boundaries.
type SendError = Box<dyn std::error::Error + Send + Sync>;

/// Evidence for this instance, in the formats served over HTTP.
#[derive(Clone, Debug)]
pub struct Evidence {
    /// Raw NSM Attestation Document (COSE_Sign1).
    pub nitro: Vec<u8>,
    /// The same document, wrapped as an RFC 9711 EAT claims-set.
    pub eat: Vec<u8>,
}

/// Port assumed for a relay address that does not name one.
pub const DEFAULT_RELAY_PORT: u16 = 4433;

/// Time allowed for forwarding a `/faf` request to its relay, RA-TLS handshake included.
pub const RELAY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Time allowed for the RA-TLS handshake with each resolved address of a relay.
pub const RELAY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Environment variable that makes [`run`](super::server::run) accept mock attestation from relay servers.
pub const ALLOW_MOCK_RELAY_ENV: &str = "TTK_ALLOW_MOCK_ATTESTATION";

/// Builds the verifier used to attest a relay server. Called once per new relay connection, so
/// each connection gets its own verifier state.
pub type RelayVerifierFactory = Arc<dyn Fn() -> EnclaveCertVerifier + Send + Sync>;

/// Most relay connections kept open for reuse at once. Relays beyond this limit are still
/// served, over a one-off connection closed after the request.
pub const MAX_POOLED_RELAYS: usize = 64;

/// Verified relay connections, keyed by `(host, port)` as given in `relay_server`.
///
/// Entries are not kept alive: a connection closed by the QUIC idle timeout (or the relay) is
/// dropped the next time the pool is consulted.
#[derive(Default)]
struct RelayPool {
    clients: Mutex<HashMap<(String, u16), Arc<TtkClient>>>,
}

/// Lookup, insertion and eviction of pooled relay connections.
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
    /// `false` (and pools nothing) if the pool is full of open connections to other relays.
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

/// State shared by the `/faf` handlers.
#[derive(Clone)]
struct FafState {
    relay_verifier: RelayVerifierFactory,
    /// How relay connections leave this server: UDP, or vsock to the parent from an enclave.
    relay_transport: ClientTransport,
    relays: Arc<RelayPool>,
    /// This server's RA-TLS private key, opening relay addresses and bodies sealed to it.
    node_key: Arc<NodeSecretKey>,
}

/// Body of `POST /faf`: an onion-routed message.
///
/// Every node on the route runs this same server. A node receiving a request with a non-empty
/// `relays` removes the first entry, reads the next hop's address from it (opening it with its
/// own RA-TLS key if `encrypted`) and forwards the rest of the request there, answering `200 OK`
/// once the next hop has. A node receiving an empty `relays` is the last hop: only it can
/// decrypt `body`, and it answers `200 OK` if it can. See [`super::seal`] for the encryption.
///
/// ```json
/// {
///   "relays": [
///     { "address": "https://relay-1.example:443", "encrypted": false },
///     { "address": "<base64 HPKE ciphertext>", "encrypted": true }
///   ],
///   "body": { "key": "<base64 HPKE ciphertext>", "message": "<base64 AES-256-GCM ciphertext>" }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FafRequest {
    /// The remaining hops, in order: the first entry is read by the node the request is at.
    /// Empty at the last hop.
    #[serde(default)]
    pub relays: Vec<FafRelay>,
    /// The message, readable only by the last hop.
    pub body: FafBody,
}

/// One hop of a [`FafRequest`] route: where the node reading it forwards the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FafRelay {
    /// The next hop as `"<server> <salt>"`, where `<server>` is `host[:port]` or
    /// `https://host[:port]` (default port [`DEFAULT_RELAY_PORT`]) and `<salt>` is
    /// [`SALT_DIGITS`] decimal digits, e.g. `"https://server.com:443 0123456789"`.
    ///
    /// If `encrypted`, this is that string sealed to the reading node's RA-TLS key
    /// ([`seal::seal_address`]) and the salt is required. Otherwise it is in the clear and the
    /// salt is optional.
    pub address: String,
    /// Whether `address` is sealed to the reading node.
    pub encrypted: bool,
}

/// The message of a [`FafRequest`], sealed to its last hop with [`seal::seal_body`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FafBody {
    /// The message key, sealed to the last hop's RA-TLS key. Never null.
    pub key: String,
    /// The message, encrypted with the message key.
    pub message: String,
}

/// Builds the Axum router: the greeting, the evidence endpoint and the `/faf` relay.
pub(crate) fn build_router(
    evidence: Arc<Evidence>,
    node_key: Arc<NodeSecretKey>,
    relay_verifier: RelayVerifierFactory,
    relay_transport: ClientTransport,
) -> Router {
    let eat_b64 = STANDARD.encode(&evidence.eat);

    Router::new()
        .route("/", get(|| async { "Hello from Enclave over HTTP/3!" }))
        .route("/evidence.eat", get(move || async move { eat_b64 }))
        .route("/faf", post(faf))
        .with_state(FafState {
            relay_verifier,
            relay_transport,
            relays: Arc::default(),
            node_key,
        })
}

/// `POST /faf`: removes the first relay entry, forwards the rest of the request to the address
/// it names and answers `200 OK` once that hop has; with no relays left, this server is the last
/// hop and answers `200 OK` if it can decrypt the body.
///
/// Answers `400` for a relay entry that can't be opened or parsed, or (as the last hop) a body
/// that can't be decrypted; `502` if the next hop can't be reached, fails attestation or answers
/// anything but `200`; and `504` if it doesn't answer within [`RELAY_TIMEOUT`].
async fn faf(
    State(state): State<FafState>,
    Json(request): Json<FafRequest>,
) -> (StatusCode, String) {
    let FafRequest { mut relays, body } = request;

    if relays.is_empty() {
        // Never log the key or the message itself.
        return match seal::open_body(&state.node_key, &body) {
            Ok(message) => {
                match String::from_utf8(message) {
                    Ok(string) => info!("Success: {string}"),
                    Err(e) => error!("Invalid UTF-8 sequence: {e}"),
                }
                (StatusCode::OK, "delivered".to_string())
            }
            Err(e) => (StatusCode::BAD_REQUEST, format!("invalid body: {e}")),
        };
    }

    let (host, port) = match next_hop(&state.node_key, &relays.remove(0)) {
        Ok(target) => target,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid relay: {e}")),
    };
    let forward = FafRequest { relays, body };

    let relayed = tokio::time::timeout(
        RELAY_TIMEOUT,
        forward_to_relay(&state, &host, port, &forward),
    )
    .await;
    match relayed {
        Ok(Ok(StatusCode::OK)) => {
            info!("/faf: relayed to {host}:{port}");
            (StatusCode::OK, "relayed".to_string())
        }
        Ok(Ok(status)) => {
            warn!("/faf: relay {host}:{port} answered {status}");
            (StatusCode::BAD_GATEWAY, format!("relay answered {status}"))
        }
        Ok(Err(e)) => {
            warn!("/faf: relaying to {host}:{port} failed: {e}");
            (StatusCode::BAD_GATEWAY, format!("relay failed: {e}"))
        }
        Err(_) => {
            warn!("/faf: relay {host}:{port} timed out");
            (StatusCode::GATEWAY_TIMEOUT, "relay timed out".to_string())
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

/// Strips the salt from a relay address `"<server> <salt>"` and returns `<server>`. The salt
/// must be [`SALT_DIGITS`] decimal digits; with `salt_required` false, `"<server>"` alone is
/// also accepted.
pub fn parse_relay_address(address: &str, salt_required: bool) -> Result<&str, String> {
    let address = address.trim();
    match address.rsplit_once(char::is_whitespace) {
        Some((server, salt)) => {
            if salt.len() != SALT_DIGITS || !salt.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("the salt must be {SALT_DIGITS} decimal digits"));
            }
            Ok(server.trim_end())
        }
        None if salt_required => Err("the address has no salt".to_string()),
        None => Ok(address),
    }
}

/// Splits a relay server (`host[:port]` or `https://host[:port][/...]`) into its host (without
/// IPv6 brackets) and port.
pub fn parse_relay_server(relay_server: &str) -> Result<(String, u16), String> {
    let uri: axum::http::Uri = relay_server
        .trim()
        .parse()
        .map_err(|e| format!("{relay_server:?}: {e}"))?;
    if let Some(scheme) = uri.scheme_str() {
        if scheme != "https" {
            return Err(format!(
                "unsupported scheme {scheme:?}; the relay speaks HTTP/3"
            ));
        }
    }
    let authority = uri
        .authority()
        .ok_or_else(|| format!("{relay_server:?} has no host"))?;
    if authority.as_str().contains('@') {
        return Err("user info is not allowed".to_string());
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.is_empty() {
        return Err(format!("{relay_server:?} has no host"));
    }
    let port = authority.port_u16().unwrap_or(DEFAULT_RELAY_PORT);
    Ok((host.to_string(), port))
}

/// Resolves `host` and connects to the first of its addresses that completes an RA-TLS
/// handshake within [`RELAY_CONNECT_TIMEOUT`], e.g. falling back from `::1` to `127.0.0.1`
/// for `localhost`.
async fn connect_to_relay(
    transport: ClientTransport,
    host: &str,
    port: u16,
    verifier: EnclaveCertVerifier,
) -> Result<TtkClient, SendError> {
    let mut last_error: SendError = format!("{host} did not resolve").into();
    for addr in tokio::net::lookup_host((host, port)).await? {
        let connecting = TtkClient::connect_over(transport, addr, host, verifier.clone());
        match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, connecting).await {
            Ok(Ok(client)) => return Ok(client),
            Ok(Err(e)) => last_error = e,
            Err(_) => last_error = format!("connecting to {addr} timed out").into(),
        }
    }
    Err(last_error)
}

/// Posts `request` to the relay's `/faf` and returns the relay's status.
///
/// Reuses the pooled connection to the relay if there is one; otherwise resolves the relay,
/// connects over RA-TLS (verified by a fresh verifier from `state`) and pools the connection.
/// A pooled connection that fails the request after it has closed (e.g. it idled out as the
/// request was sent) is evicted and the request is retried once over a new connection.
async fn forward_to_relay(
    state: &FafState,
    host: &str,
    port: u16,
    request: &FafRequest,
) -> Result<StatusCode, SendError> {
    if let Some(client) = state.relays.get(host, port) {
        match client.post_json("/faf", request).await {
            Ok(response) => return Ok(response.status),
            Err(e) => {
                state.relays.remove(host, port, &client);
                if !client.is_closed() {
                    return Err(e);
                }
                debug!("/faf: pooled connection to {host}:{port} closed ({e}); reconnecting");
            }
        }
    }

    let client = Arc::new(
        connect_to_relay(state.relay_transport, host, port, (state.relay_verifier)()).await?,
    );
    let pooled = state.relays.insert(host, port, client.clone());
    let response = client.post_json("/faf", request).await;
    if !pooled {
        close_in_background(client);
    } else if response.is_err() {
        state.relays.remove(host, port, &client);
    }
    Ok(response?.status)
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
