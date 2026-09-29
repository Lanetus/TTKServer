//! HTTP routes of the RA-TLS server, served over HTTP/3 by [`super::server`]:
//!
//! | Route               | Response                                                        |
//! |---------------------|-----------------------------------------------------------------|
//! | `GET /`             | Greeting text                                                   |
//! | `GET /evidence.eat` | Base64-encoded EAT carrying this server's [`Evidence`]          |
//! | `POST /faf`         | Forwards a [`FafRequest`] to its relay; see [`FafRequest`]      |
//!
//! When forwarding a [`FafRequest`], this server is itself a RATS (RFC 9334) Relying Party: it
//! only sends the message and key to a relay whose RA-TLS attestation verifies.

use crate::client::{EnclaveCertVerifier, TtkClient};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

/// Port assumed for a `relay_server` that does not name one.
pub const DEFAULT_RELAY_PORT: u16 = 4433;

/// Time allowed for forwarding a `/faf` request to its relay, RA-TLS handshake included.
pub const RELAY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Time allowed for the RA-TLS handshake with each resolved address of a relay.
pub const RELAY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Environment variable that makes [`run`](super::server::run) accept mock attestation from relay servers.
pub const ALLOW_MOCK_RELAY_ENV: &str = "TTK_ALLOW_MOCK_ATTESTATION";

/// Builds the verifier used to attest a relay server. Called once per forwarded request, so
/// each connection gets its own verifier state.
pub type RelayVerifierFactory = Arc<dyn Fn() -> EnclaveCertVerifier + Send + Sync>;

/// Body of `POST /faf`: a message and key to hand to `relay_server`.
///
/// The relay runs this same server. The message and key are forwarded to its `POST /faf`
/// without `relay_server`, which tells the relay it is the last hop: it accepts the request and
/// answers `200 OK`. This server answers `200 OK` once the relay has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FafRequest {
    /// Relay to forward to, as `host[:port]` or `https://host[:port]` (default port
    /// [`DEFAULT_RELAY_PORT`]). Absent when this server is the last hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_server: Option<String>,
    /// The message to transmit.
    pub message: String,
    /// The key to transmit alongside the message.
    pub key: String,
}

/// Builds the Axum router: the greeting, the evidence endpoint and the `/faf` relay.
pub(crate) fn build_router(
    evidence: Arc<Evidence>,
    relay_verifier: RelayVerifierFactory,
) -> Router {
    let eat_b64 = STANDARD.encode(&evidence.eat);

    Router::new()
        .route("/", get(|| async { "Hello from Enclave over HTTP/3!" }))
        .route("/evidence.eat", get(move || async move { eat_b64 }))
        .route("/faf", post(faf))
        .with_state(relay_verifier)
}

/// `POST /faf`: forwards the message and key to the relay and answers `200 OK` once the relay
/// has; with no `relay_server`, this server is the last hop and accepts the request directly.
///
/// Answers `400` for an unparsable `relay_server`, `502` if the relay can't be reached, fails
/// attestation or answers anything but `200`, and `504` if it doesn't answer within
/// [`RELAY_TIMEOUT`].
async fn faf(
    State(relay_verifier): State<RelayVerifierFactory>,
    Json(request): Json<FafRequest>,
) -> (StatusCode, String) {
    let FafRequest {
        relay_server,
        message,
        key,
    } = request;

    let Some(relay_server) = relay_server else {
        // Never log the key or the message itself.
        info!(
            "/faf: accepted a {}-byte message as the last hop",
            message.len()
        );
        return (StatusCode::OK, "delivered".to_string());
    };

    let (host, port) = match parse_relay_server(&relay_server) {
        Ok(target) => target,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid relay_server: {e}"),
            )
        }
    };
    let forward = FafRequest {
        relay_server: None,
        message,
        key,
    };

    let relayed = tokio::time::timeout(
        RELAY_TIMEOUT,
        forward_to_relay(&host, port, relay_verifier(), &forward),
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

/// Splits a `relay_server` value (`host[:port]` or `https://host[:port][/...]`) into its host
/// (without IPv6 brackets) and port.
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
    host: &str,
    port: u16,
    verifier: EnclaveCertVerifier,
) -> Result<TtkClient, SendError> {
    let mut last_error: SendError = format!("{host} did not resolve").into();
    for addr in tokio::net::lookup_host((host, port)).await? {
        let connecting = TtkClient::connect_with_verifier(addr, host, verifier.clone());
        match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, connecting).await {
            Ok(Ok(client)) => return Ok(client),
            Ok(Err(e)) => last_error = e,
            Err(_) => last_error = format!("connecting to {addr} timed out").into(),
        }
    }
    Err(last_error)
}

/// Resolves the relay, connects over RA-TLS (verified by `verifier`), posts `request` to its
/// `/faf` and returns the relay's status.
async fn forward_to_relay(
    host: &str,
    port: u16,
    verifier: EnclaveCertVerifier,
    request: &FafRequest,
) -> Result<StatusCode, SendError> {
    let mut client = connect_to_relay(host, port, verifier).await?;
    let response = client.post_json("/faf", request).await;
    let _ = client.close().await;
    Ok(response?.status)
}
