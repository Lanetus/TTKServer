//! The `POST /faf` request format: an onion-routed message, shared by the clients that build it,
//! the relay nodes that forward it and the terminal node that receives it.
//!
//! A relay node receiving a request removes the first entry of `relays`, reads the next hop's
//! address from it (opening it with its own RA-TLS key if `encrypted`) and forwards the rest of
//! the request there. The terminal node is the last hop: it receives an empty `relays`, and only
//! it can decrypt `body`. See [`crate::seal`] for the encryption.

use crate::seal::SALT_DIGITS;
use crate::{ClientTransport, EnclaveCertVerifier, TtkClient};
use serde::{Deserialize, Serialize};

/// Boxed error type that can cross task boundaries.
type SendError = Box<dyn std::error::Error + Send + Sync>;

/// Path of the forward-and-forget endpoint.
pub const FAF_PATH: &str = "/faf";

/// Port assumed for a relay address that does not name one.
pub const DEFAULT_RELAY_PORT: u16 = 4433;

/// Time allowed for the RA-TLS handshake with each resolved address of a node.
pub const RELAY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Body of `POST /faf`: an onion-routed message.
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
    /// ([`seal::seal_address`](crate::seal::seal_address)) and the salt is required. Otherwise
    /// it is in the clear and the salt is optional.
    pub address: String,
    /// Whether `address` is sealed to the reading node.
    pub encrypted: bool,
}

/// The message of a [`FafRequest`], sealed to its last hop with
/// [`seal::seal_body`](crate::seal::seal_body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FafBody {
    /// The message key, sealed to the last hop's RA-TLS key. Never null.
    pub key: String,
    /// The message, encrypted with the message key.
    pub message: String,
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

/// Resolves `host` and connects over `transport` to the first of its addresses that completes
/// an RA-TLS handshake (verified by `verifier`) within [`RELAY_CONNECT_TIMEOUT`], e.g. falling
/// back from `::1` to `127.0.0.1` for `localhost`.
pub async fn connect_to_node(
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
