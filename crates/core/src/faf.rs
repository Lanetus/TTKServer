//! The `POST /faf` request format: an onion-routed message, shared by the clients that build it,
//! the relay nodes that forward it and the terminal node that receives it.
//!
//! A relay node receiving a request removes the first entry of `relays`, reads the next hop's
//! address from it (opening it with its own RA-TLS key if `encrypted`) and forwards the rest of
//! the request there. The terminal node is the last hop: it receives an empty `relays`, and only
//! it can decrypt `body`. See [`crate::seal`] for the encryption.

use serde::{Deserialize, Serialize};

/// Path of the forward-and-forget endpoint.
pub const FAF_PATH: &str = "/faf";

/// Port assumed for a relay address that does not name one.
pub const DEFAULT_RELAY_PORT: u16 = 4433;

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
    /// [`SALT_DIGITS`](crate::seal::SALT_DIGITS) decimal digits, e.g. `"https://server.com:443 0123456789"`.
    ///
    /// If `encrypted`, this is that string sealed to the reading node's RA-TLS key
    /// ([`seal_address`](crate::seal::seal_address)) and the salt is required. Otherwise
    /// it is in the clear and the salt is optional.
    pub address: String,
    /// Whether `address` is sealed to the reading node.
    pub encrypted: bool,
}

/// The message of a [`FafRequest`], sealed to its last hop with
/// [`seal_body`](crate::seal::seal_body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FafBody {
    /// The message key, sealed to the last hop's RA-TLS key. Never null.
    pub key: String,
    /// The message, encrypted with the message key.
    pub message: String,
}
