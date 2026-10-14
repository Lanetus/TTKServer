//! TTKServer client library: the RATS (RFC 9334) Verifier / Relying Party side.
//!
//! Connects to TTKServer nodes over QUIC / HTTP/3, verifies the TEE Evidence embedded in their
//! RA-TLS certificates, and builds onion-routed `POST /faf` requests:
//!
//! - the crate root ([`TtkClient`], [`EnclaveCertVerifier`]): the RA-TLS HTTP/3 client.
//! - the crate root ([`FafRequest`], [`parse_relay_address`], [`connect_to_node`]): the
//!   `POST /faf` request format (re-exported from `ttk_core::faf`), relay address parsing and
//!   connecting to the nodes on a route.
//! - [`verifier`]: appraisal of TEE Evidence against vendor roots and policy.
//! - [`trust`]: the vendor trust anchors ([`TrustStore`]) and the root servers' pinned images.
//! - [`images`]: the accepted enclave images, fetched from the root servers
//!   ([`RootImageTrustStore`]).
//! - [`seal`]: onion encryption of `POST /faf` requests to the nodes' RA-TLS keys (RFC 9180 HPKE),
//!   re-exported from `ttk_core::seal`.
//!
//! A relay node receiving a `POST /faf` request removes the first entry of `relays`, reads the
//! next hop's address from it (opening it with its own RA-TLS key if `encrypted`) and forwards
//! the rest of the request there. The terminal node is the last hop: it receives an empty
//! `relays`, and only it can decrypt `body`.

mod client;
pub mod images;
pub mod trust;
pub mod verifier;

use crate::seal::SALT_DIGITS;
use std::net::SocketAddr;

pub use client::*;
pub use images::RootImageTrustStore;
pub use trust::TrustStore;
pub use ttk_core::egress::{classify_hop_address, HopAddressClass};
pub use ttk_core::faf::{FafBody, FafRelay, FafRequest, DEFAULT_RELAY_PORT, FAF_PATH};
pub use ttk_core::image_trust::{
    parse_image_allowlist, ImageMeasurement, ImageTrustStore, RootSignerTrustStore,
};
pub use ttk_core::seal;

/// Boxed error type that can cross task boundaries.
type SendError = Box<dyn std::error::Error + Send + Sync>;

/// Time allowed for the RA-TLS handshake with each resolved address of a node.
pub const RELAY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

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

/// Resolves `host` (see [`resolve_node`]) and connects over `transport` to the first of its
/// addresses that completes an RA-TLS handshake (verified by `verifier`) within
/// [`RELAY_CONNECT_TIMEOUT`], e.g. falling back from `::1` to `127.0.0.1` for `localhost`.
pub async fn connect_to_node(
    transport: ClientTransport,
    host: &str,
    port: u16,
    verifier: EnclaveCertVerifier,
) -> Result<TtkClient, SendError> {
    connect_to_node_filtered(transport, host, port, verifier, |_| true).await
}

/// Like [`connect_to_node`], but only tries the resolved addresses `allow` accepts; if it
/// accepts none, fails without sending anything.
///
/// Used by relay nodes to keep attacker-chosen next hops away from internal addresses (see
/// [`classify_hop_address`]).
pub async fn connect_to_node_filtered(
    transport: ClientTransport,
    host: &str,
    port: u16,
    verifier: EnclaveCertVerifier,
    allow: impl Fn(&SocketAddr) -> bool,
) -> Result<TtkClient, SendError> {
    let mut last_error: SendError = format!("{host} did not resolve").into();
    let mut refused = Vec::new();
    for addr in resolve_node(transport, host, port).await? {
        if !allow(&addr) {
            refused.push(addr.ip().to_string());
            continue;
        }
        let connecting = TtkClient::connect_over(transport, addr, host, verifier.clone());
        match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, connecting).await {
            Ok(Ok(client)) => return Ok(client),
            Ok(Err(e)) => last_error = e,
            Err(_) => last_error = format!("connecting to {addr} timed out").into(),
        }
    }
    if !refused.is_empty() && last_error.to_string().ends_with("did not resolve") {
        last_error = format!(
            "{host} resolved only to refused addresses ({})",
            refused.join(", ")
        )
        .into();
    }
    Err(last_error)
}

/// Resolves `host` (a host name or IP address) to the addresses to try with `port`. Over
/// [`ClientTransport::Udp`] with the system resolver; over [`ClientTransport::Vsock`] on the
/// parent instance, through its `vsock-proxy` (`ttk_core::vsock::resolve_via_parent`), since an
/// enclave has no DNS. Either answer is untrusted: each address must still pass RA-TLS.
pub async fn resolve_node(
    transport: ClientTransport,
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, SendError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    match transport {
        ClientTransport::Udp => Ok(tokio::net::lookup_host((host, port)).await?.collect()),
        #[cfg(target_os = "linux")]
        ClientTransport::Vsock {
            cid,
            port: vsock_port,
        } => Ok(ttk_core::vsock::resolve_via_parent(cid, vsock_port, host, port).await?),
        #[cfg(not(target_os = "linux"))]
        ClientTransport::Vsock { .. } => Err("vsock is only available on Linux".into()),
    }
}
