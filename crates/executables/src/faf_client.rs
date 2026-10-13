//! Shared core of the test-only `/faf` client binaries (`client`, `client-m`).
//!
//! Routes a message through two relay nodes to a terminal node:
//!
//! ```text
//! client --> entry relay (--addr) --> second relay (--relay) --> terminal (--terminal)
//! ```
//!
//! [`send`] connects to the entry relay with RA-TLS verification of the enclave's attestation
//! evidence, attests the second relay ([`DEFAULT_RELAY_SERVER`]) and the terminal
//! ([`DEFAULT_TERMINAL_SERVER`]) to learn their RA-TLS keys, and builds an onion-routed
//! [`FafRequest`]: each hop's address is sealed to the relay that reads it, and the message is
//! sealed to the terminal. It sends the request to the entry relay's `POST /faf`, logs the
//! response and decrypts the terminal's reply (sealed under the message key). What the message
//! and the reply mean is up to each binary.

use axum::http::Uri;
use log::{error, info, warn};
use std::net::SocketAddr;
use std::time::Instant;
use ttk_ra_client::seal::{self, NodePublicKey};
use ttk_ra_client::{connect_to_node, parse_relay_server, FafRelay, FafRequest, FAF_PATH};
use ttk_ra_client::{ClientTransport, EnclaveCertVerifier, TtkClient};

/// Error of the `/faf` client: `Send + Sync`, like the clients' `main`.
pub type ClientError = Box<dyn std::error::Error + Send + Sync>;

/// Entry relay node unless `TTK_SERVER_ADDR`, `--addr` or a positional URL overrides it (and
/// the fallback for an unparsable address).
pub const DEFAULT_SERVER_ADDR: &str = "127.0.0.1:4433";

/// SNI server name unless `TTK_SERVER_NAME`, `--server-name` or a positional URL overrides it.
pub const DEFAULT_SERVER_NAME: &str = "localhost";

/// Second relay node, which the entry relay forwards the `FafRequest` to unless `--relay`
/// overrides it.
pub const DEFAULT_RELAY_SERVER: &str = "127.0.0.1:4434";

/// Terminal node (the last hop) unless `--terminal` overrides it.
pub const DEFAULT_TERMINAL_SERVER: &str = "127.0.0.1:4444";

/// Where a `/faf` client sends its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// Entry relay node socket address.
    pub server_addr: SocketAddr,
    /// SNI server name.
    pub server_name: String,
    /// Second relay node, as `host[:port]` or `https://host[:port]`.
    pub relay_server: String,
    /// Terminal node the request is routed to, as `host[:port]` or `https://host[:port]`.
    pub terminal_server: String,
}

/// The [`Route`] arguments while they are parsed: `--server-name`/`-s`, `--addr`/`-a`,
/// `--relay`/`-r`, `--terminal`/`-t` and a positional URL or address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteArgs {
    server_addr: String,
    server_name: String,
    relay_server: String,
    terminal_server: String,
}

impl RouteArgs {
    /// Starts from `default_addr` and `default_name` (from `TTK_SERVER_ADDR` and
    /// `TTK_SERVER_NAME`), falling back to [`DEFAULT_SERVER_ADDR`] and [`DEFAULT_SERVER_NAME`],
    /// and from [`DEFAULT_RELAY_SERVER`] and [`DEFAULT_TERMINAL_SERVER`].
    pub fn new(default_addr: Option<String>, default_name: Option<String>) -> Self {
        Self {
            server_addr: default_addr.unwrap_or_else(|| DEFAULT_SERVER_ADDR.to_string()),
            server_name: default_name.unwrap_or_else(|| DEFAULT_SERVER_NAME.to_string()),
            relay_server: DEFAULT_RELAY_SERVER.to_string(),
            terminal_server: DEFAULT_TERMINAL_SERVER.to_string(),
        }
    }

    /// Parses `args[*i]` if it is a route argument, advancing `*i` past its value, and returns
    /// whether it was one. Any path of a positional URL is ignored (requests always go to
    /// `/faf`).
    pub fn parse_arg(&mut self, args: &[String], i: &mut usize) -> bool {
        let arg = &args[*i];
        let has_value = *i + 1 < args.len();
        let field = match arg.as_str() {
            "--server-name" | "-s" if has_value => &mut self.server_name,
            "--addr" | "-a" if has_value => &mut self.server_addr,
            "--relay" | "-r" if has_value => &mut self.relay_server,
            "--terminal" | "-t" if has_value => &mut self.terminal_server,
            _ if !arg.starts_with('-') => {
                if let Ok(uri) = arg.parse::<Uri>() {
                    if let Some(host) = uri.host() {
                        let port = uri.port_u16().unwrap_or(4433);
                        self.server_addr = format!("{}:{}", host, port);
                        if host != "127.0.0.1" && host != "0.0.0.0" {
                            self.server_name = host.to_string();
                        }
                    }
                } else {
                    self.server_addr = arg.clone();
                }
                return true;
            }
            _ => return false,
        };
        *i += 1;
        *field = args[*i].clone();
        true
    }

    /// The parsed [`Route`]; an unparsable entry relay address falls back to
    /// [`DEFAULT_SERVER_ADDR`].
    pub fn build(self) -> Route {
        Route {
            server_addr: self
                .server_addr
                .parse()
                .unwrap_or_else(|_| DEFAULT_SERVER_ADDR.parse().unwrap()),
            server_name: self.server_name,
            relay_server: self.relay_server,
            terminal_server: self.terminal_server,
        }
    }
}

/// Parses the process arguments (without the program name) and `TTK_SERVER_ADDR` /
/// `TTK_SERVER_NAME` with `parse`, printing `usage` and exiting on help (`Ok(None)`), and
/// exiting with status 2 on invalid arguments.
pub fn parse_process_args<T>(
    parse: impl FnOnce(&[String], Option<String>, Option<String>) -> Result<Option<T>, String>,
    usage: &str,
) -> T {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(
        &args,
        std::env::var("TTK_SERVER_ADDR").ok(),
        std::env::var("TTK_SERVER_NAME").ok(),
    ) {
        Ok(Some(target)) => target,
        Ok(None) => {
            print!("{usage}");
            std::process::exit(0);
        }
        Err(e) => {
            error!("{e} (see --help)");
            std::process::exit(2);
        }
    }
}

/// Sends `message` along `route` (see the [module docs](self)) and returns the terminal's
/// decrypted reply, or `None` if the request failed or was not answered `200` (logged).
///
/// `TTK_ALLOW_MOCK_ATTESTATION=1` accepts mock attestation. Errors (connecting to the entry
/// relay, attesting a hop, sealing, decrypting the reply) are fatal for the clients.
pub async fn send(route: &Route, message: &[u8]) -> Result<Option<Vec<u8>>, ClientError> {
    let Route {
        server_addr,
        server_name,
        relay_server,
        terminal_server,
    } = route;

    info!("TTKServer HTTP/3 client (RFC 9114) connecting to {server_addr} (SNI: {server_name})");

    let mut verifier = EnclaveCertVerifier::new();
    if std::env::var("TTK_ALLOW_MOCK_ATTESTATION").is_ok_and(|v| v == "1") {
        warn!("Accepting MOCK attestation (TTK_ALLOW_MOCK_ATTESTATION=1)");
        verifier = verifier.allow_mock();
    }

    let client = TtkClient::connect_with_verifier(*server_addr, server_name, verifier.clone())
        .await
        .map_err(|e| format!("Failed to connect to TTKServer at {server_addr}: {e}"))?;

    if let Some(fingerprint) = client.peer_cert_sha256_hex() {
        info!(
            "Server certificate SHA-256 fingerprint {fingerprint} \
             (attestation verified and bound to this certificate's key)"
        );
    }

    info!("--> Attesting relay {relay_server} to seal the terminal's address to it");
    let relay_key = attest_node(relay_server, verifier.clone())
        .await
        .map_err(|e| format!("Failed to attest relay {relay_server}: {e}"))?;
    info!("--> Attesting terminal {terminal_server} to seal the message to it");
    let terminal_key = attest_node(terminal_server, verifier)
        .await
        .map_err(|e| format!("Failed to attest terminal {terminal_server}: {e}"))?;

    // Each hop's address is sealed to the relay that reads it: the entry relay learns only the
    // second relay, which learns only the terminal. Only the terminal can open the body.
    let (body, message_key) = seal::seal_body_with_key(&terminal_key, message)?;
    let request = FafRequest {
        relays: vec![
            FafRelay {
                address: relay_server.clone(),
                encrypted: false,
            },
            FafRelay {
                address: seal::seal_address(&relay_key, terminal_server)?,
                encrypted: true,
            },
        ],
        body,
    };

    info!(
        "--> Sending POST {FAF_PATH} (route: {server_addr} -> {relay_server} -> {terminal_server})"
    );
    let started = Instant::now();
    let result = client.post_json(FAF_PATH, &request).await;
    let elapsed = started.elapsed();
    let mut reply = None;
    match result {
        Ok(resp) => {
            info!("<-- Response Status: {} (in {:.3?})", resp.status, elapsed);
            info!("<-- Headers:");
            for (name, val) in &resp.headers {
                info!("    {}: {}", name, val.to_str().unwrap_or("<binary>"));
            }
            match resp.text() {
                Ok(body_str) => info!("<-- Body: {}", body_str),
                Err(_) => info!("<-- Body (binary, {} bytes)", resp.body.len()),
            }
            if resp.status == 200 {
                let opened = resp
                    .text()
                    .map_err(|e| e.to_string())
                    .and_then(|sealed| {
                        seal::open_response(&message_key, &sealed).map_err(|e| e.to_string())
                    })
                    .map_err(|e| format!("Failed to decrypt the terminal's reply: {e}"))?;
                reply = Some(opened);
            }
        }
        Err(e) => {
            error!(
                "Error sending request to {} after {:.3?}: {}",
                FAF_PATH, elapsed, e
            );
        }
    }

    info!("Closing connection...");
    client.close().await?;
    info!("Connection closed successfully.");

    Ok(reply)
}

/// Connects to the node `server` with `verifier`, and returns the RA-TLS key of the first of its
/// addresses whose attestation verifies (see [`connect_to_node`]).
pub async fn attest_node(
    server: &str,
    verifier: EnclaveCertVerifier,
) -> Result<NodePublicKey, ClientError> {
    let (host, port) = parse_relay_server(server)?;
    let node = connect_to_node(ClientTransport::Udp, &host, port, verifier).await?;
    let key = node
        .peer_cert()
        .ok_or("node presented no certificate")
        .map(|cert| NodePublicKey::from_certificate(cert));
    node.close().await?;
    Ok(key??)
}
