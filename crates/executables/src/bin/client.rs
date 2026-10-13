//! `client` binary: command-line HTTP/3 client for TTKServer, for testing only.
//!
//! Thin entry point over [`ttk_ra_client`]: parses CLI arguments / environment and routes a message
//! through two relay nodes to a terminal node:
//!
//! ```text
//! client --> entry relay (--addr) --> second relay (--relay) --> terminal (--terminal)
//! ```
//!
//! It connects to the entry relay with RA-TLS verification of the enclave's attestation
//! evidence, attests the second relay ([`DEFAULT_RELAY_SERVER`]) and the terminal
//! ([`DEFAULT_TERMINAL_SERVER`]) to learn their RA-TLS keys, and builds an onion-routed
//! [`FafRequest`]: each hop's address is sealed to the relay that reads it, and the message is
//! sealed to the terminal. It sends the request to the entry relay's `POST /faf`, prints the
//! response and decrypts the terminal's reply (sealed under the message key).
//!
//! The message is a [`FileRequest`] (CBOR) for the file service terminal (bin `s3-server`):
//! `--upload` or `--download`.
//! The enclave images never include it.

use axum::http::Uri;
use log::{error, info, warn};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;
use ttk_core::file_message::{FileRequest, FileResponse, SHA256_LEN};
use ttk_ra_client::seal::{self, NodePublicKey};
use ttk_ra_client::{connect_to_node, parse_relay_server, FafRelay, FafRequest, FAF_PATH};
use ttk_ra_client::{hex_encode, ClientTransport, EnclaveCertVerifier, TtkClient};

/// Second relay node, which the entry relay forwards the `FafRequest` to unless `--relay`
/// overrides it.
const DEFAULT_RELAY_SERVER: &str = "127.0.0.1:4434";

/// Terminal node (the last hop) unless `--terminal` overrides it.
const DEFAULT_TERMINAL_SERVER: &str = "127.0.0.1:4444";

/// Usage text of this binary.
const CLIENT_USAGE: &str = "\
Usage: client [OPTIONS] (--upload <PATH> | --download <SHA256>) [URL]

Options:
  -s, --server-name <NAME>  SNI server name (default: localhost)
  -a, --addr <ADDR>         Entry relay node socket address (default: 127.0.0.1:4433)
  -r, --relay <RELAY>       Second relay node, forwarded to by the entry relay (default: 127.0.0.1:4434)
  -t, --terminal <TERMINAL> Terminal node, the last hop (default: 127.0.0.1:4444)
  -u, --upload <PATH>       Upload the file at PATH to the file service terminal; prints its SHA-256
  -d, --download <SHA256>   Download the file with this SHA-256 (64 hex digits) from the file service terminal
  -o, --out <PATH>          Where --download writes the file (default: ./<SHA256>)
  -h, --help                Print help information

Examples:
  client https://127.0.0.1:4433 --upload ./report.pdf
  client --addr 127.0.0.1:4433 --relay 127.0.0.1:4434 --terminal 127.0.0.1:4444 --upload ./report.pdf
  client --terminal 127.0.0.1:4444 --upload ./report.pdf
  client --terminal 127.0.0.1:4444 --download <SHA256> --out ./report.pdf
";

/// What a `client` invocation sends to the terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Payload {
    /// A file for the file service to store (`--upload`), sent as [`FileRequest::Upload`].
    Upload(PathBuf),
    /// A file to fetch from the file service (`--download`), sent as [`FileRequest::Download`],
    /// and the path the file is written to (`--out`).
    Download { sha256: Vec<u8>, out: PathBuf },
}

/// What a `client` invocation should connect to and send.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientTarget {
    /// Entry relay node socket address.
    server_addr: SocketAddr,
    /// SNI server name.
    server_name: String,
    /// Second relay node, as `host[:port]` or `https://host[:port]`.
    relay_server: String,
    /// Terminal node the request is routed to, as `host[:port]` or `https://host[:port]`.
    terminal_server: String,
    /// What is sealed to the terminal and sent.
    payload: Payload,
}

/// Parses `client` arguments (without the program name).
///
/// `default_addr` and `default_name` come from `TTK_SERVER_ADDR` and `TTK_SERVER_NAME`; they
/// fall back to `127.0.0.1:4433` and `localhost`. An unparsable address falls back
/// to `127.0.0.1:4433`. The second relay defaults to [`DEFAULT_RELAY_SERVER`] and the terminal
/// to [`DEFAULT_TERMINAL_SERVER`]. Returns `Ok(None)` if help was requested, and an error if
/// not exactly one of `--upload` / `--download` is given, `--out` is given without
/// `--download`, or the `--download` SHA-256 is not 64 hex digits.
fn parse_client_args(
    args: &[String],
    default_addr: Option<String>,
    default_name: Option<String>,
) -> Result<Option<ClientTarget>, String> {
    let mut server_addr_str = default_addr.unwrap_or_else(|| "127.0.0.1:4433".to_string());
    let mut server_name = default_name.unwrap_or_else(|| "localhost".to_string());
    let mut relay_server = DEFAULT_RELAY_SERVER.to_string();
    let mut terminal_server = DEFAULT_TERMINAL_SERVER.to_string();
    let mut upload = None;
    let mut download = None;
    let mut out = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--help" || arg == "-h" {
            return Ok(None);
        } else if (arg == "--server-name" || arg == "-s") && i + 1 < args.len() {
            i += 1;
            server_name = args[i].clone();
        } else if (arg == "--relay" || arg == "-r") && i + 1 < args.len() {
            i += 1;
            relay_server = args[i].clone();
        } else if (arg == "--terminal" || arg == "-t") && i + 1 < args.len() {
            i += 1;
            terminal_server = args[i].clone();
        } else if (arg == "--upload" || arg == "-u") && i + 1 < args.len() {
            i += 1;
            upload = Some(PathBuf::from(&args[i]));
        } else if (arg == "--download" || arg == "-d") && i + 1 < args.len() {
            i += 1;
            download = Some(args[i].clone());
        } else if (arg == "--out" || arg == "-o") && i + 1 < args.len() {
            i += 1;
            out = Some(PathBuf::from(&args[i]));
        } else if (arg == "--addr" || arg == "-a") && i + 1 < args.len() {
            i += 1;
            server_addr_str = args[i].clone();
        } else if !arg.starts_with('-') {
            // Positional URL or address; any URL path is ignored (requests always go to /faf).
            if let Ok(uri) = arg.parse::<Uri>() {
                if let Some(host) = uri.host() {
                    let port = uri.port_u16().unwrap_or(4433);
                    server_addr_str = format!("{}:{}", host, port);
                    if host != "127.0.0.1" && host != "0.0.0.0" {
                        server_name = host.to_string();
                    }
                }
            } else {
                server_addr_str = arg.clone();
            }
        }
        i += 1;
    }

    let server_addr: SocketAddr = server_addr_str
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:4433".parse().unwrap());

    let payload = match (upload, download) {
        (_, None) if out.is_some() => return Err("--out requires --download".into()),
        (Some(path), None) => Payload::Upload(path),
        (None, Some(hex)) => {
            let sha256 = parse_sha256_hex(&hex)?;
            let out = out.unwrap_or_else(|| PathBuf::from(hex_encode(&sha256)));
            Payload::Download { sha256, out }
        }
        (None, None) => return Err("one of --upload or --download is required".into()),
        (Some(_), Some(_)) => return Err("--upload and --download are mutually exclusive".into()),
    };

    Ok(Some(ClientTarget {
        server_addr,
        server_name,
        relay_server,
        terminal_server,
        payload,
    }))
}

/// Parses a SHA-256 given as 64 hex digits (either case).
fn parse_sha256_hex(hex: &str) -> Result<Vec<u8>, String> {
    let invalid = || {
        format!(
            "--download expects a SHA-256 as {} hex digits",
            2 * SHA256_LEN
        )
    };
    if hex.len() != 2 * SHA256_LEN || !hex.is_ascii() {
        return Err(invalid());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| invalid()))
        .collect()
}

/// Parses the process arguments and environment, printing usage and exiting on `--help`, and
/// exiting with an error on invalid arguments.
fn parse_args() -> ClientTarget {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_client_args(
        &args,
        std::env::var("TTK_SERVER_ADDR").ok(),
        std::env::var("TTK_SERVER_NAME").ok(),
    ) {
        Ok(Some(target)) => target,
        Ok(None) => {
            print!("{CLIENT_USAGE}");
            std::process::exit(0);
        }
        Err(e) => {
            error!("{e} (see --help)");
            std::process::exit(2);
        }
    }
}

/// The message sealed to the terminal for `payload`, and the SHA-256 the file service's reply is
/// checked against (the uploaded file's, or the requested one).
fn build_message(payload: &Payload) -> Result<(Vec<u8>, Vec<u8>), String> {
    match payload {
        Payload::Upload(path) => {
            let file =
                std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
            let sha256 = Sha256::digest(&file).to_vec();
            info!("--> Uploading {} ({} bytes)", path.display(), file.len());
            let message = FileRequest::Upload(file)
                .to_cbor()
                .map_err(|e| e.to_string())?;
            Ok((message, sha256))
        }
        Payload::Download { sha256, .. } => {
            info!("--> Downloading {}", hex_encode(sha256));
            let message = FileRequest::Download(sha256.clone())
                .to_cbor()
                .map_err(|e| e.to_string())?;
            Ok((message, sha256.clone()))
        }
    }
}

/// Acts on the terminal's decrypted `reply` to `payload`: decodes the file service's
/// [`FileResponse`], checks it against `expected` (a SHA-256) and, for a download, writes the
/// file.
fn handle_reply(payload: &Payload, expected: &[u8], reply: &[u8]) -> Result<(), String> {
    let response = FileResponse::from_cbor(reply)
        .map_err(|e| format!("invalid file service reply: {e}"))?
        .into_result()
        .map_err(|e| format!("file service: {e}"))?;
    match payload {
        Payload::Download { out, .. } => {
            if Sha256::digest(&response).as_slice() != expected {
                return Err("downloaded file does not match the requested SHA-256".into());
            }
            std::fs::write(out, &response)
                .map_err(|e| format!("cannot write {}: {e}", out.display()))?;
            info!(
                "<-- Downloaded {} bytes (SHA-256 verified) to {}",
                response.len(),
                out.display()
            );
        }
        _ if response != expected => {
            return Err(format!(
                "file service returned SHA-256 {}, expected {}",
                hex_encode(&response),
                hex_encode(expected)
            ));
        }
        _ => info!("<-- Uploaded, SHA-256: {}", hex_encode(&response)),
    }
    Ok(())
}

/// Entry point for the `client` binary.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let ClientTarget {
        server_addr,
        server_name,
        relay_server,
        terminal_server,
        payload,
    } = parse_args();
    let (message, expected_sha256) = match build_message(&payload) {
        Ok(built) => built,
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        }
    };

    info!("TTKServer HTTP/3 client (RFC 9114) connecting to {server_addr} (SNI: {server_name})");

    let mut verifier = EnclaveCertVerifier::new();
    if std::env::var("TTK_ALLOW_MOCK_ATTESTATION").is_ok_and(|v| v == "1") {
        warn!("Accepting MOCK attestation (TTK_ALLOW_MOCK_ATTESTATION=1)");
        verifier = verifier.allow_mock();
    }

    let client =
        match TtkClient::connect_with_verifier(server_addr, &server_name, verifier.clone()).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to connect to TTKServer at {}: {}", server_addr, e);
                std::process::exit(1);
            }
        };

    if let Some(fingerprint) = client.peer_cert_sha256_hex() {
        info!(
            "Server certificate SHA-256 fingerprint {fingerprint} \
             (attestation verified and bound to this certificate's key)"
        );
    }

    info!("--> Attesting relay {relay_server} to seal the terminal's address to it");
    let relay_key = match attest_node(&relay_server, verifier.clone()).await {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to attest relay {relay_server}: {e}");
            std::process::exit(1);
        }
    };
    info!("--> Attesting terminal {terminal_server} to seal the message to it");
    let terminal_key = match attest_node(&terminal_server, verifier).await {
        Ok(key) => key,
        Err(e) => {
            error!("Failed to attest terminal {terminal_server}: {e}");
            std::process::exit(1);
        }
    };

    // Each hop's address is sealed to the relay that reads it: the entry relay learns only the
    // second relay, which learns only the terminal. Only the terminal can open the body.
    let (body, message_key) = seal::seal_body_with_key(&terminal_key, &message)?;
    let request = FafRequest {
        relays: vec![
            FafRelay {
                address: relay_server.clone(),
                encrypted: false,
            },
            FafRelay {
                address: seal::seal_address(&relay_key, &terminal_server)?,
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
                let reply = resp
                    .text()
                    .map_err(|e| e.to_string())
                    .and_then(|sealed| {
                        seal::open_response(&message_key, &sealed).map_err(|e| e.to_string())
                    })
                    .map_err(|e| format!("Failed to decrypt the terminal's reply: {e}"))
                    .and_then(|reply| handle_reply(&payload, &expected_sha256, &reply));
                if let Err(e) = reply {
                    error!("{e}");
                    std::process::exit(1);
                }
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

    Ok(())
}

/// Connects to the node `server` with `verifier`, and returns the RA-TLS key of the first of its
/// addresses whose attestation verifies (see [`connect_to_node`]).
async fn attest_node(
    server: &str,
    verifier: EnclaveCertVerifier,
) -> Result<NodePublicKey, Box<dyn std::error::Error + Send + Sync>> {
    let (host, port) = parse_relay_server(server)?;
    let node = connect_to_node(ClientTransport::Udp, &host, port, verifier).await?;
    let key = node
        .peer_cert()
        .ok_or("node presented no certificate")
        .map(|cert| NodePublicKey::from_certificate(cert));
    node.close().await?;
    Ok(key??)
}
