//! `client` binary: command-line HTTP/3 client for TTKServer, for testing only.
//!
//! Thin entry point over [`ttk_client`]: parses CLI arguments / environment and routes a message
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
//! response and decrypts the terminal's reply (`hello:<message>`, sealed under the message key).
//! The enclave images never include it.

use axum::http::Uri;
use std::net::SocketAddr;
use std::time::Instant;
use ttk_client::faf::{connect_to_node, parse_relay_server, FafRelay, FafRequest, FAF_PATH};
use ttk_client::seal::{self, NodePublicKey};
use ttk_client::{ClientTransport, EnclaveCertVerifier, TtkClient};

/// Second relay node, which the entry relay forwards the `FafRequest` to unless `--relay`
/// overrides it.
const DEFAULT_RELAY_SERVER: &str = "127.0.0.1:4434";

/// Terminal node (the last hop) unless `--terminal` overrides it.
const DEFAULT_TERMINAL_SERVER: &str = "127.0.0.1:4444";

/// Usage text of this binary.
const CLIENT_USAGE: &str = "\
Usage: client [OPTIONS] [URL]

Options:
  -s, --server-name <NAME>  SNI server name (default: localhost)
  -a, --addr <ADDR>         Entry relay node socket address (default: 127.0.0.1:4433)
  -r, --relay <RELAY>       Second relay node, forwarded to by the entry relay (default: 127.0.0.1:4434)
  -t, --terminal <TERMINAL> Terminal node, the last hop (default: 127.0.0.1:4444)
  -m, --message <MESSAGE>   Message to send, encrypted to the terminal (default: hello)
  -h, --help                Print help information

Examples:
  client
  client https://127.0.0.1:4433
  client --addr 127.0.0.1:4433 --relay 127.0.0.1:4434 --terminal 127.0.0.1:4444 --message hi
";

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
    /// The message, sealed to the terminal before sending.
    message: String,
}

/// Parses `client` arguments (without the program name).
///
/// `default_addr` and `default_name` come from `TTK_SERVER_ADDR` and `TTK_SERVER_NAME`; they
/// fall back to `127.0.0.1:4433` and `localhost`. An unparsable address falls back
/// to `127.0.0.1:4433`. The second relay defaults to [`DEFAULT_RELAY_SERVER`] and the terminal
/// to [`DEFAULT_TERMINAL_SERVER`]. Returns `None` if help was requested.
fn parse_client_args(
    args: &[String],
    default_addr: Option<String>,
    default_name: Option<String>,
) -> Option<ClientTarget> {
    let mut server_addr_str = default_addr.unwrap_or_else(|| "127.0.0.1:4433".to_string());
    let mut server_name = default_name.unwrap_or_else(|| "localhost".to_string());
    let mut relay_server = DEFAULT_RELAY_SERVER.to_string();
    let mut terminal_server = DEFAULT_TERMINAL_SERVER.to_string();
    let mut message = "hello".to_string();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--help" || arg == "-h" {
            return None;
        } else if (arg == "--server-name" || arg == "-s") && i + 1 < args.len() {
            i += 1;
            server_name = args[i].clone();
        } else if (arg == "--relay" || arg == "-r") && i + 1 < args.len() {
            i += 1;
            relay_server = args[i].clone();
        } else if (arg == "--terminal" || arg == "-t") && i + 1 < args.len() {
            i += 1;
            terminal_server = args[i].clone();
        } else if (arg == "--message" || arg == "-m") && i + 1 < args.len() {
            i += 1;
            message = args[i].clone();
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

    Some(ClientTarget {
        server_addr,
        server_name,
        relay_server,
        terminal_server,
        message,
    })
}

/// Parses the process arguments and environment, printing usage and exiting on `--help`.
fn parse_args() -> ClientTarget {
    let args: Vec<String> = std::env::args().skip(1).collect();
    parse_client_args(
        &args,
        std::env::var("TTK_SERVER_ADDR").ok(),
        std::env::var("TTK_SERVER_NAME").ok(),
    )
    .unwrap_or_else(|| {
        print!("{CLIENT_USAGE}");
        std::process::exit(0);
    })
}

/// Entry point for the `client` binary.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let ClientTarget {
        server_addr,
        server_name,
        relay_server,
        terminal_server,
        message,
    } = parse_args();

    println!("=================================================");
    println!("TTKServer HTTP/3 Client (RFC 9114)");
    println!("Connecting to: {} (SNI: {})", server_addr, server_name);
    println!("=================================================");

    let mut verifier = EnclaveCertVerifier::new();
    if std::env::var("TTK_ALLOW_MOCK_ATTESTATION").is_ok_and(|v| v == "1") {
        eprintln!("WARNING: accepting MOCK attestation (TTK_ALLOW_MOCK_ATTESTATION=1)");
        verifier = verifier.allow_mock();
    }

    let client =
        match TtkClient::connect_with_verifier(server_addr, &server_name, verifier.clone()).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to connect to TTKServer at {}: {}", server_addr, e);
                std::process::exit(1);
            }
        };

    if let Some(fingerprint) = client.peer_cert_sha256_hex() {
        println!("Server Certificate SHA-256 Fingerprint:");
        println!("  {}", fingerprint);
        println!("  (Attestation verified and bound to this certificate's key)");
    }

    println!("\n--> Attesting relay {relay_server} to seal the terminal's address to it");
    let relay_key = match attest_node(&relay_server, verifier.clone()).await {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to attest relay {relay_server}: {e}");
            std::process::exit(1);
        }
    };
    println!("--> Attesting terminal {terminal_server} to seal the message to it");
    let terminal_key = match attest_node(&terminal_server, verifier).await {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to attest terminal {terminal_server}: {e}");
            std::process::exit(1);
        }
    };

    // Each hop's address is sealed to the relay that reads it: the entry relay learns only the
    // second relay, which learns only the terminal. Only the terminal can open the body.
    let (body, message_key) = seal::seal_body_with_key(&terminal_key, message.as_bytes())?;
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

    println!(
        "\n--> Sending POST {FAF_PATH} (route: {server_addr} -> {relay_server} -> {terminal_server})"
    );
    let started = Instant::now();
    let result = client.post_json(FAF_PATH, &request).await;
    let elapsed = started.elapsed();
    match result {
        Ok(resp) => {
            println!("<-- Response Status: {} (in {:.3?})", resp.status, elapsed);
            println!("<-- Headers:");
            for (name, val) in &resp.headers {
                println!("    {}: {}", name, val.to_str().unwrap_or("<binary>"));
            }
            match resp.text() {
                Ok(body_str) => println!("<-- Body:\n{}", body_str),
                Err(_) => println!("<-- Body (binary, {} bytes)", resp.body.len()),
            }
            if resp.status == 200 {
                let reply = resp.text().map_err(|e| e.to_string()).and_then(|sealed| {
                    seal::open_response(&message_key, &sealed).map_err(|e| e.to_string())
                });
                match reply {
                    Ok(reply) => println!(
                        "<-- Terminal reply (decrypted):\n{}",
                        String::from_utf8_lossy(&reply)
                    ),
                    Err(e) => {
                        eprintln!("Failed to decrypt the terminal's reply: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!(
                "Error sending request to {} after {:.3?}: {}",
                FAF_PATH, elapsed, e
            );
        }
    }

    println!("\nClosing connection...");
    client.close().await?;
    println!("Connection closed successfully.");

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
