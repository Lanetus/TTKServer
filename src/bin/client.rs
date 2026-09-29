//! `client` binary: command-line HTTP/3 client for TTKServer, for testing only.
//!
//! Thin entry point over [`ttk_server::client`]: parses CLI arguments / environment,
//! connects with RA-TLS verification of the enclave's attestation evidence, sends a
//! [`FafRequest`] to `POST /faf` (relayed to [`DEFAULT_RELAY_SERVER`] unless overridden), and
//! prints the response. Built only with the non-default `test-client` feature, so it is never part
//! of a production build.

use axum::http::Uri;
use std::net::SocketAddr;
use ttk_server::client::{EnclaveCertVerifier, TtkClient};
use ttk_server::router::FafRequest;

/// Relay server the `FafRequest` is forwarded to unless `--relay` overrides it.
const DEFAULT_RELAY_SERVER: &str = "127.0.0.1:4444";

/// Path of the forward-and-forget endpoint.
const FAF_PATH: &str = "/faf";

/// Usage text of this binary.
const CLIENT_USAGE: &str = "\
Usage: client [OPTIONS] [URL]

Options:
  -s, --server-name <NAME>  SNI server name (default: localhost)
  -a, --addr <ADDR>         Server socket address (default: 127.0.0.1:4433)
  -r, --relay <RELAY>       Relay server for the FafRequest (default: 127.0.0.1:4444)
  -m, --message <MESSAGE>   Message to send (default: hello)
  -k, --key <KEY>           Key to send alongside the message (default: key)
  -h, --help                Print help information

Examples:
  client
  client https://127.0.0.1:4433
  client --addr 127.0.0.1:4433 --relay 127.0.0.1:4444 --message hi --key secret
";

/// What a `client` invocation should connect to and send.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientTarget {
    /// Server socket address.
    server_addr: SocketAddr,
    /// SNI server name.
    server_name: String,
    /// The request to `POST` to [`FAF_PATH`].
    request: FafRequest,
}

/// Parses `client` arguments (without the program name).
///
/// `default_addr` and `default_name` come from `TTK_SERVER_ADDR` and `TTK_SERVER_NAME`; they
/// fall back to `127.0.0.1:4433` and `localhost`. An unparsable address falls back
/// to `127.0.0.1:4433`. The relay defaults to [`DEFAULT_RELAY_SERVER`]. Returns `None` if help
/// was requested.
fn parse_client_args(
    args: &[String],
    default_addr: Option<String>,
    default_name: Option<String>,
) -> Option<ClientTarget> {
    let mut server_addr_str = default_addr.unwrap_or_else(|| "127.0.0.1:4433".to_string());
    let mut server_name = default_name.unwrap_or_else(|| "localhost".to_string());
    let mut relay_server = DEFAULT_RELAY_SERVER.to_string();
    let mut message = "hello".to_string();
    let mut key = "key".to_string();

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
        } else if (arg == "--message" || arg == "-m") && i + 1 < args.len() {
            i += 1;
            message = args[i].clone();
        } else if (arg == "--key" || arg == "-k") && i + 1 < args.len() {
            i += 1;
            key = args[i].clone();
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
        request: FafRequest {
            relay_server: Some(relay_server),
            message,
            key,
        },
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
        request,
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

    let mut client =
        match TtkClient::connect_with_verifier(server_addr, &server_name, verifier).await {
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

    println!(
        "\n--> Sending POST {} (relay: {})",
        FAF_PATH,
        request.relay_server.as_deref().unwrap_or("<none>")
    );
    match client.post_json(FAF_PATH, &request).await {
        Ok(resp) => {
            println!("<-- Response Status: {}", resp.status);
            println!("<-- Headers:");
            for (name, val) in &resp.headers {
                println!("    {}: {}", name, val.to_str().unwrap_or("<binary>"));
            }
            match resp.text() {
                Ok(body_str) => println!("<-- Body:\n{}", body_str),
                Err(_) => println!("<-- Body (binary, {} bytes)", resp.body.len()),
            }
        }
        Err(e) => {
            eprintln!("Error sending request to {}: {}", FAF_PATH, e);
        }
    }

    println!("\nClosing connection...");
    client.close().await?;
    println!("Connection closed successfully.");

    Ok(())
}
