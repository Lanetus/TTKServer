//! `client` binary: command-line HTTP/3 client for TTKServer, for testing only.
//!
//! Thin entry point over [`ttk_server::client`]: parses CLI arguments / environment,
//! connects with RA-TLS verification of the enclave's attestation evidence, and prints
//! the responses. Built only with the non-default `test-client` feature, so it is never part
//! of a production build.

use ttk_server::client::{
    parse_client_args, ClientTarget, EnclaveCertVerifier, TtkClient, CLIENT_USAGE,
};

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
        path,
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

    println!("\n--> Sending GET {}", path);
    match client.get(&path).await {
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
            eprintln!("Error sending request to {}: {}", path, e);
        }
    }

    // If default path "/" was queried, also test "/hello" endpoint
    if path == "/" {
        println!("\n--> Sending GET /hello");
        match client.get("/hello").await {
            Ok(resp) => {
                println!("<-- Response Status: {}", resp.status);
                if let Ok(body_str) = resp.text() {
                    println!("<-- Body:\n{}", body_str);
                }
            }
            Err(e) => {
                eprintln!("Error sending request to /hello: {}", e);
            }
        }
    }

    println!("\nClosing connection...");
    client.close().await?;
    println!("Connection closed successfully.");

    Ok(())
}
