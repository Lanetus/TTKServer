//! `client` binary: command-line HTTP/3 client for TTKServer, for testing only.
//!
//! Thin entry point over [`ttk_executables::faf_client`]: parses CLI arguments / environment and
//! routes a message through two relay nodes to a terminal node (see [`faf_client::send`]).
//!
//! The message is a [`FileRequest`] (CBOR) for the file service terminal (bin `s3-server`):
//! `--upload` or `--download`.
//! The enclave images never include it.

use log::{error, info};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use ttk_core::file_message::{FileRequest, FileResponse, SHA256_LEN};
use ttk_executables::faf_client::{self, Route, RouteArgs};
use ttk_ra_client::hex_encode;

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
    /// Where the message is sent.
    route: Route,
    /// What is sealed to the terminal and sent.
    payload: Payload,
}

/// Parses `client` arguments (without the program name).
///
/// The route arguments and defaults are [`RouteArgs`]'s. Returns `Ok(None)` if help was
/// requested, and an error if not exactly one of `--upload` / `--download` is given, `--out` is
/// given without `--download`, or the `--download` SHA-256 is not 64 hex digits.
fn parse_client_args(
    args: &[String],
    default_addr: Option<String>,
    default_name: Option<String>,
) -> Result<Option<ClientTarget>, String> {
    let mut route = RouteArgs::new(default_addr, default_name);
    let mut upload = None;
    let mut download = None;
    let mut out = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--help" || arg == "-h" {
            return Ok(None);
        } else if (arg == "--upload" || arg == "-u") && i + 1 < args.len() {
            i += 1;
            upload = Some(PathBuf::from(&args[i]));
        } else if (arg == "--download" || arg == "-d") && i + 1 < args.len() {
            i += 1;
            download = Some(args[i].clone());
        } else if (arg == "--out" || arg == "-o") && i + 1 < args.len() {
            i += 1;
            out = Some(PathBuf::from(&args[i]));
        } else {
            route.parse_arg(args, &mut i);
        }
        i += 1;
    }

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
        route: route.build(),
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
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let ClientTarget { route, payload } =
        faf_client::parse_process_args(parse_client_args, CLIENT_USAGE);
    let result = match build_message(&payload) {
        Ok((message, expected_sha256)) => match faf_client::send(&route, &message).await {
            Ok(Some(reply)) => handle_reply(&payload, &expected_sha256, &reply),
            Ok(None) => Ok(()),
            Err(e) => Err(e.to_string()),
        },
        Err(e) => Err(e),
    };
    if let Err(e) = result {
        error!("{e}");
        std::process::exit(1);
    }
}
