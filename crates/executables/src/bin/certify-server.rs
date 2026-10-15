//! `certify-server` binary: test certificate authority for a TTKServer node, for testing only.
//!
//! Thin entry point over [`ttk_root::auth::authorize`]: attests the node over RA-TLS, sends a
//! random nonce to `POST /evidence` and appraises the fresh Evidence, then signs a certificate
//! for the node's RA-TLS key as the CA and installs it with `POST /certificate`.
//!
//! The CA is read from `--ca-cert` / `--ca-key` (PEM, both required). The issued certificate's
//! subject common name is `--server-name`, or the node's IP address if it is not given. Nodes
//! trust only the built-in TTK root CA
//! (`ttk_core::TTK_ROOT_CA_PEM`), so a running node accepts the certificate only if the CA is
//! that root (or an intermediate it issued). The enclave images never include this binary.

use log::{error, info, warn};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use ttk_ra_server::server::BoxError;
use ttk_root::auth::{authorize, AuthorizeOptions, CertificateAuthority};

/// Usage text of this binary.
const CERTIFY_SERVER_USAGE: &str = "\
Usage: certify-server [OPTIONS]

Options:
  -a, --addr <ADDR>         Node socket address (required)
  -s, --server-name <NAME>  SNI server name and the certificate's common name
                            (default: the node's IP address)
      --ca-cert <FILE>      CA certificate, PEM (required)
      --ca-key <FILE>       CA private key, PEM PKCS#8 (required)
  -o, --out <FILE>          Also write the installed chain (PEM) to FILE
  -h, --help                Print help information

TTK_ALLOW_MOCK_ATTESTATION=1 accepts mock attestation (local development).

Example:
  TTK_ATTESTATION=mock TTK_USE_UDP=1 cargo run --bin root
  TTK_ALLOW_MOCK_ATTESTATION=1 cargo run --bin certify-server -- \
    --addr 127.0.0.1:4433 --ca-cert TTK_Root_CA.pem --ca-key TTK_Root_CA.key

Nodes trust only the built-in TTK root CA (or an intermediate it issued).
";

/// What a `certify-server` invocation should do.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CertifyServerArgs {
    /// Node socket address.
    addr: SocketAddr,
    /// SNI server name and the issued certificate's common name; `None` = the node's IP address.
    server_name: Option<String>,
    /// CA certificate file.
    ca_cert: PathBuf,
    /// CA private key file.
    ca_key: PathBuf,
    /// Where to write the installed chain, if anywhere.
    out: Option<PathBuf>,
}

/// Parses `certify-server` arguments (without the program name). Returns `Ok(None)` if help was
/// requested.
fn parse_certify_server_args(args: &[String]) -> Result<Option<CertifyServerArgs>, String> {
    let mut addr: Option<SocketAddr> = None;
    let mut server_name = None;
    let mut ca_cert = None;
    let mut ca_key = None;
    let mut out = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            return Ok(None);
        }
        let mut value = || {
            args.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--addr" | "-a" => {
                let value = value()?;
                addr = Some(
                    value
                        .parse()
                        .map_err(|e| format!("invalid address {value}: {e}"))?,
                );
            }
            "--server-name" | "-s" => server_name = Some(value()?),
            "--ca-cert" => ca_cert = Some(value()?.into()),
            "--ca-key" => ca_key = Some(value()?.into()),
            "--out" | "-o" => out = Some(value()?.into()),
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    Ok(Some(CertifyServerArgs {
        addr: addr.ok_or("--addr is required")?,
        server_name,
        ca_cert: ca_cert.ok_or("--ca-cert is required")?,
        ca_key: ca_key.ok_or("--ca-key is required")?,
        out,
    }))
}

/// Loads the CA from its PEM certificate `cert` and PEM (PKCS#8) key `key`.
fn load_ca(cert: &Path, key: &Path) -> Result<CertificateAuthority, BoxError> {
    let read = |path: &Path| {
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))
    };
    let ca = CertificateAuthority::from_pem(&read(cert)?, &read(key)?)?;
    info!("Loaded CA from {}", cert.display());
    Ok(ca)
}

/// Entry point for the `certify-server` binary.
#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_certify_server_args(&args) {
        Ok(Some(args)) => args,
        Ok(None) => {
            info!("\n{CERTIFY_SERVER_USAGE}");
            return;
        }
        Err(e) => {
            error!("{e}\n{CERTIFY_SERVER_USAGE}");
            std::process::exit(2);
        }
    };

    let ca = match load_ca(&args.ca_cert, &args.ca_key) {
        Ok(ca) => ca,
        Err(e) => {
            error!("CA: {e}");
            std::process::exit(1);
        }
    };

    let mut options = AuthorizeOptions::default();
    if std::env::var("TTK_ALLOW_MOCK_ATTESTATION").is_ok_and(|v| v == "1") {
        warn!("Accepting MOCK attestation (TTK_ALLOW_MOCK_ATTESTATION=1)");
        options.allow_mock = true;
    }

    let server_name = args
        .server_name
        .unwrap_or_else(|| args.addr.ip().to_string());
    info!("Authorizing node {} (SNI and CN: {server_name})", args.addr);
    match authorize(args.addr, &server_name, &ca, &options).await {
        Ok(chain) => {
            let pem = ttk_root::auth::pem(&chain);
            info!("Installed CA-issued certificate:\n{pem}");
            if let Some(out) = &args.out {
                if let Err(e) = std::fs::write(out, pem) {
                    error!("Writing {}: {e}", out.display());
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            error!("Authorization of {} failed: {e}", args.addr);
            std::process::exit(1);
        }
    }
}
