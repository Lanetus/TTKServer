//! `auth-test` binary: test certificate authority for a TTKServer node, for testing only.
//!
//! Thin entry point over [`ttk_root::auth::authorize`]: attests the node over RA-TLS, sends a
//! random nonce to `POST /evidence` and appraises the fresh Evidence, then signs a certificate
//! for the node's RA-TLS key as the CA and installs it with `POST /certificate`.
//!
//! The CA is read from `--ca-cert` / `--ca-key` (PEM); if neither file exists a new root CA is
//! created and written there. The node accepts the certificate only if it trusts the CA: start
//! it with `TTK_CA_ROOTS=<ca-cert>`. The enclave images never include this binary.

use log::{error, info, warn};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use ttk_ra_server::server::BoxError;
use ttk_root::auth::{authorize, AuthorizeOptions, CertificateAuthority, DEFAULT_CA_NAME};

/// Usage text of this binary.
const AUTH_TEST_USAGE: &str = "\
Usage: auth-test [OPTIONS]

Options:
  -a, --addr <ADDR>         Node socket address (default: 127.0.0.1:4433)
  -s, --server-name <NAME>  SNI server name (default: localhost)
      --ca-cert <FILE>      CA certificate, PEM (default: auth-test-ca.pem)
      --ca-key <FILE>       CA private key, PEM PKCS#8 (default: auth-test-ca.key)
  -o, --out <FILE>          Also write the installed chain (PEM) to FILE
  -h, --help                Print help information

If neither CA file exists, a new root CA is created and written to them.
TTK_ALLOW_MOCK_ATTESTATION=1 accepts mock attestation (local development).

Example:
  TTK_CA_ROOTS=auth-test-ca.pem TTK_USE_UDP=1 cargo run --bin root
  TTK_ALLOW_MOCK_ATTESTATION=1 cargo run -p ttk-root --features auth-test --bin auth-test
";

/// What an `auth-test` invocation should do.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthTestArgs {
    /// Node socket address.
    addr: SocketAddr,
    /// SNI server name.
    server_name: String,
    /// CA certificate file.
    ca_cert: PathBuf,
    /// CA private key file.
    ca_key: PathBuf,
    /// Where to write the installed chain, if anywhere.
    out: Option<PathBuf>,
}

/// Parses `auth-test` arguments (without the program name). Returns `Ok(None)` if help was
/// requested.
fn parse_auth_test_args(args: &[String]) -> Result<Option<AuthTestArgs>, String> {
    let mut parsed = AuthTestArgs {
        addr: "127.0.0.1:4433".parse().expect("valid address"),
        server_name: "localhost".to_string(),
        ca_cert: PathBuf::from("auth-test-ca.pem"),
        ca_key: PathBuf::from("auth-test-ca.key"),
        out: None,
    };
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
                let addr = value()?;
                parsed.addr = addr
                    .parse()
                    .map_err(|e| format!("invalid address {addr}: {e}"))?;
            }
            "--server-name" | "-s" => parsed.server_name = value()?,
            "--ca-cert" => parsed.ca_cert = value()?.into(),
            "--ca-key" => parsed.ca_key = value()?.into(),
            "--out" | "-o" => parsed.out = Some(value()?.into()),
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    Ok(Some(parsed))
}

/// Loads the CA from `cert` and `key`, or creates and writes a new one if neither exists.
fn load_or_create_ca(cert: &Path, key: &Path) -> Result<CertificateAuthority, BoxError> {
    match (cert.exists(), key.exists()) {
        (true, true) => {
            let ca = CertificateAuthority::from_pem(
                &std::fs::read_to_string(cert)?,
                &std::fs::read_to_string(key)?,
            )?;
            info!("Loaded CA from {}", cert.display());
            Ok(ca)
        }
        (false, false) => {
            let ca = CertificateAuthority::generate(DEFAULT_CA_NAME)?;
            std::fs::write(cert, ca.cert_pem())?;
            write_private(key, &ca.key_pem())?;
            info!(
                "Created a new CA: certificate {}, key {} (start the node with TTK_CA_ROOTS={})",
                cert.display(),
                key.display(),
                cert.display()
            );
            Ok(ca)
        }
        _ => Err(format!(
            "only one of {} and {} exists; give both or neither",
            cert.display(),
            key.display()
        )
        .into()),
    }
}

/// Writes `contents` to `path`, readable by the owner only where supported.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    std::io::Write::write_all(&mut options.open(path)?, contents.as_bytes())
}

/// Entry point for the `auth-test` binary.
#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_auth_test_args(&args) {
        Ok(Some(args)) => args,
        Ok(None) => {
            info!("\n{AUTH_TEST_USAGE}");
            return;
        }
        Err(e) => {
            error!("{e}\n{AUTH_TEST_USAGE}");
            std::process::exit(2);
        }
    };

    let ca = match load_or_create_ca(&args.ca_cert, &args.ca_key) {
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

    info!("Authorizing node {} (SNI: {})", args.addr, args.server_name);
    match authorize(args.addr, &args.server_name, &ca, &options).await {
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
