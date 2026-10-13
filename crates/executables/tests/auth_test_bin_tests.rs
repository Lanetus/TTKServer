//! End-to-end tests of the `certify-server` binary against a root node on a free local port (mock
//! attestation) trusting a throwaway CA.

use rustls::RootCertStore;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Output;
use ttk_ra_server::server::Server;
use ttk_root::auth::CertificateAuthority;
use ttk_root::Root;

/// Starts a root node on a free local port trusting only `ca` (if any; otherwise the built-in
/// TTK root CA) and returns its address. It serves until the test's runtime shuts down.
fn start_node(ca: Option<&CertificateAuthority>) -> SocketAddr {
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    if let Some(ca) = ca {
        let mut roots = RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        server.set_trusted_roots(roots).unwrap();
    }
    let root = Root::new(server);
    let addr = root.local_addr().unwrap();
    tokio::spawn(async move { root.serve().await.unwrap() });
    addr
}

/// A fresh, empty directory for the test `name`'s files.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ttk-auth-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Writes a new CA's certificate and key to `dir` and returns it with their paths.
fn write_ca(dir: &Path) -> (CertificateAuthority, PathBuf, PathBuf) {
    let ca = CertificateAuthority::generate("auth-test CA").unwrap();
    let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
    std::fs::write(&cert, ca.cert_pem()).unwrap();
    std::fs::write(&key, ca.key_pem()).unwrap();
    (ca, cert, key)
}

async fn run_auth_test(args: &[&str], allow_mock: bool) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_certify-server"));
    command
        .args(args)
        .env_remove("TTK_ALLOW_MOCK_ATTESTATION")
        .env_remove("RUST_LOG");
    if allow_mock {
        command.env("TTK_ALLOW_MOCK_ATTESTATION", "1");
    }
    command
        .output()
        .await
        .expect("certify-server binary should run")
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_test_binary_installs_a_certificate() {
    let dir = temp_dir("installs");
    let (ca, cert, key) = write_ca(&dir);
    let addr = start_node(Some(&ca)).to_string();
    let out = dir.join("chain.pem");
    let args = [
        "--addr",
        &addr,
        "-s",
        "localhost",
        "--ca-cert",
        cert.to_str().unwrap(),
        "--ca-key",
        key.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ];

    let output = run_auth_test(&args, true).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("Loaded CA from"), "{stderr}");
    assert!(stderr.contains("Accepting MOCK attestation"), "{stderr}");
    assert!(
        stderr.contains("Installed CA-issued certificate"),
        "{stderr}"
    );
    let chain = std::fs::read_to_string(&out).unwrap();
    assert!(chain.contains("-----BEGIN CERTIFICATE-----"), "{chain}");

    // The node replaces its certificate only once.
    let output = run_auth_test(&args, true).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Authorization of"), "{stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_test_binary_fails_to_write_the_chain() {
    let dir = temp_dir("unwritable-out");
    let (ca, cert, key) = write_ca(&dir);
    let addr = start_node(Some(&ca)).to_string();
    let out = dir.join("missing").join("chain.pem");
    let output = run_auth_test(
        &[
            "--addr",
            &addr,
            "--ca-cert",
            cert.to_str().unwrap(),
            "--ca-key",
            key.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ],
        true,
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Writing"), "{stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_test_binary_refuses_mock_attestation_without_opt_in() {
    let dir = temp_dir("no-mock");
    let (ca, cert, key) = write_ca(&dir);
    let addr = start_node(Some(&ca)).to_string();
    let output = run_auth_test(
        &[
            "--addr",
            &addr,
            "--ca-cert",
            cert.to_str().unwrap(),
            "--ca-key",
            key.to_str().unwrap(),
        ],
        false,
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Authorization of"), "{stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_test_binary_creates_a_ca_the_node_refuses() {
    let dir = temp_dir("creates-ca");
    let (cert, key) = (dir.join("new.pem"), dir.join("new.key"));
    // The node trusts only the built-in TTK root CA.
    let addr = start_node(None).to_string();
    let output = run_auth_test(
        &[
            "--addr",
            &addr,
            "--ca-cert",
            cert.to_str().unwrap(),
            "--ca-key",
            key.to_str().unwrap(),
        ],
        true,
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stderr.contains("Created a new CA"), "{stderr}");
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Authorization of"), "{stderr}");
    let created = CertificateAuthority::from_pem(
        &std::fs::read_to_string(&cert).unwrap(),
        &std::fs::read_to_string(&key).unwrap(),
    );
    assert!(created.is_ok(), "the created CA should load");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the CA key is private");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn auth_test_binary_rejects_an_unusable_ca() {
    let dir = temp_dir("unusable-ca");
    let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));

    // Only one of the two files exists.
    std::fs::write(&cert, "not a certificate").unwrap();
    let args = [
        "--ca-cert",
        cert.to_str().unwrap(),
        "--ca-key",
        key.to_str().unwrap(),
    ];
    let output = run_auth_test(&args, true).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("only one of"), "{stderr}");

    // Both exist, but are not PEM.
    std::fs::write(&key, "not a key").unwrap();
    let output = run_auth_test(&args, true).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("CA: "), "{stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn auth_test_binary_prints_usage() {
    for flag in ["--help", "-h"] {
        let output = run_auth_test(&[flag], false).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(stderr.contains("Usage: certify-server"), "{stderr}");
    }
}

#[tokio::test]
async fn auth_test_binary_rejects_invalid_arguments() {
    for args in [
        &["--bogus"][..],
        &["--addr"][..],
        &["--addr", "not-an-address"][..],
        &["--out"][..],
    ] {
        let output = run_auth_test(args, false).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("Usage: certify-server"), "{stderr}");
    }
}
