//! End-to-end tests of the `certify-server` binary against a root node on a free local port (mock
//! attestation) trusting a throwaway CA.

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use rustls::pki_types::{pem::PemObject, CertificateDer};
use rustls::RootCertStore;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Output;
use ttk_ra_server::server::Server;
use ttk_root::Root;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Starts a root node on a free local port trusting only `ca` (if any; otherwise the built-in
/// TTK root CA) and returns its address. It serves until the test's runtime shuts down.
fn start_node(ca: Option<&CertificateDer<'static>>) -> SocketAddr {
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    if let Some(ca) = ca {
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        server.set_trusted_roots(roots).unwrap();
    }
    let addr = server.local_addr().unwrap();
    let root = Root::new(server);
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

/// Writes a new self-signed CA's certificate and key to `dir` and returns its certificate with
/// their paths.
fn write_ca(dir: &Path) -> (CertificateDer<'static>, PathBuf, PathBuf) {
    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "auth-test CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = params.self_signed(&key_pair).unwrap();
    let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));
    std::fs::write(&cert, ca_cert.pem()).unwrap();
    std::fs::write(&key, key_pair.serialize_pem()).unwrap();
    (ca_cert.der().clone(), cert, key)
}

/// The subject common name of the leaf of the PEM chain in `path`.
fn leaf_common_name(path: &Path) -> String {
    let pem = std::fs::read_to_string(path).unwrap();
    let leaf = CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let (_, cert) = X509Certificate::from_der(&leaf).unwrap();
    let cn = cert.subject().iter_common_name().next().unwrap();
    cn.as_str().unwrap().to_string()
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
    assert_eq!(leaf_common_name(&out), "localhost");

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
async fn auth_test_binary_names_the_node_address_without_a_server_name() {
    let dir = temp_dir("default-cn");
    let (ca, cert, key) = write_ca(&dir);
    let addr = start_node(Some(&ca));
    let out = dir.join("chain.pem");
    let output = run_auth_test(
        &[
            "--addr",
            &addr.to_string(),
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

    assert!(output.status.success(), "{stderr}");
    assert_eq!(leaf_common_name(&out), addr.ip().to_string());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn auth_test_binary_rejects_an_unusable_ca() {
    let dir = temp_dir("unusable-ca");
    let (cert, key) = (dir.join("ca.pem"), dir.join("ca.key"));

    // The key file does not exist.
    std::fs::write(&cert, "not a certificate").unwrap();
    let args = [
        "--addr",
        "127.0.0.1:4433",
        "--ca-cert",
        cert.to_str().unwrap(),
        "--ca-key",
        key.to_str().unwrap(),
    ];
    let output = run_auth_test(&args, true).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("CA: reading"), "{stderr}");

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
        &[][..],
        &["--ca-cert", "ca.pem"][..],
        &["--ca-key", "ca.key"][..],
        &["--ca-cert", "ca.pem", "--ca-key", "ca.key"][..],
    ] {
        let output = run_auth_test(args, false).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("Usage: certify-server"), "{stderr}");
    }
}
