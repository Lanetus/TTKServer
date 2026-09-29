//! End-to-end tests: the real server on a free local port (mock attestation), queried by the
//! `TtkClient` library and by the `client` binary.

#![cfg(feature = "mock")]

use base64::Engine as _;
use std::net::SocketAddr;
use std::process::Output;
use ttk_server::client::{EnclaveCertVerifier, TtkClient};
use ttk_server::eat::EatClaimsSet;
use ttk_server::server::Server;
use ttk_server::verifier::TeeKind;

/// Starts a server on a free local port and returns its address. It serves until the test's
/// runtime shuts down.
fn start_server() -> SocketAddr {
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).expect("server should start");
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());
    addr
}

async fn run_client_binary(args: &[&str], allow_mock: bool) -> Output {
    run_client_binary_with_env(args, allow_mock, &[]).await
}

async fn run_client_binary_with_env(
    args: &[&str],
    allow_mock: bool,
    env: &[(&str, &str)],
) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_client"));
    command
        .args(args)
        .env_remove("TTK_SERVER_ADDR")
        .env_remove("TTK_SERVER_NAME")
        .env_remove("TTK_ALLOW_MOCK_ATTESTATION")
        .env_remove("RUST_LOG");
    if allow_mock {
        command.env("TTK_ALLOW_MOCK_ATTESTATION", "1");
    }
    command.envs(env.iter().copied());
    command.output().await.expect("client binary should run")
}

#[tokio::test(flavor = "multi_thread")]
async fn client_verifies_the_mock_server_and_exchanges_requests() {
    let addr = start_server();
    let mut client = TtkClient::connect_with_verifier(
        addr,
        "localhost",
        EnclaveCertVerifier::new().allow_mock(),
    )
    .await
    .expect("mock evidence should verify with mock allowed");

    assert_eq!(client.server_addr(), addr);
    assert_eq!(client.server_name(), "localhost");
    assert!(client.peer_cert().is_some());
    assert_eq!(client.peer_cert_sha256_hex().map(|h| h.len()), Some(64));

    let root = client.get("/").await.unwrap();
    assert_eq!(root.status, 200);
    assert_eq!(root.text().unwrap(), "Hello from Enclave over HTTP/3!");

    // Paths without a leading slash are accepted too.
    let hello = client.get("hello").await.unwrap();
    assert_eq!(hello.text().unwrap(), "Hello from inside the Enclave!");

    // The evidence served over HTTP is the EAT embedded in the TLS certificate.
    let evidence = client.get("/evidence.eat").await.unwrap();
    let eat = base64::engine::general_purpose::STANDARD
        .decode(evidence.text().unwrap())
        .unwrap();
    let claims = EatClaimsSet::from_cbor_bytes(&eat).unwrap();
    assert!(claims.submods.is_some());

    let missing = client.get("/does-not-exist").await.unwrap();
    assert_eq!(missing.status, 404);

    // Routes are GET-only, so a POST is answered with 405.
    let post = client.post("/", b"payload").await.unwrap();
    assert_eq!(post.status, 405);
    let empty_post = client.post("hello", b"").await.unwrap();
    assert_eq!(empty_post.status, 405);

    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn verified_evidence_is_available_after_connecting() {
    let addr = start_server();
    let verifier = EnclaveCertVerifier::new().allow_mock();
    let client = TtkClient::connect_with_verifier(addr, "localhost", verifier.clone())
        .await
        .unwrap();

    let evidence = verifier.verified_evidence().expect("evidence is recorded");
    assert_eq!(evidence.tee, TeeKind::AwsNitro);
    assert_eq!(
        verifier.verified_attestation().unwrap().module_id,
        "aws-nitro-enclaves-mock"
    );
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_client_rejects_the_mock_server() {
    let addr = start_server();
    let err = TtkClient::connect(addr, "localhost").await.err().unwrap();
    assert!(err.to_string().contains("MOCK"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_binary_queries_root_and_hello() {
    let addr = start_server().to_string();
    let output = run_client_binary(&["--addr", &addr], true).await;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("Response Status: 200"), "{stdout}");
    assert!(
        stdout.contains("Hello from Enclave over HTTP/3!"),
        "{stdout}"
    );
    assert!(stdout.contains("--> Sending GET /hello"), "{stdout}");
    assert!(
        stdout.contains("Connection closed successfully."),
        "{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_binary_queries_a_given_path() {
    let addr = start_server();
    let url = format!("https://127.0.0.1:{}/evidence", addr.port());
    let output = run_client_binary(&[&url], true).await;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("--> Sending GET /evidence"), "{stdout}");
    assert!(!stdout.contains("--> Sending GET /hello"), "{stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_binary_fails_against_the_mock_server_without_opt_in() {
    let addr = start_server().to_string();
    let output = run_client_binary(&["-a", &addr], false).await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Failed to connect"), "{stderr}");
    assert!(stderr.contains("TTK_ALLOW_MOCK_ATTESTATION"), "{stderr}");
}

#[tokio::test]
async fn client_binary_prints_usage() {
    let output = run_client_binary(&["--help"], false).await;
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("Usage: client"));
}

#[tokio::test(flavor = "multi_thread")]
async fn client_binary_logs_the_verified_certificate() {
    let addr = start_server().to_string();
    let output = run_client_binary_with_env(
        &["--addr", &addr, "--path", "/hello"],
        true,
        &[("RUST_LOG", "info")],
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Server Certificate SHA-256 fingerprint"),
        "{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_connects_over_ipv6() {
    let Ok(server) = Server::bind("[::1]:0".parse().unwrap()) else {
        eprintln!("IPv6 loopback unavailable; skipping");
        return;
    };
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let mut client = TtkClient::connect_with_verifier(
        addr,
        "localhost",
        EnclaveCertVerifier::new().allow_mock(),
    )
    .await
    .expect("the client should connect over IPv6");
    assert_eq!(client.get("/").await.unwrap().status, 200);
    client.close().await.unwrap();
}
