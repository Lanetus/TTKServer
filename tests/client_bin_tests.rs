//! End-to-end tests of the `client` binary against the real server on a free local port
//! (mock attestation). The binary exists only with the `test-client` feature:
//! `cargo test --features test-client`.

#![cfg(all(feature = "mock", feature = "test-client"))]

use std::net::SocketAddr;
use std::process::Output;
use ttk_server::client::EnclaveCertVerifier;
use ttk_server::server::Server;

/// Starts a server that accepts mock-attested relays on a free local port and returns its
/// address. It serves until the test's runtime shuts down.
fn start_server() -> SocketAddr {
    let server = Server::bind("127.0.0.1:0".parse().unwrap())
        .expect("server should start")
        .with_relay_verifier(|| EnclaveCertVerifier::new().allow_mock());
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
async fn client_binary_sends_a_faf_request_through_the_relay() {
    let addr = start_server().to_string();
    let relay = start_server().to_string();
    let output = run_client_binary(&["--addr", &addr, "--relay", &relay], true).await;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.contains(&format!("--> Sending POST /faf (relay: {relay})")),
        "{stdout}"
    );
    assert!(stdout.contains("Response Status: 200"), "{stdout}");
    assert!(stdout.contains("relayed"), "{stdout}");
    assert!(
        stdout.contains("Connection closed successfully."),
        "{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_binary_defaults_to_the_relay_on_port_4444() {
    let addr = start_server();
    let url = format!("https://127.0.0.1:{}", addr.port());
    let output = run_client_binary(&[&url], true).await;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.contains("--> Sending POST /faf (relay: 127.0.0.1:4444)"),
        "{stdout}"
    );
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
        &["--addr", &addr, "--relay", &addr],
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
