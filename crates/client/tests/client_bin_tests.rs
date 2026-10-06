//! End-to-end tests of the `client` binary against real relay and terminal nodes on free local
//! ports (mock attestation).

use std::net::SocketAddr;
use std::process::Output;
use ttk_relay::Relay;
use ttk_terminal::Terminal;

/// Starts a relay node that accepts mock-attested next hops on a free local port and returns
/// its address. It serves until the test's runtime shuts down.
fn start_relay() -> SocketAddr {
    let relay = Relay::bind("127.0.0.1:0".parse().unwrap())
        .expect("relay should start")
        .allow_mock()
        .allow_private_next_hops();
    let addr = relay.local_addr().unwrap();
    tokio::spawn(async move { relay.serve().await.unwrap() });
    addr
}

/// Starts a terminal node on a free local port and returns its address.
fn start_terminal() -> SocketAddr {
    let terminal = Terminal::bind("127.0.0.1:0".parse().unwrap()).expect("terminal should start");
    let addr = terminal.local_addr().unwrap();
    tokio::spawn(async move { terminal.serve().await.unwrap() });
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
async fn client_binary_sends_a_faf_request_through_two_relays() {
    let addr = start_relay().to_string();
    let relay = start_relay().to_string();
    let terminal = start_terminal().to_string();
    let output = run_client_binary(
        &["--addr", &addr, "--relay", &relay, "--terminal", &terminal],
        true,
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "--> Sending POST /faf (route: {addr} -> {relay} -> {terminal})"
        )),
        "{stdout}"
    );
    assert!(stdout.contains("Response Status: 200"), "{stdout}");
    assert!(
        stdout.contains("Terminal reply (decrypted):\nhello:hello"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Connection closed successfully."),
        "{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_binary_fails_when_the_second_relay_is_a_terminal() {
    let addr = start_relay().to_string();
    let terminal = start_terminal().to_string();
    // The terminal rejects a request that still has relays left, so the entry relay reports a
    // bad gateway.
    let output = run_client_binary(
        &[
            "--addr",
            &addr,
            "--relay",
            &terminal,
            "--terminal",
            &terminal,
        ],
        true,
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Response Status: 502"), "{stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_binary_defaults_to_the_second_relay_on_port_4434() {
    let addr = start_relay();
    let url = format!("https://127.0.0.1:{}", addr.port());
    let output = run_client_binary(&[&url], true).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Nothing listens there, so the relay can't be attested and nothing is sent.
    assert!(
        stdout.contains("--> Attesting relay 127.0.0.1:4434"),
        "{stdout}"
    );
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("Failed to attest relay 127.0.0.1:4434"),
        "{stderr}"
    );
    assert!(!stdout.contains("Sending POST /faf"), "{stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_binary_defaults_to_the_terminal_on_port_4444() {
    let addr = start_relay().to_string();
    let relay = start_relay().to_string();
    let output = run_client_binary(&["--addr", &addr, "--relay", &relay], true).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Nothing listens there, so the terminal can't be attested and nothing is sent.
    assert!(
        stdout.contains("--> Attesting terminal 127.0.0.1:4444"),
        "{stdout}"
    );
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("Failed to attest terminal 127.0.0.1:4444"),
        "{stderr}"
    );
    assert!(!stdout.contains("Sending POST /faf"), "{stdout}");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_binary_fails_against_the_mock_server_without_opt_in() {
    let addr = start_relay().to_string();
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
    let addr = start_relay().to_string();
    let relay = start_relay().to_string();
    let terminal = start_terminal().to_string();
    let output = run_client_binary_with_env(
        &["--addr", &addr, "--relay", &relay, "--terminal", &terminal],
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
