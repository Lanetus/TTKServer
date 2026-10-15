//! End-to-end tests of the `client-m` binary (text messages) and the `echo` terminal binary
//! against real relay and terminal nodes on free local ports (mock attestation).
//!
//! The `echo` binary trusts only the built-in TTK root CA, so a test cannot unlock its routes:
//! the round trip runs against an in-process terminal with the same echo evaluator, and the
//! binary itself is checked to start, attest and keep `/faf` locked.

#[path = "../../ra-server/tests/support/test_ca.rs"]
mod test_ca;
use test_ca::SignForTests;

use std::net::{SocketAddr, UdpSocket};
use std::process::Output;
use std::time::Duration;
use ttk_executables::faf_client::attest_node;
use ttk_ra_client::EnclaveCertVerifier;
use ttk_ra_server::server::Server;
use ttk_ra_server::terminal::Terminal;
use ttk_ra_server::{EvalError, Evaluator};
use ttk_relay::Relay;

/// The `echo` binary's evaluator: answers every message with the message unchanged.
struct Echo;

impl Evaluator for Echo {
    async fn eval(&self, message: Vec<u8>) -> Result<Vec<u8>, EvalError> {
        Ok(message)
    }
}

/// Starts a relay node that accepts mock-attested next hops on a free local port and returns
/// its address. It serves (unlocked with a test CA certificate) until the test's runtime shuts
/// down.
fn start_relay() -> SocketAddr {
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).expect("relay should start");
    server.sign_for_tests().unwrap();
    let addr = server.local_addr().unwrap();
    let relay = Relay::new(server).allow_mock().allow_private_next_hops();
    tokio::spawn(async move { relay.serve().await.unwrap() });
    addr
}

/// Starts an echo terminal node (unlocked with a test CA certificate) on a free local port and
/// returns its address.
fn start_echo_terminal() -> SocketAddr {
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).expect("terminal should start");
    server.sign_for_tests().unwrap();
    let addr = server.local_addr().unwrap();
    let terminal = Terminal::new(server, Echo);
    tokio::spawn(async move { terminal.serve().await.unwrap() });
    addr
}

/// A free local UDP port (released before it is returned).
fn free_udp_addr() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn run_client_m(args: &[&str], allow_mock: bool) -> Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_client-m"));
    command
        .args(args)
        .env_remove("TTK_SERVER_ADDR")
        .env_remove("TTK_SERVER_NAME")
        .env_remove("TTK_ALLOW_MOCK_ATTESTATION")
        .env_remove("RUST_LOG");
    if allow_mock {
        command.env("TTK_ALLOW_MOCK_ATTESTATION", "1");
    }
    command.output().await.expect("client-m binary should run")
}

#[tokio::test(flavor = "multi_thread")]
async fn client_m_gets_its_message_echoed_through_two_relays() {
    let addr = start_relay().to_string();
    let relay = start_relay().to_string();
    let terminal = start_echo_terminal().to_string();
    let message = "hello, enclave ✓";
    let output = run_client_m(
        &[
            "--addr",
            &addr,
            "--relay",
            &relay,
            "--terminal",
            &terminal,
            "--message",
            message,
        ],
        true,
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains(&format!("route: {addr} -> {relay} -> {terminal}")),
        "{stderr}"
    );
    assert!(stderr.contains("Response Status: 200"), "{stderr}");
    assert!(
        stderr.contains(&format!("<-- Reply: {message}")),
        "{stderr}"
    );
    assert!(
        stderr.contains("Connection closed successfully."),
        "{stderr}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn client_m_refuses_mock_attestation_without_opt_in() {
    let addr = start_relay().to_string();
    let output = run_client_m(&["--addr", &addr, "--message", "hi"], false).await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("Failed to connect"), "{stderr}");
    assert!(!stderr.contains("Sending POST /faf"), "{stderr}");
}

#[tokio::test]
async fn client_m_prints_usage() {
    for flag in ["--help", "-h"] {
        let output = run_client_m(&[flag], false).await;
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("Usage: client-m"), "{stdout}");
    }
}

#[tokio::test]
async fn client_m_requires_a_message() {
    for args in [&[][..], &["--message"][..], &["--addr", "127.0.0.1:9"][..]] {
        let output = run_client_m(args, true).await;
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("--message is required"), "{stderr}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn echo_binary_attests_and_keeps_faf_locked_until_certified() {
    let echo_addr = free_udp_addr();
    let _echo = tokio::process::Command::new(env!("CARGO_BIN_EXE_echo"))
        .env("TTK_USE_UDP", "1")
        .env("TTK_ATTESTATION", "mock")
        .env("TTK_LISTEN_ADDR", echo_addr.to_string())
        .env_remove("RUST_LOG")
        .kill_on_drop(true)
        .spawn()
        .expect("echo binary should start");

    // Wait until the echo node answers the RA-TLS handshake with verifiable (mock) Evidence.
    let verifier = EnclaveCertVerifier::new().allow_mock();
    let mut attested = false;
    for _ in 0..100 {
        if attest_node(&echo_addr.to_string(), verifier.clone())
            .await
            .is_ok()
        {
            attested = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(attested, "echo binary should attest on {echo_addr}");

    // Self-signed, its `/faf` answers 404, which the second relay reports as a failed forward.
    let addr = start_relay().to_string();
    let relay = start_relay().to_string();
    let terminal = echo_addr.to_string();
    let output = run_client_m(
        &[
            "--addr",
            &addr,
            "--relay",
            &relay,
            "--terminal",
            &terminal,
            "--message",
            "hi",
        ],
        true,
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("Response Status: 502"), "{stderr}");
    assert!(!stderr.contains("<-- Reply:"), "{stderr}");
}

#[test]
fn echo_binary_rejects_an_invalid_listen_address() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_echo"))
        .env("TTK_USE_UDP", "1")
        .env("TTK_LISTEN_ADDR", "not-an-address")
        .env_remove("RUST_LOG")
        .output()
        .expect("echo binary should run");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("TTK_LISTEN_ADDR"), "{stderr}");
}
