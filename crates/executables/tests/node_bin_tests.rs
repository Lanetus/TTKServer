//! Tests of the enclave node binaries (`relay`, `root`, `s3-server`): each reads its
//! configuration from the environment and exits with an error on an invalid one before serving.

use std::process::Output;

/// Every variable the node binaries read, removed so the tests see only what they set.
const NODE_ENV: &[&str] = &[
    "TTK_USE_UDP",
    "TTK_ATTESTATION",
    "TTK_LISTEN_ADDR",
    "TTK_VSOCK_PORT",
    "TTK_PARENT_CID",
    "TTK_OUTBOUND_VSOCK_PORT",
    "TTK_ALLOW_MOCK_ATTESTATION",
    "TTK_ALLOW_PRIVATE_NEXT_HOPS",
    "TTK_S3_BUCKET",
    "TTK_S3_ENDPOINT",
    "TTK_S3_VSOCK_PORT",
    "TTK_IMDS_VSOCK_PORT",
    "RUST_LOG",
];

/// Runs the node binary `bin` with only `env` of [`NODE_ENV`] set, and waits for it to exit.
fn run_node(bin: &str, env: &[(&str, &str)]) -> Output {
    let mut command = std::process::Command::new(bin);
    for name in NODE_ENV {
        command.env_remove(name);
    }
    command
        .envs(env.iter().copied())
        .output()
        .expect("node binary should run")
}

/// Asserts that `output` is a failed run whose error mentions `message`.
fn assert_fails_with(output: &Output, message: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(message), "{stderr}");
}

#[test]
fn relay_binary_rejects_an_invalid_listen_address() {
    let output = run_node(
        env!("CARGO_BIN_EXE_relay"),
        &[("TTK_USE_UDP", "1"), ("TTK_LISTEN_ADDR", "not-an-address")],
    );
    assert_fails_with(&output, "invalid TTK_LISTEN_ADDR");
}

#[test]
fn relay_binary_rejects_an_invalid_vsock_port() {
    let output = run_node(
        env!("CARGO_BIN_EXE_relay"),
        &[("TTK_VSOCK_PORT", "not-a-port")],
    );
    assert_fails_with(&output, "TTK_VSOCK_PORT");
}

#[test]
fn relay_binary_refuses_mock_attestation_unless_asked_for() {
    // No TEE hardware here: without TTK_ATTESTATION=mock the node must not fall back to mock.
    let output = run_node(
        env!("CARGO_BIN_EXE_relay"),
        &[("TTK_USE_UDP", "1"), ("TTK_LISTEN_ADDR", "127.0.0.1:0")],
    );
    assert_fails_with(&output, "refusing to serve mock attestation");
}

#[test]
fn root_binary_rejects_an_invalid_listen_address() {
    let output = run_node(
        env!("CARGO_BIN_EXE_root"),
        &[("TTK_USE_UDP", "1"), ("TTK_LISTEN_ADDR", "not-an-address")],
    );
    assert_fails_with(&output, "invalid TTK_LISTEN_ADDR");
}

#[test]
fn root_binary_rejects_an_invalid_vsock_port() {
    let output = run_node(
        env!("CARGO_BIN_EXE_root"),
        &[("TTK_VSOCK_PORT", "not-a-port")],
    );
    assert_fails_with(&output, "TTK_VSOCK_PORT");
}

#[cfg(feature = "s3")]
#[test]
fn s3_server_binary_needs_a_bucket() {
    let output = run_node(
        env!("CARGO_BIN_EXE_s3-server"),
        &[("TTK_USE_UDP", "1"), ("AWS_REGION", "us-east-1")],
    );
    assert_fails_with(&output, "TTK_S3_BUCKET is not set");
}

#[cfg(feature = "s3")]
#[test]
fn s3_server_binary_rejects_an_invalid_listen_address() {
    // S3 is configured without contacting it; the listener is read next.
    let output = run_node(
        env!("CARGO_BIN_EXE_s3-server"),
        &[
            ("TTK_S3_BUCKET", "ttk-test-bucket"),
            ("AWS_REGION", "us-east-1"),
            ("AWS_ACCESS_KEY_ID", "AKIDTTKTEST"),
            ("AWS_SECRET_ACCESS_KEY", "ttk-test-secret"),
            ("AWS_EC2_METADATA_DISABLED", "true"),
            ("TTK_USE_UDP", "1"),
            ("TTK_LISTEN_ADDR", "not-an-address"),
        ],
    );
    assert_fails_with(&output, "invalid TTK_LISTEN_ADDR");
}
