//! Tests of the parent-instance proxy binaries (`vsock-proxy`, `vsock-proxy-tcp`): usage and
//! argument errors on every platform, and the refusal to run without vsock off Linux.

use std::process::Output;

/// Runs the proxy binary `bin` with `args`, logging at `info`, and waits for it to exit.
fn run_proxy(bin: &str, args: &[&str]) -> Output {
    std::process::Command::new(bin)
        .args(args)
        .env("RUST_LOG", "info")
        .env_remove("TTK_ENCLAVE_CID")
        .env_remove("TTK_RELAY_LISTEN")
        .env_remove("TTK_VSOCK_PORT")
        .env_remove("TTK_OUTBOUND_VSOCK_PORT")
        .env_remove("TTK_ALLOW_PRIVATE_NEXT_HOPS")
        .env_remove("TTK_TCP_REMOTE")
        .env_remove("TTK_TCP_VSOCK_PORT")
        .env_remove("TTK_TCP_ALLOW_IMDS")
        .output()
        .expect("proxy binary should run")
}

#[test]
fn vsock_proxy_binary_prints_usage() {
    let output = run_proxy(env!("CARGO_BIN_EXE_vsock-proxy"), &["--help"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("Usage: vsock-proxy --cid"), "{stderr}");
}

#[test]
fn vsock_proxy_binary_rejects_invalid_arguments() {
    for args in [&[][..], &["--cid", "x"][..], &["--bogus"][..]] {
        let output = run_proxy(env!("CARGO_BIN_EXE_vsock-proxy"), args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("Usage: vsock-proxy"), "{stderr}");
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn vsock_proxy_binary_needs_linux() {
    let output = run_proxy(env!("CARGO_BIN_EXE_vsock-proxy"), &["--cid", "16"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("only available on Linux"), "{stderr}");
}

#[test]
fn vsock_proxy_tcp_binary_prints_usage() {
    let output = run_proxy(env!("CARGO_BIN_EXE_vsock-proxy-tcp"), &["--help"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("Usage: vsock-proxy-tcp --cid"), "{stderr}");
}

#[test]
fn vsock_proxy_tcp_binary_rejects_invalid_arguments() {
    for args in [
        &[][..],
        &["--cid", "17"][..],
        &["--remote", "127.0.0.1:443"][..],
        &["--cid", "17", "--remote", "127.0.0.1:443", "--bogus"][..],
    ] {
        let output = run_proxy(env!("CARGO_BIN_EXE_vsock-proxy-tcp"), args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("Usage: vsock-proxy-tcp"), "{stderr}");
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn vsock_proxy_tcp_binary_needs_linux() {
    let output = run_proxy(
        env!("CARGO_BIN_EXE_vsock-proxy-tcp"),
        &["--cid", "17", "--remote", "127.0.0.1:443"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("only available on Linux"), "{stderr}");
}
