//! Tests for `ttk_executables::shutdown`: the handlers must be in place as soon as
//! `shutdown_signal()` returns, before its future is polled, so a `SIGTERM` that arrives while
//! the daemon is starting is a clean shutdown and not the default (fatal) action.
#![cfg(unix)]

use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;
use ttk_executables::shutdown::shutdown_signal;

#[tokio::test]
async fn sigterm_before_the_first_poll_completes_the_future() {
    let shutdown = shutdown_signal();
    let status = Command::new("kill")
        .args(["-TERM", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    timeout(Duration::from_secs(10), shutdown)
        .await
        .expect("SIGTERM should complete the shutdown future");
}
