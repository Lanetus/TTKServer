//! Graceful shutdown of the parent-instance daemons (`vsock-proxy`, `vsock-proxy-tcp`).

use std::future::Future;
use tokio::signal::unix::{signal, Signal, SignalKind};

/// Installs the `SIGTERM` (as a service manager such as systemd sends) and `SIGINT` (Ctrl-C)
/// handlers and returns a future that completes when either signal arrives. The daemons then
/// return from `main` instead of being killed, so their exit status is success and the process
/// exits cleanly.
///
/// The handlers are installed by this call, not when the future is first polled: a signal sent
/// at any point after it returns is caught, even if the daemon's work (polled first by
/// `tokio::select!`) has already reported itself ready.
///
/// Must be called within a Tokio runtime. If a handler cannot be installed, only the other
/// signal stops the process.
pub fn shutdown_signal() -> impl Future<Output = ()> {
    let terminate = listen(SignalKind::terminate());
    let interrupt = listen(SignalKind::interrupt());
    async move {
        tokio::select! {
            () = wait(terminate) => log::info!("SIGTERM received, shutting down"),
            () = wait(interrupt) => log::info!("SIGINT received, shutting down"),
        }
    }
}

/// Installs the handler for `kind`, or logs why it cannot.
fn listen(kind: SignalKind) -> Option<Signal> {
    signal(kind)
        .inspect_err(|e| log::warn!("Cannot handle signal {}: {e}", kind.as_raw_value()))
        .ok()
}

/// Completes when `stream` receives a signal; never without a handler.
async fn wait(stream: Option<Signal>) {
    match stream {
        Some(mut stream) => {
            stream.recv().await;
        }
        None => std::future::pending().await,
    }
}
