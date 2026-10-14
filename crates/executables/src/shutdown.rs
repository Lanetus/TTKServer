//! Graceful shutdown of the parent-instance daemons (`vsock-proxy`, `vsock-proxy-tcp`).

/// Completes when the process is asked to stop: `SIGTERM` (as a service manager such as
/// systemd sends) or `SIGINT` (Ctrl-C). The daemons then return from `main` instead of being
/// killed, so their exit status is success and the process exits cleanly.
///
/// Must be called within a Tokio runtime. If a handler cannot be installed, only the other
/// signal stops the process.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let wait = |kind: SignalKind| async move {
        match signal(kind) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(e) => {
                log::warn!("Cannot handle signal {}: {e}", kind.as_raw_value());
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = wait(SignalKind::terminate()) => log::info!("SIGTERM received, shutting down"),
        () = wait(SignalKind::interrupt()) => log::info!("SIGINT received, shutting down"),
    }
}
