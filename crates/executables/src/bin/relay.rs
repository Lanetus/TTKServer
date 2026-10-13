//! `relay` binary: the relay node, run inside the enclave. See [`ttk_relay::run`].

/// Starts logging and runs the relay node.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    ttk_relay::run().await
}
