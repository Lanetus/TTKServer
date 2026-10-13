//! `terminal` binary: the terminal node, run inside the enclave. See [`ttk_storage::run`].

/// Starts logging and runs the terminal node.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    ttk_storage::run().await
}
