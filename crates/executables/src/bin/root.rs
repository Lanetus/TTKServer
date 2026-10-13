//! `root` binary: the root node, run inside the enclave. See [`ttk_root::run`].

/// Starts logging and runs the root node.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    ttk_root::run().await
}
