//! `local-mem-server` binary: a terminal node whose `/faf` messages upload / download files in an
//! in-memory store ([`MemoryStore`] behind the [`ttk_storage`] file service), for local
//! development and testing: nothing is persisted, every file is lost when the process exits.
//! Configured by [`ttk_ra_server::server::Listener::from_env`]; otherwise like `s3-server`.

use ttk_ra_server::server::{BoxError, Listener, Server};
use ttk_ra_server::terminal::Terminal;
use ttk_ra_server::Evaluator;
use ttk_storage::adaptors::local_memory::MemoryStore;
use ttk_storage::FileService;

/// Runs a terminal node answering `/faf` messages with `evaluator`: attests, builds the RA-TLS
/// identity, then serves HTTP/3 until the endpoint closes. Listens as configured by
/// [`Listener::from_env`].
pub async fn run<E: Evaluator>(evaluator: E) -> Result<(), BoxError> {
    Terminal::new(Server::listen(Listener::from_env()?)?, evaluator)
        .serve()
        .await
}

/// Starts logging and runs the terminal node with the file service over an empty in-memory
/// store.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let store = MemoryStore::new();
    run(FileService::new(store)).await
}
