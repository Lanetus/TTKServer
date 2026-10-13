//! `s3-server` binary: a terminal node whose `/faf` messages upload / download files in S3
//! ([`ttk_storage`]). Configured by [`S3Store::from_env`] and
//! [`ttk_ra_server::server::Listener::from_env`].

use ttk_ra_server::server::{BoxError, Listener, Server};
use ttk_ra_server::terminal::Terminal;
use ttk_ra_server::Evaluator;
use ttk_storage::storage::s3::S3Store;
use ttk_storage::FileService;

/// Runs a terminal node answering `/faf` messages with `evaluator`: attests, builds the RA-TLS
/// identity, then serves HTTP/3 until the endpoint closes. Listens as configured by
/// [`Listener::from_env`].
pub async fn run<E: Evaluator>(evaluator: E) -> Result<(), BoxError> {
    Terminal::new(Server::listen(Listener::from_env()?)?, evaluator)
        .serve()
        .await
}

/// Starts logging, configures S3 and runs the terminal node with the file service.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let store = S3Store::from_env()
        .await
        .map_err(|e| e as Box<dyn std::error::Error>)?;
    run(FileService::new(store)).await
}
