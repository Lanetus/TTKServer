//! `s3-server` binary: a terminal node whose `/faf` messages upload / download files in S3
//! ([`ttk_storage::file_service`]). Configured by [`S3Store::from_env`] and
//! [`ttk_ra_server::server::Listener::from_env`].

use ttk_storage::file_service::FileService;
use ttk_storage::storage::s3::S3Store;

/// Starts logging, configures S3 and runs the terminal node with the file service.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let store = S3Store::from_env()
        .await
        .map_err(|e| e as Box<dyn std::error::Error>)?;
    ttk_storage::run_with(FileService::new(store)).await
}
