//! TTKServer storage for the terminal node: the file service [`Evaluator`]
//! ([`file_service::FileService`], bin `s3-server`) and the [`storage::BlobStore`]s it keeps
//! files in. The terminal node itself is [`ttk_ra_server::terminal::Terminal`].

pub use ttk_ra_server::evaluator::{EvalError, Evaluator};

pub mod file_service;
pub mod storage;
