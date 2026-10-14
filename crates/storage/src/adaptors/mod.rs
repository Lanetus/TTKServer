//! Content adaptors behind [`FileService`](crate::FileService):
//! named blobs, in memory ([`MemoryStore`](local_memory::MemoryStore)) or in S3 (`s3::S3Store`, feature `s3`).

use crate::EvalError;
use std::future::Future;

pub mod local_memory;
#[cfg(feature = "s3")]
pub mod s3;

/// A store of blobs by name.
pub trait BlobStore: Send + Sync + 'static {
    /// Stores `data` under `name`, replacing any blob already there.
    fn put(&self, name: &str, data: Vec<u8>) -> impl Future<Output = Result<(), EvalError>> + Send;

    /// Returns the blob stored under `name`, or `None` if there is none.
    fn get(&self, name: &str) -> impl Future<Output = Result<Option<Vec<u8>>, EvalError>> + Send;
}
