//! Content storage behind [`file_service::FileService`](crate::file_service::FileService):
//! named blobs, in memory ([`MemoryStore`]) or in S3 (`s3::S3Store`, feature `s3`).

use crate::EvalError;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

#[cfg(feature = "s3")]
pub mod s3;

/// A store of blobs by name.
pub trait BlobStore: Send + Sync + 'static {
    /// Stores `data` under `name`, replacing any blob already there.
    fn put(&self, name: &str, data: Vec<u8>) -> impl Future<Output = Result<(), EvalError>> + Send;

    /// Returns the blob stored under `name`; an error if there is none.
    fn get(&self, name: &str) -> impl Future<Output = Result<Vec<u8>, EvalError>> + Send;
}

/// An in-process [`BlobStore`], lost on exit: for tests and local runs.
#[derive(Debug, Default)]
pub struct MemoryStore {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlobStore for MemoryStore {
    async fn put(&self, name: &str, data: Vec<u8>) -> Result<(), EvalError> {
        self.blobs
            .lock()
            .map_err(|_| "memory store poisoned")?
            .insert(name.to_string(), data);
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Vec<u8>, EvalError> {
        self.blobs
            .lock()
            .map_err(|_| "memory store poisoned")?
            .get(name)
            .cloned()
            .ok_or_else(|| format!("no blob named {name}").into())
    }
}
