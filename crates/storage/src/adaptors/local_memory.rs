//! [`MemoryStore`]: an in-process [`BlobStore`], for tests and local runs.

use super::BlobStore;
use crate::EvalError;
use std::collections::HashMap;
use std::sync::Mutex;

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

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, EvalError> {
        Ok(self
            .blobs
            .lock()
            .map_err(|_| "memory store poisoned")?
            .get(name)
            .cloned())
    }
}
