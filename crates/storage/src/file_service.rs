//! The `s3-server` [`Evaluator`]: `/faf` messages that upload or download files, stored by
//! content (SHA-256) in a [`BlobStore`].
//!
//! Messages and replies are CBOR (RFC 8949) maps whose values are byte strings, so a file
//! travels as raw bytes rather than base64:
//!
//! | Message (CBOR)                                       | Reply (CBOR)                                  |
//! |------------------------------------------------------|-----------------------------------------------|
//! | `{"type": "upload", "body": h'<file>'}`              | `{"response": h'<SHA-256 of the file>'}`      |
//! | `{"type": "download", "body": h'<SHA-256>'}`         | `{"response": h'<file>'}`                     |
//! | `{"type": "download", "body": h'<unknown SHA-256>'}` | `{"error": "not_found"}`                      |
//!
//! The SHA-256 is the raw 32-byte digest; the stored blob's name is its lowercase hex.
//!
//! A [`FileError`] is a reply like any other, sealed to the sender: relays see the same `200`
//! for a missing file as for a found one.

use crate::storage::BlobStore;
use crate::EvalError;
use crate::Evaluator;
use log::debug;
use sha2::{Digest, Sha256};
use ttk_ra_client::hex_encode;

pub use ttk_core::file_message::{FileError, FileRequest, FileResponse, SHA256_LEN};

/// An [`Evaluator`] answering [`FileRequest`]s from a content-addressed [`BlobStore`].
#[derive(Debug)]
pub struct FileService<S> {
    store: S,
}

impl<S: BlobStore> FileService<S> {
    /// Serves files from `store`.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Answers one request: a missing file is a [`FileError::NotFound`] reply, not an error.
    pub async fn handle(&self, request: FileRequest) -> Result<FileResponse, EvalError> {
        Ok(match request {
            FileRequest::Upload(file) => {
                let hash = Sha256::digest(&file).to_vec();
                debug!("file service: upload of {} bytes", file.len());
                self.store.put(&blob_name(&hash)?, file).await?;
                FileResponse::Response(hash)
            }
            FileRequest::Download(hash) => match self.store.get(&blob_name(&hash)?).await? {
                Some(file) => {
                    debug!("file service: download of {} bytes", file.len());
                    FileResponse::Response(file)
                }
                None => {
                    debug!("file service: download of a missing file");
                    FileResponse::Error(FileError::NotFound)
                }
            },
        })
    }
}

impl<S: BlobStore> Evaluator for FileService<S> {
    async fn eval(&self, message: Vec<u8>) -> Result<Vec<u8>, EvalError> {
        let request = FileRequest::from_cbor(&message)?;
        self.handle(request).await?.to_cbor()
    }
}

/// Returns the stored name (lowercase hex) of the blob with SHA-256 `hash`. Rejecting anything
/// but a 32-byte digest keeps a download from naming any other object.
pub fn blob_name(hash: &[u8]) -> Result<String, EvalError> {
    if hash.len() != SHA256_LEN {
        return Err(format!("invalid SHA-256: expected {SHA256_LEN} bytes").into());
    }
    Ok(hex_encode(hash))
}
