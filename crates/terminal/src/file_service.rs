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
//!
//! The SHA-256 is the raw 32-byte digest; the stored blob's name is its lowercase hex.

use crate::storage::BlobStore;
use crate::EvalError;
use crate::Evaluator;
use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use ttk_ra_client::hex_encode;

/// Length of a SHA-256 digest, the `body` of a download and the reply to an upload.
pub const SHA256_LEN: usize = 32;

/// A `/faf` message to the file service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "lowercase")]
pub enum FileRequest {
    /// Stores the file; answered with its SHA-256.
    Upload(#[serde(with = "serde_bytes")] Vec<u8>),
    /// Retrieves the file with this SHA-256; answered with the file.
    Download(#[serde(with = "serde_bytes")] Vec<u8>),
}

impl FileRequest {
    /// Encodes as CBOR, the message a client seals to the terminal.
    pub fn to_cbor(&self) -> Result<Vec<u8>, EvalError> {
        to_cbor(self)
    }

    /// Decodes a CBOR message.
    pub fn from_cbor(message: &[u8]) -> Result<Self, EvalError> {
        Ok(ciborium::from_reader(message)?)
    }
}

/// The file service's reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileResponse {
    /// The SHA-256 for an upload, the file for a download.
    #[serde(with = "serde_bytes")]
    pub response: Vec<u8>,
}

impl FileResponse {
    /// Encodes as CBOR, the reply the terminal seals to the sender.
    pub fn to_cbor(&self) -> Result<Vec<u8>, EvalError> {
        to_cbor(self)
    }

    /// Decodes a CBOR reply.
    pub fn from_cbor(reply: &[u8]) -> Result<Self, EvalError> {
        Ok(ciborium::from_reader(reply)?)
    }
}

fn to_cbor(value: &impl Serialize) -> Result<Vec<u8>, EvalError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

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

    /// Answers one request.
    pub async fn handle(&self, request: FileRequest) -> Result<FileResponse, EvalError> {
        let response = match request {
            FileRequest::Upload(file) => {
                let hash = Sha256::digest(&file).to_vec();
                debug!("file service: upload of {} bytes", file.len());
                self.store.put(&blob_name(&hash)?, file).await?;
                hash
            }
            FileRequest::Download(hash) => {
                let file = self.store.get(&blob_name(&hash)?).await?;
                debug!("file service: download of {} bytes", file.len());
                file
            }
        };
        Ok(FileResponse { response })
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
