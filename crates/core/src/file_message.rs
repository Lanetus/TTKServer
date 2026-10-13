//! Wire format of the file service (`ttk_storage`, bin `s3-server`): the `/faf`
//! messages that upload or download files and their replies, shared by the terminal and the
//! client.
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
//! The SHA-256 is the raw 32-byte digest.

use serde::{Deserialize, Serialize};

/// Error encoding or decoding a file service message.
pub type FileMessageError = Box<dyn std::error::Error + Send + Sync>;

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
    pub fn to_cbor(&self) -> Result<Vec<u8>, FileMessageError> {
        to_cbor(self)
    }

    /// Decodes a CBOR message.
    pub fn from_cbor(message: &[u8]) -> Result<Self, FileMessageError> {
        Ok(ciborium::from_reader(message)?)
    }
}

/// The file service's reply: a CBOR map with a single key, `response` or `error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileResponse {
    /// The SHA-256 for an upload, the file for a download.
    Response(#[serde(with = "serde_bytes")] Vec<u8>),
    /// The request could not be served.
    Error(FileError),
}

/// Why a [`FileRequest`] could not be served, sent as a CBOR text string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileError {
    /// No file with the requested SHA-256 is stored (`"not_found"`).
    NotFound,
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("file not found"),
        }
    }
}

impl std::error::Error for FileError {}

impl FileResponse {
    /// Encodes as CBOR, the reply the terminal seals to the sender.
    pub fn to_cbor(&self) -> Result<Vec<u8>, FileMessageError> {
        to_cbor(self)
    }

    /// Decodes a CBOR reply.
    pub fn from_cbor(reply: &[u8]) -> Result<Self, FileMessageError> {
        Ok(ciborium::from_reader(reply)?)
    }

    /// Returns the response bytes, or the [`FileError`].
    pub fn into_result(self) -> Result<Vec<u8>, FileError> {
        match self {
            Self::Response(response) => Ok(response),
            Self::Error(e) => Err(e),
        }
    }
}

fn to_cbor(value: &impl Serialize) -> Result<Vec<u8>, FileMessageError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
