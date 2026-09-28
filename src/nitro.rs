//! AWS Nitro Security Module (NSM) interface for generating and managing Attestation Documents.
//!
//! This module provides a safe, idiomatic Rust API for interacting with the AWS Nitro Security
//! Module (`/dev/nsm`) inside an AWS Nitro Enclave. It handles:
//!
//! - Opening and managing the NSM driver session safely with RAII ([`NsmSession`]), preventing
//!   file descriptor leaks.
//! - Creating hardware-rooted Nitro Attestation Documents (COSE_Sign1 format) containing
//!   Platform Configuration Registers (PCRs), cryptographic measurements, and optional user data.
//! - Remote Attestation TLS (RA-TLS) binding by hashing public certificates or keys into the
//!   document's `user_data` field.
//! - Parsing and inspecting generated attestation documents and extracting their CBOR payload.
//! - Fallback mock document generation for local testing and CI environments where `/dev/nsm`
//!   hardware is not present.

use crate::eat::EatClaimsSet;
use crate::Attestation;
pub use crate::AttestationParams;
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest, ErrorCode};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use ciborium::value::Value;
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors that can occur when interacting with the AWS Nitro Security Module.
#[derive(Debug)]
pub enum NitroError {
    /// Failed to open the NSM device file (`/dev/nsm`).
    DeviceOpenFailed(String),

    /// The NSM driver returned an error response.
    NsmError(ErrorCode),

    /// Received an unexpected response from the NSM driver.
    UnexpectedResponse(String),

    /// Input parameter validation failed (e.g. data exceeds size limits).
    InvalidInput(String),

    /// Failed to decode or parse CBOR/COSE data from the attestation document.
    DocumentDecodingFailed(String),

    /// An I/O error occurred.
    Io(std::io::Error),
}

impl fmt::Display for NitroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceOpenFailed(msg) => write!(f, "Failed to open NSM device (/dev/nsm): {msg}"),
            Self::NsmError(code) => write!(f, "NSM driver returned error code: {code:?}"),
            Self::UnexpectedResponse(msg) => {
                write!(f, "Unexpected response from NSM driver: {msg}")
            }
            Self::InvalidInput(msg) => write!(f, "Invalid attestation input: {msg}"),
            Self::DocumentDecodingFailed(msg) => write!(f, "Document decoding failure: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for NitroError {}

impl From<std::io::Error> for NitroError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Information about the connected Nitro Security Module runtime and configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct NsmDescription {
    /// Major API version of the NSM.
    pub version_major: u16,
    /// Minor API version of the NSM.
    pub version_minor: u16,
    /// Patch version of the NSM.
    pub version_patch: u16,
    /// Module identifier for the NSM.
    pub module_id: String,
    /// Maximum number of Platform Configuration Registers (PCRs).
    pub max_pcrs: u16,
    /// The indices of PCRs that are read-only / locked.
    pub locked_pcrs: std::collections::BTreeSet<u16>,
    /// Digest algorithm used for PCR values.
    pub digest: Digest,
}

/// An open session with the Nitro Security Module (`/dev/nsm`).
///
/// Implements RAII to ensure the device file descriptor is automatically closed
/// via [`nsm_exit`] when the session is dropped.
#[derive(Debug)]
pub struct NsmSession {
    fd: i32,
}

impl Attestation for NsmSession {
    /// Opens a new session with the Nitro Security Module.
    ///
    /// Calls [`nsm_init`] to open `/dev/nsm`. Returns [`NitroError::DeviceOpenFailed`]
    /// if the device file cannot be opened (e.g., if not running inside an AWS Nitro Enclave).
    fn open() -> Result<Self, NitroError> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(NitroError::DeviceOpenFailed(
                "Unable to open /dev/nsm. Ensure this process is running inside an AWS Nitro Enclave with the NSM device enabled."
                    .to_string(),
            ));
        }
        Ok(Self { fd })
    }

    /// Creates an [`NsmSession`] from an existing raw file descriptor.
    pub fn from_raw_fd(fd: i32) -> Result<Self, NitroError> {
        if fd < 0 {
            return Err(NitroError::DeviceOpenFailed(
                "Invalid file descriptor provided".to_string(),
            ));
        }
        Ok(Self { fd })
    }

    /// Returns the underlying raw file descriptor.
    fn raw_fd(&self) -> i32 {
        self.fd
    }

    /// Requests an Attestation Document from the NSM.
    ///
    /// Returns the raw COSE_Sign1 formatted document bytes.
    fn create_attestation(&self, params: &AttestationParams) -> Result<Vec<u8>, NitroError> {
        let request = Request::Attestation {
            user_data: params.user_data.as_ref().map(|d| d.clone().into()),
            nonce: params.nonce.as_ref().map(|n| n.clone().into()),
            public_key: params.public_key.as_ref().map(|pk| pk.clone().into()),
        };

        match nsm_process_request(self.fd, request) {
            Response::Attestation { document } => Ok(document),
            Response::Error(err) => Err(NitroError::NsmError(err)),
            other => Err(NitroError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Convenience method to create an attestation document binding an ephemeral TLS certificate.
    ///
    /// Computes the SHA-256 hash of `cert_der` and supplies it as `user_data`.
    fn create_attestation_for_cert(&self, cert_der: &[u8]) -> Result<Vec<u8>, NitroError> {
        let params = AttestationParams::new().with_user_data_hash(cert_der);
        self.create_attestation(&params)
    }

    /// Describes the connected Nitro Security Module capabilities and configuration.
    fn describe_nsm(&self) -> Result<NsmDescription, NitroError> {
        match nsm_process_request(self.fd, Request::DescribeNSM) {
            Response::DescribeNSM {
                version_major,
                version_minor,
                version_patch,
                module_id,
                max_pcrs,
                locked_pcrs,
                digest,
            } => Ok(NsmDescription {
                version_major,
                version_minor,
                version_patch,
                module_id,
                max_pcrs,
                locked_pcrs,
                digest,
            }),
            Response::Error(err) => Err(NitroError::NsmError(err)),
            other => Err(NitroError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Requests cryptographic entropy (random bytes) from the NSM.
    fn get_random(&self) -> Result<Vec<u8>, NitroError> {
        match nsm_process_request(self.fd, Request::GetRandom) {
            Response::GetRandom { random } => Ok(random),
            Response::Error(err) => Err(NitroError::NsmError(err)),
            other => Err(NitroError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Describes a Platform Configuration Register (PCR) at `index`.
    /// Returns `(locked, data)`.
    fn describe_pcr(&self, index: u16) -> Result<(bool, Vec<u8>), NitroError> {
        match nsm_process_request(self.fd, Request::DescribePCR { index }) {
            Response::DescribePCR { lock, data } => Ok((lock, data)),
            Response::Error(err) => Err(NitroError::NsmError(err)),
            other => Err(NitroError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Extends a Platform Configuration Register (PCR) at `index` with `data`.
    fn extend_pcr(&self, index: u16, data: Vec<u8>) -> Result<Vec<u8>, NitroError> {
        match nsm_process_request(self.fd, Request::ExtendPCR { index, data }) {
            Response::ExtendPCR { data } => Ok(data),
            Response::Error(err) => Err(NitroError::NsmError(err)),
            other => Err(NitroError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Locks a Platform Configuration Register (PCR) at `index` against further modification.
    fn lock_pcr(&self, index: u16) -> Result<(), NitroError> {
        match nsm_process_request(self.fd, Request::LockPCR { index }) {
            Response::LockPCR => Ok(()),
            Response::Error(err) => Err(NitroError::NsmError(err)),
            other => Err(NitroError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    fn generate_document(attestation_params: AttestationParams) -> EatClaimsSet {
        todo!()
    }
}

impl Drop for NsmSession {
    fn drop(&mut self) {
        if self.fd >= 0 {
            nsm_exit(self.fd);
            self.fd = -1;
        }
    }
}

/// Generates an AWS Nitro attestation document using the specified parameters.
///
/// Automatically opens a session with `/dev/nsm`, creates the attestation, and closes the device.
fn create_attestation_document(params: &AttestationParams) -> Result<Vec<u8>, NitroError> {
    let session = NsmSession::open()?;
    session.create_attestation(params)
}

/// Generates an attestation document with `user_data` set to the SHA-256 digest of `cert_der`.
///
/// This implements Remote Attestation TLS (RA-TLS) evidence generation.
fn create_attestation_for_cert(cert_der: &[u8]) -> Result<Vec<u8>, NitroError> {
    let params = AttestationParams::new().with_user_data_hash(cert_der);
    create_attestation_document(&params)
}

/// Generates an attestation document with raw user data.
fn create_attestation_with_user_data(user_data: &[u8]) -> Result<Vec<u8>, NitroError> {
    let params = AttestationParams::new().with_user_data(user_data.to_vec());
    create_attestation_document(&params)
}

/// Checks whether the NSM device (`/dev/nsm`) is available.
fn is_nitro_enclave_available() -> bool {
    let fd = nsm_init();
    if fd >= 0 {
        nsm_exit(fd);
        true
    } else {
        false
    }
}

/// Extracts the CBOR-encoded payload from a COSE_Sign1 structure (RFC 9052).
///
/// Supports both tagged (CBOR Tag 18) and untagged 4-element CBOR arrays.
pub fn extract_cose_payload(document: &[u8]) -> Result<Vec<u8>, NitroError> {
    let value: ciborium::value::Value = ciborium::de::from_reader(Cursor::new(document))
        .map_err(|e| NitroError::DocumentDecodingFailed(format!("Invalid CBOR: {e}")))?;

    let items = match value {
        ciborium::value::Value::Tag(18, boxed) => match *boxed {
            ciborium::value::Value::Array(arr) => arr,
            _ => {
                return Err(NitroError::DocumentDecodingFailed(
                    "COSE_Sign1 tag 18 did not contain an array".to_string(),
                ))
            }
        },
        ciborium::value::Value::Array(arr) => arr,
        _ => {
            return Err(NitroError::DocumentDecodingFailed(
                "Attestation document is not a COSE_Sign1 structure".to_string(),
            ))
        }
    };

    if items.len() < 4 {
        return Err(NitroError::DocumentDecodingFailed(format!(
            "COSE_Sign1 structure has only {} elements, expected 4",
            items.len()
        )));
    }

    match &items[2] {
        ciborium::value::Value::Bytes(payload) => Ok(payload.clone()),
        _ => Err(NitroError::DocumentDecodingFailed(
            "COSE_Sign1 structure payload is not a byte string".to_string(),
        )),
    }
}

/// Parses the payload of an AWS Nitro attestation document into an [`AttestationDoc`].
pub fn parse_attestation_document(document: &[u8]) -> Result<AttestationDoc, NitroError> {
    let payload = extract_cose_payload(document)?;
    AttestationDoc::from_binary(&payload).map_err(|e| {
        NitroError::DocumentDecodingFailed(format!("Failed to parse AttestationDoc: {e:?}"))
    })
}

/// Creates a synthetic mock attestation document (COSE_Sign1 structure) for local testing.
///
/// Contains valid CBOR serialization matching the AWS Nitro Enclaves specification,
/// including the specified `user_data`, `nonce`, and `public_key`.
pub fn create_mock_attestation_document(params: &AttestationParams) -> Result<Vec<u8>, NitroError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut pcrs = BTreeMap::new();
    for i in 0..16 {
        pcrs.insert(i, vec![0u8; 48]); // Mock SHA-384 size PCRs
    }

    let mock_doc = AttestationDoc::new(
        "aws-nitro-enclaves-mock".to_string(),
        Digest::SHA384,
        now_ms,
        pcrs,
        vec![0x30, 0x82, 0x01, 0x00], // Mock DER certificate
        vec![],                       // Mock CA bundle
        params.user_data.clone(),
        params.nonce.clone(),
        params.public_key.clone(),
    );

    let payload = mock_doc.to_binary();

    // Wrap in standard COSE_Sign1 structure (Tag 18):
    // [protected, unprotected, payload, signature]
    let cose_sign1 = ciborium::value::Value::Tag(
        18,
        Box::new(ciborium::value::Value::Array(vec![
            ciborium::value::Value::Bytes(vec![0xa1, 0x01, 0x38, 0x22]), // alg: ES384 (-35)
            ciborium::value::Value::Map(vec![]),
            ciborium::value::Value::Bytes(payload),
            ciborium::value::Value::Bytes(vec![0xAA; 96]), // 96-byte mock signature for ES384
        ])),
    );

    let mut out = Vec::new();
    ciborium::ser::into_writer(&cose_sign1, &mut out)
        .map_err(|e| NitroError::DocumentDecodingFailed(e.to_string()))?;

    Ok(out)
}

/// Generates an attestation document using the NSM device, falling back to a mock document
/// if the NSM device (`/dev/nsm`) is unavailable (e.g. running on macOS or standard Linux in CI).
fn generate_attestation_or_mock(params: &AttestationParams) -> Result<Vec<u8>, NitroError> {
    match create_attestation_document(params) {
        Ok(doc) => Ok(doc),
        Err(NitroError::DeviceOpenFailed(err)) => {
            log::warn!(
                "NSM device unavailable ({err}); generating mock attestation document for local/test environment"
            );
            create_mock_attestation_document(params)
        }
        Err(e) => Err(e),
    }
}

/// Generates an attestation document bound to the SHA-256 hash of `cert_der`,
/// falling back to a mock document if `/dev/nsm` is unavailable.
pub fn generate_attestation_for_cert_or_mock(cert_der: &[u8]) -> Result<Vec<u8>, NitroError> {
    let params = AttestationParams::new().with_user_data_hash(cert_der);
    generate_attestation_or_mock(&params)
}

// ---------------------------------------------------------------------------
// EAT wrapping
// ---------------------------------------------------------------------------

/// Private EAT profile identifier (RFC 4151 tag URI) for this nested-Nitro-in-EAT
/// construction. Not IANA-registered; there is no such profile in the registry.
const EAT_PROFILE: &str = "tag:aws.amazon.com,2024:nitro-enclave-nested-eat";

/// UEID type byte for a randomly generated (non-registered) identifier,
/// per RFC 9711 Section 4.2.1.
const UEID_TYPE_RAND: u8 = 0x01;

/// Submodule label used to embed the raw Nitro COSE_Sign1 document inside the
/// EAT `submods` map.
const NITRO_SUBMOD_NAME: &str = "aws_nitro";

/// Wraps `nitro_doc` (raw COSE_Sign1 bytes from the NSM) as an RFC 9711 EAT
/// claims-set and returns the CBOR-encoded bytes.
///
/// The Nitro document is embedded verbatim under `submods` (RFC 9711 §4.2.9,
/// "CBOR-inside-CBOR" nested-token form). The outer claims-set carries a
/// best-effort mapping of standard EAT claims extracted from the Nitro payload:
///
/// | EAT claim    | Source in Nitro payload          |
/// |--------------|----------------------------------|
/// | `iat`        | `timestamp` field (ms → seconds) |
/// | `ueid`       | SHA-256 of `module_id`           |
/// | `eat_profile`| constant tag URI                 |
/// | `submods`    | the raw `nitro_doc` bytes        |
///
/// Trust still comes from the nested Nitro token, not from the outer claims-set.
pub fn wrap_as_eat(nitro_doc: &[u8]) -> Result<Vec<u8>, NitroError> {
    let payload = extract_cose_payload(nitro_doc)?;
    let (module_id, timestamp_ms) = read_module_id_and_timestamp(&payload)?;

    let mut ueid = vec![UEID_TYPE_RAND];
    ueid.extend_from_slice(&Sha256::digest(module_id.as_bytes()));

    let submods = Value::Map(vec![(
        Value::Text(NITRO_SUBMOD_NAME.to_string()),
        Value::Bytes(nitro_doc.to_vec()),
    )]);

    let claims = EatClaimsSet {
        iat: Some((timestamp_ms / 1000) as i64),
        ueid: Some(ueid),
        eat_profile: Some(EAT_PROFILE.to_string()),
        submods: Some(submods),
        ..EatClaimsSet::default()
    };

    claims
        .to_cbor_bytes()
        .map_err(|e| NitroError::DocumentDecodingFailed(e.to_string()))
}

/// Reads `module_id` and `timestamp` out of the CBOR-encoded Nitro AttestationDoc
/// payload (field names per the AWS Nitro Enclaves attestation document spec).
fn read_module_id_and_timestamp(payload: &[u8]) -> Result<(String, u64), NitroError> {
    let value: ciborium::value::Value = ciborium::de::from_reader(std::io::Cursor::new(payload))
        .map_err(|e| NitroError::DocumentDecodingFailed(format!("Invalid CBOR payload: {e}")))?;

    let map = match value {
        ciborium::value::Value::Map(m) => m,
        _ => {
            return Err(NitroError::DocumentDecodingFailed(
                "attestation document payload is not a CBOR map".to_string(),
            ))
        }
    };

    let mut module_id: Option<String> = None;
    let mut timestamp_ms: Option<u64> = None;

    for (key, val) in map {
        match (key.as_text(), val) {
            (Some("module_id"), ciborium::value::Value::Text(s)) => module_id = Some(s),
            (Some("timestamp"), ciborium::value::Value::Integer(i)) => {
                timestamp_ms = Some(i128::from(i) as u64)
            }
            _ => {}
        }
    }

    Ok((
        module_id.ok_or_else(|| {
            NitroError::DocumentDecodingFailed(
                "attestation document payload missing module_id".to_string(),
            )
        })?,
        timestamp_ms.ok_or_else(|| {
            NitroError::DocumentDecodingFailed(
                "attestation document payload missing timestamp".to_string(),
            )
        })?,
    ))
}
