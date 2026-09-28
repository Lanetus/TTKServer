use crate::AttestationParams;
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors that can occur when interacting with the AWS Nitro Security Module.
#[derive(Debug)]
pub enum TEEError {
    /// Failed to open the NSM device file (`/dev/nsm`).
    GenericError(String),
}

impl fmt::Display for TEEError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenericError(msg) => write!(f, "Failed to open NSM device (/dev/nsm): {msg}"),
        }
    }
}

impl std::error::Error for TEEError {}

/// Creates a synthetic mock attestation document (COSE_Sign1 structure) for local testing.
///
/// Contains valid CBOR serialization matching the AWS Nitro Enclaves specification,
/// including the specified `user_data`, `nonce`, and `public_key`.
pub fn create_mock_attestation_document(params: &AttestationParams) -> Result<Vec<u8>, TEEError> {
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

    let payload = params.to_binary();

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
        .map_err(|e| TEEError::GenericError(e.to_string()))?;

    Ok(out)
}
