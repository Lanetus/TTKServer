//! Nitro attestation-document helpers shared by the real (`nitro`) and `mock` providers:
//! COSE_Sign1 payload extraction, parsing, mock document creation and EAT wrapping.

use super::AttestationError;
use crate::{AttestationParams, EatClaimsSet};
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
use ciborium::value::Value;
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

/// Extracts the CBOR-encoded payload from a COSE_Sign1 structure (RFC 9052).
///
/// Supports both tagged (CBOR Tag 18) and untagged 4-element CBOR arrays.
pub fn extract_cose_payload(document: &[u8]) -> Result<Vec<u8>, AttestationError> {
    let value: ciborium::value::Value = ciborium::de::from_reader(Cursor::new(document))
        .map_err(|e| AttestationError::DocumentDecodingFailed(format!("Invalid CBOR: {e}")))?;

    let items = match value {
        ciborium::value::Value::Tag(18, boxed) => match *boxed {
            ciborium::value::Value::Array(arr) => arr,
            _ => {
                return Err(AttestationError::DocumentDecodingFailed(
                    "COSE_Sign1 tag 18 did not contain an array".to_string(),
                ))
            }
        },
        ciborium::value::Value::Array(arr) => arr,
        _ => {
            return Err(AttestationError::DocumentDecodingFailed(
                "Attestation document is not a COSE_Sign1 structure".to_string(),
            ))
        }
    };

    if items.len() < 4 {
        return Err(AttestationError::DocumentDecodingFailed(format!(
            "COSE_Sign1 structure has only {} elements, expected 4",
            items.len()
        )));
    }

    match &items[2] {
        ciborium::value::Value::Bytes(payload) => Ok(payload.clone()),
        _ => Err(AttestationError::DocumentDecodingFailed(
            "COSE_Sign1 structure payload is not a byte string".to_string(),
        )),
    }
}

/// Parses the payload of an AWS Nitro attestation document into an [`AttestationDoc`].
pub fn parse_attestation_document(document: &[u8]) -> Result<AttestationDoc, AttestationError> {
    let payload = extract_cose_payload(document)?;
    AttestationDoc::from_binary(&payload).map_err(|e| {
        AttestationError::DocumentDecodingFailed(format!("Failed to parse AttestationDoc: {e:?}"))
    })
}

/// Creates a synthetic mock attestation document (COSE_Sign1 structure) for local testing.
///
/// Contains valid CBOR serialization matching the AWS Nitro Enclaves specification,
/// including the specified `user_data`, `nonce`, and `public_key`.
pub fn create_mock_attestation_document(
    params: &AttestationParams,
) -> Result<Vec<u8>, AttestationError> {
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
        .map_err(|e| AttestationError::DocumentDecodingFailed(e.to_string()))?;

    Ok(out)
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
pub fn wrap_as_eat(nitro_doc: &[u8]) -> Result<EatClaimsSet, AttestationError> {
    let payload = extract_cose_payload(nitro_doc)?;
    let (module_id, timestamp_ms) = read_module_id_and_timestamp(&payload)?;

    let mut ueid = vec![UEID_TYPE_RAND];
    ueid.extend_from_slice(&Sha256::digest(module_id.as_bytes()));

    let submods = Value::Map(vec![(
        Value::Text(NITRO_SUBMOD_NAME.to_string()),
        Value::Bytes(nitro_doc.to_vec()),
    )]);

    Ok(EatClaimsSet {
        iat: Some((timestamp_ms / 1000) as i64),
        ueid: Some(ueid),
        eat_profile: Some(EAT_PROFILE.to_string()),
        submods: Some(submods),
        ..EatClaimsSet::default()
    })
}

/// Reads `module_id` and `timestamp` out of the CBOR-encoded Nitro AttestationDoc
/// payload (field names per the AWS Nitro Enclaves attestation document spec).
fn read_module_id_and_timestamp(payload: &[u8]) -> Result<(String, u64), AttestationError> {
    let value: ciborium::value::Value = ciborium::de::from_reader(std::io::Cursor::new(payload))
        .map_err(|e| {
            AttestationError::DocumentDecodingFailed(format!("Invalid CBOR payload: {e}"))
        })?;

    let map = match value {
        ciborium::value::Value::Map(m) => m,
        _ => {
            return Err(AttestationError::DocumentDecodingFailed(
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
            AttestationError::DocumentDecodingFailed(
                "attestation document payload missing module_id".to_string(),
            )
        })?,
        timestamp_ms.ok_or_else(|| {
            AttestationError::DocumentDecodingFailed(
                "attestation document payload missing timestamp".to_string(),
            )
        })?,
    ))
}
