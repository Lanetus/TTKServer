//! Wraps an AWS Nitro attestation document (RATS Evidence) as an RFC 9711 Entity
//! Attestation Token (EAT) claims-set.
//!
//! The Nitro document is already a COSE_Sign1 structure signed by the enclave's
//! hardware-rooted NSM key; this server has no separate key that a Relying Party
//! would already trust more than that one. So rather than minting a new signature,
//! the Nitro document is embedded verbatim as a nested token under the `submods`
//! claim (RFC 9711 Section 4.2.9, "CBOR-inside-CBOR" nested-token form), and the
//! outer claims-set carries a best-effort mapping of standard EAT claims. Trust
//! still comes from the nested Nitro token, not from the outer claims-set.
use ciborium::value::Value;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::io::Cursor;

/// Private profile identifier (RFC 4151 tag URI) for this nested-Nitro-in-EAT
/// construction. Not IANA-registered; there is no such profile in the registry.
const EAT_PROFILE: &str = "tag:aws.amazon.com,2024:nitro-enclave-nested-eat";

// EAT/CWT claim keys, from the IANA "CBOR Web Token (CWT) Claims" registry
// (https://www.iana.org/assignments/cwt), as registered by RFC 9711.
const CLAIM_IAT: i64 = 6;
const CLAIM_UEID: i64 = 256;
const CLAIM_EAT_PROFILE: i64 = 265;
const CLAIM_SUBMODS: i64 = 266;

/// UEID type byte for a randomly generated (non-registered) identifier,
/// RFC 9711 Section 4.2.1.
const UEID_TYPE_RAND: u8 = 0x01;

const NITRO_SUBMOD_NAME: &str = "aws_nitro";

/// Builds an EAT claims-set (raw CBOR bytes) that nests `nitro_doc`, the raw bytes
/// of an NSM Attestation Document, as a submodule.
pub fn wrap_as_eat(nitro_doc: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let payload = cose_sign1_payload(nitro_doc)?;
    let (module_id, timestamp_ms) = read_module_id_and_timestamp(&payload)?;

    let mut ueid = vec![UEID_TYPE_RAND];
    ueid.extend_from_slice(&Sha256::digest(module_id.as_bytes()));

    let submods = Value::Map(vec![(
        Value::Text(NITRO_SUBMOD_NAME.to_string()),
        Value::Bytes(nitro_doc.to_vec()),
    )]);

    let claims = Value::Map(vec![
        (
            Value::Integer(CLAIM_IAT.into()),
            Value::Integer(((timestamp_ms / 1000) as i64).into()),
        ),
        (Value::Integer(CLAIM_UEID.into()), Value::Bytes(ueid)),
        (
            Value::Integer(CLAIM_EAT_PROFILE.into()),
            Value::Text(EAT_PROFILE.to_string()),
        ),
        (Value::Integer(CLAIM_SUBMODS.into()), submods),
    ]);

    let mut out = Vec::new();
    ciborium::ser::into_writer(&claims, &mut out)?;
    Ok(out)
}

/// Extracts the `payload` element (index 2) from a COSE_Sign1 structure, which may
/// be wrapped in CBOR tag 18 or left untagged (RFC 9052 Section 2; AWS Nitro emits
/// the tagged form).
fn cose_sign1_payload(cose_sign1: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let value: Value = ciborium::de::from_reader(Cursor::new(cose_sign1))?;

    let array = match value {
        Value::Tag(18, boxed) => match *boxed {
            Value::Array(items) => items,
            _ => return Err("COSE_Sign1 tag did not wrap a CBOR array".into()),
        },
        Value::Array(items) => items,
        _ => return Err("attestation document is not a COSE_Sign1 structure".into()),
    };

    match array.into_iter().nth(2) {
        Some(Value::Bytes(payload)) => Ok(payload),
        _ => Err("COSE_Sign1 structure is missing its payload".into()),
    }
}

/// Reads `module_id` and `timestamp` out of the CBOR-encoded AttestationDoc payload
/// (field names per the Nitro Enclaves attestation document specification).
fn read_module_id_and_timestamp(payload: &[u8]) -> Result<(String, u64), Box<dyn Error>> {
    let value: Value = ciborium::de::from_reader(Cursor::new(payload))?;
    let map = match value {
        Value::Map(m) => m,
        _ => return Err("attestation document payload is not a CBOR map".into()),
    };

    let mut module_id = None;
    let mut timestamp_ms = None;
    for (key, val) in map {
        match (key.as_text(), val) {
            (Some("module_id"), Value::Text(s)) => module_id = Some(s),
            (Some("timestamp"), Value::Integer(i)) => timestamp_ms = Some(i128::from(i) as u64),
            _ => {}
        }
    }

    Ok((
        module_id.ok_or("attestation document payload missing module_id")?,
        timestamp_ms.ok_or("attestation document payload missing timestamp")?,
    ))
}
