//! Test support shared by the workspace's tests (included with `#[path]`, never built into a
//! library or an enclave image): reads the payload of a Nitro attestation document without
//! verifying it, to inspect what a provider put into it.

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use ciborium::Value;

/// Parses the payload of a COSE_Sign1 (RFC 9052, tagged or untagged) AWS Nitro attestation
/// document into an [`AttestationDoc`]. The signature is not checked.
pub fn parse_attestation_document(document: &[u8]) -> Result<AttestationDoc, String> {
    let value: Value = ciborium::de::from_reader(document).map_err(|e| format!("CBOR: {e}"))?;
    let items = match value {
        Value::Tag(18, boxed) => match *boxed {
            Value::Array(items) => items,
            _ => return Err("COSE_Sign1 tag 18 did not contain an array".into()),
        },
        Value::Array(items) => items,
        _ => return Err("not a COSE_Sign1 structure".into()),
    };
    match items.get(2) {
        Some(Value::Bytes(payload)) if items.len() == 4 => AttestationDoc::from_binary(payload)
            .map_err(|e| format!("Failed to parse AttestationDoc: {e:?}")),
        _ => Err("malformed COSE_Sign1 structure".into()),
    }
}
