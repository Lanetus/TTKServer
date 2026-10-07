//! Nitro attestation-document helpers shared by the real (`nitro`) and `mock` providers:
//! COSE_Sign1 payload extraction, parsing, mock document creation and CMW wrapping.

use super::AttestationError;
use crate::{AttestationParams, Cmw};
use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest};
use ciborium::value::Value;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P384_SHA384,
};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};
use rustls_pki_types::PrivatePkcs8KeyDer;
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

/// Mock root CA certificate (DER), shared with the client verifier, which trusts it only when
/// mock attestation is explicitly allowed.
const MOCK_ROOT_CERT: &[u8] = super::MOCK_NITRO_ROOT_CERT;

/// PKCS#8 private key of the mock root CA. **Deliberately public test material**: anyone can
/// sign "mock" evidence with it, which is why clients accept mock evidence only on opt-in.
const MOCK_ROOT_KEY: &[u8] = include_bytes!("mock_nitro_root_key.pk8");

/// `module_id` of mock attestation documents.
pub const MOCK_MODULE_ID: &str = "aws-nitro-enclaves-mock";

/// COSE protected header `{1: -35}` (alg: ES384).
const COSE_PROTECTED_ES384: [u8; 4] = [0xa1, 0x01, 0x38, 0x22];

/// Creates a mock attestation document (COSE_Sign1) for local development and testing.
///
/// The document has the AWS Nitro layout, including the specified `user_data`, `nonce` and
/// `public_key`, all-zero (debug-mode) PCRs, and a real ES384 signature by a fresh signing
/// certificate issued by the mock root CA, which is the only `cabundle` entry. A client that
/// trusts the mock root (`EnclaveCertVerifier::allow_mock`) can therefore verify it exactly like
/// a Nitro document.
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

    let (signing_cert, signing_key) = mock_signing_identity()?;
    let mock_doc = AttestationDoc::new(
        MOCK_MODULE_ID.to_string(),
        Digest::SHA384,
        now_ms,
        pcrs,
        signing_cert,
        vec![MOCK_ROOT_CERT.to_vec()],
        params.user_data.clone(),
        params.nonce.clone(),
        params.public_key.clone(),
    );
    let payload = mock_doc.to_binary();

    // Sig_structure = ["Signature1", protected, external_aad, payload] (RFC 9052 §4.4)
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(COSE_PROTECTED_ES384.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.clone()),
    ]);
    let mut to_sign = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut to_sign)
        .map_err(|e| AttestationError::DocumentDecodingFailed(e.to_string()))?;
    let signature = signing_key
        .sign(&SystemRandom::new(), &to_sign)
        .map_err(|_| AttestationError::Driver("failed to sign mock attestation document".into()))?;

    // COSE_Sign1 (Tag 18): [protected, unprotected, payload, signature]
    let cose_sign1 = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(COSE_PROTECTED_ES384.to_vec()),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(signature.as_ref().to_vec()),
        ])),
    );

    let mut out = Vec::new();
    ciborium::ser::into_writer(&cose_sign1, &mut out)
        .map_err(|e| AttestationError::DocumentDecodingFailed(e.to_string()))?;

    Ok(out)
}

/// Issues a fresh P-384 signing certificate from the mock root CA and returns its DER with the
/// matching signing key.
fn mock_signing_identity() -> Result<(Vec<u8>, EcdsaKeyPair), AttestationError> {
    let mock_err = |what: &str, e: rcgen::Error| {
        AttestationError::Driver(format!("failed to {what} for mock attestation: {e}"))
    };

    let root_key = KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(MOCK_ROOT_KEY),
        &PKCS_ECDSA_P384_SHA384,
    )
    .map_err(|e| mock_err("load the mock root key", e))?;
    // Rebuilt with the parameters the embedded root was generated with, so the issued
    // certificate's issuer name and key identifier match `MOCK_ROOT_CERT`.
    let mut root_params = CertificateParams::default();
    root_params.distinguished_name = DistinguishedName::new();
    root_params.distinguished_name.push(
        DnType::CommonName,
        "TTKServer Mock Nitro Root CA (INSECURE, test only)",
    );
    root_params
        .distinguished_name
        .push(DnType::OrganizationName, "TTKServer");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = root_params
        .self_signed(&root_key)
        .map_err(|e| mock_err("build the mock root", e))?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)
        .map_err(|e| mock_err("generate a signing key", e))?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "TTKServer Mock Nitro Enclave");
    let cert = params
        .signed_by(&key, &root, &root_key)
        .map_err(|e| mock_err("issue the signing certificate", e))?;

    let signing_key = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P384_SHA384_FIXED_SIGNING,
        &key.serialize_der(),
        &SystemRandom::new(),
    )
    .map_err(|_| AttestationError::Driver("failed to load the mock signing key".into()))?;
    Ok((cert.der().to_vec(), signing_key))
}

// ---------------------------------------------------------------------------
// CMW wrapping
// ---------------------------------------------------------------------------

/// Wraps `nitro_doc` (raw COSE_Sign1 bytes from the NSM) verbatim as a CMW Evidence record of
/// type [`media_type::AWS_NITRO`](super::media_type::AWS_NITRO).
pub fn wrap_as_cmw(nitro_doc: Vec<u8>) -> Cmw {
    Cmw::evidence(super::media_type::AWS_NITRO, nitro_doc)
}
