//! AWS Nitro Enclaves evidence: an NSM attestation document (COSE_Sign1, ES384) whose signing
//! certificate chains to the AWS Nitro Enclaves root.

use super::{
    chain_algorithms, verify_ecdsa, AnyKeyUsage, ImageTrustStore, Policy, TeeKind, TrustStore,
    VerifiedEvidence,
};
use ciborium::Value;
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use x509_parser::prelude::*;

/// COSE algorithm identifier for ECDSA P-384 with SHA-384 (RFC 9053).
const COSE_ALG_ES384: i128 = -35;

/// Tolerated clock skew when checking that the document is not from the future.
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

/// Decoded payload of an AWS Nitro attestation document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub module_id: String,
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: BTreeMap<usize, Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    #[serde(default)]
    pub public_key: Option<Vec<u8>>,
    #[serde(default)]
    pub user_data: Option<Vec<u8>>,
    #[serde(default)]
    pub nonce: Option<Vec<u8>>,
}

/// Structural checks on a decoded attestation document.
impl AttestationDocument {
    /// Checks the mandatory fields per the AWS Nitro Enclaves attestation document spec.
    fn check_sanity(&self) -> Result<(), String> {
        if self.module_id.is_empty() {
            return Err("attestation module_id is empty".into());
        }
        if self.digest != "SHA384" {
            return Err(format!("unsupported attestation digest {}", self.digest));
        }
        if self.pcrs.is_empty() || self.pcrs.len() > 32 {
            return Err("attestation document has an invalid number of PCRs".into());
        }
        if self.pcrs.values().any(|v| ![32, 48, 64].contains(&v.len())) {
            return Err("attestation document has a PCR of invalid length".into());
        }
        if self.certificate.is_empty() {
            return Err("attestation signing certificate is empty".into());
        }
        Ok(())
    }
}

/// Verifies the Nitro attestation document `doc_bytes` at time `now`; a non-debug enclave's
/// image must be in `images`.
pub fn verify(
    doc_bytes: &[u8],
    now: UnixTime,
    trust: &TrustStore,
    images: &dyn ImageTrustStore,
    policy: Policy,
) -> Result<VerifiedEvidence, String> {
    let cose = CoseSign1Parts::parse(doc_bytes)?;
    let doc: AttestationDocument = ciborium::from_reader(cose.payload.as_slice())
        .map_err(|e| format!("invalid attestation document payload: {e}"))?;
    doc.check_sanity()?;

    if doc.timestamp > (now.as_secs() + MAX_CLOCK_SKEW.as_secs()) * 1000 {
        return Err("attestation document timestamp is in the future".into());
    }

    let root = trusted_root(&doc, trust, policy)?;
    verify_chain(&doc, root)?;
    cose.verify_signature(&doc.certificate)?;

    // Debug-mode enclaves report all-zero PCRs.
    let debug = doc.pcrs.get(&0).is_some_and(|p| p.iter().all(|b| *b == 0));
    // A debug enclave's image cannot be identified; `verify_evidence` rejects it by policy.
    if !debug {
        check_image_allowed(&doc, images)?;
    }
    let measurements = doc
        .pcrs
        .iter()
        .map(|(i, v)| (format!("pcr{i}"), v.clone()))
        .collect();

    Ok(VerifiedEvidence {
        tee: TeeKind::AwsNitro,
        report_data: doc.user_data.clone().unwrap_or_default(),
        measurements,
        debug,
        nitro: Some(doc),
    })
}

/// Checks that the image's PCR (by default PCR0, the SHA-384 of the enclave image file) is in
/// the allowlist of `images`.
fn check_image_allowed(
    doc: &AttestationDocument,
    images: &dyn ImageTrustStore,
) -> Result<(), String> {
    let index = images.nitro_pcr_index();
    let pcr = doc
        .pcrs
        .get(&index)
        .ok_or(format!("attestation document has no PCR{index}"))?;
    if images.nitro_image_allowlist().iter().any(|p| p == pcr) {
        return Ok(());
    }
    Err(format!(
        "enclave image PCR{index} {} is not in the list of verified images",
        crate::hex_encode(pcr)
    ))
}

/// Parser of the Nitro image allowlist format (defined in [`crate::trust`]).
pub use crate::trust::parse_image_allowlist;

/// `module_id` the server's mock provider puts in its documents.
const MOCK_MODULE_ID: &str = "aws-nitro-enclaves-mock";

/// Returns the pinned root that `doc`'s `cabundle` must start with: the AWS Nitro root, or the
/// mock root when mock attestation is allowed.
fn trusted_root<'a>(
    doc: &AttestationDocument,
    trust: &'a TrustStore,
    policy: Policy,
) -> Result<&'a [u8], String> {
    let root = doc.cabundle.first();
    let is_mock = doc.module_id == MOCK_MODULE_ID || root == Some(&trust.mock_nitro_root);
    if is_mock && !policy.allow_mock {
        return Err(
            "the server presented MOCK attestation evidence, which is only accepted for local \
             development: set TTK_ALLOW_MOCK_ATTESTATION=1 for the client binary, or use \
             EnclaveCertVerifier::allow_mock()"
                .into(),
        );
    }
    let root = root.ok_or(if is_mock {
        "the mock attestation document is unsigned (empty cabundle): rebuild and restart the \
         server to get signed mock evidence"
    } else {
        "attestation cabundle is empty"
    })?;

    if *root == trust.aws_nitro_root {
        return Ok(&trust.aws_nitro_root);
    }
    if *root == trust.mock_nitro_root {
        log::warn!("Accepting MOCK attestation evidence signed by the TTKServer mock root CA");
        return Ok(&trust.mock_nitro_root);
    }
    Err("attestation cabundle is not rooted at the AWS Nitro root CA".into())
}

/// Verifies the document's signing certificate up to the pinned `root`.
///
/// The chain is validated at the document's timestamp: Nitro signing certificates are
/// short-lived, while the server reuses one document for the lifetime of its TLS certificate.
fn verify_chain(doc: &AttestationDocument, root: &[u8]) -> Result<(), String> {
    let root_der = CertificateDer::from(root);
    let anchor = webpki::anchor_from_trusted_cert(&root_der)
        .map_err(|e| format!("invalid attestation root certificate: {e:?}"))?;
    let intermediates: Vec<CertificateDer<'_>> = doc.cabundle[1..]
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let leaf_der = CertificateDer::from(doc.certificate.as_slice());
    let leaf = webpki::EndEntityCert::try_from(&leaf_der)
        .map_err(|e| format!("invalid attestation signing certificate: {e:?}"))?;

    leaf.verify_for_usage(
        chain_algorithms(),
        &[anchor],
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_millis(doc.timestamp)),
        AnyKeyUsage,
        None,
        None,
    )
    .map_err(|e| format!("attestation certificate chain is invalid: {e:?}"))?;
    Ok(())
}

/// The parts of a COSE_Sign1 structure (RFC 9052) needed for verification.
struct CoseSign1Parts {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

/// Parsing and signature verification of COSE_Sign1 documents.
impl CoseSign1Parts {
    /// Parses a tagged (tag 18) or untagged COSE_Sign1 array.
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| format!("invalid COSE_Sign1 CBOR: {e}"))?;
        let items = match value {
            Value::Tag(18, inner) => match *inner {
                Value::Array(items) => items,
                _ => return Err("COSE_Sign1 tag does not contain an array".into()),
            },
            Value::Array(items) => items,
            _ => return Err("attestation document is not a COSE_Sign1 structure".into()),
        };
        let [protected, _unprotected, payload, signature] = <[Value; 4]>::try_from(items)
            .map_err(|_| "COSE_Sign1 structure must have 4 elements".to_string())?;
        let bytes_of = |v: Value, what: &str| match v {
            Value::Bytes(b) => Ok(b),
            _ => Err(format!("COSE_Sign1 {what} is not a byte string")),
        };
        Ok(Self {
            protected: bytes_of(protected, "protected header")?,
            payload: bytes_of(payload, "payload")?,
            signature: bytes_of(signature, "signature")?,
        })
    }

    /// Verifies the ES384 signature with the public key of `signing_cert_der`.
    fn verify_signature(&self, signing_cert_der: &[u8]) -> Result<(), String> {
        let header: Value = ciborium::from_reader(self.protected.as_slice())
            .map_err(|e| format!("invalid COSE protected header: {e}"))?;
        let alg = header.as_map().and_then(|m| {
            m.iter().find_map(|(k, v)| match (k, v) {
                (Value::Integer(k), Value::Integer(v)) if i128::from(*k) == 1 => {
                    Some(i128::from(*v))
                }
                _ => None,
            })
        });
        if alg != Some(COSE_ALG_ES384) {
            return Err("attestation document is not signed with ES384".into());
        }

        // Sig_structure = ["Signature1", protected, external_aad, payload] (RFC 9052 §4.4)
        let sig_structure = Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(self.protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(self.payload.clone()),
        ]);
        let mut to_verify = Vec::new();
        ciborium::into_writer(&sig_structure, &mut to_verify)
            .map_err(|e| format!("failed to encode COSE Sig_structure: {e}"))?;

        let (_, signing_cert) = X509Certificate::from_der(signing_cert_der)
            .map_err(|e| format!("malformed attestation signing certificate: {e}"))?;
        verify_ecdsa(
            &ring::signature::ECDSA_P384_SHA384_FIXED,
            &signing_cert.public_key().subject_public_key.data,
            &to_verify,
            &self.signature,
        )
        .map_err(|_| "attestation document signature is invalid".to_string())
    }
}
