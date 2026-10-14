//! The `POST /evidence` response: fresh TEE Evidence for a Verifier's nonce, together with the
//! RA-TLS certificate it is bound to (RFC 9334 §10).
//!
//! Encoded as a CMW collection of type [`media_type::FRESH_EVIDENCE_COLLECTION`]:
//!
//! - [`media_type::FRESH_EVIDENCE_LABEL`]: the TEE Evidence CMW (as in the RA-TLS certificate),
//!   whose report data binds the SHA-256 of the certificate's SubjectPublicKeyInfo and the
//!   Verifier's nonce: for Nitro, the document's `nonce`; for TEEs whose report data holds only
//!   64 bytes (TDX, SEV-SNP), its SHA-256 in the second half ([`report_data`]);
//! - [`media_type::FRESH_CERTIFICATE_LABEL`]: the DER certificate the server currently presents
//!   ([`media_type::PKIX_CERT`]).
//!
//! The wrapper is unsigned: a Verifier compares the certificate with the one from its TLS
//! handshake and appraises the Evidence against that certificate's key.

use crate::cmw::{Cmw, CmwCollection, CmwRecord, CmwType};
use crate::media_type;

/// Size of the caller data TDX and SEV-SNP bind into their evidence (`REPORT_DATA`).
pub const REPORT_DATA_LEN: usize = 64;

/// Largest `user_data` [`report_data`] binds together with a nonce.
pub const NONCE_BOUND_USER_DATA_LEN: usize = REPORT_DATA_LEN / 2;

/// Builds the 64-byte report data of TEEs that bind only that much caller data (TDX, SEV-SNP).
///
/// Without a nonce: `user_data` (at most [`REPORT_DATA_LEN`] bytes), zero-padded. With one:
/// `user_data` (at most [`NONCE_BOUND_USER_DATA_LEN`] bytes) zero-padded to 32 bytes, then the
/// SHA-256 of the nonce. The RA-TLS key binding is a 32-byte SHA-256, so startup Evidence is
/// `binding || 0^32` and `POST /evidence` Evidence is `binding || SHA-256(nonce)`.
pub fn report_data(
    user_data: &[u8],
    nonce: Option<&[u8]>,
) -> Result<[u8; REPORT_DATA_LEN], String> {
    let limit = match nonce {
        Some(_) => NONCE_BOUND_USER_DATA_LEN,
        None => REPORT_DATA_LEN,
    };
    if user_data.len() > limit {
        return Err(format!(
            "user_data is {} bytes, at most {limit} are supported{}",
            user_data.len(),
            if nonce.is_some() { " with a nonce" } else { "" }
        ));
    }
    let mut data = [0u8; REPORT_DATA_LEN];
    data[..user_data.len()].copy_from_slice(user_data);
    if let Some(nonce) = nonce {
        data[NONCE_BOUND_USER_DATA_LEN..]
            .copy_from_slice(ring::digest::digest(&ring::digest::SHA256, nonce).as_ref());
    }
    Ok(data)
}

/// Fresh Evidence and the RA-TLS certificate it is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreshEvidence {
    /// The TEE Evidence CMW.
    pub evidence: Cmw,
    /// The DER certificate the server presents.
    pub certificate: Vec<u8>,
}

/// Conversion to and from the CMW collection.
impl FreshEvidence {
    /// Wraps the Evidence and certificate as a [`media_type::FRESH_EVIDENCE_COLLECTION`].
    pub fn to_cmw(&self) -> Cmw {
        Cmw::Collection(CmwCollection {
            collection_type: Some(media_type::FRESH_EVIDENCE_COLLECTION.to_string()),
            entries: vec![
                (
                    media_type::FRESH_EVIDENCE_LABEL.to_string(),
                    self.evidence.clone(),
                ),
                (
                    media_type::FRESH_CERTIFICATE_LABEL.to_string(),
                    Cmw::Record(CmwRecord {
                        cm_type: CmwType::MediaType(media_type::PKIX_CERT.to_string()),
                        value: self.certificate.clone(),
                        ind: None,
                    }),
                ),
            ],
        })
    }

    /// Reads a [`media_type::FRESH_EVIDENCE_COLLECTION`]; does not appraise it.
    pub fn from_cmw(cmw: &Cmw) -> Result<Self, String> {
        let Cmw::Collection(collection) = cmw else {
            return Err("fresh Evidence is not a CMW collection".into());
        };
        if collection.collection_type.as_deref() != Some(media_type::FRESH_EVIDENCE_COLLECTION) {
            return Err("CMW collection is not fresh Evidence".into());
        }
        let evidence = collection
            .get(media_type::FRESH_EVIDENCE_LABEL)
            .ok_or("fresh Evidence has no Evidence member")?
            .clone();
        let certificate = match collection.get(media_type::FRESH_CERTIFICATE_LABEL) {
            Some(Cmw::Record(r)) if r.media_type() == Some(media_type::PKIX_CERT) => {
                r.value.clone()
            }
            Some(_) => return Err("fresh Evidence certificate is not a PKIX record".into()),
            None => return Err("fresh Evidence has no certificate member".into()),
        };
        Ok(Self {
            evidence,
            certificate,
        })
    }

    /// Reads fresh Evidence from its CBOR encoding.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, String> {
        Self::from_cmw(&Cmw::from_cbor_bytes(bytes)?)
    }
}
