//! The `POST /evidence` response: fresh TEE Evidence for a Verifier's nonce, together with the
//! RA-TLS certificate it is bound to (RFC 9334 §10).
//!
//! Encoded as a CMW collection of type [`media_type::FRESH_EVIDENCE_COLLECTION`]:
//!
//! - [`media_type::FRESH_EVIDENCE_LABEL`]: the TEE Evidence CMW (as in the RA-TLS certificate),
//!   whose report data binds the SHA-256 of the certificate's SubjectPublicKeyInfo and, for
//!   Nitro, whose `nonce` is the Verifier's nonce;
//! - [`media_type::FRESH_CERTIFICATE_LABEL`]: the DER certificate the server currently presents
//!   ([`media_type::PKIX_CERT`]).
//!
//! The wrapper is unsigned: a Verifier compares the certificate with the one from its TLS
//! handshake and appraises the Evidence against that certificate's key.

use crate::cmw::{Cmw, CmwCollection, CmwRecord, CmwType};
use crate::media_type;

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
