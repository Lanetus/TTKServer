//! Verification of TEE attestation evidence carried in a RATS Conceptual Message Wrapper (CMW).
//!
//! The server wraps exactly one TEE's evidence in a CMW whose type, from [`media_type`], names
//! the TEE. [`verify_evidence`] dispatches on that type:
//!
//! | CMW                                         | TEE         | Evidence                              | Verified by |
//! |---------------------------------------------|-------------|---------------------------------------|-------------|
//! | record [`media_type::AWS_NITRO`]            | AWS Nitro   | NSM attestation document (COSE_Sign1) | [`nitro`]   |
//! | collection [`media_type::SEV_SNP_COLLECTION`] | AMD SEV-SNP | `report` record + `vcek` record (DER) | [`sev_snp`] |
//! | record [`media_type::TDX`]                  | Intel TDX   | DCAP quote v4/v5 with PCK chain       | [`dcap`]    |
//! | record [`media_type::SGX`]                  | Intel SGX   | DCAP quote v3/v4/v5 with PCK chain    | [`dcap`]    |
//!
//! A record whose `ind` is set must mark it as Evidence. The CMW itself is unsigned; trust
//! comes only from the wrapped evidence.
//!
//! Every verifier checks the vendor signature chain up to a root in the [`TrustStore`] and
//! returns a [`VerifiedEvidence`]; the Nitro verifier also requires the enclave image's PCR0 to
//! be in the [`ImageTrustStore::nitro_image_allowlist`]. [`verify_evidence`] then enforces the
//! [`Policy`] and checks
//! that the evidence's report data is bound to the expected hash (the SHA-256 of the RA-TLS
//! certificate's public key).

pub mod dcap;
pub mod nitro;
pub mod sev_snp;

use rustls_pki_types::{SignatureVerificationAlgorithm, UnixTime};
use std::collections::BTreeMap;
use std::fmt;
use ttk_core::cmw::{ind, Cmw, CmwCollection, CmwRecord};

/// CMW types identifying the TEE that produced the wrapped evidence.
pub use ttk_core::media_type;

/// Trust anchors and accepted images the verifiers check evidence against (defined in
/// [`crate::trust`]).
pub use crate::trust::{ImageTrustStore, TrustStore};

/// The trusted execution environment that produced a piece of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TeeKind {
    /// AWS Nitro Enclaves.
    AwsNitro,
    /// AMD SEV-SNP.
    SevSnp,
    /// Intel TDX.
    Tdx,
    /// Intel SGX.
    Sgx,
}

/// Human-readable TEE names.
impl fmt::Display for TeeKind {
    /// Writes the TEE's common name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AwsNitro => "AWS Nitro",
            Self::SevSnp => "AMD SEV-SNP",
            Self::Tdx => "Intel TDX",
            Self::Sgx => "Intel SGX",
        })
    }
}

/// Mapping between TEE kinds and their CMW types.
impl TeeKind {
    /// Returns the TEE whose evidence `cmw` carries, judged by its type alone: the media type
    /// of a record, or the collection type of a collection.
    pub fn from_cmw(cmw: &Cmw) -> Option<Self> {
        match cmw {
            Cmw::Record(record) => match record.media_type()? {
                media_type::AWS_NITRO => Some(Self::AwsNitro),
                media_type::TDX => Some(Self::Tdx),
                media_type::SGX => Some(Self::Sgx),
                _ => None,
            },
            Cmw::Collection(collection) => match collection.collection_type.as_deref()? {
                media_type::SEV_SNP_COLLECTION => Some(Self::SevSnp),
                _ => None,
            },
        }
    }
}

/// Evidence whose signature chain has been verified.
#[derive(Debug, Clone)]
pub struct VerifiedEvidence {
    /// The TEE that produced the evidence.
    pub tee: TeeKind,
    /// Data bound into the evidence by the attester: Nitro `user_data`, or the 64-byte
    /// `REPORT_DATA` of an SEV-SNP report or DCAP quote.
    pub report_data: Vec<u8>,
    /// Named measurements, compared against expected values by the caller. Names per TEE:
    /// Nitro `pcr0`..`pcrN`; SEV-SNP `measurement`, `host_data`, `id_key_digest`,
    /// `author_key_digest`; TDX `mrtd`, `rtmr0`..`rtmr3`, `mrseam`, `mrconfigid`, `mrowner`,
    /// `mrownerconfig`; SGX `mrenclave`, `mrsigner`.
    pub measurements: BTreeMap<String, Vec<u8>>,
    /// `true` if the TEE runs in debug mode, where its memory is not confidential.
    pub debug: bool,
    /// The decoded Nitro attestation document, for Nitro evidence.
    pub nitro: Option<nitro::AttestationDocument>,
}

/// Relaxations of the default (strict) verification policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Policy {
    /// Accept mock Nitro documents: additionally trusts the mock root CA (whose private key is
    /// public) and implies `allow_debug`. Mock documents are still fully verified. For local
    /// development only.
    pub allow_mock: bool,
    /// Accept TEEs running in debug mode.
    pub allow_debug: bool,
}

/// Verifies the TEE evidence in the CBOR CMW `cmw_bytes` at time `now` and checks that it is bound to
/// `binding`, the SHA-256 of the RA-TLS certificate's public key. Nitro images must be in
/// `images`.
pub fn verify_evidence(
    cmw_bytes: &[u8],
    binding: &[u8],
    now: UnixTime,
    trust: &TrustStore,
    images: &dyn ImageTrustStore,
    policy: Policy,
) -> Result<VerifiedEvidence, String> {
    let cmw = Cmw::from_cbor_bytes(cmw_bytes).map_err(|e| format!("invalid CMW: {e}"))?;
    let tee = TeeKind::from_cmw(&cmw).ok_or("CMW does not carry supported TEE evidence")?;

    let evidence = match (tee, &cmw) {
        (TeeKind::AwsNitro, Cmw::Record(r)) => {
            nitro::verify(evidence_of(r, tee)?, now, trust, images, policy)?
        }
        (TeeKind::Tdx | TeeKind::Sgx, Cmw::Record(r)) => {
            dcap::verify(evidence_of(r, tee)?, tee, now, trust)?
        }
        (TeeKind::SevSnp, Cmw::Collection(c)) => {
            let report = member(
                c,
                media_type::SEV_SNP_REPORT_LABEL,
                media_type::SEV_SNP_REPORT,
            )?;
            let vcek = member(c, media_type::SEV_SNP_VCEK_LABEL, media_type::PKIX_CERT)?;
            sev_snp::verify(evidence_of(report, tee)?, &vcek.value, now, trust)?
        }
        _ => return Err(format!("{tee} evidence has the wrong CMW form")),
    };

    if evidence.debug && !(policy.allow_debug || policy.allow_mock) {
        return Err(format!("{tee} evidence comes from a debug-mode TEE"));
    }
    if !is_bound_to(&evidence.report_data, binding) {
        return Err(format!(
            "{tee} report data does not match the certificate's public key"
        ));
    }
    Ok(evidence)
}

/// Returns the `tee` evidence in `record`, which must not be marked as anything but Evidence.
fn evidence_of(record: &CmwRecord, tee: TeeKind) -> Result<&[u8], String> {
    match record.ind {
        Some(bits) if bits & ind::EVIDENCE == 0 => {
            Err(format!("{tee} CMW record is not marked as Evidence"))
        }
        _ => Ok(&record.value),
    }
}

/// Returns the record labelled `label` in `collection`, which must be of `media_type`.
fn member<'a>(
    collection: &'a CmwCollection,
    label: &str,
    media_type: &str,
) -> Result<&'a CmwRecord, String> {
    match collection.get(label) {
        Some(Cmw::Record(r)) if r.media_type() == Some(media_type) => Ok(r),
        Some(_) => Err(format!("CMW member '{label}' is not a {media_type} record")),
        None => Err(format!("CMW collection has no '{label}' member")),
    }
}

/// Returns `true` if `report_data` equals `binding`, or starts with it and is zero-padded.
pub fn is_bound_to(report_data: &[u8], binding: &[u8]) -> bool {
    report_data.len() >= binding.len()
        && report_data[..binding.len()] == *binding
        && report_data[binding.len()..].iter().all(|b| *b == 0)
}

/// Signature algorithms accepted when validating vendor certificate chains.
fn chain_algorithms() -> &'static [&'static dyn SignatureVerificationAlgorithm] {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .all
}

/// Verifies a fixed-size (`r || s`) ECDSA `signature` over `message` with the uncompressed
/// point `public_key`.
fn verify_ecdsa(
    alg: &'static ring::signature::EcdsaVerificationAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ()> {
    ring::signature::UnparsedPublicKey::new(alg, public_key)
        .verify(message, signature)
        .map_err(|_| ())
}

/// Returns the `len` bytes at `offset` as an owned vector. Callers check the buffer length.
fn field(buf: &[u8], offset: usize, len: usize) -> Vec<u8> {
    buf[offset..offset + len].to_vec()
}

/// Reads a little-endian `u64` at `offset`. Callers check the buffer length.
fn le_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().expect("8-byte slice"))
}

/// EKU policy for vendor attestation chains: they sign evidence, not TLS sessions, so no
/// particular Extended Key Usage is required.
struct AnyKeyUsage;

/// Accepts any (well-formed) Extended Key Usage extension.
impl webpki::ExtendedKeyUsageValidator for AnyKeyUsage {
    /// Only rejects a malformed EKU extension.
    fn validate(&self, iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for eku in iter {
            eku?;
        }
        Ok(())
    }
}
