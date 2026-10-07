//! Verification of TEE attestation evidence carried in an RFC 9711 EAT.
//!
//! The server embeds exactly one TEE-specific evidence blob in the EAT `submods` map, under a
//! label from [`submod`]. [`verify_evidence`] dispatches on that label:
//!
//! | Label       | TEE            | Evidence                                   | Verified by   |
//! |-------------|----------------|--------------------------------------------|---------------|
//! | `aws_nitro` | AWS Nitro      | NSM attestation document (COSE_Sign1)      | [`nitro`]     |
//! | `sev_snp`   | AMD SEV-SNP    | map `{report, vcek}`: report + VCEK (DER)  | [`sev_snp`]   |
//! | `tdx`       | Intel TDX      | DCAP quote v4/v5 with PCK chain            | [`dcap`]      |
//! | `sgx`       | Intel SGX      | DCAP quote v3/v4/v5 with PCK chain         | [`dcap`]      |
//!
//! Every verifier checks the vendor signature chain up to a root in the [`TrustStore`] and
//! returns a [`VerifiedEvidence`]; the Nitro verifier also requires the enclave image's PCR0 to
//! be in [`TrustStore::nitro_image_allowlist`]. [`verify_evidence`] then enforces the [`Policy`] and checks
//! that the evidence's report data is bound to the expected hash (the SHA-256 of the RA-TLS
//! certificate's public key).

pub mod dcap;
pub mod nitro;
pub mod sev_snp;

use ciborium::Value;
use rustls_pki_types::{SignatureVerificationAlgorithm, UnixTime};
use std::collections::BTreeMap;
use std::fmt;
use ttk_core::eat::EatClaimsSet;

/// EAT `submods` labels identifying the TEE that produced the nested evidence.
pub use ttk_core::attestation::submod;

/// Trust anchors the verifiers check evidence against (defined in [`ttk_core::trust`]).
pub use ttk_core::trust::TrustStore;

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

/// Mapping between TEE kinds and their EAT submodule labels.
impl TeeKind {
    /// Returns the TEE whose evidence is stored under the submodule `label`, if any.
    pub fn from_submod(label: &str) -> Option<Self> {
        match label {
            submod::AWS_NITRO => Some(Self::AwsNitro),
            submod::SEV_SNP => Some(Self::SevSnp),
            submod::TDX => Some(Self::Tdx),
            submod::SGX => Some(Self::Sgx),
            _ => None,
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

/// Verifies the TEE evidence in `eat_bytes` at time `now` and checks that it is bound to
/// `binding`, the SHA-256 of the RA-TLS certificate's public key.
pub fn verify_evidence(
    eat_bytes: &[u8],
    binding: &[u8],
    now: UnixTime,
    trust: &TrustStore,
    policy: Policy,
) -> Result<VerifiedEvidence, String> {
    let claims =
        EatClaimsSet::from_bytes(eat_bytes).map_err(|e| format!("invalid EAT token: {e}"))?;
    let submods = claims.submods.ok_or("EAT token has no submods")?;
    let entries = submods.into_map().map_err(|_| "EAT submods is not a map")?;

    let mut known: Vec<(TeeKind, Value)> = entries
        .into_iter()
        .filter_map(|(label, value)| {
            let tee = TeeKind::from_submod(label.as_text()?)?;
            Some((tee, value))
        })
        .collect();
    let (tee, value) = match known.len() {
        0 => return Err("EAT token contains no supported TEE evidence".into()),
        1 => known.remove(0),
        _ => return Err("EAT token contains evidence from more than one TEE".into()),
    };

    let evidence = match tee {
        TeeKind::AwsNitro => nitro::verify(&bytes_of(value, tee)?, now, trust, policy)?,
        TeeKind::SevSnp => sev_snp::verify(&value, now, trust)?,
        TeeKind::Tdx | TeeKind::Sgx => dcap::verify(&bytes_of(value, tee)?, tee, now, trust)?,
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

/// Unwraps a CBOR byte string holding `tee` evidence.
fn bytes_of(value: Value, tee: TeeKind) -> Result<Vec<u8>, String> {
    value
        .into_bytes()
        .map_err(|_| format!("{tee} evidence is not a byte string"))
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
