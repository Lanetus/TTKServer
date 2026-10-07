//! Intel TDX and SGX evidence: ECDSA-P256 DCAP quotes (SGX v3, SGX/TDX v4 and v5).
//!
//! Checks performed:
//! 1. the PCK certificate chain embedded in the quote (certification data type 5, PEM or
//!    DER) chains to the pinned Intel SGX Root CA and is valid now;
//! 2. the Quoting Enclave (QE) report is signed by the PCK key, and is not a debug enclave;
//! 3. the QE report's `REPORT_DATA` binds the attestation key: `SHA-256(attestation_key ||
//!    qe_auth_data)` followed by 32 zero bytes;
//! 4. the quote header and body are signed by the attestation key.
//!
//! Not evaluated: TCB status and QE identity against Intel PCS collateral (TCB Info, QE
//! Identity, PCK CRLs). A genuine but out-of-date or revoked platform is therefore accepted.

use super::{
    chain_algorithms, field, le_u64, verify_ecdsa, AnyKeyUsage, TeeKind, TrustStore,
    VerifiedEvidence,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use x509_parser::prelude::*;

const HEADER_LEN: usize = 48;
const SGX_REPORT_BODY_LEN: usize = 384;
const TD10_REPORT_BODY_LEN: usize = 584;
const TD15_REPORT_BODY_LEN: usize = 648;

/// Attestation key type: ECDSA-256-with-P-256 curve.
const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;
/// Header `tee_type` values.
const TEE_TYPE_SGX: u32 = 0x0000_0000;
const TEE_TYPE_TDX: u32 = 0x0000_0081;
/// Quote v5 body types.
const BODY_TYPE_SGX: u16 = 1;
const BODY_TYPE_TD10: u16 = 2;
const BODY_TYPE_TD15: u16 = 3;
/// Certification data types.
const CERT_TYPE_PCK_CHAIN: u16 = 5;
const CERT_TYPE_QE_REPORT: u16 = 6;

/// SGX report body offsets.
const SGX_ATTRIBUTES: usize = 48;
const SGX_MRENCLAVE: usize = 64;
const SGX_MRSIGNER: usize = 128;
const SGX_REPORT_DATA: usize = 320;
/// SGX `ATTRIBUTES.FLAGS` debug bit.
const SGX_FLAG_DEBUG: u64 = 1 << 1;

/// TDX report body offsets.
const TD_MRSEAM: usize = 16;
const TD_ATTRIBUTES: usize = 120;
const TD_MRTD: usize = 136;
const TD_MRCONFIGID: usize = 184;
const TD_MROWNER: usize = 232;
const TD_MROWNERCONFIG: usize = 280;
const TD_RTMR0: usize = 328;
const TD_REPORT_DATA: usize = 520;
/// `TDATTRIBUTES` debug bit.
const TD_ATTRIBUTE_DEBUG: u64 = 1;

/// Verifies the DCAP `quote` produced by `tee` (TDX or SGX) at time `now`.
pub fn verify(
    quote: &[u8],
    tee: TeeKind,
    now: UnixTime,
    trust: &TrustStore,
) -> Result<VerifiedEvidence, String> {
    let parts = QuoteParts::parse(quote, tee)?;

    let pck_leaf = verify_pck_chain(parts.pck_chain, now, trust)?;
    let (_, pck) = X509Certificate::from_der(&pck_leaf)
        .map_err(|e| format!("malformed PCK certificate: {e}"))?;
    verify_ecdsa(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        &pck.public_key().subject_public_key.data,
        parts.qe_report,
        parts.qe_report_signature,
    )
    .map_err(|_| "QE report signature is invalid".to_string())?;
    if le_u64(parts.qe_report, SGX_ATTRIBUTES) & SGX_FLAG_DEBUG != 0 {
        return Err("quote was produced by a debug-mode Quoting Enclave".into());
    }

    let mut hasher = Sha256::new();
    hasher.update(parts.attestation_key);
    hasher.update(parts.qe_auth_data);
    let expected = hasher.finalize();
    let qe_report_data = &parts.qe_report[SGX_REPORT_DATA..SGX_REPORT_DATA + 64];
    if !super::is_bound_to(qe_report_data, &expected) {
        return Err("QE report does not bind the quote's attestation key".into());
    }

    let mut attestation_key = Vec::with_capacity(65);
    attestation_key.push(0x04);
    attestation_key.extend_from_slice(parts.attestation_key);
    verify_ecdsa(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        &attestation_key,
        parts.signed,
        parts.quote_signature,
    )
    .map_err(|_| "quote signature is invalid".to_string())?;

    Ok(match tee {
        TeeKind::Tdx => td_evidence(parts.body),
        _ => sgx_evidence(parts.body),
    })
}

/// Extracts measurements from a TDX report body.
fn td_evidence(body: &[u8]) -> VerifiedEvidence {
    let mut measurements = BTreeMap::from([
        ("mrseam".to_string(), field(body, TD_MRSEAM, 48)),
        ("mrtd".to_string(), field(body, TD_MRTD, 48)),
        ("mrconfigid".to_string(), field(body, TD_MRCONFIGID, 48)),
        ("mrowner".to_string(), field(body, TD_MROWNER, 48)),
        (
            "mrownerconfig".to_string(),
            field(body, TD_MROWNERCONFIG, 48),
        ),
    ]);
    for i in 0..4 {
        measurements.insert(format!("rtmr{i}"), field(body, TD_RTMR0 + 48 * i, 48));
    }
    VerifiedEvidence {
        tee: TeeKind::Tdx,
        report_data: field(body, TD_REPORT_DATA, 64),
        measurements,
        debug: le_u64(body, TD_ATTRIBUTES) & TD_ATTRIBUTE_DEBUG != 0,
        nitro: None,
    }
}

/// Extracts measurements from an SGX report body.
fn sgx_evidence(body: &[u8]) -> VerifiedEvidence {
    VerifiedEvidence {
        tee: TeeKind::Sgx,
        report_data: field(body, SGX_REPORT_DATA, 64),
        measurements: BTreeMap::from([
            ("mrenclave".to_string(), field(body, SGX_MRENCLAVE, 32)),
            ("mrsigner".to_string(), field(body, SGX_MRSIGNER, 32)),
        ]),
        debug: le_u64(body, SGX_ATTRIBUTES) & SGX_FLAG_DEBUG != 0,
        nitro: None,
    }
}

/// Verifies the embedded PCK chain up to the pinned Intel SGX Root CA and returns the DER of
/// the PCK leaf certificate.
///
/// The chain may be PEM (as produced by the Intel quote library) or concatenated DER, in any
/// order; the leaf is the one certificate that is not a CA.
fn verify_pck_chain(data: &[u8], now: UnixTime, trust: &TrustStore) -> Result<Vec<u8>, String> {
    let chain = parse_cert_chain(data)?;
    let leaf_index = chain
        .iter()
        .position(|der| {
            X509Certificate::from_der(der)
                .map(|(_, cert)| !cert.is_ca())
                .unwrap_or(false)
        })
        .ok_or("quote PCK certificate chain has no leaf certificate")?;
    let leaf_der = &chain[leaf_index];
    let intermediates: Vec<CertificateDer<'_>> = chain
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != leaf_index)
        .map(|(_, der)| der.clone())
        .collect();

    let root_der = CertificateDer::from(trust.intel_sgx_root.as_slice());
    let anchor = webpki::anchor_from_trusted_cert(&root_der)
        .map_err(|e| format!("invalid Intel SGX root certificate: {e:?}"))?;
    let leaf = webpki::EndEntityCert::try_from(leaf_der)
        .map_err(|e| format!("invalid PCK certificate: {e:?}"))?;
    leaf.verify_for_usage(
        chain_algorithms(),
        &[anchor],
        &intermediates,
        now,
        AnyKeyUsage,
        None,
        None,
    )
    .map_err(|e| format!("PCK certificate chain is invalid: {e:?}"))?;
    Ok(leaf_der.to_vec())
}

/// Splits PCK certification data (PEM or concatenated DER, optionally NUL-terminated) into
/// DER certificates.
fn parse_cert_chain(data: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let data = match data.iter().rposition(|b| *b != 0) {
        Some(end) => &data[..=end],
        None => return Err("quote PCK certificate chain is empty".into()),
    };
    if data.starts_with(b"-----BEGIN") {
        return CertificateDer::pem_slice_iter(data)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("malformed PCK certificate chain: {e:?}"));
    }
    let mut chain = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (remaining, _) = X509Certificate::from_der(rest)
            .map_err(|e| format!("malformed PCK certificate chain: {e}"))?;
        let len = rest.len() - remaining.len();
        chain.push(CertificateDer::from(rest[..len].to_vec()));
        rest = remaining;
    }
    Ok(chain)
}

/// Borrowed views into a parsed DCAP quote.
struct QuoteParts<'a> {
    /// Header and body bytes covered by the quote signature.
    signed: &'a [u8],
    /// The TD or SGX report body.
    body: &'a [u8],
    quote_signature: &'a [u8],
    /// Raw P-256 public key (`x || y`).
    attestation_key: &'a [u8],
    qe_report: &'a [u8],
    qe_report_signature: &'a [u8],
    qe_auth_data: &'a [u8],
    pck_chain: &'a [u8],
}

/// Parsing of the quote layout.
impl<'a> QuoteParts<'a> {
    /// Splits `quote` into its parts, checking that it is an ECDSA-P256 quote from `tee`.
    fn parse(quote: &'a [u8], tee: TeeKind) -> Result<Self, String> {
        let mut r = Reader::new(quote);
        let header = r.take(HEADER_LEN)?;
        let version = u16::from_le_bytes([header[0], header[1]]);
        let att_key_type = u16::from_le_bytes([header[2], header[3]]);
        let tee_type = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);

        if att_key_type != ATT_KEY_TYPE_ECDSA_P256 {
            return Err(format!(
                "unsupported quote attestation key type {att_key_type}"
            ));
        }
        let expected_tee_type = if tee == TeeKind::Tdx {
            TEE_TYPE_TDX
        } else {
            TEE_TYPE_SGX
        };
        if tee_type != expected_tee_type {
            return Err(format!(
                "quote TEE type {tee_type:#x} does not match {tee} evidence"
            ));
        }

        let body = match (version, tee) {
            (3, TeeKind::Sgx) | (4, TeeKind::Sgx) => r.take(SGX_REPORT_BODY_LEN)?,
            (4, TeeKind::Tdx) => r.take(TD10_REPORT_BODY_LEN)?,
            (5, _) => {
                let body_type = r.u16()?;
                let body_len = r.u32()? as usize;
                let expected_len = match (body_type, tee) {
                    (BODY_TYPE_SGX, TeeKind::Sgx) => SGX_REPORT_BODY_LEN,
                    (BODY_TYPE_TD10, TeeKind::Tdx) => TD10_REPORT_BODY_LEN,
                    (BODY_TYPE_TD15, TeeKind::Tdx) => TD15_REPORT_BODY_LEN,
                    _ => {
                        return Err(format!(
                            "unsupported quote v5 body type {body_type} for {tee}"
                        ))
                    }
                };
                if body_len != expected_len {
                    return Err(format!(
                        "quote v5 body is {body_len} bytes, expected {expected_len}"
                    ));
                }
                r.take(body_len)?
            }
            _ => return Err(format!("unsupported {tee} quote version {version}")),
        };
        let signed = &quote[..r.pos];

        let signature_data_len = r.u32()? as usize;
        let mut s = Reader::new(r.take(signature_data_len)?);
        let quote_signature = s.take(64)?;
        let attestation_key = s.take(64)?;

        // v3 stores the QE certification data inline; v4/v5 wrap it as certification data type 6.
        let mut qe = if version == 3 {
            s
        } else {
            let cert_type = s.u16()?;
            if cert_type != CERT_TYPE_QE_REPORT {
                return Err(format!(
                    "unsupported quote certification data type {cert_type}"
                ));
            }
            let len = s.u32()? as usize;
            Reader::new(s.take(len)?)
        };
        let qe_report = qe.take(SGX_REPORT_BODY_LEN)?;
        let qe_report_signature = qe.take(64)?;
        let auth_len = qe.u16()? as usize;
        let qe_auth_data = qe.take(auth_len)?;
        let cert_type = qe.u16()?;
        if cert_type != CERT_TYPE_PCK_CHAIN {
            return Err(format!(
                "quote does not embed a PCK certificate chain (certification data type {cert_type})"
            ));
        }
        let pck_len = qe.u32()? as usize;
        let pck_chain = qe.take(pck_len)?;

        Ok(Self {
            signed,
            body,
            quote_signature,
            attestation_key,
            qe_report,
            qe_report_signature,
            qe_auth_data,
            pck_chain,
        })
    }
}

/// Bounds-checked little-endian cursor over a byte slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

/// Sequential reads that fail instead of panicking on truncated input.
impl<'a> Reader<'a> {
    /// Starts reading at the beginning of `buf`.
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns the next `len` bytes.
    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.buf.len())
            .ok_or("quote is truncated")?;
        let bytes = &self.buf[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    /// Reads a little-endian `u16`.
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("2-byte slice"),
        ))
    }

    /// Reads a little-endian `u32`.
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4-byte slice"),
        ))
    }
}
