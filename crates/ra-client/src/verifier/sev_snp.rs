//! AMD SEV-SNP evidence: an attestation report signed either by the chip's VCEK (Versioned Chip
//! Endorsement Key), whose certificate chains through the ASK to the AMD Root Key (ARK) of the
//! processor family, or by a VLEK (Versioned Loaded Endorsement Key, which cloud providers such
//! as AWS EC2 load into their chips), whose certificate chains through the ASVK to the ARK.
//!
//! The evidence is the raw 1184-byte report (SEV-SNP ABI spec, `ATTESTATION_REPORT`) and the
//! DER-encoded VCEK or VLEK certificate as served by the AMD Key Distribution Service, carried as
//! the `report` and `vcek` records of a CMW collection (see [`super::media_type`]). The report's
//! `SIGNING_KEY` flags select which of the two it is. The ARK, ASK and ASVK are pinned in the
//! trust store.
//!
//! Checks: ARK → ASK → VCEK or ARK → ASVK → VLEK chain (RSA-PSS), validity periods, the VCEK's
//! `hwID` (VLEKs are not chip-specific) and the TCB extensions match the report, and the
//! report's ECDSA P-384 signature. Revocation (CRL) checks are not supported.
//!
//! The guest policy is chosen by the host at launch and is not part of the measurement, so it is
//! checked here: a guest that allows a migration agent (`MIGRATE_MA`, which can export its
//! memory) is rejected, as is a report requested from a VMPL other than 0 (the guest's most
//! privileged level; otherwise a more privileged component could have shaped it). The debug bit
//! is reported as [`VerifiedEvidence::debug`] and left to the verifier's policy.

use super::{field, le_u64, verify_ecdsa, TeeKind, TrustStore, VerifiedEvidence};
use rustls_pki_types::UnixTime;
use std::collections::BTreeMap;
use x509_parser::prelude::*;

/// Size of an `ATTESTATION_REPORT` structure.
const REPORT_LEN: usize = 0x4A0;
/// The report is signed over bytes `0..SIGNED_LEN`; the signature follows.
const SIGNED_LEN: usize = 0x2A0;

const OFFSET_VERSION: usize = 0x00;
const OFFSET_POLICY: usize = 0x08;
const OFFSET_VMPL: usize = 0x30;
const OFFSET_SIGNATURE_ALGO: usize = 0x34;
const OFFSET_FLAGS: usize = 0x48;
const OFFSET_REPORT_DATA: usize = 0x50;
const OFFSET_MEASUREMENT: usize = 0x90;
const OFFSET_HOST_DATA: usize = 0xC0;
const OFFSET_ID_KEY_DIGEST: usize = 0xE0;
const OFFSET_AUTHOR_KEY_DIGEST: usize = 0x110;
const OFFSET_REPORTED_TCB: usize = 0x180;
const OFFSET_CHIP_ID: usize = 0x1A0;

/// `SIGNATURE_ALGO` value for ECDSA P-384 with SHA-384.
const SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;
/// Guest policy bit that must be one (reserved, "must be one" in the SEV-SNP ABI).
const POLICY_RESERVED_MBO: u64 = 1 << 17;
/// Guest policy bit allowing a migration agent, which can export the guest's memory.
const POLICY_MIGRATE_MA: u64 = 1 << 18;
/// Guest policy bit allowing the hypervisor to debug the guest.
const POLICY_DEBUG: u64 = 1 << 19;
/// The only VMPL a report is accepted from: the guest's most privileged level.
const REQUIRED_VMPL: u32 = 0;
/// `FLAGS` bit set when the chip ID is masked (all zeros) in the report.
const FLAG_MASK_CHIP_ID: u32 = 1 << 1;

/// VCEK extension OIDs (AMD "Versioned Chip Endorsement Key" specification).
const OID_BL_SPL: &str = "1.3.6.1.4.1.3704.1.3.1";
const OID_TEE_SPL: &str = "1.3.6.1.4.1.3704.1.3.2";
const OID_SNP_SPL: &str = "1.3.6.1.4.1.3704.1.3.3";
const OID_UCODE_SPL: &str = "1.3.6.1.4.1.3704.1.3.8";
const OID_FMC_SPL: &str = "1.3.6.1.4.1.3704.1.3.9";
const OID_HW_ID: &str = "1.3.6.1.4.1.3704.1.4";

/// AMD processor families and their pinned roots (defined in [`crate::trust`]).
pub use crate::trust::{AmdProduct, AmdRoots};

/// Verifies the SEV-SNP `report` and the DER certificate `vcek_der` of its signing key (the VCEK,
/// or the VLEK for VLEK-signed reports) at time `now`.
pub fn verify(
    report: &[u8],
    vcek_der: &[u8],
    now: UnixTime,
    trust: &TrustStore,
) -> Result<VerifiedEvidence, String> {
    if report.len() != REPORT_LEN {
        return Err(format!(
            "SEV-SNP report is {} bytes, expected {REPORT_LEN}",
            report.len()
        ));
    }
    let version = le_u32(report, OFFSET_VERSION);
    if version < 2 {
        return Err(format!("unsupported SEV-SNP report version {version}"));
    }
    if le_u32(report, OFFSET_SIGNATURE_ALGO) != SIG_ALGO_ECDSA_P384_SHA384 {
        return Err("SEV-SNP report is not signed with ECDSA P-384".into());
    }
    let policy = le_u64(report, OFFSET_POLICY);
    if policy & POLICY_RESERVED_MBO == 0 {
        return Err("SEV-SNP guest policy is malformed (reserved bit 17 is clear)".into());
    }
    if policy & POLICY_MIGRATE_MA != 0 {
        return Err("SEV-SNP guest policy allows a migration agent (MIGRATE_MA)".into());
    }
    let vmpl = le_u32(report, OFFSET_VMPL);
    if vmpl != REQUIRED_VMPL {
        return Err(format!(
            "SEV-SNP report was requested from VMPL {vmpl}, expected {REQUIRED_VMPL}"
        ));
    }
    let flags = le_u32(report, OFFSET_FLAGS);
    let signing_key = match (flags >> 2) & 0b111 {
        0 => SigningKey::Vcek,
        1 => SigningKey::Vlek,
        _ => return Err("SEV-SNP report is not signed by a VCEK or VLEK".into()),
    };

    let (_, vcek) = X509Certificate::from_der(vcek_der)
        .map_err(|e| format!("malformed SEV-SNP {signing_key} certificate: {e}"))?;
    let product = verify_vcek_chain(&vcek, signing_key, now, trust)?;
    check_vcek_matches_report(
        &vcek,
        signing_key,
        report,
        product,
        flags & FLAG_MASK_CHIP_ID != 0,
    )?;
    verify_report_signature(&vcek, signing_key, report)?;

    let measurements = BTreeMap::from([
        (
            "measurement".to_string(),
            field(report, OFFSET_MEASUREMENT, 48),
        ),
        ("host_data".to_string(), field(report, OFFSET_HOST_DATA, 32)),
        (
            "id_key_digest".to_string(),
            field(report, OFFSET_ID_KEY_DIGEST, 48),
        ),
        (
            "author_key_digest".to_string(),
            field(report, OFFSET_AUTHOR_KEY_DIGEST, 48),
        ),
    ]);

    Ok(VerifiedEvidence {
        tee: TeeKind::SevSnp,
        report_data: field(report, OFFSET_REPORT_DATA, 64),
        measurements,
        debug: policy & POLICY_DEBUG != 0,
        mock: false,
        nitro: None,
    })
}

/// Reads a little-endian `u32` at `offset`. Callers check the buffer length.
fn le_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("4-byte slice"))
}

/// Key that signed an SEV-SNP report (`FLAGS.SIGNING_KEY`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SigningKey {
    /// Versioned Chip Endorsement Key, certified by the ASK.
    Vcek,
    /// Versioned Loaded Endorsement Key, certified by the ASVK.
    Vlek,
}

/// Displays `VCEK` or `VLEK`.
impl std::fmt::Display for SigningKey {
    /// Writes the key's acronym.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Vcek => "VCEK",
            Self::Vlek => "VLEK",
        })
    }
}

/// Finds the pinned ARK and intermediate (ASK for a VCEK, ASVK for a VLEK) that signed `vcek`
/// and checks the chain at time `now`.
fn verify_vcek_chain(
    vcek: &X509Certificate<'_>,
    signing_key: SigningKey,
    now: UnixTime,
    trust: &TrustStore,
) -> Result<AmdProduct, String> {
    let intermediate_name = match signing_key {
        SigningKey::Vcek => "ASK",
        SigningKey::Vlek => "ASVK",
    };
    for roots in &trust.amd {
        let (_, ark) = X509Certificate::from_der(&roots.ark)
            .map_err(|e| format!("malformed pinned AMD ARK: {e}"))?;
        let intermediate = match signing_key {
            SigningKey::Vcek => &roots.ask,
            SigningKey::Vlek => &roots.asvk,
        };
        let (_, ask) = X509Certificate::from_der(intermediate)
            .map_err(|e| format!("malformed pinned AMD {intermediate_name}: {e}"))?;
        if vcek.verify_signature(Some(ask.public_key())).is_err() {
            continue;
        }
        ark.verify_signature(None)
            .map_err(|_| format!("pinned {:?} ARK is not self-signed", roots.product))?;
        ask.verify_signature(Some(ark.public_key())).map_err(|_| {
            format!(
                "pinned {:?} {intermediate_name} is not signed by its ARK",
                roots.product
            )
        })?;
        for cert in [&ark, &ask, vcek] {
            if !cert.validity().is_valid_at(to_asn1_time(now)?) {
                return Err(format!(
                    "SEV-SNP certificate '{}' is outside its validity period",
                    cert.subject()
                ));
            }
        }
        return Ok(roots.product);
    }
    Err(format!(
        "SEV-SNP {signing_key} is not signed by a pinned AMD {intermediate_name}"
    ))
}

/// Converts `now` to an ASN.1 time for certificate validity checks.
fn to_asn1_time(now: UnixTime) -> Result<ASN1Time, String> {
    ASN1Time::from_timestamp(now.as_secs() as i64).map_err(|e| format!("invalid time: {e}"))
}

/// Checks that the VCEK was issued for this chip (`hwID`; VLEKs are not chip-specific) and that
/// the VCEK or VLEK was issued for the report's TCB.
fn check_vcek_matches_report(
    vcek: &X509Certificate<'_>,
    signing_key: SigningKey,
    report: &[u8],
    product: AmdProduct,
    chip_id_masked: bool,
) -> Result<(), String> {
    let chip_id = &report[OFFSET_CHIP_ID..OFFSET_CHIP_ID + 64];
    if signing_key == SigningKey::Vcek && !chip_id_masked {
        let hw_id = extension(vcek, OID_HW_ID).ok_or("SEV-SNP VCEK has no hwID extension")?;
        let hw_id = unwrap_octet_string(hw_id);
        // Turin VCEKs carry an 8-byte hardware ID; earlier families the full 64-byte chip ID.
        if hw_id.is_empty() || hw_id.len() > chip_id.len() || chip_id[..hw_id.len()] != *hw_id {
            return Err("SEV-SNP VCEK was not issued for the chip that signed the report".into());
        }
    }

    // REPORTED_TCB layout (SEV-SNP ABI spec, TCB_VERSION): bytes are SPL values.
    let tcb = &report[OFFSET_REPORTED_TCB..OFFSET_REPORTED_TCB + 8];
    let expected: &[(&str, &str, u8)] = match product {
        AmdProduct::Milan | AmdProduct::Genoa => &[
            ("blSPL", OID_BL_SPL, tcb[0]),
            ("teeSPL", OID_TEE_SPL, tcb[1]),
            ("snpSPL", OID_SNP_SPL, tcb[6]),
            ("ucodeSPL", OID_UCODE_SPL, tcb[7]),
        ],
        AmdProduct::Turin => &[
            ("fmcSPL", OID_FMC_SPL, tcb[0]),
            ("blSPL", OID_BL_SPL, tcb[1]),
            ("teeSPL", OID_TEE_SPL, tcb[2]),
            ("snpSPL", OID_SNP_SPL, tcb[3]),
            ("ucodeSPL", OID_UCODE_SPL, tcb[7]),
        ],
    };
    for (name, oid, value) in expected {
        let ext = extension(vcek, oid)
            .ok_or_else(|| format!("SEV-SNP {signing_key} has no {name} extension"))?;
        let (_, int) = der_parser::der::parse_der_integer(ext)
            .map_err(|_| format!("SEV-SNP {signing_key} {name} extension is not an integer"))?;
        let spl = int
            .as_u32()
            .map_err(|_| format!("SEV-SNP {signing_key} {name} extension is out of range"))?;
        if spl != u32::from(*value) {
            return Err(format!(
                "SEV-SNP {signing_key} {name} ({spl}) does not match the report's TCB ({value})"
            ));
        }
    }
    Ok(())
}

/// Returns the raw value of the extension with dotted `oid`, if present.
fn extension<'a>(cert: &'a X509Certificate<'_>, oid: &str) -> Option<&'a [u8]> {
    cert.extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == oid)
        .map(|ext| ext.value)
}

/// Strips a DER OCTET STRING header if `value` is one; otherwise returns it unchanged.
fn unwrap_octet_string(value: &[u8]) -> &[u8] {
    match der_parser::der::parse_der_octetstring(value) {
        Ok(([], obj)) => obj.as_slice().unwrap_or(value),
        _ => value,
    }
}

/// Verifies the report's ECDSA P-384 signature with the VCEK or VLEK public key.
///
/// The signature stores `r` and `s` as 72-byte little-endian integers; ring expects them as
/// 48-byte big-endian values.
fn verify_report_signature(
    vcek: &X509Certificate<'_>,
    signing_key: SigningKey,
    report: &[u8],
) -> Result<(), String> {
    let signature = &report[SIGNED_LEN..SIGNED_LEN + 144];
    let mut fixed = Vec::with_capacity(96);
    for component in [&signature[..72], &signature[72..144]] {
        if component[48..].iter().any(|b| *b != 0) {
            return Err("SEV-SNP report signature component is too large".into());
        }
        fixed.extend(component[..48].iter().rev());
    }
    verify_ecdsa(
        &ring::signature::ECDSA_P384_SHA384_FIXED,
        &vcek.public_key().subject_public_key.data,
        &report[..SIGNED_LEN],
        &fixed,
    )
    .map_err(|_| format!("SEV-SNP report signature is invalid for its {signing_key}"))
}
