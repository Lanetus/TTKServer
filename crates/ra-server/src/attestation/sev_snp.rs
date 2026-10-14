//! AMD SEV-SNP provider: obtains an attestation report and the chip's VCEK certificate through
//! the Linux configfs-tsm interface.
//!
//! Inside an SEV-SNP guest, Linux 6.7+ exposes `/sys/kernel/config/tsm/report` (see
//! [`super::tsm`]). Writing the 64-byte `REPORT_DATA` to an entry's `inblob` and reading
//! `outblob` returns the report signed by the AMD Secure Processor; `auxblob` returns the
//! certificate table the host attached to the extended report, which normally holds the key
//! that signed the report: the chip's VCEK (Versioned Chip Endorsement Key), or, on clouds that
//! sign with a VLEK (Versioned Loaded Endorsement Key, e.g. AWS EC2), the VLEK. The report's
//! `SIGNING_KEY` flags say which one is expected.
//!
//! If the host does not supply certificates, the key must be provided out of band: set
//! `TTK_SEV_SNP_VCEK` to the VCEK (or, for VLEK-signed reports, VLEK) certificate (DER or PEM),
//! e.g. fetched from the AMD Key Distribution Service for this chip and TCB.
//!
//! The report and its endorsement key certificate (VCEK or VLEK, in the `vcek` member) are
//! wrapped as a CMW collection of type
//! `media_type::SEV_SNP_COLLECTION` (`{"report": Evidence record, "vcek": Endorsement record}`),
//! which the client's
//! `ttk_ra_client::verifier::sev_snp` verifies them.

use super::cmw::{self, CmwCollection, CmwRecord};
use super::media_type;
use super::tsm::{self, TsmRoot};
use super::{AttestationError, AttestationProvider};
use crate::{AttestationParams, Cmw};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use std::path::{Path, PathBuf};

pub use super::tsm::{report_data, CONFIGFS_TSM_REPORT, REPORT_DATA_LEN};

/// Path of the AMD SEV-SNP guest device used for detection.
const DEVICE: &str = "/dev/sev-guest";

/// Value of an entry's `provider` attribute when the SEV-SNP guest driver serves it.
const TSM_PROVIDER_SEV: &str = "sev_guest";

/// Environment variable naming the VCEK (or, for VLEK-signed reports, VLEK) certificate file,
/// used when the host supplies none.
pub const VCEK_ENV: &str = "TTK_SEV_SNP_VCEK";

/// `ATTESTATION_REPORT` layout (SEV-SNP ABI specification).
const REPORT_LEN: usize = 0x4A0;
const OFFSET_FLAGS: usize = 0x48;
const OFFSET_REPORT_DATA: usize = 0x50;

/// VCEK GUID in the extended-report certificate table: 63da758d-e664-4564-adc5-f4b93be8accd.
const VCEK_GUID: [u8; 16] = [
    0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];

/// VLEK GUID in the extended-report certificate table: a8074bc2-a25a-483e-aae6-39c045a0b8a1.
const VLEK_GUID: [u8; 16] = [
    0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1,
];

/// Key that signed an SEV-SNP report (`FLAGS.SIGNING_KEY`, bits 4:2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKey {
    /// Versioned Chip Endorsement Key, derived from the chip's secrets (value 0).
    Vcek,
    /// Versioned Loaded Endorsement Key, provisioned by a cloud provider (value 1).
    Vlek,
}

/// Decoding of the `SIGNING_KEY` field.
impl SigningKey {
    /// Reads `SIGNING_KEY` from the report `FLAGS`; `None` for an unsigned report (7) or a
    /// reserved value.
    pub fn from_flags(flags: u32) -> Option<Self> {
        match (flags >> 2) & 0b111 {
            0 => Some(Self::Vcek),
            1 => Some(Self::Vlek),
            _ => None,
        }
    }

    /// `"VCEK"` or `"VLEK"`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Vcek => "VCEK",
            Self::Vlek => "VLEK",
        }
    }
}

/// Size of one certificate table entry: GUID (16), offset (u32), length (u32).
const CERT_TABLE_ENTRY_LEN: usize = 24;

/// Session with the configfs-tsm report interface of an AMD SEV-SNP guest.
#[derive(Debug)]
pub struct SevSnpSession {
    tsm: TsmRoot,
    vcek: Option<Vec<u8>>,
}

/// Evidence for one request: the signed report and the VCEK that signed it.
#[derive(Debug, Clone)]
pub struct SevSnpEvidence {
    /// The raw 1184-byte `ATTESTATION_REPORT`.
    pub report: Vec<u8>,
    /// DER-encoded certificate of the key that signed the report: the VCEK, or the VLEK for
    /// VLEK-signed reports.
    pub vcek: Vec<u8>,
}

/// Construction and evidence retrieval.
impl SevSnpSession {
    /// Opens the provider at the default configfs-tsm location, loading the VCEK named by
    /// `TTK_SEV_SNP_VCEK` if set.
    pub fn open() -> Result<Self, AttestationError> {
        let session = Self::open_at(CONFIGFS_TSM_REPORT)?;
        match std::env::var_os(VCEK_ENV) {
            Some(path) => session.with_vcek_file(path),
            None => Ok(session),
        }
    }

    /// Opens the provider with the configfs-tsm report interface at `report_root`.
    pub fn open_at(report_root: impl Into<PathBuf>) -> Result<Self, AttestationError> {
        Ok(Self {
            tsm: TsmRoot::open_at(report_root, "an SEV-SNP")?,
            vcek: None,
        })
    }

    /// Uses the VCEK or VLEK certificate (DER or PEM) in the file at `path` instead of the
    /// certificate the host attaches to the report.
    pub fn with_vcek_file(self, path: impl AsRef<Path>) -> Result<Self, AttestationError> {
        let path = path.as_ref();
        let vcek = std::fs::read(path).map_err(|e| {
            AttestationError::InvalidInput(format!(
                "failed to read the VCEK certificate {}: {e}",
                path.display()
            ))
        })?;
        self.with_vcek(&vcek)
    }

    /// Uses `vcek`, a VCEK or VLEK certificate (DER or PEM), instead of the certificate the host
    /// attaches to the report.
    pub fn with_vcek(mut self, vcek: &[u8]) -> Result<Self, AttestationError> {
        self.vcek = Some(parse_certificate(vcek)?);
        Ok(self)
    }

    /// Requests an SEV-SNP report whose `REPORT_DATA` is `report_data`.
    pub fn get_evidence(
        &self,
        report_data: &[u8; REPORT_DATA_LEN],
    ) -> Result<SevSnpEvidence, AttestationError> {
        let response = self.tsm.request(TSM_PROVIDER_SEV, report_data, true)?;
        evidence_from_response(response, report_data, self.vcek.as_deref())
    }
}

/// AMD SEV-SNP implementation of [`AttestationProvider`].
impl AttestationProvider for SevSnpSession {
    /// Returns `"sev-snp"`.
    fn name(&self) -> &'static str {
        "sev-snp"
    }

    /// Returns `true` if `/dev/sev-guest` exists.
    fn is_available() -> bool {
        Path::new(DEVICE).exists()
    }

    /// Obtains an SEV-SNP report binding `params.user_data` and wraps it with its VCEK as an
    /// CMW.
    fn generate_document(&self, params: &AttestationParams) -> Result<Cmw, AttestationError> {
        let evidence = self.get_evidence(&report_data(params)?)?;
        Ok(wrap_evidence_as_cmw(evidence))
    }
}

/// Reads a report from an existing configfs-tsm `entry` directory for `report_data`.
///
/// The VCEK (or, for a VLEK-signed report, the VLEK) is taken from the entry's certificate table
/// (`auxblob`), unless `vcek` (DER) is given. Checks that the entry is served by the SEV-SNP
/// guest driver, that no concurrent writer changed the request, and that the report carries
/// `report_data` and is signed by a VCEK or VLEK.
pub fn evidence_from_entry(
    entry: &Path,
    report_data: &[u8; REPORT_DATA_LEN],
    vcek: Option<&[u8]>,
) -> Result<SevSnpEvidence, AttestationError> {
    let response = tsm::request_in_entry(entry, TSM_PROVIDER_SEV, report_data, vcek.is_none())?;
    evidence_from_response(response, report_data, vcek)
}

/// Checks the report in `response` and pairs it with the certificate of its signing key.
fn evidence_from_response(
    response: tsm::TsmReport,
    report_data: &[u8; REPORT_DATA_LEN],
    vcek: Option<&[u8]>,
) -> Result<SevSnpEvidence, AttestationError> {
    let report = response.outblob;
    let signing_key = check_report(&report, report_data)?;

    let vcek = match vcek {
        Some(vcek) => vcek.to_vec(),
        None => response
            .auxblob
            .as_deref()
            .map(|table| match signing_key {
                SigningKey::Vcek => vcek_from_cert_table(table),
                SigningKey::Vlek => vlek_from_cert_table(table),
            })
            .transpose()?
            .flatten()
            .ok_or_else(|| {
                let key = signing_key.name();
                AttestationError::UnexpectedResponse(format!(
                    "the host did not attach a {key} certificate to the SEV-SNP report; set \
                     {VCEK_ENV} to the {key} certificate (AMD Key Distribution Service)"
                ))
            })?,
    };
    Ok(SevSnpEvidence { report, vcek })
}

/// Checks that `report` is an SEV-SNP report signed by a VCEK or VLEK whose `REPORT_DATA` is
/// `report_data`, and returns its signing key.
fn check_report(
    report: &[u8],
    report_data: &[u8; REPORT_DATA_LEN],
) -> Result<SigningKey, AttestationError> {
    if report.len() != REPORT_LEN {
        return Err(AttestationError::DocumentDecodingFailed(format!(
            "SEV-SNP report is {} bytes, expected {REPORT_LEN}",
            report.len()
        )));
    }
    if report[OFFSET_REPORT_DATA..OFFSET_REPORT_DATA + REPORT_DATA_LEN] != *report_data {
        return Err(AttestationError::UnexpectedResponse(
            "SEV-SNP report does not carry the requested REPORT_DATA".into(),
        ));
    }
    let flags = u32::from_le_bytes(
        report[OFFSET_FLAGS..OFFSET_FLAGS + 4]
            .try_into()
            .expect("4-byte slice"),
    );
    SigningKey::from_flags(flags).ok_or_else(|| {
        AttestationError::Unsupported(
            "SEV-SNP report is not signed by a VCEK or VLEK, which the client requires".into(),
        )
    })
}

/// Finds the VCEK in an extended-report certificate table (by its GUID).
pub fn vcek_from_cert_table(table: &[u8]) -> Result<Option<Vec<u8>>, AttestationError> {
    cert_from_table(table, &VCEK_GUID)
}

/// Finds the VLEK in an extended-report certificate table (by its GUID).
pub fn vlek_from_cert_table(table: &[u8]) -> Result<Option<Vec<u8>>, AttestationError> {
    cert_from_table(table, &VLEK_GUID)
}

/// Finds the certificate with `guid` in an extended-report certificate table.
///
/// The table is a list of `{guid, offset, length}` entries terminated by an all-zero GUID;
/// offsets are relative to the start of the table. GUIDs are matched in both the RFC 4122 byte
/// order and the little-endian (EFI) layout.
fn cert_from_table(table: &[u8], wanted: &[u8; 16]) -> Result<Option<Vec<u8>>, AttestationError> {
    let malformed = |msg: &str| {
        AttestationError::DocumentDecodingFailed(format!("SEV-SNP certificate table {msg}"))
    };
    let wanted_le = guid_to_le(wanted);
    for entry in table.chunks(CERT_TABLE_ENTRY_LEN) {
        if entry.len() < CERT_TABLE_ENTRY_LEN {
            return Err(malformed("has a truncated entry"));
        }
        let guid = &entry[..16];
        if guid.iter().all(|b| *b == 0) {
            break;
        }
        if guid != wanted && guid != wanted_le {
            continue;
        }
        let offset = u32::from_le_bytes(entry[16..20].try_into().expect("4-byte slice")) as usize;
        let length = u32::from_le_bytes(entry[20..24].try_into().expect("4-byte slice")) as usize;
        let cert = offset
            .checked_add(length)
            .and_then(|end| table.get(offset..end))
            .ok_or_else(|| malformed("points outside the table"))?;
        return parse_certificate(cert).map(Some);
    }
    Ok(None)
}

/// Converts an RFC 4122 GUID to its little-endian (EFI `guid_t`) byte layout.
fn guid_to_le(guid: &[u8; 16]) -> [u8; 16] {
    let mut le = *guid;
    le[0..4].reverse();
    le[4..6].reverse();
    le[6..8].reverse();
    le
}

/// Accepts a certificate as DER or PEM and returns its DER encoding.
fn parse_certificate(bytes: &[u8]) -> Result<Vec<u8>, AttestationError> {
    let der = if bytes.starts_with(b"-----BEGIN") {
        CertificateDer::from_pem_slice(bytes)
            .map_err(|e| AttestationError::InvalidInput(format!("invalid VCEK/VLEK PEM: {e:?}")))?
            .to_vec()
    } else {
        // Certificate table entries may be zero-padded after the DER structure.
        let (rest, _) = x509_parser::parse_x509_certificate(bytes).map_err(|e| {
            AttestationError::InvalidInput(format!("invalid VCEK/VLEK certificate: {e}"))
        })?;
        bytes[..bytes.len() - rest.len()].to_vec()
    };
    Ok(der)
}

/// Wraps SEV-SNP `evidence` as a CMW collection of type [`media_type::SEV_SNP_COLLECTION`]:
/// the report as an Evidence record, its VCEK or VLEK certificate as an Endorsement record.
pub fn wrap_evidence_as_cmw(evidence: SevSnpEvidence) -> Cmw {
    Cmw::Collection(CmwCollection {
        collection_type: Some(media_type::SEV_SNP_COLLECTION.to_string()),
        entries: vec![
            (
                media_type::SEV_SNP_REPORT_LABEL.to_string(),
                Cmw::evidence(media_type::SEV_SNP_REPORT, evidence.report),
            ),
            (
                media_type::SEV_SNP_VCEK_LABEL.to_string(),
                Cmw::Record(CmwRecord::new(
                    media_type::PKIX_CERT,
                    evidence.vcek,
                    cmw::ind::ENDORSEMENTS,
                )),
            ),
        ],
    })
}
