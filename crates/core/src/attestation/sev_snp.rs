//! AMD SEV-SNP provider: obtains an attestation report and the chip's VCEK certificate through
//! the Linux configfs-tsm interface.
//!
//! Inside an SEV-SNP guest, Linux 6.7+ exposes `/sys/kernel/config/tsm/report` (see
//! [`super::tsm`]). Writing the 64-byte `REPORT_DATA` to an entry's `inblob` and reading
//! `outblob` returns the report signed by the AMD Secure Processor; `auxblob` returns the
//! certificate table the host attached to the extended report, which normally holds the VCEK.
//!
//! If the host does not supply certificates, the VCEK must be provided out of band: set
//! `TTK_SEV_SNP_VCEK` to a VCEK certificate (DER or PEM) fetched from the AMD Key Distribution
//! Service for this chip and TCB.
//!
//! The report and VCEK are embedded in the EAT under the `sev_snp` submodule as
//! `{"report": bstr, "vcek": bstr}`, where the client's
//! `ttk_client::verifier::sev_snp` verifies them.

use super::submod;
use super::tsm::{self, TsmRoot};
use super::{AttestationError, AttestationProvider};
use crate::{AttestationParams, EatClaimsSet};
use ciborium::Value;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub use super::tsm::{report_data, CONFIGFS_TSM_REPORT, REPORT_DATA_LEN};

/// Path of the AMD SEV-SNP guest device used for detection.
const DEVICE: &str = "/dev/sev-guest";

/// Value of an entry's `provider` attribute when the SEV-SNP guest driver serves it.
const TSM_PROVIDER_SEV: &str = "sev_guest";

/// Environment variable naming a VCEK certificate file, used when the host supplies none.
pub const VCEK_ENV: &str = "TTK_SEV_SNP_VCEK";

/// Private EAT profile identifier (RFC 4151 tag URI) for an SEV-SNP report nested in an EAT.
/// Not IANA-registered.
const EAT_PROFILE: &str = "tag:lanetus.github.io,2026:sev-snp-nested-eat";

/// `ATTESTATION_REPORT` layout (SEV-SNP ABI specification).
const REPORT_LEN: usize = 0x4A0;
const OFFSET_FLAGS: usize = 0x48;
const OFFSET_REPORT_DATA: usize = 0x50;

/// VCEK GUID in the extended-report certificate table: 63da758d-e664-4564-adc5-f4b93be8accd.
const VCEK_GUID: [u8; 16] = [
    0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];

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
    /// DER-encoded VCEK certificate.
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

    /// Uses the VCEK certificate (DER or PEM) in the file at `path` instead of the certificate the
    /// host attaches to the report.
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

    /// Uses `vcek` (DER or PEM) instead of the certificate the host attaches to the report.
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
    /// EAT claims-set.
    fn generate_document(
        &self,
        params: &AttestationParams,
    ) -> Result<EatClaimsSet, AttestationError> {
        let evidence = self.get_evidence(&report_data(params)?)?;
        Ok(wrap_evidence_as_eat(&evidence))
    }
}

/// Reads a report from an existing configfs-tsm `entry` directory for `report_data`.
///
/// The VCEK is taken from the entry's certificate table (`auxblob`), unless `vcek` (DER) is
/// given. Checks that the entry is served by the SEV-SNP guest driver, that no concurrent
/// writer changed the request, and that the report carries `report_data` and is VCEK-signed.
pub fn evidence_from_entry(
    entry: &Path,
    report_data: &[u8; REPORT_DATA_LEN],
    vcek: Option<&[u8]>,
) -> Result<SevSnpEvidence, AttestationError> {
    let response = tsm::request_in_entry(entry, TSM_PROVIDER_SEV, report_data, vcek.is_none())?;
    evidence_from_response(response, report_data, vcek)
}

/// Checks the report in `response` and pairs it with its VCEK.
fn evidence_from_response(
    response: tsm::TsmReport,
    report_data: &[u8; REPORT_DATA_LEN],
    vcek: Option<&[u8]>,
) -> Result<SevSnpEvidence, AttestationError> {
    let report = response.outblob;
    check_report(&report, report_data)?;

    let vcek = match vcek {
        Some(vcek) => vcek.to_vec(),
        None => response
            .auxblob
            .as_deref()
            .map(vcek_from_cert_table)
            .transpose()?
            .flatten()
            .ok_or_else(|| {
                AttestationError::UnexpectedResponse(format!(
                    "the host did not attach a VCEK certificate to the SEV-SNP report; set \
                     {VCEK_ENV} to this chip's VCEK from the AMD Key Distribution Service"
                ))
            })?,
    };
    Ok(SevSnpEvidence { report, vcek })
}

/// Checks that `report` is a VCEK-signed SEV-SNP report whose `REPORT_DATA` is `report_data`.
fn check_report(
    report: &[u8],
    report_data: &[u8; REPORT_DATA_LEN],
) -> Result<(), AttestationError> {
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
    if (flags >> 2) & 0b111 != 0 {
        return Err(AttestationError::Unsupported(
            "SEV-SNP report is signed by a VLEK, which the client does not support".into(),
        ));
    }
    Ok(())
}

/// Finds the VCEK in an extended-report certificate table.
///
/// The table is a list of `{guid, offset, length}` entries terminated by an all-zero GUID;
/// offsets are relative to the start of the table. GUIDs are matched in both the RFC 4122 byte
/// order and the little-endian (EFI) layout.
pub fn vcek_from_cert_table(table: &[u8]) -> Result<Option<Vec<u8>>, AttestationError> {
    let malformed = |msg: &str| {
        AttestationError::DocumentDecodingFailed(format!("SEV-SNP certificate table {msg}"))
    };
    let vcek_guid_le = guid_to_le(&VCEK_GUID);
    for entry in table.chunks(CERT_TABLE_ENTRY_LEN) {
        if entry.len() < CERT_TABLE_ENTRY_LEN {
            return Err(malformed("has a truncated entry"));
        }
        let guid = &entry[..16];
        if guid.iter().all(|b| *b == 0) {
            break;
        }
        if guid != VCEK_GUID && guid != vcek_guid_le {
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
            .map_err(|e| AttestationError::InvalidInput(format!("invalid VCEK PEM: {e:?}")))?
            .to_vec()
    } else {
        // Certificate table entries may be zero-padded after the DER structure.
        let (rest, _) = x509_parser::parse_x509_certificate(bytes).map_err(|e| {
            AttestationError::InvalidInput(format!("invalid VCEK certificate: {e}"))
        })?;
        bytes[..bytes.len() - rest.len()].to_vec()
    };
    Ok(der)
}

/// Wraps SEV-SNP `evidence` as an RFC 9711 EAT claims-set, nested under the `sev_snp` submodule
/// as `{"report": bstr, "vcek": bstr}`.
///
/// Trust comes from the nested report; `iat` is the local time the report was obtained.
pub fn wrap_evidence_as_eat(evidence: &SevSnpEvidence) -> EatClaimsSet {
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    EatClaimsSet {
        iat: Some(iat),
        eat_profile: Some(EAT_PROFILE.to_string()),
        submods: Some(Value::Map(vec![(
            Value::Text(submod::SEV_SNP.to_string()),
            Value::Map(vec![
                (
                    Value::Text("report".into()),
                    Value::Bytes(evidence.report.clone()),
                ),
                (
                    Value::Text("vcek".into()),
                    Value::Bytes(evidence.vcek.clone()),
                ),
            ]),
        )])),
        ..EatClaimsSet::default()
    }
}
