//! Intel TDX provider: obtains a DCAP quote for the TD through the Linux configfs-tsm interface.
//!
//! Inside a TDX guest, Linux 6.7+ exposes `/sys/kernel/config/tsm/report` (see [`super::tsm`]).
//! Writing the 64-byte `REPORTDATA` to an entry's `inblob` and reading `outblob` returns a quote
//! signed by the platform's Quoting Enclave; the kernel fetches it from the host's Quote
//! Generation Service.
//!
//! The quote is wrapped as a CMW record of type `media_type::TDX`, which the client's
//! `ttk_ra_client::verifier::dcap` verifies it.

use super::media_type;
use super::tsm::{self, TsmRoot};
use super::{AttestationError, AttestationProvider};
use crate::{AttestationParams, Cmw};
use std::path::{Path, PathBuf};

pub use super::tsm::{report_data, CONFIGFS_TSM_REPORT, REPORT_DATA_LEN};

/// Path of the Intel TDX guest device used for detection.
const DEVICE: &str = "/dev/tdx_guest";

/// Value of an entry's `provider` attribute when the TDX guest driver serves it.
const TSM_PROVIDER_TDX: &str = "tdx_guest";

/// Quote layout offsets (Intel TDX DCAP Quoting Library API, quote v4/v5).
const QUOTE_HEADER_LEN: usize = 48;
const QUOTE_TEE_TYPE_TDX: u32 = 0x81;
const TD_REPORT_DATA_OFFSET: usize = 520;

/// Session with the configfs-tsm report interface of an Intel TDX guest.
#[derive(Debug)]
pub struct TdxSession {
    tsm: TsmRoot,
}

/// Construction and quote retrieval.
impl TdxSession {
    /// Opens the provider at the default configfs-tsm location.
    pub fn open() -> Result<Self, AttestationError> {
        Self::open_at(CONFIGFS_TSM_REPORT)
    }

    /// Opens the provider with the configfs-tsm report interface at `report_root`.
    pub fn open_at(report_root: impl Into<PathBuf>) -> Result<Self, AttestationError> {
        Ok(Self {
            tsm: TsmRoot::open_at(report_root, "a TDX")?,
        })
    }

    /// Requests a TDX quote whose `REPORTDATA` is `report_data`.
    pub fn get_quote(
        &self,
        report_data: &[u8; REPORT_DATA_LEN],
    ) -> Result<Vec<u8>, AttestationError> {
        let quote = self
            .tsm
            .request(TSM_PROVIDER_TDX, report_data, false)?
            .outblob;
        check_quote(&quote, report_data)?;
        Ok(quote)
    }
}

/// Intel TDX implementation of [`AttestationProvider`].
impl AttestationProvider for TdxSession {
    /// Returns `"tdx"`.
    fn name(&self) -> &'static str {
        "tdx"
    }

    /// Returns `true` if `/dev/tdx_guest` exists.
    fn is_available() -> bool {
        Path::new(DEVICE).exists()
    }

    /// Obtains a TDX quote binding `params.user_data` and wraps it as a CMW.
    fn generate_document(&self, params: &AttestationParams) -> Result<Cmw, AttestationError> {
        let quote = self.get_quote(&report_data(params)?)?;
        Ok(wrap_quote_as_cmw(quote))
    }
}

/// Reads a quote from an existing configfs-tsm `entry` directory for `report_data`.
///
/// Checks that the entry is served by the TDX guest driver, that no concurrent writer changed
/// the request, and that the returned quote is a TDX quote carrying `report_data`.
pub fn quote_from_entry(
    entry: &Path,
    report_data: &[u8; REPORT_DATA_LEN],
) -> Result<Vec<u8>, AttestationError> {
    let quote = tsm::request_in_entry(entry, TSM_PROVIDER_TDX, report_data, false)?.outblob;
    check_quote(&quote, report_data)?;
    Ok(quote)
}

/// Checks that `quote` is a TDX quote whose `REPORTDATA` is `report_data`.
fn check_quote(quote: &[u8], report_data: &[u8; REPORT_DATA_LEN]) -> Result<(), AttestationError> {
    let malformed =
        |msg: &str| AttestationError::DocumentDecodingFailed(format!("TDX quote {msg}"));
    let header = quote
        .get(..QUOTE_HEADER_LEN)
        .ok_or_else(|| malformed("is truncated"))?;
    let version = u16::from_le_bytes([header[0], header[1]]);
    let tee_type = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if tee_type != QUOTE_TEE_TYPE_TDX {
        return Err(malformed(&format!(
            "has TEE type {tee_type:#x}, expected TDX"
        )));
    }
    // v5 inserts the body type (u16) and size (u32) before the body.
    let body = match version {
        4 => QUOTE_HEADER_LEN,
        5 => QUOTE_HEADER_LEN + 6,
        _ => return Err(malformed(&format!("has unsupported version {version}"))),
    };
    let offset = body + TD_REPORT_DATA_OFFSET;
    let actual = quote
        .get(offset..offset + REPORT_DATA_LEN)
        .ok_or_else(|| malformed("is truncated"))?;
    if actual != report_data {
        return Err(AttestationError::UnexpectedResponse(
            "TDX quote does not carry the requested REPORTDATA".into(),
        ));
    }
    Ok(())
}

/// Wraps a raw TDX `quote` verbatim as a CMW Evidence record of type
/// [`media_type::TDX`].
pub fn wrap_quote_as_cmw(quote: Vec<u8>) -> Cmw {
    Cmw::evidence(media_type::TDX, quote)
}
