//! Intel TDX provider: obtains a DCAP quote for the TD through the Linux configfs-tsm interface.
//!
//! Inside a TDX guest, Linux 6.7+ exposes `/sys/kernel/config/tsm/report` (configfs-tsm, see the
//! kernel's `Documentation/ABI/testing/configfs-tsm`). Creating an entry directory, writing the
//! 64-byte `REPORTDATA` to its `inblob` and reading `outblob` returns a quote signed by the
//! platform's Quoting Enclave; the kernel fetches it from the host's Quote Generation Service.
//!
//! The quote is embedded in the EAT under the `tdx` submodule, where the client's
//! [`verifier::dcap`](crate::verifier::dcap) verifies it.

use super::{AttestationError, AttestationProvider};
use crate::verifier::submod;
use crate::{AttestationParams, EatClaimsSet};
use ciborium::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Path of the Intel TDX guest device used for detection.
const DEVICE: &str = "/dev/tdx_guest";

/// Default location of the configfs-tsm report interface.
pub const CONFIGFS_TSM_REPORT: &str = "/sys/kernel/config/tsm/report";

/// Value of an entry's `provider` attribute when the TDX guest driver serves it.
const TSM_PROVIDER_TDX: &str = "tdx_guest";

/// Size of the TDX `REPORTDATA` field.
pub const REPORT_DATA_LEN: usize = 64;

/// Private EAT profile identifier (RFC 4151 tag URI) for a TDX quote nested in an EAT.
/// Not IANA-registered.
const EAT_PROFILE: &str = "tag:lanetus.github.io,2026:tdx-nested-eat";

/// Quote layout offsets (Intel TDX DCAP Quoting Library API, quote v4/v5).
const QUOTE_HEADER_LEN: usize = 48;
const QUOTE_TEE_TYPE_TDX: u32 = 0x81;
const TD_REPORT_DATA_OFFSET: usize = 520;

/// Distinguishes the configfs entries created by this process.
static ENTRY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Session with the configfs-tsm report interface of an Intel TDX guest.
#[derive(Debug)]
pub struct TdxSession {
    report_root: PathBuf,
}

/// Construction and quote retrieval.
impl TdxSession {
    /// Opens the provider at the default configfs-tsm location.
    pub fn open() -> Result<Self, AttestationError> {
        Self::open_at(CONFIGFS_TSM_REPORT)
    }

    /// Opens the provider with the configfs-tsm report interface at `report_root`.
    pub fn open_at(report_root: impl Into<PathBuf>) -> Result<Self, AttestationError> {
        let report_root = report_root.into();
        if !report_root.is_dir() {
            return Err(AttestationError::DeviceOpenFailed(format!(
                "configfs-tsm report interface not found at {} (requires Linux 6.7+ in a TDX \
                 guest with configfs mounted)",
                report_root.display()
            )));
        }
        Ok(Self { report_root })
    }

    /// Requests a TDX quote whose `REPORTDATA` is `report_data`.
    pub fn get_quote(
        &self,
        report_data: &[u8; REPORT_DATA_LEN],
    ) -> Result<Vec<u8>, AttestationError> {
        let name = format!(
            "ttk-{}-{}",
            std::process::id(),
            ENTRY_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let entry = EntryGuard::create(self.report_root.join(name))?;
        quote_from_entry(&entry.0, report_data)
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

    /// Obtains a TDX quote binding `params.user_data` and wraps it as an EAT claims-set.
    fn generate_document(
        &self,
        params: &AttestationParams,
    ) -> Result<EatClaimsSet, AttestationError> {
        let quote = self.get_quote(&report_data(params)?)?;
        Ok(wrap_quote_as_eat(&quote))
    }
}

/// Builds the TDX `REPORTDATA` for `params`: `user_data`, zero-padded to 64 bytes.
///
/// TDX binds only 64 bytes of caller data, so `nonce` and `public_key` are rejected; bind them
/// by hashing them into `user_data` instead.
pub fn report_data(params: &AttestationParams) -> Result<[u8; REPORT_DATA_LEN], AttestationError> {
    if params.nonce().is_some() || params.public_key().is_some() {
        return Err(AttestationError::InvalidInput(
            "TDX REPORTDATA can only carry user_data; hash the nonce or public key into it".into(),
        ));
    }
    let user_data = params.user_data().unwrap_or_default();
    if user_data.len() > REPORT_DATA_LEN {
        return Err(AttestationError::InvalidInput(format!(
            "TDX user_data is {} bytes, at most {REPORT_DATA_LEN} are supported",
            user_data.len()
        )));
    }
    let mut report_data = [0u8; REPORT_DATA_LEN];
    report_data[..user_data.len()].copy_from_slice(user_data);
    Ok(report_data)
}

/// Reads a quote from an existing configfs-tsm `entry` directory for `report_data`.
///
/// Checks that the entry is served by the TDX guest driver, that no concurrent writer changed
/// the request (`generation`), and that the returned quote is a TDX quote carrying
/// `report_data`.
pub fn quote_from_entry(
    entry: &Path,
    report_data: &[u8; REPORT_DATA_LEN],
) -> Result<Vec<u8>, AttestationError> {
    let provider = read_attribute(entry, "provider")?;
    if provider != TSM_PROVIDER_TDX {
        return Err(AttestationError::UnexpectedResponse(format!(
            "configfs-tsm provider is '{provider}', expected '{TSM_PROVIDER_TDX}'"
        )));
    }

    fs::write(entry.join("inblob"), report_data)?;
    let generation = read_attribute(entry, "generation")?;
    let quote = fs::read(entry.join("outblob")).map_err(|e| {
        AttestationError::Driver(format!(
            "failed to obtain a TDX quote from configfs-tsm: {e}"
        ))
    })?;
    if read_attribute(entry, "generation")? != generation {
        return Err(AttestationError::UnexpectedResponse(
            "configfs-tsm entry was modified while the quote was generated".into(),
        ));
    }

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

/// Reads a text attribute of a configfs entry, without the trailing newline.
fn read_attribute(entry: &Path, name: &str) -> Result<String, AttestationError> {
    let value = fs::read_to_string(entry.join(name)).map_err(|e| {
        AttestationError::Driver(format!(
            "failed to read configfs-tsm attribute '{name}': {e}"
        ))
    })?;
    Ok(value.trim_end().to_string())
}

/// Wraps a raw TDX `quote` as an RFC 9711 EAT claims-set, nested under the `tdx` submodule.
///
/// Trust comes from the nested quote; `iat` is the local time the quote was obtained.
pub fn wrap_quote_as_eat(quote: &[u8]) -> EatClaimsSet {
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default();
    EatClaimsSet {
        iat: Some(iat),
        eat_profile: Some(EAT_PROFILE.to_string()),
        submods: Some(Value::Map(vec![(
            Value::Text(submod::TDX.to_string()),
            Value::Bytes(quote.to_vec()),
        )])),
        ..EatClaimsSet::default()
    }
}

/// A configfs-tsm entry directory, removed when dropped so entries don't accumulate.
struct EntryGuard(PathBuf);

/// Creation of the entry.
impl EntryGuard {
    /// Creates the entry directory at `path`.
    fn create(path: PathBuf) -> Result<Self, AttestationError> {
        fs::create_dir(&path).map_err(|e| {
            AttestationError::DeviceOpenFailed(format!(
                "failed to create configfs-tsm entry {}: {e}",
                path.display()
            ))
        })?;
        Ok(Self(path))
    }
}

/// Removes the entry directory.
impl Drop for EntryGuard {
    /// Best-effort removal; configfs discards the entry's attributes with it.
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir(&self.0) {
            log::warn!(
                "failed to remove configfs-tsm entry {}: {e}",
                self.0.display()
            );
        }
    }
}
