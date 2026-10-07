//! Linux configfs-tsm report interface, shared by the Intel TDX and AMD SEV-SNP providers.
//!
//! Linux 6.7+ exposes `/sys/kernel/config/tsm/report` inside confidential guests (see the
//! kernel's `Documentation/ABI/testing/configfs-tsm`). A request is an entry directory: writing
//! the 64-byte report data to `inblob` and reading `outblob` returns the TEE's signed evidence
//! (a TDX quote or an SEV-SNP report), and `auxblob` returns supplemental data such as the
//! SEV-SNP certificate table. `provider` names the serving driver and `generation` counts
//! writes, so concurrent modification of the request can be detected.

use super::AttestationError;
use crate::AttestationParams;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Default location of the configfs-tsm report interface.
pub const CONFIGFS_TSM_REPORT: &str = "/sys/kernel/config/tsm/report";

/// Size of the report data bound into TDX and SEV-SNP evidence.
pub const REPORT_DATA_LEN: usize = 64;

/// Distinguishes the configfs entries created by this process.
static ENTRY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Evidence returned by a configfs-tsm request.
#[derive(Debug, Clone)]
pub struct TsmReport {
    /// The signed evidence (`outblob`).
    pub outblob: Vec<u8>,
    /// Supplemental data (`auxblob`), if requested and non-empty.
    pub auxblob: Option<Vec<u8>>,
}

/// The configfs-tsm report directory.
#[derive(Debug, Clone)]
pub struct TsmRoot {
    root: PathBuf,
}

/// Opening the interface and issuing requests.
impl TsmRoot {
    /// Opens the interface at `root`; `guest` names the TEE for the error message.
    pub fn open_at(root: impl Into<PathBuf>, guest: &str) -> Result<Self, AttestationError> {
        let root = root.into();
        if !root.is_dir() {
            return Err(AttestationError::DeviceOpenFailed(format!(
                "configfs-tsm report interface not found at {} (requires Linux 6.7+ in {guest} \
                 guest with configfs mounted)",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    /// Issues a request in a fresh entry, which is removed afterwards.
    pub fn request(
        &self,
        provider: &str,
        report_data: &[u8; REPORT_DATA_LEN],
        with_auxblob: bool,
    ) -> Result<TsmReport, AttestationError> {
        let name = format!(
            "ttk-{}-{}",
            std::process::id(),
            ENTRY_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let entry = EntryGuard::create(self.root.join(name))?;
        request_in_entry(&entry.0, provider, report_data, with_auxblob)
    }
}

/// Issues a request in the existing configfs-tsm `entry`, which must be served by `provider`.
///
/// Fails if another writer modified the entry while the evidence was generated.
pub fn request_in_entry(
    entry: &Path,
    provider: &str,
    report_data: &[u8; REPORT_DATA_LEN],
    with_auxblob: bool,
) -> Result<TsmReport, AttestationError> {
    let actual = read_attribute(entry, "provider")?;
    if actual != provider {
        return Err(AttestationError::UnexpectedResponse(format!(
            "configfs-tsm provider is '{actual}', expected '{provider}'"
        )));
    }

    fs::write(entry.join("inblob"), report_data)?;
    let generation = read_attribute(entry, "generation")?;
    let outblob = fs::read(entry.join("outblob")).map_err(|e| {
        AttestationError::Driver(format!("failed to obtain evidence from configfs-tsm: {e}"))
    })?;
    let auxblob = if with_auxblob {
        let aux = fs::read(entry.join("auxblob")).map_err(|e| {
            AttestationError::Driver(format!("failed to read configfs-tsm auxblob: {e}"))
        })?;
        Some(aux).filter(|aux| !aux.is_empty())
    } else {
        None
    };
    if read_attribute(entry, "generation")? != generation {
        return Err(AttestationError::UnexpectedResponse(
            "configfs-tsm entry was modified while the evidence was generated".into(),
        ));
    }

    Ok(TsmReport { outblob, auxblob })
}

/// Builds the 64-byte report data for `params`: `user_data`, zero-padded.
///
/// TDX and SEV-SNP bind only 64 bytes of caller data, so `nonce` and `public_key` are rejected;
/// bind them by hashing them into `user_data` instead.
pub fn report_data(params: &AttestationParams) -> Result<[u8; REPORT_DATA_LEN], AttestationError> {
    if params.nonce().is_some() || params.public_key().is_some() {
        return Err(AttestationError::InvalidInput(
            "report data can only carry user_data; hash the nonce or public key into it".into(),
        ));
    }
    let user_data = params.user_data().unwrap_or_default();
    if user_data.len() > REPORT_DATA_LEN {
        return Err(AttestationError::InvalidInput(format!(
            "user_data is {} bytes, at most {REPORT_DATA_LEN} are supported",
            user_data.len()
        )));
    }
    let mut report_data = [0u8; REPORT_DATA_LEN];
    report_data[..user_data.len()].copy_from_slice(user_data);
    Ok(report_data)
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
