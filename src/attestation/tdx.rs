//! Intel TDX provider (placeholder: hardware detection only, evidence generation not yet implemented).

use super::{AttestationError, AttestationProvider};
use crate::{AttestationParams, EatClaimsSet};
use std::path::Path;

/// Path of the Intel TDX guest device used for detection.
const DEVICE: &str = "/dev/tdx_guest";

/// Session with the Intel TDX guest device.
#[derive(Debug)]
pub struct TdxSession;

/// Construction of the Intel TDX session.
impl TdxSession {
    /// Opens the provider, failing if the guest device is absent.
    pub fn open() -> Result<Self, AttestationError> {
        if Self::is_available() {
            Ok(Self)
        } else {
            Err(AttestationError::DeviceOpenFailed(format!(
                "{DEVICE} not found"
            )))
        }
    }
}

/// Intel TDX implementation of [`AttestationProvider`] (evidence generation not yet implemented).
impl AttestationProvider for TdxSession {
    /// Returns `"tdx"`.
    fn name(&self) -> &'static str {
        "tdx"
    }

    /// Returns `true` if `/dev/tdx_guest` exists.
    fn is_available() -> bool {
        Path::new(DEVICE).exists()
    }

    /// Always fails with [`AttestationError::Unsupported`] until evidence generation is implemented.
    fn generate_document(
        &self,
        _params: &AttestationParams,
    ) -> Result<EatClaimsSet, AttestationError> {
        Err(AttestationError::Unsupported(
            "tdx evidence generation is not implemented yet".to_string(),
        ))
    }
}
