//! Intel TDX provider (placeholder: hardware detection only, evidence generation not yet implemented).

use super::{AttestationError, AttestationProvider};
use crate::{AttestationParams, EatClaimsSet};
use std::path::Path;

const DEVICE: &str = "/dev/tdx_guest";

/// Session with the Intel TDX guest device.
#[derive(Debug)]
pub struct TdxSession;

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

impl AttestationProvider for TdxSession {
    fn name(&self) -> &'static str {
        "tdx"
    }

    fn is_available() -> bool {
        Path::new(DEVICE).exists()
    }

    fn generate_document(
        &self,
        _params: &AttestationParams,
    ) -> Result<EatClaimsSet, AttestationError> {
        Err(AttestationError::Unsupported(
            "tdx evidence generation is not implemented yet".to_string(),
        ))
    }
}
