//! AMD SEV-SNP provider (placeholder: hardware detection only, evidence generation not yet implemented).

use super::{AttestationError, AttestationProvider};
use crate::{AttestationParams, EatClaimsSet};
use std::path::Path;

/// Path of the AMD SEV-SNP guest device used for detection.
const DEVICE: &str = "/dev/sev-guest";

/// Session with the AMD SEV-SNP guest device.
#[derive(Debug)]
pub struct SevSnpSession;

/// Construction of the AMD SEV-SNP session.
impl SevSnpSession {
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

/// AMD SEV-SNP implementation of [`AttestationProvider`] (evidence generation not yet implemented).
impl AttestationProvider for SevSnpSession {
    /// Returns `"sev-snp"`.
    fn name(&self) -> &'static str {
        "sev-snp"
    }

    /// Returns `true` if `/dev/sev-guest` exists.
    fn is_available() -> bool {
        Path::new(DEVICE).exists()
    }

    /// Always fails with [`AttestationError::Unsupported`] until evidence generation is implemented.
    fn generate_document(
        &self,
        _params: &AttestationParams,
    ) -> Result<EatClaimsSet, AttestationError> {
        Err(AttestationError::Unsupported(
            "sev-snp evidence generation is not implemented yet".to_string(),
        ))
    }
}
