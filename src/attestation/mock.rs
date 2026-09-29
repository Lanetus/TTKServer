//! Mock provider for local development and CI where no TEE hardware exists.

use super::nitro_doc::{create_mock_attestation_document, wrap_as_eat};
use super::{AttestationError, AttestationProvider};
use crate::{AttestationParams, EatClaimsSet};

/// Always-available provider producing synthetic (unsigned) Nitro-format documents.
pub struct MockSession;

/// Mock implementation of [`AttestationProvider`]; builds a synthetic Nitro-format document.
impl AttestationProvider for MockSession {
    /// Returns `"mock"`.
    fn name(&self) -> &'static str {
        "mock"
    }

    /// The mock provider is always available.
    fn is_available() -> bool {
        true
    }

    /// Builds a mock attestation document for `params` and wraps it as an EAT claims-set.
    fn generate_document(
        &self,
        params: &AttestationParams,
    ) -> Result<EatClaimsSet, AttestationError> {
        wrap_as_eat(&create_mock_attestation_document(params)?)
    }
}
