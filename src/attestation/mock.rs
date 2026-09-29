//! Mock provider for local development and CI where no TEE hardware exists.

use super::nitro_doc::{create_mock_attestation_document, wrap_as_eat};
use super::{AttestationError, AttestationProvider};
use crate::{AttestationParams, EatClaimsSet};

/// Always-available provider producing synthetic (unsigned) Nitro-format documents.
pub struct MockSession;

impl AttestationProvider for MockSession {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn is_available() -> bool {
        true
    }

    fn generate_document(
        &self,
        params: &AttestationParams,
    ) -> Result<EatClaimsSet, AttestationError> {
        wrap_as_eat(&create_mock_attestation_document(params)?)
    }
}
