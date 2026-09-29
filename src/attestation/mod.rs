//! Hardware-agnostic attestation providers.
//!
//! Each supported TEE (AWS Nitro, AMD SEV-SNP, Intel TDX, ...) implements
//! [`AttestationProvider`]. [`detect`] probes the machine at runtime and returns the provider
//! matching the hardware we are running on; [`by_name`] selects one explicitly.
//!
//! Backends are gated by additive Cargo features (`nitro`, `sev-snp`, `tdx`, `mock`), so a single
//! binary can support several of them.

use crate::{AttestationParams, EatClaimsSet};
use std::fmt;

#[cfg(any(feature = "nitro", feature = "mock"))]
pub mod nitro_doc;

#[cfg(feature = "nitro")]
pub mod nitro;
#[cfg(feature = "nitro")]
pub use nitro::NsmSession;

#[cfg(feature = "sev-snp")]
pub mod sev_snp;

#[cfg(feature = "tdx")]
pub mod tdx;

#[cfg(feature = "mock")]
pub mod mock;
#[cfg(feature = "mock")]
pub use mock::MockSession;

/// Environment variable that forces a specific provider (see [`by_name`]).
pub const PROVIDER_ENV: &str = "TTK_ATTESTATION";

/// Errors produced by any attestation provider.
#[derive(Debug)]
pub enum AttestationError {
    /// The TEE device could not be opened (e.g. `/dev/nsm`).
    DeviceOpenFailed(String),
    /// The TEE driver returned an error.
    Driver(String),
    /// The TEE driver returned an unexpected response.
    UnexpectedResponse(String),
    /// Input parameter validation failed.
    InvalidInput(String),
    /// Failed to decode or parse an attestation document.
    DocumentDecodingFailed(String),
    /// The requested provider is unknown, not compiled in, or not implemented.
    Unsupported(String),
    /// No provider matches the current hardware.
    NoProvider,
    /// An I/O error occurred.
    Io(std::io::Error),
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceOpenFailed(msg) => write!(f, "Failed to open TEE device: {msg}"),
            Self::Driver(msg) => write!(f, "TEE driver returned an error: {msg}"),
            Self::UnexpectedResponse(msg) => {
                write!(f, "Unexpected response from TEE driver: {msg}")
            }
            Self::InvalidInput(msg) => write!(f, "Invalid attestation input: {msg}"),
            Self::DocumentDecodingFailed(msg) => write!(f, "Document decoding failure: {msg}"),
            Self::Unsupported(msg) => write!(f, "Unsupported attestation provider: {msg}"),
            Self::NoProvider => write!(f, "No attestation provider matches this hardware"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for AttestationError {}

impl From<std::io::Error> for AttestationError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// A source of attestation evidence backed by a specific TEE.
pub trait AttestationProvider: Send + Sync {
    /// Short stable identifier, e.g. `"aws-nitro"`, `"sev-snp"`, `"tdx"`, `"mock"`.
    fn name(&self) -> &'static str;

    /// Cheap probe: is this provider's hardware present on this machine?
    fn is_available() -> bool
    where
        Self: Sized;

    /// Produces an EAT claims-set carrying this TEE's evidence for `params`.
    fn generate_document(
        &self,
        params: &AttestationParams,
    ) -> Result<EatClaimsSet, AttestationError>;
}

/// Picks the provider matching the current hardware.
///
/// `TTK_ATTESTATION=<name>` overrides probing. Otherwise real hardware backends are probed in a
/// fixed order, and the mock provider (if compiled in) is used only as a last resort.
pub fn detect() -> Result<Box<dyn AttestationProvider>, AttestationError> {
    if let Ok(name) = std::env::var(PROVIDER_ENV) {
        return by_name(&name);
    }

    #[cfg(feature = "nitro")]
    if nitro::NsmSession::is_available() {
        return by_name("aws-nitro");
    }
    #[cfg(feature = "sev-snp")]
    if sev_snp::SevSnpSession::is_available() {
        return by_name("sev-snp");
    }
    #[cfg(feature = "tdx")]
    if tdx::TdxSession::is_available() {
        return by_name("tdx");
    }

    fallback()
}

#[cfg(feature = "mock")]
fn fallback() -> Result<Box<dyn AttestationProvider>, AttestationError> {
    log::warn!("No TEE hardware detected; using MOCK attestation. Evidence is NOT trustworthy.");
    by_name("mock")
}

#[cfg(not(feature = "mock"))]
fn fallback() -> Result<Box<dyn AttestationProvider>, AttestationError> {
    Err(AttestationError::NoProvider)
}

/// Opens the provider called `name`.
pub fn by_name(name: &str) -> Result<Box<dyn AttestationProvider>, AttestationError> {
    match name {
        #[cfg(feature = "nitro")]
        "aws-nitro" => Ok(Box::new(nitro::NsmSession::open()?)),
        #[cfg(feature = "sev-snp")]
        "sev-snp" => Ok(Box::new(sev_snp::SevSnpSession::open()?)),
        #[cfg(feature = "tdx")]
        "tdx" => Ok(Box::new(tdx::TdxSession::open()?)),
        #[cfg(feature = "mock")]
        "mock" => Ok(Box::new(mock::MockSession)),
        other => Err(AttestationError::Unsupported(format!(
            "'{other}' is unknown or not compiled into this build"
        ))),
    }
}
