//! AWS Nitro Security Module (NSM) provider.
//!
//! Opens `/dev/nsm` with RAII ([`NsmSession`]) and produces hardware-rooted Nitro Attestation
//! Documents, wrapped as EAT claims-sets. Document parsing helpers live in [`super::nitro_doc`].

use super::nitro_doc::wrap_as_eat;
use super::{AttestationError, AttestationProvider};
pub use crate::AttestationParams;
use crate::EatClaimsSet;
use aws_nitro_enclaves_nsm_api::api::Digest;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use std::path::Path;

/// Information about the connected Nitro Security Module runtime and configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct NsmDescription {
    /// Major API version of the NSM.
    pub version_major: u16,
    /// Minor API version of the NSM.
    pub version_minor: u16,
    /// Patch version of the NSM.
    pub version_patch: u16,
    /// Module identifier for the NSM.
    pub module_id: String,
    /// Maximum number of Platform Configuration Registers (PCRs).
    pub max_pcrs: u16,
    /// The indices of PCRs that are read-only / locked.
    pub locked_pcrs: std::collections::BTreeSet<u16>,
    /// Digest algorithm used for PCR values.
    pub digest: Digest,
}

/// An open session with the Nitro Security Module (`/dev/nsm`).
///
/// Implements RAII to ensure the device file descriptor is automatically closed
/// via [`nsm_exit`] when the session is dropped.
#[derive(Debug)]
pub struct NsmSession {
    fd: i32,
}

/// Nitro implementation of [`AttestationProvider`], backed by `/dev/nsm`.
impl AttestationProvider for NsmSession {
    /// Returns `"aws-nitro"`.
    fn name(&self) -> &'static str {
        "aws-nitro"
    }

    /// Returns `true` if the NSM device `/dev/nsm` exists.
    fn is_available() -> bool {
        Path::new("/dev/nsm").exists()
    }

    /// Requests a real attestation document from the NSM for `params` and wraps it as an EAT claims-set.
    fn generate_document(
        &self,
        params: &AttestationParams,
    ) -> Result<EatClaimsSet, AttestationError> {
        wrap_as_eat(&self.create_attestation(params)?)
    }
}

/// NSM operations: opening a session, attestation requests and PCR management.
impl NsmSession {
    /// Opens a new session with the Nitro Security Module.
    ///
    /// Calls [`nsm_init`] to open `/dev/nsm`. Returns [`AttestationError::DeviceOpenFailed`]
    /// if the device file cannot be opened (e.g., if not running inside an AWS Nitro Enclave).
    pub fn open() -> Result<Self, AttestationError> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(AttestationError::DeviceOpenFailed(
                "Unable to open /dev/nsm. Ensure this process is running inside an AWS Nitro Enclave with the NSM device enabled."
                    .to_string(),
            ));
        }
        Ok(Self { fd })
    }

    /// Creates an [`NsmSession`] from an existing raw file descriptor.
    pub fn from_raw_fd(fd: i32) -> Result<Self, AttestationError> {
        if fd < 0 {
            return Err(AttestationError::DeviceOpenFailed(
                "Invalid file descriptor provided".to_string(),
            ));
        }
        Ok(Self { fd })
    }

    /// Returns the underlying raw file descriptor.
    pub fn raw_fd(&self) -> i32 {
        self.fd
    }

    /// Requests an Attestation Document from the NSM.
    ///
    /// Returns the raw COSE_Sign1 formatted document bytes.
    pub fn create_attestation(
        &self,
        params: &AttestationParams,
    ) -> Result<Vec<u8>, AttestationError> {
        let request = Request::Attestation {
            user_data: params.user_data.as_ref().map(|d| d.clone().into()),
            nonce: params.nonce.as_ref().map(|n| n.clone().into()),
            public_key: params.public_key.as_ref().map(|pk| pk.clone().into()),
        };

        match nsm_process_request(self.fd, request) {
            Response::Attestation { document } => Ok(document),
            Response::Error(err) => Err(AttestationError::Driver(format!("{err:?}"))),
            other => Err(AttestationError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Convenience method to create an attestation document binding an ephemeral TLS certificate.
    ///
    /// Computes the SHA-256 hash of `cert_der` and supplies it as `user_data`.
    pub fn create_attestation_for_cert(
        &self,
        cert_der: &[u8],
    ) -> Result<Vec<u8>, AttestationError> {
        let params = AttestationParams::new().with_user_data_hash(cert_der);
        self.create_attestation(&params)
    }

    /// Describes the connected Nitro Security Module capabilities and configuration.
    pub fn describe_nsm(&self) -> Result<NsmDescription, AttestationError> {
        match nsm_process_request(self.fd, Request::DescribeNSM) {
            Response::DescribeNSM {
                version_major,
                version_minor,
                version_patch,
                module_id,
                max_pcrs,
                locked_pcrs,
                digest,
            } => Ok(NsmDescription {
                version_major,
                version_minor,
                version_patch,
                module_id,
                max_pcrs,
                locked_pcrs,
                digest,
            }),
            Response::Error(err) => Err(AttestationError::Driver(format!("{err:?}"))),
            other => Err(AttestationError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Requests cryptographic entropy (random bytes) from the NSM.
    pub fn get_random(&self) -> Result<Vec<u8>, AttestationError> {
        match nsm_process_request(self.fd, Request::GetRandom) {
            Response::GetRandom { random } => Ok(random),
            Response::Error(err) => Err(AttestationError::Driver(format!("{err:?}"))),
            other => Err(AttestationError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Describes a Platform Configuration Register (PCR) at `index`.
    /// Returns `(locked, data)`.
    pub fn describe_pcr(&self, index: u16) -> Result<(bool, Vec<u8>), AttestationError> {
        match nsm_process_request(self.fd, Request::DescribePCR { index }) {
            Response::DescribePCR { lock, data } => Ok((lock, data)),
            Response::Error(err) => Err(AttestationError::Driver(format!("{err:?}"))),
            other => Err(AttestationError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Extends a Platform Configuration Register (PCR) at `index` with `data`.
    pub fn extend_pcr(&self, index: u16, data: Vec<u8>) -> Result<Vec<u8>, AttestationError> {
        match nsm_process_request(self.fd, Request::ExtendPCR { index, data }) {
            Response::ExtendPCR { data } => Ok(data),
            Response::Error(err) => Err(AttestationError::Driver(format!("{err:?}"))),
            other => Err(AttestationError::UnexpectedResponse(format!("{other:?}"))),
        }
    }

    /// Locks a Platform Configuration Register (PCR) at `index` against further modification.
    pub fn lock_pcr(&self, index: u16) -> Result<(), AttestationError> {
        match nsm_process_request(self.fd, Request::LockPCR { index }) {
            Response::LockPCR => Ok(()),
            Response::Error(err) => Err(AttestationError::Driver(format!("{err:?}"))),
            other => Err(AttestationError::UnexpectedResponse(format!("{other:?}"))),
        }
    }
}

/// Closes the NSM device file descriptor when the session goes out of scope.
impl Drop for NsmSession {
    /// Calls `nsm_exit` on the open file descriptor, at most once.
    fn drop(&mut self) {
        if self.fd >= 0 {
            nsm_exit(self.fd);
            self.fd = -1;
        }
    }
}
