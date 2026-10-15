//! AWS Nitro Security Module (NSM) provider.
//!
//! Opens `/dev/nsm` with RAII ([`NsmSession`]) and produces hardware-rooted Nitro Attestation
//! Documents, wrapped as CMWs. The CMW wrapping helper lives in [`super::nitro_doc`].

use super::nitro_doc::wrap_as_cmw;
use super::{AttestationError, AttestationProvider};
use crate::AttestationParams;
use crate::Cmw;
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use std::path::Path;

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

    /// Requests a real attestation document from the NSM for `params` and wraps it as a CMW.
    fn generate_document(&self, params: &AttestationParams) -> Result<Cmw, AttestationError> {
        Ok(wrap_as_cmw(self.create_attestation(params)?))
    }
}

/// NSM operations: opening a session and attestation requests.
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

    /// Requests an Attestation Document from the NSM.
    ///
    /// Returns the raw COSE_Sign1 formatted document bytes.
    fn create_attestation(&self, params: &AttestationParams) -> Result<Vec<u8>, AttestationError> {
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
