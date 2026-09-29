//! Network services of the RA-TLS stack over QUIC / HTTP/3 (RFC 9114), plus the RA-TLS
//! identity and attestation request parameters they share.
//!
//! - [`server`]: the RATS (RFC 9334) Attester endpoint, serving Evidence from inside the TEE.
//! - [`client`]: the Relying Party side, verifying the RA-TLS certificate's embedded Evidence.

pub mod client;
pub mod server;

use rcgen::generate_simple_self_signed;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

/// Generates a self-signed ephemeral TLS certificate and private key for Remote Attestation TLS (RA-TLS).
///
/// Returns `(certificates, private_key, certificate_der_bytes)`.
pub fn generate_identity() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    Vec<u8>,
) {
    let subject_alt_names = vec!["localhost".to_string(), "enclave.local".to_string()];
    let certified_key = generate_simple_self_signed(subject_alt_names).unwrap();

    let cert_der = certified_key.cert.der().to_vec();
    let rustls_cert = certified_key.cert.der().clone();
    let rustls_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified_key.key_pair.serialize_der(),
    ));

    (vec![rustls_cert], rustls_key, cert_der)
}

/// Parameters for requesting an attestation document from the Nitro Security Module.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AttestationParams {
    /// Optional user data to include in the attestation document (e.g. SHA-256 hash of TLS cert).
    pub user_data: Option<Vec<u8>>,
    /// Optional cryptographic nonce to prevent replay attacks.
    pub nonce: Option<Vec<u8>>,
    /// Optional public key (DER-encoded) for cryptographic sealing or key exchange.
    pub public_key: Option<Vec<u8>>,
}

/// Builder-style setters and accessors for the attestation parameters.
impl AttestationParams {
    /// Creates a new, empty set of attestation parameters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets user data bytes.
    pub fn with_user_data(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.user_data = Some(data.into());
        self
    }

    /// Computes the SHA-256 hash of the input data (such as a DER-encoded certificate)
    /// and sets it as the `user_data` field for Remote Attestation TLS (RA-TLS).
    pub fn with_user_data_hash(mut self, data: &[u8]) -> Self {
        let hash = Sha256::digest(data);
        self.user_data = Some(hash.to_vec());
        self
    }

    /// Sets the cryptographic nonce.
    pub fn with_nonce(mut self, nonce: impl Into<Vec<u8>>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Sets the DER-encoded public key.
    pub fn with_public_key(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.public_key = Some(public_key.into());
        self
    }

    /// Returns a reference to the user data, if set.
    pub fn user_data(&self) -> Option<&[u8]> {
        self.user_data.as_deref()
    }

    /// Returns a reference to the nonce, if set.
    pub fn nonce(&self) -> Option<&[u8]> {
        self.nonce.as_deref()
    }

    /// Returns a reference to the public key, if set.
    pub fn public_key(&self) -> Option<&[u8]> {
        self.public_key.as_deref()
    }
}
