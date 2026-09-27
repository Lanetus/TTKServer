//! TTKServer library.
//!
//! Provides modules for AWS Nitro Enclave attestation, Entity Attestation Tokens (EAT),
//! and remote attestation identity generation.

pub mod client;
pub mod eat;
pub mod nitro;

// Re-export common types and functions for convenience
pub use eat::{EatClaimKey, EatClaimsSet};
pub use nitro::{
    generate_attestation_for_cert_or_mock, wrap_as_eat,
};

use rcgen::generate_simple_self_signed;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

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
