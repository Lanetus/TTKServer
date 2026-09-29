//! TTKServer library.
//!
//! Provides AWS Nitro Enclave / TEE attestation, Entity Attestation Tokens (EAT), remote
//! attestation identity generation, and the RA-TLS client and server over QUIC / HTTP/3.
//! This file only wires the modules together:
//!
//! - [`attestation`]: hardware-agnostic Attester providers and the EAT data model.
//! - [`service`]: the HTTP/3 [`server`] (Attester) and [`client`] (Relying Party).
//! - [`verifier`]: appraisal of TEE Evidence against vendor roots and policy.

extern crate self as ttk_server;

pub mod attestation;
pub mod service;
pub mod verifier;

// Re-export common types and functions for convenience
pub use attestation::eat;
pub use attestation::eat::{EatClaimKey, EatClaimsSet};
pub use service::{client, generate_identity, router, server, AttestationParams};
