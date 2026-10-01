//! TTKServer core library: the attested RA-TLS server over QUIC / HTTP/3.
//!
//! Provides TEE attestation (AWS Nitro, AMD SEV-SNP, Intel TDX), Entity Attestation Tokens
//! (EAT), the RA-TLS identity and the HTTP/3 [`server`] that acts as a RATS (RFC 9334) Attester.
//! It serves only the evidence routes; the nodes built on it (the `relay` and `terminal`
//! crates) add their own routes. This file only wires the modules together:
//!
//! - [`attestation`]: hardware-agnostic Attester providers and the EAT data model.
//! - [`server`]: the HTTP/3 Attester endpoint, serving Evidence from inside the TEE.
//! - [`router`]: the server's base HTTP routes (`GET /`, `GET /evidence.eat`).
//! - `vsock` (Linux): QUIC datagram sockets over vsock, the enclave's only way out.

extern crate self as ttk_core;

pub mod attestation;
mod identity;
pub mod router;
pub mod server;
#[cfg(target_os = "linux")]
pub mod vsock;

// Re-export common types and functions for convenience
pub use attestation::eat;
pub use attestation::eat::{EatClaimKey, EatClaimsSet};
pub use identity::{generate_identity, AttestationParams};
