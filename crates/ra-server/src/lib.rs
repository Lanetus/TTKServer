//! TTKServer RA-TLS server library: the attested RA-TLS server over QUIC / HTTP/3.
//!
//! Provides TEE attestation (AWS Nitro, AMD SEV-SNP, Intel TDX), Evidence wrapped in RATS
//! Conceptual Message Wrappers (CMW), the RA-TLS identity and the HTTP/3 [`server`] that acts as a RATS (RFC 9334) Attester.
//! It serves only the evidence routes; the nodes built on it (the `relay` and `terminal`
//! crates) add their own routes. This file only wires the modules together:
//!
//! - [`attestation`]: hardware-agnostic Attester providers and the CMW evidence wrapper.
//! - [`egress`]: the egress policy for peer-chosen destinations (re-exported from [`ttk_core`]).
//! - [`server`]: the HTTP/3 Attester endpoint, serving Evidence from inside the TEE.
//! - [`router`]: the server's base HTTP routes (`GET /`, `GET /evidence.cmw`, `POST /evidence`).
//! - `vsock` (Linux): QUIC datagram sockets over vsock, the enclave's only way out (re-exported
//!   from [`ttk_core`]).

extern crate self as ttk_ra_server;

pub mod attestation;

pub use ttk_core::egress;
pub mod router;
pub mod server;
#[cfg(target_os = "linux")]
pub use ttk_core::vsock;

// Re-export common types and functions for convenience
pub use attestation::cmw;
pub use attestation::cmw::{Cmw, CmwCollection, CmwRecord, CmwType};

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
