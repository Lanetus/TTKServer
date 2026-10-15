//! TTKServer RA-TLS server library: the attested RA-TLS server over QUIC / HTTP/3.
//!
//! Provides TEE attestation (AWS Nitro, AMD SEV-SNP, Intel TDX), Evidence wrapped in RATS
//! Conceptual Message Wrappers (CMW), the RA-TLS identity and the HTTP/3 [`server`] that acts as a RATS (RFC 9334) Attester.
//! It serves only the evidence routes; the nodes built on it (the `relay` and `terminal`
//! crates) add their own routes. This file wires the modules together and defines what a node
//! does with a delivered message: the [`Evaluator`] trait and its [`EvalError`].
//!
//! - [`attestation`]: hardware-agnostic Attester providers and the CMW evidence wrapper.
//! - [`certificate`]: the replaceable RA-TLS certificate (`POST /certificate`).
//! - [`server`]: the HTTP/3 Attester endpoint, serving Evidence from inside the TEE.
//! - [`terminal`]: the terminal node, the last hop of `POST /faf`, answered by an [`Evaluator`].
//! - [`router`]: the server's base HTTP routes (`GET /`, `GET /evidence.cmw`, `POST /evidence`,
//!   `POST /certificate`) and the gating of every route on the certificate replacement.
//! - `vsock` (Linux): QUIC datagram sockets over vsock, the enclave's only way out (re-exported
//!   from [`ttk_core`]).

extern crate self as ttk_ra_server;

use std::future::Future;

pub mod attestation;
pub mod certificate;

pub mod router;
pub mod server;
pub mod terminal;
#[cfg(target_os = "linux")]
pub use ttk_core::vsock;

// Re-export common types and functions for convenience
pub use attestation::cmw;
pub use attestation::cmw::{Cmw, CmwCollection, CmwRecord};

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

/// Error of an [`Evaluator`] (or the adaptors behind it): unlike
/// [`BoxError`](crate::server::BoxError), `Send + Sync`, so it can be held across `.await` in
/// their `Send` futures.
pub type EvalError = Box<dyn std::error::Error + Send + Sync>;

/// What a node does with a delivered message: turns the decrypted message into the reply, which
/// the node then seals to the sender. The server itself evaluates nothing; nodes built on it
/// (the terminal, with its file service) answer the decrypted `/faf` message through it.
///
/// An error answers `500` without detail, so relays learn nothing about the message.
pub trait Evaluator: Send + Sync + 'static {
    /// Evaluates the decrypted `message` into the (plaintext) reply.
    fn eval(&self, message: Vec<u8>) -> impl Future<Output = Result<Vec<u8>, EvalError>> + Send;
}
