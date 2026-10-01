//! TTKServer client library: the RATS (RFC 9334) Verifier / Relying Party side.
//!
//! Connects to TTKServer nodes over QUIC / HTTP/3, verifies the TEE Evidence embedded in their
//! RA-TLS certificates, and builds onion-routed `POST /faf` requests. This file only wires the
//! modules together:
//!
//! - the crate root ([`TtkClient`], [`EnclaveCertVerifier`]): the RA-TLS HTTP/3 client.
//! - [`verifier`]: appraisal of TEE Evidence against vendor roots and policy.
//! - [`faf`]: the `POST /faf` request format shared by clients, relays and terminals.
//! - [`seal`]: onion encryption of `POST /faf` requests to the nodes' RA-TLS keys (RFC 9180 HPKE).

mod client;
pub mod faf;
pub mod seal;
pub mod verifier;

pub use client::*;
