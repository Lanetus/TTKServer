//! TTKServer client library: the RATS (RFC 9334) Verifier / Relying Party side.
//!
//! Connects to TTKServer nodes over QUIC / HTTP/3, verifies the TEE Evidence embedded in their
//! RA-TLS certificates, and builds onion-routed `POST /faf` requests. This file only wires the
//! modules together:
//!
//! - the crate root ([`TtkClient`], [`EnclaveCertVerifier`]): the RA-TLS HTTP/3 client.
//! - [`verifier`]: appraisal of TEE Evidence against vendor roots and policy.
//! - [`faf`]: the `POST /faf` request format shared by clients, relays and terminals.
//! - [`trust`]: the vendor trust anchors ([`TrustStore`]) and the root servers' pinned images.
//! - [`images`]: the accepted enclave images, fetched from the root servers
//!   ([`RootImageTrustStore`]).
//! - [`seal`]: onion encryption of `POST /faf` requests to the nodes' RA-TLS keys (RFC 9180 HPKE).

mod client;
pub mod faf;
pub mod images;
pub mod seal;
pub mod trust;
pub mod verifier;

pub use client::*;
pub use images::RootImageTrustStore;
pub use trust::{ImageTrustStore, TrustStore};
