//! Base HTTP routes of the RA-TLS server, served over HTTP/3 by [`super::server`]:
//!
//! | Route               | Response                                                        |
//! |---------------------|-----------------------------------------------------------------|
//! | `GET /`             | Greeting text                                                   |
//! | `GET /evidence.cmw` | Base64-encoded CBOR CMW carrying this server's [`Evidence`]     |
//! | `POST /evidence`    | Base64-encoded CBOR [`FreshEvidence`]: Evidence carrying the body as nonce, and the certificate |
//! | `POST /certificate` | Replaces the RA-TLS certificate with a CA-issued one (`204`)    |
//!
//! `POST /evidence` gives a Verifier freshness (RFC 9334 §10): the request body is the raw
//! nonce (1 to [`MAX_NONCE_LEN`] bytes, else `400`), and the server asks the TEE for new Evidence
//! bound, like the startup Evidence, to the RA-TLS key (`user_data` = SHA-256 of its
//! SubjectPublicKeyInfo), with the nonce in the attestation document's `nonce` field. The
//! response is a [`FreshEvidence`] CMW collection: that Evidence and the certificate currently
//! presented (self-signed or CA-issued), which the Verifier compares with the one from its TLS
//! handshake. At most [`MAX_CONCURRENT_ATTESTATIONS`] requests are attested at
//! once; further ones get `503`. Providers that cannot carry a nonce (TDX, SEV-SNP) answer `500`.
//!
//! `POST /certificate` takes a certificate chain (PEM, leaf first, or one DER certificate) issued
//! by a trusted root authority for the current RA-TLS certificate (same key and evidence, see
//! [`crate::certificate`]) and presents it to new connections. Refusals: `400` malformed chain,
//! `422` not the current certificate, `403` not issued by a trusted root, `503` no trusted roots
//! configured.
//!
//! Nodes built on the server add their own routes with
//! [`Server::serve_with`](super::server::Server::serve_with).

use crate::attestation::AttestationProvider;
use crate::certificate::{parse_chain, CertificateError, CertificateStore};
use crate::AttestationParams;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::{error, warn};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::Semaphore;
use ttk_core::FreshEvidence;
use x509_parser::prelude::{FromDer, X509Certificate};

/// Largest nonce `POST /evidence` accepts, in bytes (the NSM's limit for `nonce`).
pub const MAX_NONCE_LEN: usize = 512;

/// Most `POST /evidence` requests attested at once; further ones get `503 Service Unavailable`.
pub const MAX_CONCURRENT_ATTESTATIONS: usize = 4;

/// Evidence for this instance, in the formats served over HTTP.
#[derive(Clone, Debug)]
pub struct Evidence {
    /// The TEE evidence, wrapped as a CBOR-encoded RATS Conceptual Message Wrapper.
    pub cmw: Vec<u8>,
}

/// Builds the Axum router serving the greeting and the evidence endpoints, merged with `routes`.
///
/// `POST /evidence` asks `provider` for Evidence carrying the request's nonce, bound to the key
/// of the certificate held by `certificates`, and returns it with that certificate;
/// `POST /certificate` replaces the chain held by `certificates`.
pub fn build_router(
    evidence: &Evidence,
    provider: Arc<dyn AttestationProvider>,
    certificates: Arc<CertificateStore>,
    routes: Router,
) -> Router {
    let cmw_b64 = STANDARD.encode(&evidence.cmw);
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_ATTESTATIONS));
    let evidence_certificates = certificates.clone();

    Router::new()
        .route("/", get(|| async { "Hello from Enclave over HTTP/3!" }))
        .route("/evidence.cmw", get(move || async move { cmw_b64 }))
        .route(
            "/evidence",
            post(move |nonce: Bytes| {
                evidence_with_nonce(provider, permits, evidence_certificates, nonce)
            }),
        )
        .route(
            "/certificate",
            post(move |body: Bytes| async move { replace_certificate(&certificates, &body) }),
        )
        .merge(routes)
}

/// Handles `POST /evidence`: generates fresh Evidence carrying `nonce`, bound to the key of the
/// current certificate, and returns both as a base64-encoded CBOR [`FreshEvidence`].
async fn evidence_with_nonce(
    provider: Arc<dyn AttestationProvider>,
    permits: Arc<Semaphore>,
    certificates: Arc<CertificateStore>,
    nonce: Bytes,
) -> Response {
    if nonce.is_empty() || nonce.len() > MAX_NONCE_LEN {
        return (
            StatusCode::BAD_REQUEST,
            format!("nonce must be 1 to {MAX_NONCE_LEN} bytes"),
        )
            .into_response();
    }
    let Ok(_permit) = permits.try_acquire_owned() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "attestation busy").into_response();
    };
    let certificate = certificates.current_chain().swap_remove(0).to_vec();
    let Some(binding) = key_binding(&certificate) else {
        error!("Current RA-TLS certificate is malformed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "evidence generation failed",
        )
            .into_response();
    };
    let params = AttestationParams {
        user_data: Some(binding),
        nonce: Some(nonce.to_vec()),
        ..AttestationParams::default()
    };
    let generate = move || {
        provider.generate_document(&params).map(|evidence| {
            FreshEvidence {
                evidence,
                certificate,
            }
            .to_cmw()
            .to_cbor_bytes()
        })
    };
    match tokio::task::spawn_blocking(generate).await {
        Ok(Ok(cmw)) => STANDARD.encode(cmw).into_response(),
        Ok(Err(e)) => {
            error!("Evidence generation with nonce failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence generation failed",
            )
                .into_response()
        }
        Err(e) => {
            error!("Evidence generation task failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "evidence generation failed",
            )
                .into_response()
        }
    }
}

/// SHA-256 of the SubjectPublicKeyInfo of the DER certificate `cert`, the RA-TLS key binding.
fn key_binding(cert: &[u8]) -> Option<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert).ok()?;
    Some(Sha256::digest(cert.public_key().raw).to_vec())
}

/// Handles `POST /certificate`: validates the chain in `body` and, if it is the current
/// certificate issued by a trusted root, presents it from now on (`204 No Content`).
fn replace_certificate(certificates: &CertificateStore, body: &[u8]) -> Response {
    let result = parse_chain(body).and_then(|chain| certificates.replace(chain));
    let Err(e) = result else {
        return StatusCode::NO_CONTENT.into_response();
    };
    warn!("Refused certificate replacement: {e}");
    let status = match e {
        CertificateError::Malformed(_) => StatusCode::BAD_REQUEST,
        CertificateError::Mismatch(_) => StatusCode::UNPROCESSABLE_ENTITY,
        CertificateError::Untrusted(_) => StatusCode::FORBIDDEN,
        CertificateError::NoTrustedRoots => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, e.to_string()).into_response()
}
