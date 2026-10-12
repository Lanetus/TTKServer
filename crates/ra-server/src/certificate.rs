//! Replacement of the self-signed RA-TLS certificate with one issued by a trusted root
//! authority (`POST /certificate`, see [`super::router`]).
//!
//! The server starts with a self-signed certificate carrying its Evidence (see
//! [`super::server`]). An external CA can later issue a certificate for the same identity; the
//! server accepts it only if:
//!
//! - it is the **same** certificate in substance: same SubjectPublicKeyInfo (the RA-TLS key,
//!   which never leaves the TEE, so the Evidence's `user_data` binding still holds) and the same
//!   attestation extension ([`ATTESTATION_OID`]) byte for byte, and
//! - it chains (with the intermediates sent after it) to one of the configured trusted roots,
//!   is currently valid and names [`CERT_DNS_NAME`] (Web PKI path validation by `rustls`).
//!
//! The accepted chain then replaces the current one for new TLS handshakes; open connections
//! keep the certificate they negotiated. A certificate is replaced at most once: afterwards
//! [`CertificateStore::is_replaced`] is `true`, further replacements are refused
//! ([`CertificateError::AlreadyReplaced`]). The router serves its routes according to this
//! state (see [`super::router`]): until the replacement, only `POST /evidence` and
//! `POST /certificate`; after it, every other route (on connections that negotiated the
//! CA-issued certificate) and no longer those two. The trusted root is the built-in TTK root
//! authority ([`TTK_ROOT_CA_PEM`], see [`CertificateStore::load_builtin_trusted_roots`]);
//! [`CertificateStore::set_trusted_roots`] overrides it. Without trusted roots every replacement
//! is refused.

use crate::server::BoxError;
use log::info;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::RootCertStore;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use ttk_core::{ATTESTATION_OID, TTK_ROOT_CA_PEM};
use x509_parser::prelude::{FromDer, X509Certificate};

/// DNS name (subject alternative name) of the RA-TLS certificate; a replacement must be valid
/// for it.
pub const CERT_DNS_NAME: &str = "enclave.internal";

/// Why a replacement certificate was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateError {
    /// The body is not a PEM or DER certificate chain.
    Malformed(String),
    /// The leaf is not the current certificate (different key or attestation extension).
    Mismatch(&'static str),
    /// The chain does not validate against the trusted roots.
    Untrusted(String),
    /// No trusted root authorities are configured.
    NoTrustedRoots,
    /// A CA-issued certificate has already replaced the self-signed one.
    AlreadyReplaced,
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "malformed certificate chain: {e}"),
            Self::Mismatch(what) => write!(f, "certificate does not match the current one: {what}"),
            Self::Untrusted(e) => write!(f, "certificate not issued by a trusted root: {e}"),
            Self::NoTrustedRoots => write!(f, "no trusted root authorities configured"),
            Self::AlreadyReplaced => write!(f, "certificate already replaced"),
        }
    }
}

impl std::error::Error for CertificateError {}

/// The RA-TLS certificate chain presented in TLS handshakes, replaceable at runtime by one
/// issued by a trusted root authority. Serves as the rustls certificate resolver.
pub struct CertificateStore {
    /// The chain and key presented to new connections.
    current: RwLock<Arc<CertifiedKey>>,
    /// The RA-TLS signing key (never changes).
    signing_key: Arc<dyn SigningKey>,
    /// Validates replacement chains against the trusted roots; `None` refuses all.
    verifier: RwLock<Option<Arc<WebPkiServerVerifier>>>,
    /// Whether a CA-issued chain has replaced the self-signed certificate.
    replaced: AtomicBool,
}

impl fmt::Debug for CertificateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateStore").finish_non_exhaustive()
    }
}

impl CertificateStore {
    /// Creates a store presenting `cert` with the RA-TLS `key`, with no trusted roots.
    pub fn new(
        cert: CertificateDer<'static>,
        key: &PrivateKeyDer<'static>,
    ) -> Result<Self, BoxError> {
        let signing_key = any_supported_type(key)?;
        Ok(Self {
            current: RwLock::new(Arc::new(CertifiedKey::new(vec![cert], signing_key.clone()))),
            signing_key,
            verifier: RwLock::new(None),
            replaced: AtomicBool::new(false),
        })
    }

    /// Sets the root authorities replacement certificates must chain to. An empty store
    /// refuses all replacements.
    pub fn set_trusted_roots(&self, roots: RootCertStore) -> Result<(), BoxError> {
        let verifier = if roots.is_empty() {
            None
        } else {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            Some(WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build()?)
        };
        *self
            .verifier
            .write()
            .map_err(|_| "certificate store poisoned")? = verifier;
        Ok(())
    }

    /// Whether trusted root authorities are configured, i.e. whether a replacement can succeed.
    pub fn has_trusted_roots(&self) -> bool {
        self.verifier
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Trusts the built-in TTK root authority ([`TTK_ROOT_CA_PEM`]).
    pub fn load_builtin_trusted_roots(&self) -> Result<(), BoxError> {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(TTK_ROOT_CA_PEM) {
            roots.add(cert?)?;
        }
        if roots.is_empty() {
            return Err("the built-in TTK root CA holds no certificates".into());
        }
        info!("Loaded {} built-in trusted root authorities", roots.len());
        self.set_trusted_roots(roots)
    }

    /// Returns the chain currently presented (leaf first).
    pub fn current_chain(&self) -> Vec<CertificateDer<'static>> {
        self.current_key().cert.clone()
    }

    /// The chain and key presented to new connections.
    fn current_key(&self) -> Arc<CertifiedKey> {
        // A writer only swaps an `Arc`, so a poisoned lock still holds a consistent value.
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Whether a CA-issued chain has replaced the self-signed certificate (see
    /// [`replace`](Self::replace)).
    pub fn is_replaced(&self) -> bool {
        self.replaced.load(Ordering::Acquire)
    }

    /// Validates `chain` (leaf first, then intermediates) and, if it is the current certificate
    /// issued by a trusted root, presents it to new connections from now on. Succeeds at most
    /// once; later calls fail with [`CertificateError::AlreadyReplaced`].
    pub fn replace(&self, chain: Vec<CertificateDer<'static>>) -> Result<(), CertificateError> {
        if self.is_replaced() {
            return Err(CertificateError::AlreadyReplaced);
        }
        let verifier = self
            .verifier
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(CertificateError::NoTrustedRoots)?;
        let (leaf, intermediates) = chain
            .split_first()
            .ok_or_else(|| CertificateError::Malformed("empty chain".into()))?;

        let current = self.current_key();
        same_identity(&current.cert[0], leaf)?;

        let name = ServerName::try_from(CERT_DNS_NAME).expect("valid DNS name");
        verifier
            .verify_server_cert(leaf, intermediates, &name, &[], UnixTime::now())
            .map_err(|e| CertificateError::Untrusted(e.to_string()))?;

        // Only the first of concurrent valid replacements wins.
        if self
            .replaced
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(CertificateError::AlreadyReplaced);
        }
        let replacement = Arc::new(CertifiedKey::new(chain, self.signing_key.clone()));
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = replacement;
        info!("Replaced the RA-TLS certificate with a CA-issued one; routes unlocked for new connections");
        Ok(())
    }
}

impl ResolvesServerCert for CertificateStore {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current_key())
    }
}

/// Parses a request body as a certificate chain: PEM `CERTIFICATE` blocks, or one DER
/// certificate.
pub fn parse_chain(body: &[u8]) -> Result<Vec<CertificateDer<'static>>, CertificateError> {
    let chain = if body.trim_ascii_start().starts_with(b"-----BEGIN") {
        CertificateDer::pem_slice_iter(body)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CertificateError::Malformed(e.to_string()))?
    } else {
        vec![CertificateDer::from(body.to_vec())]
    };
    if chain.is_empty() {
        return Err(CertificateError::Malformed("no certificate".into()));
    }
    Ok(chain)
}

/// Checks that `candidate` has the same SubjectPublicKeyInfo and attestation extension as
/// `current`.
fn same_identity(
    current: &CertificateDer<'_>,
    candidate: &CertificateDer<'_>,
) -> Result<(), CertificateError> {
    let (_, current) = X509Certificate::from_der(current)
        .map_err(|e| CertificateError::Malformed(format!("current certificate: {e}")))?;
    let (_, candidate) = X509Certificate::from_der(candidate)
        .map_err(|e| CertificateError::Malformed(e.to_string()))?;

    if current.public_key().raw != candidate.public_key().raw {
        return Err(CertificateError::Mismatch("different public key"));
    }
    let current_ext = attestation_extension(&current).ok_or(CertificateError::Mismatch(
        "current certificate has no evidence",
    ))?;
    match attestation_extension(&candidate) {
        Some(ext) if ext == current_ext => Ok(()),
        Some(_) => Err(CertificateError::Mismatch("different attestation evidence")),
        None => Err(CertificateError::Mismatch("missing attestation evidence")),
    }
}

/// Returns the raw value of the attestation extension ([`ATTESTATION_OID`]), if present.
fn attestation_extension<'a>(cert: &'a X509Certificate<'_>) -> Option<&'a [u8]> {
    cert.extensions()
        .iter()
        .find(|ext| {
            ext.oid
                .iter()
                .into_iter()
                .flatten()
                .eq(ATTESTATION_OID.iter().copied())
        })
        .map(|ext| ext.value)
}
