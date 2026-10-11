//! Test certificate authority for attested nodes (feature `auth-test`, bin `auth-test`).
//!
//! Acts as a Verifier and a CA for one TTKServer node:
//!
//! 1. connects over RA-TLS ([`EnclaveCertVerifier`]), which appraises the Evidence in the node's
//!    self-signed certificate and its binding to the TLS key;
//! 2. sends a random nonce to `POST /evidence` and checks the [`FreshEvidence`] it gets back
//!    (RFC 9334 §10, [`verify_fresh_evidence`]): its certificate is the one from the TLS
//!    handshake, and its Evidence is genuine, bound to that certificate's key, carries the
//!    nonce, and comes from the same enclave image (equal measurements) as the certificate's
//!    Evidence;
//! 3. issues a certificate for the node's RA-TLS key with the same attestation extension
//!    ([`CertificateAuthority::issue`]) and installs it with `POST /certificate`.
//!
//! Accepted Nitro images are this crate's [`FileImageTrustStore`] by default.

use crate::FileImageTrustStore;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use log::info;
use rand_core::{OsRng, RngCore};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    DnValue, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
    SignatureAlgorithm,
};
use rustls_pki_types::{pem::PemObject, CertificateDer, UnixTime};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use time::{Duration, OffsetDateTime};
use ttk_core::{FreshEvidence, ATTESTATION_OID};
use ttk_ra_client::verifier::{self, Policy, VerifiedEvidence};
use ttk_ra_client::{EnclaveCertVerifier, ImageTrustStore, TrustStore, TtkClient};
use ttk_ra_server::certificate::CERT_DNS_NAME;
use ttk_ra_server::server::BoxError;
use x509_parser::der_parser::asn1_rs::Tag;
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};

/// Path of the fresh-Evidence endpoint (body: raw nonce).
pub const EVIDENCE_PATH: &str = "/evidence";

/// Path of the certificate replacement endpoint (body: PEM chain, leaf first).
pub const CERTIFICATE_PATH: &str = "/certificate";

/// Length of the random nonce sent to `POST /evidence`, in bytes.
pub const NONCE_LEN: usize = 32;

/// Common name of a CA created by [`CertificateAuthority::generate`].
pub const DEFAULT_CA_NAME: &str = "TTK auth-test CA";

/// Validity of a CA created by [`CertificateAuthority::generate`], in days.
pub const CA_VALIDITY_DAYS: i64 = 3650;

/// A certificate authority issuing certificates for nodes' RA-TLS keys.
pub struct CertificateAuthority {
    /// The CA certificate as given (PEM, DER).
    cert_der: CertificateDer<'static>,
    /// In-memory issuer with the CA's subject name, used only to sign.
    issuer: Certificate,
    /// The CA's signing key.
    key: KeyPair,
    /// Whether the CA certificate is self-signed (a root, not sent in issued chains).
    self_signed: bool,
}

/// Creation, loading and issuance.
impl CertificateAuthority {
    /// Creates a new self-signed root CA named `common_name`.
    pub fn generate(common_name: &str) -> Result<Self, BoxError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = params.not_before + Duration::days(CA_VALIDITY_DAYS);
        let cert = params.self_signed(&key)?;
        let cert_der = cert.der().clone();
        Ok(Self {
            cert_der,
            issuer: cert,
            key,
            self_signed: true,
        })
    }

    /// Loads a CA from its PEM certificate and PEM (PKCS#8) private key.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, BoxError> {
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|e| format!("CA certificate: {e}"))?;
        let key = KeyPair::from_pem(key_pem).map_err(|e| format!("CA key: {e}"))?;
        let (_, cert) =
            X509Certificate::from_der(&cert_der).map_err(|e| format!("CA certificate: {e}"))?;
        if cert.public_key().raw != key.public_key_der() {
            return Err("CA key does not match the CA certificate".into());
        }
        let self_signed = cert.subject().as_raw() == cert.issuer().as_raw();

        // rcgen signs with an issuer certificate; rebuild one with the CA's subject name and key
        // so issued certificates name the CA as issuer.
        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name(cert.subject())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = params.self_signed(&key)?;
        Ok(Self {
            cert_der: cert_der.clone(),
            issuer,
            key,
            self_signed,
        })
    }

    /// The CA certificate, PEM-encoded (for the node's `TTK_CA_ROOTS`).
    pub fn cert_pem(&self) -> String {
        pem(std::slice::from_ref(&self.cert_der))
    }

    /// The CA private key, PEM-encoded (PKCS#8).
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    /// The CA certificate, DER-encoded.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// Issues a certificate for the node presenting `ra_tls_cert`: same SubjectPublicKeyInfo,
    /// same attestation extension ([`ATTESTATION_OID`]) byte for byte, same validity period,
    /// naming [`CERT_DNS_NAME`]. Returns the chain to send to `POST /certificate` (leaf first,
    /// then the CA certificate unless it is a root).
    ///
    /// Only issue for a certificate whose Evidence has been appraised (see [`authorize`]).
    pub fn issue(
        &self,
        ra_tls_cert: &CertificateDer<'_>,
    ) -> Result<Vec<CertificateDer<'static>>, BoxError> {
        let (_, cert) = X509Certificate::from_der(ra_tls_cert)
            .map_err(|e| format!("malformed RA-TLS certificate: {e}"))?;
        let extension = cert
            .extensions()
            .iter()
            .find(|ext| {
                ext.oid
                    .iter()
                    .into_iter()
                    .flatten()
                    .eq(ATTESTATION_OID.iter().copied())
            })
            .ok_or("RA-TLS certificate has no attestation extension")?;
        let public_key = NodePublicKey::from_spki(cert.public_key())?;

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![SanType::DnsName(CERT_DNS_NAME.try_into()?)];
        params.not_before = cert.validity().not_before.to_datetime();
        params.not_after = cert.validity().not_after.to_datetime();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                ATTESTATION_OID,
                extension.value.to_vec(),
            ));
        let leaf = params.signed_by(&public_key, &self.issuer, &self.key)?;

        let (_, issued) = X509Certificate::from_der(leaf.der())
            .map_err(|e| format!("issued certificate: {e}"))?;
        if issued.public_key().raw != cert.public_key().raw {
            return Err("issued certificate does not reproduce the RA-TLS public key".into());
        }

        let mut chain = vec![leaf.der().clone()];
        if !self.self_signed {
            chain.push(self.cert_der.clone());
        }
        Ok(chain)
    }
}

/// What [`authorize`] accepts.
#[derive(Clone, Default)]
pub struct AuthorizeOptions {
    /// Accept mock attestation (for local development only).
    pub allow_mock: bool,
    /// Accepted Nitro images; `None` = this crate's [`FileImageTrustStore::builtin`].
    pub images: Option<FileImageTrustStore>,
}

/// Attests the node at `addr`, checks fresh Evidence for a random nonce, issues a certificate
/// for its RA-TLS key with `ca` and installs it with `POST /certificate`. Returns the installed
/// chain.
pub async fn authorize(
    addr: SocketAddr,
    server_name: &str,
    ca: &CertificateAuthority,
    options: &AuthorizeOptions,
) -> Result<Vec<CertificateDer<'static>>, BoxError> {
    let images = options
        .images
        .clone()
        .unwrap_or_else(FileImageTrustStore::builtin);
    let policy = Policy {
        allow_mock: options.allow_mock,
        allow_debug: false,
    };
    let mut verifier = EnclaveCertVerifier::new().with_image_trust_store(images.clone());
    if options.allow_mock {
        verifier = verifier.allow_mock();
    }

    let client = TtkClient::connect_with_verifier(addr, server_name, verifier.clone())
        .await
        .map_err(|e| format!("connecting to {addr}: {e}"))?;
    let result = authorize_over(&client, &verifier, ca, &images, policy).await;
    let _ = client.close().await;
    result
}

/// [`authorize`] over an established RA-TLS connection verified by `verifier`.
async fn authorize_over(
    client: &TtkClient,
    verifier: &EnclaveCertVerifier,
    ca: &CertificateAuthority,
    images: &FileImageTrustStore,
    policy: Policy,
) -> Result<Vec<CertificateDer<'static>>, BoxError> {
    let ra_tls_cert = client
        .peer_cert()
        .ok_or("no RA-TLS certificate received")?
        .clone();
    let cert_evidence = verifier
        .verified_evidence()
        .ok_or("RA-TLS Evidence was not verified")?;
    info!(
        "RA-TLS certificate {} attested ({})",
        client.peer_cert_sha256_hex().unwrap_or_default(),
        cert_evidence.tee
    );

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let response = client
        .post(EVIDENCE_PATH, &nonce)
        .await
        .map_err(|e| format!("POST {EVIDENCE_PATH}: {e}"))?;
    if response.status != 200 {
        return Err(format!(
            "POST {EVIDENCE_PATH} answered {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )
        .into());
    }
    let cmw = STANDARD
        .decode(response.body.trim_ascii())
        .map_err(|e| format!("fresh Evidence is not base64: {e}"))?;
    let fresh = verify_fresh_evidence(&cmw, &nonce, &ra_tls_cert, &cert_evidence, images, policy)?;
    info!(
        "Fresh {} Evidence verified for nonce {} (certificate matches the TLS certificate)",
        fresh.tee,
        ttk_ra_client::hex_encode(&nonce)
    );

    let chain = ca.issue(&ra_tls_cert)?;
    let response = client
        .post(CERTIFICATE_PATH, pem(&chain).as_bytes())
        .await
        .map_err(|e| format!("POST {CERTIFICATE_PATH}: {e}"))?;
    if response.status != 204 {
        return Err(format!(
            "POST {CERTIFICATE_PATH} answered {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        )
        .into());
    }
    info!("Node accepted the CA-issued certificate");
    Ok(chain)
}

/// Checks the [`FreshEvidence`] `cmw` (CBOR CMW) from `POST /evidence` against the node's
/// RA-TLS certificate `ra_tls_cert` (from the TLS handshake) and its Evidence `cert_evidence`:
///
/// 1. the certificate in the response is `ra_tls_cert`, byte for byte;
/// 2. the Evidence is genuine under `policy` and bound to that certificate's key (as in
///    [`verifier::verify_evidence`]);
/// 3. it carries `nonce` (only AWS Nitro Evidence can);
/// 4. it has the same measurements as `cert_evidence`.
pub fn verify_fresh_evidence(
    cmw: &[u8],
    nonce: &[u8],
    ra_tls_cert: &CertificateDer<'_>,
    cert_evidence: &VerifiedEvidence,
    images: &dyn ImageTrustStore,
    policy: Policy,
) -> Result<VerifiedEvidence, String> {
    let fresh =
        FreshEvidence::from_cbor_bytes(cmw).map_err(|e| format!("invalid fresh Evidence: {e}"))?;
    if fresh.certificate != ra_tls_cert.as_ref() {
        return Err("fresh Evidence certificate differs from the TLS certificate".into());
    }

    let (_, cert) = X509Certificate::from_der(&fresh.certificate)
        .map_err(|e| format!("malformed fresh Evidence certificate: {e}"))?;
    let binding = Sha256::digest(cert.public_key().raw);
    let evidence = verifier::verify_evidence(
        &fresh.evidence.to_cbor_bytes(),
        &binding,
        UnixTime::now(),
        &TrustStore::builtin(),
        images,
        policy,
    )?;

    let doc_nonce = evidence.nitro.as_ref().and_then(|doc| doc.nonce.as_deref());
    if doc_nonce != Some(nonce) {
        return Err("fresh Evidence does not carry the nonce".into());
    }
    if evidence.tee != cert_evidence.tee || evidence.measurements != cert_evidence.measurements {
        return Err("fresh Evidence measurements differ from the RA-TLS certificate's".into());
    }
    Ok(evidence)
}

/// PEM encoding of `chain`.
pub fn pem(chain: &[CertificateDer<'_>]) -> String {
    chain
        .iter()
        .map(|cert| {
            let b64 = STANDARD.encode(cert);
            let lines: Vec<&str> = b64
                .as_bytes()
                .chunks(64)
                .map(|line| std::str::from_utf8(line).expect("base64 is ASCII"))
                .collect();
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                lines.join("\n")
            )
        })
        .collect()
}

/// A node's public key, as rcgen signs certificates for keys it does not hold.
struct NodePublicKey {
    /// The subjectPublicKey bits.
    key: Vec<u8>,
    /// The key's algorithm (only its SubjectPublicKeyInfo algorithm identifier is used).
    algorithm: &'static SignatureAlgorithm,
}

/// SubjectPublicKeyInfo algorithm identifiers.
mod oid {
    /// `id-ecPublicKey`.
    pub const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
    /// `prime256v1` (P-256).
    pub const P256: &str = "1.2.840.10045.3.1.7";
    /// `secp384r1` (P-384).
    pub const P384: &str = "1.3.132.0.34";
    /// `id-Ed25519`.
    pub const ED25519: &str = "1.3.101.112";
}

impl NodePublicKey {
    /// Reads a P-256, P-384 or Ed25519 key from `spki`.
    fn from_spki(spki: &x509_parser::x509::SubjectPublicKeyInfo<'_>) -> Result<Self, BoxError> {
        let alg = spki.algorithm.algorithm.to_id_string();
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|oid| oid.to_id_string());
        let algorithm = match (alg.as_str(), curve.as_deref()) {
            (oid::EC_PUBLIC_KEY, Some(oid::P256)) => &rcgen::PKCS_ECDSA_P256_SHA256,
            (oid::EC_PUBLIC_KEY, Some(oid::P384)) => &rcgen::PKCS_ECDSA_P384_SHA384,
            (oid::ED25519, None) => &rcgen::PKCS_ED25519,
            _ => return Err(format!("unsupported RA-TLS key algorithm {alg}").into()),
        };
        Ok(Self {
            key: spki.subject_public_key.data.to_vec(),
            algorithm,
        })
    }
}

impl PublicKeyData for NodePublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.key
    }

    fn algorithm(&self) -> &SignatureAlgorithm {
        self.algorithm
    }
}

/// Converts `name` to an rcgen name with the same attributes and string types, so it encodes
/// to the same bytes (one attribute per RDN, each type at most once).
fn distinguished_name(name: &X509Name<'_>) -> Result<DistinguishedName, BoxError> {
    let mut dn = DistinguishedName::new();
    for rdn in name.iter() {
        let [attr] = rdn.iter().collect::<Vec<_>>()[..] else {
            return Err("CA subject has a multi-valued RDN".into());
        };
        let arcs: Vec<u64> = attr
            .attr_type()
            .iter()
            .ok_or("CA subject has an unsupported attribute type")?
            .collect();
        let ty = DnType::CustomDnType(arcs);
        if dn.get(&ty).is_some() {
            return Err("CA subject repeats an attribute type".into());
        }
        let value = attr.attr_value();
        let text = std::str::from_utf8(value.data)
            .map_err(|_| "CA subject has a non-UTF-8 attribute")?
            .to_string();
        let value = match value.tag() {
            Tag::Utf8String => DnValue::Utf8String(text),
            Tag::PrintableString => DnValue::PrintableString(text.try_into()?),
            Tag::Ia5String => DnValue::Ia5String(text.try_into()?),
            Tag::TeletexString => DnValue::TeletexString(text.try_into()?),
            tag => return Err(format!("CA subject has an unsupported string type {tag}").into()),
        };
        dn.push(ty, value);
    }
    Ok(dn)
}
