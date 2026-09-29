//! TTKServer HTTP/3 (QUIC) Client implementation.
//!
//! Connects to TTKServer running inside an AWS Nitro Enclave (or local testing environment)
//! over QUIC and HTTP/3 (RFC 9114).
//!
//! Handles:
//! - QUIC transport negotiation via `quinn` with ALPN `h3`
//! - RA-TLS verification of the enclave's ephemeral self-signed certificate: the embedded
//!   Nitro attestation document is verified against the AWS Nitro root and must bind
//!   (via `user_data`) to the SHA-256 of the certificate's public key
//! - Sending HTTP/3 requests and receiving responses using `h3` and `h3-quinn`

use axum::http::{HeaderMap, Method, Request, StatusCode, Uri};
use bytes::Buf;
use ciborium::Value;
use log::{debug, info};
use quinn::Endpoint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::Error as RustlsError;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ttk_server::eat::EatClaimsSet;
use x509_parser::prelude::*;

/// SHA-256 fingerprint of the AWS Nitro Enclaves root certificate (G1), as published in the
/// AWS Nitro Enclaves documentation. The first certificate of every attestation document's
/// `cabundle` must match it.
const AWS_NITRO_ROOT_SHA256: [u8; 32] = [
    0x64, 0x1a, 0x03, 0x21, 0xa3, 0xe2, 0x44, 0xef, 0xe4, 0x56, 0x46, 0x31, 0x95, 0xd6, 0x06, 0x31,
    0x7e, 0xd7, 0xcd, 0xcc, 0x3c, 0x17, 0x56, 0xe0, 0x98, 0x93, 0xf3, 0xc6, 0x8f, 0x79, 0xbb, 0x5b,
];

/// Label of the EAT submodule carrying the raw Nitro COSE_Sign1 document (see `nitro_doc.rs`).
const NITRO_SUBMOD_NAME: &str = "aws_nitro";

/// COSE algorithm identifier for ECDSA P-384 with SHA-384 (RFC 9053).
const COSE_ALG_ES384: i128 = -35;

/// Tolerated clock skew when checking that the evidence is not from the future.
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

/// Custom certificate verifier for Remote Attestation TLS (RA-TLS).
///
/// The server presents an ephemeral self-signed certificate that carries an EAT with a nested
/// AWS Nitro attestation document in a custom X.509 extension. Instead of a Web PKI CA chain,
/// [`verify_server_cert`](ServerCertVerifier::verify_server_cert) checks:
///
/// 1. the certificate itself: well-formed, within its validity period, correctly self-signed;
/// 2. the attestation document: COSE_Sign1 signature, certificate chain up to the pinned AWS
///    Nitro root, and document sanity;
/// 3. the binding: `user_data` equals the SHA-256 of the certificate's SubjectPublicKeyInfo;
/// 4. any expected PCR values configured with [`with_expected_pcr`](Self::with_expected_pcr).
///
/// The TLS handshake signature is verified against the same certificate, proving the peer holds
/// the attested key.
#[derive(Debug, Clone)]
pub struct EnclaveCertVerifier {
    received_cert: Arc<Mutex<Option<CertificateDer<'static>>>>,
    verified_attestation: Arc<Mutex<Option<AttestationDocument>>>,
    expected_pcrs: BTreeMap<usize, Vec<u8>>,
    allow_mock: bool,
    algorithms: WebPkiSupportedAlgorithms,
}

/// Construction, policy configuration and inspection of the verifier.
impl EnclaveCertVerifier {
    /// Creates a strict verifier: only genuine, AWS-signed Nitro attestation documents are accepted.
    pub fn new() -> Self {
        Self {
            received_cert: Arc::new(Mutex::new(None)),
            verified_attestation: Arc::new(Mutex::new(None)),
            expected_pcrs: BTreeMap::new(),
            allow_mock: false,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }

    /// Requires PCR `index` of the attestation document to equal `value`.
    pub fn with_expected_pcr(mut self, index: usize, value: impl Into<Vec<u8>>) -> Self {
        self.expected_pcrs.insert(index, value.into());
        self
    }

    /// Accepts unsigned mock attestation documents (for local development only).
    ///
    /// Skips the COSE signature and AWS certificate-chain checks; the certificate checks, the
    /// key binding and the PCR checks still apply. Never enable this in production.
    pub fn allow_mock(mut self) -> Self {
        self.allow_mock = true;
        self
    }

    /// Retrieve the server certificate DER bytes captured during a successful verification.
    pub fn received_certificate(&self) -> Option<CertificateDer<'static>> {
        self.received_cert
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Returns the attestation document accepted during the last successful verification.
    pub fn verified_attestation(&self) -> Option<AttestationDocument> {
        self.verified_attestation
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Runs all certificate and attestation checks on `end_entity` at time `now`.
    fn verify(
        &self,
        end_entity: &CertificateDer<'_>,
        now: UnixTime,
    ) -> Result<AttestationDocument, String> {
        // 1. The certificate itself
        let (_, cert) = X509Certificate::from_der(end_entity.as_ref())
            .map_err(|e| format!("malformed certificate: {e}"))?;
        let now_secs = now.as_secs() as i64;
        if now_secs < cert.validity().not_before.timestamp() {
            return Err("certificate is not valid yet".into());
        }
        if now_secs > cert.validity().not_after.timestamp() {
            return Err("certificate has expired".into());
        }
        cert.verify_signature(None)
            .map_err(|e| format!("certificate is not correctly self-signed: {e}"))?;

        // 2. The attestation document embedded in the certificate
        let eat_bytes = extract_attestation_doc(end_entity.as_ref())
            .map_err(|e| format!("missing attestation extension: {e}"))?;
        let nitro_doc = nitro_doc_from_eat(&eat_bytes)?;
        let cose = CoseSign1Parts::parse(&nitro_doc)?;
        let doc: AttestationDocument = ciborium::from_reader(cose.payload.as_slice())
            .map_err(|e| format!("invalid attestation document payload: {e}"))?;
        doc.check_sanity()?;

        if doc.timestamp > (now.as_secs() + MAX_CLOCK_SKEW.as_secs()) * 1000 {
            return Err("attestation document timestamp is in the future".into());
        }

        if self.allow_mock {
            log::warn!("Mock attestation allowed: skipping COSE signature and AWS chain checks");
        } else {
            self.verify_chain(&doc)?;
            cose.verify_signature(&doc.certificate)?;
        }

        // 3. Binding between the attestation document and this TLS key
        let expected = Sha256::digest(cert.public_key().raw);
        if doc.user_data.as_deref() != Some(expected.as_slice()) {
            return Err("attestation user_data does not match the certificate's public key".into());
        }

        // 4. Reference values
        for (index, expected) in &self.expected_pcrs {
            if doc.pcrs.get(index) != Some(expected) {
                return Err(format!("PCR{index} does not match the expected value"));
            }
        }

        Ok(doc)
    }

    /// Verifies the document's signing certificate up to the pinned AWS Nitro root.
    ///
    /// The chain is validated at the document's timestamp: Nitro signing certificates are
    /// short-lived, while the server reuses one document for the lifetime of its TLS certificate.
    fn verify_chain(&self, doc: &AttestationDocument) -> Result<(), String> {
        let root = doc
            .cabundle
            .first()
            .ok_or("attestation cabundle is empty")?;
        if Sha256::digest(root).as_slice() != AWS_NITRO_ROOT_SHA256 {
            return Err("attestation cabundle is not rooted at the AWS Nitro root CA".into());
        }

        let root_der = CertificateDer::from(root.as_slice());
        let anchor = webpki::anchor_from_trusted_cert(&root_der)
            .map_err(|e| format!("invalid AWS Nitro root certificate: {e:?}"))?;
        let intermediates: Vec<CertificateDer<'_>> = doc.cabundle[1..]
            .iter()
            .map(|c| CertificateDer::from(c.as_slice()))
            .collect();
        let leaf_der = CertificateDer::from(doc.certificate.as_slice());
        let leaf = webpki::EndEntityCert::try_from(&leaf_der)
            .map_err(|e| format!("invalid attestation signing certificate: {e:?}"))?;

        leaf.verify_for_usage(
            self.algorithms.all,
            &[anchor],
            &intermediates,
            UnixTime::since_unix_epoch(Duration::from_millis(doc.timestamp)),
            AnyKeyUsage,
            None,
            None,
        )
        .map_err(|e| format!("attestation certificate chain is invalid: {e:?}"))?;
        Ok(())
    }
}

/// EKU policy for the attestation signing chain: it signs documents, not TLS sessions, so no
/// particular Extended Key Usage is required.
struct AnyKeyUsage;

/// Accepts any (well-formed) Extended Key Usage extension.
impl webpki::ExtendedKeyUsageValidator for AnyKeyUsage {
    /// Only rejects a malformed EKU extension.
    fn validate(&self, iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for eku in iter {
            eku?;
        }
        Ok(())
    }
}

/// Default is equivalent to [`EnclaveCertVerifier::new`].
impl Default for EnclaveCertVerifier {
    /// Creates a new strict verifier.
    fn default() -> Self {
        Self::new()
    }
}

/// OID of the X.509 extension carrying the attestation document (placeholder, not a registered PEN).
const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

/// Decoded payload of an AWS Nitro attestation document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub module_id: String,
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: BTreeMap<usize, Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    #[serde(default)]
    pub public_key: Option<Vec<u8>>,
    #[serde(default)]
    pub user_data: Option<Vec<u8>>,
    #[serde(default)]
    pub nonce: Option<Vec<u8>>,
}

/// Structural checks on a decoded attestation document.
impl AttestationDocument {
    /// Checks the mandatory fields per the AWS Nitro Enclaves attestation document spec.
    fn check_sanity(&self) -> Result<(), String> {
        if self.module_id.is_empty() {
            return Err("attestation module_id is empty".into());
        }
        if self.digest != "SHA384" {
            return Err(format!("unsupported attestation digest {}", self.digest));
        }
        if self.pcrs.is_empty() || self.pcrs.len() > 32 {
            return Err("attestation document has an invalid number of PCRs".into());
        }
        if self.pcrs.values().any(|v| ![32, 48, 64].contains(&v.len())) {
            return Err("attestation document has a PCR of invalid length".into());
        }
        if self.certificate.is_empty() {
            return Err("attestation signing certificate is empty".into());
        }
        Ok(())
    }
}

/// The parts of a COSE_Sign1 structure (RFC 9052) needed for verification.
struct CoseSign1Parts {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

/// Parsing and signature verification of COSE_Sign1 documents.
impl CoseSign1Parts {
    /// Parses a tagged (tag 18) or untagged COSE_Sign1 array.
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Value =
            ciborium::from_reader(bytes).map_err(|e| format!("invalid COSE_Sign1 CBOR: {e}"))?;
        let items = match value {
            Value::Tag(18, inner) => match *inner {
                Value::Array(items) => items,
                _ => return Err("COSE_Sign1 tag does not contain an array".into()),
            },
            Value::Array(items) => items,
            _ => return Err("attestation document is not a COSE_Sign1 structure".into()),
        };
        let [protected, _unprotected, payload, signature] = <[Value; 4]>::try_from(items)
            .map_err(|_| "COSE_Sign1 structure must have 4 elements".to_string())?;
        let bytes_of = |v: Value, what: &str| match v {
            Value::Bytes(b) => Ok(b),
            _ => Err(format!("COSE_Sign1 {what} is not a byte string")),
        };
        Ok(Self {
            protected: bytes_of(protected, "protected header")?,
            payload: bytes_of(payload, "payload")?,
            signature: bytes_of(signature, "signature")?,
        })
    }

    /// Verifies the ES384 signature with the public key of `signing_cert_der`.
    fn verify_signature(&self, signing_cert_der: &[u8]) -> Result<(), String> {
        let header: Value = ciborium::from_reader(self.protected.as_slice())
            .map_err(|e| format!("invalid COSE protected header: {e}"))?;
        let alg = header.as_map().and_then(|m| {
            m.iter().find_map(|(k, v)| match (k, v) {
                (Value::Integer(k), Value::Integer(v)) if i128::from(*k) == 1 => {
                    Some(i128::from(*v))
                }
                _ => None,
            })
        });
        if alg != Some(COSE_ALG_ES384) {
            return Err("attestation document is not signed with ES384".into());
        }

        // Sig_structure = ["Signature1", protected, external_aad, payload] (RFC 9052 §4.4)
        let sig_structure = Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(self.protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(self.payload.clone()),
        ]);
        let mut to_verify = Vec::new();
        ciborium::into_writer(&sig_structure, &mut to_verify)
            .map_err(|e| format!("failed to encode COSE Sig_structure: {e}"))?;

        let (_, signing_cert) = X509Certificate::from_der(signing_cert_der)
            .map_err(|e| format!("malformed attestation signing certificate: {e}"))?;
        let public_key = signing_cert.public_key().subject_public_key.data.as_ref();
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P384_SHA384_FIXED,
            public_key,
        )
        .verify(&to_verify, &self.signature)
        .map_err(|_| "attestation document signature is invalid".to_string())
    }
}

/// Extracts the raw Nitro COSE_Sign1 document from the `submods` of an EAT claims-set.
fn nitro_doc_from_eat(eat_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let claims =
        EatClaimsSet::from_bytes(eat_bytes).map_err(|e| format!("invalid EAT token: {e}"))?;
    let submods = claims.submods.ok_or("EAT token has no submods")?;
    let entries = submods.into_map().map_err(|_| "EAT submods is not a map")?;
    entries
        .into_iter()
        .find(|(k, _)| k.as_text() == Some(NITRO_SUBMOD_NAME))
        .and_then(|(_, v)| v.into_bytes().ok())
        .ok_or_else(|| format!("EAT token has no '{NITRO_SUBMOD_NAME}' submodule"))
}

/// RA-TLS verification: the server is trusted because of its attestation, not a CA chain.
impl ServerCertVerifier for EnclaveCertVerifier {
    /// Verifies the RA-TLS certificate and its embedded attestation document.
    ///
    /// The hostname is not checked: the server's identity is established by its attestation.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let doc = self
            .verify(end_entity, now)
            .map_err(|e| RustlsError::General(format!("RA-TLS verification failed: {e}")))?;
        debug!(
            "Attestation verified for module {} (timestamp {})",
            doc.module_id, doc.timestamp
        );

        if let Ok(mut guard) = self.received_cert.lock() {
            *guard = Some(end_entity.clone().into_owned());
        }
        if let Ok(mut guard) = self.verified_attestation.lock() {
            *guard = Some(doc);
        }
        Ok(ServerCertVerified::assertion())
    }

    /// Verifies the TLS 1.2 handshake signature with the server certificate's key.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    /// Verifies the TLS 1.3 handshake signature with the server certificate's key.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    /// Lists the signature schemes the verifier accepts.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Extract raw attestation bytes from the leaf certificate
pub fn extract_attestation_doc(
    cert_der: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // 1. Parse DER bytes into an X509 certificate
    let (_, cert) = X509Certificate::from_der(cert_der)?;

    // 2. Search for the custom extension by OID
    for ext in cert.extensions() {
        if ext
            .oid
            .iter()
            .into_iter()
            .flatten()
            .eq(ATTESTATION_OID.iter().copied())
        {
            let raw_value = ext.value;

            // 3. Un-wrap ASN.1 OCTET STRING header if present (Tag 0x04)
            if !raw_value.is_empty() && raw_value[0] == 0x04 {
                let (_, octet_string) = der_parser::der::parse_der_octetstring(raw_value)?;
                return Ok(octet_string.as_slice()?.to_vec());
            }

            return Ok(raw_value.to_vec());
        }
    }

    Err("Attestation extension OID not found in certificate".into())
}

/// Represents the response received from the HTTP/3 server.
#[derive(Debug, Clone)]
pub struct ClientResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// Accessors for the response body.
impl ClientResponse {
    /// Return the response body interpreted as a UTF-8 string.
    pub fn text(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.body.clone())
    }
}

/// HTTP/3 client for communicating with TTKServer over QUIC.
pub struct TtkClient {
    endpoint: Endpoint,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, axum::body::Bytes>,
    driver_handle: tokio::task::JoinHandle<Result<(), h3::Error>>,
    server_addr: SocketAddr,
    server_name: String,
    peer_cert: Option<CertificateDer<'static>>,
}

/// Connecting to the server and issuing requests.
impl TtkClient {
    /// Connect to the TTKServer at the specified `server_addr` with the given SNI `server_name`,
    /// accepting only genuine AWS Nitro attestation (see [`EnclaveCertVerifier::new`]).
    pub async fn connect(
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::connect_with_verifier(server_addr, server_name, EnclaveCertVerifier::new()).await
    }

    /// Connect to the TTKServer using a custom attestation `verifier` policy.
    pub async fn connect_with_verifier(
        server_addr: SocketAddr,
        server_name: &str,
        verifier: EnclaveCertVerifier,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Ensure the default crypto provider is installed
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert_verifier = Arc::new(verifier);

        let mut client_crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(cert_verifier.clone())
            .with_no_client_auth();

        // Negotiate HTTP/3 ALPN
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];

        let quic_client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
        ));

        // Bind client endpoint to an arbitrary local UDP port
        let bind_addr: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse()?
        } else {
            "0.0.0.0:0".parse()?
        };
        let mut endpoint = Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(quic_client_config);

        info!(
            "Initiating QUIC connection to {} ({})",
            server_addr, server_name
        );
        let connecting = endpoint.connect(server_addr, server_name)?;
        let connection = connecting.await?;
        info!("QUIC connection established with {}", server_addr);

        let peer_cert = cert_verifier.received_certificate();
        if let Some(ref cert) = peer_cert {
            let hash = Sha256::digest(cert.as_ref());
            info!(
                "Server Certificate SHA-256 fingerprint: {}",
                hex_encode(&hash)
            );
        }

        // Establish HTTP/3 on top of the QUIC connection
        let h3_quic_conn = h3_quinn::Connection::new(connection);
        let (mut driver, send_request) = h3::client::new(h3_quic_conn).await?;

        // Drive the HTTP/3 connection state machine in the background
        let driver_handle =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

        Ok(Self {
            endpoint,
            send_request,
            driver_handle,
            server_addr,
            server_name: server_name.to_string(),
            peer_cert,
        })
    }

    /// Return the server address this client is connected to.
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Return the SNI server name configured for this client.
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Retrieve the peer's certificate DER bytes if captured.
    pub fn peer_cert(&self) -> Option<&CertificateDer<'static>> {
        self.peer_cert.as_ref()
    }

    /// Retrieve the SHA-256 digest of the peer certificate.
    pub fn peer_cert_sha256(&self) -> Option<[u8; 32]> {
        self.peer_cert.as_ref().map(|c| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&Sha256::digest(c.as_ref()));
            arr
        })
    }

    /// Retrieve the SHA-256 digest of the peer certificate as a hex string.
    pub fn peer_cert_sha256_hex(&self) -> Option<String> {
        self.peer_cert_sha256().map(|h| hex_encode(&h))
    }

    /// Send an HTTP/3 GET request to the specified path.
    pub async fn get(
        &mut self,
        path: &str,
    ) -> Result<ClientResponse, Box<dyn std::error::Error + Send + Sync>> {
        let uri: Uri = if path.starts_with('/') {
            format!("https://{}{}", self.server_name, path).parse()?
        } else {
            format!("https://{}/{}", self.server_name, path).parse()?
        };

        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("Host", &self.server_name)
            .header("User-Agent", "TTKClient/0.6.0")
            .header("Accept", "*/*")
            .body(())?;

        self.send(req, None).await
    }

    /// Send an HTTP/3 POST request with the given body to the specified path.
    pub async fn post(
        &mut self,
        path: &str,
        body: &[u8],
    ) -> Result<ClientResponse, Box<dyn std::error::Error + Send + Sync>> {
        let uri: Uri = if path.starts_with('/') {
            format!("https://{}{}", self.server_name, path).parse()?
        } else {
            format!("https://{}/{}", self.server_name, path).parse()?
        };

        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("Host", &self.server_name)
            .header("User-Agent", "TTKClient/0.6.0")
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", body.len().to_string())
            .body(())?;

        self.send(req, Some(body)).await
    }

    /// Send an HTTP/3 request with an optional payload and receive the response.
    pub async fn send(
        &mut self,
        req: Request<()>,
        payload: Option<&[u8]>,
    ) -> Result<ClientResponse, Box<dyn std::error::Error + Send + Sync>> {
        debug!("Sending HTTP/3 request: {} {}", req.method(), req.uri());
        let mut stream = self.send_request.send_request(req).await?;

        if let Some(data) = payload {
            if !data.is_empty() {
                stream
                    .send_data(axum::body::Bytes::copy_from_slice(data))
                    .await?;
            }
        }
        stream.finish().await?;

        let response = stream.recv_response().await?;
        let status = response.status();
        let headers = response.headers().clone();

        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            while chunk.has_remaining() {
                let slice = chunk.chunk();
                body.extend_from_slice(slice);
                let len = slice.len();
                chunk.advance(len);
            }
        }

        Ok(ClientResponse {
            status,
            headers,
            body,
        })
    }

    /// Close the client and wait for underlying QUIC streams and driver to settle.
    pub async fn close(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        drop(self.send_request);
        // Allow up to 1 second for the driver task to exit gracefully
        let _ = tokio::time::timeout(Duration::from_secs(1), self.driver_handle).await;
        self.endpoint.wait_idle().await;
        Ok(())
    }
}

/// Helper function to format bytes as a hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Parse command-line target or default to `127.0.0.1:4433`.
#[allow(dead_code)] // used by the `client` binary, which also compiles this file
fn parse_args() -> (SocketAddr, String, String) {
    let args: Vec<String> = std::env::args().collect();
    let mut server_addr_str =
        std::env::var("TTK_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:4433".to_string());
    let mut server_name =
        std::env::var("TTK_SERVER_NAME").unwrap_or_else(|_| "localhost".to_string());
    let mut path = "/".to_string();

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--help" || arg == "-h" {
            println!("Usage: client [OPTIONS] [URL]");
            println!();
            println!("Options:");
            println!("  -s, --server-name <NAME>  SNI server name (default: localhost)");
            println!("  -p, --path <PATH>         Request path (default: /)");
            println!("  -a, --addr <ADDR>         Server socket address (default: 127.0.0.1:4433)");
            println!("  -h, --help                Print help information");
            println!();
            println!("Examples:");
            println!("  client");
            println!("  client https://127.0.0.1:4433/hello");
            println!("  client --addr 127.0.0.1:4433 --server-name enclave.local --path /evidence");
            std::process::exit(0);
        } else if (arg == "--server-name" || arg == "-s") && i + 1 < args.len() {
            i += 1;
            server_name = args[i].clone();
        } else if (arg == "--path" || arg == "-p") && i + 1 < args.len() {
            i += 1;
            path = args[i].clone();
        } else if (arg == "--addr" || arg == "-a") && i + 1 < args.len() {
            i += 1;
            server_addr_str = args[i].clone();
        } else if !arg.starts_with('-') {
            // Positional URL or address
            if let Ok(uri) = arg.parse::<Uri>() {
                if let Some(host) = uri.host() {
                    let port = uri.port_u16().unwrap_or(4433);
                    server_addr_str = format!("{}:{}", host, port);
                    if host != "127.0.0.1" && host != "0.0.0.0" {
                        server_name = host.to_string();
                    }
                }
                if !uri.path().is_empty() {
                    path = uri.path().to_string();
                    if let Some(query) = uri.query() {
                        path.push('?');
                        path.push_str(query);
                    }
                }
            } else {
                server_addr_str = arg.clone();
            }
        }
        i += 1;
    }

    let server_addr: SocketAddr = server_addr_str
        .parse()
        .unwrap_or_else(|_| "127.0.0.1:4433".parse().unwrap());

    (server_addr, server_name, path)
}

/// Entry point for the `client` binary.
#[allow(dead_code)] // entry point for the `client` binary; unused when built as a lib module
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let (server_addr, server_name, path) = parse_args();

    println!("=================================================");
    println!("TTKServer HTTP/3 Client (RFC 9114)");
    println!("Connecting to: {} (SNI: {})", server_addr, server_name);
    println!("=================================================");

    let mut verifier = EnclaveCertVerifier::new();
    if std::env::var("TTK_ALLOW_MOCK_ATTESTATION").is_ok_and(|v| v == "1") {
        eprintln!("WARNING: accepting MOCK attestation (TTK_ALLOW_MOCK_ATTESTATION=1)");
        verifier = verifier.allow_mock();
    }

    let mut client =
        match TtkClient::connect_with_verifier(server_addr, &server_name, verifier).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to connect to TTKServer at {}: {}", server_addr, e);
                std::process::exit(1);
            }
        };

    if let Some(fingerprint) = client.peer_cert_sha256_hex() {
        println!("Server Certificate SHA-256 Fingerprint:");
        println!("  {}", fingerprint);
        println!("  (Attestation verified and bound to this certificate's key)");
    }

    println!("\n--> Sending GET {}", path);
    match client.get(&path).await {
        Ok(resp) => {
            println!("<-- Response Status: {}", resp.status);
            println!("<-- Headers:");
            for (name, val) in &resp.headers {
                println!("    {}: {}", name, val.to_str().unwrap_or("<binary>"));
            }
            match resp.text() {
                Ok(body_str) => println!("<-- Body:\n{}", body_str),
                Err(_) => println!("<-- Body (binary, {} bytes)", resp.body.len()),
            }
        }
        Err(e) => {
            eprintln!("Error sending request to {}: {}", path, e);
        }
    }

    // If default path "/" was queried, also test "/hello" endpoint
    if path == "/" {
        println!("\n--> Sending GET /hello");
        match client.get("/hello").await {
            Ok(resp) => {
                println!("<-- Response Status: {}", resp.status);
                if let Ok(body_str) = resp.text() {
                    println!("<-- Body:\n{}", body_str);
                }
            }
            Err(e) => {
                eprintln!("Error sending request to /hello: {}", e);
            }
        }
    }

    println!("\nClosing connection...");
    client.close().await?;
    println!("Connection closed successfully.");

    Ok(())
}
