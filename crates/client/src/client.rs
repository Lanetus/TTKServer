//! TTKServer HTTP/3 (QUIC) client implementation.
//!
//! Connects to TTKServer running inside an AWS Nitro Enclave (or local testing environment)
//! over QUIC and HTTP/3 (RFC 9114).
//!
//! Handles:
//! - QUIC transport negotiation via `quinn` with ALPN `h3`
//! - RA-TLS verification of the enclave's ephemeral self-signed certificate: the embedded
//!   TEE evidence (AWS Nitro, AMD SEV-SNP, Intel TDX or SGX) is verified against the vendor's
//!   root and must bind to the SHA-256 of the certificate's public key
//! - Sending HTTP/3 requests and receiving responses using `h3` and `h3-quinn`

pub use crate::verifier::nitro::AttestationDocument;
use crate::verifier::{self, Policy, TrustStore, VerifiedEvidence};
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri};
use bytes::Buf;
use log::{debug, info};
use quinn::Endpoint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::Error as RustlsError;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ttk_core::server::ATTESTATION_OID;
pub use ttk_core::server::PARENT_CID;
use x509_parser::prelude::*;

/// Custom certificate verifier for Remote Attestation TLS (RA-TLS).
///
/// The server presents an ephemeral self-signed certificate that carries an EAT with nested
/// TEE evidence (AWS Nitro, AMD SEV-SNP, Intel TDX or Intel SGX) in a custom X.509 extension.
/// Instead of a Web PKI CA chain, [`verify_server_cert`](ServerCertVerifier::verify_server_cert)
/// checks:
///
/// 1. the certificate itself: well-formed, within its validity period, correctly self-signed;
/// 2. the evidence: vendor signature chain up to a root in the [`TrustStore`] (see
///    [`crate::verifier`]), and that the TEE is not in debug mode;
/// 3. the binding: the evidence's report data equals the SHA-256 of the certificate's
///    SubjectPublicKeyInfo;
/// 4. any expected measurements configured with
///    [`with_expected_measurement`](Self::with_expected_measurement) or
///    [`with_expected_pcr`](Self::with_expected_pcr).
///
/// The TLS handshake signature is verified against the same certificate, proving the peer holds
/// the attested key.
#[derive(Debug, Clone)]
pub struct EnclaveCertVerifier {
    received_cert: Arc<Mutex<Option<CertificateDer<'static>>>>,
    verified_evidence: Arc<Mutex<Option<VerifiedEvidence>>>,
    expected_measurements: BTreeMap<String, Vec<u8>>,
    policy: Policy,
    trust: Arc<TrustStore>,
    algorithms: WebPkiSupportedAlgorithms,
}

/// Construction, policy configuration and inspection of the verifier.
impl EnclaveCertVerifier {
    /// Creates a strict verifier: only genuine, vendor-signed evidence from a non-debug TEE is
    /// accepted, checked against the built-in vendor roots.
    pub fn new() -> Self {
        Self {
            received_cert: Arc::new(Mutex::new(None)),
            verified_evidence: Arc::new(Mutex::new(None)),
            expected_measurements: BTreeMap::new(),
            policy: Policy::default(),
            trust: Arc::new(TrustStore::builtin()),
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }

    /// Requires the evidence measurement `name` to equal `value`.
    ///
    /// See [`VerifiedEvidence::measurements`] for the names each TEE reports. Evidence that
    /// lacks the measurement (e.g. from a different TEE) is rejected.
    pub fn with_expected_measurement(
        mut self,
        name: impl Into<String>,
        value: impl Into<Vec<u8>>,
    ) -> Self {
        self.expected_measurements
            .insert(name.into().to_lowercase(), value.into());
        self
    }

    /// Requires PCR `index` of a Nitro attestation document to equal `value`.
    pub fn with_expected_pcr(self, index: usize, value: impl Into<Vec<u8>>) -> Self {
        self.with_expected_measurement(format!("pcr{index}"), value)
    }

    /// Replaces the built-in vendor roots, e.g. for testing or private deployments.
    pub fn with_trust_store(mut self, trust: TrustStore) -> Self {
        self.trust = Arc::new(trust);
        self
    }

    /// Accepts unsigned mock attestation documents (for local development only).
    ///
    /// Skips the Nitro COSE signature and AWS certificate-chain checks; the certificate checks,
    /// the key binding and the measurement checks still apply. Never enable this in production.
    pub fn allow_mock(mut self) -> Self {
        self.policy.allow_mock = true;
        self
    }

    /// Accepts evidence from TEEs running in debug mode, whose memory is not confidential.
    pub fn allow_debug(mut self) -> Self {
        self.policy.allow_debug = true;
        self
    }

    /// Retrieve the server certificate DER bytes captured during a successful verification.
    pub fn received_certificate(&self) -> Option<CertificateDer<'static>> {
        self.received_cert
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Returns the evidence accepted during the last successful verification.
    pub fn verified_evidence(&self) -> Option<VerifiedEvidence> {
        self.verified_evidence
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Returns the Nitro attestation document accepted during the last successful verification,
    /// if the server attested with AWS Nitro.
    pub fn verified_attestation(&self) -> Option<AttestationDocument> {
        self.verified_evidence().and_then(|evidence| evidence.nitro)
    }

    /// Runs all certificate and attestation checks on `end_entity` at time `now`.
    fn verify(
        &self,
        end_entity: &CertificateDer<'_>,
        now: UnixTime,
    ) -> Result<VerifiedEvidence, String> {
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

        // 2 & 3. The embedded evidence, bound to this certificate's public key
        let eat_bytes = extract_attestation_doc(end_entity.as_ref())
            .map_err(|e| format!("missing attestation extension: {e}"))?;
        let binding = Sha256::digest(cert.public_key().raw);
        let evidence =
            verifier::verify_evidence(&eat_bytes, &binding, now, &self.trust, self.policy)?;

        // 4. Reference values
        for (name, expected) in &self.expected_measurements {
            match evidence.measurements.get(name) {
                Some(actual) if actual == expected => {}
                Some(_) => {
                    return Err(format!(
                        "{} does not match the expected value",
                        name.to_uppercase()
                    ))
                }
                None => {
                    return Err(format!(
                        "{} evidence has no measurement '{name}'",
                        evidence.tee
                    ))
                }
            }
        }

        Ok(evidence)
    }
}

/// Default is equivalent to [`EnclaveCertVerifier::new`].
impl Default for EnclaveCertVerifier {
    /// Creates a new strict verifier.
    fn default() -> Self {
        Self::new()
    }
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
        let evidence = self
            .verify(end_entity, now)
            .map_err(|e| RustlsError::General(format!("RA-TLS verification failed: {e}")))?;
        debug!("{} attestation verified", evidence.tee);

        if let Ok(mut guard) = self.received_cert.lock() {
            *guard = Some(end_entity.clone().into_owned());
        }
        if let Ok(mut guard) = self.verified_evidence.lock() {
            *guard = Some(evidence);
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

/// How a [`TtkClient`] reaches the server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClientTransport {
    /// A regular UDP socket.
    #[default]
    Udp,
    /// From inside an enclave: through the parent's `vsock-proxy` at vsock `cid`:`port`, which
    /// sends the datagrams on to the server over UDP (see `ttk_core::vsock`). Linux only.
    Vsock {
        /// CID of the proxy, normally [`PARENT_CID`].
        cid: u32,
        /// vsock port the proxy accepts outbound connections on.
        port: u32,
    },
}

/// HTTP/3 client for communicating with TTKServer over QUIC.
///
/// Requests take `&self` and run as independent HTTP/3 streams, so one client (e.g. shared
/// behind an `Arc`) can carry concurrent requests over the same QUIC connection.
pub struct TtkClient {
    endpoint: Endpoint,
    connection: quinn::Connection,
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
        Self::connect_over(ClientTransport::Udp, server_addr, server_name, verifier).await
    }

    /// Connect to the TTKServer over `transport`, using a custom attestation `verifier` policy.
    pub async fn connect_over(
        transport: ClientTransport,
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

        let mut endpoint = client_endpoint(transport, server_addr)?;
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
        let h3_quic_conn = h3_quinn::Connection::new(connection.clone());
        let (mut driver, send_request) = h3::client::new(h3_quic_conn).await?;

        // Drive the HTTP/3 connection state machine in the background
        let driver_handle =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });

        Ok(Self {
            endpoint,
            connection,
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

    /// Returns `true` once the QUIC connection has closed (e.g. idle timeout or peer close);
    /// a closed client can no longer send requests.
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
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
        &self,
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
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<ClientResponse, Box<dyn std::error::Error + Send + Sync>> {
        self.post_with_content_type(path, "application/octet-stream", body)
            .await
    }

    /// Send an HTTP/3 POST request with `value` serialized as a JSON body to the specified path.
    pub async fn post_json<T: Serialize + ?Sized>(
        &self,
        path: &str,
        value: &T,
    ) -> Result<ClientResponse, Box<dyn std::error::Error + Send + Sync>> {
        let body = serde_json::to_vec(value)?;
        self.post_with_content_type(path, "application/json", &body)
            .await
    }

    /// Send an HTTP/3 POST request with the given body and `Content-Type`.
    async fn post_with_content_type(
        &self,
        path: &str,
        content_type: &str,
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
            .header("Content-Type", content_type)
            .header("Content-Length", body.len().to_string())
            .body(())?;

        self.send(req, Some(body)).await
    }

    /// Send an HTTP/3 request with an optional payload and receive the response.
    pub async fn send(
        &self,
        req: Request<()>,
        payload: Option<&[u8]>,
    ) -> Result<ClientResponse, Box<dyn std::error::Error + Send + Sync>> {
        debug!("Sending HTTP/3 request: {} {}", req.method(), req.uri());
        let mut stream = self.send_request.clone().send_request(req).await?;

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

/// Creates a client endpoint on `transport` able to reach `server_addr`.
fn client_endpoint(
    transport: ClientTransport,
    server_addr: SocketAddr,
) -> Result<Endpoint, Box<dyn std::error::Error + Send + Sync>> {
    match transport {
        ClientTransport::Udp => {
            // Bind client endpoint to an arbitrary local UDP port
            let bind_addr: SocketAddr = if server_addr.is_ipv6() {
                "[::]:0".parse()?
            } else {
                "0.0.0.0:0".parse()?
            };
            Ok(Endpoint::client(bind_addr)?)
        }
        #[cfg(target_os = "linux")]
        ClientTransport::Vsock { cid, port } => {
            let runtime = quinn::default_runtime().ok_or("no async runtime found")?;
            Ok(Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                None,
                Arc::new(ttk_core::vsock::VsockOutboundSocket::new(cid, port)),
                runtime,
            )?)
        }
        #[cfg(not(target_os = "linux"))]
        ClientTransport::Vsock { .. } => Err("vsock is only available on Linux".into()),
    }
}

/// Helper function to format bytes as a hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
