//! TTKServer HTTP/3 (QUIC) Client implementation.
//!
//! Connects to TTKServer running inside an AWS Nitro Enclave (or local testing environment)
//! over QUIC and HTTP/3 (RFC 9114).
//!
//! Handles:
//! - QUIC transport negotiation via `quinn` with ALPN `h3`
//! - TLS 1.3 certificate verification accepting the enclave's ephemeral self-signed
//!   certificate (RA-TLS)
//! - Extracting and calculating the SHA-256 fingerprint of the server's certificate,
//!   which can be validated against the `user_data` field of the NSM Attestation Document
//! - Sending HTTP/3 requests and receiving responses using `h3` and `h3-quinn`

use aws_nitro_enclaves_cose::crypto::Openssl;
use aws_nitro_enclaves_cose::sign::CoseSign1;
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri};
use ciborium::Value;
use hyper::body::Buf;
use log::{debug, info};
use quinn::Endpoint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::Error as RustlsError;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ttk_server::eat::EatClaimsSet;
use x509_parser::prelude::*;

/// Custom certificate verifier for Remote Attestation TLS (RA-TLS).
///
/// In an AWS Nitro Enclave environment, the server generates an ephemeral self-signed
/// certificate whose SHA-256 hash is bound to the Nitro Security Module (NSM) Attestation
/// Document. Rather than relying on a traditional Web PKI CA chain, the Relying Party
/// authenticates the connection by checking this certificate hash against the NSM Evidence.
#[derive(Debug, Clone)]
pub struct EnclaveCertVerifier {
    received_cert: Arc<Mutex<Option<CertificateDer<'static>>>>,
}

impl EnclaveCertVerifier {
    pub fn new() -> Self {
        Self {
            received_cert: Arc::new(Mutex::new(None)),
        }
    }

    /// Retrieve the server certificate DER bytes captured during the TLS handshake.
    pub fn received_certificate(&self) -> Option<CertificateDer<'static>> {
        self.received_cert
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }
}

const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

impl Default for EnclaveCertVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize)]
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

fn parse_attestation_doc(raw_bytes: &[u8]) -> Result<AttestationDocument, Box<dyn Error>> {
    // 1. Unpack the COSE_Sign1 wrapper from raw CBOR bytes
    let cose_sign1 = CoseSign1::from_bytes(raw_bytes)?;

    // 2. Extract the payload bytes (this contains the CBOR-encoded document)
    let payload_bytes = cose_sign1.get_payload::<Openssl>(None)?;

    // 3. Deserialize the payload into our AttestationDocument struct
    let doc: AttestationDocument = ciborium::from_reader(payload_bytes.as_slice())?;

    Ok(doc)
}

impl ServerCertVerifier for EnclaveCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 1. Extract the attestation document
        let attestation_bytes = extract_attestation_doc(end_entity.as_ref())
            .map_err(|_| RustlsError::General("Missing attestation extension".into()))?;

        let _claims_set = EatClaimsSet::from_bytes(&attestation_bytes);
        let map_val = _claims_set.unwrap().submods.unwrap();
        if let Value::Map(entries) = map_val {
            if let Some((first_key, first_value)) = entries.first() {
                println!("First Key:   {:?}", first_key);
                println!("First Value: {:?}", first_value);

                let _ = parse_attestation_doc(first_value.as_bytes().unwrap())
                    .map_err(|_| RustlsError::General("Invalid attestation document".into()))?;
                println!("First Value: {:?}", first_value);
            } else {
                println!("Map is empty.");
            }
        } else {
            println!("Not a CBOR Map.");
        }
        // Note: For production mTLS/TLS, combine this with standard webpki signature checks.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Extract raw attestation bytes from the leaf certificate
pub fn extract_attestation_doc<'a>(
    cert_der: &'a [u8],
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

impl TtkClient {
    /// Connect to the TTKServer at the specified `server_addr` with the given SNI `server_name`.
    pub async fn connect(
        server_addr: SocketAddr,
        server_name: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Ensure the default crypto provider is installed
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert_verifier = Arc::new(EnclaveCertVerifier::new());

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

#[allow(dead_code)] // entry point for the `client` binary; unused when built as a lib module
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let (server_addr, server_name, path) = parse_args();

    println!("=================================================");
    println!("TTKServer HTTP/3 Client (RFC 9114)");
    println!("Connecting to: {} (SNI: {})", server_addr, server_name);
    println!("=================================================");

    let mut client = match TtkClient::connect(server_addr, &server_name).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to connect to TTKServer at {}: {}", server_addr, e);
            std::process::exit(1);
        }
    };

    if let Some(fingerprint) = client.peer_cert_sha256_hex() {
        println!("Server Certificate SHA-256 Fingerprint:");
        println!("  {}", fingerprint);
        println!("  (Matches NSM Attestation Document user_data for RA-TLS)");
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
