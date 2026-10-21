//! Tests of QUIC address validation in `Server::serve`: a connection attempt from an address
//! not validated yet is answered with a Retry (RFC 9000 §8.1.2) before any handshake.

use quinn::crypto::rustls::QuicClientConfig;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};
use ttk_ra_server::server::Server;

/// RFC 9000 §17.2: long header form bit, and the QUIC v1 long packet type bits (Retry = 3).
const LONG_HEADER: u8 = 0x80;
const RETRY_TYPE: u8 = 0x3;

/// Starts a server on a free local UDP port and returns its address.
fn start_server() -> SocketAddr {
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).expect("server should start");
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());
    addr
}

/// A client's first Initial datagram (no token) for a connection to `server`.
fn first_initial(server: SocketAddr) -> Vec<u8> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
    let mut endpoint = quinn_proto::Endpoint::new(
        Arc::new(quinn_proto::EndpointConfig::default()),
        None,
        true,
        None,
    );
    let (_, mut connection) = endpoint
        .connect(Instant::now(), config, server, "localhost")
        .unwrap();
    let mut buf = Vec::new();
    let transmit = connection
        .poll_transmit(Instant::now(), 1, &mut buf)
        .expect("a new connection sends its Initial");
    buf.truncate(transmit.size);
    buf
}

#[tokio::test]
async fn unvalidated_initial_gets_a_retry() {
    let server = start_server();
    let initial = first_initial(server);
    let sent = initial.len();

    let reply = tokio::task::spawn_blocking(move || {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.send_to(&initial, server).unwrap();
        let mut buf = [0u8; 2048];
        let (len, _) = socket.recv_from(&mut buf).expect("the server answers");
        buf[..len].to_vec()
    })
    .await
    .unwrap();

    assert_eq!(reply[0] & LONG_HEADER, LONG_HEADER, "long header packet");
    assert_eq!((reply[0] >> 4) & 0x3, RETRY_TYPE, "Retry, not a handshake");
    // A Retry carries no certificate: it is far smaller than the 3x amplification allowance.
    assert!(reply.len() < sent);
}

#[tokio::test]
async fn clients_still_connect_after_a_retry() {
    let server = start_server();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        client.connect(server, "localhost").unwrap(),
    )
    .await
    .expect("handshake completes in time")
    .expect("handshake succeeds after the Retry");
    connection.close(0u32.into(), b"done");
}

/// Accepts any server certificate: this test checks the transport, not RA-TLS.
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
