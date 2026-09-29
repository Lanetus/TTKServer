//! End-to-end tests: the real server on a free local port (mock attestation), queried by the
//! `TtkClient` library.

#![cfg(feature = "mock")]

use base64::Engine as _;
use std::net::SocketAddr;
use ttk_server::client::{EnclaveCertVerifier, TtkClient};
use ttk_server::eat::EatClaimsSet;
use ttk_server::server::Server;
use ttk_server::verifier::TeeKind;

/// Starts a server on a free local port and returns its address. It serves until the test's
/// runtime shuts down.
fn start_server() -> SocketAddr {
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).expect("server should start");
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());
    addr
}

#[tokio::test(flavor = "multi_thread")]
async fn client_verifies_the_mock_server_and_exchanges_requests() {
    let addr = start_server();
    let mut client = TtkClient::connect_with_verifier(
        addr,
        "localhost",
        EnclaveCertVerifier::new().allow_mock(),
    )
    .await
    .expect("mock evidence should verify with mock allowed");

    assert_eq!(client.server_addr(), addr);
    assert_eq!(client.server_name(), "localhost");
    assert!(client.peer_cert().is_some());
    assert_eq!(client.peer_cert_sha256_hex().map(|h| h.len()), Some(64));

    let root = client.get("/").await.unwrap();
    assert_eq!(root.status, 200);
    assert_eq!(root.text().unwrap(), "Hello from Enclave over HTTP/3!");

    // Paths without a leading slash are accepted too.
    let hello = client.get("hello").await.unwrap();
    assert_eq!(hello.text().unwrap(), "Hello from inside the Enclave!");

    // The evidence served over HTTP is the EAT embedded in the TLS certificate.
    let evidence = client.get("/evidence.eat").await.unwrap();
    let eat = base64::engine::general_purpose::STANDARD
        .decode(evidence.text().unwrap())
        .unwrap();
    let claims = EatClaimsSet::from_cbor_bytes(&eat).unwrap();
    assert!(claims.submods.is_some());

    let missing = client.get("/does-not-exist").await.unwrap();
    assert_eq!(missing.status, 404);

    // Routes are GET-only, so a POST is answered with 405.
    let post = client.post("/", b"payload").await.unwrap();
    assert_eq!(post.status, 405);
    let empty_post = client.post("hello", b"").await.unwrap();
    assert_eq!(empty_post.status, 405);

    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn verified_evidence_is_available_after_connecting() {
    let addr = start_server();
    let verifier = EnclaveCertVerifier::new().allow_mock();
    let client = TtkClient::connect_with_verifier(addr, "localhost", verifier.clone())
        .await
        .unwrap();

    let evidence = verifier.verified_evidence().expect("evidence is recorded");
    assert_eq!(evidence.tee, TeeKind::AwsNitro);
    assert_eq!(
        verifier.verified_attestation().unwrap().module_id,
        "aws-nitro-enclaves-mock"
    );
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_client_rejects_the_mock_server() {
    let addr = start_server();
    let err = TtkClient::connect(addr, "localhost").await.err().unwrap();
    assert!(err.to_string().contains("MOCK"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn client_connects_over_ipv6() {
    let Ok(server) = Server::bind("[::1]:0".parse().unwrap()) else {
        eprintln!("IPv6 loopback unavailable; skipping");
        return;
    };
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let mut client = TtkClient::connect_with_verifier(
        addr,
        "localhost",
        EnclaveCertVerifier::new().allow_mock(),
    )
    .await
    .expect("the client should connect over IPv6");
    assert_eq!(client.get("/").await.unwrap().status, 200);
    client.close().await.unwrap();
}
