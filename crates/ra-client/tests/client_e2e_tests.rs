//! End-to-end tests: the `ttk-ra-server` server on a free local port (mock attestation), queried by the
//! `TtkClient` library.

use base64::Engine as _;
use std::net::SocketAddr;
use ttk_ra_client::verifier::TeeKind;
use ttk_ra_client::{EnclaveCertVerifier, TtkClient, MAX_RESPONSE_BODY};
use ttk_ra_server::attestation::media_type;
use ttk_ra_server::attestation::nitro_doc::parse_attestation_document;
use ttk_ra_server::server::{Server, MAX_REQUEST_HEADERS};
use ttk_ra_server::Cmw;

/// Decodes the CBOR CMW record `cmw`, returning its media type and value.
fn nitro_record(cmw: &[u8]) -> (Option<String>, Vec<u8>) {
    match Cmw::from_cbor_bytes(cmw).unwrap() {
        Cmw::Record(r) => (r.media_type().map(String::from), r.value),
        Cmw::Collection(_) => panic!("Nitro evidence should be a CMW record"),
    }
}

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
    let client = TtkClient::connect_with_verifier(
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

    // Only `/` and `/evidence.cmw` are served over GET; `/evidence` is POST-only.
    for removed in ["/hello", "/attestation"] {
        assert_eq!(client.get(removed).await.unwrap().status, 404, "{removed}");
    }
    assert_eq!(client.get("/evidence").await.unwrap().status, 405);

    // The evidence served over HTTP is the CMW embedded in the TLS certificate. Paths without a
    // leading slash are accepted too.
    let evidence = client.get("evidence.cmw").await.unwrap();
    let cmw = base64::engine::general_purpose::STANDARD
        .decode(evidence.text().unwrap())
        .unwrap();
    assert_eq!(nitro_record(&cmw).0, Some(media_type::AWS_NITRO.into()));
    assert_eq!(client.get("/evidence.eat").await.unwrap().status, 404);

    let missing = client.get("/does-not-exist").await.unwrap();
    assert_eq!(missing.status, 404);

    // `/` and `/evidence.cmw` are GET-only, so a POST is answered with 405.
    let post = client.post("/", b"payload").await.unwrap();
    assert_eq!(post.status, 405);
    let empty_post = client.post("evidence.cmw", b"").await.unwrap();
    assert_eq!(empty_post.status, 405);
    // The base `ttk-ra-server` server has no `/faf`: relay and terminal nodes add it.
    assert_eq!(client.post("/faf", b"{}").await.unwrap().status, 404);

    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn evidence_with_nonce_carries_the_nonce() {
    let addr = start_server();
    let client = TtkClient::connect_with_verifier(
        addr,
        "localhost",
        EnclaveCertVerifier::new().allow_mock(),
    )
    .await
    .unwrap();

    let nonce = b"fresh-client-nonce";
    let response = client.post("/evidence", nonce).await.unwrap();
    assert_eq!(response.status, 200);
    let cmw = base64::engine::general_purpose::STANDARD
        .decode(response.text().unwrap())
        .unwrap();
    let doc = parse_attestation_document(&nitro_record(&cmw).1).unwrap();
    assert_eq!(doc.nonce.unwrap().as_slice(), nonce);

    // The nonce is required and bounded.
    assert_eq!(client.post("/evidence", b"").await.unwrap().status, 400);
    let too_long = vec![0; ttk_ra_server::router::MAX_NONCE_LEN + 1];
    assert_eq!(
        client.post("/evidence", &too_long).await.unwrap().status,
        400
    );

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

    let client = TtkClient::connect_with_verifier(
        addr,
        "localhost",
        EnclaveCertVerifier::new().allow_mock(),
    )
    .await
    .expect("the client should connect over IPv6");
    assert_eq!(client.get("/").await.unwrap().status, 200);
    client.close().await.unwrap();
}

/// Connects to the server at `addr`, accepting its mock evidence.
async fn connect_mock(addr: SocketAddr) -> TtkClient {
    TtkClient::connect_with_verifier(addr, "localhost", EnclaveCertVerifier::new().allow_mock())
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn client_rejects_responses_larger_than_max_response_body() {
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.local_addr().unwrap();
    let routes = axum::Router::new()
        .route(
            "/big",
            axum::routing::get(|| async { vec![b'x'; MAX_RESPONSE_BODY + 1] }),
        )
        .route(
            "/fits",
            axum::routing::get(|| async { vec![b'x'; MAX_RESPONSE_BODY] }),
        );
    tokio::spawn(server.serve_with(routes));
    let client = connect_mock(addr).await;

    let err = client.get("/big").await.unwrap_err();
    assert!(err.to_string().contains("response body exceeds"), "{err}");
    let fits = client.get("/fits").await.unwrap();
    assert_eq!(fits.body.len(), MAX_RESPONSE_BODY);
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn server_refuses_request_headers_larger_than_max_request_headers() {
    let addr = start_server();
    let client = connect_mock(addr).await;

    let request = axum::http::Request::get("https://localhost/")
        .header("x-padding", "x".repeat(MAX_REQUEST_HEADERS as usize + 1))
        .body(())
        .unwrap();
    // The oversized header section closes the connection instead of being served.
    assert!(client.send(request, None).await.is_err());
    assert!(client.get("/").await.is_err());

    // The server itself keeps serving new connections.
    let fresh = connect_mock(addr).await;
    assert_eq!(fresh.get("/").await.unwrap().status, 200);
    fresh.close().await.unwrap();
}
