//! Tests of `POST /faf`: forwarding a message and key to an attested relay running the same
//! server, on free local ports with mock attestation.

#![cfg(feature = "mock")]

use std::net::SocketAddr;
use ttk_server::client::{EnclaveCertVerifier, TtkClient};
use ttk_server::server::{parse_relay_server, FafRequest, Server, DEFAULT_RELAY_PORT};

/// Starts a server that accepts mock-attested relays, and returns its address.
fn start_server() -> SocketAddr {
    start(|server| server.with_relay_verifier(|| EnclaveCertVerifier::new().allow_mock()))
}

/// Starts a server configured by `configure` on a free local port and returns its address.
fn start(configure: impl FnOnce(Server) -> Server) -> SocketAddr {
    let server = configure(Server::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());
    addr
}

async fn connect(addr: SocketAddr) -> TtkClient {
    TtkClient::connect_with_verifier(addr, "localhost", EnclaveCertVerifier::new().allow_mock())
        .await
        .unwrap()
}

fn request(relay_server: Option<String>) -> FafRequest {
    FafRequest {
        relay_server,
        message: "hello relay".to_string(),
        key: "c2VjcmV0LWtleQ==".to_string(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_relays_to_an_attested_relay_and_answers_200() {
    let relay = start_server();
    let mut client = connect(start_server()).await;

    let response = client
        .post_json("/faf", &request(Some(relay.to_string())))
        .await
        .unwrap();
    assert_eq!(response.status, 200, "{:?}", response.text());
    assert_eq!(response.text().unwrap(), "relayed");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_accepts_an_https_relay_url() {
    let relay = start_server();
    let mut client = connect(start_server()).await;

    let url = format!("https://localhost:{}", relay.port());
    let response = client.post_json("/faf", &request(Some(url))).await.unwrap();
    assert_eq!(response.status, 200, "{:?}", response.text());
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_without_relay_server_is_the_last_hop() {
    let mut client = connect(start_server()).await;

    let response = client.post_json("/faf", &request(None)).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.text().unwrap(), "delivered");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_answers_502_when_the_relay_fails_attestation() {
    // The default relay policy accepts only genuine TEE evidence, so a mock relay is rejected.
    let relay = start_server();
    let mut client = connect(start(|server| server)).await;

    let response = client
        .post_json("/faf", &request(Some(relay.to_string())))
        .await
        .unwrap();
    assert_eq!(response.status, 502);
    assert!(response.text().unwrap().starts_with("relay failed"));
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_rejects_an_invalid_relay_server() {
    let mut client = connect(start_server()).await;

    for bad in [
        "http://localhost:4433",
        "ftp://relay",
        "",
        "user@relay:4433",
    ] {
        let response = client
            .post_json("/faf", &request(Some(bad.to_string())))
            .await
            .unwrap();
        assert_eq!(response.status, 400, "{bad:?}");
    }
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_rejects_malformed_requests() {
    let mut client = connect(start_server()).await;

    // Not JSON.
    let not_json = client.post("/faf", b"message=hi").await.unwrap();
    assert_eq!(not_json.status, 415);
    // JSON missing the required `key` field.
    let missing = client
        .post_json("/faf", &serde_json::json!({ "message": "hi" }))
        .await
        .unwrap();
    assert_eq!(missing.status, 422);
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_request_bodies_get_413() {
    let mut client = connect(start_server()).await;

    let huge = FafRequest {
        message: "x".repeat(ttk_server::server::MAX_REQUEST_BODY + 1),
        ..request(None)
    };
    let response = client.post_json("/faf", &huge).await.unwrap();
    assert_eq!(response.status, 413);
    client.close().await.unwrap();
}

#[test]
fn relay_server_accepts_host_port_and_https_forms() {
    let parse = |s: &str| parse_relay_server(s).unwrap();
    assert_eq!(parse("relay.example:9000"), ("relay.example".into(), 9000));
    assert_eq!(
        parse("relay.example"),
        ("relay.example".into(), DEFAULT_RELAY_PORT)
    );
    assert_eq!(
        parse("https://relay.example"),
        ("relay.example".into(), DEFAULT_RELAY_PORT)
    );
    assert_eq!(
        parse("https://10.0.0.1:4500/faf"),
        ("10.0.0.1".into(), 4500)
    );
    assert_eq!(parse("[::1]:4433"), ("::1".into(), 4433));
    assert_eq!(parse(" https://[::1] "), ("::1".into(), DEFAULT_RELAY_PORT));
}

#[test]
fn faf_request_omits_a_missing_relay_server() {
    let json = serde_json::to_value(request(None)).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "message": "hello relay", "key": "c2VjcmV0LWtleQ==" })
    );
    let parsed: FafRequest = serde_json::from_value(serde_json::json!({
        "relay_server": "relay:4433", "message": "m", "key": "k"
    }))
    .unwrap();
    assert_eq!(parsed.relay_server.as_deref(), Some("relay:4433"));
}
