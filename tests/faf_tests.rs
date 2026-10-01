//! Tests of `POST /faf`: onion-routing a sealed message through attested relays running the
//! same server, on free local ports with mock attestation, and of the sealing itself.

#![cfg(feature = "mock")]

use rcgen::KeyPair;
use std::net::SocketAddr;
use ttk_server::client::{EnclaveCertVerifier, TtkClient};
use ttk_server::router::{
    parse_relay_address, parse_relay_server, FafBody, FafRelay, FafRequest, DEFAULT_RELAY_PORT,
};
use ttk_server::seal::{self, NodePublicKey, NodeSecretKey, SALT_DIGITS};
use ttk_server::server::Server;

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

/// Attests the node at `addr` and returns its RA-TLS key, as a client would before sealing.
async fn node_key(addr: SocketAddr) -> NodePublicKey {
    let client = connect(addr).await;
    let key = NodePublicKey::from_certificate(client.peer_cert().unwrap()).unwrap();
    client.close().await.unwrap();
    key
}

/// A relay entry naming `addr` in the clear.
fn plain(addr: SocketAddr) -> FafRelay {
    FafRelay {
        address: format!("https://{addr} {}", seal::random_salt().unwrap()),
        encrypted: false,
    }
}

/// A relay entry naming `addr`, sealed to `reader`.
fn sealed(reader: &NodePublicKey, addr: SocketAddr) -> FafRelay {
    FafRelay {
        address: seal::seal_address(reader, &format!("https://{addr}")).unwrap(),
        encrypted: true,
    }
}

fn body_for(last: &NodePublicKey) -> FafBody {
    seal::seal_body(last, b"hello relay").unwrap()
}

/// A fresh RA-TLS-style key pair, as the server generates at startup.
fn key_pair() -> (NodeSecretKey, NodePublicKey) {
    let secret =
        NodeSecretKey::from_pkcs8_der(&KeyPair::generate().unwrap().serialize_der()).unwrap();
    let public = secret.public_key();
    (secret, public)
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_relays_to_an_attested_relay_and_answers_200() {
    let relay = start_server();
    let client = connect(start_server()).await;

    let request = FafRequest {
        relays: vec![plain(relay)],
        body: body_for(&node_key(relay).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 200, "{:?}", response.text());
    assert_eq!(response.text().unwrap(), "relayed");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_routes_through_plain_and_sealed_relays_to_the_last_hop() {
    let (entry, middle, last) = (start_server(), start_server(), start_server());
    let middle_key = node_key(middle).await;
    let client = connect(entry).await;

    // entry reads `middle` in the clear; middle opens the address of `last`; last opens the body.
    let request = FafRequest {
        relays: vec![plain(middle), sealed(&middle_key, last)],
        body: body_for(&node_key(last).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 200, "{:?}", response.text());
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_answers_502_when_the_body_is_not_sealed_to_the_last_hop() {
    let (entry, relay) = (start_server(), start_server());
    let client = connect(entry).await;

    // Sealed to the entry node rather than the relay, which is the last hop.
    let request = FafRequest {
        relays: vec![plain(relay)],
        body: body_for(&node_key(entry).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 502);
    assert_eq!(response.text().unwrap(), "relay answered 400 Bad Request");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_rejects_a_relay_address_sealed_to_another_node() {
    let (entry, relay) = (start_server(), start_server());
    let relay_key = node_key(relay).await;
    let client = connect(entry).await;

    let request = FafRequest {
        relays: vec![sealed(&relay_key, relay)],
        body: body_for(&relay_key),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 400);
    assert!(response.text().unwrap().starts_with("invalid relay"));
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_reuses_the_relay_connection_across_sequential_and_concurrent_requests() {
    let relay = start_server();
    let client = connect(start_server()).await;
    let relay_key = node_key(relay).await;
    let req = FafRequest {
        relays: vec![plain(relay)],
        body: body_for(&relay_key),
    };

    // The first request pools the relay connection; the later ones reuse it.
    for _ in 0..3 {
        let response = client.post_json("/faf", &req).await.unwrap();
        assert_eq!(response.status, 200, "{:?}", response.text());
    }
    // Concurrent requests share the pooled connection as separate HTTP/3 streams.
    let send = || client.post_json("/faf", &req);
    let (a, b, c, d) = tokio::join!(send(), send(), send(), send());
    for response in [a, b, c, d] {
        assert_eq!(response.unwrap().status, 200);
    }
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_accepts_a_plain_address_without_a_salt() {
    let relay = start_server();
    let client = connect(start_server()).await;

    let request = FafRequest {
        relays: vec![FafRelay {
            address: format!("localhost:{}", relay.port()),
            encrypted: false,
        }],
        body: body_for(&node_key(relay).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 200, "{:?}", response.text());
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_without_relays_is_the_last_hop() {
    let server = start_server();
    let client = connect(server).await;

    let request = FafRequest {
        relays: vec![],
        body: body_for(&node_key(server).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.text().unwrap(), "delivered");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_last_hop_rejects_a_body_it_cannot_decrypt() {
    let server = start_server();
    let client = connect(server).await;
    let (_, other) = key_pair();

    let mut tampered = body_for(&node_key(server).await);
    tampered.message = body_for(&node_key(server).await).message;
    for body in [
        body_for(&other),
        tampered,
        FafBody {
            key: String::new(),
            message: String::new(),
        },
    ] {
        let request = FafRequest {
            relays: vec![],
            body,
        };
        let response = client.post_json("/faf", &request).await.unwrap();
        assert_eq!(response.status, 400);
        assert!(response.text().unwrap().starts_with("invalid body"));
    }
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_answers_502_when_the_relay_fails_attestation() {
    // The default relay policy accepts only genuine TEE evidence, so a mock relay is rejected.
    let relay = start_server();
    let client = connect(start(|server| server)).await;

    let request = FafRequest {
        relays: vec![plain(relay)],
        body: body_for(&node_key(relay).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 502);
    assert!(response.text().unwrap().starts_with("relay failed"));
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_rejects_an_invalid_relay_address() {
    let server = start_server();
    let server_key = node_key(server).await;
    let client = connect(server).await;

    for bad in [
        "http://localhost:4433",
        "ftp://relay",
        "",
        "user@relay:4433",
        "https://relay:4433 123",
        "https://relay:4433 12345abcde",
    ] {
        let request = FafRequest {
            relays: vec![FafRelay {
                address: bad.to_string(),
                encrypted: false,
            }],
            body: body_for(&server_key),
        };
        let response = client.post_json("/faf", &request).await.unwrap();
        assert_eq!(response.status, 400, "{bad:?}");
    }
    // An encrypted entry that isn't a sealed value.
    let request = FafRequest {
        relays: vec![FafRelay {
            address: "https://relay:4433 0123456789".to_string(),
            encrypted: true,
        }],
        body: body_for(&server_key),
    };
    assert_eq!(
        client.post_json("/faf", &request).await.unwrap().status,
        400
    );
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_rejects_malformed_requests() {
    let client = connect(start_server()).await;

    // Not JSON.
    let not_json = client.post("/faf", b"message=hi").await.unwrap();
    assert_eq!(not_json.status, 415);
    for missing in [
        // No body.
        serde_json::json!({ "relays": [] }),
        // A null key.
        serde_json::json!({ "relays": [], "body": { "key": null, "message": "m" } }),
        // A relay entry without its `encrypted` flag.
        serde_json::json!({ "relays": [{ "address": "relay" }], "body": { "key": "k", "message": "m" } }),
    ] {
        let response = client.post_json("/faf", &missing).await.unwrap();
        assert_eq!(response.status, 422, "{missing}");
    }
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_request_bodies_get_413() {
    let client = connect(start_server()).await;

    let huge = FafRequest {
        relays: vec![],
        body: FafBody {
            key: String::new(),
            message: "x".repeat(ttk_server::server::MAX_REQUEST_BODY + 1),
        },
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
fn relay_address_carries_a_ten_digit_salt() {
    assert_eq!(
        parse_relay_address("https://server.com:443 0123456789", true),
        Ok("https://server.com:443")
    );
    assert_eq!(
        parse_relay_address(" https://server.com:443  0123456789 ", false),
        Ok("https://server.com:443")
    );
    assert_eq!(
        parse_relay_address("https://server.com:443", false),
        Ok("https://server.com:443")
    );
    assert!(parse_relay_address("https://server.com:443", true).is_err());
    assert!(parse_relay_address("https://server.com:443 123456789", false).is_err());
    assert!(parse_relay_address("https://server.com:443 01234567890", false).is_err());
    assert!(parse_relay_address("https://server.com:443 012345678x", false).is_err());
}

#[test]
fn sealed_address_opens_to_the_server_and_a_fresh_salt() {
    let (secret, public) = key_pair();
    let sealed = seal::seal_address(&public, "https://server.com:443").unwrap();
    let opened = seal::open_address(&secret, &sealed).unwrap();

    let (server, salt) = opened.split_once(' ').unwrap();
    assert_eq!(server, "https://server.com:443");
    assert_eq!(salt.len(), SALT_DIGITS);
    assert!(salt.bytes().all(|b| b.is_ascii_digit()));
    // Sealing is randomized, so the same address never seals the same way twice.
    assert_ne!(
        sealed,
        seal::seal_address(&public, "https://server.com:443").unwrap()
    );
    // Only the node it is sealed to can open it.
    let (other, _) = key_pair();
    assert!(seal::open_address(&other, &sealed).is_err());
}

#[test]
fn sealed_body_opens_only_for_the_last_hop() {
    let (secret, public) = key_pair();
    let body = seal::seal_body(&public, b"hello relay").unwrap();
    assert_eq!(seal::open_body(&secret, &body).unwrap(), b"hello relay");

    let (other, _) = key_pair();
    assert!(seal::open_body(&other, &body).is_err());
    // A sealed address isn't a sealed key: the two are domain-separated.
    let swapped = FafBody {
        key: seal::seal_address(&public, "https://server.com").unwrap(),
        ..body.clone()
    };
    assert!(seal::open_body(&secret, &swapped).is_err());
    // A tampered message fails authentication.
    let mut message = body.message.into_bytes();
    message[20] = if message[20] == b'A' { b'B' } else { b'A' };
    let tampered = FafBody {
        key: body.key,
        message: String::from_utf8(message).unwrap(),
    };
    assert!(seal::open_body(&secret, &tampered).is_err());
}

#[test]
fn node_public_key_comes_from_the_certificate() {
    let key_pair = KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let secret = NodeSecretKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
    let public = NodePublicKey::from_certificate(cert.der()).unwrap();

    let body = seal::seal_body(&public, b"m").unwrap();
    assert_eq!(seal::open_body(&secret, &body).unwrap(), b"m");
    assert!(NodePublicKey::from_certificate(b"not a certificate").is_err());
}

#[test]
fn faf_request_json_shape() {
    let request = FafRequest {
        relays: vec![
            FafRelay {
                address: "a".to_string(),
                encrypted: false,
            },
            FafRelay {
                address: "b".to_string(),
                encrypted: true,
            },
        ],
        body: FafBody {
            key: "k".to_string(),
            message: "m".to_string(),
        },
    };
    let json = serde_json::json!({
        "relays": [
            { "address": "a", "encrypted": false },
            { "address": "b", "encrypted": true }
        ],
        "body": { "key": "k", "message": "m" }
    });
    assert_eq!(serde_json::to_value(&request).unwrap(), json);
    assert_eq!(serde_json::from_value::<FafRequest>(json).unwrap(), request);
    // `relays` may be omitted at the last hop.
    let last: FafRequest = serde_json::from_value(serde_json::json!({
        "body": { "key": "k", "message": "m" }
    }))
    .unwrap();
    assert!(last.relays.is_empty());
}
