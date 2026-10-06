//! Tests of the relay node's `POST /faf`: onion-routing a sealed message through attested relay
//! nodes to a terminal node, on free local ports with mock attestation.

use std::net::SocketAddr;
use ttk_client::faf::{FafBody, FafRelay, FafRequest};
use ttk_client::seal::{self, NodePublicKey};
use ttk_client::{EnclaveCertVerifier, TtkClient};
use ttk_relay::{Relay, MAX_RELAYS};
use ttk_terminal::Terminal;

/// Starts a relay node that accepts mock-attested next hops on local addresses, and returns its
/// address.
fn start_relay() -> SocketAddr {
    start(|relay| relay.allow_mock().allow_private_next_hops())
}

/// Starts a relay node configured by `configure` on a free local port and returns its address.
fn start(configure: impl FnOnce(Relay) -> Relay) -> SocketAddr {
    let relay = configure(Relay::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let addr = relay.local_addr().unwrap();
    tokio::spawn(async move { relay.serve().await.unwrap() });
    addr
}

/// Starts a terminal node on a free local port and returns its address.
fn start_terminal() -> SocketAddr {
    let terminal = Terminal::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = terminal.local_addr().unwrap();
    tokio::spawn(async move { terminal.serve().await.unwrap() });
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

#[tokio::test(flavor = "multi_thread")]
async fn faf_relays_to_an_attested_terminal_and_answers_200() {
    let terminal = start_terminal();
    let client = connect(start_relay()).await;

    let (body, key) = seal::seal_body_with_key(&node_key(terminal).await, b"hello relay").unwrap();
    let request = FafRequest {
        relays: vec![plain(terminal)],
        body,
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 200, "{:?}", response.text());
    // The terminal's sealed reply comes back through the relay unchanged.
    let reply = seal::open_response(&key, &response.text().unwrap()).unwrap();
    assert_eq!(reply, b"hello:hello relay");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_routes_through_plain_and_sealed_relays_to_the_terminal() {
    let (entry, middle, last) = (start_relay(), start_relay(), start_terminal());
    let middle_key = node_key(middle).await;
    let client = connect(entry).await;

    // entry reads `middle` in the clear; middle opens the address of `last`; last opens the body.
    let (body, key) = seal::seal_body_with_key(&node_key(last).await, b"hello relay").unwrap();
    let request = FafRequest {
        relays: vec![plain(middle), sealed(&middle_key, last)],
        body,
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 200, "{:?}", response.text());
    let reply = seal::open_response(&key, &response.text().unwrap()).unwrap();
    assert_eq!(reply, b"hello:hello relay");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_answers_502_when_the_body_is_not_sealed_to_the_terminal() {
    let (entry, terminal) = (start_relay(), start_terminal());
    let client = connect(entry).await;

    // Sealed to the entry node rather than the terminal, which is the last hop.
    let request = FafRequest {
        relays: vec![plain(terminal)],
        body: body_for(&node_key(entry).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 502);
    assert_eq!(response.text().unwrap(), "relay failed");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_answers_502_when_the_route_ends_at_a_relay() {
    let (entry, last) = (start_relay(), start_relay());
    let client = connect(entry).await;

    // `last` is a relay node, which never acts as the last hop.
    let request = FafRequest {
        relays: vec![plain(last)],
        body: body_for(&node_key(last).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 502);
    assert_eq!(response.text().unwrap(), "relay failed");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_without_relays_is_rejected_by_a_relay() {
    let relay = start_relay();
    let client = connect(relay).await;

    let request = FafRequest {
        relays: vec![],
        body: body_for(&node_key(relay).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 400);
    assert!(response.text().unwrap().starts_with("no relays left"));
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_rejects_a_relay_address_sealed_to_another_node() {
    let (entry, terminal) = (start_relay(), start_terminal());
    let terminal_key = node_key(terminal).await;
    let client = connect(entry).await;

    let request = FafRequest {
        relays: vec![sealed(&terminal_key, terminal)],
        body: body_for(&terminal_key),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 400);
    assert!(response.text().unwrap().starts_with("invalid relay"));
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_reuses_the_next_hop_connection_across_sequential_and_concurrent_requests() {
    let terminal = start_terminal();
    let client = connect(start_relay()).await;
    let terminal_key = node_key(terminal).await;
    let req = FafRequest {
        relays: vec![plain(terminal)],
        body: body_for(&terminal_key),
    };

    // The first request pools the next-hop connection; the later ones reuse it.
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
    let terminal = start_terminal();
    let client = connect(start_relay()).await;

    let request = FafRequest {
        relays: vec![FafRelay {
            address: format!("localhost:{}", terminal.port()),
            encrypted: false,
        }],
        body: body_for(&node_key(terminal).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 200, "{:?}", response.text());
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_answers_502_when_the_next_hop_fails_attestation() {
    // The default policy accepts only genuine TEE evidence, so a mock terminal is rejected.
    let terminal = start_terminal();
    let client = connect(start(Relay::allow_private_next_hops)).await;

    let request = FafRequest {
        relays: vec![plain(terminal)],
        body: body_for(&node_key(terminal).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 502);
    assert_eq!(response.text().unwrap(), "relay failed");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_refuses_loopback_next_hops_by_default() {
    // Mock attestation is allowed, so only the egress policy can stop this hop.
    let terminal = start_terminal();
    let client = connect(start(Relay::allow_mock)).await;

    for address in [
        format!("https://{terminal}"),
        format!("localhost:{}", terminal.port()),
    ] {
        let request = FafRequest {
            relays: vec![FafRelay {
                address,
                encrypted: false,
            }],
            body: body_for(&node_key(terminal).await),
        };
        let response = client.post_json("/faf", &request).await.unwrap();
        assert_eq!(response.status, 502);
        assert_eq!(response.text().unwrap(), "relay failed");
    }
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_refuses_link_local_next_hops_even_when_private_ones_are_allowed() {
    let client = connect(start_relay()).await;

    let request = FafRequest {
        // The instance metadata endpoint.
        relays: vec![FafRelay {
            address: "169.254.169.254:80".to_string(),
            encrypted: false,
        }],
        body: body_for(&node_key(start_terminal()).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 502);
    assert_eq!(response.text().unwrap(), "relay failed");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_rejects_routes_longer_than_max_relays() {
    let terminal = start_terminal();
    let client = connect(start_relay()).await;

    let request = FafRequest {
        relays: vec![plain(terminal); MAX_RELAYS + 1],
        body: body_for(&node_key(terminal).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 400);
    assert!(response.text().unwrap().starts_with("too many relays"));
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_rejects_an_invalid_relay_address() {
    let relay = start_relay();
    let relay_key = node_key(relay).await;
    let client = connect(relay).await;

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
            body: body_for(&relay_key),
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
        body: body_for(&relay_key),
    };
    assert_eq!(
        client.post_json("/faf", &request).await.unwrap().status,
        400
    );
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_rejects_malformed_requests() {
    let client = connect(start_relay()).await;

    // `/faf` is POST-only.
    assert_eq!(client.get("/faf").await.unwrap().status, 405);
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
    let client = connect(start_relay()).await;

    let huge = FafRequest {
        relays: vec![],
        body: FafBody {
            key: String::new(),
            message: "x".repeat(ttk_core::server::MAX_REQUEST_BODY + 1),
        },
    };
    let response = client.post_json("/faf", &huge).await.unwrap();
    assert_eq!(response.status, 413);
    client.close().await.unwrap();
}
