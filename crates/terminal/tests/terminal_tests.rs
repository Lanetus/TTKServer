//! Tests of the terminal node's `POST /faf`: receiving the last hop of an onion-routed message,
//! on a free local port with mock attestation.

use rcgen::KeyPair;
use std::net::SocketAddr;
use ttk_client::faf::{FafBody, FafRelay, FafRequest};
use ttk_client::seal::{self, NodePublicKey, NodeSecretKey};
use ttk_client::{EnclaveCertVerifier, TtkClient};
use ttk_terminal::Terminal;

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

fn body_for(last: &NodePublicKey) -> FafBody {
    seal::seal_body(last, b"hello terminal").unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_without_relays_is_delivered() {
    let terminal = start_terminal();
    let client = connect(terminal).await;

    let request = FafRequest {
        relays: vec![],
        body: body_for(&node_key(terminal).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.text().unwrap(), "delivered");
    client.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_rejects_a_body_it_cannot_decrypt() {
    let terminal = start_terminal();
    let client = connect(terminal).await;
    let other = NodeSecretKey::from_pkcs8_der(&KeyPair::generate().unwrap().serialize_der())
        .unwrap()
        .public_key();

    let mut tampered = body_for(&node_key(terminal).await);
    tampered.message = body_for(&node_key(terminal).await).message;
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
async fn faf_with_relays_left_is_rejected() {
    let terminal = start_terminal();
    let client = connect(terminal).await;

    let request = FafRequest {
        relays: vec![FafRelay {
            address: "localhost:4433".to_string(),
            encrypted: false,
        }],
        body: body_for(&node_key(terminal).await),
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 400);
    assert!(response.text().unwrap().starts_with("relays left"));
    client.close().await.unwrap();
}
