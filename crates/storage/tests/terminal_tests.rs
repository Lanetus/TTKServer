//! Tests of the terminal node's `POST /faf`: receiving the last hop of an onion-routed message,
//! on a free local port with mock attestation.

use rcgen::KeyPair;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use ttk_ra_client::faf::{FafBody, FafRelay, FafRequest};
use ttk_ra_client::seal::{self, NodePublicKey, NodeSecretKey};
use ttk_ra_client::{EnclaveCertVerifier, TtkClient};
use ttk_ra_server::terminal::Terminal;
use ttk_storage::file_service::{FileRequest, FileResponse, FileService};
use ttk_storage::storage::MemoryStore;

/// Binds a file service terminal node (in-memory store) to a free local port.
fn bind_terminal() -> Terminal<FileService<MemoryStore>> {
    Terminal::bind(
        "127.0.0.1:0".parse().unwrap(),
        FileService::new(MemoryStore::new()),
    )
    .unwrap()
}

/// Starts a file service terminal node (unlocked with a test CA certificate) on a free local port
/// and returns its address.
fn start_terminal() -> SocketAddr {
    let terminal = bind_terminal();
    terminal.server().sign_for_tests().unwrap();
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

/// The message the tests seal to the terminal: a file service upload of `hello terminal`.
fn message() -> Vec<u8> {
    FileRequest::Upload(b"hello terminal".to_vec())
        .to_cbor()
        .unwrap()
}

fn body_for(last: &NodePublicKey) -> FafBody {
    seal::seal_body(last, &message()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn faf_without_relays_answers_the_evaluators_reply_sealed_to_the_sender() {
    let terminal = start_terminal();
    let client = connect(terminal).await;

    let (body, key) = seal::seal_body_with_key(&node_key(terminal).await, &message()).unwrap();
    let request = FafRequest {
        relays: vec![],
        body,
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 200);
    let sealed = response.text().unwrap();
    let reply = FileResponse::from_cbor(&seal::open_response(&key, &sealed).unwrap()).unwrap();
    assert_eq!(
        reply,
        FileResponse::Response(Sha256::digest(b"hello terminal").to_vec())
    );
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

#[tokio::test(flavor = "multi_thread")]
async fn faf_is_locked_until_the_certificate_is_replaced() {
    let node = bind_terminal();
    let addr = node.local_addr().unwrap();
    tokio::spawn(async move { node.serve().await.unwrap() });
    let client = connect(addr).await;
    assert_eq!(client.post("/faf", b"{}").await.unwrap().status, 404);
    assert_eq!(client.get("/").await.unwrap().status, 404);
    client.close().await.unwrap();
}
