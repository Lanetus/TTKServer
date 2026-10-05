//! Tests of the root node's `GET /root-attestation`, on a free local port with mock attestation.

use std::net::SocketAddr;
use ttk_client::verifier::{nitro, TrustStore};
use ttk_client::{hex_encode, EnclaveCertVerifier, TtkClient};
use ttk_core::server::Server;
use ttk_root::{Root, RootAttestation, ROOT_ATTESTATION_PATH};

const PCR0_A: &str = "7807833a90cc86f5a853a1f49043a568f3428f6b03eb983aed99899fbfa77d6b86b34fa934e318dd3741debca32c0aba";
const PCR0_B: &str = "1de927770d7a1c250ba364440947226ed9af7250ae25fdad391c3cd87d0044b1e4a4e96810bc8f2dfc9160fcf0742c8d";

/// Starts `root` on a free local port and returns its address.
fn start(root: Root) -> SocketAddr {
    let addr = root.local_addr().unwrap();
    tokio::spawn(async move { root.serve().await.unwrap() });
    addr
}

/// Fetches and decodes `GET /root-attestation` from the node at `addr`.
async fn fetch(addr: SocketAddr) -> RootAttestation {
    let client = TtkClient::connect_with_verifier(
        addr,
        "localhost",
        EnclaveCertVerifier::new().allow_mock(),
    )
    .await
    .unwrap();
    let response = client.get(ROOT_ATTESTATION_PATH).await.unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.headers["content-type"], "application/json");
    let body = serde_json::from_slice(&response.body).unwrap();
    client.close().await.unwrap();
    body
}

#[tokio::test(flavor = "multi_thread")]
async fn root_attestation_serves_the_builtin_accepted_images() {
    let addr = start(Root::bind("127.0.0.1:0".parse().unwrap()).unwrap());

    let expected: Vec<String> = TrustStore::builtin()
        .nitro_image_allowlist
        .iter()
        .map(|pcr0| hex_encode(pcr0))
        .collect();
    let body = fetch(addr).await;
    assert_eq!(body.hash_algorithm, "SHA384");
    assert!(!body.pcr0.is_empty());
    assert_eq!(body.pcr0, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn root_attestation_serves_a_custom_trust_store() {
    let trust = TrustStore {
        nitro_image_allowlist: nitro::parse_image_allowlist(&format!("{PCR0_A}\n{PCR0_B}"))
            .unwrap(),
        ..TrustStore::builtin()
    };
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = start(Root::with_trust_store(server, &trust));

    let body = fetch(addr).await;
    assert_eq!(body.pcr0, vec![PCR0_A, PCR0_B]);
}

#[tokio::test(flavor = "multi_thread")]
async fn base_routes_are_still_served() {
    let addr = start(Root::bind("127.0.0.1:0".parse().unwrap()).unwrap());
    let client = TtkClient::connect_with_verifier(
        addr,
        "localhost",
        EnclaveCertVerifier::new().allow_mock(),
    )
    .await
    .unwrap();
    assert_eq!(client.get("/evidence.eat").await.unwrap().status, 200);
    assert_eq!(client.get("/").await.unwrap().status, 200);
    client.close().await.unwrap();
}
