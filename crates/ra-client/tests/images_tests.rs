//! Fetching the accepted enclave images from root nodes (`ttk_root`) running locally with mock
//! attestation.

#[path = "../../ra-server/tests/support/test_ca.rs"]
mod test_ca;
use test_ca::SignForTests;

use std::net::SocketAddr;
use ttk_ra_client::images::RootImageTrustStore;
use ttk_ra_client::{parse_image_allowlist, ImageTrustStore};
use ttk_ra_client::{ClientTransport, EnclaveCertVerifier};
use ttk_ra_server::server::Server;
use ttk_root::{FileImageTrustStore, Root};

const IMAGE_A: &str = "7807833a90cc86f5a853a1f49043a568f3428f6b03eb983aed99899fbfa77d6b86b34fa934e318dd3741debca32c0aba";
const IMAGE_B: &str = "1de927770d7a1c250ba364440947226ed9af7250ae25fdad391c3cd87d0044b1e4a4e96810bc8f2dfc9160fcf0742c8d";

/// Starts a root node serving `allowlist`, unlocked with a test CA certificate, on a free local
/// port and returns its address.
fn start_root(allowlist: &str) -> SocketAddr {
    let images = FileImageTrustStore::parse(allowlist).unwrap();
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let root = Root::with_image_trust_store(server, &images);
    root.server().sign_for_tests().unwrap();
    let addr = root.local_addr().unwrap();
    tokio::spawn(async move { root.serve().await.unwrap() });
    addr
}

/// Fetches from `roots`, accepting their mock attestation.
async fn fetch(roots: &[&str]) -> Result<RootImageTrustStore, String> {
    let verifier = EnclaveCertVerifier::new().allow_mock();
    RootImageTrustStore::fetch(roots, ClientTransport::Udp, verifier)
        .await
        .map_err(|e| e.to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn fetches_the_accepted_images_from_a_root_server() {
    let root = start_root(&format!("{IMAGE_A}\n{IMAGE_B}")).to_string();
    let images = fetch(&[&root]).await.unwrap();
    assert_eq!(
        images.image_allowlist(),
        parse_image_allowlist(&format!("{IMAGE_A}\n{IMAGE_B}")).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn falls_back_to_the_next_root_server() {
    let empty_root = start_root("# no images").to_string();
    let root = start_root(IMAGE_A).to_string();
    let images = fetch(&[&empty_root, &root]).await.unwrap();
    assert_eq!(
        images.image_allowlist(),
        parse_image_allowlist(IMAGE_A).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_when_no_root_server_answers() {
    let empty_root = start_root("").to_string();
    let err = fetch(&[&empty_root]).await.unwrap_err();
    assert!(err.contains("lists no accepted images"), "{err}");
    assert!(fetch(&[]).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn root_servers_must_attest() {
    let root = start_root(IMAGE_A).to_string();
    let err =
        RootImageTrustStore::fetch(&[&root], ClientTransport::Udp, EnclaveCertVerifier::new())
            .await
            .unwrap_err();
    assert!(err.to_string().contains("MOCK"), "{err}");
}
