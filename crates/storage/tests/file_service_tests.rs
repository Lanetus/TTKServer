//! Tests of the `s3-server` file service ([`FileService`]) on an in-memory store: directly, and
//! as a terminal node's `/faf` evaluator on a free local port with mock attestation.

#[path = "../../ra-server/tests/support/test_ca.rs"]
mod test_ca;
use test_ca::SignForTests;

use ciborium::Value;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use ttk_core::file_message::{FileError, FileRequest, FileResponse};
use ttk_ra_client::seal::{self, NodePublicKey};
use ttk_ra_client::FafRequest;
use ttk_ra_client::{EnclaveCertVerifier, TtkClient};
use ttk_ra_server::server::Server;
use ttk_ra_server::terminal::Terminal;
use ttk_ra_server::Evaluator;
use ttk_storage::adaptors::local_memory::MemoryStore;
use ttk_storage::adaptors::BlobStore;
use ttk_storage::{EvalError, FileService};

/// Lowercase hex SHA-256 of `hello world`: the stored blob's name.
const HELLO_NAME: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

fn hello_sha256() -> Vec<u8> {
    Sha256::digest(b"hello world").to_vec()
}

/// A [`MemoryStore`] the test keeps a handle to, to look at what the service stored.
#[derive(Clone, Default)]
struct SharedStore(Arc<MemoryStore>);

impl BlobStore for SharedStore {
    async fn put(&self, name: &str, data: Vec<u8>) -> Result<(), EvalError> {
        self.0.put(name, data).await
    }

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, EvalError> {
        self.0.get(name).await
    }
}

/// Answers `request` through the service's CBOR [`Evaluator`] interface.
async fn handle<S: BlobStore>(service: &FileService<S>, request: FileRequest) -> FileResponse {
    let reply = service.eval(request.to_cbor().unwrap()).await.unwrap();
    FileResponse::from_cbor(&reply).unwrap()
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn message(kind: &str, body: Value) -> Vec<u8> {
    cbor(&Value::Map(vec![
        (Value::Text("type".into()), Value::Text(kind.into())),
        (Value::Text("body".into()), body),
    ]))
}

#[tokio::test]
async fn upload_stores_the_file_under_its_sha256() {
    let store = SharedStore::default();
    let service = FileService::new(store.clone());
    let response = handle(&service, FileRequest::Upload(b"hello world".to_vec())).await;
    assert_eq!(response, FileResponse::Response(hello_sha256()));
    // Stored under the lowercase hex of its SHA-256.
    assert_eq!(
        store.get(HELLO_NAME).await.unwrap(),
        Some(b"hello world".to_vec())
    );

    let downloaded = handle(&service, FileRequest::Download(hello_sha256())).await;
    assert_eq!(downloaded, FileResponse::Response(b"hello world".to_vec()));
}

#[tokio::test]
async fn download_of_a_missing_file_is_not_found() {
    let service = FileService::new(MemoryStore::new());
    let response = handle(&service, FileRequest::Download(hello_sha256())).await;
    assert_eq!(response, FileResponse::Error(FileError::NotFound));
    assert_eq!(response.into_result(), Err(FileError::NotFound));

    // Built by hand, as a non-Rust client would read it.
    let request = FileRequest::Download(hello_sha256()).to_cbor().unwrap();
    assert_eq!(
        service.eval(request).await.unwrap(),
        cbor(&Value::Map(vec![(
            Value::Text("error".into()),
            Value::Text("not_found".into())
        )]))
    );
}

#[tokio::test]
async fn eval_speaks_cbor_with_byte_strings() {
    let service = FileService::new(MemoryStore::new());
    // Built by hand, as a non-Rust client would.
    let reply = service
        .eval(message("upload", Value::Bytes(b"hello world".to_vec())))
        .await
        .unwrap();
    assert_eq!(
        reply,
        cbor(&Value::Map(vec![(
            Value::Text("response".into()),
            Value::Bytes(hello_sha256())
        )]))
    );

    let request = FileRequest::Download(hello_sha256()).to_cbor().unwrap();
    assert_eq!(request, message("download", Value::Bytes(hello_sha256())));
    let reply = service.eval(request).await.unwrap();
    assert_eq!(
        FileResponse::from_cbor(&reply).unwrap().into_result(),
        Ok(b"hello world".to_vec())
    );
}

#[tokio::test]
async fn eval_rejects_bad_requests() {
    let service = FileService::new(MemoryStore::new());
    for message in [
        b"not cbor".to_vec(),
        br#"{"type":"upload","body":"aGVsbG8="}"#.to_vec(),
        message("delete", Value::Bytes(vec![])),
        // A file as text, or as an array of integers, rather than a byte string.
        message("upload", Value::Text("hello".into())),
        // Anything but a 32-byte SHA-256 could name another object.
        message("download", Value::Bytes(b"../other-object".to_vec())),
        message("download", Value::Bytes(hello_sha256()[1..].to_vec())),
    ] {
        assert!(service.eval(message.clone()).await.is_err(), "{message:?}");
    }
}

#[tokio::test]
async fn memory_store_round_trips() {
    let store = MemoryStore::new();
    assert_eq!(store.get("a").await.unwrap(), None);
    store.put("a", b"1".to_vec()).await.unwrap();
    assert_eq!(store.get("a").await.unwrap(), Some(b"1".to_vec()));
}

/// Sends `message` sealed to the terminal behind `client` and returns the opened reply.
async fn faf(client: &TtkClient, message: &[u8]) -> Vec<u8> {
    let node = NodePublicKey::from_certificate(client.peer_cert().unwrap()).unwrap();
    let (body, key) = seal::seal_body_with_key(&node, message).unwrap();
    let request = FafRequest {
        relays: vec![],
        body,
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 200, "{:?}", response.text());
    seal::open_response(&key, &response.text().unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn terminal_with_the_file_service_uploads_and_downloads_over_faf() {
    let server = Server::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    server.sign_for_tests().unwrap();
    let addr: SocketAddr = server.local_addr().unwrap();
    let terminal = Terminal::new(server, FileService::new(MemoryStore::new()));
    tokio::spawn(async move { terminal.serve().await.unwrap() });
    let client = TtkClient::connect_with_verifier(
        addr,
        "localhost",
        EnclaveCertVerifier::new().allow_mock(),
    )
    .await
    .unwrap();

    // Binary content survives unchanged.
    let file: Vec<u8> = (0..=255).cycle().take(100_000).collect();
    let upload = FileRequest::Upload(file.clone()).to_cbor().unwrap();
    let hash = FileResponse::from_cbor(&faf(&client, &upload).await)
        .unwrap()
        .into_result()
        .unwrap();
    assert_eq!(hash, Sha256::digest(&file).to_vec());
    let download = FileRequest::Download(hash).to_cbor().unwrap();
    let reply = FileResponse::from_cbor(&faf(&client, &download).await).unwrap();
    assert_eq!(reply.into_result(), Ok(file));

    // A missing file is a sealed not-found reply, still a 200 to the relays.
    let missing = FileRequest::Download(vec![0; 32]).to_cbor().unwrap();
    let reply = FileResponse::from_cbor(&faf(&client, &missing).await).unwrap();
    assert_eq!(reply, FileResponse::Error(FileError::NotFound));

    // An evaluation failure is a bare 500, without detail.
    let node = NodePublicKey::from_certificate(client.peer_cert().unwrap()).unwrap();
    let request = FafRequest {
        relays: vec![],
        body: seal::seal_body_with_key(&node, b"not cbor").unwrap().0,
    };
    let response = client.post_json("/faf", &request).await.unwrap();
    assert_eq!(response.status, 500);
    assert_eq!(response.text().unwrap(), "response evaluation failed");
    client.close().await.unwrap();
}
