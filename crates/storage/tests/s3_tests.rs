//! Tests of [`S3Store`] (feature `s3`): configuration from the environment, and the
//! [`BlobStore`] operations against a minimal S3 fake on a free local port (path-style, over
//! plain HTTP through [`ENDPOINT_ENV`]).
#![cfg(feature = "s3")]

use aws_smithy_runtime_api::client::dns::ResolveDns;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use ttk_storage::storage::s3::{
    LoopbackResolver, S3Store, BUCKET_ENV, ENDPOINT_ENV, IMDS_VSOCK_PORT_ENV, VSOCK_PORT_ENV,
};
use ttk_storage::storage::BlobStore;

/// Bucket the fake serves.
const BUCKET: &str = "ttk-test-bucket";

/// Object key the fake refuses with `403 AccessDenied` (not retried by the SDK).
const DENIED_KEY: &str = "denied";

/// Serializes the tests that change the process environment.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Every variable [`S3Store::from_env`] reads, plus the AWS ones the tests set.
const ENV_VARS: &[&str] = &[
    BUCKET_ENV,
    ENDPOINT_ENV,
    VSOCK_PORT_ENV,
    IMDS_VSOCK_PORT_ENV,
    "AWS_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
];

/// Resets the variables of [`ENV_VARS`] to `vars` (others unset), with static test credentials.
fn set_env(vars: &[(&str, &str)]) {
    for name in ENV_VARS {
        std::env::remove_var(name);
    }
    std::env::set_var("AWS_REGION", "us-east-1");
    std::env::set_var("AWS_ACCESS_KEY_ID", "AKIDTTKTEST");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "ttk-test-secret");
    for (name, value) in vars {
        std::env::set_var(name, value);
    }
}

/// [`S3Store::from_env`] with exactly `vars` set; its error message on failure.
async fn from_env(vars: &[(&str, &str)]) -> Result<S3Store, String> {
    let _lock = ENV_LOCK.lock().await;
    set_env(vars);
    let store = S3Store::from_env().await.map_err(|e| e.to_string());
    set_env(&[]);
    store
}

/// Objects of the fake bucket by key.
type Objects = Arc<Mutex<HashMap<String, Vec<u8>>>>;

/// An S3 error response with `code`.
fn s3_error(status: StatusCode, code: &str) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <Error><Code>{code}</Code><Message>{code}</Message><RequestId>ttk</RequestId></Error>"
    );
    (status, [("content-type", "application/xml")], body).into_response()
}

/// Path-style S3 fake: `PUT` / `GET /<BUCKET>/<key>`, `NoSuchKey` for missing objects.
async fn fake_s3(
    State(objects): State<Objects>,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let Some(key) = uri
        .path()
        .strip_prefix(&format!("/{BUCKET}/"))
        .map(str::to_string)
    else {
        return s3_error(StatusCode::NOT_FOUND, "NoSuchBucket");
    };
    if key == DENIED_KEY {
        return s3_error(StatusCode::FORBIDDEN, "AccessDenied");
    }
    match method {
        Method::PUT => {
            objects.lock().unwrap().insert(key, body.to_vec());
            StatusCode::OK.into_response()
        }
        Method::GET => match objects.lock().unwrap().get(&key) {
            Some(data) => data.clone().into_response(),
            None => s3_error(StatusCode::NOT_FOUND, "NoSuchKey"),
        },
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// Starts the S3 fake on a free local port; its endpoint URL and objects.
async fn start_fake_s3() -> (String, Objects) {
    let objects = Objects::default();
    let app = Router::new().fallback(fake_s3).with_state(objects.clone());
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), objects)
}

#[tokio::test]
async fn from_env_requires_the_bucket() {
    let err = from_env(&[]).await.unwrap_err();
    assert!(err.contains(BUCKET_ENV), "{err}");
}

#[tokio::test]
async fn from_env_rejects_an_empty_bucket() {
    let err = from_env(&[(BUCKET_ENV, "")]).await.unwrap_err();
    assert!(err.contains(BUCKET_ENV), "{err}");
}

#[tokio::test]
async fn from_env_rejects_an_invalid_vsock_port() {
    let err = from_env(&[(BUCKET_ENV, BUCKET), (VSOCK_PORT_ENV, "s3")])
        .await
        .unwrap_err();
    assert!(err.contains(&format!("invalid {VSOCK_PORT_ENV}")), "{err}");
}

#[tokio::test]
async fn from_env_rejects_an_invalid_imds_vsock_port() {
    let err = from_env(&[
        (BUCKET_ENV, BUCKET),
        (VSOCK_PORT_ENV, ""),
        (IMDS_VSOCK_PORT_ENV, "-1"),
    ])
    .await
    .unwrap_err();
    assert!(
        err.contains(&format!("invalid {IMDS_VSOCK_PORT_ENV}")),
        "{err}"
    );
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn from_env_over_vsock_needs_linux() {
    let err = from_env(&[(BUCKET_ENV, BUCKET), (VSOCK_PORT_ENV, "8001")])
        .await
        .unwrap_err();
    assert!(err.contains("S3 over vsock"), "{err}");

    let err = from_env(&[(BUCKET_ENV, BUCKET), (IMDS_VSOCK_PORT_ENV, "8002")])
        .await
        .unwrap_err();
    assert!(err.contains("IMDS over vsock"), "{err}");
}

#[tokio::test]
async fn from_env_without_an_endpoint_uses_the_aws_chain() {
    let store = from_env(&[(BUCKET_ENV, BUCKET), (IMDS_VSOCK_PORT_ENV, "")])
        .await
        .unwrap();
    assert!(format!("{store:?}").contains(BUCKET));
}

#[tokio::test]
async fn put_then_get_round_trips_through_the_endpoint() {
    let (endpoint, objects) = start_fake_s3().await;
    let store = from_env(&[(BUCKET_ENV, BUCKET), (ENDPOINT_ENV, &endpoint)])
        .await
        .unwrap()
        .clone();

    store.put("blob", b"hello world".to_vec()).await.unwrap();
    assert_eq!(
        objects.lock().unwrap().get("blob"),
        Some(&b"hello world".to_vec())
    );
    assert_eq!(
        store.get("blob").await.unwrap(),
        Some(b"hello world".to_vec())
    );
}

#[tokio::test]
async fn get_of_a_missing_object_is_none() {
    let (endpoint, _) = start_fake_s3().await;
    let store = from_env(&[(BUCKET_ENV, BUCKET), (ENDPOINT_ENV, &endpoint)])
        .await
        .unwrap();
    assert_eq!(store.get("missing").await.unwrap(), None);
}

#[tokio::test]
async fn service_errors_are_errors() {
    let (endpoint, _) = start_fake_s3().await;
    let store = from_env(&[(BUCKET_ENV, BUCKET), (ENDPOINT_ENV, &endpoint)])
        .await
        .unwrap();
    assert!(store.put(DENIED_KEY, b"data".to_vec()).await.is_err());
    assert!(store.get(DENIED_KEY).await.is_err());
}

#[tokio::test]
async fn loopback_resolver_answers_loopback_for_every_name() {
    for name in ["s3.us-east-1.amazonaws.com", "example.com", "localhost"] {
        let addrs = LoopbackResolver.resolve_dns(name).await.unwrap();
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }
}
