//! [`BlobStore`] on an Amazon S3 bucket (feature `s3`): each blob is an object keyed by its name.
//!
//! Inside a Nitro Enclave there is no network: with [`VSOCK_PORT_ENV`] set, S3 is reached over
//! vsock instead. Every host name resolves to loopback ([`LoopbackResolver`]), where a local
//! listener on [`LOCAL_PORT`] carries each TCP connection over vsock to the parent
//! ([`forward_tcp_to_vsock`](ttk_ra_server::vsock::forward_tcp_to_vsock)), whose
//! `vsock-proxy-tcp` forwards it to the S3 endpoint. TLS still runs here, end to end with S3,
//! and checks the endpoint's real host name.

use super::BlobStore;
use crate::EvalError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use aws_smithy_http_client::tls::{rustls_provider::CryptoMode, Provider};
use aws_smithy_runtime_api::client::dns::{DnsFuture, ResolveDns};
use log::info;
use std::net::{IpAddr, Ipv4Addr};

/// Environment variable naming the bucket (required by [`S3Store::from_env`]).
pub const BUCKET_ENV: &str = "TTK_S3_BUCKET";

/// Environment variable overriding the S3 endpoint URL (optional, e.g. an S3-compatible store);
/// path-style addressing is used when set.
pub const ENDPOINT_ENV: &str = "TTK_S3_ENDPOINT";

/// Environment variable with the parent's vsock port of `vsock-proxy-tcp` (Linux, optional;
/// conventionally `8001`). When set, S3 is reached over vsock rather than the network.
pub const VSOCK_PORT_ENV: &str = "TTK_S3_VSOCK_PORT";

/// Loopback TCP port carried over vsock: the HTTPS port, so endpoint URLs need no port. An
/// endpoint ([`ENDPOINT_ENV`]) with another port would not reach the listener.
pub const LOCAL_PORT: u16 = 443;

/// A [`BlobStore`] storing each blob as an object of one S3 bucket.
#[derive(Debug, Clone)]
pub struct S3Store {
    client: Client,
    bucket: String,
}

impl S3Store {
    /// Stores in `bucket` through `client`.
    pub fn new(client: Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }

    /// Configures from the environment: the bucket from [`BUCKET_ENV`], an optional endpoint
    /// from [`ENDPOINT_ENV`], the transport from [`VSOCK_PORT_ENV`], and region / credentials
    /// from the standard AWS chain (`AWS_REGION`, `AWS_ACCESS_KEY_ID`, …). HTTPS uses rustls with
    /// `ring`.
    ///
    /// Over vsock, starts the loopback listener on [`LOCAL_PORT`]; must be called within a Tokio
    /// runtime.
    pub async fn from_env() -> Result<Self, EvalError> {
        let bucket = std::env::var(BUCKET_ENV)
            .ok()
            .filter(|bucket| !bucket.is_empty())
            .ok_or_else(|| format!("{BUCKET_ENV} is not set"))?;
        let builder =
            aws_smithy_http_client::Builder::new().tls_provider(Provider::Rustls(CryptoMode::Ring));
        let http_client = match std::env::var(VSOCK_PORT_ENV) {
            Ok(port) => {
                let port = port
                    .parse()
                    .map_err(|e| format!("invalid {VSOCK_PORT_ENV} {port:?}: {e}"))?;
                start_vsock_forwarding(port).await?;
                builder.build_with_resolver(LoopbackResolver)
            }
            Err(_) => builder.build_https(),
        };
        let shared = aws_config::from_env().http_client(http_client).load().await;
        let mut config = aws_sdk_s3::config::Builder::from(&shared);
        if let Ok(endpoint) = std::env::var(ENDPOINT_ENV) {
            info!("S3 endpoint: {endpoint}");
            config = config.endpoint_url(endpoint).force_path_style(true);
        }
        info!("S3 bucket: {bucket}");
        Ok(Self::new(Client::from_conf(config.build()), bucket))
    }
}

/// Listens on loopback [`LOCAL_PORT`] and carries each connection over vsock to the parent's
/// `vsock-proxy-tcp` on `port`.
#[cfg(target_os = "linux")]
async fn start_vsock_forwarding(port: u32) -> Result<(), EvalError> {
    use ttk_ra_server::server::PARENT_CID;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, LOCAL_PORT)).await?;
    info!("S3 over vsock: 127.0.0.1:{LOCAL_PORT} -> {PARENT_CID}:{port}");
    tokio::spawn(async move {
        if let Err(e) = ttk_ra_server::vsock::forward_tcp_to_vsock(listener, PARENT_CID, port).await
        {
            log::error!("S3 over vsock stopped: {e}");
        }
    });
    Ok(())
}

/// vsock is Linux only.
#[cfg(not(target_os = "linux"))]
async fn start_vsock_forwarding(_port: u32) -> Result<(), EvalError> {
    Err(format!("{VSOCK_PORT_ENV} needs vsock, which is only available on Linux").into())
}

/// A DNS resolver answering loopback for every name, so the S3 client connects to the local
/// vsock forwarder while TLS still verifies the name it asked for.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoopbackResolver;

impl ResolveDns for LoopbackResolver {
    fn resolve_dns<'a>(&'a self, _name: &'a str) -> DnsFuture<'a> {
        DnsFuture::ready(Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]))
    }
}

impl BlobStore for S3Store {
    async fn put(&self, name: &str, data: Vec<u8>) -> Result<(), EvalError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(name)
            .content_type("application/octet-stream")
            .body(ByteStream::from(data))
            .send()
            .await?;
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Vec<u8>, EvalError> {
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(name)
            .send()
            .await?;
        Ok(object.body.collect().await?.into_bytes().to_vec())
    }
}
