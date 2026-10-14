//! [`BlobStore`] on an Amazon S3 bucket (feature `s3`): each blob is an object keyed by its name.
//!
//! Inside a Nitro Enclave there is no network: with [`VSOCK_PORT_ENV`] set, S3 is reached over
//! vsock instead. Every host name resolves to loopback ([`LoopbackResolver`]), where a local
//! listener on [`LOCAL_PORT`] carries each TCP connection over vsock to the parent
//! (`ttk_ra_server::vsock::forward_tcp_to_vsock`, Linux only), whose
//! `vsock-proxy-tcp` forwards it to the S3 endpoint. TLS still runs here, end to end with S3,
//! and checks the endpoint's real host name.
//!
//! The enclave cannot reach the EC2 instance metadata service either: with
//! [`IMDS_VSOCK_PORT_ENV`] set, credentials come from the parent instance's IAM role through a
//! second `vsock-proxy-tcp` (`--allow-imds --remote 169.254.169.254:80`), reached from loopback
//! [`IMDS_LOCAL_PORT`]. Those credentials pass through the parent, which holds the role anyway.

use super::BlobStore;
use crate::EvalError;
use aws_config::imds::credentials::ImdsCredentialsProvider;
use aws_config::provider_config::ProviderConfig;
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

/// Environment variable with the parent's vsock port of the `vsock-proxy-tcp` forwarding to the
/// instance metadata service (Linux, optional; conventionally `8002`). When set, credentials
/// come from the instance role over vsock instead of the standard AWS chain.
pub const IMDS_VSOCK_PORT_ENV: &str = "TTK_IMDS_VSOCK_PORT";

/// Loopback TCP port carried over vsock to the instance metadata service (plain HTTP).
pub const IMDS_LOCAL_PORT: u16 = 80;

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
    /// from the standard AWS chain (`AWS_REGION`, `AWS_ACCESS_KEY_ID`, …), or credentials from the
    /// instance metadata service over vsock with [`IMDS_VSOCK_PORT_ENV`]. HTTPS uses rustls with
    /// `ring`.
    ///
    /// Over vsock, starts the loopback listeners on [`LOCAL_PORT`] (and [`IMDS_LOCAL_PORT`]); must
    /// be called within a Tokio runtime.
    pub async fn from_env() -> Result<Self, EvalError> {
        let bucket = std::env::var(BUCKET_ENV)
            .ok()
            .filter(|bucket| !bucket.is_empty())
            .ok_or_else(|| format!("{BUCKET_ENV} is not set"))?;
        let builder =
            aws_smithy_http_client::Builder::new().tls_provider(Provider::Rustls(CryptoMode::Ring));
        let http_client = match vsock_port(VSOCK_PORT_ENV)? {
            Some(port) => {
                start_vsock_forwarding("S3", LOCAL_PORT, port).await?;
                builder.build_with_resolver(LoopbackResolver)
            }
            None => builder.build_https(),
        };
        let mut loader = aws_config::from_env().http_client(http_client.clone());
        if let Some(port) = vsock_port(IMDS_VSOCK_PORT_ENV)? {
            start_vsock_forwarding("IMDS", IMDS_LOCAL_PORT, port).await?;
            let provider_config = ProviderConfig::default().with_http_client(http_client);
            let imds = aws_config::imds::Client::builder()
                .configure(&provider_config)
                .endpoint(format!("http://127.0.0.1:{IMDS_LOCAL_PORT}"))?
                .build();
            info!("S3 credentials: instance role via IMDS over vsock");
            loader = loader.credentials_provider(
                ImdsCredentialsProvider::builder()
                    .configure(&provider_config)
                    .imds_client(imds)
                    .build(),
            );
        }
        let shared = loader.load().await;
        let mut config = aws_sdk_s3::config::Builder::from(&shared);
        if let Ok(endpoint) = std::env::var(ENDPOINT_ENV) {
            info!("S3 endpoint: {endpoint}");
            config = config.endpoint_url(endpoint).force_path_style(true);
        }
        info!("S3 bucket: {bucket}");
        Ok(Self::new(Client::from_conf(config.build()), bucket))
    }
}

/// The vsock port in the environment variable `name`, if set and not empty.
fn vsock_port(name: &str) -> Result<Option<u32>, EvalError> {
    match std::env::var(name) {
        Ok(port) if port.is_empty() => Ok(None),
        Ok(port) => Ok(Some(
            port.parse()
                .map_err(|e| format!("invalid {name} {port:?}: {e}"))?,
        )),
        Err(_) => Ok(None),
    }
}

/// Listens on loopback `local_port` and carries each connection over vsock to the parent's
/// `vsock-proxy-tcp` on `port`; `what` names the destination in logs.
#[cfg(target_os = "linux")]
async fn start_vsock_forwarding(what: &str, local_port: u16, port: u32) -> Result<(), EvalError> {
    use ttk_ra_server::server::PARENT_CID;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, local_port)).await?;
    info!("{what} over vsock: 127.0.0.1:{local_port} -> {PARENT_CID}:{port}");
    let what = what.to_string();
    tokio::spawn(async move {
        if let Err(e) = ttk_ra_server::vsock::forward_tcp_to_vsock(listener, PARENT_CID, port).await
        {
            log::error!("{what} over vsock stopped: {e}");
        }
    });
    Ok(())
}

/// vsock is Linux only.
#[cfg(not(target_os = "linux"))]
async fn start_vsock_forwarding(what: &str, _local_port: u16, _port: u32) -> Result<(), EvalError> {
    Err(format!("{what} over vsock needs vsock, which is only available on Linux").into())
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

    async fn get(&self, name: &str) -> Result<Option<Vec<u8>>, EvalError> {
        let object = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(name)
            .send()
            .await
        {
            Ok(object) => object,
            Err(e) if e.as_service_error().is_some_and(|e| e.is_no_such_key()) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        Ok(Some(object.body.collect().await?.into_bytes().to_vec()))
    }
}
