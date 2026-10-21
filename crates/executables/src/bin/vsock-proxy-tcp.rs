//! `vsock-proxy-tcp` binary: parent-instance daemon forwarding TCP connections from the Nitro
//! Enclave to one fixed remote, such as the S3 endpoint the `s3-server` node stores files in.
//!
//! An enclave has no network interface, and `vsock-proxy` only relays QUIC (UDP). This proxy
//! listens on vsock port `--vsock-port` (default `8001`) for connections from the enclave (only
//! from CID `--cid`) and pipes each to a new TCP connection to `--remote`. The enclave never
//! chooses the destination: the remote is fixed here and resolved by the parent on each
//! connection, and an address the egress policy refuses (link-local, including the instance
//! metadata and DNS endpoints, multicast, broadcast, unspecified; loopback or private unless
//! `--allow-private`) is never connected to (see `ttk_core::egress::classify_hop_address`).
//! The one exception is the EC2 instance metadata service with `--allow-imds`, so a second
//! instance (`--remote 169.254.169.254:80`, vsock port `8002`) can give the enclave the instance
//! role's credentials. In that mode the bytes are not opaque: each HTTP request is checked
//! (`ttk_core::vsock_proxy_tcp::check_imds_request`) and only IMDSv2 token and role credential
//! requests are forwarded; anything else closes the connection.
//!
//! The proxy only moves opaque bytes: TLS terminates inside the enclave, end to end with the
//! remote. It runs in the foreground; run it as a daemon under a service manager such as
//! systemd. `SIGTERM` / `SIGINT` stop it cleanly. Linux only.

use ttk_core::vsock_proxy_tcp::{parse_tcp_proxy_args, TcpProxyConfig, TCP_PROXY_USAGE};

/// Parses the process arguments and environment, printing usage and exiting on help or error.
fn parse_args() -> TcpProxyConfig {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_tcp_proxy_args(&args, |name| std::env::var(name).ok()) {
        Ok(Some(config)) => config,
        Ok(None) => {
            log::info!("{TCP_PROXY_USAGE}");
            std::process::exit(0);
        }
        Err(e) => {
            log::error!("error: {e}\n\n{TCP_PROXY_USAGE}");
            std::process::exit(2);
        }
    }
}

/// Entry point for the `vsock-proxy-tcp` binary: runs until the listener fails (an error) or the
/// process gets `SIGTERM` / `SIGINT` (a clean exit).
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = parse_args();
    tokio::select! {
        result = imp::run(config) => result,
        () = ttk_executables::shutdown::shutdown_signal() => Ok(()),
    }
}

/// Entry point for the `vsock-proxy-tcp` binary on platforms without vsock.
#[cfg(not(target_os = "linux"))]
fn main() {
    env_logger::init();
    let _ = parse_args();
    log::error!("vsock-proxy-tcp needs vsock, which is only available on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod imp {
    use super::TcpProxyConfig;
    use log::{debug, info, warn};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_vsock::{VsockAddr, VsockListener, VsockStream};
    use ttk_core::egress::{classify_hop_address, is_instance_metadata_address, HopAddressClass};
    use ttk_core::vsock_proxy_tcp::check_imds_request;

    /// `VMADDR_CID_ANY`: accept vsock connections addressed to any CID of this instance.
    const VMADDR_CID_ANY: u32 = u32::MAX;

    /// Most connections forwarded at once; further ones are refused.
    const MAX_CONNECTIONS: usize = 1024;

    /// Time allowed to resolve and connect to the remote.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Accepts vsock connections from the enclave and forwards each to the remote, until the
    /// listener fails.
    pub async fn run(config: TcpProxyConfig) -> std::io::Result<()> {
        let listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, config.vsock_port))?;
        info!(
            "Forwarding vsock port {} (from CID {}) -> TCP {}",
            config.vsock_port, config.cid, config.remote
        );
        let config = Arc::new(config);
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    warn!("vsock accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let cid = addr.cid();
            if cid != config.cid {
                warn!(
                    "Rejecting connection from CID {cid} (expected {})",
                    config.cid
                );
                continue;
            }
            if active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                warn!("Rejecting connection, {MAX_CONNECTIONS} already forwarded");
                continue;
            }
            active.fetch_add(1, Ordering::Relaxed);
            let (active, config) = (active.clone(), config.clone());
            tokio::spawn(async move {
                forward(stream, &config).await;
                active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    /// Connects to the remote and pipes bytes both ways until either side closes.
    async fn forward(mut vsock: VsockStream, config: &TcpProxyConfig) {
        let mut tcp = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect(&config.remote, config.allow_private, config.allow_imds),
        )
        .await
        {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(e)) => return warn!("To {}: {e}", config.remote),
            Err(_) => return warn!("To {}: connect timed out", config.remote),
        };
        if config.allow_imds {
            return forward_imds(vsock, tcp, &config.remote).await;
        }
        match tokio::io::copy_bidirectional(&mut vsock, &mut tcp).await {
            Ok((sent, received)) => debug!(
                "To {} closed ({sent} bytes out, {received} bytes in)",
                config.remote
            ),
            Err(e) => debug!("To {} closed: {e}", config.remote),
        }
    }

    /// Forwards the enclave's requests to the instance metadata service one at a time, after
    /// [`check_imds_request`]; responses pass back unchanged. A refused or malformed request
    /// closes the connection.
    async fn forward_imds(mut vsock: VsockStream, mut tcp: TcpStream, remote: &str) {
        let (mut from_enclave, mut to_enclave) = vsock.split();
        let (mut from_imds, mut to_imds) = tcp.split();
        let responses = tokio::io::copy(&mut from_imds, &mut to_enclave);
        let requests = async {
            let mut buffered = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match check_imds_request(&buffered) {
                    Ok(Some(head_len)) => {
                        to_imds.write_all(&buffered[..head_len]).await?;
                        buffered.drain(..head_len);
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!("To {remote}: refusing a request: {e}");
                        return Ok(());
                    }
                }
                let read = from_enclave.read(&mut chunk).await?;
                if read == 0 {
                    return Ok::<_, std::io::Error>(());
                }
                buffered.extend_from_slice(&chunk[..read]);
            }
        };
        tokio::select! {
            result = requests => if let Err(e) = result { debug!("To {remote} closed: {e}") },
            result = responses => if let Err(e) = result { debug!("To {remote} closed: {e}") },
        }
    }

    /// Resolves `remote` and connects to the first address the egress policy permits that
    /// accepts. With `allow_imds`, the instance metadata service is permitted too.
    async fn connect(
        remote: &str,
        allow_private: bool,
        allow_imds: bool,
    ) -> std::io::Result<TcpStream> {
        let mut last_error = None;
        for addr in tokio::net::lookup_host(remote).await? {
            let permitted = match classify_hop_address(addr.ip()) {
                _ if allow_imds && is_instance_metadata_address(addr.ip()) => true,
                HopAddressClass::Public => true,
                HopAddressClass::Private => allow_private,
                HopAddressClass::Forbidden => false,
            };
            if !permitted {
                warn!("To {remote}: {addr} refused by the egress policy");
                continue;
            }
            match TcpStream::connect(addr).await {
                Ok(tcp) => return Ok(tcp),
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error
            .unwrap_or_else(|| std::io::Error::other("no address permitted by the egress policy")))
    }
}
