//! `vsock-proxy` binary: parent-instance daemon bridging QUIC traffic into and out of the Nitro
//! Enclave.
//!
//! An enclave has no network interface; the parent instance reaches it only over vsock, which is
//! a stream transport. The relay works in both directions, with datagrams carried over vsock as
//! `[u16 big-endian length][payload]` (see `ttk_core::vsock`):
//!
//! - **Inbound**: listens on a UDP socket (default `0.0.0.0:443`) and, for each client address,
//!   opens one vsock connection to the enclave (CID `--cid`, port `--vsock-port`, default
//!   `5000`).
//! - **Outbound**: listens on vsock port `--outbound-port` (default `5001`) for connections from
//!   the enclave (only from CID `--cid`). Each starts with a destination header, and its
//!   datagrams are sent to that UDP address from a socket of its own, with replies framed back.
//!   Destinations that are link-local (including the instance metadata and DNS endpoints),
//!   multicast, broadcast or unspecified are refused, and loopback or private ones are refused
//!   unless `--allow-private` is given (see `ttk_core::egress::classify_hop_address`).
//!
//! The relay only moves opaque QUIC datagrams: TLS terminates inside the enclave, so peers still
//! verify the RA-TLS evidence end to end. It runs in the foreground; run it as a daemon under a
//! service manager such as systemd. Linux only.

#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use ttk_core::vsock_proxy::{parse_relay_args, RelayConfig, RELAY_USAGE};

/// Parses the process arguments and environment, printing usage and exiting on help or error.
fn parse_args() -> RelayConfig {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_relay_args(&args, |name| std::env::var(name).ok()) {
        Ok(Some(config)) => config,
        Ok(None) => {
            log::info!("{RELAY_USAGE}");
            std::process::exit(0);
        }
        Err(e) => {
            log::error!("error: {e}\n\n{RELAY_USAGE}");
            std::process::exit(2);
        }
    }
}

/// Entry point for the `vsock-proxy` binary.
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = parse_args();
    imp::run(config).await
}

/// Entry point for the `vsock-proxy` binary on platforms without vsock.
#[cfg(not(target_os = "linux"))]
fn main() {
    env_logger::init();
    let _ = parse_args();
    log::error!("vsock-proxy needs vsock, which is only available on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{RelayConfig, SocketAddr};
    use bytes::Bytes;
    use log::{debug, info, warn};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc::{self, error::TrySendError};
    use tokio_vsock::{SockAddr, VsockListener, VsockStream};
    use ttk_core::egress::{classify_hop_address, HopAddressClass};
    use ttk_core::vsock::{read_destination, read_frame, write_frame};

    /// `VMADDR_CID_ANY`: accept vsock connections addressed to any CID of this instance.
    const VMADDR_CID_ANY: u32 = u32::MAX;

    /// A peer with no datagrams for this long is dropped and its vsock connection closed.
    const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

    /// Time allowed for an outbound connection to send its destination header.
    const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

    /// Most peers relayed at once in each direction. Each one holds a vsock connection (and,
    /// outbound, a UDP socket), so this bounds what spoofed source addresses can make the relay
    /// open; datagrams from further clients are dropped.
    const MAX_CLIENTS: usize = 4096;

    /// Datagrams buffered per client toward the enclave; further datagrams are dropped, as a
    /// full UDP socket buffer would.
    const CLIENT_QUEUE: usize = 256;

    /// Queues of datagrams toward the enclave, one per client address, tagged with the id of
    /// the relay task draining them.
    type Clients = Arc<Mutex<HashMap<SocketAddr, (u64, mpsc::Sender<Bytes>)>>>;

    /// Relays both directions until the inbound UDP socket or the outbound listener fails.
    pub async fn run(config: RelayConfig) -> std::io::Result<()> {
        let outbound = if config.outbound_port == 0 {
            info!("Outbound relaying disabled");
            None
        } else {
            let listener = VsockListener::bind(VMADDR_CID_ANY, config.outbound_port)?;
            info!(
                "Relaying vsock port {} (from CID {}) -> UDP",
                config.outbound_port, config.cid
            );
            Some(serve_outbound(listener, config.cid, config.allow_private))
        };
        let inbound = serve_inbound(config);
        match outbound {
            Some(outbound) => tokio::try_join!(inbound, outbound).map(|_| ()),
            None => inbound.await,
        }
    }

    /// Inbound: relays UDP datagrams from clients to the enclave, one vsock connection per
    /// client address.
    async fn serve_inbound(config: RelayConfig) -> std::io::Result<()> {
        let udp = Arc::new(UdpSocket::bind(config.listen).await?);
        info!(
            "Relaying UDP {} -> vsock {}:{}",
            udp.local_addr()?,
            config.cid,
            config.vsock_port
        );

        let clients = Clients::default();
        let mut next_id: u64 = 0;
        let mut buf = vec![0u8; usize::from(u16::MAX)];
        loop {
            let (len, client) = udp.recv_from(&mut buf).await?;
            let datagram = Bytes::copy_from_slice(&buf[..len]);

            let mut map = clients.lock().unwrap();
            let tx = match map.get(&client) {
                Some((_, tx)) if !tx.is_closed() => tx.clone(),
                _ => {
                    map.remove(&client);
                    if map.len() >= MAX_CLIENTS {
                        debug!("Dropping datagram from {client}: {MAX_CLIENTS} clients relayed");
                        continue;
                    }
                    let (tx, rx) = mpsc::channel(CLIENT_QUEUE);
                    next_id += 1;
                    map.insert(client, (next_id, tx.clone()));
                    tokio::spawn(relay_client(
                        next_id,
                        client,
                        rx,
                        udp.clone(),
                        clients.clone(),
                        config.clone(),
                    ));
                    tx
                }
            };
            drop(map);

            if let Err(TrySendError::Full(_)) = tx.try_send(datagram) {
                debug!("Dropping datagram from {client}: queue full");
            }
        }
    }

    /// Relays one inbound client: connects to the enclave, then pumps datagrams both ways until
    /// the client goes idle or either side closes.
    async fn relay_client(
        id: u64,
        client: SocketAddr,
        mut rx: mpsc::Receiver<Bytes>,
        udp: Arc<UdpSocket>,
        clients: Clients,
        config: RelayConfig,
    ) {
        match VsockStream::connect(config.cid, config.vsock_port).await {
            Ok(stream) => {
                info!("Client {client} connected");
                let (mut rd, mut wr) = stream.split();
                let to_client = async {
                    while let Some(datagram) = read_frame(&mut rd).await {
                        if let Err(e) = udp.send_to(&datagram, client).await {
                            debug!("Client {client}: UDP send failed: {e}");
                        }
                    }
                };
                let to_enclave = async {
                    while let Ok(Some(datagram)) =
                        tokio::time::timeout(IDLE_TIMEOUT, rx.recv()).await
                    {
                        if write_frame(&mut wr, &datagram).await.is_err() {
                            break;
                        }
                    }
                };
                tokio::select! {
                    _ = to_client => {}
                    _ = to_enclave => {}
                }
                info!("Client {client} disconnected");
            }
            Err(e) => warn!(
                "Client {client}: vsock connect to {}:{} failed: {e}",
                config.cid, config.vsock_port
            ),
        }

        // Forget this client, unless a newer relay has already replaced the entry.
        let mut map = clients.lock().unwrap();
        if map.get(&client).is_some_and(|(entry, _)| *entry == id) {
            map.remove(&client);
        }
    }

    /// Outbound: accepts vsock connections from the enclave (CID `enclave_cid` only) and relays
    /// each to the UDP destination named in its header.
    async fn serve_outbound(
        mut listener: VsockListener,
        enclave_cid: u32,
        allow_private: bool,
    ) -> std::io::Result<()> {
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    warn!("Outbound: vsock accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let cid = match addr {
                SockAddr::Vsock(addr) => addr.cid(),
                _ => u32::MAX,
            };
            if cid != enclave_cid {
                warn!("Outbound: rejecting connection from CID {cid} (expected {enclave_cid})");
                continue;
            }
            if active.load(Ordering::Relaxed) >= MAX_CLIENTS {
                warn!("Outbound: rejecting connection, {MAX_CLIENTS} already relayed");
                continue;
            }
            active.fetch_add(1, Ordering::Relaxed);
            let active = active.clone();
            tokio::spawn(async move {
                relay_outbound(stream, allow_private).await;
                active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    /// Relays one outbound connection: reads its destination, then pumps datagrams between the
    /// vsock and a UDP socket connected to the destination until the destination goes idle or
    /// either side closes. Destinations the egress policy refuses are dropped unanswered.
    async fn relay_outbound(mut stream: VsockStream, allow_private: bool) {
        let destination =
            match tokio::time::timeout(HEADER_TIMEOUT, read_destination(&mut stream)).await {
                Ok(Ok(destination)) => destination,
                Ok(Err(e)) => return warn!("Outbound: invalid destination header: {e}"),
                Err(_) => return warn!("Outbound: no destination header"),
            };
        let permitted = match classify_hop_address(destination.ip()) {
            HopAddressClass::Public => true,
            HopAddressClass::Private => allow_private,
            HopAddressClass::Forbidden => false,
        };
        if !permitted {
            return warn!("Outbound to {destination}: refused by the egress policy");
        }
        let bind: SocketAddr = if destination.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let udp = match UdpSocket::bind(bind).await {
            Ok(udp) => udp,
            Err(e) => return warn!("Outbound to {destination}: UDP bind failed: {e}"),
        };
        if let Err(e) = udp.connect(destination).await {
            return warn!("Outbound to {destination}: UDP connect failed: {e}");
        }
        info!("Outbound to {destination} opened");

        let (mut rd, mut wr) = stream.split();
        let to_destination = async {
            while let Some(datagram) = read_frame(&mut rd).await {
                if let Err(e) = udp.send(&datagram).await {
                    debug!("Outbound to {destination}: UDP send failed: {e}");
                }
            }
        };
        let to_enclave = async {
            let mut buf = vec![0u8; usize::from(u16::MAX)];
            loop {
                match tokio::time::timeout(IDLE_TIMEOUT, udp.recv(&mut buf)).await {
                    Ok(Ok(len)) => {
                        if write_frame(&mut wr, &buf[..len]).await.is_err() {
                            break;
                        }
                    }
                    // ICMP port unreachable from an earlier send; the destination may come up.
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                    Ok(Err(e)) => {
                        debug!("Outbound to {destination}: UDP receive failed: {e}");
                        break;
                    }
                    Err(_) => break,
                }
            }
        };
        tokio::select! {
            _ = to_destination => {}
            _ = to_enclave => {}
        }
        info!("Outbound to {destination} closed");
    }
}
