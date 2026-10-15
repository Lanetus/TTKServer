//! vsock transport for QUIC endpoints inside a Nitro Enclave.
//!
//! An enclave has no network interface: it reaches the outside world only over vsock to the
//! parent instance, which is a stream transport, while QUIC needs datagrams. The sockets here
//! adapt vsock to quinn's datagram socket ([`AsyncUdpSocket`]), relayed on the parent by the
//! `vsock-proxy` binary (this crate):
//!
//! - [`VsockUdpSocket`] (inbound, for the server): listens on a vsock port; each connection from
//!   the parent carries one client's datagrams and appears to quinn as its own synthetic peer
//!   address.
//! - [`VsockOutboundSocket`] (outbound, for clients such as `/faf` relaying): connects to the
//!   parent once per destination, first sending a [destination header](write_destination), and
//!   the parent relays the datagrams to that UDP address.
//! - [`resolve_via_parent`]: the enclave has no DNS either, so host names are resolved by the
//!   parent over a short-lived connection to the same outbound port, opened by a
//!   [resolve request](write_resolve_request) instead of a destination header.
//!
//! On every vsock connection, datagrams are framed as `[u16 big-endian length][payload]`.
//!
//! TCP needs no framing: [`forward_tcp_to_vsock`] carries each local TCP connection over its own
//! vsock connection to the parent, where the `vsock-proxy-tcp` binary forwards it to one fixed
//! remote (e.g. S3).

use bytes::Bytes;
use log::{debug, info, warn};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tokio_vsock::{VsockListener, VsockStream};

/// `VMADDR_CID_ANY`: accept vsock connections addressed to any CID of this VM.
const VMADDR_CID_ANY: u32 = u32::MAX;

/// Received datagrams buffered for the endpoint, across all peers.
const RECV_QUEUE: usize = 1024;

/// Outgoing datagrams buffered per peer; further datagrams are dropped, as a full UDP socket
/// buffer would.
const PEER_QUEUE: usize = 256;

/// Inbound vsock connections served at once (each one task and one outgoing queue of 256
/// datagrams); further connections wait in the listen backlog until one closes. Equal to the
/// number of clients `vsock-proxy` relays at once, so the parent never needs more.
pub const MAX_VSOCK_PEERS: usize = 4096;

/// Outgoing datagram queues, keyed by the peer address quinn sees for each vsock connection.
type Peers = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Bytes>>>>;

/// Datagrams received from any peer, tagged with the peer address.
type Incoming = mpsc::Sender<(SocketAddr, Bytes)>;

/// A QUIC datagram socket accepting length-framed vsock connections (inbound).
#[derive(Debug)]
pub struct VsockUdpSocket {
    port: u32,
    peers: Peers,
    incoming: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    accept_task: JoinHandle<()>,
}

impl VsockUdpSocket {
    /// Listens on vsock `port` (any CID) and starts accepting connections.
    ///
    /// Must be called within a Tokio runtime.
    pub fn bind(port: u32) -> io::Result<Self> {
        let listener = VsockListener::bind(VMADDR_CID_ANY, port)?;
        let peers = Peers::default();
        let (tx, rx) = mpsc::channel(RECV_QUEUE);
        let accept_task = tokio::spawn(accept_loop(listener, peers.clone(), tx));
        Ok(Self {
            port,
            peers,
            incoming: Mutex::new(rx),
            accept_task,
        })
    }
}

impl Drop for VsockUdpSocket {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.peers.lock().unwrap().clear();
    }
}

/// Accepts vsock connections, giving each a unique synthetic peer address. At most
/// [`MAX_VSOCK_PEERS`] are served at once, so the parent cannot exhaust enclave memory.
async fn accept_loop(mut listener: VsockListener, peers: Peers, incoming: Incoming) {
    let slots = Arc::new(Semaphore::new(MAX_VSOCK_PEERS));
    let mut next_id: u64 = 0;
    loop {
        // Only accept once a slot is free: further connections wait in the backlog.
        let Ok(slot) = slots.clone().acquire_owned().await else {
            return;
        };
        if slots.available_permits() == 0 {
            warn!("{MAX_VSOCK_PEERS} vsock peers connected; new connections wait");
        }
        let (stream, vsock_addr) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!("vsock accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        next_id += 1;
        // Unique local address fd00::<id>: never a real peer, only a key for quinn.
        let peer = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from((0xfd00_u128 << 112) | u128::from(next_id)),
            1,
            0,
            0,
        ));
        info!("vsock connection from {vsock_addr:?} as peer {peer}");
        let (tx, rx) = mpsc::channel(PEER_QUEUE);
        peers.lock().unwrap().insert(peer, tx.clone());
        let (peers, incoming) = (peers.clone(), incoming.clone());
        tokio::spawn(async move {
            pump(stream, peer, rx, &incoming).await;
            forget_peer(&peers, peer, &tx);
            info!("vsock peer {peer} disconnected");
            drop(slot);
        });
    }
}

/// A QUIC datagram socket that reaches each destination over its own vsock connection to the
/// parent's `vsock-proxy` (outbound).
#[derive(Debug)]
pub struct VsockOutboundSocket {
    cid: u32,
    port: u32,
    peers: Peers,
    incoming_tx: Incoming,
    incoming: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
}

impl VsockOutboundSocket {
    /// Relays datagrams through the parent's `vsock-proxy` at vsock `cid`:`port` (normally
    /// [`PARENT_CID`](crate::PARENT_CID)). Connections open on the first datagram to each destination.
    ///
    /// Must be used within a Tokio runtime.
    pub fn new(cid: u32, port: u32) -> Self {
        let (incoming_tx, rx) = mpsc::channel(RECV_QUEUE);
        Self {
            cid,
            port,
            peers: Peers::default(),
            incoming_tx,
            incoming: Mutex::new(rx),
        }
    }

    /// Returns the queue toward `destination`, connecting to the proxy if there is none.
    fn peer(&self, destination: SocketAddr) -> mpsc::Sender<Bytes> {
        let mut peers = self.peers.lock().unwrap();
        if let Some(tx) = peers.get(&destination).filter(|tx| !tx.is_closed()) {
            return tx.clone();
        }
        let (tx, rx) = mpsc::channel(PEER_QUEUE);
        peers.insert(destination, tx.clone());

        let (cid, port) = (self.cid, self.port);
        let (peers, incoming) = (self.peers.clone(), self.incoming_tx.clone());
        let own = tx.downgrade();
        tokio::spawn(async move {
            match VsockStream::connect(cid, port).await {
                Ok(mut stream) => match write_destination(&mut stream, destination).await {
                    Ok(()) => {
                        debug!("vsock relay to {destination} via {cid}:{port} open");
                        pump(stream, destination, rx, &incoming).await;
                        debug!("vsock relay to {destination} closed");
                    }
                    Err(e) => warn!("vsock relay to {destination}: sending header failed: {e}"),
                },
                Err(e) => {
                    warn!("vsock relay to {destination}: connect to {cid}:{port} failed: {e}")
                }
            }
            if let Some(tx) = own.upgrade() {
                forget_peer(&peers, destination, &tx);
            }
        });
        tx
    }
}

impl Drop for VsockOutboundSocket {
    fn drop(&mut self) {
        // Dropping the queues ends each connection's pump, closing its vsock stream.
        self.peers.lock().unwrap().clear();
    }
}

/// Writes the header that opens an outbound relay connection: the destination as
/// `[4 | 6][IPv4 or IPv6 address][u16 big-endian port]`. IPv4-mapped IPv6 addresses are sent as
/// IPv4.
pub async fn write_destination<W: AsyncWrite + Unpin>(
    writer: &mut W,
    destination: SocketAddr,
) -> io::Result<()> {
    let mut header = Vec::with_capacity(19);
    match destination.ip().to_canonical() {
        IpAddr::V4(ip) => {
            header.push(4);
            header.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            header.push(6);
            header.extend_from_slice(&ip.octets());
        }
    }
    header.extend_from_slice(&destination.port().to_be_bytes());
    writer.write_all(&header).await
}

/// Reads the header written by [`write_destination`].
pub async fn read_destination<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<SocketAddr> {
    let family = reader.read_u8().await?;
    read_address(family, reader).await
}

/// Reads the rest of a destination header whose family byte `family` was already read.
async fn read_address<R: AsyncRead + Unpin>(family: u8, reader: &mut R) -> io::Result<SocketAddr> {
    let ip = match family {
        4 => {
            let mut octets = [0; 4];
            reader.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        6 => {
            let mut octets = [0; 16];
            reader.read_exact(&mut octets).await?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        family => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown address family {family}"),
            ))
        }
    };
    Ok(SocketAddr::new(ip, reader.read_u16().await?))
}

/// Header family byte of a [resolve request](write_resolve_request), in place of the `4` / `6` of
/// a [destination header](write_destination).
pub const RESOLVE_REQUEST: u8 = 0;

/// Longest host name a [resolve request](write_resolve_request) carries (RFC 1035 §2.3.4).
pub const MAX_HOST_NAME_LEN: usize = 253;

/// Most addresses a [resolve response](write_resolved) carries; further ones are dropped.
pub const MAX_RESOLVED_ADDRESSES: usize = 16;

/// Time allowed for the parent to answer a resolve request ([`resolve_via_parent`]), and for
/// the parent's own lookup ([`answer_resolve`]).
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// What an outbound vsock connection asks the parent's `vsock-proxy` for, read by
/// [`read_outbound_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundRequest {
    /// Relay the connection's datagrams to this UDP address ([`write_destination`]).
    Relay(SocketAddr),
    /// Resolve `host` on the parent and answer its addresses with `port`
    /// ([`write_resolve_request`]); the connection then closes.
    Resolve {
        /// The host name to resolve.
        host: String,
        /// The port of the answered addresses.
        port: u16,
    },
}

/// Checks that `host` is a DNS host name a resolve request may carry: 1 to
/// [`MAX_HOST_NAME_LEN`] ASCII letters, digits, `-` and `.`, with no empty label, and a last
/// label starting with a letter (so it is never a numeric IPv4 address in disguise).
///
/// The parent resolves the names: it learns which next hops a relay contacts and may answer
/// anything. Its answers are egress-filtered again, and RA-TLS still authenticates the hop.
pub fn check_host_name(host: &str) -> io::Result<()> {
    let valid = !host.is_empty()
        && host.len() <= MAX_HOST_NAME_LEN
        && host.trim_end_matches('.').split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        // The last label must start with a letter: otherwise `getaddrinfo` may read the name as
        // a numeric IPv4 address (`2130706433`, `0x7f000001`, `127.1`).
        && host
            .trim_end_matches('.')
            .rsplit('.')
            .next()
            .is_some_and(|label| label.starts_with(|c: char| c.is_ascii_alphabetic()));
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid host name {host:?}"),
        ))
    }
}

/// Writes the header of a resolve request, asking the parent to resolve `host` (an enclave has
/// no DNS): `[0][u8 length][host name][u16 big-endian port]`.
pub async fn write_resolve_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    host: &str,
    port: u16,
) -> io::Result<()> {
    check_host_name(host)?;
    let mut header = Vec::with_capacity(4 + host.len());
    header.push(RESOLVE_REQUEST);
    header.push(host.len() as u8);
    header.extend_from_slice(host.as_bytes());
    header.extend_from_slice(&port.to_be_bytes());
    writer.write_all(&header).await
}

/// Reads the header of an outbound connection: a [destination header](write_destination) or a
/// [resolve request](write_resolve_request).
pub async fn read_outbound_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<OutboundRequest> {
    let family = reader.read_u8().await?;
    if family != RESOLVE_REQUEST {
        return read_address(family, reader)
            .await
            .map(OutboundRequest::Relay);
    }
    let mut host = vec![0; usize::from(reader.read_u8().await?)];
    reader.read_exact(&mut host).await?;
    let host = String::from_utf8(host)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "host name is not UTF-8"))?;
    check_host_name(&host).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let port = reader.read_u16().await?;
    Ok(OutboundRequest::Resolve { host, port })
}

/// Writes the answer to a resolve request: `[u8 count]`, then each address as a
/// [destination header](write_destination). At most [`MAX_RESOLVED_ADDRESSES`] are written.
pub async fn write_resolved<W: AsyncWrite + Unpin>(
    writer: &mut W,
    addresses: &[SocketAddr],
) -> io::Result<()> {
    let addresses = &addresses[..addresses.len().min(MAX_RESOLVED_ADDRESSES)];
    let mut answer = vec![addresses.len() as u8];
    for address in addresses {
        write_destination(&mut answer, *address).await?;
    }
    writer.write_all(&answer).await
}

/// Reads the answer written by [`write_resolved`].
pub async fn read_resolved<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<SocketAddr>> {
    let count = usize::from(reader.read_u8().await?);
    if count > MAX_RESOLVED_ADDRESSES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{count} resolved addresses (at most {MAX_RESOLVED_ADDRESSES})"),
        ));
    }
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        addresses.push(read_destination(reader).await?);
    }
    Ok(addresses)
}

/// Parent side of a resolve request: looks `host` up (within `RESOLVE_TIMEOUT`) and answers
/// the addresses `permit` accepts (the egress policy), deduplicated, on `writer`. A failed
/// lookup is answered with no addresses. Returns how many addresses were answered.
pub async fn answer_resolve<W: AsyncWrite + Unpin>(
    writer: &mut W,
    host: &str,
    port: u16,
    permit: impl Fn(&SocketAddr) -> bool,
) -> io::Result<usize> {
    let mut addresses = Vec::new();
    match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(found)) => {
            for address in found {
                let address = SocketAddr::new(address.ip().to_canonical(), address.port());
                if permit(&address) && !addresses.contains(&address) {
                    addresses.push(address);
                }
            }
        }
        Ok(Err(e)) => debug!("Resolving {host}: {e}"),
        Err(_) => debug!("Resolving {host}: timed out"),
    }
    addresses.truncate(MAX_RESOLVED_ADDRESSES);
    write_resolved(writer, &addresses).await?;
    Ok(addresses.len())
}

/// Enclave side of a resolve request over `stream` (any connection to the parent's
/// `vsock-proxy`): sends the request and reads the answer, within `RESOLVE_TIMEOUT`.
pub async fn resolve_over<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let exchange = async {
        write_resolve_request(stream, host, port).await?;
        read_resolved(stream).await
    };
    tokio::time::timeout(RESOLVE_TIMEOUT, exchange)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "resolving via the parent timed out",
            )
        })?
}

/// Resolves `host` on the parent instance, through its `vsock-proxy` at vsock `cid`:`vsock_port`
/// (the outbound port, normally `5001`): an enclave has no DNS of its own. The addresses carry
/// `port` and are those the parent's egress policy would relay to.
///
/// The answer is not trusted: whichever address is connected to must still pass RA-TLS.
pub async fn resolve_via_parent(
    cid: u32,
    vsock_port: u32,
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let mut stream = VsockStream::connect(cid, vsock_port).await?;
    resolve_over(&mut stream, host, port).await
}

/// Reads one `[u16 big-endian length][payload]` frame; `None` once the stream ends.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Option<Vec<u8>> {
    let len = reader.read_u16().await.ok()?;
    let mut datagram = vec![0; usize::from(len)];
    reader.read_exact(&mut datagram).await.ok()?;
    Some(datagram)
}

/// Writes `datagram` as one `[u16 big-endian length][payload]` frame. Datagrams longer than
/// `u16::MAX` are rejected.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, datagram: &[u8]) -> io::Result<()> {
    let len = u16::try_from(datagram.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too long"))?;
    let mut frame = Vec::with_capacity(2 + datagram.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(datagram);
    writer.write_all(&frame).await
}

/// Pumps one vsock connection until either direction ends: frames in to `incoming` (tagged
/// `peer`), queued datagrams out. The stream is closed on return.
async fn pump(
    stream: VsockStream,
    peer: SocketAddr,
    mut outgoing: mpsc::Receiver<Bytes>,
    incoming: &Incoming,
) {
    let (mut rd, mut wr) = stream.split();
    let read = async {
        while let Some(datagram) = read_frame(&mut rd).await {
            if incoming.send((peer, datagram.into())).await.is_err() {
                break;
            }
        }
    };
    let write = async {
        while let Some(datagram) = outgoing.recv().await {
            if write_frame(&mut wr, &datagram).await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _ = read => {}
        _ = write => {}
    }
}

/// Removes `peer`'s queue, unless it has already been replaced by a newer connection's.
fn forget_peer(peers: &Peers, peer: SocketAddr, own: &mpsc::Sender<Bytes>) {
    let mut peers = peers.lock().unwrap();
    if peers.get(&peer).is_some_and(|tx| tx.same_channel(own)) {
        peers.remove(&peer);
    }
}

/// Queues the datagram(s) of `transmit` on `tx`. Datagrams beyond a full queue are dropped, as
/// UDP would.
fn queue_transmit(tx: &mpsc::Sender<Bytes>, transmit: &Transmit) {
    let segment = transmit
        .segment_size
        .unwrap_or(transmit.contents.len())
        .max(1);
    for datagram in transmit.contents.chunks(segment) {
        if datagram.len() <= usize::from(u16::MAX) {
            let _ = tx.try_send(Bytes::copy_from_slice(datagram));
        }
    }
}

/// Fills `bufs`/`meta` from `rx`: waits for the first datagram, then takes whatever else is
/// already queued.
fn poll_incoming(
    rx: &Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    cx: &mut Context,
    bufs: &mut [IoSliceMut<'_>],
    meta: &mut [RecvMeta],
) -> Poll<io::Result<usize>> {
    let mut rx = rx.lock().unwrap();
    let mut count = 0;
    while count < bufs.len().min(meta.len()) {
        let (addr, datagram) = if count == 0 {
            match rx.poll_recv(cx) {
                Poll::Ready(Some(item)) => item,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "vsock socket stopped",
                    )))
                }
                Poll::Pending => return Poll::Pending,
            }
        } else {
            match rx.try_recv() {
                Ok(item) => item,
                Err(_) => break,
            }
        };
        let len = datagram.len().min(bufs[count].len());
        bufs[count][..len].copy_from_slice(&datagram[..len]);
        meta[count] = RecvMeta {
            addr,
            len,
            stride: len,
            ecn: None,
            dst_ip: None,
        };
        count += 1;
    }
    Poll::Ready(Ok(count))
}

impl AsyncUdpSocket for VsockUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    /// Queues the datagram(s) for the destination's vsock connection. Datagrams to unknown
    /// (disconnected) peers are dropped, as UDP would.
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let tx = self
            .peers
            .lock()
            .unwrap()
            .get(&transmit.destination)
            .cloned();
        if let Some(tx) = tx {
            queue_transmit(&tx, transmit);
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        poll_incoming(&self.incoming, cx, bufs, meta)
    }

    /// `[::]:<port>`, or port 0 if the vsock port does not fit a UDP port.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let port = u16::try_from(self.port).unwrap_or(0);
        Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            port,
            0,
            0,
        )))
    }

    /// Frames are delivered whole, so path MTU discovery may run.
    fn may_fragment(&self) -> bool {
        false
    }
}

impl AsyncUdpSocket for VsockOutboundSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    /// Queues the datagram(s) for the destination, connecting to the proxy if needed.
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        queue_transmit(&self.peer(transmit.destination), transmit);
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        poll_incoming(&self.incoming, cx, bufs, meta)
    }

    /// `[::]:0`, so quinn can reach both IPv4 (as IPv4-mapped) and IPv6 destinations.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            0,
            0,
            0,
        )))
    }

    /// Frames are delivered whole, so path MTU discovery may run.
    fn may_fragment(&self) -> bool {
        false
    }
}

/// Forwards each TCP connection accepted on `listener` (typically loopback inside the enclave)
/// over a new vsock connection to `cid:port`, both ways, until either side closes. Runs until
/// `listener` fails.
///
/// The bytes are opaque: TLS (e.g. to S3) runs inside the enclave, end to end with the remote,
/// so the parent's `vsock-proxy-tcp` only sees ciphertext.
pub async fn forward_tcp_to_vsock(
    listener: tokio::net::TcpListener,
    cid: u32,
    port: u32,
) -> io::Result<()> {
    loop {
        let (mut tcp, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let mut vsock = match VsockStream::connect(cid, port).await {
                Ok(vsock) => vsock,
                Err(e) => {
                    return warn!("TCP from {peer}: vsock connect to {cid}:{port} failed: {e}")
                }
            };
            match tokio::io::copy_bidirectional(&mut tcp, &mut vsock).await {
                Ok((sent, received)) => {
                    debug!("TCP from {peer} closed ({sent} bytes out, {received} bytes in)")
                }
                Err(e) => debug!("TCP from {peer} closed: {e}"),
            }
        });
    }
}

/// Sends never block (full queues drop), so the sockets are always writable.
#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
