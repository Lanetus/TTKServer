//! Tests for the vsock datagram framing, destination header and parent-side host name
//! resolution ([`ttk_core::vsock`]), and the vsock sockets. Linux only; the socket tests that
//! need vsock connections to this host (`vsock_loopback`) are skipped without it.
#![cfg(target_os = "linux")]

use quinn::udp::{RecvMeta, Transmit};
use quinn::AsyncUdpSocket;
use std::io::{self, ErrorKind, IoSliceMut};
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_vsock::{VsockListener, VsockStream};
use ttk_core::vsock::{
    answer_resolve, check_host_name, forward_tcp_to_vsock, read_destination, read_frame,
    read_outbound_request, read_resolved, resolve_over, resolve_via_parent, write_destination,
    write_frame, write_resolve_request, write_resolved, OutboundRequest, VsockOutboundSocket,
    VsockUdpSocket, MAX_HOST_NAME_LEN, MAX_RESOLVED_ADDRESSES, RESOLVE_REQUEST,
};

#[tokio::test]
async fn destination_header_round_trips() {
    for destination in [
        "203.0.113.7:443".parse().unwrap(),
        "[2001:db8::1]:4433".parse().unwrap(),
    ] {
        let mut buf = Vec::new();
        write_destination(&mut buf, destination).await.unwrap();
        assert_eq!(read_destination(&mut &buf[..]).await.unwrap(), destination);
    }
}

#[tokio::test]
async fn mapped_ipv4_destination_is_sent_as_ipv4() {
    let mut buf = Vec::new();
    let mapped = "[::ffff:203.0.113.7]:443".parse().unwrap();
    write_destination(&mut buf, mapped).await.unwrap();
    assert_eq!(buf[0], 4);
    assert_eq!(
        read_destination(&mut &buf[..]).await.unwrap(),
        "203.0.113.7:443".parse().unwrap()
    );
}

#[tokio::test]
async fn rejects_unknown_family() {
    assert!(read_destination(&mut &[5u8, 0, 0][..]).await.is_err());
}

#[tokio::test]
async fn frames_round_trip() {
    let mut buf = Vec::new();
    write_frame(&mut buf, b"hello").await.unwrap();
    write_frame(&mut buf, b"").await.unwrap();
    let mut reader = &buf[..];
    assert_eq!(read_frame(&mut reader).await.unwrap(), b"hello");
    assert_eq!(read_frame(&mut reader).await.unwrap(), b"");
    assert!(read_frame(&mut reader).await.is_none());
    assert!(write_frame(&mut Vec::new(), &vec![0; 70_000])
        .await
        .is_err());
}

#[tokio::test]
async fn resolve_request_round_trips() {
    let mut buf = Vec::new();
    write_resolve_request(&mut buf, "a.root.ttk-servers.net", 443)
        .await
        .unwrap();
    assert_eq!(buf[0], RESOLVE_REQUEST);
    assert_eq!(
        read_outbound_request(&mut &buf[..]).await.unwrap(),
        OutboundRequest::Resolve {
            host: "a.root.ttk-servers.net".to_string(),
            port: 443
        }
    );
}

#[tokio::test]
async fn destination_header_is_a_relay_request() {
    let destination = "203.0.113.7:443".parse().unwrap();
    let mut buf = Vec::new();
    write_destination(&mut buf, destination).await.unwrap();
    assert_eq!(
        read_outbound_request(&mut &buf[..]).await.unwrap(),
        OutboundRequest::Relay(destination)
    );
}

#[test]
fn host_names_are_checked() {
    for host in ["a.root.ttk-servers.net", "localhost", "example.com."] {
        assert!(check_host_name(host).is_ok(), "{host}");
    }
    let too_long = format!("{}.com", "a".repeat(250));
    let long_label = format!("{}.com", "a".repeat(64));
    for host in [
        "",
        ".",
        "a..b",
        ".a",
        "a b",
        "a/b",
        "a\0b",
        "über.de",
        &too_long,
        &long_label,
    ] {
        assert!(check_host_name(host).is_err(), "{host:?}");
    }
}

#[tokio::test]
async fn invalid_host_names_are_refused_both_ways() {
    assert!(write_resolve_request(&mut Vec::new(), "a b", 443)
        .await
        .is_err());
    let mut buf = vec![RESOLVE_REQUEST, 3];
    buf.extend_from_slice(b"a/b");
    buf.extend_from_slice(&443u16.to_be_bytes());
    assert!(read_outbound_request(&mut &buf[..]).await.is_err());
}

#[tokio::test]
async fn resolved_addresses_round_trip() {
    let addresses: Vec<std::net::SocketAddr> = vec![
        "203.0.113.7:443".parse().unwrap(),
        "[2001:db8::1]:443".parse().unwrap(),
    ];
    let mut buf = Vec::new();
    write_resolved(&mut buf, &addresses).await.unwrap();
    assert_eq!(read_resolved(&mut &buf[..]).await.unwrap(), addresses);

    let mut empty = Vec::new();
    write_resolved(&mut empty, &[]).await.unwrap();
    assert!(read_resolved(&mut &empty[..]).await.unwrap().is_empty());
}

#[tokio::test]
async fn resolved_answer_is_capped() {
    let many: Vec<std::net::SocketAddr> = (0..40)
        .map(|i| format!("203.0.113.{i}:443").parse().unwrap())
        .collect();
    let mut buf = Vec::new();
    write_resolved(&mut buf, &many).await.unwrap();
    assert_eq!(
        read_resolved(&mut &buf[..]).await.unwrap(),
        many[..MAX_RESOLVED_ADDRESSES]
    );
    let too_many = [u8::try_from(MAX_RESOLVED_ADDRESSES + 1).unwrap()];
    assert!(read_resolved(&mut &too_many[..]).await.is_err());
}

/// Runs a resolve exchange for `host` between [`resolve_over`] and [`answer_resolve`] over an
/// in-memory stream.
async fn resolve_through_parent(
    host: &str,
    permit: impl Fn(&std::net::SocketAddr) -> bool,
) -> Vec<std::net::SocketAddr> {
    let (mut enclave, mut parent) = tokio::io::duplex(1024);
    let parent_side = async {
        match read_outbound_request(&mut parent).await.unwrap() {
            OutboundRequest::Resolve { host, port } => {
                answer_resolve(&mut parent, &host, port, permit)
                    .await
                    .unwrap();
            }
            other => panic!("expected a resolve request, got {other:?}"),
        }
    };
    let (resolved, ()) = tokio::join!(resolve_over(&mut enclave, host, 4433), parent_side);
    resolved.unwrap()
}

#[tokio::test]
async fn parent_resolves_for_the_enclave() {
    let resolved = resolve_through_parent("localhost", |_| true).await;
    assert!(!resolved.is_empty());
    assert!(resolved
        .iter()
        .all(|a| a.ip().is_loopback() && a.port() == 4433));
}

#[tokio::test]
async fn parent_answers_only_permitted_addresses() {
    assert!(resolve_through_parent("localhost", |_| false)
        .await
        .is_empty());
}

#[tokio::test]
async fn failed_lookup_is_answered_empty() {
    assert!(resolve_through_parent("does-not-exist.invalid", |_| true)
        .await
        .is_empty());
}

#[tokio::test]
async fn truncated_destination_headers_are_refused() {
    for header in [
        &[][..],
        &[4, 203, 0, 113][..],
        &[4, 203, 0, 113, 7, 1][..],
        &[6, 0x20, 0x01, 0x0d, 0xb8][..],
    ] {
        assert!(
            read_destination(&mut &header[..]).await.is_err(),
            "{header:?}"
        );
    }
}

#[tokio::test]
async fn malformed_outbound_requests_are_refused() {
    // Unknown family.
    let err = read_outbound_request(&mut &[9u8, 0, 0][..])
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    // Host name that is not UTF-8.
    let mut not_utf8 = vec![RESOLVE_REQUEST, 2, 0xff, 0xfe];
    not_utf8.extend_from_slice(&443u16.to_be_bytes());
    let err = read_outbound_request(&mut &not_utf8[..]).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    // Truncated host name, missing port.
    assert!(read_outbound_request(&mut &[RESOLVE_REQUEST, 5, b'a'][..])
        .await
        .is_err());
    assert!(read_outbound_request(&mut &[RESOLVE_REQUEST, 1, b'a'][..])
        .await
        .is_err());
    assert!(read_outbound_request(&mut &[][..]).await.is_err());
}

#[tokio::test]
async fn longest_host_name_round_trips() {
    let host = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    assert_eq!(host.len(), MAX_HOST_NAME_LEN);
    let mut buf = Vec::new();
    write_resolve_request(&mut buf, &host, 53).await.unwrap();
    assert_eq!(
        read_outbound_request(&mut &buf[..]).await.unwrap(),
        OutboundRequest::Resolve { host, port: 53 }
    );
}

#[tokio::test]
async fn truncated_resolved_answers_are_refused() {
    assert!(read_resolved(&mut &[][..]).await.is_err());
    let mut buf = Vec::new();
    write_resolved(&mut buf, &["203.0.113.7:443".parse().unwrap()])
        .await
        .unwrap();
    buf[0] = 2;
    assert!(read_resolved(&mut &buf[..]).await.is_err());
}

#[tokio::test]
async fn truncated_frames_end_the_stream() {
    assert!(read_frame(&mut &[0u8][..]).await.is_none());
    assert!(read_frame(&mut &[0u8, 5, b'h', b'i'][..]).await.is_none());
}

#[tokio::test]
async fn largest_frame_round_trips() {
    let datagram = vec![0xa5; usize::from(u16::MAX)];
    let mut buf = Vec::new();
    write_frame(&mut buf, &datagram).await.unwrap();
    assert_eq!(read_frame(&mut &buf[..]).await.unwrap(), datagram);
}

#[tokio::test]
async fn frame_write_errors_are_reported() {
    let (writer, reader) = tokio::io::duplex(16);
    drop(reader);
    let mut writer = writer;
    assert!(write_frame(&mut writer, b"hello").await.is_err());
}

#[tokio::test]
async fn invalid_host_name_is_not_sent() {
    let (mut enclave, mut parent) = tokio::io::duplex(1024);
    let err = resolve_over(&mut enclave, "a b", 443).await.unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    drop(enclave);
    let mut sent = Vec::new();
    parent.read_to_end(&mut sent).await.unwrap();
    assert!(sent.is_empty());
}

#[tokio::test(start_paused = true)]
async fn silent_parent_times_out() {
    let (mut enclave, _parent) = tokio::io::duplex(1024);
    let err = resolve_over(&mut enclave, "localhost", 443)
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
}

#[tokio::test]
async fn closed_parent_is_an_error() {
    let (mut enclave, parent) = tokio::io::duplex(1024);
    drop(parent);
    assert!(resolve_over(&mut enclave, "localhost", 443).await.is_err());
}

#[tokio::test]
async fn answer_is_canonical_and_deduplicated() {
    let mut buf = Vec::new();
    let count = answer_resolve(&mut buf, "localhost", 4433, |_| true)
        .await
        .unwrap();
    let answered = read_resolved(&mut &buf[..]).await.unwrap();
    assert_eq!(answered.len(), count);
    for (i, address) in answered.iter().enumerate() {
        assert_eq!(address.ip(), address.ip().to_canonical());
        assert!(!answered[..i].contains(address), "{address} answered twice");
    }
}

#[tokio::test]
async fn answer_reports_write_errors() {
    let (mut writer, reader) = tokio::io::duplex(16);
    drop(reader);
    assert!(answer_resolve(&mut writer, "localhost", 443, |_| true)
        .await
        .is_err());
}

#[tokio::test]
async fn permit_sees_every_resolved_address() {
    let seen = std::sync::Mutex::new(Vec::new());
    let mut buf = Vec::new();
    answer_resolve(&mut buf, "localhost", 8443, |address| {
        seen.lock().unwrap().push(*address);
        address.is_ipv4()
    })
    .await
    .unwrap();
    let answered = read_resolved(&mut &buf[..]).await.unwrap();
    assert!(answered.iter().all(SocketAddr::is_ipv4));
    let seen = seen.into_inner().unwrap();
    assert!(seen.iter().all(|a| a.port() == 8443));
    assert!(answered.iter().all(|a| seen.contains(a)));
}

// --- vsock sockets -------------------------------------------------------------------------

/// A CID no VM has (`VMADDR_CID_ANY` minus one), so connections to it fail.
const UNREACHABLE_CID: u32 = u32::MAX - 1;

/// `VMADDR_CID_LOCAL`: this VM, reachable when the `vsock_loopback` transport is loaded.
const LOCAL_CID: u32 = 1;

/// A quinn transmit of `contents` to `destination`, split into `segment_size` datagrams.
fn transmit(destination: SocketAddr, contents: &[u8], segment_size: Option<usize>) -> Transmit<'_> {
    Transmit {
        destination,
        ecn: None,
        contents,
        segment_size,
        src_ip: None,
    }
}

/// Datagrams received by a socket, with the peer address quinn sees for each.
type Received = Vec<(SocketAddr, Vec<u8>)>;

/// Polls `socket` once for received datagrams, without waiting.
fn poll_once(socket: &dyn AsyncUdpSocket) -> Poll<io::Result<Received>> {
    let mut storage = [[0u8; 2048]; 4];
    let mut meta = [RecvMeta::default(); 4];
    let mut bufs: Vec<IoSliceMut<'_>> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let mut cx = Context::from_waker(Waker::noop());
    socket
        .poll_recv(&mut cx, &mut bufs, &mut meta)
        .map_ok(|count| {
            meta[..count]
                .iter()
                .zip(&bufs)
                .map(|(meta, buf)| (meta.addr, buf[..meta.len].to_vec()))
                .collect()
        })
}

/// Receives at least one datagram from `socket`, within a few seconds.
async fn recv(socket: &dyn AsyncUdpSocket) -> Received {
    timeout(Duration::from_secs(5), async {
        loop {
            if let Poll::Ready(received) = poll_once(socket) {
                return received.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("no datagram received")
}

/// Whether this host can carry vsock connections to itself (`vsock_loopback`). The socket
/// tests below need it and are skipped without it.
async fn vsock_loopback(port: u32) -> Option<VsockListener> {
    let listener = VsockListener::bind(LOCAL_CID, port).ok()?;
    match timeout(
        Duration::from_secs(2),
        VsockStream::connect(LOCAL_CID, port),
    )
    .await
    {
        Ok(Ok(_)) => {
            let mut listener = listener;
            listener.accept().await.ok()?;
            Some(listener)
        }
        _ => None,
    }
}

#[tokio::test]
async fn outbound_socket_reports_its_properties() {
    let socket = Arc::new(VsockOutboundSocket::new(UNREACHABLE_CID, 5001));
    assert_eq!(
        socket.local_addr().unwrap(),
        "[::]:0".parse::<SocketAddr>().unwrap()
    );
    assert!(!socket.may_fragment());
    let mut poller = socket.clone().create_io_poller();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        poller.as_mut().poll_writable(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(poll_once(&*socket).is_pending());
}

#[tokio::test]
async fn outbound_socket_drops_datagrams_it_cannot_relay() {
    let socket = VsockOutboundSocket::new(UNREACHABLE_CID, 5001);
    let destination = "203.0.113.7:443".parse().unwrap();
    for _ in 0..3 {
        socket
            .try_send(&transmit(destination, b"datagram", None))
            .unwrap();
        // Let the connection attempt fail, so the next send opens a new one.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Empty transmits and oversized datagrams are not errors either.
    socket.try_send(&transmit(destination, b"", None)).unwrap();
    socket
        .try_send(&transmit(destination, &vec![0; 70_000], None))
        .unwrap();
    assert!(poll_once(&socket).is_pending());
}

#[tokio::test]
async fn resolving_via_an_unreachable_parent_fails() {
    if let Ok(resolved) = timeout(
        Duration::from_secs(10),
        resolve_via_parent(UNREACHABLE_CID, 5001, "localhost", 443),
    )
    .await
    {
        assert!(resolved.is_err());
    }
}

#[tokio::test]
async fn tcp_is_closed_when_the_parent_is_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let forwarder = tokio::spawn(forward_tcp_to_vsock(listener, UNREACHABLE_CID, 8001));
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0; 16];
    let read = timeout(Duration::from_secs(10), tcp.read(&mut buf))
        .await
        .expect("TCP connection was not closed");
    assert!(matches!(read, Ok(0) | Err(_)));
    forwarder.abort();
}

#[tokio::test]
async fn inbound_socket_relays_datagrams() {
    const PORT: u32 = 47_101;
    let Some(_) = vsock_loopback(PORT + 100).await else {
        return;
    };
    let socket = Arc::new(VsockUdpSocket::bind(PORT).unwrap());
    assert_eq!(socket.local_addr().unwrap().port(), 47_101);
    assert!(socket.local_addr().unwrap().ip().is_unspecified());
    assert!(!socket.may_fragment());
    let mut poller = socket.clone().create_io_poller();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(poller.as_mut().poll_writable(&mut cx).is_ready());
    assert!(poll_once(&*socket).is_pending());

    // Two parent connections are two distinct peers.
    let mut first = VsockStream::connect(LOCAL_CID, PORT).await.unwrap();
    let mut second = VsockStream::connect(LOCAL_CID, PORT).await.unwrap();
    write_frame(&mut first, b"one").await.unwrap();
    let received = recv(&*socket).await;
    assert_eq!(received.len(), 1);
    let (first_peer, datagram) = &received[0];
    assert_eq!(datagram, b"one");
    write_frame(&mut second, b"two").await.unwrap();
    write_frame(&mut second, b"three").await.unwrap();
    let mut received = recv(&*socket).await;
    if received.len() == 1 {
        received.extend(recv(&*socket).await);
    }
    let second_peer = received[0].0;
    assert_ne!(*first_peer, second_peer);
    assert!(received.iter().all(|(peer, _)| *peer == second_peer));
    let datagrams: Vec<_> = received.iter().map(|(_, d)| d.as_slice()).collect();
    assert_eq!(datagrams, [&b"two"[..], &b"three"[..]]);

    // Replies go to the right connection, split by segment size.
    socket
        .try_send(&transmit(*first_peer, b"abcdef", Some(4)))
        .unwrap();
    assert_eq!(read_frame(&mut first).await.unwrap(), b"abcd");
    assert_eq!(read_frame(&mut first).await.unwrap(), b"ef");

    // Datagrams to unknown or disconnected peers are dropped.
    socket
        .try_send(&transmit("[fd00::ffff]:1".parse().unwrap(), b"x", None))
        .unwrap();
    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    socket
        .try_send(&transmit(*first_peer, b"gone", None))
        .unwrap();

    // Once the socket is dropped, a connection ends at its next datagram.
    drop(poller);
    drop(socket);
    write_frame(&mut second, b"late").await.unwrap();
    let closed = timeout(Duration::from_secs(5), read_frame(&mut second)).await;
    assert!(matches!(closed, Ok(None)));
}

#[tokio::test]
async fn inbound_socket_with_a_large_port_has_no_udp_port() {
    const PORT: u32 = 100_000;
    let Some(_) = vsock_loopback(47_201).await else {
        return;
    };
    let socket = VsockUdpSocket::bind(PORT).unwrap();
    assert_eq!(socket.local_addr().unwrap().port(), 0);
}

#[tokio::test]
async fn outbound_socket_relays_through_the_parent() {
    const PORT: u32 = 47_301;
    let Some(_) = vsock_loopback(PORT + 100).await else {
        return;
    };
    let mut proxy = VsockListener::bind(LOCAL_CID, PORT).unwrap();
    let socket = VsockOutboundSocket::new(LOCAL_CID, PORT);
    let destination: SocketAddr = "203.0.113.7:443".parse().unwrap();
    socket
        .try_send(&transmit(destination, b"hello", None))
        .unwrap();
    let (mut stream, _) = timeout(Duration::from_secs(5), proxy.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read_destination(&mut stream).await.unwrap(), destination);
    assert_eq!(read_frame(&mut stream).await.unwrap(), b"hello");

    // Further datagrams reuse the connection.
    socket
        .try_send(&transmit(destination, b"again", None))
        .unwrap();
    assert_eq!(read_frame(&mut stream).await.unwrap(), b"again");

    write_frame(&mut stream, b"reply").await.unwrap();
    assert_eq!(recv(&socket).await, [(destination, b"reply".to_vec())]);

    // Once the parent closes it, the next datagram opens a new connection.
    drop(stream);
    tokio::time::sleep(Duration::from_millis(200)).await;
    socket
        .try_send(&transmit(destination, b"reopen", None))
        .unwrap();
    let (mut stream, _) = timeout(Duration::from_secs(5), proxy.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read_destination(&mut stream).await.unwrap(), destination);
    assert_eq!(read_frame(&mut stream).await.unwrap(), b"reopen");

    // Dropping the socket closes its connections.
    drop(socket);
    let closed = timeout(Duration::from_secs(5), read_frame(&mut stream)).await;
    assert!(matches!(closed, Ok(None)));
}

#[tokio::test]
async fn enclave_resolves_through_a_vsock_parent() {
    const PORT: u32 = 47_401;
    let Some(_) = vsock_loopback(PORT + 100).await else {
        return;
    };
    let mut parent = VsockListener::bind(LOCAL_CID, PORT).unwrap();
    let parent_side = tokio::spawn(async move {
        let (mut stream, _) = parent.accept().await.unwrap();
        match read_outbound_request(&mut stream).await.unwrap() {
            OutboundRequest::Resolve { host, port } => {
                answer_resolve(&mut stream, &host, port, |_| true)
                    .await
                    .unwrap()
            }
            other => panic!("expected a resolve request, got {other:?}"),
        }
    });
    let resolved = resolve_via_parent(LOCAL_CID, PORT, "localhost", 4433)
        .await
        .unwrap();
    assert_eq!(resolved.len(), parent_side.await.unwrap());
    assert!(resolved
        .iter()
        .all(|a| a.ip().is_loopback() && a.port() == 4433));
}

#[tokio::test]
async fn tcp_is_forwarded_over_vsock() {
    const PORT: u32 = 47_501;
    let Some(_) = vsock_loopback(PORT + 100).await else {
        return;
    };
    // The parent's `vsock-proxy-tcp`, echoing instead of forwarding.
    let mut parent = VsockListener::bind(LOCAL_CID, PORT).unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = parent.accept().await.unwrap();
        let mut buf = [0; 64];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => stream.write_all(&buf[..n]).await.unwrap(),
            }
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let forwarder = tokio::spawn(forward_tcp_to_vsock(listener, LOCAL_CID, PORT));

    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"opaque bytes").await.unwrap();
    let mut buf = [0; 12];
    timeout(Duration::from_secs(5), tcp.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"opaque bytes");
    drop(tcp);
    timeout(Duration::from_secs(5), echo)
        .await
        .unwrap()
        .unwrap();
    forwarder.abort();
}
