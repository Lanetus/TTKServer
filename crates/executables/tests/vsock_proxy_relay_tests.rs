//! Tests of the parent-instance proxy binaries (`vsock-proxy`, `vsock-proxy-tcp`) relaying
//! traffic: the binaries run as processes, with the enclave played by this test over vsock to
//! this host (`--cid 1`, `VMADDR_CID_LOCAL`). Linux only; the tests that need vsock connections
//! to this host (the `vsock_loopback` transport) are skipped without it. Each proxy is stopped
//! with `SIGTERM`, which it must answer with a clean exit.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};
use ttk_core::vsock::{
    read_frame, read_resolved, write_destination, write_frame, write_resolve_request,
};

/// `VMADDR_CID_LOCAL`: this host, reachable when the `vsock_loopback` transport is loaded.
const LOCAL_CID: u32 = 1;

/// How long a proxy may take to start, and a relayed exchange to complete.
const WAIT: Duration = Duration::from_secs(10);

/// A running proxy binary, killed on drop unless [`stop`](Proxy::stop)ped.
struct Proxy {
    child: Child,
    log: mpsc::Receiver<String>,
}

impl Proxy {
    /// Starts the proxy binary `bin` with `args` (environment cleared of `TTK_*` defaults) and
    /// waits until it logs `ready`.
    fn start(bin: &str, args: &[&str], ready: &str) -> Self {
        let mut child = Command::new(bin)
            .args(args)
            .env("RUST_LOG", "debug")
            .env_remove("TTK_ENCLAVE_CID")
            .env_remove("TTK_RELAY_LISTEN")
            .env_remove("TTK_VSOCK_PORT")
            .env_remove("TTK_OUTBOUND_VSOCK_PORT")
            .env_remove("TTK_ALLOW_PRIVATE_NEXT_HOPS")
            .env_remove("TTK_TCP_REMOTE")
            .env_remove("TTK_TCP_VSOCK_PORT")
            .env_remove("TTK_TCP_ALLOW_IMDS")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("proxy binary should start");
        let (tx, log) = mpsc::channel();
        let stderr = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let mut proxy = Self { child, log };
        proxy.wait_for(ready);
        proxy
    }

    /// Waits until the proxy logs a line containing `text`, returning it.
    fn wait_for(&mut self, text: &str) -> String {
        loop {
            match self.log.recv_timeout(WAIT) {
                Ok(line) if line.contains(text) => return line,
                Ok(_) => {}
                Err(e) => panic!("proxy never logged {text:?}: {e}"),
            }
        }
    }

    /// Asks the proxy to stop with `SIGTERM` and returns its exit status.
    fn stop(mut self) -> ExitStatus {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        self.wait()
    }

    /// Waits for the proxy to exit on its own.
    fn wait(&mut self) -> ExitStatus {
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(std::time::Instant::now() < deadline, "proxy did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Whether this host can carry vsock connections to itself (`vsock_loopback`), probed on vsock
/// `port`.
async fn vsock_loopback(port: u32) -> bool {
    let Ok(listener) = VsockListener::bind(VsockAddr::new(LOCAL_CID, port)) else {
        return false;
    };
    matches!(
        timeout(Duration::from_secs(2), async {
            let _client = VsockStream::connect(VsockAddr::new(LOCAL_CID, port)).await?;
            listener.accept().await
        })
        .await,
        Ok(Ok(_))
    )
}

/// A loopback UDP address that is free right now.
fn free_udp_addr() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Connects to the proxy's vsock `port` as the enclave would.
async fn connect(port: u32) -> VsockStream {
    timeout(WAIT, VsockStream::connect(VsockAddr::new(LOCAL_CID, port)))
        .await
        .unwrap()
        .unwrap()
}

/// Waits until the proxy closes `stream` (any frame it might send first is a failure).
async fn assert_closed(stream: &mut VsockStream) {
    let mut buf = [0; 64];
    match timeout(WAIT, stream.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("expected the connection closed, got {n} bytes"),
        Err(_) => panic!("connection not closed"),
    }
}

// --- vsock-proxy ---------------------------------------------------------------------------

/// Starts `vsock-proxy` for the enclave on this host, with extra `args`.
fn start_relay(args: &[&str], ready: &str) -> Proxy {
    let mut all = vec!["--cid", "1"];
    all.extend_from_slice(args);
    Proxy::start(env!("CARGO_BIN_EXE_vsock-proxy"), &all, ready)
}

#[tokio::test]
async fn relay_carries_client_datagrams_to_the_enclave_and_back() {
    const ENCLAVE_PORT: u32 = 48_101;
    if !vsock_loopback(ENCLAVE_PORT + 50).await {
        return;
    }
    let enclave = VsockListener::bind(VsockAddr::new(LOCAL_CID, ENCLAVE_PORT)).unwrap();
    let listen = free_udp_addr();
    let proxy = start_relay(
        &[
            "--listen",
            &listen.to_string(),
            "--vsock-port",
            &ENCLAVE_PORT.to_string(),
            "--outbound-port",
            "0",
        ],
        "Relaying UDP",
    );

    // Each client address gets its own vsock connection.
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    first.send_to(b"hello", listen).await.unwrap();
    let (mut first_conn, _) = timeout(WAIT, enclave.accept()).await.unwrap().unwrap();
    assert_eq!(read_frame(&mut first_conn).await.unwrap(), b"hello");
    first.send_to(b"again", listen).await.unwrap();
    assert_eq!(read_frame(&mut first_conn).await.unwrap(), b"again");
    second.send_to(b"other", listen).await.unwrap();
    let (mut second_conn, _) = timeout(WAIT, enclave.accept()).await.unwrap().unwrap();
    assert_eq!(read_frame(&mut second_conn).await.unwrap(), b"other");

    // Replies reach the right client.
    write_frame(&mut first_conn, b"reply").await.unwrap();
    let mut buf = [0; 64];
    let (len, from) = timeout(WAIT, first.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((&buf[..len], from), (&b"reply"[..], listen));

    // Once the enclave closes a client's connection, its next datagram opens a new one.
    drop(first_conn);
    tokio::time::sleep(Duration::from_millis(200)).await;
    first.send_to(b"reopen", listen).await.unwrap();
    let (mut reopened, _) = timeout(WAIT, enclave.accept()).await.unwrap().unwrap();
    assert_eq!(read_frame(&mut reopened).await.unwrap(), b"reopen");

    assert!(proxy.stop().success());
}

#[tokio::test]
async fn relay_survives_an_unreachable_enclave() {
    const ENCLAVE_PORT: u32 = 48_201;
    if !vsock_loopback(ENCLAVE_PORT + 50).await {
        return;
    }
    let listen = free_udp_addr();
    let mut proxy = start_relay(
        &[
            "--listen",
            &listen.to_string(),
            "--vsock-port",
            &ENCLAVE_PORT.to_string(),
            "--outbound-port",
            "0",
        ],
        "Relaying UDP",
    );
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"hello", listen).await.unwrap();
    proxy.wait_for("vsock connect to 1:");
    // Let the failed relay forget the client.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The enclave comes up: the client's next datagram reaches it.
    let enclave = VsockListener::bind(VsockAddr::new(LOCAL_CID, ENCLAVE_PORT)).unwrap();
    client.send_to(b"later", listen).await.unwrap();
    let (mut conn, _) = timeout(WAIT, enclave.accept()).await.unwrap().unwrap();
    assert_eq!(read_frame(&mut conn).await.unwrap(), b"later");
    assert!(proxy.stop().success());
}

#[tokio::test]
async fn relay_carries_enclave_datagrams_out_and_back() {
    const OUTBOUND_PORT: u32 = 48_301;
    if !vsock_loopback(OUTBOUND_PORT + 50).await {
        return;
    }
    let proxy = start_relay(
        &[
            "--listen",
            &free_udp_addr().to_string(),
            "--outbound-port",
            &OUTBOUND_PORT.to_string(),
            "--allow-private",
        ],
        "Relaying vsock port",
    );
    let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut stream = connect(OUTBOUND_PORT).await;
    write_destination(&mut stream, destination.local_addr().unwrap())
        .await
        .unwrap();
    write_frame(&mut stream, b"ping").await.unwrap();
    let mut buf = [0; 64];
    let (len, from) = timeout(WAIT, destination.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..len], b"ping");
    destination.send_to(b"pong", from).await.unwrap();
    assert_eq!(
        timeout(WAIT, read_frame(&mut stream))
            .await
            .unwrap()
            .unwrap(),
        b"pong"
    );
    drop(stream);
    assert!(proxy.stop().success());
}

#[tokio::test]
async fn relay_keeps_relaying_after_an_unreachable_destination() {
    const OUTBOUND_PORT: u32 = 48_401;
    if !vsock_loopback(OUTBOUND_PORT + 50).await {
        return;
    }
    let mut proxy = start_relay(
        &[
            "--listen",
            &free_udp_addr().to_string(),
            "--outbound-port",
            &OUTBOUND_PORT.to_string(),
            "--allow-private",
        ],
        "Relaying vsock port",
    );
    // Nothing listens there: the ICMP port unreachable must not end the relay.
    let closed_port = free_udp_addr();
    let mut stream = connect(OUTBOUND_PORT).await;
    write_destination(&mut stream, closed_port).await.unwrap();
    proxy.wait_for("opened");
    write_frame(&mut stream, b"lost").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    write_frame(&mut stream, b"lost too").await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let destination = UdpSocket::bind(closed_port).await.unwrap();
    write_frame(&mut stream, b"found").await.unwrap();
    let mut buf = [0; 64];
    let (len, _) = timeout(WAIT, destination.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..len], b"found");
    drop(stream);
    proxy.wait_for("closed");
    assert!(proxy.stop().success());
}

#[tokio::test]
async fn relay_resolves_host_names_for_the_enclave() {
    const OUTBOUND_PORT: u32 = 48_501;
    if !vsock_loopback(OUTBOUND_PORT + 50).await {
        return;
    }
    let mut proxy = start_relay(
        &[
            "--listen",
            &free_udp_addr().to_string(),
            "--outbound-port",
            &OUTBOUND_PORT.to_string(),
            "--allow-private",
        ],
        "Relaying vsock port",
    );
    let mut stream = connect(OUTBOUND_PORT).await;
    write_resolve_request(&mut stream, "localhost", 4433)
        .await
        .unwrap();
    let resolved = timeout(WAIT, read_resolved(&mut stream))
        .await
        .unwrap()
        .unwrap();
    assert!(!resolved.is_empty());
    assert!(resolved
        .iter()
        .all(|a| a.ip().is_loopback() && a.port() == 4433));
    assert_closed(&mut stream).await;
    proxy.wait_for("Resolved localhost for the enclave");
    assert!(proxy.stop().success());
}

#[tokio::test]
async fn relay_enforces_the_egress_policy() {
    const OUTBOUND_PORT: u32 = 48_601;
    if !vsock_loopback(OUTBOUND_PORT + 50).await {
        return;
    }
    // Without --allow-private.
    let mut proxy = start_relay(
        &[
            "--listen",
            &free_udp_addr().to_string(),
            "--outbound-port",
            &OUTBOUND_PORT.to_string(),
        ],
        "Relaying vsock port",
    );

    // Loopback names resolve to nothing; the connection closes.
    let mut stream = connect(OUTBOUND_PORT).await;
    write_resolve_request(&mut stream, "localhost", 443)
        .await
        .unwrap();
    assert!(read_resolved(&mut stream).await.unwrap().is_empty());
    assert_closed(&mut stream).await;

    // Private, loopback and forbidden destinations are dropped unanswered.
    for destination in ["127.0.0.1:443", "10.0.0.1:443", "169.254.169.254:80"] {
        let mut stream = connect(OUTBOUND_PORT).await;
        write_destination(&mut stream, destination.parse().unwrap())
            .await
            .unwrap();
        assert_closed(&mut stream).await;
        proxy.wait_for("refused by the egress policy");
    }
    assert!(proxy.stop().success());
}

#[tokio::test]
async fn relay_refuses_malformed_and_foreign_connections() {
    const OUTBOUND_PORT: u32 = 48_701;
    if !vsock_loopback(OUTBOUND_PORT + 50).await {
        return;
    }
    let mut proxy = start_relay(
        &[
            "--listen",
            &free_udp_addr().to_string(),
            "--outbound-port",
            &OUTBOUND_PORT.to_string(),
        ],
        "Relaying vsock port",
    );
    // An unknown header.
    let mut stream = connect(OUTBOUND_PORT).await;
    stream.write_all(&[9, 0, 0]).await.unwrap();
    assert_closed(&mut stream).await;
    proxy.wait_for("invalid header");

    // No header at all, within the header timeout.
    let mut silent = connect(OUTBOUND_PORT).await;
    assert_closed(&mut silent).await;
    proxy.wait_for("no header");
    assert!(proxy.stop().success());

    // Connections from any CID but the enclave's are refused.
    let mut proxy = Proxy::start(
        env!("CARGO_BIN_EXE_vsock-proxy"),
        &[
            "--cid",
            "16",
            "--listen",
            &free_udp_addr().to_string(),
            "--outbound-port",
            &OUTBOUND_PORT.to_string(),
        ],
        "Relaying vsock port",
    );
    let mut foreign = connect(OUTBOUND_PORT).await;
    assert_closed(&mut foreign).await;
    proxy.wait_for("rejecting connection from CID 1");
    assert!(proxy.stop().success());
}

#[test]
fn relay_exits_when_it_cannot_listen() {
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut proxy = Proxy {
        child: Command::new(env!("CARGO_BIN_EXE_vsock-proxy"))
            .args([
                "--cid",
                "1",
                "--listen",
                &taken.local_addr().unwrap().to_string(),
                "--outbound-port",
                "0",
            ])
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        log: mpsc::channel().1,
    };
    let status = proxy.wait();
    assert!(!status.success());
}

// --- vsock-proxy-tcp -----------------------------------------------------------------------

/// Starts `vsock-proxy-tcp` for the enclave on this host, forwarding vsock `port` to `remote`.
fn start_tcp_proxy(port: u32, remote: &str, extra: &[&str]) -> Proxy {
    let port = port.to_string();
    let mut args = vec!["--cid", "1", "--vsock-port", &port, "--remote", remote];
    args.extend_from_slice(extra);
    Proxy::start(
        env!("CARGO_BIN_EXE_vsock-proxy-tcp"),
        &args,
        "Forwarding vsock port",
    )
}

/// A TCP server echoing everything back, on a loopback address.
async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut rd, mut wr) = tcp.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn tcp_proxy_forwards_to_the_remote() {
    const PORT: u32 = 48_801;
    if !vsock_loopback(PORT + 50).await {
        return;
    }
    let remote = tcp_echo().await;
    let mut proxy = start_tcp_proxy(PORT, &remote.to_string(), &["--allow-private"]);
    for message in [&b"first connection"[..], &b"second connection"[..]] {
        let mut stream = connect(PORT).await;
        stream.write_all(message).await.unwrap();
        let mut echoed = vec![0; message.len()];
        timeout(WAIT, stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echoed, message);
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        assert_closed(&mut stream).await;
        proxy.wait_for("closed");
    }
    assert!(proxy.stop().success());
}

#[tokio::test]
async fn tcp_proxy_refuses_private_remotes_by_default() {
    const PORT: u32 = 48_901;
    if !vsock_loopback(PORT + 50).await {
        return;
    }
    let remote = tcp_echo().await;
    let mut proxy = start_tcp_proxy(PORT, &remote.to_string(), &[]);
    let mut stream = connect(PORT).await;
    assert_closed(&mut stream).await;
    proxy.wait_for("refused by the egress policy");
    proxy.wait_for("no address permitted by the egress policy");
    assert!(proxy.stop().success());
}

#[tokio::test]
async fn tcp_proxy_closes_when_the_remote_is_unreachable() {
    const PORT: u32 = 49_001;
    if !vsock_loopback(PORT + 50).await {
        return;
    }
    // A port nothing listens on: the connection is refused.
    let closed = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let mut proxy = start_tcp_proxy(PORT, &closed.to_string(), &["--allow-private"]);
    let mut stream = connect(PORT).await;
    assert_closed(&mut stream).await;
    proxy.wait_for(&format!("To {closed}:"));
    assert!(proxy.stop().success());

    // A remote that does not resolve.
    let mut proxy = start_tcp_proxy(PORT, "does-not-exist.invalid:443", &[]);
    let mut stream = connect(PORT).await;
    assert_closed(&mut stream).await;
    proxy.wait_for("To does-not-exist.invalid:443:");
    assert!(proxy.stop().success());
}

#[tokio::test]
async fn tcp_proxy_refuses_foreign_cids() {
    const PORT: u32 = 49_101;
    if !vsock_loopback(PORT + 50).await {
        return;
    }
    let remote = tcp_echo().await;
    let mut proxy = Proxy::start(
        env!("CARGO_BIN_EXE_vsock-proxy-tcp"),
        &[
            "--cid",
            "17",
            "--vsock-port",
            &PORT.to_string(),
            "--remote",
            &remote.to_string(),
            "--allow-private",
        ],
        "Forwarding vsock port",
    );
    let mut stream = connect(PORT).await;
    assert_closed(&mut stream).await;
    proxy.wait_for("Rejecting connection from CID 1");
    assert!(proxy.stop().success());
}

#[tokio::test]
async fn tcp_proxy_exits_when_it_cannot_listen() {
    const PORT: u32 = 49_201;
    if !vsock_loopback(PORT + 50).await {
        return;
    }
    let _taken = VsockListener::bind(VsockAddr::new(u32::MAX, PORT)).unwrap();
    let mut proxy = Proxy {
        child: Command::new(env!("CARGO_BIN_EXE_vsock-proxy-tcp"))
            .args([
                "--cid",
                "1",
                "--vsock-port",
                &PORT.to_string(),
                "--remote",
                "127.0.0.1:443",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        log: mpsc::channel().1,
    };
    assert!(!proxy.wait().success());
}
