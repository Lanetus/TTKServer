//! Criterion benchmarks for the `ttk_client` library.
//!
//! Covers the offline helpers (hex encoding, extracting the RA-TLS evidence from
//! the server certificate) and the online paths against an in-process server with mock
//! attestation: a full QUIC + RA-TLS handshake (including evidence appraisal) and an HTTP/3
//! (RFC 9114) GET over an established connection.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::net::SocketAddr;
use tokio::runtime::Runtime;
use ttk_client::{extract_attestation_doc, hex_encode, EnclaveCertVerifier, TtkClient};
use ttk_core::server::Server;

/// Starts a mock-attestation server on a free local port inside `rt` and returns its address.
fn start_server(rt: &Runtime) -> SocketAddr {
    rt.block_on(async {
        let server = Server::bind("127.0.0.1:0".parse().unwrap()).expect("server should start");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        addr
    })
}

/// Connects to `addr`, accepting mock attestation.
async fn connect(addr: SocketAddr) -> TtkClient {
    TtkClient::connect_with_verifier(addr, "localhost", EnclaveCertVerifier::new().allow_mock())
        .await
        .expect("mock evidence should verify with mock allowed")
}

fn bench_offline(c: &mut Criterion) {
    let digest = [0xabu8; 32];
    c.bench_function("hex_encode/32B", |b| {
        b.iter(|| hex_encode(black_box(&digest)))
    });
}

fn bench_online(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let addr = start_server(&rt);

    // Grab the server's RA-TLS certificate once for the extraction benchmark.
    let cert = rt.block_on(async {
        let client = connect(addr).await;
        let cert = client.peer_cert().expect("peer cert").to_vec();
        client.close().await.unwrap();
        cert
    });
    c.bench_function("extract_attestation_doc", |b| {
        b.iter(|| extract_attestation_doc(black_box(&cert)).unwrap())
    });

    let mut group = c.benchmark_group("h3");
    group.sample_size(20);

    group.bench_function("connect_and_verify", |b| {
        b.iter(|| {
            rt.block_on(async {
                let client = connect(addr).await;
                client.close().await.unwrap();
            })
        })
    });

    let client = rt.block_on(connect(addr));
    group.bench_function("get_root", |b| {
        b.iter(|| rt.block_on(client.get(black_box("/"))).unwrap())
    });
    group.finish();
    rt.block_on(client.close()).unwrap();
}

criterion_group!(benches, bench_offline, bench_online);
criterion_main!(benches);
