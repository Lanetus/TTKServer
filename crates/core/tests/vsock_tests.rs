//! Tests for the vsock datagram framing, destination header and parent-side host name
//! resolution ([`ttk_core::vsock`]). Linux only.
#![cfg(target_os = "linux")]

use ttk_core::vsock::{
    answer_resolve, check_host_name, read_destination, read_frame, read_outbound_request,
    read_resolved, resolve_over, write_destination, write_frame, write_resolve_request,
    write_resolved, OutboundRequest, MAX_RESOLVED_ADDRESSES, RESOLVE_REQUEST,
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
