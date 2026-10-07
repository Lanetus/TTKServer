//! Tests for the vsock datagram framing and destination header ([`ttk_core::vsock`]). Linux only.
#![cfg(target_os = "linux")]

use ttk_core::vsock::{read_destination, read_frame, write_destination, write_frame};

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
