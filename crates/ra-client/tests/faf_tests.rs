//! Tests of `POST /faf` relay address parsing, node resolution and the egress policy
//! (`ttk_ra_client`).
//! The wire format and its sealing are tested in `ttk-core` (`crates/core/tests/faf_tests.rs`).

use ttk_ra_client::{
    classify_hop_address, parse_relay_address, parse_relay_server, resolve_node, ClientTransport,
    HopAddressClass, DEFAULT_RELAY_PORT,
};

#[test]
fn relay_server_accepts_host_port_and_https_forms() {
    let parse = |s: &str| parse_relay_server(s).unwrap();
    assert_eq!(parse("relay.example:9000"), ("relay.example".into(), 9000));
    assert_eq!(
        parse("relay.example"),
        ("relay.example".into(), DEFAULT_RELAY_PORT)
    );
    assert_eq!(
        parse("https://relay.example"),
        ("relay.example".into(), DEFAULT_RELAY_PORT)
    );
    assert_eq!(
        parse("https://10.0.0.1:4500/faf"),
        ("10.0.0.1".into(), 4500)
    );
    assert_eq!(parse("[::1]:4433"), ("::1".into(), 4433));
    assert_eq!(parse(" https://[::1] "), ("::1".into(), DEFAULT_RELAY_PORT));
}

#[test]
fn relay_address_carries_a_ten_digit_salt() {
    assert_eq!(
        parse_relay_address("https://server.com:443 0123456789", true),
        Ok("https://server.com:443")
    );
    assert_eq!(
        parse_relay_address(" https://server.com:443  0123456789 ", false),
        Ok("https://server.com:443")
    );
    assert_eq!(
        parse_relay_address("https://server.com:443", false),
        Ok("https://server.com:443")
    );
    assert!(parse_relay_address("https://server.com:443", true).is_err());
    assert!(parse_relay_address("https://server.com:443 123456789", false).is_err());
    assert!(parse_relay_address("https://server.com:443 01234567890", false).is_err());
    assert!(parse_relay_address("https://server.com:443 012345678x", false).is_err());
}

#[test]
fn hop_addresses_are_classified_for_the_egress_policy() {
    let class = |ip: &str| classify_hop_address(ip.parse().unwrap());
    for public in ["8.8.8.8", "52.95.110.1", "2001:4860:4860::8888"] {
        assert_eq!(class(public), HopAddressClass::Public, "{public}");
    }
    for private in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",
        "100.64.0.1",
        "::1",
        "fd00::1",
        "::ffff:10.0.0.1",
    ] {
        assert_eq!(class(private), HopAddressClass::Private, "{private}");
    }
    for forbidden in [
        "0.0.0.0",
        "0.1.2.3",
        "169.254.169.254",
        "169.254.169.253",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "fe80::1",
        "ff02::1",
        "::ffff:169.254.169.254",
    ] {
        assert_eq!(class(forbidden), HopAddressClass::Forbidden, "{forbidden}");
    }
}

#[tokio::test]
async fn ip_literals_resolve_without_a_lookup() {
    // Even over vsock (no parent here): IP literals need no resolver.
    let vsock = ClientTransport::Vsock { cid: 3, port: 5001 };
    for transport in [ClientTransport::Udp, vsock] {
        assert_eq!(
            resolve_node(transport, "203.0.113.7", 443).await.unwrap(),
            vec!["203.0.113.7:443".parse().unwrap()]
        );
        assert_eq!(
            resolve_node(transport, "2001:db8::1", 443).await.unwrap(),
            vec!["[2001:db8::1]:443".parse().unwrap()]
        );
    }
}

#[tokio::test]
async fn host_names_resolve_over_udp_with_the_system_resolver() {
    let resolved = resolve_node(ClientTransport::Udp, "localhost", 4433)
        .await
        .unwrap();
    assert!(!resolved.is_empty());
    assert!(resolved
        .iter()
        .all(|a| a.ip().is_loopback() && a.port() == 4433));
}
