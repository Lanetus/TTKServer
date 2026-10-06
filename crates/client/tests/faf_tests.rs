//! Tests of the `POST /faf` request format and its onion sealing (`ttk_client::faf`,
//! `ttk_client::seal`).

use rcgen::KeyPair;
use ttk_client::faf::{
    classify_hop_address, parse_relay_address, parse_relay_server, FafBody, FafRelay, FafRequest,
    HopAddressClass, DEFAULT_RELAY_PORT,
};
use ttk_client::seal::{self, NodePublicKey, NodeSecretKey, SALT_DIGITS};

/// A fresh RA-TLS-style key pair, as the server generates at startup.
fn key_pair() -> (NodeSecretKey, NodePublicKey) {
    let secret =
        NodeSecretKey::from_pkcs8_der(&KeyPair::generate().unwrap().serialize_der()).unwrap();
    let public = secret.public_key();
    (secret, public)
}

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
fn sealed_address_opens_to_the_server_and_a_fresh_salt() {
    let (secret, public) = key_pair();
    let sealed = seal::seal_address(&public, "https://server.com:443").unwrap();
    let opened = seal::open_address(&secret, &sealed).unwrap();

    let (server, salt) = opened.split_once(' ').unwrap();
    assert_eq!(server, "https://server.com:443");
    assert_eq!(salt.len(), SALT_DIGITS);
    assert!(salt.bytes().all(|b| b.is_ascii_digit()));
    // Sealing is randomized, so the same address never seals the same way twice.
    assert_ne!(
        sealed,
        seal::seal_address(&public, "https://server.com:443").unwrap()
    );
    // Only the node it is sealed to can open it.
    let (other, _) = key_pair();
    assert!(seal::open_address(&other, &sealed).is_err());
}

#[test]
fn sealed_body_opens_only_for_the_last_hop() {
    let (secret, public) = key_pair();
    let body = seal::seal_body(&public, b"hello relay").unwrap();
    assert_eq!(seal::open_body(&secret, &body).unwrap(), b"hello relay");

    let (other, _) = key_pair();
    assert!(seal::open_body(&other, &body).is_err());
    // A sealed address isn't a sealed key: the two are domain-separated.
    let swapped = FafBody {
        key: seal::seal_address(&public, "https://server.com").unwrap(),
        ..body.clone()
    };
    assert!(seal::open_body(&secret, &swapped).is_err());
    // A tampered message fails authentication.
    let mut message = body.message.into_bytes();
    message[20] = if message[20] == b'A' { b'B' } else { b'A' };
    let tampered = FafBody {
        key: body.key,
        message: String::from_utf8(message).unwrap(),
    };
    assert!(seal::open_body(&secret, &tampered).is_err());
}

#[test]
fn response_opens_only_under_the_message_key() {
    let (secret, public) = key_pair();
    let (body, client_key) = seal::seal_body_with_key(&public, b"hi").unwrap();
    let (node_key, message) = seal::open_body_with_key(&secret, &body).unwrap();
    assert_eq!(message, b"hi");

    let sealed = seal::seal_response(&node_key, b"hello:hi").unwrap();
    assert_eq!(
        seal::open_response(&client_key, &sealed).unwrap(),
        b"hello:hi"
    );

    let (_, other_key) = seal::seal_body_with_key(&public, b"hi").unwrap();
    assert!(seal::open_response(&other_key, &sealed).is_err());
    // A response isn't a request message: the two are domain-separated.
    assert!(seal::open_response(&client_key, &body.message).is_err());
}

#[test]
fn node_public_key_comes_from_the_certificate() {
    let key_pair = KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let secret = NodeSecretKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
    let public = NodePublicKey::from_certificate(cert.der()).unwrap();

    let body = seal::seal_body(&public, b"m").unwrap();
    assert_eq!(seal::open_body(&secret, &body).unwrap(), b"m");
    assert!(NodePublicKey::from_certificate(b"not a certificate").is_err());
}

#[test]
fn faf_request_json_shape() {
    let request = FafRequest {
        relays: vec![
            FafRelay {
                address: "a".to_string(),
                encrypted: false,
            },
            FafRelay {
                address: "b".to_string(),
                encrypted: true,
            },
        ],
        body: FafBody {
            key: "k".to_string(),
            message: "m".to_string(),
        },
    };
    let json = serde_json::json!({
        "relays": [
            { "address": "a", "encrypted": false },
            { "address": "b", "encrypted": true }
        ],
        "body": { "key": "k", "message": "m" }
    });
    assert_eq!(serde_json::to_value(&request).unwrap(), json);
    assert_eq!(serde_json::from_value::<FafRequest>(json).unwrap(), request);
    // `relays` may be omitted at the last hop.
    let last: FafRequest = serde_json::from_value(serde_json::json!({
        "body": { "key": "k", "message": "m" }
    }))
    .unwrap();
    assert!(last.relays.is_empty());
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
