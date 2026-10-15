//! Tests for the egress policy's instance metadata exception ([`ttk_core::egress`]).

use ttk_core::egress::{classify_hop_address, is_instance_metadata_address, HopAddressClass};

#[test]
fn only_the_instance_metadata_service_is_an_imds_address() {
    for imds in ["169.254.169.254", "fd00:ec2::254", "::ffff:169.254.169.254"] {
        assert!(
            is_instance_metadata_address(imds.parse().unwrap()),
            "{imds}"
        );
    }
    for other in [
        "169.254.169.253",
        "169.254.170.2",
        "fd00:ec2::253",
        "127.0.0.1",
        "8.8.8.8",
    ] {
        assert!(
            !is_instance_metadata_address(other.parse().unwrap()),
            "{other}"
        );
    }
}

#[test]
fn the_instance_metadata_service_stays_forbidden_as_a_hop() {
    assert_eq!(
        classify_hop_address("169.254.169.254".parse().unwrap()),
        HopAddressClass::Forbidden
    );
}

/// Asserts the class of every address in `addresses`.
fn assert_class(class: HopAddressClass, addresses: &[&str]) {
    for address in addresses {
        assert_eq!(
            classify_hop_address(address.parse().unwrap()),
            class,
            "{address}"
        );
    }
}

#[test]
fn public_unicast_addresses_are_public() {
    assert_class(
        HopAddressClass::Public,
        &[
            "8.8.8.8",
            "52.95.110.1",
            "1.0.0.1",
            "192.0.1.255",
            "192.0.3.0",
            "198.17.255.255",
            "198.20.0.0",
            "203.0.112.255",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "169.253.255.255",
            "223.255.255.255",
            "2001:4860:4860::8888",
            "2001:db9::1",
            "2003::1",
            "2606:4700::1111",
            "64:ff9a::1",
            "fbff::1",
            "fe7f::1",
            "::ffff:8.8.8.8",
        ],
    );
}

#[test]
fn loopback_private_and_shared_addresses_are_private() {
    assert_class(
        HopAddressClass::Private,
        &[
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "::1",
            "fc00::1",
            "fd00:ec2:0:1::1",
            "fdff:ffff::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
        ],
    );
}

#[test]
fn unroutable_link_local_and_group_addresses_are_forbidden() {
    assert_class(
        HopAddressClass::Forbidden,
        &[
            "0.0.0.0",
            "0.1.2.3",
            "169.254.0.1",
            "169.254.170.2",
            "224.0.0.1",
            "239.255.255.250",
            "255.255.255.255",
            "::",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "ff0e::1",
            "::ffff:169.254.169.254",
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
        ],
    );
}

#[test]
fn reserved_documentation_and_ec2_service_addresses_are_forbidden() {
    assert_class(
        HopAddressClass::Forbidden,
        &[
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "198.51.100.1",
            "203.0.113.7",
            "198.18.0.1",
            "198.19.255.255",
            "240.0.0.1",
            "254.255.255.255",
            "2001:db8::1",
            "fec0::1",
            "feff::1",
            "100::1",
            "fd00:ec2::254",
            "fd00:ec2::253",
            "fd00:ec2::123",
        ],
    );
}

#[test]
fn ipv6_addresses_embedding_an_ipv4_address_are_forbidden() {
    assert_class(
        HopAddressClass::Forbidden,
        &[
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::808:808",
            "64:ff9b:1::1",
            "2002:a9fe:a9fe::1",
            "2001:0:4136:e378::1",
            "::169.254.169.254",
            "::8.8.8.8",
        ],
    );
}

#[test]
fn only_port_443_and_unprivileged_ports_are_permitted() {
    use ttk_core::egress::is_permitted_hop_port;
    for port in [443, 1024, 4433, 65535] {
        assert!(is_permitted_hop_port(port), "{port}");
    }
    for port in [0, 22, 25, 53, 80, 1023] {
        assert!(!is_permitted_hop_port(port), "{port}");
    }
}
