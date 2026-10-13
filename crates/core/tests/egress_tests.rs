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
            "203.0.113.7",
            "1.0.0.1",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "169.253.255.255",
            "223.255.255.255",
            "2001:db8::1",
            "2606:4700::1111",
            "fbff::1",
            "fe7f::1",
            "fec0::1",
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
            "fd00:ec2::254",
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
