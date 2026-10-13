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
