//! Egress policy for traffic whose destination comes from a peer: the next hops of a relay
//! node, and the enclave's outbound datagrams relayed by `vsock-proxy` on the parent instance.
//!
//! Such destinations are attacker-chosen, so they are classified before any packet is sent:
//! link-local (including cloud metadata and DNS endpoints), multicast, broadcast, unspecified,
//! reserved and documentation addresses, and IPv6 addresses that tunnel or translate to an
//! arbitrary IPv4 address (NAT64, 6to4, Teredo, IPv4-compatible), are always refused, and
//! loopback or private ones are allowed only where the nodes run on a private network or in
//! local development. Destination ports are limited too ([`is_permitted_hop_port`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where a next-hop address points, for a relay's egress policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopAddressClass {
    /// A globally routable unicast address: always a valid next hop.
    Public,
    /// Loopback (`127.0.0.0/8`, `::1`), private (`10/8`, `172.16/12`, `192.168/16`,
    /// `fc00::/7`) or shared (`100.64/10`) address: a valid next hop only where relays run on a
    /// private network or in local development.
    Private,
    /// An address never valid as a next hop: unspecified, "this network" (`0/8`), link-local
    /// (`169.254/16`, including cloud metadata and DNS endpoints, and `fe80::/10`), the EC2
    /// IPv6 service endpoints (`fd00:ec2::/64`, including `fd00:ec2::254`), multicast, broadcast,
    /// IETF protocol assignments (`192.0.0/24`), the deprecated 6to4 relay anycast
    /// (`192.88.99/24`) and IPv6 site-local (`fec0::/10`) ranges, documentation (`192.0.2/24`, `198.51.100/24`,
    /// `203.0.113/24`, `2001:db8::/32`), benchmarking (`198.18/15`), reserved (`240/4`),
    /// discard-only (`100::/64`), and IPv6 addresses that reach an arbitrary IPv4 address:
    /// NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`), Teredo (`2001::/32`) and
    /// IPv4-compatible (`::/96`).
    Forbidden,
}

/// Classifies `ip` as a next-hop destination. IPv4-mapped IPv6 addresses are classified as
/// their IPv4 address.
pub fn classify_hop_address(ip: IpAddr) -> HopAddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

/// Whether a peer-chosen destination may use `port`: any port from 1024 up, and 443. Other
/// well-known ports (SSH, DNS, SMTP, …) and port 0 are refused, so that relays can't be used to
/// reach or probe those services.
pub fn is_permitted_hop_port(port: u16) -> bool {
    port == 443 || port >= 1024
}

/// The EC2 instance metadata service (IMDS) address over IPv4.
const IMDS_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

/// The EC2 instance metadata service (IMDS) address over IPv6 (Nitro instances).
const IMDS_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);

/// Whether `ip` is the EC2 instance metadata service (`169.254.169.254` or `fd00:ec2::254`), which only
/// a parent operator may open to the enclave (`vsock-proxy-tcp --allow-imds`), never a peer.
/// IPv4-mapped IPv6 addresses are checked as their IPv4 address.
pub fn is_instance_metadata_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == IMDS_V4,
        IpAddr::V6(v6) => v6 == IMDS_V6 || v6.to_ipv4_mapped() == Some(IMDS_V4),
    }
}

/// [`classify_hop_address`] for IPv4.
fn classify_v4(ip: Ipv4Addr) -> HopAddressClass {
    let [a, b, c, _] = ip.octets();
    let reserved = matches!(
        (a, b, c),
        (192, 0, 0) | (192, 0, 2) | (192, 88, 99) | (198, 51, 100) | (203, 0, 113)
    ) || (a == 198 && (b & 0xfe) == 18)
        || a >= 240;
    if ip.is_unspecified()
        || a == 0
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || reserved
    {
        HopAddressClass::Forbidden
    } else if ip.is_loopback() || ip.is_private() || (a == 100 && (64..128).contains(&b)) {
        HopAddressClass::Private
    } else {
        HopAddressClass::Public
    }
}

/// [`classify_hop_address`] for IPv6.
fn classify_v6(ip: Ipv6Addr) -> HopAddressClass {
    let s = ip.segments();
    let first = s[0];
    // IPv4-compatible (`::a.b.c.d`; `::` and `::1` are handled below).
    let ipv4_compatible = s[..6] == [0; 6] && !ip.is_unspecified() && !ip.is_loopback();
    let nat64 = (s[..6] == [0x64, 0xff9b, 0, 0, 0, 0]) || (s[..3] == [0x64, 0xff9b, 1]);
    let tunnel = first == 0x2002 || (first == 0x2001 && s[1] == 0);
    let documentation = first == 0x2001 && s[1] == 0x0db8;
    let discard = s[..4] == [0x100, 0, 0, 0];
    let ec2_services = s[..4] == [0xfd00, 0x0ec2, 0, 0];
    if ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xffc0) == 0xfe80
        || (first & 0xffc0) == 0xfec0
        || ipv4_compatible
        || nat64
        || tunnel
        || documentation
        || discard
        || ec2_services
    {
        HopAddressClass::Forbidden
    } else if ip.is_loopback() || (first & 0xfe00) == 0xfc00 {
        HopAddressClass::Private
    } else {
        HopAddressClass::Public
    }
}
