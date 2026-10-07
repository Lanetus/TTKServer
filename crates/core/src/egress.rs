//! Egress policy for traffic whose destination comes from a peer: the next hops of a relay
//! node, and the enclave's outbound datagrams relayed by `vsock-proxy` on the parent instance.
//!
//! Such destinations are attacker-chosen, so they are classified before any packet is sent:
//! link-local (including cloud metadata and DNS endpoints), multicast, broadcast and unspecified
//! addresses are always refused, and loopback or private ones are allowed only where the nodes
//! run on a private network or in local development.

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
    /// (`169.254/16`, including cloud metadata and DNS endpoints, and `fe80::/10`), multicast
    /// or broadcast.
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

/// [`classify_hop_address`] for IPv4.
fn classify_v4(ip: Ipv4Addr) -> HopAddressClass {
    let [a, b, ..] = ip.octets();
    if ip.is_unspecified() || a == 0 || ip.is_link_local() || ip.is_multicast() || ip.is_broadcast()
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
    let first = ip.segments()[0];
    if ip.is_unspecified() || ip.is_multicast() || (first & 0xffc0) == 0xfe80 {
        HopAddressClass::Forbidden
    } else if ip.is_loopback() || (first & 0xfe00) == 0xfc00 {
        HopAddressClass::Private
    } else {
        HopAddressClass::Public
    }
}
