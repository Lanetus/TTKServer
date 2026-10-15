//! Tests of the per-source connection limit (`ttk_ra_server::server::SourceConnections`).

use std::net::IpAddr;
use ttk_ra_server::server::SourceConnections;

#[test]
fn connections_per_source_are_limited_and_released_on_drop() {
    let sources = SourceConnections::new(2);
    let a: IpAddr = "192.0.2.1".parse().unwrap();
    let b: IpAddr = "192.0.2.2".parse().unwrap();

    let first = sources.try_acquire(a).unwrap();
    let _second = sources.try_acquire(a).unwrap();
    assert!(sources.try_acquire(a).is_none());
    // Other sources are unaffected.
    let _other = sources.try_acquire(b).unwrap();
    assert_eq!(sources.count(b), 1);

    drop(first);
    assert_eq!(sources.count(a), 1);
    assert!(sources.try_acquire(a).is_some());
}
