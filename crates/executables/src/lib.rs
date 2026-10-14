//! TTKServer executables: every binary lives in `src/bin/`. This library only holds what several
//! of them share.
//!
//! - [`faf_client`]: the test-only `/faf` clients (`client`, `client-m`): the route arguments,
//!   attesting the hops and sending an onion-routed message through two relays to a terminal.
//! - [`shutdown`] (Unix): the `SIGTERM` / `SIGINT` shutdown of the parent-instance daemons
//!   (`vsock-proxy`, `vsock-proxy-tcp`).

pub mod faf_client;
#[cfg(unix)]
pub mod shutdown;
