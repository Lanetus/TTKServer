//! Configuration of the parent-instance `vsock-proxy` binary: its usage text, defaults and
//! argument parsing (flags over `TTK_*` environment variables), and its table of inbound clients
//! ([`ClientTable`]). Platform independent; the relay itself is Linux only.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Usage text of the `vsock-proxy` binary.
pub const RELAY_USAGE: &str = "\
Usage: vsock-proxy --cid <CID> [OPTIONS]

Options:
  -c, --cid <CID>                Enclave CID to relay to (required, e.g. 16)
  -l, --listen <ADDR>            UDP address to listen on (default: 0.0.0.0:443)
  -p, --vsock-port <PORT>        Enclave vsock port (default: 5000)
  -o, --outbound-port <PORT>     vsock port for outbound traffic from the enclave
                                 (default: 5001; 0 disables outbound relaying)
  -P, --allow-private            Allow outbound traffic to loopback and private addresses
                                 (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)
  -h, --help                     Print help information

Environment variables TTK_ENCLAVE_CID, TTK_RELAY_LISTEN, TTK_VSOCK_PORT,
TTK_OUTBOUND_VSOCK_PORT and TTK_ALLOW_PRIVATE_NEXT_HOPS=1 set the same options; flags take
precedence. RUST_LOG=info enables logs.
";

/// Default UDP address the relay listens on.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:443";

/// Default enclave vsock port, matching the server's default.
pub const DEFAULT_VSOCK_PORT: u32 = 5000;

/// Default vsock port for outbound traffic from the enclave, matching the server's default.
pub const DEFAULT_OUTBOUND_PORT: u32 = 5001;

/// Where a `vsock-proxy` invocation listens and what it relays to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    /// Public UDP address clients send QUIC datagrams to.
    pub listen: std::net::SocketAddr,
    /// Enclave CID.
    pub cid: u32,
    /// Enclave vsock port.
    pub vsock_port: u32,
    /// vsock port accepting outbound traffic from the enclave; 0 disables it.
    pub outbound_port: u32,
    /// Whether outbound traffic may go to loopback and private addresses.
    pub allow_private: bool,
}

/// Parses `vsock-proxy` arguments (without the program name) over `env` defaults.
///
/// `env` looks up an environment variable. Returns `Ok(None)` if help was requested, `Err` with a
/// message on invalid or missing options.
pub fn parse_relay_args(
    args: &[String],
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<RelayConfig>, String> {
    let mut listen = env("TTK_RELAY_LISTEN").unwrap_or_else(|| DEFAULT_LISTEN.to_string());
    let mut cid = env("TTK_ENCLAVE_CID");
    let mut vsock_port = env("TTK_VSOCK_PORT");
    let mut outbound_port = env("TTK_OUTBOUND_VSOCK_PORT");
    let mut allow_private = env("TTK_ALLOW_PRIVATE_NEXT_HOPS").is_some_and(|v| v == "1");

    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let mut value = || {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("missing value for {arg}"))
        };
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "-c" | "--cid" => cid = Some(value()?),
            "-l" | "--listen" => listen = value()?,
            "-p" | "--vsock-port" => vsock_port = Some(value()?),
            "-o" | "--outbound-port" => outbound_port = Some(value()?),
            "-P" | "--allow-private" => allow_private = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    let cid = cid.ok_or("the enclave CID is required (--cid or TTK_ENCLAVE_CID)")?;
    Ok(Some(RelayConfig {
        listen: listen
            .parse()
            .map_err(|e| format!("invalid listen address {listen:?}: {e}"))?,
        cid: cid
            .parse()
            .map_err(|e| format!("invalid CID {cid:?}: {e}"))?,
        vsock_port: parse_port(vsock_port, DEFAULT_VSOCK_PORT)?,
        outbound_port: parse_port(outbound_port, DEFAULT_OUTBOUND_PORT)?,
        allow_private,
    }))
}

/// Parses a vsock port, or returns `default` if none was given.
fn parse_port(port: Option<String>, default: u32) -> Result<u32, String> {
    match port {
        Some(port) => port
            .parse()
            .map_err(|e| format!("invalid vsock port {port:?}: {e}")),
        None => Ok(default),
    }
}

/// Most inbound clients relayed at once from one IP address; datagrams opening further flows
/// from it are dropped.
pub const MAX_CLIENTS_PER_IP: usize = 64;

/// Longest an inbound client is relayed before it is [confirmed](confirms_client): a flow from
/// a spoofed source address never completes its QUIC handshake, so it is dropped after this
/// rather than the regular idle timeout.
pub const UNCONFIRMED_CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether `datagram`, sent by the enclave to a client, confirms that client's address: a QUIC
/// short-header (1-RTT) packet, which the enclave only sends once the handshake has completed,
/// i.e. once the client has proven it receives what is sent to its address (RFC 9000, section
/// 17.3: the header form bit is 0).
pub fn confirms_client(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|first| first & 0x80 == 0)
}

/// Why [`ClientTable::insert`] refused a new client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientRefused {
    /// [`MAX_CLIENTS_PER_IP`] clients from the same IP address are already relayed.
    PerIpLimit,
    /// The table is full of confirmed clients.
    Full,
}

/// One relayed client: its relay task's id, its datagram queue `value`, and whether the enclave
/// has [confirmed](confirms_client) it.
#[derive(Debug)]
pub struct ClientEntry<V> {
    /// Id of the relay task serving the client.
    pub id: u64,
    /// The client's queue toward the enclave.
    pub value: V,
    /// Set once the enclave confirms the client's address.
    pub confirmed: Arc<AtomicBool>,
}

/// The inbound clients relayed at once, keyed by UDP source address.
///
/// Bounded in total (`capacity`) and per IP address (`per_ip`). When full, a new client evicts
/// the oldest client the enclave has not confirmed yet, so source addresses spoofed to fill the
/// table can't lock out clients that complete their handshake.
#[derive(Debug)]
pub struct ClientTable<V> {
    entries: HashMap<SocketAddr, ClientEntry<V>>,
    per_ip_counts: HashMap<IpAddr, usize>,
    /// Clients in insertion order, for eviction; entries since removed or confirmed are skipped.
    order: VecDeque<(SocketAddr, u64)>,
    capacity: usize,
    per_ip: usize,
    next_id: u64,
}

/// Lookup, admission and removal of clients.
impl<V> ClientTable<V> {
    /// An empty table of at most `capacity` clients, `per_ip` of them per IP address.
    pub fn new(capacity: usize, per_ip: usize) -> Self {
        Self {
            entries: HashMap::new(),
            per_ip_counts: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            per_ip,
            next_id: 0,
        }
    }

    /// Number of clients relayed.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no client is relayed.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry of `client`, if relayed.
    pub fn get(&self, client: &SocketAddr) -> Option<&ClientEntry<V>> {
        self.entries.get(client)
    }

    /// Admits `client` with queue `value`, replacing any entry it had. Returns the new entry's
    /// id and confirmation flag. Evicts the oldest unconfirmed client if the table is full.
    pub fn insert(
        &mut self,
        client: SocketAddr,
        value: V,
    ) -> Result<(u64, Arc<AtomicBool>), ClientRefused> {
        if let Some(id) = self.entries.get(&client).map(|entry| entry.id) {
            self.remove(&client, id);
        }
        if self.per_ip_counts.get(&client.ip()).copied().unwrap_or(0) >= self.per_ip {
            return Err(ClientRefused::PerIpLimit);
        }
        if self.entries.len() >= self.capacity && !self.evict_unconfirmed() {
            return Err(ClientRefused::Full);
        }
        self.next_id += 1;
        let id = self.next_id;
        let confirmed = Arc::new(AtomicBool::new(false));
        self.entries.insert(
            client,
            ClientEntry {
                id,
                value,
                confirmed: confirmed.clone(),
            },
        );
        *self.per_ip_counts.entry(client.ip()).or_default() += 1;
        self.order.push_back((client, id));
        if self.order.len() > 2 * self.capacity.max(1) {
            self.compact_order();
        }
        Ok((id, confirmed))
    }

    /// Removes `client` if its entry is still the one with `id` (a newer relay task may have
    /// replaced it). Returns whether it was removed.
    pub fn remove(&mut self, client: &SocketAddr, id: u64) -> bool {
        if self.entries.get(client).is_none_or(|entry| entry.id != id) {
            return false;
        }
        self.entries.remove(client);
        if let Some(count) = self.per_ip_counts.get_mut(&client.ip()) {
            *count -= 1;
            if *count == 0 {
                self.per_ip_counts.remove(&client.ip());
            }
        }
        true
    }

    /// Evicts the oldest unconfirmed client. Returns `false` if every client is confirmed.
    fn evict_unconfirmed(&mut self) -> bool {
        while let Some((client, id)) = self.order.pop_front() {
            let unconfirmed = self
                .entries
                .get(&client)
                .is_some_and(|entry| entry.id == id && !entry.confirmed.load(Ordering::Relaxed));
            if unconfirmed && self.remove(&client, id) {
                return true;
            }
        }
        false
    }

    /// Drops eviction candidates that were removed or confirmed since being queued.
    fn compact_order(&mut self) {
        let entries = &self.entries;
        self.order.retain(|(client, id)| {
            entries
                .get(client)
                .is_some_and(|entry| entry.id == *id && !entry.confirmed.load(Ordering::Relaxed))
        });
    }
}
