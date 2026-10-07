//! Configuration of the parent-instance `vsock-proxy` binary: its usage text, defaults and
//! argument parsing (flags over `TTK_*` environment variables). Platform independent; the relay
//! itself is Linux only.

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
