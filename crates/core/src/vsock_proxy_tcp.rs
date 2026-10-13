//! Configuration of the parent-instance `vsock-proxy-tcp` binary: its usage text, defaults and
//! argument parsing (flags over `TTK_*` environment variables). Platform independent; the proxy
//! itself is Linux only.

/// Usage text of the `vsock-proxy-tcp` binary.
pub const TCP_PROXY_USAGE: &str = "\
Usage: vsock-proxy-tcp --cid <CID> --remote <HOST:PORT> [OPTIONS]

Forwards TCP connections from the enclave (vsock) to one fixed remote, e.g. S3.

Options:
  -c, --cid <CID>                Enclave CID to accept connections from (required, e.g. 17)
  -r, --remote <HOST:PORT>       The only destination, resolved by the parent (required,
                                 e.g. s3.eu-west-1.amazonaws.com:443)
  -p, --vsock-port <PORT>        vsock port to listen on (default: 8001)
  -P, --allow-private            Allow the remote to resolve to loopback and private addresses
                                 (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7)
  -I, --allow-imds               Allow the remote to be the EC2 instance metadata service
                                 (169.254.169.254, fd00:ec2::254), so the enclave can fetch
                                 the instance role's credentials (e.g. --remote 169.254.169.254:80)
  -h, --help                     Print help information

Environment variables TTK_ENCLAVE_CID, TTK_TCP_REMOTE, TTK_TCP_VSOCK_PORT,
TTK_ALLOW_PRIVATE_NEXT_HOPS=1 and TTK_TCP_ALLOW_IMDS=1 set the same options; flags take
precedence. RUST_LOG=info enables logs.
";

/// Default vsock port the TCP proxy listens on, matching `S3Store`'s default in `ttk-storage`.
pub const DEFAULT_TCP_VSOCK_PORT: u32 = 8001;

/// Conventional vsock port of the `vsock-proxy-tcp` instance forwarding to the instance metadata
/// service (`--allow-imds`), matching `TTK_IMDS_VSOCK_PORT` of the `s3-server` image.
pub const IMDS_TCP_VSOCK_PORT: u32 = 8002;

/// What a `vsock-proxy-tcp` invocation accepts and where it forwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpProxyConfig {
    /// Enclave CID; connections from any other CID are refused.
    pub cid: u32,
    /// vsock port to listen on.
    pub vsock_port: u32,
    /// The fixed remote `host:port`, resolved on each connection.
    pub remote: String,
    /// Whether the remote may resolve to loopback and private addresses.
    pub allow_private: bool,
    /// Whether the remote may be the EC2 instance metadata service
    /// ([`crate::egress::is_instance_metadata_address`]); other link-local addresses stay refused.
    pub allow_imds: bool,
}

/// Parses `vsock-proxy-tcp` arguments (without the program name) over `env` defaults.
///
/// `env` looks up an environment variable. Returns `Ok(None)` if help was requested, `Err` with a
/// message on invalid or missing options.
pub fn parse_tcp_proxy_args(
    args: &[String],
    env: impl Fn(&str) -> Option<String>,
) -> Result<Option<TcpProxyConfig>, String> {
    let mut cid = env("TTK_ENCLAVE_CID");
    let mut remote = env("TTK_TCP_REMOTE");
    let mut vsock_port = env("TTK_TCP_VSOCK_PORT");
    let mut allow_private = env("TTK_ALLOW_PRIVATE_NEXT_HOPS").is_some_and(|v| v == "1");
    let mut allow_imds = env("TTK_TCP_ALLOW_IMDS").is_some_and(|v| v == "1");

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
            "-r" | "--remote" => remote = Some(value()?),
            "-p" | "--vsock-port" => vsock_port = Some(value()?),
            "-P" | "--allow-private" => allow_private = true,
            "-I" | "--allow-imds" => allow_imds = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }

    let cid = cid.ok_or("the enclave CID is required (--cid or TTK_ENCLAVE_CID)")?;
    let remote = remote.ok_or("the remote is required (--remote or TTK_TCP_REMOTE)")?;
    match remote.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0) => {}
        _ => return Err(format!("invalid remote {remote:?}: expected HOST:PORT")),
    }
    Ok(Some(TcpProxyConfig {
        cid: cid
            .parse()
            .map_err(|e| format!("invalid CID {cid:?}: {e}"))?,
        vsock_port: match vsock_port {
            Some(port) => port
                .parse()
                .map_err(|e| format!("invalid vsock port {port:?}: {e}"))?,
            None => DEFAULT_TCP_VSOCK_PORT,
        },
        remote,
        allow_private,
        allow_imds,
    }))
}
