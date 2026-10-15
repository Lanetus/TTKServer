//! Configuration of the parent-instance `vsock-proxy-tcp` binary: its usage text, defaults and
//! argument parsing (flags over `TTK_*` environment variables), and the request filter of its
//! `--allow-imds` mode ([`check_imds_request`]). Platform independent; the proxy itself is Linux
//! only.

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
                                 the instance role's credentials (e.g. --remote 169.254.169.254:80);
                                 only the IMDSv2 token and role credential requests are forwarded
  -h, --help                     Print help information

Environment variables TTK_ENCLAVE_CID, TTK_TCP_REMOTE, TTK_TCP_VSOCK_PORT,
TTK_ALLOW_PRIVATE_NEXT_HOPS=1 and TTK_TCP_ALLOW_IMDS=1 set the same options; flags take
precedence. RUST_LOG=info enables logs.
";

/// Default vsock port the TCP proxy listens on, matching `S3Store`'s default in `ttk-storage`.
pub const DEFAULT_TCP_VSOCK_PORT: u32 = 8001;

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

/// Largest HTTP request head forwarded to the instance metadata service.
pub const MAX_IMDS_REQUEST_HEAD: usize = 8 * 1024;

/// The instance metadata paths under which the role credentials are listed and served.
const IMDS_CREDENTIAL_PATHS: [&str; 2] = [
    "/latest/meta-data/iam/security-credentials/",
    "/latest/meta-data/iam/security-credentials-extended/",
];

/// Checks the HTTP/1.1 request at the start of `buffered` (bytes the enclave sent to the
/// instance metadata service) before it is forwarded.
///
/// Only what the instance role credentials need passes: `PUT /latest/api/token` (an IMDSv2
/// session token) and `GET` of the role list or one role's credentials under
/// `/latest/meta-data/iam/security-credentials[-extended]/`, with no body. Returns the length of
/// the request head to forward, `None` if it is not complete yet, or why it is refused (user
/// data, other metadata, bodies, oversized heads, malformed requests).
pub fn check_imds_request(buffered: &[u8]) -> Result<Option<usize>, String> {
    let Some(end) = buffered.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buffered.len() > MAX_IMDS_REQUEST_HEAD {
            return Err("request head too large".into());
        }
        return Ok(None);
    };
    let head_len = end + 4;
    if head_len > MAX_IMDS_REQUEST_HEAD {
        return Err("request head too large".into());
    }
    let head = std::str::from_utf8(&buffered[..end]).map_err(|_| "request head is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(path), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed request line".into());
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(format!("unsupported HTTP version {version:?}"));
    }
    if !is_allowed_imds_request(method, path) {
        return Err(format!("{method} {path} is not a credentials request"));
    }
    for header in lines {
        let (name, value) = header
            .split_once(':')
            .ok_or_else(|| format!("malformed header {header:?}"))?;
        let name = name.trim();
        if name.eq_ignore_ascii_case("transfer-encoding")
            || (name.eq_ignore_ascii_case("content-length") && value.trim() != "0")
        {
            return Err("requests with a body are not forwarded".into());
        }
    }
    Ok(Some(head_len))
}

/// Whether `method` `path` is an IMDSv2 token or role credentials request.
fn is_allowed_imds_request(method: &str, path: &str) -> bool {
    match method {
        "PUT" => path == "/latest/api/token",
        "GET" => IMDS_CREDENTIAL_PATHS.iter().any(|prefix| {
            path.strip_prefix(prefix).is_some_and(|role| {
                role.len() <= 128
                    && role != "."
                    && role != ".."
                    && role
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_-".contains(&b))
            })
        }),
        _ => false,
    }
}
