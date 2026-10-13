//! `client-m` binary: command-line HTTP/3 client for TTKServer that sends a text message, for
//! testing only.
//!
//! Thin entry point over [`ttk_executables::faf_client`]: like `client`, it routes a message
//! through two relay nodes to a terminal node (see [`faf_client::send`]).
//!
//! The message is the UTF-8 text given by `--message`, sent as is; the decrypted reply is
//! printed as text (e.g. the same message back from the `echo` terminal).
//! The enclave images never include it.

use log::{error, info};
use ttk_executables::faf_client::{self, Route, RouteArgs};

/// Usage text of this binary.
const CLIENT_USAGE: &str = "\
Usage: client-m [OPTIONS] --message <TEXT> [URL]

Options:
  -s, --server-name <NAME>  SNI server name (default: localhost)
  -a, --addr <ADDR>         Entry relay node socket address (default: 127.0.0.1:4433)
  -r, --relay <RELAY>       Second relay node, forwarded to by the entry relay (default: 127.0.0.1:4434)
  -t, --terminal <TERMINAL> Terminal node, the last hop (default: 127.0.0.1:4444)
  -m, --message <TEXT>      Text message sealed to the terminal; its reply is printed as text
  -h, --help                Print help information

Examples:
  client-m https://127.0.0.1:4433 --message \"hello\"
  client-m --addr 127.0.0.1:4433 --relay 127.0.0.1:4434 --terminal 127.0.0.1:4444 --message \"hello\"
";

/// What a `client-m` invocation should connect to and send.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientTarget {
    /// Where the message is sent.
    route: Route,
    /// The text message sealed to the terminal.
    message: String,
}

/// Parses `client-m` arguments (without the program name).
///
/// The route arguments and defaults are [`RouteArgs`]'s. Returns `Ok(None)` if help was
/// requested, and an error if `--message` is missing.
fn parse_client_args(
    args: &[String],
    default_addr: Option<String>,
    default_name: Option<String>,
) -> Result<Option<ClientTarget>, String> {
    let mut route = RouteArgs::new(default_addr, default_name);
    let mut message = None;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--help" || arg == "-h" {
            return Ok(None);
        } else if (arg == "--message" || arg == "-m") && i + 1 < args.len() {
            i += 1;
            message = Some(args[i].clone());
        } else {
            route.parse_arg(args, &mut i);
        }
        i += 1;
    }

    Ok(Some(ClientTarget {
        route: route.build(),
        message: message.ok_or("--message is required")?,
    }))
}

/// Entry point for the `client-m` binary.
#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let ClientTarget { route, message } =
        faf_client::parse_process_args(parse_client_args, CLIENT_USAGE);
    info!("--> Message: {message}");
    match faf_client::send(&route, message.as_bytes()).await {
        Ok(Some(reply)) => info!("<-- Reply: {}", String::from_utf8_lossy(&reply)),
        Ok(None) => {}
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        }
    }
}
