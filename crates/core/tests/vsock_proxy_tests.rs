//! Tests for the `vsock-proxy` argument parsing ([`ttk_core::vsock_proxy`]).

use ttk_core::vsock_proxy::{
    parse_relay_args, DEFAULT_LISTEN, DEFAULT_OUTBOUND_PORT, DEFAULT_VSOCK_PORT,
};

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn no_env(_: &str) -> Option<String> {
    None
}

#[test]
fn requires_cid() {
    assert!(parse_relay_args(&[], no_env).unwrap_err().contains("CID"));
}

#[test]
fn defaults_listen_and_port() {
    let config = parse_relay_args(&args(&["--cid", "16"]), no_env)
        .unwrap()
        .unwrap();
    assert_eq!(config.listen, DEFAULT_LISTEN.parse().unwrap());
    assert_eq!(config.cid, 16);
    assert_eq!(config.vsock_port, DEFAULT_VSOCK_PORT);
    assert_eq!(config.outbound_port, DEFAULT_OUTBOUND_PORT);
    assert!(!config.allow_private);
}

#[test]
fn allow_private_from_flag_or_env() {
    let env = |name: &str| (name == "TTK_ALLOW_PRIVATE_NEXT_HOPS").then(|| "1".to_string());
    let from_env = parse_relay_args(&args(&["--cid", "16"]), env)
        .unwrap()
        .unwrap();
    assert!(from_env.allow_private);
    let from_flag = parse_relay_args(&args(&["--cid", "16", "-P"]), no_env)
        .unwrap()
        .unwrap();
    assert!(from_flag.allow_private);
}

#[test]
fn flags_override_env() {
    let env = |name: &str| match name {
        "TTK_ENCLAVE_CID" => Some("7".to_string()),
        "TTK_RELAY_LISTEN" => Some("127.0.0.1:8443".to_string()),
        "TTK_VSOCK_PORT" => Some("6000".to_string()),
        "TTK_OUTBOUND_VSOCK_PORT" => Some("6001".to_string()),
        _ => None,
    };
    let config = parse_relay_args(&args(&["-c", "16", "-p", "7000", "-o", "0"]), env)
        .unwrap()
        .unwrap();
    assert_eq!(config.listen, "127.0.0.1:8443".parse().unwrap());
    assert_eq!(config.cid, 16);
    assert_eq!(config.vsock_port, 7000);
    assert_eq!(config.outbound_port, 0);
}

#[test]
fn help_and_errors() {
    assert_eq!(parse_relay_args(&args(&["--help"]), no_env), Ok(None));
    assert!(parse_relay_args(&args(&["--cid"]), no_env).is_err());
    assert!(parse_relay_args(&args(&["--cid", "x"]), no_env).is_err());
    assert!(parse_relay_args(&args(&["--bogus"]), no_env).is_err());
}
