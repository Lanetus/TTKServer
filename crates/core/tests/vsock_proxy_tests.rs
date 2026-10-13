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

mod tcp {
    use super::{args, no_env};
    use ttk_core::vsock_proxy_tcp::{parse_tcp_proxy_args, DEFAULT_TCP_VSOCK_PORT};

    const REMOTE: &str = "s3.eu-west-1.amazonaws.com:443";

    #[test]
    fn requires_cid_and_remote() {
        assert!(parse_tcp_proxy_args(&args(&["-r", REMOTE]), no_env)
            .unwrap_err()
            .contains("CID"));
        assert!(parse_tcp_proxy_args(&args(&["-c", "17"]), no_env)
            .unwrap_err()
            .contains("remote"));
    }

    #[test]
    fn defaults_the_vsock_port() {
        let config = parse_tcp_proxy_args(&args(&["--cid", "17", "--remote", REMOTE]), no_env)
            .unwrap()
            .unwrap();
        assert_eq!(config.cid, 17);
        assert_eq!(config.remote, REMOTE);
        assert_eq!(config.vsock_port, DEFAULT_TCP_VSOCK_PORT);
        assert!(!config.allow_private);
    }

    #[test]
    fn flags_override_env() {
        let env = |name: &str| match name {
            "TTK_ENCLAVE_CID" => Some("16".to_string()),
            "TTK_TCP_REMOTE" => Some("example.com:443".to_string()),
            "TTK_TCP_VSOCK_PORT" => Some("9000".to_string()),
            "TTK_ALLOW_PRIVATE_NEXT_HOPS" => Some("1".to_string()),
            _ => None,
        };
        let from_env = parse_tcp_proxy_args(&[], env).unwrap().unwrap();
        assert_eq!(
            (from_env.cid, from_env.remote.as_str(), from_env.vsock_port),
            (16, "example.com:443", 9000)
        );
        assert!(from_env.allow_private);
        let from_flags =
            parse_tcp_proxy_args(&args(&["-c", "17", "-r", REMOTE, "-p", "8001"]), env)
                .unwrap()
                .unwrap();
        assert_eq!(
            (
                from_flags.cid,
                from_flags.remote.as_str(),
                from_flags.vsock_port
            ),
            (17, REMOTE, 8001)
        );
    }

    #[test]
    fn rejects_invalid_remotes_and_ports() {
        for remote in [
            "s3.amazonaws.com",
            ":443",
            "host:0",
            "host:https",
            "host:70000",
        ] {
            assert!(
                parse_tcp_proxy_args(&args(&["-c", "17", "-r", remote]), no_env).is_err(),
                "{remote}"
            );
        }
        assert!(
            parse_tcp_proxy_args(&args(&["-c", "17", "-r", REMOTE, "-p", "x"]), no_env).is_err()
        );
        assert!(
            parse_tcp_proxy_args(&args(&["-c", "17", "-r", REMOTE, "--bogus"]), no_env).is_err()
        );
    }

    #[test]
    fn allow_imds_from_flag_or_env_only() {
        let base = ["-c", "17", "-r", "169.254.169.254:80"];
        let default = parse_tcp_proxy_args(&args(&base), no_env).unwrap().unwrap();
        assert!(!default.allow_imds);
        let env = |name: &str| (name == "TTK_TCP_ALLOW_IMDS").then(|| "1".to_string());
        assert!(
            parse_tcp_proxy_args(&args(&base), env)
                .unwrap()
                .unwrap()
                .allow_imds
        );
        let from_flag =
            parse_tcp_proxy_args(&args(&[&base[..], &["--allow-imds"]].concat()), no_env)
                .unwrap()
                .unwrap();
        assert!(from_flag.allow_imds);
        assert!(!from_flag.allow_private);
    }

    #[test]
    fn help() {
        assert_eq!(parse_tcp_proxy_args(&args(&["-h"]), no_env).unwrap(), None);
    }
}
