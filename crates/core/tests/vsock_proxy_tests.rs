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

#[test]
fn rejects_invalid_listen_addresses_and_ports() {
    let error = parse_relay_args(&args(&["-c", "16", "-l", "0.0.0.0"]), no_env).unwrap_err();
    assert!(error.contains("listen"), "{error}");
    for port in ["-p", "--vsock-port", "-o", "--outbound-port"] {
        let error = parse_relay_args(&args(&["-c", "16", port, "x"]), no_env).unwrap_err();
        assert!(error.contains("vsock port"), "{port}: {error}");
    }
    let env = |name: &str| (name == "TTK_VSOCK_PORT").then(|| "-1".to_string());
    assert!(parse_relay_args(&args(&["-c", "16"]), env).is_err());
}

#[test]
fn reports_the_option_missing_its_value() {
    for option in ["-l", "-p", "-o"] {
        let error = parse_relay_args(&args(&["-c", "16", option]), no_env).unwrap_err();
        assert!(error.contains(option), "{error}");
    }
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
    fn rejects_invalid_cids_and_missing_values() {
        let error = parse_tcp_proxy_args(&args(&["-c", "x", "-r", REMOTE]), no_env).unwrap_err();
        assert!(error.contains("CID"), "{error}");
        for option in ["-c", "-r", "-p"] {
            let error = parse_tcp_proxy_args(&args(&[option]), no_env).unwrap_err();
            assert!(error.contains(option), "{error}");
        }
    }

    #[test]
    fn accepts_ipv6_remotes() {
        let config = parse_tcp_proxy_args(&args(&["-c", "17", "-r", "[fd00:ec2::254]:80"]), no_env)
            .unwrap()
            .unwrap();
        assert_eq!(config.remote, "[fd00:ec2::254]:80");
    }

    #[test]
    fn help() {
        assert_eq!(parse_tcp_proxy_args(&args(&["-h"]), no_env).unwrap(), None);
    }
}

mod client_table {
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;
    use ttk_core::vsock_proxy::{confirms_client, ClientRefused, ClientTable};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_short_header_packets_confirm_a_client() {
        assert!(confirms_client(&[0x40, 1, 2]));
        assert!(!confirms_client(&[0xC0, 0, 0, 0, 1])); // long header (Initial)
        assert!(!confirms_client(&[0xF0, 0, 0, 0, 1])); // long header (Retry)
        assert!(!confirms_client(&[]));
    }

    #[test]
    fn clients_per_ip_are_limited() {
        let mut table = ClientTable::new(10, 2);
        table.insert(addr("192.0.2.1:1000"), ()).unwrap();
        table.insert(addr("192.0.2.1:1001"), ()).unwrap();
        assert_eq!(
            table.insert(addr("192.0.2.1:1002"), ()).unwrap_err(),
            ClientRefused::PerIpLimit
        );
        // Re-admitting a known client replaces it rather than counting twice.
        let (id, _) = table.insert(addr("192.0.2.1:1001"), ()).unwrap();
        assert_eq!(table.len(), 2);
        assert!(table.remove(&addr("192.0.2.1:1001"), id));
        table.insert(addr("192.0.2.1:1002"), ()).unwrap();
        table.insert(addr("192.0.2.2:1000"), ()).unwrap();
    }

    #[test]
    fn a_full_table_evicts_the_oldest_unconfirmed_client() {
        let mut table = ClientTable::new(3, 10);
        let (_, first) = table.insert(addr("192.0.2.1:1"), ()).unwrap();
        table.insert(addr("192.0.2.2:1"), ()).unwrap();
        table.insert(addr("192.0.2.3:1"), ()).unwrap();
        first.store(true, Ordering::Relaxed);

        // The first client is confirmed, so the second (oldest unconfirmed) makes room.
        table.insert(addr("192.0.2.4:1"), ()).unwrap();
        assert!(table.get(&addr("192.0.2.1:1")).is_some());
        assert!(table.get(&addr("192.0.2.2:1")).is_none());
        assert_eq!(table.len(), 3);

        for (_, entry) in [addr("192.0.2.3:1"), addr("192.0.2.4:1")]
            .iter()
            .map(|a| (a, table.get(a).unwrap()))
        {
            entry.confirmed.store(true, Ordering::Relaxed);
        }
        assert_eq!(
            table.insert(addr("192.0.2.5:1"), ()).unwrap_err(),
            ClientRefused::Full
        );
    }

    #[test]
    fn a_stale_relay_task_does_not_remove_its_replacement() {
        let mut table = ClientTable::new(3, 3);
        let (old, _) = table.insert(addr("192.0.2.1:1"), ()).unwrap();
        let (new, _) = table.insert(addr("192.0.2.1:1"), ()).unwrap();
        assert!(!table.remove(&addr("192.0.2.1:1"), old));
        assert!(table.remove(&addr("192.0.2.1:1"), new));
        assert!(table.is_empty());
    }
}

mod imds_filter {
    use ttk_core::vsock_proxy_tcp::{check_imds_request, MAX_IMDS_REQUEST_HEAD};

    fn request(line: &str, headers: &str) -> Vec<u8> {
        format!("{line}\r\nHost: 127.0.0.1\r\n{headers}\r\n").into_bytes()
    }

    #[test]
    fn credential_requests_pass() {
        for line in [
            "PUT /latest/api/token HTTP/1.1",
            "GET /latest/meta-data/iam/security-credentials/ HTTP/1.1",
            "GET /latest/meta-data/iam/security-credentials/ttk-s3-role HTTP/1.1",
            "GET /latest/meta-data/iam/security-credentials-extended/ttk-s3-role HTTP/1.1",
        ] {
            let req = request(line, "X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n");
            assert_eq!(check_imds_request(&req), Ok(Some(req.len())), "{line}");
        }
        // A pipelined second request is left for the next check.
        let mut two = request("PUT /latest/api/token HTTP/1.1", "Content-Length: 0\r\n");
        let first = two.len();
        two.extend(request("GET /latest/user-data HTTP/1.1", ""));
        assert_eq!(check_imds_request(&two), Ok(Some(first)));
        assert!(check_imds_request(&two[first..]).is_err());
    }

    #[test]
    fn other_metadata_and_bodies_are_refused() {
        for line in [
            "GET /latest/user-data HTTP/1.1",
            "GET /latest/meta-data/ HTTP/1.1",
            "GET /latest/meta-data/iam/security-credentials/../../user-data HTTP/1.1",
            "GET /latest/meta-data/iam/security-credentials/role?x=1 HTTP/1.1",
            "GET /latest/meta-data/iam/security-credentials/%2e%2e HTTP/1.1",
            "POST /latest/api/token HTTP/1.1",
            "GET /latest/api/token HTTP/1.1",
            "PUT /latest/api/token HTTP/2",
            "PUT  /latest/api/token HTTP/1.1",
        ] {
            assert!(check_imds_request(&request(line, "")).is_err(), "{line}");
        }
        for headers in ["Content-Length: 5\r\n", "Transfer-Encoding: chunked\r\n"] {
            let req = request("PUT /latest/api/token HTTP/1.1", headers);
            assert!(check_imds_request(&req).is_err(), "{headers}");
        }
    }

    #[test]
    fn incomplete_and_oversized_heads() {
        assert_eq!(
            check_imds_request(b"PUT /latest/api/token HTTP/1.1\r\n"),
            Ok(None)
        );
        let huge = vec![b'a'; MAX_IMDS_REQUEST_HEAD + 1];
        assert!(check_imds_request(&huge).is_err());
    }
}
