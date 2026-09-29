use axum::http::{HeaderMap, StatusCode};
use rustls::client::danger::ServerCertVerifier;
use ttk_server::client::{hex_encode, ClientResponse, EnclaveCertVerifier};

#[test]
fn test_hex_encode() {
    let bytes = [0x00, 0x12, 0xab, 0xff];
    assert_eq!(hex_encode(&bytes), "0012abff");
}

#[test]
fn test_client_response_text() {
    let resp = ClientResponse {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
        body: b"Hello World".to_vec(),
    };
    assert_eq!(resp.text().unwrap(), "Hello World");
}

#[test]
fn test_enclave_cert_verifier() {
    let verifier = EnclaveCertVerifier::new();
    assert!(verifier.received_certificate().is_none());
    assert!(!verifier.supported_verify_schemes().is_empty());
}

#[test]
fn test_extract_attestation_doc() {
    use rcgen::{CertificateParams, CustomExtension, KeyPair};
    use ttk_server::client::extract_attestation_doc;

    let key_pair = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();

    let expected_payload = b"test_attestation_payload_data";
    // Wrap in ASN.1 octet string header (tag 0x04, length 30)
    let mut wrapped = vec![0x04, expected_payload.len() as u8];
    wrapped.extend_from_slice(expected_payload);

    let ext = CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], wrapped);
    params.custom_extensions.push(ext);

    let cert = params.self_signed(&key_pair).unwrap();
    let extracted = extract_attestation_doc(cert.der()).unwrap();
    assert_eq!(extracted, expected_payload);
}

#[cfg(feature = "mock")]
mod attestation_verification {
    use rcgen::KeyPair;
    use rustls::client::danger::ServerCertVerifier;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
    use ttk_server::attestation::by_name;
    use ttk_server::attestation::nitro_doc::{
        create_mock_attestation_document, parse_attestation_document, wrap_as_eat,
    };
    use ttk_server::client::EnclaveCertVerifier;
    use ttk_server::server::create_cert_with_attestation;
    use ttk_server::AttestationParams;

    /// Builds an RA-TLS certificate for `cert_key` carrying mock evidence bound to `bound_key`.
    fn ra_tls_cert(cert_key: &KeyPair, bound_key: &KeyPair) -> CertificateDer<'static> {
        let params = AttestationParams::new().with_user_data_hash(&bound_key.public_key_der());
        let eat = by_name("mock")
            .unwrap()
            .generate_document(&params)
            .unwrap()
            .to_cbor_bytes()
            .unwrap();
        let pem = create_cert_with_attestation(cert_key, "enclave.internal", &eat, 1).unwrap();
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    fn verify(
        verifier: &EnclaveCertVerifier,
        cert: &CertificateDer<'_>,
    ) -> Result<(), rustls::Error> {
        let name = ServerName::try_from("localhost").unwrap();
        verifier
            .verify_server_cert(cert, &[], &name, &[], UnixTime::now())
            .map(|_| ())
    }

    #[test]
    fn accepts_bound_mock_evidence_when_allowed() {
        let key = KeyPair::generate().unwrap();
        let cert = ra_tls_cert(&key, &key);
        let verifier = EnclaveCertVerifier::new().allow_mock();

        verify(&verifier, &cert).expect("mock evidence bound to the cert key should verify");
        assert_eq!(verifier.received_certificate().as_ref(), Some(&cert));
        let doc = verifier.verified_attestation().unwrap();
        assert_eq!(doc.module_id, "aws-nitro-enclaves-mock");
    }

    #[test]
    fn strict_verifier_rejects_mock_evidence() {
        let key = KeyPair::generate().unwrap();
        let cert = ra_tls_cert(&key, &key);
        let verifier = EnclaveCertVerifier::new();

        let err = verify(&verifier, &cert).unwrap_err();
        assert!(
            err.to_string().contains("TTK_ALLOW_MOCK_ATTESTATION"),
            "the error should explain how to accept mock evidence: {err}"
        );
        assert!(verifier.received_certificate().is_none());
    }

    #[test]
    fn mock_evidence_is_signed_through_the_mock_root() {
        let params = AttestationParams::new().with_user_data(vec![1; 32]);
        let doc = parse_attestation_document(&create_mock_attestation_document(&params).unwrap())
            .unwrap();
        assert_eq!(doc.cabundle.len(), 1);
        assert_eq!(
            doc.cabundle[0],
            ttk_server::verifier::TrustStore::builtin().mock_nitro_root
        );
    }

    #[test]
    fn tampered_mock_evidence_is_rejected_even_when_allowed() {
        let key = KeyPair::generate().unwrap();
        let params = AttestationParams::new().with_user_data_hash(&key.public_key_der());
        let mut doc = create_mock_attestation_document(&params).unwrap();
        let last = doc.len() - 1;
        doc[last] ^= 1; // last byte of the COSE signature
        let eat = wrap_as_eat(&doc).unwrap().to_cbor_bytes().unwrap();
        let pem = create_cert_with_attestation(&key, "enclave.internal", &eat, 1).unwrap();
        let cert = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();

        let err = verify(&EnclaveCertVerifier::new().allow_mock(), &cert).unwrap_err();
        assert!(err.to_string().contains("signature is invalid"), "{err}");
    }

    #[test]
    fn rejects_evidence_bound_to_another_key() {
        let key = KeyPair::generate().unwrap();
        let other = KeyPair::generate().unwrap();
        let cert = ra_tls_cert(&key, &other);

        let err = verify(&EnclaveCertVerifier::new().allow_mock(), &cert).unwrap_err();
        assert!(err.to_string().contains("report data"), "{err}");
    }

    #[test]
    fn rejects_unexpected_pcr() {
        let key = KeyPair::generate().unwrap();
        let cert = ra_tls_cert(&key, &key);
        let verifier = EnclaveCertVerifier::new()
            .allow_mock()
            .with_expected_pcr(0, vec![0xff; 48]);

        let err = verify(&verifier, &cert).unwrap_err();
        assert!(err.to_string().contains("PCR0"), "{err}");
    }

    #[test]
    fn rejects_certificate_without_attestation() {
        let key = KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();

        let err = verify(&EnclaveCertVerifier::new().allow_mock(), cert.der()).unwrap_err();
        assert!(err.to_string().contains("attestation extension"), "{err}");
    }
}

mod argument_parsing {
    use ttk_server::client::{parse_client_args, ClientTarget};

    fn parse(args: &[&str]) -> Option<ClientTarget> {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        parse_client_args(&args, None, None)
    }

    #[test]
    fn defaults_to_localhost_4433_root() {
        let target = parse(&[]).unwrap();
        assert_eq!(target.server_addr, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(target.server_name, "localhost");
        assert_eq!(target.path, "/");
    }

    #[test]
    fn environment_defaults_are_used_and_overridden_by_flags() {
        let env = || {
            (
                Some("10.0.0.1:9000".to_string()),
                Some("enclave.local".to_string()),
            )
        };
        let (addr, name) = env();
        let target = parse_client_args(&[], addr, name).unwrap();
        assert_eq!(target.server_addr, "10.0.0.1:9000".parse().unwrap());
        assert_eq!(target.server_name, "enclave.local");

        let args: Vec<String> = ["-a", "10.0.0.2:1", "--server-name", "other", "-p", "/x"]
            .iter()
            .map(|a| a.to_string())
            .collect();
        let (addr, name) = env();
        let target = parse_client_args(&args, addr, name).unwrap();
        assert_eq!(target.server_addr, "10.0.0.2:1".parse().unwrap());
        assert_eq!(target.server_name, "other");
        assert_eq!(target.path, "/x");
    }

    #[test]
    fn long_and_short_flags_are_equivalent() {
        let long = parse(&[
            "--addr",
            "10.0.0.3:2",
            "--path",
            "/evidence",
            "--server-name",
            "s",
        ]);
        let short = parse(&["-a", "10.0.0.3:2", "-p", "/evidence", "-s", "s"]);
        assert_eq!(long, short);
        assert_eq!(long.unwrap().path, "/evidence");
    }

    #[test]
    fn url_sets_address_path_and_query() {
        let target = parse(&["https://127.0.0.1:5000/evidence.eat?raw=1"]).unwrap();
        assert_eq!(target.server_addr, "127.0.0.1:5000".parse().unwrap());
        assert_eq!(
            target.server_name, "localhost",
            "IP hosts keep the SNI name"
        );
        assert_eq!(target.path, "/evidence.eat?raw=1");
    }

    #[test]
    fn url_with_hostname_sets_the_sni_name() {
        // The hostname becomes the SNI name; it cannot be a socket address, so the address
        // falls back to the default.
        let target = parse(&["https://enclave.example/hello"]).unwrap();
        assert_eq!(target.server_name, "enclave.example");
        assert_eq!(target.path, "/hello");
        assert_eq!(target.server_addr, "127.0.0.1:4433".parse().unwrap());
    }

    #[test]
    fn bare_socket_address_is_accepted_positionally() {
        let target = parse(&["10.1.2.3:7000"]).unwrap();
        assert_eq!(target.server_addr, "10.1.2.3:7000".parse().unwrap());
        assert_eq!(target.path, "/");
    }

    #[test]
    fn unparsable_address_falls_back_to_the_default() {
        let target = parse(&["--addr", "not-an-address"]).unwrap();
        assert_eq!(target.server_addr, "127.0.0.1:4433".parse().unwrap());
    }

    #[test]
    fn flag_without_value_is_ignored() {
        let target = parse(&["--path"]).unwrap();
        assert_eq!(target.path, "/");
    }

    #[test]
    fn positional_argument_that_is_not_a_url_is_taken_as_an_address() {
        let target = parse(&["not a url"]).unwrap();
        assert_eq!(target.server_addr, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(target.path, "/");
    }

    #[test]
    fn url_without_host_sets_only_the_path() {
        let target = parse(&["/evidence"]).unwrap();
        assert_eq!(target.server_addr, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(target.server_name, "localhost");
        assert_eq!(target.path, "/evidence");
    }

    #[test]
    fn help_returns_none() {
        assert!(parse(&["--help"]).is_none());
        assert!(parse(&["-a", "10.0.0.1:1", "-h"]).is_none());
    }
}

mod certificate_checks {
    use rcgen::{date_time_ymd, CertificateParams, CustomExtension, KeyPair};
    use rustls::client::danger::ServerCertVerifier;
    use rustls_pki_types::{ServerName, UnixTime};
    use ttk_server::client::{extract_attestation_doc, EnclaveCertVerifier};

    fn verify_cert_with_validity(
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> Result<(), rustls::Error> {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        let cert = params.self_signed(&key).unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        EnclaveCertVerifier::default()
            .allow_debug()
            .verify_server_cert(cert.der(), &[], &name, &[], UnixTime::now())
            .map(|_| ())
    }

    #[test]
    fn expired_certificate_is_rejected() {
        let err = verify_cert_with_validity((2000, 1, 1), (2001, 1, 1)).unwrap_err();
        assert!(err.to_string().contains("certificate has expired"), "{err}");
    }

    #[test]
    fn not_yet_valid_certificate_is_rejected() {
        let err = verify_cert_with_validity((2090, 1, 1), (2091, 1, 1)).unwrap_err();
        assert!(err.to_string().contains("not valid yet"), "{err}");
    }

    #[test]
    fn attestation_extension_without_octet_string_wrapper_is_returned_raw() {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        // A DER NULL (not an OCTET STRING) as the extension value.
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 99999, 1],
                vec![0x05, 0x00],
            ));
        let cert = params.self_signed(&key).unwrap();
        assert_eq!(
            extract_attestation_doc(cert.der()).unwrap(),
            vec![0x05, 0x00]
        );
    }

    #[test]
    fn certificate_without_the_extension_or_malformed_der_is_rejected() {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::default().self_signed(&key).unwrap();
        assert!(extract_attestation_doc(cert.der()).is_err());
        assert!(extract_attestation_doc(b"not a certificate").is_err());
    }
}

/// Full in-memory TLS handshakes between a server presenting a real RA-TLS certificate (mock
/// evidence) and a client using `EnclaveCertVerifier`. QUIC always negotiates TLS 1.3, so this
/// is how the TLS 1.2 signature check is exercised.
#[cfg(feature = "mock")]
mod tls_handshake {
    use rcgen::KeyPair;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::version::{TLS12, TLS13};
    use rustls::{
        ClientConfig, ClientConnection, ServerConfig, ServerConnection, SupportedProtocolVersion,
    };
    use std::sync::Arc;
    use ttk_server::attestation::by_name;
    use ttk_server::client::EnclaveCertVerifier;
    use ttk_server::server::create_cert_with_attestation;
    use ttk_server::AttestationParams;

    fn server_config(version: &'static SupportedProtocolVersion) -> ServerConfig {
        let key = KeyPair::generate().unwrap();
        let params = AttestationParams::new().with_user_data_hash(&key.public_key_der());
        let eat = by_name("mock")
            .unwrap()
            .generate_document(&params)
            .unwrap()
            .to_cbor_bytes()
            .unwrap();
        let pem = create_cert_with_attestation(&key, "enclave.internal", &eat, 1).unwrap();
        let cert = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap()
    }

    fn client_config(
        version: &'static SupportedProtocolVersion,
        verifier: EnclaveCertVerifier,
    ) -> ClientConfig {
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth()
    }

    /// Shuttles TLS records between the two connections until both finish the handshake.
    fn handshake(
        version: &'static SupportedProtocolVersion,
        verifier: EnclaveCertVerifier,
    ) -> Result<ClientConnection, rustls::Error> {
        let name = ServerName::try_from("localhost").unwrap();
        let mut client =
            ClientConnection::new(Arc::new(client_config(version, verifier)), name).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config(version))).unwrap();

        for _ in 0..10 {
            let mut records = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut records).unwrap();
            }
            if !records.is_empty() {
                server.read_tls(&mut records.as_slice()).unwrap();
                server.process_new_packets()?;
            }
            let mut records = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut records).unwrap();
            }
            if !records.is_empty() {
                client.read_tls(&mut records.as_slice()).unwrap();
                client.process_new_packets()?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(client);
            }
        }
        panic!("handshake did not complete");
    }

    #[test]
    fn tls12_handshake_verifies_the_server_signature() {
        let client = handshake(&TLS12, EnclaveCertVerifier::new().allow_mock())
            .expect("TLS 1.2 handshake with an attested server should succeed");
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_2)
        );
    }

    #[test]
    fn tls13_handshake_verifies_the_server_signature() {
        let client = handshake(&TLS13, EnclaveCertVerifier::new().allow_mock())
            .expect("TLS 1.3 handshake with an attested server should succeed");
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
    }

    #[test]
    fn handshake_fails_when_the_evidence_is_rejected() {
        let err = handshake(&TLS12, EnclaveCertVerifier::new()).unwrap_err();
        assert!(err.to_string().contains("MOCK"), "{err}");
    }
}
