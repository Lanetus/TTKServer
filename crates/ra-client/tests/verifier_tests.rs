//! Tests for TEE evidence verification (`ttk_ra_client::verifier`) and its use in
//! `EnclaveCertVerifier`.
//!
//! Real vendor data (see `tests/fixtures/README.md`) checks that report and quote layouts are
//! parsed correctly; synthetic evidence signed by test PKIs exercises the policy and binding
//! checks for every TEE.

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use ciborium::Value;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
};
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
};
use rustls::client::danger::ServerCertVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;
use ttk_ra_client::trust::RootSignerTrustStore;
use ttk_ra_client::verifier::sev_snp::{AmdProduct, AmdRoots};
use ttk_ra_client::verifier::{
    dcap, is_bound_to, nitro, sev_snp, submod, verify_evidence, ImageTrustStore, Policy, TeeKind,
    TrustStore,
};
use ttk_ra_client::{EnclaveCertVerifier, RootImageTrustStore};
use ttk_ra_server::attestation::eat::EatClaimsSet;
use ttk_ra_server::server::create_cert_with_attestation;
use x509_parser::prelude::*;

const MILAN_REPORT: &[u8] = include_bytes!("fixtures/sev_snp_milan_report.bin");
const MILAN_VCEK: &[u8] = include_bytes!("fixtures/sev_snp_milan_vcek.der");
const TDX_QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote_v4.dat");
const TDX_QUOTE_ROOT: &[u8] = include_bytes!("fixtures/tdx_quote_v4_test_root.der");

/// 2026-01-01T00:00:00Z: inside the validity of every fixture certificate.
fn fixture_time() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_767_225_600))
}

fn snp_evidence(report: &[u8], vcek: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Text("report".into()), Value::Bytes(report.to_vec())),
        (Value::Text("vcek".into()), Value::Bytes(vcek.to_vec())),
    ])
}

fn eat_with(submods: Vec<(&str, Value)>) -> Vec<u8> {
    EatClaimsSet {
        submods: Some(Value::Map(
            submods
                .into_iter()
                .map(|(label, value)| (Value::Text(label.into()), value))
                .collect(),
        )),
        ..EatClaimsSet::default()
    }
    .to_cbor_bytes()
    .unwrap()
}

// ---------------------------------------------------------------------------
// Real vendor data
// ---------------------------------------------------------------------------

#[test]
fn builtin_amd_ask_certificates_are_signed_by_their_arks() {
    let roots = AmdRoots::builtin();
    assert_eq!(roots.len(), 3);
    for r in roots {
        let (_, ark) = X509Certificate::from_der(&r.ark).unwrap();
        let (_, ask) = X509Certificate::from_der(&r.ask).unwrap();
        ark.verify_signature(None)
            .unwrap_or_else(|e| panic!("{:?} ARK: {e}", r.product));
        ask.verify_signature(Some(ark.public_key()))
            .unwrap_or_else(|e| panic!("{:?} ASK: {e}", r.product));
    }
}

#[test]
fn real_milan_report_verifies_against_builtin_amd_roots() {
    let evidence = sev_snp::verify(
        &snp_evidence(MILAN_REPORT, MILAN_VCEK),
        fixture_time(),
        &TrustStore::builtin(),
    )
    .expect("genuine Milan report should verify");

    assert_eq!(evidence.tee, TeeKind::SevSnp);
    assert_eq!(evidence.report_data, MILAN_REPORT[0x50..0x90]);
    assert_eq!(
        evidence.measurements["measurement"],
        MILAN_REPORT[0x90..0xC0]
    );
}

#[test]
fn tampered_milan_report_is_rejected() {
    let mut report = MILAN_REPORT.to_vec();
    report[0x90] ^= 1; // measurement
    let err = sev_snp::verify(
        &snp_evidence(&report, MILAN_VCEK),
        fixture_time(),
        &TrustStore::builtin(),
    )
    .unwrap_err();
    assert!(err.contains("signature is invalid"), "{err}");
}

#[test]
fn milan_report_with_different_tcb_is_rejected() {
    let mut report = MILAN_REPORT.to_vec();
    report[0x187] ^= 1; // REPORTED_TCB microcode SPL
    let err = sev_snp::verify(
        &snp_evidence(&report, MILAN_VCEK),
        fixture_time(),
        &TrustStore::builtin(),
    )
    .unwrap_err();
    assert!(err.contains("ucodeSPL"), "{err}");
}

#[test]
fn milan_report_is_rejected_without_amd_roots() {
    let mut trust = TrustStore::builtin();
    trust.amd.retain(|r| r.product != AmdProduct::Milan);
    let err = sev_snp::verify(
        &snp_evidence(MILAN_REPORT, MILAN_VCEK),
        fixture_time(),
        &trust,
    )
    .unwrap_err();
    assert!(err.contains("not signed by a pinned AMD ASK"), "{err}");
}

#[test]
fn real_tdx_quote_verifies_against_its_root() {
    let trust = TrustStore {
        intel_sgx_root: TDX_QUOTE_ROOT.to_vec(),
        ..TrustStore::builtin()
    };
    let evidence = dcap::verify(TDX_QUOTE, TeeKind::Tdx, fixture_time(), &trust)
        .expect("Intel sample TDX quote should verify against its test root");

    assert_eq!(evidence.tee, TeeKind::Tdx);
    assert_eq!(evidence.report_data, TDX_QUOTE[48 + 520..48 + 584]);
    assert_eq!(evidence.measurements["mrtd"], TDX_QUOTE[48 + 136..48 + 184]);
    assert_eq!(evidence.measurements.len(), 9);
}

#[test]
fn real_tdx_quote_is_rejected_by_the_production_intel_root() {
    let err = dcap::verify(
        TDX_QUOTE,
        TeeKind::Tdx,
        fixture_time(),
        &TrustStore::builtin(),
    )
    .unwrap_err();
    assert!(err.contains("PCK certificate chain is invalid"), "{err}");
}

#[test]
fn tampered_tdx_quote_is_rejected() {
    let trust = TrustStore {
        intel_sgx_root: TDX_QUOTE_ROOT.to_vec(),
        ..TrustStore::builtin()
    };
    let mut quote = TDX_QUOTE.to_vec();
    quote[48 + 136] ^= 1; // MRTD
    let err = dcap::verify(&quote, TeeKind::Tdx, fixture_time(), &trust).unwrap_err();
    assert!(err.contains("quote signature is invalid"), "{err}");
}

#[test]
fn tdx_quote_is_rejected_as_sgx_evidence() {
    let err = dcap::verify(
        TDX_QUOTE,
        TeeKind::Sgx,
        fixture_time(),
        &TrustStore::builtin(),
    )
    .unwrap_err();
    assert!(err.contains("does not match Intel SGX"), "{err}");
}

// ---------------------------------------------------------------------------
// Synthetic evidence
// ---------------------------------------------------------------------------

/// Creates a certificate named `cn` for `key`, self-signed or signed by `issuer`.
fn cert(
    cn: &str,
    key: &KeyPair,
    ca: bool,
    issuer: Option<(&Certificate, &KeyPair)>,
    extensions: Vec<CustomExtension>,
) -> Certificate {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    if ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    }
    params.custom_extensions = extensions;
    match issuer {
        Some((issuer, issuer_key)) => params.signed_by(key, issuer, issuer_key).unwrap(),
        None => params.self_signed(key).unwrap(),
    }
}

fn signer(key: &KeyPair, alg: &'static EcdsaSigningAlgorithm) -> EcdsaKeyPair {
    EcdsaKeyPair::from_pkcs8(alg, &key.serialize_der(), &SystemRandom::new()).unwrap()
}

fn sign(key: &EcdsaKeyPair, message: &[u8]) -> Vec<u8> {
    key.sign(&SystemRandom::new(), message)
        .unwrap()
        .as_ref()
        .to_vec()
}

/// A test Intel PKI: root CA → PCK CA → PCK leaf, all ECDSA P-256.
struct IntelPki {
    root: Vec<u8>,
    chain_pem: String,
    pck: EcdsaKeyPair,
}

fn intel_pki() -> IntelPki {
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let root = cert("Test SGX Root CA", &root_key, true, None, vec![]);
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let ca = cert(
        "Test PCK CA",
        &ca_key,
        true,
        Some((&root, &root_key)),
        vec![],
    );
    let pck_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let pck = cert("Test PCK", &pck_key, false, Some((&ca, &ca_key)), vec![]);
    IntelPki {
        root: root.der().to_vec(),
        chain_pem: format!("{}{}{}", pck.pem(), ca.pem(), root.pem()),
        pck: signer(&pck_key, &ECDSA_P256_SHA256_FIXED_SIGNING),
    }
}

/// Builds a signed ECDSA-P256 DCAP quote (v3 for SGX, v4 for TDX) around `body`.
fn build_quote(tee: TeeKind, body: &[u8], pki: &IntelPki) -> Vec<u8> {
    let (version, tee_type): (u16, u32) = match tee {
        TeeKind::Tdx => (4, 0x81),
        _ => (3, 0),
    };
    let mut quote = Vec::new();
    quote.extend(version.to_le_bytes());
    quote.extend(2u16.to_le_bytes()); // ECDSA-256-with-P-256
    quote.extend(tee_type.to_le_bytes());
    quote.extend([0u8; 40]); // reserved, QE vendor ID, user data
    quote.extend(body);

    let attestation_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let attestation_key = signer(&attestation_key, &ECDSA_P256_SHA256_FIXED_SIGNING);
    let attestation_pub = &attestation_key.public_key().as_ref()[1..];
    let auth_data = b"qe-auth-data";

    let mut qe_report = vec![0u8; 384];
    let mut hasher = Sha256::new();
    hasher.update(attestation_pub);
    hasher.update(auth_data);
    qe_report[320..352].copy_from_slice(&hasher.finalize());

    let mut qe_data = qe_report.clone();
    qe_data.extend(sign(&pki.pck, &qe_report));
    qe_data.extend((auth_data.len() as u16).to_le_bytes());
    qe_data.extend(auth_data);
    qe_data.extend(5u16.to_le_bytes());
    qe_data.extend((pki.chain_pem.len() as u32).to_le_bytes());
    qe_data.extend(pki.chain_pem.as_bytes());

    let mut signature_data = sign(&attestation_key, &quote);
    signature_data.extend(attestation_pub);
    if version == 3 {
        signature_data.extend(qe_data);
    } else {
        signature_data.extend(6u16.to_le_bytes());
        signature_data.extend((qe_data.len() as u32).to_le_bytes());
        signature_data.extend(qe_data);
    }
    quote.extend((signature_data.len() as u32).to_le_bytes());
    quote.extend(signature_data);
    quote
}

fn td_body(report_data: &[u8], mrtd: u8, debug: bool) -> Vec<u8> {
    let mut body = vec![0u8; 584];
    body[120] = u8::from(debug);
    body[136..184].fill(mrtd);
    body[520..520 + report_data.len()].copy_from_slice(report_data);
    body
}

fn sgx_body(report_data: &[u8], mrenclave: u8, debug: bool) -> Vec<u8> {
    let mut body = vec![0u8; 384];
    body[48] = if debug { 0b10 } else { 0 };
    body[64..96].fill(mrenclave);
    body[320..320 + report_data.len()].copy_from_slice(report_data);
    body
}

/// A test AMD PKI: ARK → ASK → VCEK (ECDSA P-384 instead of RSA-PSS) for one chip.
struct AmdPki {
    roots: AmdRoots,
    vcek: Vec<u8>,
    vcek_key: EcdsaKeyPair,
    chip_id: [u8; 64],
    tcb: [u8; 8],
}

fn amd_pki() -> AmdPki {
    let ark_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let ark = cert("ARK-Test", &ark_key, true, None, vec![]);
    let ask_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let ask = cert("SEV-Test", &ask_key, true, Some((&ark, &ark_key)), vec![]);

    let chip_id = [0xC5; 64];
    // Milan layout: bl, tee, reserved x4, snp, ucode
    let tcb = [3, 0, 0, 0, 0, 0, 8, 115];
    let spl = |arc: u64, value: u8| {
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 3704, 1, 3, arc], vec![2, 1, value])
    };
    let vcek_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let vcek = cert(
        "SEV-VCEK",
        &vcek_key,
        false,
        Some((&ask, &ask_key)),
        vec![
            spl(1, tcb[0]),
            spl(2, tcb[1]),
            spl(3, tcb[6]),
            spl(8, tcb[7]),
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 3704, 1, 4], chip_id.to_vec()),
        ],
    );
    AmdPki {
        roots: AmdRoots {
            product: AmdProduct::Milan,
            ark: ark.der().to_vec(),
            ask: ask.der().to_vec(),
        },
        vcek: vcek.der().to_vec(),
        vcek_key: signer(&vcek_key, &ECDSA_P384_SHA384_FIXED_SIGNING),
        chip_id,
        tcb,
    }
}

/// Builds a signed SEV-SNP attestation report.
fn build_snp_report(pki: &AmdPki, report_data: &[u8], measurement: u8, debug: bool) -> Vec<u8> {
    let mut report = vec![0u8; 0x4A0];
    report[0..4].copy_from_slice(&3u32.to_le_bytes());
    let policy: u64 = (1 << 17) | if debug { 1 << 19 } else { 0 };
    report[0x08..0x10].copy_from_slice(&policy.to_le_bytes());
    report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    report[0x50..0x50 + report_data.len()].copy_from_slice(report_data);
    report[0x90..0xC0].fill(measurement);
    report[0x180..0x188].copy_from_slice(&pki.tcb);
    report[0x1A0..0x1E0].copy_from_slice(&pki.chip_id);

    let signature = sign(&pki.vcek_key, &report[..0x2A0]);
    for (i, component) in signature.chunks(48).enumerate() {
        let start = 0x2A0 + 72 * i;
        for (j, b) in component.iter().rev().enumerate() {
            report[start + j] = *b;
        }
    }
    report
}

/// A trust store holding the synthetic Intel and AMD roots.
fn test_trust(intel: &IntelPki, amd: &AmdPki) -> TrustStore {
    TrustStore {
        intel_sgx_root: intel.root.clone(),
        amd: vec![amd.roots.clone()],
        ..TrustStore::builtin()
    }
}

#[test]
fn synthetic_evidence_verifies_for_every_hardware_tee() {
    let intel = intel_pki();
    let amd = amd_pki();
    let trust = test_trust(&intel, &amd);
    let binding = [0x42; 32];

    let cases = [
        (
            submod::TDX,
            TeeKind::Tdx,
            Value::Bytes(build_quote(
                TeeKind::Tdx,
                &td_body(&binding, 7, false),
                &intel,
            )),
            "mrtd",
        ),
        (
            submod::SGX,
            TeeKind::Sgx,
            Value::Bytes(build_quote(
                TeeKind::Sgx,
                &sgx_body(&binding, 7, false),
                &intel,
            )),
            "mrenclave",
        ),
        (
            submod::SEV_SNP,
            TeeKind::SevSnp,
            snp_evidence(&build_snp_report(&amd, &binding, 7, false), &amd.vcek),
            "measurement",
        ),
    ];
    for (label, tee, value, measurement) in cases {
        let eat = eat_with(vec![(label, value)]);
        let evidence = verify_evidence(
            &eat,
            &binding,
            UnixTime::now(),
            &trust,
            &RootImageTrustStore::default(),
            Policy::default(),
        )
        .unwrap_or_else(|e| panic!("{tee}: {e}"));
        assert_eq!(evidence.tee, tee);
        assert!(evidence.measurements[measurement].iter().all(|b| *b == 7));
        assert!(!evidence.debug);
    }
}

#[test]
fn debug_mode_is_rejected_unless_allowed() {
    let intel = intel_pki();
    let amd = amd_pki();
    let trust = test_trust(&intel, &amd);
    let binding = [0x42; 32];

    let cases = [
        (
            submod::TDX,
            Value::Bytes(build_quote(
                TeeKind::Tdx,
                &td_body(&binding, 0, true),
                &intel,
            )),
        ),
        (
            submod::SGX,
            Value::Bytes(build_quote(
                TeeKind::Sgx,
                &sgx_body(&binding, 0, true),
                &intel,
            )),
        ),
        (
            submod::SEV_SNP,
            snp_evidence(&build_snp_report(&amd, &binding, 0, true), &amd.vcek),
        ),
    ];
    for (label, value) in cases {
        let eat = eat_with(vec![(label, value)]);
        let err = verify_evidence(
            &eat,
            &binding,
            UnixTime::now(),
            &trust,
            &RootImageTrustStore::default(),
            Policy::default(),
        )
        .unwrap_err();
        assert!(err.contains("debug-mode"), "{label}: {err}");

        let relaxed = Policy {
            allow_debug: true,
            ..Policy::default()
        };
        let evidence = verify_evidence(
            &eat,
            &binding,
            UnixTime::now(),
            &trust,
            &RootImageTrustStore::default(),
            relaxed,
        )
        .unwrap();
        assert!(evidence.debug, "{label}");
    }
}

#[test]
fn evidence_bound_to_other_data_is_rejected() {
    let intel = intel_pki();
    let amd = amd_pki();
    let trust = test_trust(&intel, &amd);
    let quote = build_quote(TeeKind::Tdx, &td_body(&[0x42; 32], 0, false), &intel);
    let eat = eat_with(vec![(submod::TDX, Value::Bytes(quote))]);

    let err = verify_evidence(
        &eat,
        &[0x43; 32],
        UnixTime::now(),
        &trust,
        &RootImageTrustStore::default(),
        Policy::default(),
    )
    .unwrap_err();
    assert!(err.contains("report data does not match"), "{err}");
}

#[test]
fn eat_must_carry_exactly_one_supported_tee() {
    let trust = TrustStore::builtin();
    let now = UnixTime::now();

    let none = eat_with(vec![("other", Value::Bytes(vec![1]))]);
    let err = verify_evidence(
        &none,
        &[0; 32],
        now,
        &trust,
        &RootImageTrustStore::default(),
        Policy::default(),
    )
    .unwrap_err();
    assert!(err.contains("no supported TEE evidence"), "{err}");

    let two = eat_with(vec![
        (submod::TDX, Value::Bytes(vec![1])),
        (submod::SGX, Value::Bytes(vec![1])),
    ]);
    let err = verify_evidence(
        &two,
        &[0; 32],
        now,
        &trust,
        &RootImageTrustStore::default(),
        Policy::default(),
    )
    .unwrap_err();
    assert!(err.contains("more than one TEE"), "{err}");
}

#[test]
fn truncated_quote_is_rejected() {
    let err = dcap::verify(
        &TDX_QUOTE[..700],
        TeeKind::Tdx,
        fixture_time(),
        &TrustStore::builtin(),
    )
    .unwrap_err();
    assert!(err.contains("truncated"), "{err}");
}

#[test]
fn report_data_binding_allows_zero_padding_only() {
    let hash = [9u8; 32];
    let mut padded = [0u8; 64];
    padded[..32].copy_from_slice(&hash);
    assert!(is_bound_to(&hash, &hash));
    assert!(is_bound_to(&padded, &hash));
    padded[63] = 1;
    assert!(!is_bound_to(&padded, &hash));
    assert!(!is_bound_to(&hash[..16], &hash));
}

// ---------------------------------------------------------------------------
// Nitro enclave image allowlist
// ---------------------------------------------------------------------------

/// PCR0 of an image in the test allowlist.
const LISTED_PCR0: &str = "7807833a90cc86f5a853a1f49043a568f3428f6b03eb983aed99899fbfa77d6b86b34fa934e318dd3741debca32c0aba";

/// A test AWS Nitro PKI: root CA → signing certificate, both ECDSA P-384.
struct NitroPki {
    root: Vec<u8>,
    signing_cert: Vec<u8>,
    signing_key: EcdsaKeyPair,
}

fn nitro_pki() -> NitroPki {
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let root = cert("Test Nitro Root CA", &root_key, true, None, vec![]);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let leaf = cert(
        "Test Nitro Signer",
        &key,
        false,
        Some((&root, &root_key)),
        vec![],
    );
    NitroPki {
        root: root.der().to_vec(),
        signing_cert: leaf.der().to_vec(),
        signing_key: signer(&key, &ECDSA_P384_SHA384_FIXED_SIGNING),
    }
}

/// Builds a signed COSE_Sign1 Nitro attestation document whose PCR0 is `pcr0`.
fn build_nitro_doc(pki: &NitroPki, pcr0: Vec<u8>) -> Vec<u8> {
    let mut pcrs = BTreeMap::from([(0, pcr0)]);
    for i in 1..16 {
        pcrs.insert(i, vec![i as u8; 48]);
    }
    let timestamp = UnixTime::now().as_secs() * 1000;
    let payload = AttestationDoc::new(
        "i-0123456789abcdef0-enc0123456789abcdef".into(),
        aws_nitro_enclaves_nsm_api::api::Digest::SHA384,
        timestamp,
        pcrs,
        pki.signing_cert.clone(),
        vec![pki.root.clone()],
        Some(vec![7; 32]),
        None,
        None,
    )
    .to_binary();

    let protected = vec![0xa1, 0x01, 0x38, 0x22]; // {1: -35} (alg: ES384)
    let mut to_sign = Vec::new();
    ciborium::into_writer(
        &Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload.clone()),
        ]),
        &mut to_sign,
    )
    .unwrap();
    let signature = sign(&pki.signing_key, &to_sign);

    let mut out = Vec::new();
    ciborium::into_writer(
        &Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(vec![]),
                Value::Bytes(payload),
                Value::Bytes(signature),
            ])),
        ),
        &mut out,
    )
    .unwrap();
    out
}

/// A trust store rooted at the test Nitro PKI.
fn nitro_trust(pki: &NitroPki) -> TrustStore {
    TrustStore {
        aws_nitro_root: pki.root.clone(),
        ..TrustStore::builtin()
    }
}

/// An image trust store allowing only [`LISTED_PCR0`].
fn nitro_images() -> RootImageTrustStore {
    RootImageTrustStore {
        nitro_image_allowlist: nitro::parse_image_allowlist(LISTED_PCR0).unwrap(),
    }
}

fn listed_pcr0() -> Vec<u8> {
    nitro::parse_image_allowlist(LISTED_PCR0).unwrap().remove(0)
}

#[test]
fn builtin_root_signer_pcr8_allowlist_is_valid() {
    let store = RootSignerTrustStore::builtin();
    assert_eq!(store.nitro_pcr_index(), 8);
    assert_eq!(store.nitro_image_allowlist(), store.pcr8_allowlist);
}

#[test]
fn nitro_image_allowlist_skips_comments_and_blank_lines() {
    let text = format!(
        "# header\n\n  {LISTED_PCR0} # v1\n{}\n",
        LISTED_PCR0.to_uppercase()
    );
    let list = nitro::parse_image_allowlist(&text).unwrap();
    assert_eq!(list, vec![listed_pcr0(), listed_pcr0()]);
    assert_eq!(list[0].len(), 48);
}

#[test]
fn nitro_image_allowlist_rejects_malformed_entries() {
    let too_long = format!("{LISTED_PCR0}00");
    let signed = format!("+{}", &LISTED_PCR0[1..]);
    for bad in [&LISTED_PCR0[..94], &too_long, &signed] {
        let err = nitro::parse_image_allowlist(bad).unwrap_err();
        assert!(err.starts_with("line 1:"), "{err}");
    }
}

#[test]
fn nitro_evidence_from_a_listed_image_is_accepted() {
    let pki = nitro_pki();
    let doc = build_nitro_doc(&pki, listed_pcr0());
    let evidence = nitro::verify(
        &doc,
        UnixTime::now(),
        &nitro_trust(&pki),
        &nitro_images(),
        Policy::default(),
    )
    .expect("a listed image should verify");
    assert_eq!(evidence.tee, TeeKind::AwsNitro);
    assert_eq!(evidence.measurements["pcr0"], listed_pcr0());
    assert!(!evidence.debug);
}

#[test]
fn nitro_evidence_from_an_unlisted_image_is_rejected() {
    let pki = nitro_pki();
    let mut pcr0 = listed_pcr0();
    pcr0[0] ^= 1;
    let doc = build_nitro_doc(&pki, pcr0);
    let err = nitro::verify(
        &doc,
        UnixTime::now(),
        &nitro_trust(&pki),
        &nitro_images(),
        Policy::default(),
    )
    .unwrap_err();
    assert!(err.contains("not in the list of verified images"), "{err}");
}

#[test]
fn nitro_debug_evidence_is_left_to_the_debug_policy() {
    let pki = nitro_pki();
    let doc = build_nitro_doc(&pki, vec![0; 48]);
    let trust = nitro_trust(&pki);
    let evidence = nitro::verify(
        &doc,
        UnixTime::now(),
        &trust,
        &nitro_images(),
        Policy::default(),
    )
    .expect("debug images cannot be identified, so the allowlist does not apply");
    assert!(evidence.debug);

    let eat = eat_with(vec![(submod::AWS_NITRO, Value::Bytes(doc))]);
    let err = verify_evidence(
        &eat,
        &[7; 32],
        UnixTime::now(),
        &trust,
        &nitro_images(),
        Policy::default(),
    )
    .unwrap_err();
    assert!(err.contains("debug-mode TEE"), "{err}");
}

#[test]
fn root_signer_store_checks_pcr8_instead_of_pcr0() {
    let pki = nitro_pki();
    let mut pcr0 = listed_pcr0();
    pcr0[0] ^= 1;
    // `build_nitro_doc` sets PCR8 to 48 bytes of 8.
    let doc = build_nitro_doc(&pki, pcr0);
    let signer = |pcr8: Vec<u8>| RootSignerTrustStore {
        pcr8_allowlist: vec![pcr8],
    };

    let trust = nitro_trust(&pki);
    nitro::verify(
        &doc,
        UnixTime::now(),
        &trust,
        &signer(vec![8; 48]),
        Policy::default(),
    )
    .expect("a pinned PCR8 should verify whatever the PCR0");
    let err = nitro::verify(
        &doc,
        UnixTime::now(),
        &trust,
        &signer(vec![9; 48]),
        Policy::default(),
    )
    .unwrap_err();
    assert!(err.contains("PCR8"), "{err}");
    assert!(err.contains("not in the list of verified images"), "{err}");
}

// ---------------------------------------------------------------------------
// End to end through the RA-TLS certificate verifier
// ---------------------------------------------------------------------------

/// Builds an RA-TLS certificate for `key` carrying a TDX quote bound to `bound_key`.
fn tdx_ra_tls_cert(
    key: &KeyPair,
    bound_key: &KeyPair,
    intel: &IntelPki,
) -> CertificateDer<'static> {
    let binding = Sha256::digest(bound_key.public_key_der());
    let quote = build_quote(TeeKind::Tdx, &td_body(&binding, 7, false), intel);
    let eat = eat_with(vec![(submod::TDX, Value::Bytes(quote))]);
    let pem = create_cert_with_attestation(key, "enclave.internal", &eat, 1).unwrap();
    CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
}

fn verify_cert(
    verifier: &EnclaveCertVerifier,
    cert: &CertificateDer<'_>,
) -> Result<(), rustls::Error> {
    let name = ServerName::try_from("localhost").unwrap();
    verifier
        .verify_server_cert(cert, &[], &name, &[], UnixTime::now())
        .map(|_| ())
}

#[test]
fn cert_verifier_accepts_tdx_evidence_and_checks_measurements() {
    let intel = intel_pki();
    let amd = amd_pki();
    let key = KeyPair::generate().unwrap();
    let cert = tdx_ra_tls_cert(&key, &key, &intel);

    let verifier = EnclaveCertVerifier::new().with_trust_store(test_trust(&intel, &amd));
    verify_cert(&verifier, &cert).expect("TDX evidence bound to the cert key should verify");
    let evidence = verifier.verified_evidence().unwrap();
    assert_eq!(evidence.tee, TeeKind::Tdx);
    assert!(verifier.verified_attestation().is_none());

    let pinned = EnclaveCertVerifier::new()
        .with_trust_store(test_trust(&intel, &amd))
        .with_expected_measurement("mrtd", vec![7; 48]);
    verify_cert(&pinned, &cert).expect("matching MRTD should verify");

    let wrong = EnclaveCertVerifier::new()
        .with_trust_store(test_trust(&intel, &amd))
        .with_expected_measurement("MRTD", vec![8; 48]);
    let err = verify_cert(&wrong, &cert).unwrap_err();
    assert!(err.to_string().contains("MRTD does not match"), "{err}");

    let other_tee = EnclaveCertVerifier::new()
        .with_trust_store(test_trust(&intel, &amd))
        .with_expected_pcr(0, vec![0; 48]);
    let err = verify_cert(&other_tee, &cert).unwrap_err();
    assert!(
        err.to_string().contains("has no measurement 'pcr0'"),
        "{err}"
    );
}

#[test]
fn cert_verifier_rejects_tdx_evidence_bound_to_another_key() {
    let intel = intel_pki();
    let amd = amd_pki();
    let key = KeyPair::generate().unwrap();
    let other = KeyPair::generate().unwrap();
    let cert = tdx_ra_tls_cert(&key, &other, &intel);

    let verifier = EnclaveCertVerifier::new().with_trust_store(test_trust(&intel, &amd));
    let err = verify_cert(&verifier, &cert).unwrap_err();
    assert!(
        err.to_string().contains("report data does not match"),
        "{err}"
    );
}

#[test]
fn cert_verifier_rejects_tdx_evidence_with_builtin_roots() {
    let intel = intel_pki();
    let key = KeyPair::generate().unwrap();
    let cert = tdx_ra_tls_cert(&key, &key, &intel);

    let err = verify_cert(&EnclaveCertVerifier::new(), &cert).unwrap_err();
    assert!(
        err.to_string().contains("PCK certificate chain is invalid"),
        "{err}"
    );
}
