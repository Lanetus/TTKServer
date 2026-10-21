//! Tests for TEE evidence verification (`ttk_ra_client::verifier`) and its use in
//! `EnclaveCertVerifier`.
//!
//! Real vendor data (see `tests/fixtures/README.md`) checks that report and quote layouts are
//! parsed correctly; synthetic evidence signed by test PKIs exercises the policy and binding
//! checks for every TEE.

use aws_nitro_enclaves_nsm_api::api::AttestationDoc;
use ciborium::Value;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, CustomExtension, DnType, IsCa, KeyPair,
    PublicKeyData, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384,
};
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
};
use rustls::client::danger::ServerCertVerifier;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256, Sha384};
use std::collections::BTreeMap;
use std::time::Duration;
use ttk_ra_client::verifier::sev_snp::{AmdProduct, AmdRoots};
use ttk_ra_client::verifier::{
    check_image_allowed, dcap, image_measurement, is_bound_to, media_type, nitro, sev_snp,
    verify_evidence, verify_evidence_with_nonce, ImageMeasurement, Policy, TeeKind, TrustStore,
};
use ttk_ra_client::{parse_image_allowlist, RootSignerTrustStore};
use ttk_ra_client::{EnclaveCertVerifier, RootImageTrustStore};
use ttk_ra_server::server::create_cert_with_attestation;
use ttk_ra_server::{cmw, Cmw, CmwCollection, CmwRecord};
use x509_parser::prelude::*;

const MILAN_REPORT: &[u8] = include_bytes!("fixtures/sev_snp_milan_report.bin");
const MILAN_VCEK: &[u8] = include_bytes!("fixtures/sev_snp_milan_vcek.der");
const TDX_QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote_v4.dat");
const TDX_QUOTE_ROOT: &[u8] = include_bytes!("fixtures/tdx_quote_v4_test_root.der");

/// 2026-01-01T00:00:00Z: inside the validity of every fixture certificate.
fn fixture_time() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_767_225_600))
}

/// CBOR CMW Evidence record of `media_type` holding `value`.
fn record(media_type: &str, value: Vec<u8>) -> Vec<u8> {
    Cmw::evidence(media_type, value).to_cbor_bytes()
}

/// SEV-SNP evidence: a CMW collection of the `report` and its `vcek`.
fn snp_collection(report: &[u8], vcek: &[u8]) -> CmwCollection {
    CmwCollection {
        collection_type: Some(media_type::SEV_SNP_COLLECTION.into()),
        entries: vec![
            (
                "report".into(),
                Cmw::evidence(media_type::SEV_SNP_REPORT, report.to_vec()),
            ),
            (
                "vcek".into(),
                Cmw::Record(CmwRecord::new(
                    media_type::PKIX_CERT,
                    vcek.to_vec(),
                    cmw::ind::ENDORSEMENTS,
                )),
            ),
        ],
    }
}

fn snp_cmw(report: &[u8], vcek: &[u8]) -> Vec<u8> {
    Cmw::Collection(snp_collection(report, vcek)).to_cbor_bytes()
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
fn builtin_amd_asvk_certificates_are_signed_by_their_arks() {
    for r in AmdRoots::builtin() {
        let (_, ark) = X509Certificate::from_der(&r.ark).unwrap();
        let (_, asvk) = X509Certificate::from_der(&r.asvk).unwrap();
        asvk.verify_signature(Some(ark.public_key()))
            .unwrap_or_else(|e| panic!("{:?} ASVK: {e}", r.product));
        assert!(
            asvk.subject().to_string().contains("SEV-VLEK"),
            "{:?}: {}",
            r.product,
            asvk.subject()
        );
    }
}

#[test]
fn real_milan_report_verifies_against_builtin_amd_roots() {
    let evidence = sev_snp::verify(
        MILAN_REPORT,
        MILAN_VCEK,
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
    let err =
        sev_snp::verify(&report, MILAN_VCEK, fixture_time(), &TrustStore::builtin()).unwrap_err();
    assert!(err.contains("signature is invalid"), "{err}");
}

#[test]
fn milan_report_with_different_tcb_is_rejected() {
    let mut report = MILAN_REPORT.to_vec();
    report[0x187] ^= 1; // REPORTED_TCB microcode SPL
    let err =
        sev_snp::verify(&report, MILAN_VCEK, fixture_time(), &TrustStore::builtin()).unwrap_err();
    assert!(err.contains("ucodeSPL"), "{err}");
}

#[test]
fn milan_report_is_rejected_without_amd_roots() {
    let mut trust = TrustStore::builtin();
    trust.amd.retain(|r| r.product != AmdProduct::Milan);
    let err = sev_snp::verify(MILAN_REPORT, MILAN_VCEK, fixture_time(), &trust).unwrap_err();
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
    assert_eq!(
        evidence.measurements["tdattributes"],
        TDX_QUOTE[48 + 120..48 + 128]
    );
    assert_eq!(evidence.measurements.len(), 10);
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
fn cert<'k>(
    cn: &str,
    key: &'k KeyPair,
    ca: bool,
    issuer: Option<&CertifiedIssuer<'_, &KeyPair>>,
    extensions: Vec<CustomExtension>,
) -> CertifiedIssuer<'static, &'k KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    if ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    }
    params.custom_extensions = extensions;
    match issuer {
        Some(issuer) => CertifiedIssuer::signed_by(params, key, issuer).unwrap(),
        None => CertifiedIssuer::self_signed(params, key).unwrap(),
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
    let ca = cert("Test PCK CA", &ca_key, true, Some(&root), vec![]);
    let pck_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    // Every genuine PCK certificate carries the Intel SGX extensions.
    let sgx_extensions =
        CustomExtension::from_oid_content(&[1, 2, 840, 113741, 1, 13, 1], vec![0x30, 0x00]);
    let pck = cert("Test PCK", &pck_key, false, Some(&ca), vec![sgx_extensions]);
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
    td_body_with_attributes(report_data, mrtd, u64::from(debug) | (1 << 28))
}

/// A TDX report body with `TDATTRIBUTES` = `attributes`.
fn td_body_with_attributes(report_data: &[u8], mrtd: u8, attributes: u64) -> Vec<u8> {
    let mut body = vec![0u8; 584];
    body[120..128].copy_from_slice(&attributes.to_le_bytes());
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

/// A test AMD PKI: ARK → ASK → VCEK for one chip and ARK → ASVK → VLEK (ECDSA P-384 instead
/// of RSA-PSS).
struct AmdPki {
    roots: AmdRoots,
    vcek: Vec<u8>,
    vcek_key: EcdsaKeyPair,
    vlek: Vec<u8>,
    vlek_key: EcdsaKeyPair,
    chip_id: [u8; 64],
    tcb: [u8; 8],
}

fn amd_pki() -> AmdPki {
    let ark_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let ark = cert("ARK-Test", &ark_key, true, None, vec![]);
    let ask_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let ask = cert("SEV-Test", &ask_key, true, Some(&ark), vec![]);
    let asvk_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let asvk = cert("SEV-VLEK-Test", &asvk_key, true, Some(&ark), vec![]);

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
        Some(&ask),
        vec![
            spl(1, tcb[0]),
            spl(2, tcb[1]),
            spl(3, tcb[6]),
            spl(8, tcb[7]),
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 3704, 1, 4], chip_id.to_vec()),
        ],
    );
    // A VLEK has the TCB extensions but no hwID: it is not tied to one chip.
    let vlek_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
    let vlek = cert(
        "SEV-VLEK",
        &vlek_key,
        false,
        Some(&asvk),
        vec![
            spl(1, tcb[0]),
            spl(2, tcb[1]),
            spl(3, tcb[6]),
            spl(8, tcb[7]),
        ],
    );
    AmdPki {
        roots: AmdRoots {
            product: AmdProduct::Milan,
            ark: ark.der().to_vec(),
            ask: ask.der().to_vec(),
            asvk: asvk.der().to_vec(),
        },
        vcek: vcek.der().to_vec(),
        vcek_key: signer(&vcek_key, &ECDSA_P384_SHA384_FIXED_SIGNING),
        vlek: vlek.der().to_vec(),
        vlek_key: signer(&vlek_key, &ECDSA_P384_SHA384_FIXED_SIGNING),
        chip_id,
        tcb,
    }
}

/// Builds a VCEK-signed SEV-SNP attestation report.
fn build_snp_report(pki: &AmdPki, report_data: &[u8], measurement: u8, debug: bool) -> Vec<u8> {
    build_snp_report_signed(pki, report_data, measurement, debug, false)
}

/// Builds an SEV-SNP attestation report signed by the VLEK if `vlek`, else by the VCEK.
fn build_snp_report_signed(
    pki: &AmdPki,
    report_data: &[u8],
    measurement: u8,
    debug: bool,
    vlek: bool,
) -> Vec<u8> {
    let policy: u64 = (1 << 17) | if debug { 1 << 19 } else { 0 };
    build_snp_report_with(pki, report_data, measurement, policy, 0, vlek)
}

/// Builds an SEV-SNP attestation report with guest `policy`, requested from `vmpl`.
fn build_snp_report_with(
    pki: &AmdPki,
    report_data: &[u8],
    measurement: u8,
    policy: u64,
    vmpl: u32,
    vlek: bool,
) -> Vec<u8> {
    let mut report = vec![0u8; 0x4A0];
    if vlek {
        report[0x48] = 1 << 2; // FLAGS.SIGNING_KEY = VLEK
    }
    report[0..4].copy_from_slice(&3u32.to_le_bytes());
    report[0x08..0x10].copy_from_slice(&policy.to_le_bytes());
    report[0x30..0x34].copy_from_slice(&vmpl.to_le_bytes());
    report[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
    report[0x50..0x50 + report_data.len()].copy_from_slice(report_data);
    report[0x90..0xC0].fill(measurement);
    report[0x180..0x188].copy_from_slice(&pki.tcb);
    report[0x1A0..0x1E0].copy_from_slice(&pki.chip_id);

    let key = if vlek { &pki.vlek_key } else { &pki.vcek_key };
    let signature = sign(key, &report[..0x2A0]);
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

/// An image trust store listing the synthetic images whose measurement bytes are all `fill`:
/// TDX (`SHA-384(MRTD || RTMR0..2)`, the RTMRs being zero), SGX (MRENCLAVE) and SEV-SNP
/// (MEASUREMENT).
fn synthetic_images(fill: u8) -> RootImageTrustStore {
    let mut td_image = vec![fill; 48];
    td_image.extend([0; 3 * 48]);
    RootImageTrustStore {
        image_allowlist: vec![
            Sha384::digest(&td_image).to_vec(),
            vec![fill; 32],
            vec![fill; 48],
        ],
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
            TeeKind::Tdx,
            record(
                media_type::TDX,
                build_quote(TeeKind::Tdx, &td_body(&binding, 7, false), &intel),
            ),
            "mrtd",
        ),
        (
            TeeKind::Sgx,
            record(
                media_type::SGX,
                build_quote(TeeKind::Sgx, &sgx_body(&binding, 7, false), &intel),
            ),
            "mrenclave",
        ),
        (
            TeeKind::SevSnp,
            snp_cmw(&build_snp_report(&amd, &binding, 7, false), &amd.vcek),
            "measurement",
        ),
    ];
    for (tee, cmw, measurement) in cases {
        let evidence = verify_evidence(
            &cmw,
            &binding,
            UnixTime::now(),
            &trust,
            &synthetic_images(7),
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
            TeeKind::Tdx,
            record(
                media_type::TDX,
                build_quote(TeeKind::Tdx, &td_body(&binding, 0, true), &intel),
            ),
        ),
        (
            TeeKind::Sgx,
            record(
                media_type::SGX,
                build_quote(TeeKind::Sgx, &sgx_body(&binding, 0, true), &intel),
            ),
        ),
        (
            TeeKind::SevSnp,
            snp_cmw(&build_snp_report(&amd, &binding, 0, true), &amd.vcek),
        ),
    ];
    for (tee, cmw) in cases {
        let err = verify_evidence(
            &cmw,
            &binding,
            UnixTime::now(),
            &trust,
            &RootImageTrustStore::default(),
            Policy::default(),
        )
        .unwrap_err();
        assert!(err.contains("debug-mode"), "{tee}: {err}");

        let relaxed = Policy {
            allow_debug: true,
            ..Policy::default()
        };
        let evidence = verify_evidence(
            &cmw,
            &binding,
            UnixTime::now(),
            &trust,
            &RootImageTrustStore::default(),
            relaxed,
        )
        .unwrap();
        assert!(evidence.debug, "{tee}");
    }
}

#[test]
fn unlisted_images_are_rejected_for_every_hardware_tee() {
    let intel = intel_pki();
    let amd = amd_pki();
    let trust = test_trust(&intel, &amd);
    let binding = [0x42; 32];

    let cases = [
        (
            TeeKind::Tdx,
            record(
                media_type::TDX,
                build_quote(TeeKind::Tdx, &td_body(&binding, 7, false), &intel),
            ),
        ),
        (
            TeeKind::Sgx,
            record(
                media_type::SGX,
                build_quote(TeeKind::Sgx, &sgx_body(&binding, 7, false), &intel),
            ),
        ),
        (
            TeeKind::SevSnp,
            snp_cmw(&build_snp_report(&amd, &binding, 7, false), &amd.vcek),
        ),
    ];
    for (tee, cmw) in cases {
        for images in [synthetic_images(8), RootImageTrustStore::default()] {
            let err = verify_evidence(
                &cmw,
                &binding,
                UnixTime::now(),
                &trust,
                &images,
                Policy::default(),
            )
            .unwrap_err();
            assert!(err.contains(&format!("{tee} image")), "{tee}: {err}");
            assert!(
                err.contains("not in the list of verified images"),
                "{tee}: {err}"
            );
        }
    }
}

#[test]
fn signer_measurements_per_hardware_tee() {
    let intel = intel_pki();
    let amd = amd_pki();
    let binding = [0x42; 32];

    let sgx = dcap::verify(
        &build_quote(TeeKind::Sgx, &sgx_body(&binding, 7, false), &intel),
        TeeKind::Sgx,
        UnixTime::now(),
        &test_trust(&intel, &amd),
    )
    .unwrap();
    assert_eq!(
        image_measurement(&sgx, ImageMeasurement::Signer).unwrap(),
        sgx.measurements["mrsigner"]
    );

    let snp = sev_snp::verify(
        &build_snp_report(&amd, &binding, 7, false),
        &amd.vcek,
        UnixTime::now(),
        &test_trust(&intel, &amd),
    )
    .unwrap();
    assert_eq!(
        image_measurement(&snp, ImageMeasurement::Signer).unwrap(),
        snp.measurements["id_key_digest"]
    );

    let tdx = dcap::verify(
        &build_quote(TeeKind::Tdx, &td_body(&binding, 7, false), &intel),
        TeeKind::Tdx,
        UnixTime::now(),
        &test_trust(&intel, &amd),
    )
    .unwrap();
    let err = image_measurement(&tdx, ImageMeasurement::Signer).unwrap_err();
    assert!(err.contains("no signer measurement"), "{err}");
}
#[test]
fn evidence_bound_to_other_data_is_rejected() {
    let intel = intel_pki();
    let amd = amd_pki();
    let trust = test_trust(&intel, &amd);
    let quote = build_quote(TeeKind::Tdx, &td_body(&[0x42; 32], 0, false), &intel);
    let cmw = record(media_type::TDX, quote);

    let err = verify_evidence(
        &cmw,
        &[0x43; 32],
        UnixTime::now(),
        &trust,
        &synthetic_images(0),
        Policy::default(),
    )
    .unwrap_err();
    assert!(err.contains("report data does not match"), "{err}");
}

#[test]
fn cmw_must_carry_supported_tee_evidence() {
    let trust = TrustStore::builtin();
    let verify = |cmw: Vec<u8>| {
        verify_evidence(
            &cmw,
            &[0; 32],
            UnixTime::now(),
            &trust,
            &RootImageTrustStore::default(),
            Policy::default(),
        )
        .unwrap_err()
    };

    let err = verify(vec![0xff]);
    assert!(err.contains("invalid CMW"), "{err}");

    let err = verify(record("application/octet-stream", vec![1]));
    assert!(
        err.contains("does not carry supported TEE evidence"),
        "{err}"
    );

    // A quote marked as an Endorsement rather than Evidence.
    let endorsement = Cmw::Record(CmwRecord::new(
        media_type::TDX,
        vec![1],
        cmw::ind::ENDORSEMENTS,
    ));
    let err = verify(endorsement.to_cbor_bytes());
    assert!(err.contains("not marked as Evidence"), "{err}");

    // A bare SEV-SNP report record: the VCEK is missing.
    let err = verify(record(media_type::SEV_SNP_REPORT, vec![1]));
    assert!(
        err.contains("does not carry supported TEE evidence"),
        "{err}"
    );

    let amd = amd_pki();
    let report = build_snp_report(&amd, &[0; 32], 0, false);
    let mut no_vcek = snp_collection(&report, &amd.vcek);
    no_vcek.entries.retain(|(label, _)| label != "vcek");
    let err = verify(Cmw::Collection(no_vcek).to_cbor_bytes());
    assert!(err.contains("no 'vcek' member"), "{err}");

    let mut mistyped = snp_collection(&report, &amd.vcek);
    mistyped.entries[1].1 = Cmw::evidence(media_type::TDX, amd.vcek.clone());
    let err = verify(Cmw::Collection(mistyped).to_cbor_bytes());
    assert!(
        err.contains("is not a application/pkix-cert record"),
        "{err}"
    );

    let mut untyped = snp_collection(&report, &amd.vcek);
    untyped.collection_type = None;
    let err = verify(Cmw::Collection(untyped).to_cbor_bytes());
    assert!(
        err.contains("does not carry supported TEE evidence"),
        "{err}"
    );
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
    let leaf = cert("Test Nitro Signer", &key, false, Some(&root), vec![]);
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
        image_allowlist: parse_image_allowlist(LISTED_PCR0).unwrap(),
    }
}

fn listed_pcr0() -> Vec<u8> {
    parse_image_allowlist(LISTED_PCR0).unwrap().remove(0)
}

#[test]
fn nitro_evidence_from_a_listed_image_is_accepted() {
    let pki = nitro_pki();
    let doc = build_nitro_doc(&pki, listed_pcr0());
    let evidence =
        nitro::verify(&doc, UnixTime::now(), &nitro_trust(&pki), Policy::default()).unwrap();
    assert_eq!(evidence.tee, TeeKind::AwsNitro);
    assert_eq!(evidence.measurements["pcr0"], listed_pcr0());
    assert!(!evidence.debug);
    assert_eq!(
        image_measurement(&evidence, ImageMeasurement::Image).unwrap(),
        listed_pcr0()
    );
    check_image_allowed(&evidence, &nitro_images()).expect("a listed image should verify");
}

#[test]
fn nitro_evidence_from_an_unlisted_image_is_rejected() {
    let pki = nitro_pki();
    let mut pcr0 = listed_pcr0();
    pcr0[0] ^= 1;
    let doc = build_nitro_doc(&pki, pcr0);
    let cmw = record(media_type::AWS_NITRO, doc);
    let err = verify_evidence(
        &cmw,
        &[7; 32],
        UnixTime::now(),
        &nitro_trust(&pki),
        &nitro_images(),
        Policy::default(),
    )
    .unwrap_err();
    assert!(err.contains("AWS Nitro image"), "{err}");
    assert!(err.contains("not in the list of verified images"), "{err}");
}

#[test]
fn nitro_debug_evidence_is_left_to_the_debug_policy() {
    let pki = nitro_pki();
    let doc = build_nitro_doc(&pki, vec![0; 48]);
    let trust = nitro_trust(&pki);
    let evidence = nitro::verify(&doc, UnixTime::now(), &trust, Policy::default()).unwrap();
    assert!(evidence.debug);

    let cmw = record(media_type::AWS_NITRO, doc);
    let err = verify_evidence(
        &cmw,
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
fn root_signer_store_checks_the_signer_instead_of_the_image() {
    let pki = nitro_pki();
    let mut pcr0 = listed_pcr0();
    pcr0[0] ^= 1;
    // `build_nitro_doc` sets PCR8 to 48 bytes of 8.
    let doc = build_nitro_doc(&pki, pcr0);
    let signer = |pcr8: Vec<u8>| RootSignerTrustStore {
        signer_allowlist: vec![pcr8],
    };

    let evidence =
        nitro::verify(&doc, UnixTime::now(), &nitro_trust(&pki), Policy::default()).unwrap();
    assert_eq!(
        image_measurement(&evidence, ImageMeasurement::Signer).unwrap(),
        vec![8; 48]
    );
    check_image_allowed(&evidence, &signer(vec![8; 48]))
        .expect("a pinned PCR8 should verify whatever the PCR0");
    let err = check_image_allowed(&evidence, &signer(vec![9; 48])).unwrap_err();
    assert!(err.contains("image signer"), "{err}");
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
    let binding = Sha256::digest(bound_key.subject_public_key_info());
    let quote = build_quote(TeeKind::Tdx, &td_body(&binding, 7, false), intel);
    let cmw = record(media_type::TDX, quote);
    let pem = create_cert_with_attestation(key, "enclave.internal", &cmw, 1).unwrap();
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

#[test]
fn tdx_evidence_without_sept_ve_disable_is_rejected() {
    let intel = intel_pki();
    let trust = test_trust(&intel, &amd_pki());
    let binding = [0x42; 32];
    let verify = |attributes: u64| {
        let body = td_body_with_attributes(&binding, 7, attributes);
        let cmw = record(media_type::TDX, build_quote(TeeKind::Tdx, &body, &intel));
        verify_evidence(
            &cmw,
            &binding,
            UnixTime::now(),
            &trust,
            &synthetic_images(7),
            Policy::default(),
        )
    };
    verify(1 << 28).expect("SEPT_VE_DISABLE set should verify");
    let err = verify(0).unwrap_err();
    assert!(err.contains("SEPT_VE_DISABLE"), "{err}");
}

#[test]
fn pck_certificate_without_sgx_extensions_is_rejected() {
    let mut intel = intel_pki();
    // Re-issue the PCK leaf without the Intel SGX extensions.
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let root = cert("Test SGX Root CA", &root_key, true, None, vec![]);
    let pck_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let pck = cert("Test PCK", &pck_key, false, Some(&root), vec![]);
    intel.root = root.der().to_vec();
    intel.chain_pem = format!("{}{}", pck.pem(), root.pem());
    intel.pck = signer(&pck_key, &ECDSA_P256_SHA256_FIXED_SIGNING);
    let trust = test_trust(&intel, &amd_pki());

    let quote = build_quote(TeeKind::Sgx, &sgx_body(&[0x42; 32], 7, false), &intel);
    let err = dcap::verify(&quote, TeeKind::Sgx, UnixTime::now(), &trust).unwrap_err();
    assert!(err.contains("Intel SGX extensions"), "{err}");
}

#[test]
fn snp_guest_policy_and_vmpl_are_checked() {
    let amd = amd_pki();
    let trust = test_trust(&intel_pki(), &amd);
    let binding = [0x42; 32];
    let verify = |report: &[u8]| sev_snp::verify(report, &amd.vcek, UnixTime::now(), &trust);

    let smt = (1 << 16) | (1 << 17);
    verify(&build_snp_report_with(&amd, &binding, 7, smt, 0, false))
        .expect("a policy with SMT allowed and VMPL 0 should verify");

    let migratable = (1 << 17) | (1 << 18);
    let err = verify(&build_snp_report_with(
        &amd, &binding, 7, migratable, 0, false,
    ))
    .unwrap_err();
    assert!(err.contains("MIGRATE_MA"), "{err}");

    let err = verify(&build_snp_report_with(&amd, &binding, 7, 0, 0, false)).unwrap_err();
    assert!(err.contains("reserved bit 17"), "{err}");

    let err = verify(&build_snp_report_with(&amd, &binding, 7, 1 << 17, 1, false)).unwrap_err();
    assert!(err.contains("VMPL 1"), "{err}");
}

#[test]
fn vlek_signed_snp_report_verifies_through_the_asvk() {
    let amd = amd_pki();
    let trust = test_trust(&intel_pki(), &amd);
    let binding = [0x42; 32];
    let report = build_snp_report_signed(&amd, &binding, 7, false, true);

    let evidence = verify_evidence(
        &snp_cmw(&report, &amd.vlek),
        &binding,
        UnixTime::now(),
        &trust,
        &synthetic_images(7),
        Policy::default(),
    )
    .expect("a VLEK-signed report should verify");
    assert_eq!(evidence.tee, TeeKind::SevSnp);
    assert!(evidence.measurements["measurement"].iter().all(|b| *b == 7));
}

#[test]
fn snp_signing_key_must_match_its_certificate_chain() {
    let amd = amd_pki();
    let trust = test_trust(&intel_pki(), &amd);
    let binding = [0x42; 32];
    let verify = |report: &[u8], cert: &[u8]| {
        verify_evidence(
            &snp_cmw(report, cert),
            &binding,
            UnixTime::now(),
            &trust,
            &RootImageTrustStore::default(),
            Policy::default(),
        )
        .unwrap_err()
    };

    // A VLEK-flagged report with the VCEK: the VCEK is not certified by the ASVK.
    let vlek_report = build_snp_report_signed(&amd, &binding, 0, false, true);
    let err = verify(&vlek_report, &amd.vcek);
    assert!(err.contains("not signed by a pinned AMD ASVK"), "{err}");

    // A VCEK-flagged report with the VLEK: the VLEK is not certified by the ASK.
    let vcek_report = build_snp_report(&amd, &binding, 0, false);
    let err = verify(&vcek_report, &amd.vlek);
    assert!(err.contains("not signed by a pinned AMD ASK"), "{err}");

    // A VLEK-flagged report signed by the VCEK key, carried with the VLEK certificate.
    let mut forged = build_snp_report(&amd, &binding, 0, false);
    forged[0x48] = 1 << 2;
    let err = verify(&forged, &amd.vlek);
    assert!(err.contains("signature is invalid for its VLEK"), "{err}");

    // SIGNING_KEY = 7: unsigned report.
    let mut unsigned = vcek_report.clone();
    unsigned[0x48] = 7 << 2;
    let err = verify(&unsigned, &amd.vcek);
    assert!(err.contains("not signed by a VCEK or VLEK"), "{err}");
}

#[test]
fn fresh_tdx_and_snp_evidence_binds_the_nonce_in_the_report_data() {
    let intel = intel_pki();
    let amd = amd_pki();
    let trust = test_trust(&intel, &amd);
    let binding = [0x42; 32];
    let nonce = b"verifier nonce";
    let report_data = ttk_core::fresh_evidence::report_data(&binding, Some(nonce)).unwrap();
    assert_eq!(report_data[..32], binding);
    assert_eq!(report_data[32..], Sha256::digest(nonce)[..]);

    let cases = [
        (
            TeeKind::Tdx,
            record(
                media_type::TDX,
                build_quote(TeeKind::Tdx, &td_body(&report_data, 7, false), &intel),
            ),
        ),
        (
            TeeKind::SevSnp,
            snp_cmw(
                &build_snp_report_signed(&amd, &report_data, 7, false, true),
                &amd.vlek,
            ),
        ),
    ];
    for (tee, cmw) in cases {
        let verify = |binding: &[u8], nonce: &[u8]| {
            verify_evidence_with_nonce(
                &cmw,
                binding,
                nonce,
                UnixTime::now(),
                &trust,
                &synthetic_images(7),
                Policy::default(),
            )
        };
        let evidence = verify(&binding, nonce).unwrap_or_else(|e| panic!("{tee}: {e}"));
        assert_eq!(evidence.tee, tee);

        let err = verify(&binding, b"other nonce").unwrap_err();
        assert!(err.contains("and the nonce"), "{tee}: {err}");
        let err = verify(&[0x43; 32], nonce).unwrap_err();
        assert!(err.contains("and the nonce"), "{tee}: {err}");

        // Without a nonce check, the hash in the second half is not zero padding.
        let err = verify_evidence(
            &cmw,
            &binding,
            UnixTime::now(),
            &trust,
            &synthetic_images(7),
            Policy::default(),
        )
        .unwrap_err();
        assert!(err.contains("report data does not match"), "{tee}: {err}");
    }

    // Startup Evidence (zero-padded report data) does not answer a nonce.
    let startup = snp_cmw(&build_snp_report(&amd, &binding, 7, false), &amd.vcek);
    let err = verify_evidence_with_nonce(
        &startup,
        &binding,
        nonce,
        UnixTime::now(),
        &trust,
        &synthetic_images(7),
        Policy::default(),
    )
    .unwrap_err();
    assert!(err.contains("and the nonce"), "{err}");
}
