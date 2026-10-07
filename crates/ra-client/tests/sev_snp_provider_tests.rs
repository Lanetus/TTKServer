//! Tests for the AMD SEV-SNP attestation provider (`ttk_ra_server::attestation::sev_snp`).
//!
//! configfs-tsm is emulated with a temporary directory holding the attributes the kernel would
//! expose; `outblob` holds a genuine Milan report and `auxblob` a certificate table with its
//! VCEK (see `tests/fixtures/README.md`).

use rustls_pki_types::UnixTime;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use ttk_ra_client::verifier::{verify_evidence, Policy, TeeKind, TrustStore};
use ttk_ra_client::RootImageTrustStore;
use ttk_ra_server::attestation::sev_snp::{
    evidence_from_entry, report_data, vcek_from_cert_table, wrap_evidence_as_eat, SevSnpSession,
    REPORT_DATA_LEN,
};
use ttk_ra_server::attestation::AttestationError;
use ttk_ra_server::AttestationParams;

const MILAN_REPORT: &[u8] = include_bytes!("fixtures/sev_snp_milan_report.bin");
const MILAN_VCEK: &[u8] = include_bytes!("fixtures/sev_snp_milan_vcek.der");

/// VCEK GUID 63da758d-e664-4564-adc5-f4b93be8accd in RFC 4122 byte order.
const VCEK_GUID: [u8; 16] = [
    0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd,
];
/// ARK GUID c0b406a4-a803-4952-9743-3fb6014cd0ae.
const ARK_GUID: [u8; 16] = [
    0xc0, 0xb4, 0x06, 0xa4, 0xa8, 0x03, 0x49, 0x52, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0, 0xae,
];

/// The `REPORT_DATA` carried by the Milan report.
fn milan_report_data() -> [u8; REPORT_DATA_LEN] {
    MILAN_REPORT[0x50..0x90].try_into().unwrap()
}

fn le(guid: [u8; 16]) -> [u8; 16] {
    let mut g = guid;
    g[0..4].reverse();
    g[4..6].reverse();
    g[6..8].reverse();
    g
}

/// Builds an extended-report certificate table holding `certs`, zero-padding each certificate
/// to a 4 KiB boundary like the host does.
fn cert_table(certs: &[([u8; 16], &[u8])]) -> Vec<u8> {
    let header_len = 24 * (certs.len() + 1);
    let mut header = Vec::new();
    let mut body = Vec::new();
    for (guid, cert) in certs {
        header.extend(guid);
        header.extend(((header_len + body.len()) as u32).to_le_bytes());
        header.extend((cert.len() as u32).to_le_bytes());
        body.extend(*cert);
        body.resize(body.len().next_multiple_of(4096), 0);
    }
    header.extend([0u8; 24]);
    header.extend(body);
    header
}

/// A temporary directory, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ttk-snp-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Emulates a configfs-tsm entry served by `provider`.
fn fake_entry(provider: &str, outblob: &[u8], auxblob: &[u8]) -> TempDir {
    let dir = TempDir::new();
    fs::write(dir.0.join("provider"), format!("{provider}\n")).unwrap();
    fs::write(dir.0.join("generation"), "1\n").unwrap();
    fs::write(dir.0.join("outblob"), outblob).unwrap();
    fs::write(dir.0.join("auxblob"), auxblob).unwrap();
    dir
}

#[test]
fn report_and_vcek_are_read_from_the_configfs_entry() {
    let table = cert_table(&[(le(ARK_GUID), b"ark"), (le(VCEK_GUID), MILAN_VCEK)]);
    let entry = fake_entry("sev_guest", MILAN_REPORT, &table);

    let evidence = evidence_from_entry(&entry.0, &milan_report_data(), None).unwrap();
    assert_eq!(evidence.report, MILAN_REPORT);
    assert_eq!(
        evidence.vcek, MILAN_VCEK,
        "padding after the DER must be dropped"
    );
    assert_eq!(
        fs::read(entry.0.join("inblob")).unwrap(),
        milan_report_data()
    );
}

#[test]
fn vcek_guid_in_rfc4122_byte_order_is_also_found() {
    let table = cert_table(&[(VCEK_GUID, MILAN_VCEK)]);
    assert_eq!(vcek_from_cert_table(&table).unwrap().unwrap(), MILAN_VCEK);
}

#[test]
fn cert_table_without_vcek_yields_none() {
    let table = cert_table(&[(le(ARK_GUID), b"ark")]);
    assert!(vcek_from_cert_table(&table).unwrap().is_none());
}

#[test]
fn cert_table_pointing_outside_is_rejected() {
    let mut table = cert_table(&[(le(VCEK_GUID), MILAN_VCEK)]);
    table[20..24].copy_from_slice(&u32::MAX.to_le_bytes()); // length
    let err = vcek_from_cert_table(&table).unwrap_err();
    assert!(err.to_string().contains("outside the table"), "{err}");
}

#[test]
fn missing_vcek_asks_for_the_override() {
    let entry = fake_entry("sev_guest", MILAN_REPORT, b"");
    let err = evidence_from_entry(&entry.0, &milan_report_data(), None).unwrap_err();
    assert!(err.to_string().contains("TTK_SEV_SNP_VCEK"), "{err}");
}

#[test]
fn vcek_override_is_used_without_reading_auxblob() {
    let entry = fake_entry("sev_guest", MILAN_REPORT, b"");
    fs::remove_file(entry.0.join("auxblob")).unwrap();

    let evidence = evidence_from_entry(&entry.0, &milan_report_data(), Some(MILAN_VCEK)).unwrap();
    assert_eq!(evidence.vcek, MILAN_VCEK);
}

#[test]
fn entry_from_another_provider_is_rejected() {
    let entry = fake_entry("tdx_guest", MILAN_REPORT, b"");
    let err = evidence_from_entry(&entry.0, &milan_report_data(), Some(MILAN_VCEK)).unwrap_err();
    assert!(err.to_string().contains("expected 'sev_guest'"), "{err}");
}

#[test]
fn report_with_other_report_data_is_rejected() {
    let entry = fake_entry("sev_guest", MILAN_REPORT, b"");
    let err =
        evidence_from_entry(&entry.0, &[0x42; REPORT_DATA_LEN], Some(MILAN_VCEK)).unwrap_err();
    assert!(
        err.to_string()
            .contains("does not carry the requested REPORT_DATA"),
        "{err}"
    );
}

#[test]
fn truncated_report_is_rejected() {
    let entry = fake_entry("sev_guest", &MILAN_REPORT[..1000], b"");
    let err = evidence_from_entry(&entry.0, &milan_report_data(), Some(MILAN_VCEK)).unwrap_err();
    assert!(err.to_string().contains("expected 1184"), "{err}");
}

#[test]
fn vlek_signed_report_is_rejected() {
    let mut report = MILAN_REPORT.to_vec();
    report[0x48] |= 1 << 2; // SIGNING_KEY = VLEK
    let entry = fake_entry("sev_guest", &report, b"");
    let err = evidence_from_entry(&entry.0, &milan_report_data(), Some(MILAN_VCEK)).unwrap_err();
    assert!(matches!(err, AttestationError::Unsupported(_)), "{err}");
}

#[test]
fn vcek_override_accepts_pem_and_rejects_garbage() {
    let root = TempDir::new();
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode(MILAN_VCEK)
    );
    assert!(SevSnpSession::open_at(&root.0)
        .unwrap()
        .with_vcek(pem.as_bytes())
        .is_ok());
    assert!(matches!(
        SevSnpSession::open_at(&root.0)
            .unwrap()
            .with_vcek(b"not a cert"),
        Err(AttestationError::InvalidInput(_))
    ));
}

#[test]
fn missing_configfs_is_reported_on_open() {
    let err = SevSnpSession::open_at("/nonexistent/tsm/report").unwrap_err();
    assert!(
        matches!(err, AttestationError::DeviceOpenFailed(_)),
        "{err}"
    );
}

#[test]
fn get_evidence_cleans_up_its_entry_on_failure() {
    // A plain directory has no provider attribute, so the request fails before writing.
    let root = TempDir::new();
    let session = SevSnpSession::open_at(&root.0).unwrap();
    let err = session.get_evidence(&[0; REPORT_DATA_LEN]).unwrap_err();
    assert!(err.to_string().contains("provider"), "{err}");
    assert_eq!(
        fs::read_dir(&root.0).unwrap().count(),
        0,
        "entry should be removed"
    );
}

#[test]
fn report_data_is_user_data_zero_padded() {
    let params = AttestationParams {
        user_data: Some(vec![7; 32]),
        ..Default::default()
    };
    let data = report_data(&params).unwrap();
    assert_eq!(data[..32], [7; 32]);
    assert_eq!(data[32..], [0; 32]);
}

#[test]
fn provider_eat_is_accepted_by_the_client_verifier() {
    let table = cert_table(&[(le(VCEK_GUID), MILAN_VCEK)]);
    let entry = fake_entry("sev_guest", MILAN_REPORT, &table);
    let evidence = evidence_from_entry(&entry.0, &milan_report_data(), None).unwrap();
    let eat = wrap_evidence_as_eat(&evidence).to_cbor_bytes().unwrap();

    // 2026-01-01: inside the VCEK's validity period.
    let now = UnixTime::since_unix_epoch(Duration::from_secs(1_767_225_600));
    let verified = verify_evidence(
        &eat,
        &milan_report_data(),
        now,
        &TrustStore::builtin(),
        &RootImageTrustStore::default(),
        Policy::default(),
    )
    .expect("the verifier should accept the provider's EAT with the real AMD roots");
    assert_eq!(verified.tee, TeeKind::SevSnp);
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn truncated_cert_table_entry_is_rejected() {
    let err = vcek_from_cert_table(&[1; 10]).unwrap_err();
    assert!(err.to_string().contains("truncated entry"), "{err}");
}

#[test]
fn vcek_is_loaded_from_a_file() {
    let dir = TempDir::new();
    let path = dir.0.join("vcek.der");
    fs::write(&path, MILAN_VCEK).unwrap();
    let root = TempDir::new();

    assert!(SevSnpSession::open_at(&root.0)
        .unwrap()
        .with_vcek_file(&path)
        .is_ok());
    let err = SevSnpSession::open_at(&root.0)
        .unwrap()
        .with_vcek_file(dir.0.join("missing.der"))
        .unwrap_err();
    assert!(err.to_string().contains("failed to read the VCEK"), "{err}");
}

#[test]
fn session_reports_its_name_and_propagates_errors() {
    use ttk_ra_server::attestation::AttestationProvider;

    let root = TempDir::new();
    let session = SevSnpSession::open_at(&root.0).unwrap();
    assert_eq!(session.name(), "sev-snp");
    let _ = SevSnpSession::is_available();

    let params = AttestationParams {
        user_data: Some(vec![1; 32]),
        ..Default::default()
    };
    let err = session.generate_document(&params).unwrap_err();
    assert!(err.to_string().contains("provider"), "{err}");

    let with_key = AttestationParams {
        public_key: Some(vec![2; 8]),
        ..params
    };
    assert!(matches!(
        session.generate_document(&with_key),
        Err(AttestationError::InvalidInput(_))
    ));
}
