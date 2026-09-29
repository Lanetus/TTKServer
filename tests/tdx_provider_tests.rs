//! Tests for the Intel TDX attestation provider (`ttk_server::attestation::tdx`).
//!
//! configfs-tsm is emulated with a temporary directory holding the attributes the kernel would
//! expose; `outblob` holds Intel's sample TDX quote (see `tests/fixtures/README.md`).

#![cfg(feature = "tdx")]

use rustls_pki_types::UnixTime;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use ttk_server::attestation::tdx::{
    quote_from_entry, report_data, wrap_quote_as_eat, TdxSession, REPORT_DATA_LEN,
};
use ttk_server::attestation::AttestationError;
use ttk_server::verifier::{verify_evidence, Policy, TeeKind, TrustStore};
use ttk_server::AttestationParams;

const TDX_QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote_v4.dat");
const TDX_QUOTE_ROOT: &[u8] = include_bytes!("fixtures/tdx_quote_v4_test_root.der");

/// The `REPORTDATA` carried by the sample quote.
fn quote_report_data() -> [u8; REPORT_DATA_LEN] {
    TDX_QUOTE[48 + 520..48 + 584].try_into().unwrap()
}

/// A temporary directory, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ttk-tdx-test-{}-{}",
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

/// Emulates a configfs-tsm entry served by `provider` that returns `outblob`.
fn fake_entry(provider: &str, outblob: &[u8]) -> TempDir {
    let dir = TempDir::new();
    fs::write(dir.0.join("provider"), format!("{provider}\n")).unwrap();
    fs::write(dir.0.join("generation"), "1\n").unwrap();
    fs::write(dir.0.join("outblob"), outblob).unwrap();
    dir
}

#[test]
fn quote_is_read_from_the_configfs_entry() {
    let entry = fake_entry("tdx_guest", TDX_QUOTE);
    let report_data = quote_report_data();

    let quote = quote_from_entry(&entry.0, &report_data).expect("quote should be returned");
    assert_eq!(quote, TDX_QUOTE);
    assert_eq!(fs::read(entry.0.join("inblob")).unwrap(), report_data);
}

#[test]
fn entry_from_another_provider_is_rejected() {
    let entry = fake_entry("sev_guest", TDX_QUOTE);
    let err = quote_from_entry(&entry.0, &quote_report_data()).unwrap_err();
    assert!(err.to_string().contains("expected 'tdx_guest'"), "{err}");
    assert!(
        !entry.0.join("inblob").exists(),
        "nothing should be requested"
    );
}

#[test]
fn quote_with_other_report_data_is_rejected() {
    let entry = fake_entry("tdx_guest", TDX_QUOTE);
    let err = quote_from_entry(&entry.0, &[0x42; REPORT_DATA_LEN]).unwrap_err();
    assert!(
        err.to_string()
            .contains("does not carry the requested REPORTDATA"),
        "{err}"
    );
}

#[test]
fn non_tdx_quote_is_rejected() {
    let mut quote = TDX_QUOTE.to_vec();
    quote[4] = 0; // tee_type: SGX
    let entry = fake_entry("tdx_guest", &quote);
    let err = quote_from_entry(&entry.0, &quote_report_data()).unwrap_err();
    assert!(err.to_string().contains("expected TDX"), "{err}");
}

#[test]
fn missing_configfs_is_reported_on_open() {
    let err = TdxSession::open_at("/nonexistent/tsm/report").unwrap_err();
    assert!(
        matches!(err, AttestationError::DeviceOpenFailed(_)),
        "{err}"
    );
}

#[test]
fn get_quote_cleans_up_its_entry_on_failure() {
    // A plain directory has no provider attribute, so the request fails before writing.
    let root = TempDir::new();
    let session = TdxSession::open_at(&root.0).unwrap();
    let err = session.get_quote(&[0; REPORT_DATA_LEN]).unwrap_err();
    assert!(err.to_string().contains("provider"), "{err}");
    assert_eq!(
        fs::read_dir(&root.0).unwrap().count(),
        0,
        "entry should be removed"
    );
}

#[test]
fn report_data_is_user_data_zero_padded() {
    let params = AttestationParams::new().with_user_data(vec![7; 32]);
    let data = report_data(&params).unwrap();
    assert_eq!(data[..32], [7; 32]);
    assert_eq!(data[32..], [0; 32]);
}

#[test]
fn report_data_rejects_oversized_or_unsupported_inputs() {
    let oversized = AttestationParams::new().with_user_data(vec![1; 65]);
    assert!(matches!(
        report_data(&oversized),
        Err(AttestationError::InvalidInput(_))
    ));

    let with_nonce = AttestationParams::new()
        .with_user_data(vec![1; 32])
        .with_nonce(vec![2; 16]);
    assert!(matches!(
        report_data(&with_nonce),
        Err(AttestationError::InvalidInput(_))
    ));
}

#[test]
fn provider_eat_is_accepted_by_the_client_verifier() {
    let eat = wrap_quote_as_eat(TDX_QUOTE).to_cbor_bytes().unwrap();
    let trust = TrustStore {
        intel_sgx_root: TDX_QUOTE_ROOT.to_vec(),
        ..TrustStore::builtin()
    };
    // 2026-01-01: inside the validity of the sample quote's PCK chain.
    let now = UnixTime::since_unix_epoch(Duration::from_secs(1_767_225_600));

    let evidence = verify_evidence(&eat, &quote_report_data(), now, &trust, Policy::default())
        .expect("the verifier should accept the provider's EAT");
    assert_eq!(evidence.tee, TeeKind::Tdx);
}
