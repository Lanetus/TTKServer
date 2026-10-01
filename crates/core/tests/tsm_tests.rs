//! Tests for the shared configfs-tsm request handling (`ttk_core::attestation::tsm`).
//!
//! configfs-tsm is emulated with temporary directories holding the attributes the kernel would
//! expose.

#![cfg(any(feature = "tdx", feature = "sev-snp"))]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use ttk_core::attestation::tsm::{request_in_entry, TsmRoot, REPORT_DATA_LEN};
use ttk_core::attestation::AttestationError;

/// A temporary directory, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ttk-tsm-test-{}-{}",
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

/// Emulates an entry served by `provider`, without `outblob` or `auxblob`.
fn entry(provider: &str) -> TempDir {
    let dir = TempDir::new();
    fs::write(dir.0.join("provider"), format!("{provider}\n")).unwrap();
    fs::write(dir.0.join("generation"), "1\n").unwrap();
    dir
}

fn driver_error(result: Result<impl std::fmt::Debug, AttestationError>) -> String {
    match result {
        Err(AttestationError::Driver(msg)) => msg,
        other => panic!("expected a Driver error, got {other:?}"),
    }
}

#[test]
fn request_returns_outblob_and_non_empty_auxblob() {
    let entry = entry("test_guest");
    fs::write(entry.0.join("outblob"), b"evidence").unwrap();
    fs::write(entry.0.join("auxblob"), b"certs").unwrap();

    let report = request_in_entry(&entry.0, "test_guest", &[3; REPORT_DATA_LEN], true).unwrap();
    assert_eq!(report.outblob, b"evidence");
    assert_eq!(report.auxblob.as_deref(), Some(b"certs".as_slice()));

    let without_aux =
        request_in_entry(&entry.0, "test_guest", &[3; REPORT_DATA_LEN], false).unwrap();
    assert!(without_aux.auxblob.is_none());
}

#[test]
fn missing_outblob_is_a_driver_error() {
    let entry = entry("test_guest");
    let msg = driver_error(request_in_entry(
        &entry.0,
        "test_guest",
        &[0; REPORT_DATA_LEN],
        false,
    ));
    assert!(msg.contains("failed to obtain evidence"), "{msg}");
}

#[test]
fn missing_auxblob_is_a_driver_error() {
    let entry = entry("test_guest");
    fs::write(entry.0.join("outblob"), b"evidence").unwrap();
    let msg = driver_error(request_in_entry(
        &entry.0,
        "test_guest",
        &[0; REPORT_DATA_LEN],
        true,
    ));
    assert!(msg.contains("auxblob"), "{msg}");
}

#[test]
fn missing_generation_is_a_driver_error() {
    let dir = TempDir::new();
    fs::write(dir.0.join("provider"), "test_guest\n").unwrap();
    let msg = driver_error(request_in_entry(
        &dir.0,
        "test_guest",
        &[0; REPORT_DATA_LEN],
        false,
    ));
    assert!(msg.contains("'generation'"), "{msg}");
}

/// Simulates another writer changing the entry while the evidence is generated: `outblob` is a
/// named pipe, and the writer bumps `generation` after the request opens it, before any data
/// arrives.
#[cfg(unix)]
#[test]
fn concurrent_modification_is_detected() {
    let entry = entry("test_guest");
    let outblob = entry.0.join("outblob");
    let status = std::process::Command::new("mkfifo")
        .arg(&outblob)
        .status()
        .expect("mkfifo is available on Unix");
    assert!(status.success());

    let generation = entry.0.join("generation");
    let writer = std::thread::spawn(move || {
        // Opening the pipe for writing blocks until the request opens it for reading.
        let mut pipe = fs::OpenOptions::new().write(true).open(&outblob).unwrap();
        fs::write(&generation, "2\n").unwrap();
        std::io::Write::write_all(&mut pipe, b"evidence").unwrap();
    });

    let result = request_in_entry(&entry.0, "test_guest", &[0; REPORT_DATA_LEN], false);
    writer.join().unwrap();
    match result {
        Err(AttestationError::UnexpectedResponse(msg)) => {
            assert!(msg.contains("modified"), "{msg}")
        }
        other => panic!("expected the modification to be detected, got {other:?}"),
    }
}

#[test]
fn entry_creation_failure_is_reported() {
    let root = TempDir::new();
    let tsm = TsmRoot::open_at(&root.0, "a test").unwrap();
    fs::remove_dir(&root.0).unwrap();

    match tsm.request("test_guest", &[0; REPORT_DATA_LEN], false) {
        Err(AttestationError::DeviceOpenFailed(msg)) => {
            assert!(msg.contains("failed to create configfs-tsm entry"), "{msg}")
        }
        other => panic!("expected DeviceOpenFailed, got {other:?}"),
    }
}

#[test]
fn open_at_names_the_guest_in_its_error() {
    match TsmRoot::open_at("/nonexistent/tsm/report", "a test") {
        Err(AttestationError::DeviceOpenFailed(msg)) => {
            assert!(msg.contains("in a test guest"), "{msg}")
        }
        other => panic!("expected DeviceOpenFailed, got {other:?}"),
    }
}
