//! Tests for provider selection and errors in `ttk_ra_server::attestation`.

use ttk_ra_server::attestation::{by_name, detect, AttestationError, PROVIDER_ENV};

#[test]
fn every_error_variant_has_a_message() {
    let cases = [
        (
            AttestationError::DeviceOpenFailed("x".into()),
            "Failed to open TEE device: x",
        ),
        (
            AttestationError::Driver("x".into()),
            "TEE driver returned an error: x",
        ),
        (
            AttestationError::UnexpectedResponse("x".into()),
            "Unexpected response from TEE driver: x",
        ),
        (
            AttestationError::InvalidInput("x".into()),
            "Invalid attestation input: x",
        ),
        (
            AttestationError::DocumentDecodingFailed("x".into()),
            "Document decoding failure: x",
        ),
        (
            AttestationError::Unsupported("x".into()),
            "Unsupported attestation provider: x",
        ),
        (
            AttestationError::NoProvider,
            "No attestation provider matches this hardware",
        ),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn io_errors_convert_to_the_io_variant() {
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
    let error = AttestationError::from(io);
    assert!(matches!(error, AttestationError::Io(_)));
    assert_eq!(error.to_string(), "I/O error: gone");
    let _: &dyn std::error::Error = &error;
}

#[test]
fn unknown_provider_names_are_rejected() {
    let err = by_name("no-such-tee").err().unwrap();
    assert!(
        err.to_string().contains("'no-such-tee' is unknown"),
        "{err}"
    );
}

#[cfg(feature = "mock")]
#[test]
fn mock_provider_is_always_available() {
    use ttk_ra_server::attestation::{AttestationProvider, MockSession};
    assert!(MockSession::is_available());
    assert_eq!(MockSession.name(), "mock");
}

#[cfg(feature = "sev-snp")]
#[test]
fn sev_snp_provider_requires_configfs_tsm() {
    use ttk_ra_server::attestation::sev_snp::{SevSnpSession, CONFIGFS_TSM_REPORT};
    if std::path::Path::new(CONFIGFS_TSM_REPORT).is_dir() {
        return; // running inside a confidential guest
    }
    assert!(matches!(
        SevSnpSession::open(),
        Err(AttestationError::DeviceOpenFailed(_))
    ));
    assert!(matches!(
        by_name("sev-snp"),
        Err(AttestationError::DeviceOpenFailed(_))
    ));
}

#[cfg(feature = "tdx")]
#[test]
fn tdx_provider_requires_configfs_tsm() {
    use ttk_ra_server::attestation::tdx::{TdxSession, CONFIGFS_TSM_REPORT};
    if std::path::Path::new(CONFIGFS_TSM_REPORT).is_dir() {
        return; // running inside a confidential guest
    }
    assert!(matches!(
        TdxSession::open(),
        Err(AttestationError::DeviceOpenFailed(_))
    ));
    assert!(matches!(
        by_name("tdx"),
        Err(AttestationError::DeviceOpenFailed(_))
    ));
}

/// `detect` reads the process-wide `TTK_ATTESTATION` variable, so all its cases run in this one
/// test to avoid racing with each other.
#[cfg(feature = "mock")]
#[test]
fn detect_honours_the_override_and_falls_back_to_mock() {
    std::env::set_var(PROVIDER_ENV, "mock");
    let forced = detect().map(|p| p.name());
    std::env::set_var(PROVIDER_ENV, "no-such-tee");
    let unknown = detect().err();
    std::env::remove_var(PROVIDER_ENV);

    assert_eq!(forced.unwrap(), "mock");
    assert!(matches!(unknown, Some(AttestationError::Unsupported(_))));

    // Without the override and without TEE hardware, the mock provider is the fallback.
    let on_tee_hardware = ["/dev/nsm", "/dev/sev-guest", "/dev/tdx_guest"]
        .iter()
        .any(|d| std::path::Path::new(d).exists());
    if !on_tee_hardware {
        assert_eq!(detect().unwrap().name(), "mock");
    }
}
