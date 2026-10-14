//! Tests for the accepted-images reference values ([`ttk_core::image_trust`]).

use ttk_core::image_trust::{
    parse_image_allowlist, ImageMeasurement, ImageTrustStore, RootAttestation, RootSignerTrustStore,
};

/// A 96-character hex SHA-384 measurement whose every byte is `byte`.
fn sha384_hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(48)
}

/// A 64-character hex SHA-256 measurement whose every byte is `byte`.
fn sha256_hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

/// An in-memory [`ImageTrustStore`] using the default measurement.
#[derive(Debug)]
struct Fixed(Vec<Vec<u8>>);

impl ImageTrustStore for Fixed {
    fn builtin() -> Self {
        Self(vec![vec![0xab; 48], vec![0x01; 32]])
    }

    fn image_allowlist(&self) -> &[Vec<u8>] {
        &self.0
    }
}

#[test]
fn parses_one_measurement_per_line_ignoring_comments_and_blanks() {
    let text = format!(
        "# accepted images\n\n{}\n  {}  # relay v1\n   \n#{}\n",
        sha384_hex(0xab),
        sha256_hex(0x01).to_uppercase(),
        sha384_hex(0xff),
    );
    assert_eq!(
        parse_image_allowlist(&text).unwrap(),
        vec![vec![0xab; 48], vec![0x01; 32]]
    );
}

#[test]
fn empty_allowlist_is_empty() {
    assert!(parse_image_allowlist("").unwrap().is_empty());
    assert!(parse_image_allowlist("# nothing yet\n\n")
        .unwrap()
        .is_empty());
}

#[test]
fn rejects_invalid_entries_with_their_line_number() {
    let short = "ab".repeat(47);
    let between = "ab".repeat(40);
    let long = "ab".repeat(49);
    let odd = format!("{}a", "ab".repeat(32));
    let not_hex = format!("{}zz", "ab".repeat(47));
    let multibyte = format!("{}é", "a".repeat(94));
    for bad in [short.as_str(), &between, &long, &odd, &not_hex, &multibyte] {
        let error = parse_image_allowlist(&format!("{}\n{bad}\n", sha384_hex(1))).unwrap_err();
        assert!(error.starts_with("line 2:"), "{error}");
        assert!(error.contains(bad), "{error}");
    }
}

#[test]
fn rejects_all_zero_measurements() {
    for zero in [sha384_hex(0), sha256_hex(0)] {
        let error =
            parse_image_allowlist(&format!("{}\n{zero}  # debug\n", sha384_hex(1))).unwrap_err();
        assert!(error.starts_with("line 2:"), "{error}");
        assert!(error.contains("all-zero"), "{error}");
    }

    let attestation = RootAttestation {
        measurements: vec![sha384_hex(0)],
    };
    assert!(attestation
        .measurement_values()
        .unwrap_err()
        .contains("all-zero"));
}

#[test]
fn default_measurement_is_the_image() {
    assert_eq!(Fixed::builtin().measurement(), ImageMeasurement::Image);
    assert_eq!(ImageMeasurement::default(), ImageMeasurement::Image);
}

#[test]
fn builtin_root_signer_allowlist_is_valid() {
    let store = RootSignerTrustStore::builtin();
    assert_eq!(store.measurement(), ImageMeasurement::Signer);
    assert_eq!(store.image_allowlist(), store.signer_allowlist);
}

#[test]
fn root_attestation_lists_lowercase_hex_measurements() {
    let attestation = RootAttestation::from_image_trust_store(&Fixed::builtin());
    assert_eq!(
        attestation.measurements,
        vec![sha384_hex(0xab), sha256_hex(0x01)]
    );
    assert_eq!(
        attestation.measurement_values().unwrap(),
        Fixed::builtin().image_allowlist()
    );
}

#[test]
fn root_attestation_json_round_trips() {
    let attestation = RootAttestation::from_image_trust_store(&Fixed(vec![vec![0x5a; 48]]));
    let json = serde_json::to_value(&attestation).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "measurements": [sha384_hex(0x5a)] })
    );
    let decoded: RootAttestation = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, attestation);
}

#[test]
fn root_attestation_rejects_invalid_measurements() {
    let attestation = RootAttestation {
        measurements: vec![sha384_hex(1), "abcd".to_string()],
    };
    assert!(attestation
        .measurement_values()
        .unwrap_err()
        .contains("abcd"));
}

#[test]
fn empty_root_attestation_accepts_no_image() {
    let attestation = RootAttestation::from_image_trust_store(&Fixed(Vec::new()));
    assert!(attestation.measurements.is_empty());
    assert!(attestation.measurement_values().unwrap().is_empty());
}
