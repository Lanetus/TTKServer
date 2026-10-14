//! Tests for the accepted-images reference values ([`ttk_core::image_trust`]).

use ttk_core::image_trust::{
    parse_image_allowlist, ImageTrustStore, RootAttestation, ROOT_ATTESTATION_HASH,
};

/// A 96-character hex PCR whose every byte is `byte`.
fn pcr_hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(48)
}

/// An in-memory [`ImageTrustStore`] using the default PCR index.
#[derive(Debug)]
struct Fixed(Vec<Vec<u8>>);

impl ImageTrustStore for Fixed {
    fn builtin() -> Self {
        Self(vec![vec![0xab; 48], vec![0x01; 48]])
    }

    fn nitro_image_allowlist(&self) -> &[Vec<u8>] {
        &self.0
    }
}

#[test]
fn parses_one_pcr_per_line_ignoring_comments_and_blanks() {
    let text = format!(
        "# accepted images\n\n{}\n  {}  # relay v1\n   \n#{}\n",
        pcr_hex(0xab),
        pcr_hex(0x01).to_uppercase(),
        pcr_hex(0xff),
    );
    assert_eq!(
        parse_image_allowlist(&text).unwrap(),
        vec![vec![0xab; 48], vec![0x01; 48]]
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
    let long = "ab".repeat(49);
    let not_hex = format!("{}zz", "ab".repeat(47));
    let multibyte = format!("{}é", "a".repeat(94));
    for bad in [short.as_str(), &long, &not_hex, &multibyte] {
        let error = parse_image_allowlist(&format!("{}\n{bad}\n", pcr_hex(1))).unwrap_err();
        assert!(error.starts_with("line 2:"), "{error}");
        assert!(error.contains(bad), "{error}");
    }
}

#[test]
fn default_pcr_index_is_pcr0() {
    assert_eq!(Fixed::builtin().nitro_pcr_index(), 0);
}

#[test]
fn root_attestation_lists_lowercase_hex_pcr0_values() {
    let attestation = RootAttestation::from_image_trust_store(&Fixed::builtin());
    assert_eq!(attestation.hash_algorithm, ROOT_ATTESTATION_HASH);
    assert_eq!(attestation.pcr0, vec![pcr_hex(0xab), pcr_hex(0x01)]);
    assert_eq!(
        attestation.pcr0_values().unwrap(),
        Fixed::builtin().nitro_image_allowlist()
    );
}

#[test]
fn root_attestation_json_round_trips() {
    let attestation = RootAttestation::from_image_trust_store(&Fixed(vec![vec![0x5a; 48]]));
    let json = serde_json::to_value(&attestation).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "hash_algorithm": "SHA384", "pcr0": [pcr_hex(0x5a)] })
    );
    let decoded: RootAttestation = serde_json::from_value(json).unwrap();
    assert_eq!(decoded, attestation);
}

#[test]
fn rejects_all_zero_pcrs() {
    let error =
        parse_image_allowlist(&format!("{}\n{}  # debug\n", pcr_hex(1), pcr_hex(0))).unwrap_err();
    assert!(error.starts_with("line 2:"), "{error}");
    assert!(error.contains("all-zero"), "{error}");

    let attestation = RootAttestation {
        hash_algorithm: ROOT_ATTESTATION_HASH.to_string(),
        pcr0: vec![pcr_hex(0)],
    };
    assert!(attestation.pcr0_values().unwrap_err().contains("all-zero"));
}

#[test]
fn root_attestation_rejects_other_hash_algorithms() {
    let attestation = RootAttestation {
        hash_algorithm: "SHA256".to_string(),
        pcr0: vec![pcr_hex(1)],
    };
    assert!(attestation.pcr0_values().unwrap_err().contains("SHA256"));
}

#[test]
fn root_attestation_rejects_invalid_pcr0_values() {
    let attestation = RootAttestation {
        hash_algorithm: ROOT_ATTESTATION_HASH.to_string(),
        pcr0: vec![pcr_hex(1), "abcd".to_string()],
    };
    assert!(attestation.pcr0_values().unwrap_err().contains("abcd"));
}

#[test]
fn empty_root_attestation_accepts_no_image() {
    let attestation = RootAttestation::from_image_trust_store(&Fixed(Vec::new()));
    assert!(attestation.pcr0.is_empty());
    assert!(attestation.pcr0_values().unwrap().is_empty());
}
