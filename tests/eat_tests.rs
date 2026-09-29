//! Tests for RFC 9711 EAT claims-set encoding and decoding (`ttk_server::eat`).

use ciborium::Value;
use ttk_server::eat::{EatClaimKey, EatClaimsSet};

/// A claims-set with every claim populated.
fn full_claims() -> EatClaimsSet {
    let text = |s: &str| Value::Text(s.into());
    EatClaimsSet {
        iat: Some(1_700_000_000),
        nonce: Some(Value::Bytes(vec![1; 16])),
        ueid: Some(vec![0x01, 2, 3]),
        sueids: Some(Value::Map(vec![(text("s"), Value::Bytes(vec![4]))])),
        oem_id: Some(Value::Integer(42.into())),
        hw_model: Some(vec![5, 6]),
        hw_version: Some(Value::Array(vec![text("1.0"), Value::Integer(1.into())])),
        uptime: Some(3_600),
        oem_boot: Some(true),
        dbg_stat: Some(3),
        location: Some(Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Float(52.0),
        )])),
        eat_profile: Some("tag:example.com,2026:test".into()),
        submods: Some(Value::Map(vec![(text("m"), Value::Bytes(vec![7]))])),
        boot_count: Some(9),
        boot_seed: Some(vec![8; 32]),
        dloas: Some(Value::Array(vec![])),
        sw_name: Some("ttk".into()),
        sw_version: Some(Value::Array(vec![text("0.17.1")])),
        manifests: Some(Value::Array(vec![])),
        measurements: Some(Value::Array(vec![Value::Bytes(vec![9])])),
        meas_res: Some(Value::Array(vec![])),
        int_use: Some(2),
    }
}

/// Compares every field (the struct derives no `PartialEq`).
fn assert_same(a: &EatClaimsSet, b: &EatClaimsSet) {
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
}

#[test]
fn every_claim_round_trips_through_cbor() {
    let claims = full_claims();
    let bytes = claims.to_cbor_bytes().unwrap();
    assert_same(&EatClaimsSet::from_cbor_bytes(&bytes).unwrap(), &claims);
    assert_same(&EatClaimsSet::from_bytes(&bytes).unwrap(), &claims);
}

#[test]
fn every_claim_is_encoded_under_its_registered_key() {
    let map = match full_claims().to_cbor_value() {
        Value::Map(map) => map,
        other => panic!("expected a map, got {other:?}"),
    };
    let keys: Vec<i64> = map
        .iter()
        .map(|(k, _)| i128::from(k.as_integer().unwrap()) as i64)
        .collect();
    let mut expected = vec![i64::from(EatClaimKey::Iat), i64::from(EatClaimKey::Nonce)];
    expected.extend(256..=275);
    assert_eq!(keys.len(), expected.len());
    for key in expected {
        assert!(keys.contains(&key), "missing key {key}");
    }
}

#[test]
fn empty_claims_set_encodes_as_an_empty_map() {
    assert_eq!(EatClaimsSet::default().to_cbor_value(), Value::Map(vec![]));
}

#[test]
fn non_map_input_is_rejected() {
    assert!(EatClaimsSet::from_cbor_value(&Value::Array(vec![])).is_err());
    assert!(EatClaimsSet::from_cbor_bytes(&[0xff]).is_err());
}

#[test]
fn unknown_and_non_integer_keys_are_ignored() {
    let value = Value::Map(vec![
        (Value::Text("iat".into()), Value::Integer(1.into())),
        (Value::Integer(9999.into()), Value::Integer(1.into())),
        (Value::Integer(6.into()), Value::Integer(7.into())),
    ]);
    let claims = EatClaimsSet::from_cbor_value(&value).unwrap();
    assert_eq!(claims.iat, Some(7));
}

#[test]
fn claims_with_the_wrong_cbor_type_are_ignored() {
    let wrong = |key: i64| (Value::Integer(key.into()), Value::Null);
    let typed_keys = [6, 256, 259, 261, 262, 263, 265, 267, 268, 270, 275];
    let value = Value::Map(typed_keys.iter().map(|k| wrong(*k)).collect());

    let claims = EatClaimsSet::from_cbor_value(&value).unwrap();
    assert!(claims.iat.is_none());
    assert!(claims.ueid.is_none());
    assert!(claims.hw_model.is_none());
    assert!(claims.uptime.is_none());
    assert!(claims.oem_boot.is_none());
    assert!(claims.dbg_stat.is_none());
    assert!(claims.eat_profile.is_none());
    assert!(claims.boot_count.is_none());
    assert!(claims.boot_seed.is_none());
    assert_eq!(claims.sw_name, None);
    assert!(claims.int_use.is_none());
}

#[test]
fn claim_keys_convert_to_their_integer_labels() {
    assert_eq!(i64::from(EatClaimKey::Iat), 6);
    assert_eq!(i64::from(EatClaimKey::Nonce), 10);
    assert_eq!(i64::from(EatClaimKey::Ueid), 256);
    assert_eq!(i64::from(EatClaimKey::Submods), 266);
    assert_eq!(i64::from(EatClaimKey::IntUse), 275);
}
