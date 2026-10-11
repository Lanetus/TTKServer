//! Tests for the RATS Conceptual Message Wrapper encoding and decoding (`ttk_core::cmw`).

use ciborium::Value;
use ttk_core::cmw::{ind, Cmw, CmwCollection, CmwRecord, CmwType, COLLECTION_TYPE_KEY};
use ttk_core::{media_type, FreshEvidence};

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

fn decode(value: Value) -> Result<Cmw, String> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    Cmw::from_cbor_bytes(&bytes)
}

fn collection() -> Cmw {
    Cmw::Collection(CmwCollection {
        collection_type: Some("tag:example.com,2026:test".into()),
        entries: vec![
            ("a".into(), Cmw::evidence("application/x-a", vec![1, 2])),
            (
                "b".into(),
                Cmw::Record(CmwRecord::new(
                    "application/pkix-cert",
                    vec![3],
                    ind::ENDORSEMENTS,
                )),
            ),
        ],
    })
}

#[test]
fn evidence_record_encodes_as_a_three_item_array() {
    let cmw = Cmw::evidence("application/x-test", vec![7, 8]);
    assert_eq!(
        cmw.to_cbor_value(),
        Value::Array(vec![
            text("application/x-test"),
            Value::Bytes(vec![7, 8]),
            Value::Integer(4.into()),
        ])
    );
    assert_eq!(Cmw::from_cbor_bytes(&cmw.to_cbor_bytes()).unwrap(), cmw);
}

#[test]
fn record_without_ind_and_with_content_format_round_trips() {
    let cmw = Cmw::Record(CmwRecord {
        cm_type: CmwType::ContentFormat(263),
        value: vec![1],
        ind: None,
    });
    assert_eq!(
        cmw.to_cbor_value(),
        Value::Array(vec![Value::Integer(263.into()), Value::Bytes(vec![1])])
    );
    let decoded = Cmw::from_cbor_bytes(&cmw.to_cbor_bytes()).unwrap();
    assert_eq!(decoded, cmw);
    let Cmw::Record(record) = decoded else {
        unreachable!()
    };
    assert_eq!(record.media_type(), None);
}

#[test]
fn collection_round_trips_with_its_type_first() {
    let cmw = collection();
    let Value::Map(map) = cmw.to_cbor_value() else {
        panic!("a collection encodes as a map");
    };
    assert_eq!(map[0].0, text(COLLECTION_TYPE_KEY));
    assert_eq!(Cmw::from_cbor_bytes(&cmw.to_cbor_bytes()).unwrap(), cmw);

    let Cmw::Collection(c) = cmw else {
        unreachable!()
    };
    assert!(matches!(c.get("b"), Some(Cmw::Record(r)) if r.ind == Some(ind::ENDORSEMENTS)));
    assert!(c.get("c").is_none());
}

#[test]
fn malformed_records_are_rejected() {
    let bytes = || Value::Bytes(vec![1]);
    let cases = [
        (Value::Array(vec![text("t")]), "1 items"),
        (
            Value::Array(vec![text("t"), bytes(), bytes(), bytes()]),
            "4 items",
        ),
        (Value::Array(vec![bytes(), bytes()]), "neither a media type"),
        (
            Value::Array(vec![Value::Integer(70_000.into()), bytes()]),
            "out of range",
        ),
        (
            Value::Array(vec![text("t"), text("not bytes")]),
            "not a byte string",
        ),
        (
            Value::Array(vec![text("t"), bytes(), Value::Integer(256.into())]),
            "ind",
        ),
        (
            Value::Array(vec![text("t"), bytes(), Value::Integer((-1).into())]),
            "ind",
        ),
        (Value::Bytes(vec![]), "neither a record"),
    ];
    for (value, expected) in cases {
        let err = decode(value.clone()).unwrap_err();
        assert!(err.contains(expected), "{value:?}: {err}");
    }
    assert!(Cmw::from_cbor_bytes(&[0xff])
        .unwrap_err()
        .contains("invalid CBOR"));
}

#[test]
fn malformed_collections_are_rejected() {
    let member = || Value::Array(vec![text("t"), Value::Bytes(vec![1])]);
    let cases = [
        (Value::Map(vec![]), "no members"),
        (
            Value::Map(vec![(text(COLLECTION_TYPE_KEY), text("tag:x"))]),
            "no members",
        ),
        (
            Value::Map(vec![(Value::Integer(1.into()), member())]),
            "label is not text",
        ),
        (
            Value::Map(vec![
                (text(COLLECTION_TYPE_KEY), Value::Bytes(vec![])),
                (text("a"), member()),
            ]),
            "not a URI",
        ),
        (
            Value::Map(vec![(text("a"), member()), (text("a"), member())]),
            "repeated",
        ),
        (
            Value::Map(vec![
                (text(COLLECTION_TYPE_KEY), text("tag:x")),
                (text(COLLECTION_TYPE_KEY), text("tag:y")),
                (text("a"), member()),
            ]),
            "repeated",
        ),
        (
            Value::Map(vec![(text("a"), Value::Bytes(vec![]))]),
            "member 'a'",
        ),
    ];
    for (value, expected) in cases {
        let err = decode(value.clone()).unwrap_err();
        assert!(err.contains(expected), "{value:?}: {err}");
    }
}

#[test]
fn nested_collections_round_trip() {
    let cmw = Cmw::Collection(CmwCollection {
        collection_type: None,
        entries: vec![("inner".into(), collection())],
    });
    assert_eq!(Cmw::from_cbor_bytes(&cmw.to_cbor_bytes()).unwrap(), cmw);
}

#[test]
fn fresh_evidence_round_trips_through_cbor() {
    let fresh = FreshEvidence {
        evidence: Cmw::evidence(media_type::AWS_NITRO, b"doc".to_vec()),
        certificate: b"cert".to_vec(),
    };
    let cmw = fresh.to_cmw();
    let Cmw::Collection(collection) = &cmw else {
        panic!("fresh Evidence should be a collection");
    };
    assert_eq!(
        collection.collection_type.as_deref(),
        Some(media_type::FRESH_EVIDENCE_COLLECTION)
    );
    assert_eq!(
        FreshEvidence::from_cbor_bytes(&cmw.to_cbor_bytes()).unwrap(),
        fresh
    );
}

#[test]
fn fresh_evidence_requires_its_type_and_members() {
    let evidence = Cmw::evidence(media_type::AWS_NITRO, b"doc".to_vec());
    // A bare Evidence record (the old `POST /evidence` response).
    assert!(FreshEvidence::from_cmw(&evidence).is_err());

    let collection = |collection_type: &str, entries: Vec<(&str, Cmw)>| {
        Cmw::Collection(CmwCollection {
            collection_type: Some(collection_type.to_string()),
            entries: entries
                .into_iter()
                .map(|(label, cmw)| (label.to_string(), cmw))
                .collect(),
        })
    };
    let cert = Cmw::Record(CmwRecord::new(media_type::PKIX_CERT, b"cert".to_vec(), 0));
    let wrong_type = collection(
        media_type::SEV_SNP_COLLECTION,
        vec![
            (media_type::FRESH_EVIDENCE_LABEL, evidence.clone()),
            (media_type::FRESH_CERTIFICATE_LABEL, cert.clone()),
        ],
    );
    let no_cert = collection(
        media_type::FRESH_EVIDENCE_COLLECTION,
        vec![(media_type::FRESH_EVIDENCE_LABEL, evidence.clone())],
    );
    let no_evidence = collection(
        media_type::FRESH_EVIDENCE_COLLECTION,
        vec![(media_type::FRESH_CERTIFICATE_LABEL, cert)],
    );
    let cert_not_pkix = collection(
        media_type::FRESH_EVIDENCE_COLLECTION,
        vec![
            (media_type::FRESH_EVIDENCE_LABEL, evidence.clone()),
            (media_type::FRESH_CERTIFICATE_LABEL, evidence),
        ],
    );
    for cmw in [wrong_type, no_cert, no_evidence, cert_not_pkix] {
        assert!(FreshEvidence::from_cmw(&cmw).is_err(), "{cmw:?}");
    }
}
