//! Tests for the file service wire format ([`ttk_core::file_message`]).

use ciborium::Value;
use ttk_core::file_message::{FileError, FileRequest, FileResponse, SHA256_LEN};

/// Decodes `bytes` as a generic CBOR value.
fn cbor(bytes: &[u8]) -> Value {
    ciborium::from_reader(bytes).unwrap()
}

/// A CBOR map with text keys.
fn map(entries: &[(&str, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(k, v)| (Value::Text(k.to_string()), v.clone()))
            .collect(),
    )
}

/// Encodes a generic CBOR value.
fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

#[test]
fn upload_encodes_as_a_typed_map_with_a_byte_string_body() {
    let request = FileRequest::Upload(b"file contents".to_vec());
    let bytes = request.to_cbor().unwrap();
    assert_eq!(
        cbor(&bytes),
        map(&[
            ("type", Value::Text("upload".into())),
            ("body", Value::Bytes(b"file contents".to_vec())),
        ])
    );
    assert_eq!(FileRequest::from_cbor(&bytes).unwrap(), request);
}

#[test]
fn download_round_trips() {
    let request = FileRequest::Download(vec![0xab; SHA256_LEN]);
    let bytes = request.to_cbor().unwrap();
    assert_eq!(
        cbor(&bytes),
        map(&[
            ("type", Value::Text("download".into())),
            ("body", Value::Bytes(vec![0xab; SHA256_LEN])),
        ])
    );
    assert_eq!(FileRequest::from_cbor(&bytes).unwrap(), request);
}

#[test]
fn empty_upload_round_trips() {
    let request = FileRequest::Upload(Vec::new());
    assert_eq!(
        FileRequest::from_cbor(&request.to_cbor().unwrap()).unwrap(),
        request
    );
}

#[test]
fn rejects_malformed_requests() {
    for value in [
        // Unknown type.
        map(&[
            ("type", Value::Text("delete".into())),
            ("body", Value::Bytes(vec![1])),
        ]),
        // Body as a text string instead of bytes (no base64).
        map(&[
            ("type", Value::Text("upload".into())),
            ("body", Value::Text("aGVsbG8=".into())),
        ]),
        // Missing type.
        map(&[("body", Value::Bytes(vec![1]))]),
        // Not a map.
        Value::Array(vec![Value::Text("upload".into())]),
    ] {
        assert!(
            FileRequest::from_cbor(&encode(&value)).is_err(),
            "{value:?}"
        );
    }
    assert!(FileRequest::from_cbor(&[]).is_err());
    assert!(FileRequest::from_cbor(&[0xff, 0x00]).is_err());
}

#[test]
fn response_encodes_as_a_single_key_map() {
    let response = FileResponse::Response(vec![7; SHA256_LEN]);
    let bytes = response.to_cbor().unwrap();
    assert_eq!(
        cbor(&bytes),
        map(&[("response", Value::Bytes(vec![7; SHA256_LEN]))])
    );
    assert_eq!(FileResponse::from_cbor(&bytes).unwrap(), response);
    assert_eq!(response.into_result(), Ok(vec![7; SHA256_LEN]));
}

#[test]
fn not_found_encodes_as_a_snake_case_error() {
    let response = FileResponse::Error(FileError::NotFound);
    let bytes = response.to_cbor().unwrap();
    assert_eq!(
        cbor(&bytes),
        map(&[("error", Value::Text("not_found".into()))])
    );
    assert_eq!(FileResponse::from_cbor(&bytes).unwrap(), response);
    assert_eq!(response.into_result(), Err(FileError::NotFound));
}

#[test]
fn rejects_malformed_responses() {
    for value in [
        map(&[("error", Value::Text("forbidden".into()))]),
        map(&[("result", Value::Bytes(vec![1]))]),
        map(&[]),
        Value::Bytes(vec![1]),
    ] {
        assert!(
            FileResponse::from_cbor(&encode(&value)).is_err(),
            "{value:?}"
        );
    }
    assert!(FileResponse::from_cbor(&[]).is_err());
}

#[test]
fn file_error_is_a_displayable_error() {
    let error: Box<dyn std::error::Error + Send + Sync> = Box::new(FileError::NotFound);
    assert_eq!(error.to_string(), "file not found");
}
