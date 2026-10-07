//! RATS Conceptual Message Wrapper (CMW, `draft-ietf-rats-msg-wrap`), CBOR serialisation.
//!
//! A CMW carries an opaque RATS conceptual message (RFC 9334: Evidence, Endorsements, ...)
//! together with its type, so a Verifier knows how to parse it. It adds no claims of its own:
//! the wrapped TEE evidence is signed by the hardware, the wrapper is not, and trust comes only
//! from what it wraps.
//!
//! Two forms are supported:
//!
//! - [`CmwRecord`]: `[type, value, ?ind]`, where `type` is a media type or a CoAP
//!   Content-Format id, `value` the message bytes and `ind` the [`ind`] bits saying what kind of
//!   conceptual message it is.
//! - [`CmwCollection`]: a map from text labels to CMWs, with an optional `"__cmwc_t"` collection
//!   type (a URI) naming what the whole collection is.
//!
//! The CBOR-tag form, integer labels, OID collection types and the JSON serialisation are not
//! supported: decoding them fails.

use ciborium::value::Value;

/// Conceptual-message indicator bits (`ind`) of a [`CmwRecord`].
pub mod ind {
    /// Reference Values.
    pub const REFERENCE_VALUES: u8 = 1;
    /// Endorsements.
    pub const ENDORSEMENTS: u8 = 2;
    /// Evidence.
    pub const EVIDENCE: u8 = 4;
    /// Attestation Results.
    pub const ATTESTATION_RESULTS: u8 = 8;
}

/// Map key of a [`CmwCollection`]'s collection type.
pub const COLLECTION_TYPE_KEY: &str = "__cmwc_t";

/// The type of the message in a [`CmwRecord`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CmwType {
    /// A media type (RFC 6838), e.g. `application/eat+cwt`.
    MediaType(String),
    /// A CoAP Content-Format id (RFC 7252 §12.3).
    ContentFormat(u16),
}

/// A record CMW: one typed conceptual message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CmwRecord {
    /// The message's type.
    pub cm_type: CmwType,
    /// The message, verbatim.
    pub value: Vec<u8>,
    /// What kind of conceptual message it is ([`ind`] bits); `None` if unspecified.
    pub ind: Option<u8>,
}

/// A collection CMW: labelled CMWs making up one composite message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CmwCollection {
    /// What the collection as a whole is (a URI); `None` if unspecified.
    pub collection_type: Option<String>,
    /// The members, in encoding order.
    pub entries: Vec<(String, Cmw)>,
}

/// A Conceptual Message Wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cmw {
    /// A single typed message.
    Record(CmwRecord),
    /// Labelled messages.
    Collection(CmwCollection),
}

/// Constructors and accessors.
impl CmwRecord {
    /// A record holding `value` of `media_type`, marked as `ind`.
    pub fn new(media_type: &str, value: Vec<u8>, ind: u8) -> Self {
        Self {
            cm_type: CmwType::MediaType(media_type.to_string()),
            value,
            ind: Some(ind),
        }
    }

    /// The record's media type, if it is typed by one.
    pub fn media_type(&self) -> Option<&str> {
        match &self.cm_type {
            CmwType::MediaType(t) => Some(t),
            CmwType::ContentFormat(_) => None,
        }
    }
}

/// Member lookup.
impl CmwCollection {
    /// Returns the member labelled `label`, if any.
    pub fn get(&self, label: &str) -> Option<&Cmw> {
        self.entries
            .iter()
            .find(|(l, _)| l == label)
            .map(|(_, cmw)| cmw)
    }
}

/// CBOR encoding and decoding.
impl Cmw {
    /// A record CMW holding Evidence `value` of `media_type`.
    pub fn evidence(media_type: &str, value: Vec<u8>) -> Self {
        Self::Record(CmwRecord::new(media_type, value, ind::EVIDENCE))
    }

    /// Encodes the CMW as a CBOR value.
    pub fn to_cbor_value(&self) -> Value {
        match self {
            Self::Record(r) => {
                let cm_type = match &r.cm_type {
                    CmwType::MediaType(t) => Value::Text(t.clone()),
                    CmwType::ContentFormat(cf) => Value::Integer((*cf).into()),
                };
                let mut items = vec![cm_type, Value::Bytes(r.value.clone())];
                if let Some(ind) = r.ind {
                    items.push(Value::Integer(ind.into()));
                }
                Value::Array(items)
            }
            Self::Collection(c) => {
                let mut map = Vec::with_capacity(c.entries.len() + 1);
                if let Some(t) = &c.collection_type {
                    map.push((
                        Value::Text(COLLECTION_TYPE_KEY.into()),
                        Value::Text(t.clone()),
                    ));
                }
                for (label, cmw) in &c.entries {
                    map.push((Value::Text(label.clone()), cmw.to_cbor_value()));
                }
                Value::Map(map)
            }
        }
    }

    /// Encodes the CMW as CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(&self.to_cbor_value(), &mut out)
            .expect("encoding a CBOR value into a Vec cannot fail");
        out
    }

    /// Decodes a CMW from a CBOR value: an array is a record, a map a collection.
    pub fn from_cbor_value(value: &Value) -> Result<Self, String> {
        match value {
            Value::Array(items) => record_from_items(items).map(Self::Record),
            Value::Map(map) => collection_from_map(map).map(Self::Collection),
            _ => Err("CMW is neither a record (array) nor a collection (map)".into()),
        }
    }

    /// Decodes a CMW from CBOR bytes.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value: Value =
            ciborium::de::from_reader(bytes).map_err(|e| format!("invalid CBOR: {e}"))?;
        Self::from_cbor_value(&value)
    }
}

/// Decodes the items of a record CMW, `[type, value, ?ind]`.
fn record_from_items(items: &[Value]) -> Result<CmwRecord, String> {
    let (cm_type, value, ind) = match items {
        [t, v] => (t, v, None),
        [t, v, i] => (t, v, Some(i)),
        _ => {
            return Err(format!(
                "CMW record has {} items, expected 2 or 3",
                items.len()
            ))
        }
    };
    let cm_type = match cm_type {
        Value::Text(t) => CmwType::MediaType(t.clone()),
        Value::Integer(i) => CmwType::ContentFormat(
            u16::try_from(*i).map_err(|_| "CMW record Content-Format is out of range")?,
        ),
        _ => return Err("CMW record type is neither a media type nor a Content-Format".into()),
    };
    let value = value
        .as_bytes()
        .ok_or("CMW record value is not a byte string")?
        .clone();
    let ind = ind
        .map(|i| {
            i.as_integer()
                .and_then(|i| u8::try_from(i).ok())
                .ok_or("CMW record ind is not a small unsigned integer")
        })
        .transpose()?;
    Ok(CmwRecord {
        cm_type,
        value,
        ind,
    })
}

/// Decodes the map of a collection CMW, `{ ?"__cmwc_t": uri, + label => CMW }`.
fn collection_from_map(map: &[(Value, Value)]) -> Result<CmwCollection, String> {
    let mut collection = CmwCollection::default();
    for (label, value) in map {
        let label = label.as_text().ok_or("CMW collection label is not text")?;
        if collection.get(label).is_some()
            || (label == COLLECTION_TYPE_KEY && collection.collection_type.is_some())
        {
            return Err(format!("CMW collection label '{label}' is repeated"));
        }
        if label == COLLECTION_TYPE_KEY {
            let t = value.as_text().ok_or("CMW collection type is not a URI")?;
            collection.collection_type = Some(t.to_string());
        } else {
            let cmw = Cmw::from_cbor_value(value)
                .map_err(|e| format!("CMW collection member '{label}': {e}"))?;
            collection.entries.push((label.to_string(), cmw));
        }
    }
    if collection.entries.is_empty() {
        return Err("CMW collection has no members".into());
    }
    Ok(collection)
}
