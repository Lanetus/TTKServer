//! RFC 9711 Entity Attestation Token (EAT) data model.
//!
//! Defines the full set of IANA-registered EAT claim keys ([`EatClaimKey`]) and a
//! strongly-typed claims-set structure ([`EatClaimsSet`]) that can be serialised to
//! CBOR.  Nitro-enclave-specific wrapping logic lives in [`crate::attestation::nitro_doc`].
use ciborium::value::Value;

// ---------------------------------------------------------------------------
// IANA-registered EAT/CWT claim keys (RFC 9711)
// https://www.iana.org/assignments/cwt
// ---------------------------------------------------------------------------

/// CWT / EAT claim key integers as registered by RFC 9711.
///
/// Standard JWT/CWT claims that predate EAT (e.g., `iat = 6`) are included
/// for completeness. The RFC 9711-specific claims start at key 10 (Nonce)
/// and run through 275 (Intended Use).
#[allow(dead_code)]
#[repr(i64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EatClaimKey {
    // ---- Standard CWT claims used by EAT ----
    /// Issued-At (seconds since epoch).  CWT key 6.
    Iat = 6,

    // ---- RFC 9711 claims ----
    /// Nonce – `eat_nonce`.  Key 10.  Value: bstr or array.
    Nonce = 10,
    /// Universal Entity ID – `ueid`.  Key 256.  Value: bstr.
    Ueid = 256,
    /// Semipermanent UEIDs – `sueids`.  Key 257.  Value: map.
    Sueids = 257,
    /// Hardware OEM ID – `oemid`.  Key 258.  Value: bstr or int.
    OemId = 258,
    /// Hardware Model – `hwmodel`.  Key 259.  Value: bstr.
    HwModel = 259,
    /// Hardware Version – `hwversion`.  Key 260.  Value: array.
    HwVersion = 260,
    /// Uptime – `uptime`.  Key 261.  Value: uint.
    Uptime = 261,
    /// OEM Authorized Boot – `oemboot`.  Key 262.  Value: bool.
    OemBoot = 262,
    /// Debug Status – `dbgstat`.  Key 263.  Value: uint.
    DbgStat = 263,
    /// Location – `location`.  Key 264.  Value: map.
    Location = 264,
    /// EAT Profile – `eat_profile`.  Key 265.  Value: uri or oid.
    EatProfile = 265,
    /// Submodules Section – `submods`.  Key 266.  Value: map.
    Submods = 266,
    /// Boot Count – `bootcount`.  Key 267.  Value: uint.
    BootCount = 267,
    /// Boot Seed – `bootseed`.  Key 268.  Value: bstr.
    BootSeed = 268,
    /// DLOAs (Digital Letters of Approval) – `dloas`.  Key 269.  Value: array.
    Dloas = 269,
    /// Software Name – `swname`.  Key 270.  Value: tstr.
    SwName = 270,
    /// Software Version – `swversion`.  Key 271.  Value: array.
    SwVersion = 271,
    /// Software Manifests – `manifests`.  Key 272.  Value: array.
    Manifests = 272,
    /// Measurements – `measurements`.  Key 273.  Value: array.
    Measurements = 273,
    /// Software Measurement Results – `measres`.  Key 274.  Value: array.
    MeasRes = 274,
    /// Intended Use – `intuse`.  Key 275.  Value: uint.
    IntUse = 275,
}

/// Converts a claim key into its integer CBOR map key.
impl From<EatClaimKey> for i64 {
    /// Returns the numeric key of `k`.
    fn from(k: EatClaimKey) -> i64 {
        k as i64
    }
}

// ---------------------------------------------------------------------------
// RFC 9711 EAT claims-set structure
// ---------------------------------------------------------------------------

/// Strongly-typed representation of an RFC 9711 EAT claims-set.
///
/// Every field is `Option<…>` so that only the claims relevant to a
/// particular token need to be populated.  Fields whose CBOR value type
/// is composite (map / array) are left as raw `ciborium::value::Value` so
/// that callers can construct them without an additional indirection layer.
///
/// # Claim → CBOR key mapping
///
/// | Field           | JWT name      | CWT key |
/// |-----------------|---------------|---------|
/// | `iat`           | —             | 6       |
/// | `nonce`         | eat_nonce     | 10      |
/// | `ueid`          | ueid          | 256     |
/// | `sueids`        | sueids        | 257     |
/// | `oem_id`        | oemid         | 258     |
/// | `hw_model`      | hwmodel       | 259     |
/// | `hw_version`    | hwversion     | 260     |
/// | `uptime`        | uptime        | 261     |
/// | `oem_boot`      | oemboot       | 262     |
/// | `dbg_stat`      | dbgstat       | 263     |
/// | `location`      | location      | 264     |
/// | `eat_profile`   | eat_profile   | 265     |
/// | `submods`       | submods       | 266     |
/// | `boot_count`    | bootcount     | 267     |
/// | `boot_seed`     | bootseed      | 268     |
/// | `dloas`         | dloas         | 269     |
/// | `sw_name`       | swname        | 270     |
/// | `sw_version`    | swversion     | 271     |
/// | `manifests`     | manifests     | 272     |
/// | `measurements`  | measurements  | 273     |
/// | `meas_res`      | measres       | 274     |
/// | `int_use`       | intuse        | 275     |
#[derive(Clone, Debug, Default)]
pub struct EatClaimsSet {
    // ---- Standard CWT ----
    /// Issued-At: seconds since POSIX epoch (CWT key 6).
    pub iat: Option<i64>,

    // ---- RFC 9711 ----
    /// Nonce – `eat_nonce` (key 10).
    /// CBOR value: bstr or array-of-bstr.
    pub nonce: Option<Value>,

    /// Universal Entity ID – `ueid` (key 256).
    /// A byte string whose first byte encodes the UEID type
    /// (0x01 = RAND, 0x02 = IEEE EUI, 0x03 = IMEI, …).
    pub ueid: Option<Vec<u8>>,

    /// Semipermanent UEIDs – `sueids` (key 257).
    /// CBOR value: map of label → bstr.
    pub sueids: Option<Value>,

    /// Hardware OEM ID – `oemid` (key 258).
    /// CBOR value: bstr or int.
    pub oem_id: Option<Value>,

    /// Hardware Model – `hwmodel` (key 259).
    /// A byte string that uniquely identifies the model within an OEM.
    pub hw_model: Option<Vec<u8>>,

    /// Hardware Version – `hwversion` (key 260).
    /// CBOR value: array \[version-string, scheme\].
    pub hw_version: Option<Value>,

    /// Uptime in seconds – `uptime` (key 261).
    pub uptime: Option<u64>,

    /// OEM Authorized Boot indicator – `oemboot` (key 262).
    /// `true` when the booted software is OEM-authorized.
    pub oem_boot: Option<bool>,

    /// Debug Status – `dbgstat` (key 263).
    /// Encoded as a uint; see RFC 9711 Section 4.2.8 for the registry.
    pub dbg_stat: Option<u64>,

    /// Geographic Location – `location` (key 264).
    /// CBOR value: map with optional latitude, longitude, altitude, …
    pub location: Option<Value>,

    /// EAT Profile – `eat_profile` (key 265).
    /// A URI or OID identifying the profile this token conforms to.
    pub eat_profile: Option<String>,

    /// Submodules Section – `submods` (key 266).
    /// CBOR value: map of submodule-name → nested-token or claims-set.
    pub submods: Option<Value>,

    /// Boot Count – `bootcount` (key 267).
    pub boot_count: Option<u64>,

    /// Boot Seed – `bootseed` (key 268).
    /// A byte string that changes on every boot; ties measurements to a
    /// single boot cycle.
    pub boot_seed: Option<Vec<u8>>,

    /// DLOAs – `dloas` (key 269).
    /// CBOR value: array of DLOA maps (Digital Letters of Approval).
    pub dloas: Option<Value>,

    /// Software Name – `swname` (key 270).
    pub sw_name: Option<String>,

    /// Software Version – `swversion` (key 271).
    /// CBOR value: array \[version-string, scheme\].
    pub sw_version: Option<Value>,

    /// Software Manifests – `manifests` (key 272).
    /// CBOR value: array of CoSWID or similar manifest structures.
    pub manifests: Option<Value>,

    /// Measurements – `measurements` (key 273).
    /// CBOR value: array of measurement maps.
    pub measurements: Option<Value>,

    /// Software Measurement Results – `measres` (key 274).
    /// CBOR value: array of measurement-result maps.
    pub meas_res: Option<Value>,

    /// Intended Use – `intuse` (key 275).
    /// Encoded as a uint; see RFC 9711 Section 4.2.20 for the registry.
    pub int_use: Option<u64>,
}

/// CBOR encoding and decoding of the claims-set.
impl EatClaimsSet {
    /// Serialise the populated fields into a CBOR map (`Value::Map`).
    ///
    /// Only `Some(…)` fields are emitted; absent claims are omitted from
    /// the encoding, consistent with RFC 9711's optional-claim model.
    pub fn to_cbor_value(&self) -> Value {
        let mut map: Vec<(Value, Value)> = Vec::new();

        macro_rules! push_int {
            ($key:expr, $val:expr) => {
                if let Some(v) = $val {
                    map.push((
                        Value::Integer(($key as i64).into()),
                        Value::Integer((v as i64).into()),
                    ));
                }
            };
        }
        macro_rules! push_bool {
            ($key:expr, $val:expr) => {
                if let Some(v) = $val {
                    map.push((Value::Integer(($key as i64).into()), Value::Bool(v)));
                }
            };
        }
        macro_rules! push_bytes {
            ($key:expr, $val:expr) => {
                if let Some(ref v) = $val {
                    map.push((
                        Value::Integer(($key as i64).into()),
                        Value::Bytes(v.clone()),
                    ));
                }
            };
        }
        macro_rules! push_text {
            ($key:expr, $val:expr) => {
                if let Some(ref v) = $val {
                    map.push((Value::Integer(($key as i64).into()), Value::Text(v.clone())));
                }
            };
        }
        macro_rules! push_raw {
            ($key:expr, $val:expr) => {
                if let Some(ref v) = $val {
                    map.push((Value::Integer(($key as i64).into()), v.clone()));
                }
            };
        }

        push_int!(EatClaimKey::Iat, self.iat);
        push_raw!(EatClaimKey::Nonce, self.nonce);
        push_bytes!(EatClaimKey::Ueid, self.ueid);
        push_raw!(EatClaimKey::Sueids, self.sueids);
        push_raw!(EatClaimKey::OemId, self.oem_id);
        push_bytes!(EatClaimKey::HwModel, self.hw_model);
        push_raw!(EatClaimKey::HwVersion, self.hw_version);
        push_int!(EatClaimKey::Uptime, self.uptime);
        push_bool!(EatClaimKey::OemBoot, self.oem_boot);
        push_int!(EatClaimKey::DbgStat, self.dbg_stat);
        push_raw!(EatClaimKey::Location, self.location);
        push_text!(EatClaimKey::EatProfile, self.eat_profile);
        push_raw!(EatClaimKey::Submods, self.submods);
        push_int!(EatClaimKey::BootCount, self.boot_count);
        push_bytes!(EatClaimKey::BootSeed, self.boot_seed);
        push_raw!(EatClaimKey::Dloas, self.dloas);
        push_text!(EatClaimKey::SwName, self.sw_name);
        push_raw!(EatClaimKey::SwVersion, self.sw_version);
        push_raw!(EatClaimKey::Manifests, self.manifests);
        push_raw!(EatClaimKey::Measurements, self.measurements);
        push_raw!(EatClaimKey::MeasRes, self.meas_res);
        push_int!(EatClaimKey::IntUse, self.int_use);

        Value::Map(map)
    }

    /// Encode the claims-set to raw CBOR bytes.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(&self.to_cbor_value(), &mut out)?;
        Ok(out)
    }

    /// Parse from a CBOR `Value::Map` representation into [`EatClaimsSet`].
    pub fn from_cbor_value(value: &Value) -> Result<Self, Box<dyn std::error::Error>> {
        let map = match value {
            Value::Map(m) => m,
            _ => return Err("Expected CBOR Map for EatClaimsSet".into()),
        };

        let mut claims = EatClaimsSet::default();

        for (k, v) in map {
            let key_int = match k {
                Value::Integer(i) => i128::from(*i) as i64,
                _ => continue,
            };

            match key_int {
                x if x == EatClaimKey::Iat as i64 => {
                    if let Value::Integer(i) = v {
                        claims.iat = Some(i128::from(*i) as i64);
                    }
                }
                x if x == EatClaimKey::Nonce as i64 => {
                    claims.nonce = Some(v.clone());
                }
                x if x == EatClaimKey::Ueid as i64 => {
                    if let Value::Bytes(b) = v {
                        claims.ueid = Some(b.clone());
                    }
                }
                x if x == EatClaimKey::Sueids as i64 => {
                    claims.sueids = Some(v.clone());
                }
                x if x == EatClaimKey::OemId as i64 => {
                    claims.oem_id = Some(v.clone());
                }
                x if x == EatClaimKey::HwModel as i64 => {
                    if let Value::Bytes(b) = v {
                        claims.hw_model = Some(b.clone());
                    }
                }
                x if x == EatClaimKey::HwVersion as i64 => {
                    claims.hw_version = Some(v.clone());
                }
                x if x == EatClaimKey::Uptime as i64 => {
                    if let Value::Integer(i) = v {
                        claims.uptime = Some(i128::from(*i) as u64);
                    }
                }
                x if x == EatClaimKey::OemBoot as i64 => {
                    if let Value::Bool(b) = v {
                        claims.oem_boot = Some(*b);
                    }
                }
                x if x == EatClaimKey::DbgStat as i64 => {
                    if let Value::Integer(i) = v {
                        claims.dbg_stat = Some(i128::from(*i) as u64);
                    }
                }
                x if x == EatClaimKey::Location as i64 => {
                    claims.location = Some(v.clone());
                }
                x if x == EatClaimKey::EatProfile as i64 => {
                    if let Value::Text(s) = v {
                        claims.eat_profile = Some(s.clone());
                    }
                }
                x if x == EatClaimKey::Submods as i64 => {
                    claims.submods = Some(v.clone());
                }
                x if x == EatClaimKey::BootCount as i64 => {
                    if let Value::Integer(i) = v {
                        claims.boot_count = Some(i128::from(*i) as u64);
                    }
                }
                x if x == EatClaimKey::BootSeed as i64 => {
                    if let Value::Bytes(b) = v {
                        claims.boot_seed = Some(b.clone());
                    }
                }
                x if x == EatClaimKey::Dloas as i64 => {
                    claims.dloas = Some(v.clone());
                }
                x if x == EatClaimKey::SwName as i64 => {
                    if let Value::Text(s) = v {
                        claims.sw_name = Some(s.clone());
                    }
                }
                x if x == EatClaimKey::SwVersion as i64 => {
                    claims.sw_version = Some(v.clone());
                }
                x if x == EatClaimKey::Manifests as i64 => {
                    claims.manifests = Some(v.clone());
                }
                x if x == EatClaimKey::Measurements as i64 => {
                    claims.measurements = Some(v.clone());
                }
                x if x == EatClaimKey::MeasRes as i64 => {
                    claims.meas_res = Some(v.clone());
                }
                x if x == EatClaimKey::IntUse as i64 => {
                    if let Value::Integer(i) = v {
                        claims.int_use = Some(i128::from(*i) as u64);
                    }
                }
                _ => {}
            }
        }

        Ok(claims)
    }

    /// Decode the claims-set from raw CBOR bytes.
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let value: Value = ciborium::de::from_reader(bytes)?;
        Self::from_cbor_value(&value)
    }

    /// Alias for [`Self::from_cbor_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Self::from_cbor_bytes(bytes)
    }
}
