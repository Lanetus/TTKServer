//! Reference values (RFC 9334) for the accepted enclave images: the measurements that identify
//! the verified images, whatever TEE runs them.
//!
//! Defines what the root node and its clients share, with no verification logic and no
//! knowledge of any particular TEE:
//!
//! - [`ImageTrustStore`]: a source of accepted image measurements. The root node (`ttk_root`)
//!   implements it from its built-in allowlist file and publishes it at
//!   [`ROOT_ATTESTATION_PATH`]; the client (`ttk_ra_client`) implements it by fetching that list
//!   from the root servers, and its verifier rejects Evidence from images not in it.
//! - [`ImageMeasurement`]: which of a TEE's measurements a store lists (the image itself, or the
//!   key that signed it). The verifier maps it to each TEE's own field.
//! - [`RootSignerTrustStore`]: the signer measurements pinned for the root servers' own images,
//!   against which the client attests a root server before trusting its list.
//! - [`RootAttestation`]: the JSON body of `GET /root-attestation`.
//! - [`parse_image_allowlist`]: the allowlist text format (one measurement per line).

use serde::{Deserialize, Serialize};

/// Signer measurements pinned for the root servers' images.
const ROOT_SIGNER_ALLOWLIST: &str = include_str!("certs/root_signer_allowlist.txt");

/// Lengths, in bytes, of the measurement digests an allowlist may hold (SHA-256 and SHA-384).
const MEASUREMENT_LENGTHS: [usize; 2] = [32, 48];

/// Which measurement of the Evidence identifies an accepted image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ImageMeasurement {
    /// The measurement of the image itself (code and initial configuration).
    #[default]
    Image,
    /// The measurement of the key or certificate that signed the image, accepting every image
    /// it signs.
    Signer,
}

/// A source of accepted enclave images: the measurements Evidence must match.
pub trait ImageTrustStore: std::fmt::Debug + Send + Sync {
    /// The accepted images built into (or obtained by) this implementation.
    fn builtin() -> Self
    where
        Self: Sized;

    /// Accepted values of the [`measurement`](Self::measurement). Evidence from a non-debug TEE
    /// with any other value is rejected.
    fn image_allowlist(&self) -> &[Vec<u8>];

    /// Which measurement [`image_allowlist`](Self::image_allowlist) lists. Defaults to
    /// [`ImageMeasurement::Image`].
    fn measurement(&self) -> ImageMeasurement {
        ImageMeasurement::Image
    }
}

/// The root servers' images, identified by their signer rather than by the image measurement:
/// the image allowlist is what the client fetches from them.
#[derive(Debug, Clone)]
pub struct RootSignerTrustStore {
    /// Accepted signer measurements of a root server's image.
    pub signer_allowlist: Vec<Vec<u8>>,
}

/// The signer measurements built into this crate.
impl ImageTrustStore for RootSignerTrustStore {
    /// The signer measurements of `root_signer_allowlist.txt`.
    fn builtin() -> Self {
        Self {
            signer_allowlist: parse_image_allowlist(ROOT_SIGNER_ALLOWLIST)
                .expect("built-in root_signer_allowlist.txt is invalid"),
        }
    }

    /// The pinned signer measurements.
    fn image_allowlist(&self) -> &[Vec<u8>] {
        &self.signer_allowlist
    }

    /// [`ImageMeasurement::Signer`].
    fn measurement(&self) -> ImageMeasurement {
        ImageMeasurement::Signer
    }
}

/// Path of the root node's accepted-images endpoint.
pub const ROOT_ATTESTATION_PATH: &str = "/root-attestation";

/// Body of `GET /root-attestation`.
///
/// ```json
/// {
///   "measurements": ["7807833a90cc86f5…"]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootAttestation {
    /// The image measurement of each accepted enclave image, as lowercase hex.
    pub measurements: Vec<String>,
}

/// Conversion from and to an image trust store.
impl RootAttestation {
    /// The accepted enclave images of `images`.
    pub fn from_image_trust_store(images: &dyn ImageTrustStore) -> Self {
        Self {
            measurements: images
                .image_allowlist()
                .iter()
                .map(|measurement| hex_encode(measurement))
                .collect(),
        }
    }

    /// Decodes the accepted measurements, checking every entry.
    pub fn measurement_values(&self) -> Result<Vec<Vec<u8>>, String> {
        parse_image_allowlist(&self.measurements.join("\n"))
    }
}

/// Parses an image allowlist: one measurement per line, a SHA-256 or SHA-384 digest as 64 or 96
/// hex characters. Blank lines and text after `#` are ignored.
///
/// An all-zero measurement is refused: TEEs report it for debug-mode or unsigned images, so
/// listing it would accept any such enclave.
pub fn parse_image_allowlist(text: &str) -> Result<Vec<Vec<u8>>, String> {
    text.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.split('#').next().unwrap_or_default().trim()))
        .filter(|(_, entry)| !entry.is_empty())
        .map(|(n, entry)| {
            let measurement = decode_digest_hex(entry).ok_or(format!(
                "line {n}: expected a measurement of 64 or 96 hex characters, got '{entry}'"
            ))?;
            if measurement.iter().all(|b| *b == 0) {
                return Err(format!(
                    "line {n}: an all-zero measurement (debug-mode or unsigned image) is never \
                     an accepted image"
                ));
            }
            Ok(measurement)
        })
        .collect()
}

/// Decodes hex into a digest of one of the [`MEASUREMENT_LENGTHS`].
fn decode_digest_hex(hex: &str) -> Option<Vec<u8>> {
    if !MEASUREMENT_LENGTHS.iter().any(|len| hex.len() == 2 * len)
        || !hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Formats `bytes` as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
