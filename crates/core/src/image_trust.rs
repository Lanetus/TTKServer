//! Reference values (RFC 9334) for the accepted enclave images: the Nitro PCR values that
//! identify the verified enclave images.
//!
//! Defines what the root node and its clients share, with no verification logic:
//!
//! - [`ImageTrustStore`]: a source of accepted images. The root node (`ttk_root`) implements it
//!   from its built-in allowlist file and publishes it at [`ROOT_ATTESTATION_PATH`]; the client
//!   (`ttk_ra_client`) implements it by fetching that list from the root servers, and its
//!   verifier rejects Nitro Evidence from images not in it.
//! - [`RootAttestation`]: the JSON body of `GET /root-attestation`.
//! - [`parse_image_allowlist`]: the allowlist text format (one PCR per line).

use serde::{Deserialize, Serialize};

/// A source of accepted enclave images: the Nitro PCR values Evidence must match.
pub trait ImageTrustStore: std::fmt::Debug + Send + Sync {
    /// The accepted images built into (or obtained by) this implementation.
    fn builtin() -> Self
    where
        Self: Sized;

    /// Accepted values (SHA-384) of PCR [`nitro_pcr_index`](Self::nitro_pcr_index). Evidence
    /// from a non-debug Nitro enclave with any other value is rejected.
    fn nitro_image_allowlist(&self) -> &[Vec<u8>];

    /// Index of the Nitro PCR checked against the allowlist. Defaults to `0`, the SHA-384 of
    /// the enclave image file; `8` pins the image's signing certificate instead.
    fn nitro_pcr_index(&self) -> usize {
        0
    }
}

/// Path of the root node's accepted-images endpoint.
pub const ROOT_ATTESTATION_PATH: &str = "/root-attestation";

/// Hash algorithm of the checksums in a [`RootAttestation`] (Nitro PCRs).
pub const ROOT_ATTESTATION_HASH: &str = "SHA384";

/// Body of `GET /root-attestation`.
///
/// ```json
/// {
///   "hash_algorithm": "SHA384",
///   "pcr0": ["7807833a90cc86f5…"]
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootAttestation {
    /// Hash algorithm of the checksums: always [`ROOT_ATTESTATION_HASH`].
    pub hash_algorithm: String,
    /// PCR0 of each accepted enclave image (the SHA-384 of its EIF), as lowercase hex.
    pub pcr0: Vec<String>,
}

/// Conversion from and to an image trust store.
impl RootAttestation {
    /// The accepted enclave images of `images`.
    pub fn from_image_trust_store(images: &dyn ImageTrustStore) -> Self {
        Self {
            hash_algorithm: ROOT_ATTESTATION_HASH.to_string(),
            pcr0: images
                .nitro_image_allowlist()
                .iter()
                .map(|pcr0| hex_encode(pcr0))
                .collect(),
        }
    }

    /// Decodes the accepted PCR0 values, checking the hash algorithm and every entry.
    pub fn pcr0_values(&self) -> Result<Vec<Vec<u8>>, String> {
        if self.hash_algorithm != ROOT_ATTESTATION_HASH {
            return Err(format!(
                "unsupported hash algorithm '{}', expected {ROOT_ATTESTATION_HASH}",
                self.hash_algorithm
            ));
        }
        parse_image_allowlist(&self.pcr0.join("\n"))
    }
}

/// Parses a Nitro image allowlist: one PCR (96 hex characters, a SHA-384 digest) per line.
/// Blank lines and text after `#` are ignored.
pub fn parse_image_allowlist(text: &str) -> Result<Vec<Vec<u8>>, String> {
    text.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.split('#').next().unwrap_or_default().trim()))
        .filter(|(_, entry)| !entry.is_empty())
        .map(|(n, entry)| {
            decode_sha384_hex(entry).ok_or(format!(
                "line {n}: expected a PCR of 96 hex characters, got '{entry}'"
            ))
        })
        .collect()
}

/// Decodes 96 hex characters into a 48-byte SHA-384 digest.
fn decode_sha384_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() != 96 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
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
