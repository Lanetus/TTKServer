//! Trust anchors for appraising TEE Evidence (RFC 9334): the vendor roots of each attestation
//! signing chain and the reference values (PCR0) of the accepted Nitro enclave images.
//!
//! Pure data, with no verification logic: the [`verifier`](crate::verifier)
//! checks Evidence against a [`TrustStore`], and the root node (`ttk_root`) publishes its
//! [`TrustStore::nitro_image_allowlist`].

/// AWS Nitro Enclaves root certificate (G1), from the AWS Nitro Enclaves documentation.
const AWS_NITRO_ROOT: &[u8] = include_bytes!("certs/aws_nitro_root_g1.der");
/// Mock root CA used by the server's `mock` provider. Its private key is public, so verifiers
/// must trust it only when explicitly allowed (local development).
const MOCK_NITRO_ROOT: &[u8] = ttk_core::MOCK_NITRO_ROOT_CERT;
/// Intel SGX Root CA, which also roots TDX PCK certificate chains.
const INTEL_SGX_ROOT: &[u8] = include_bytes!("certs/intel_sgx_root_ca.der");
/// PCR0 values (enclave image checksums) of the verified Nitro enclave images.
const NITRO_IMAGE_ALLOWLIST: &str = include_str!("nitro_image_allowlist.txt");

/// AMD EPYC processor families with SEV-SNP support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AmdProduct {
    /// 3rd generation EPYC.
    Milan,
    /// 4th generation EPYC.
    Genoa,
    /// 5th generation EPYC.
    Turin,
}

/// Pinned AMD certificates for one processor family.
#[derive(Debug, Clone)]
pub struct AmdRoots {
    /// The processor family these certificates belong to.
    pub product: AmdProduct,
    /// DER of the AMD Root Key certificate (self-signed).
    pub ark: Vec<u8>,
    /// DER of the AMD SEV Key certificate, signed by the ARK; it signs VCEKs.
    pub ask: Vec<u8>,
}

/// Built-in AMD roots.
impl AmdRoots {
    /// ARK/ASK pairs for Milan, Genoa and Turin, downloaded from the AMD KDS
    /// (`https://kdsintf.amd.com/vcek/v1/<product>/cert_chain`).
    pub fn builtin() -> Vec<Self> {
        vec![
            Self {
                product: AmdProduct::Milan,
                ark: include_bytes!("certs/amd_milan_ark.der").to_vec(),
                ask: include_bytes!("certs/amd_milan_ask.der").to_vec(),
            },
            Self {
                product: AmdProduct::Genoa,
                ark: include_bytes!("certs/amd_genoa_ark.der").to_vec(),
                ask: include_bytes!("certs/amd_genoa_ask.der").to_vec(),
            },
            Self {
                product: AmdProduct::Turin,
                ark: include_bytes!("certs/amd_turin_ark.der").to_vec(),
                ask: include_bytes!("certs/amd_turin_ask.der").to_vec(),
            },
        ]
    }
}

/// Trust anchors for each vendor's attestation signing chain.
#[derive(Debug, Clone)]
pub struct TrustStore {
    /// DER of the AWS Nitro Enclaves root certificate.
    pub aws_nitro_root: Vec<u8>,
    /// DER of the TTKServer mock root CA, trusted only when the verifier allows mock
    /// attestation.
    pub mock_nitro_root: Vec<u8>,
    /// DER of the Intel SGX Root CA (roots both SGX and TDX PCK chains).
    pub intel_sgx_root: Vec<u8>,
    /// AMD root (ARK) and signing (ASK) certificates per processor family.
    pub amd: Vec<AmdRoots>,
    /// PCR0 values (SHA-384 of the enclave image file) of the verified Nitro enclave images.
    /// Evidence from a non-debug Nitro enclave running any other image is rejected.
    pub nitro_image_allowlist: Vec<Vec<u8>>,
}

/// Construction of the trust store.
impl TrustStore {
    /// The vendor roots embedded in this crate, downloaded from AWS, Intel and AMD KDS, and the
    /// Nitro image allowlist in `nitro_image_allowlist.txt`.
    pub fn builtin() -> Self {
        Self {
            aws_nitro_root: AWS_NITRO_ROOT.to_vec(),
            mock_nitro_root: MOCK_NITRO_ROOT.to_vec(),
            intel_sgx_root: INTEL_SGX_ROOT.to_vec(),
            amd: AmdRoots::builtin(),
            nitro_image_allowlist: parse_image_allowlist(NITRO_IMAGE_ALLOWLIST)
                .expect("built-in nitro_image_allowlist.txt is invalid"),
        }
    }
}

/// Defaults to [`TrustStore::builtin`].
impl Default for TrustStore {
    /// Returns the built-in vendor roots.
    fn default() -> Self {
        Self::builtin()
    }
}

/// Parses a Nitro image allowlist: one PCR0 (96 hex characters, the SHA-384 of an enclave
/// image file) per line. Blank lines and text after `#` are ignored.
pub fn parse_image_allowlist(text: &str) -> Result<Vec<Vec<u8>>, String> {
    text.lines()
        .enumerate()
        .map(|(i, line)| (i + 1, line.split('#').next().unwrap_or_default().trim()))
        .filter(|(_, entry)| !entry.is_empty())
        .map(|(n, entry)| {
            decode_sha384_hex(entry).ok_or(format!(
                "line {n}: expected a PCR0 of 96 hex characters, got '{entry}'"
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
