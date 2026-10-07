//! Trust anchors for appraising TEE Evidence (RFC 9334): the vendor roots of each attestation
//! signing chain ([`TrustStore`]) and the PCR8 values pinned for the root servers
//! ([`RootSignerTrustStore`]).
//!
//! Pure data, with no verification logic: the [`verifier`](crate::verifier) checks Evidence
//! signatures against a [`TrustStore`] and Nitro images against an [`ImageTrustStore`]: for
//! the root servers a [`RootSignerTrustStore`], for every other node the image list fetched
//! from them ([`RootImageTrustStore`](crate::images::RootImageTrustStore)).

/// AWS Nitro Enclaves root certificate (G1), from the AWS Nitro Enclaves documentation.
const AWS_NITRO_ROOT: &[u8] = include_bytes!("certs/aws_nitro_root_g1.der");
/// Mock root CA used by the server's `mock` provider. Its private key is public, so verifiers
/// must trust it only when explicitly allowed (local development).
const MOCK_NITRO_ROOT: &[u8] = ttk_core::MOCK_NITRO_ROOT_CERT;
/// Intel SGX Root CA, which also roots TDX PCK certificate chains.
const INTEL_SGX_ROOT: &[u8] = include_bytes!("certs/intel_sgx_root_ca.der");
/// PCR8 values (signing certificate hashes) pinned for the root servers' enclave images.
const ROOT_SIGNER_PCR8: &str = include_str!("root_signer_pcr8.txt");

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
}

/// Construction of the trust store.
impl TrustStore {
    /// The vendor roots embedded in this crate, downloaded from AWS, Intel and AMD KDS.
    pub fn builtin() -> Self {
        Self {
            aws_nitro_root: AWS_NITRO_ROOT.to_vec(),
            mock_nitro_root: MOCK_NITRO_ROOT.to_vec(),
            intel_sgx_root: INTEL_SGX_ROOT.to_vec(),
            amd: AmdRoots::builtin(),
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

/// The accepted-images interface and the allowlist parser (defined in
/// [`ttk_core::image_trust`]).
pub use ttk_core::image_trust::{parse_image_allowlist, ImageTrustStore};

/// The root servers' enclave images, identified by PCR8 (the SHA-384 of the certificate that
/// signed the image) rather than PCR0: the PCR0 allowlist is what the client fetches from them.
#[derive(Debug, Clone)]
pub struct RootSignerTrustStore {
    /// Accepted PCR8 values of a root server's enclave image.
    pub pcr8_allowlist: Vec<Vec<u8>>,
}

/// The PCR8 values built into this crate.
impl ImageTrustStore for RootSignerTrustStore {
    /// The PCR8 values of `root_signer_pcr8.txt`.
    fn builtin() -> Self {
        Self {
            pcr8_allowlist: parse_image_allowlist(ROOT_SIGNER_PCR8)
                .expect("built-in root_signer_pcr8.txt is invalid"),
        }
    }

    /// The pinned PCR8 values.
    fn nitro_image_allowlist(&self) -> &[Vec<u8>] {
        &self.pcr8_allowlist
    }

    /// PCR8: the image's signing certificate.
    fn nitro_pcr_index(&self) -> usize {
        8
    }
}
