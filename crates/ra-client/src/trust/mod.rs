//! Trust anchors for appraising TEE Evidence (RFC 9334): the vendor roots of each attestation
//! signing chain ([`TrustStore`]).
//!
//! Pure data, with no verification logic: the [`verifier`](crate::verifier) checks Evidence
//! signatures against a [`TrustStore`] and images against an
//! [`ImageTrustStore`](crate::ImageTrustStore): for the root servers the pinned
//! [`RootSignerTrustStore`](crate::RootSignerTrustStore), for every other node the image list
//! fetched from them ([`RootImageTrustStore`](crate::images::RootImageTrustStore)).

/// AWS Nitro Enclaves root certificate (G1), from the AWS Nitro Enclaves documentation.
const AWS_NITRO_ROOT: &[u8] = include_bytes!("certs/aws_nitro_root_g1.der");
/// Mock root CA used by the server's `mock` provider. Its private key is public, so verifiers
/// must trust it only when explicitly allowed (local development).
const MOCK_NITRO_ROOT: &[u8] = ttk_core::MOCK_NITRO_ROOT_CERT;
/// Intel SGX Root CA, which also roots TDX PCK certificate chains.
const INTEL_SGX_ROOT: &[u8] = include_bytes!("certs/intel_sgx_root_ca.der");

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
    /// DER of the AMD SEV VLEK Key certificate, signed by the ARK; it signs VLEKs (the
    /// endorsement keys cloud providers such as AWS load into their chips).
    pub asvk: Vec<u8>,
}

/// Built-in AMD roots.
impl AmdRoots {
    /// ARK/ASK/ASVK certificates for Milan, Genoa and Turin, downloaded from the AMD KDS
    /// (`https://kdsintf.amd.com/vcek/v1/<product>/cert_chain` and
    /// `https://kdsintf.amd.com/vlek/v1/<product>/cert_chain`).
    pub fn builtin() -> Vec<Self> {
        vec![
            Self {
                product: AmdProduct::Milan,
                ark: include_bytes!("certs/amd_milan_ark.der").to_vec(),
                ask: include_bytes!("certs/amd_milan_ask.der").to_vec(),
                asvk: include_bytes!("certs/amd_milan_asvk.der").to_vec(),
            },
            Self {
                product: AmdProduct::Genoa,
                ark: include_bytes!("certs/amd_genoa_ark.der").to_vec(),
                ask: include_bytes!("certs/amd_genoa_ask.der").to_vec(),
                asvk: include_bytes!("certs/amd_genoa_asvk.der").to_vec(),
            },
            Self {
                product: AmdProduct::Turin,
                ark: include_bytes!("certs/amd_turin_ark.der").to_vec(),
                ask: include_bytes!("certs/amd_turin_ask.der").to_vec(),
                asvk: include_bytes!("certs/amd_turin_asvk.der").to_vec(),
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
    /// AMD root (ARK) and signing (ASK, ASVK) certificates per processor family.
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
