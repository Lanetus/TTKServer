//! TTKServer core library: what the attested server (`ttk-ra-server`) and the RA-TLS client
//! (`ttk-ra-client`) share, so neither depends on the other.
//!
//! - [`eat`]: the RFC 9711 Entity Attestation Token data model carrying the Evidence.
//! - [`submod`]: EAT `submods` labels naming the TEE behind nested Evidence.
//! - [`egress`]: the egress policy for peer-chosen destinations ([`egress::classify_hop_address`]).
//! - `vsock` (Linux): QUIC datagram sockets over vsock, the enclave's only way out.
//! - The RA-TLS certificate extension OID ([`ATTESTATION_OID`]), the parent instance's vsock CID
//!   ([`PARENT_CID`]) and the mock root CA ([`MOCK_NITRO_ROOT_CERT`]).

pub mod eat;
pub mod egress;
#[cfg(target_os = "linux")]
pub mod vsock;

pub use eat::{EatClaimKey, EatClaimsSet};

/// EAT `submods` labels identifying the TEE that produced the nested evidence.
pub mod submod {
    /// AWS Nitro Enclaves attestation document.
    pub const AWS_NITRO: &str = "aws_nitro";
    /// AMD SEV-SNP attestation report and VCEK certificate.
    pub const SEV_SNP: &str = "sev_snp";
    /// Intel TDX DCAP quote.
    pub const TDX: &str = "tdx";
    /// Intel SGX DCAP quote.
    pub const SGX: &str = "sgx";
}

/// OID of the X.509 extension carrying the attestation document (placeholder, not a registered PEN).
pub const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

/// CID of the parent instance, as seen from a Nitro Enclave.
pub const PARENT_CID: u32 = 3;

/// DER of the mock root CA that signs the server's `mock` attestation documents. Its private
/// key is public, so verifiers must trust it only when mock attestation is explicitly allowed
/// (local development).
pub const MOCK_NITRO_ROOT_CERT: &[u8] = include_bytes!("mock_nitro_root.der");
