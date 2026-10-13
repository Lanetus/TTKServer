//! TTKServer core library: what the attested server (`ttk-ra-server`) and the RA-TLS client
//! (`ttk-ra-client`) share, so neither depends on the other.
//!
//! - [`cmw`]: the RATS Conceptual Message Wrapper carrying the Evidence.
//! - [`media_type`]: the CMW types naming the TEE behind the wrapped Evidence.
//! - [`image_trust`]: the accepted enclave images ([`ImageTrustStore`]) and the root node's
//!   `GET /root-attestation` format.
//! - [`file_message`]: the file service's `/faf` messages and replies ([`file_message::FileRequest`]).
//! - [`fresh_evidence`]: the `POST /evidence` response ([`FreshEvidence`]).
//! - [`faf`]: the `POST /faf` onion-routed request format ([`faf::FafRequest`]).
//! - [`seal`]: onion encryption of `POST /faf` requests to the nodes' RA-TLS keys (RFC 9180 HPKE).
//! - [`egress`]: the egress policy for peer-chosen destinations ([`egress::classify_hop_address`]).
//! - `vsock` (Linux): QUIC datagram sockets over vsock, the enclave's only way out.
//! - [`vsock_proxy`]: configuration of the parent-instance `vsock-proxy` binary.
//! - [`vsock_proxy_tcp`]: configuration of the parent-instance `vsock-proxy-tcp` binary.
//! - The RA-TLS certificate extension OID ([`ATTESTATION_OID`]), the parent instance's vsock CID
//!   ([`PARENT_CID`]), the mock root CA ([`MOCK_NITRO_ROOT_CERT`]), the TTK root authority
//!   ([`TTK_ROOT_CA_PEM`]) and the boxed error type ([`BoxError`]).

pub mod cmw;
pub mod egress;
pub mod faf;
pub mod file_message;
pub mod fresh_evidence;
pub mod image_trust;
pub mod seal;
#[cfg(target_os = "linux")]
pub mod vsock;
pub mod vsock_proxy;
pub mod vsock_proxy_tcp;

pub use cmw::{Cmw, CmwCollection, CmwRecord, CmwType};
pub use fresh_evidence::FreshEvidence;
pub use image_trust::ImageTrustStore;

/// Boxed error type used by the server functions (not `Send + Sync`; see `ttk_ra_server::EvalError`
/// for one that crosses `.await` in `Send` futures).
pub type BoxError = Box<dyn std::error::Error>;

/// CMW types of the TEE Evidence carried in the RA-TLS certificate and served over HTTP.
///
/// The vendor media types (`vnd.ttk.*`) are this project's own and not IANA-registered: no
/// registered types exist for these formats.
pub mod media_type {
    /// AWS Nitro Enclaves attestation document (COSE_Sign1), a record.
    pub const AWS_NITRO: &str = "application/vnd.ttk.aws-nitro-attestation-document";
    /// Intel TDX DCAP quote, a record.
    pub const TDX: &str = "application/vnd.ttk.intel-tdx-quote";
    /// Intel SGX DCAP quote, a record.
    pub const SGX: &str = "application/vnd.ttk.intel-sgx-quote";
    /// AMD SEV-SNP attestation report, the [`SEV_SNP_REPORT_LABEL`] member of an
    /// [`SEV_SNP_COLLECTION`].
    pub const SEV_SNP_REPORT: &str = "application/vnd.ttk.amd-sev-snp-report";
    /// DER X.509 certificate (RFC 2585): the VCEK, the [`SEV_SNP_VCEK_LABEL`] member of an
    /// [`SEV_SNP_COLLECTION`].
    pub const PKIX_CERT: &str = "application/pkix-cert";
    /// Collection type (RFC 4151 tag URI, not registered) of AMD SEV-SNP evidence: the report
    /// (Evidence) and the chip's VCEK certificate (Endorsement).
    pub const SEV_SNP_COLLECTION: &str = "tag:lanetus.github.io,2026:sev-snp-evidence";
    /// Label of the report in an [`SEV_SNP_COLLECTION`].
    pub const SEV_SNP_REPORT_LABEL: &str = "report";
    /// Label of the VCEK in an [`SEV_SNP_COLLECTION`].
    pub const SEV_SNP_VCEK_LABEL: &str = "vcek";
    /// Collection type (RFC 4151 tag URI, not registered) of the `POST /evidence` response:
    /// fresh Evidence and the RA-TLS certificate it is bound to (see [`crate::FreshEvidence`]).
    pub const FRESH_EVIDENCE_COLLECTION: &str = "tag:lanetus.github.io,2026:fresh-evidence";
    /// Label of the Evidence CMW in a [`FRESH_EVIDENCE_COLLECTION`].
    pub const FRESH_EVIDENCE_LABEL: &str = "evidence";
    /// Label of the DER certificate ([`PKIX_CERT`]) in a [`FRESH_EVIDENCE_COLLECTION`].
    pub const FRESH_CERTIFICATE_LABEL: &str = "certificate";
}

/// OID of the X.509 extension carrying the attestation document (placeholder, not a registered PEN).
pub const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

/// CID of the parent instance, as seen from a Nitro Enclave.
pub const PARENT_CID: u32 = 3;

/// DER of the mock root CA that signs the server's `mock` attestation documents. Its private
/// key is public, so verifiers must trust it only when mock attestation is explicitly allowed
/// (local development).
pub const MOCK_NITRO_ROOT_CERT: &[u8] = include_bytes!("mock_nitro_root.der");

/// PEM of the TTK root certificate authority: the only root a CA-issued RA-TLS certificate
/// (installed with `POST /certificate`) may chain to.
pub const TTK_ROOT_CA_PEM: &[u8] = include_bytes!("TTK_Root_CA.pem");
