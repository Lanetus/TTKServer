//! Test support shared by the workspace's tests (included with `#[path]`, never built into a
//! library or an enclave image): unlocks a [`Server`]'s routes by replacing its self-signed RA-TLS
//! certificate with one issued by a throwaway CA, through the same
//! [`Server::replace_certificate`] path as `POST /certificate` (see [`ttk_ra_server::router`]
//! for the route gating).

use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, IsCa, KeyPair, SanType,
};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use ttk_ra_server::certificate::CERT_DNS_NAME;
use ttk_ra_server::server::{BoxError, Server, ATTESTATION_OID};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Test-only setup of a [`Server`].
pub trait SignForTests {
    /// Generates a self-signed CA, makes it the only trusted root, issues a certificate for the
    /// RA-TLS key with the same attestation extension and installs it. Afterwards new connections
    /// get the CA-issued certificate (still accepted by RA-TLS clients) and every route but
    /// `POST /evidence` and `POST /certificate` is served. Returns the installed chain.
    fn sign_for_tests(&self) -> Result<Vec<CertificateDer<'static>>, BoxError>;
}

impl SignForTests for Server {
    fn sign_for_tests(&self) -> Result<Vec<CertificateDer<'static>>, BoxError> {
        let ca_key = KeyPair::generate()?;
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key)?;

        let current = self.certificate_chain().swap_remove(0);
        let (_, cert) = X509Certificate::from_der(&current)
            .map_err(|e| format!("malformed RA-TLS certificate: {e}"))?;
        let extension = cert
            .extensions()
            .iter()
            .find(|ext| {
                ext.oid
                    .iter()
                    .into_iter()
                    .flatten()
                    .eq(ATTESTATION_OID.iter().copied())
            })
            .ok_or("RA-TLS certificate has no attestation extension")?;

        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.subject_alt_names = vec![SanType::DnsName(CERT_DNS_NAME.try_into()?)];
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                ATTESTATION_OID,
                extension.value.to_vec(),
            ));
        let node_key = KeyPair::try_from(self.private_key_der())?;
        let leaf = params.signed_by(&node_key, &ca_cert, &ca_key)?;

        let mut roots = RootCertStore::empty();
        roots.add(ca_cert.der().clone())?;
        self.set_trusted_roots(roots)?;
        let chain = vec![leaf.der().clone()];
        self.replace_certificate(chain.clone())?;
        Ok(chain)
    }
}
