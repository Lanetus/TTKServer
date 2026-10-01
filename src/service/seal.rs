//! Sealing of `POST /faf` requests (see [`FafRequest`](super::router::FafRequest)) to the RA-TLS keys of the nodes on
//! their route, onion-style.
//!
//! Every node's RA-TLS certificate key (ECDSA P-256) is bound to its TEE Evidence, so a client
//! that has attested a node can encrypt to it with RFC 9180 HPKE in base mode, suite
//! DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM:
//!
//! - **Relay addresses** (`relays[i].address` with `encrypted: true`) are sealed to the node that
//!   reads them, i.e. the node the request is at when the entry is first in `relays`. The
//!   plaintext is `"<server> <salt>"`, e.g. `"https://server.com:443 0123456789"`, where the salt
//!   is [`SALT_DIGITS`] random decimal digits.
//! - **The body** is for the last node only: `body.message` is encrypted with a fresh
//!   AES-256-GCM message key, and `body.key` is that key sealed to the last node.
//!
//! Every sealed value is base64 (standard alphabet, padded): HPKE values as the encapsulated
//! key (65-byte uncompressed P-256 point) followed by the ciphertext, and `body.message` as a
//! 12-byte nonce followed by the ciphertext.

use super::router::FafBody;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use p256::pkcs8::DecodePrivateKey;
use rand_core::OsRng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use x509_parser::prelude::*;

/// HPKE KEM: DHKEM(P-256, HKDF-SHA256), matching the RA-TLS certificate key.
type Kem = hpke::kem::DhP256HkdfSha256;
/// HPKE KDF.
type Kdf = hpke::kdf::HkdfSha256;
/// HPKE AEAD.
type Aead = hpke::aead::AesGcm256;

/// HPKE `info` for a sealed relay address, separating it from a sealed message key.
const ADDRESS_INFO: &[u8] = b"ttk-faf/v1 relay address";
/// HPKE `info` for a sealed message key.
const KEY_INFO: &[u8] = b"ttk-faf/v1 message key";

/// Length of the encapsulated key: an uncompressed SEC1 P-256 point.
const ENCAPPED_KEY_LEN: usize = 65;
/// Length of the AES-256-GCM message key.
const MESSAGE_KEY_LEN: usize = 32;

/// Number of decimal digits in the salt that follows a sealed relay address.
pub const SALT_DIGITS: usize = 10;

/// Error sealing or opening a `/faf` value. Deliberately vague when opening, so it can't serve
/// as a decryption oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealError(String);

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SealError {}

impl SealError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// A node's public RA-TLS key, which clients seal relay addresses and message keys to.
#[derive(Clone)]
pub struct NodePublicKey(<Kem as hpke::Kem>::PublicKey);

/// Construction from the node's certificate or raw key.
impl NodePublicKey {
    /// Takes the key from a node's RA-TLS certificate (DER), e.g.
    /// [`TtkClient::peer_cert`](crate::client::TtkClient::peer_cert) after attesting the node.
    pub fn from_certificate(cert_der: &[u8]) -> Result<Self, SealError> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| SealError::new(format!("invalid certificate: {e}")))?;
        Self::from_sec1_bytes(&cert.public_key().subject_public_key.data)
    }

    /// Parses an uncompressed SEC1 P-256 point (65 bytes, starting with `0x04`).
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, SealError> {
        <Kem as hpke::Kem>::PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| SealError::new("not an uncompressed P-256 public key"))
    }
}

/// A node's private RA-TLS key, which opens what clients sealed to it. The server holds its
/// own; it never leaves the TEE.
pub struct NodeSecretKey(<Kem as hpke::Kem>::PrivateKey);

/// Construction from the RA-TLS key pair.
impl NodeSecretKey {
    /// Parses a PKCS#8 (DER) P-256 private key, as produced by `rcgen::KeyPair::serialize_der`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, SealError> {
        let key = p256::SecretKey::from_pkcs8_der(der)
            .map_err(|e| SealError::new(format!("not a PKCS#8 P-256 private key: {e}")))?;
        <Kem as hpke::Kem>::PrivateKey::from_bytes(&key.to_bytes())
            .map(Self)
            .map_err(|_| SealError::new("invalid P-256 private key"))
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> NodePublicKey {
        NodePublicKey(<Kem as hpke::Kem>::sk_to_pk(&self.0))
    }
}

/// Returns a fresh salt of [`SALT_DIGITS`] random decimal digits.
pub fn random_salt() -> Result<String, SealError> {
    let mut bytes = [0u8; 8];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| SealError::new("no randomness available"))?;
    // The modulo bias over a 64-bit value is below 2^-30.
    let salt = u64::from_be_bytes(bytes) % 10u64.pow(SALT_DIGITS as u32);
    Ok(format!("{salt:0width$}", width = SALT_DIGITS))
}

/// Seals relay address `server` (e.g. `https://server.com:443`) to `node`, the node that will
/// read it, appending a fresh salt: the plaintext is `"<server> <salt>"`.
pub fn seal_address(node: &NodePublicKey, server: &str) -> Result<String, SealError> {
    let address = format!("{} {}", server.trim(), random_salt()?);
    hpke_seal(node, ADDRESS_INFO, address.as_bytes())
}

/// Opens a relay address sealed to this node, returning `"<server> <salt>"`.
pub fn open_address(node: &NodeSecretKey, sealed: &str) -> Result<String, SealError> {
    let address = hpke_open(node, ADDRESS_INFO, sealed)?;
    String::from_utf8(address).map_err(|_| SealError::new("relay address is not UTF-8"))
}

/// Encrypts `message` for `last`, the last node of the route, under a fresh message key.
pub fn seal_body(last: &NodePublicKey, message: &[u8]) -> Result<FafBody, SealError> {
    let rng = SystemRandom::new();
    let mut key = [0u8; MESSAGE_KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut key)
        .and_then(|()| rng.fill(&mut nonce))
        .map_err(|_| SealError::new("no randomness available"))?;

    let mut ciphertext = message.to_vec();
    message_key(&key)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut ciphertext,
        )
        .map_err(|_| SealError::new("message encryption failed"))?;
    let mut sealed_message = nonce.to_vec();
    sealed_message.extend_from_slice(&ciphertext);

    Ok(FafBody {
        key: hpke_seal(last, KEY_INFO, &key)?,
        message: STANDARD.encode(sealed_message),
    })
}

/// Decrypts a body sealed to this node with [`seal_body`], returning the message.
pub fn open_body(node: &NodeSecretKey, body: &FafBody) -> Result<Vec<u8>, SealError> {
    let undecryptable = || SealError::new("body can't be decrypted");
    let key = hpke_open(node, KEY_INFO, &body.key)?;
    let mut sealed = STANDARD
        .decode(body.message.trim())
        .map_err(|_| undecryptable())?;
    if sealed.len() < NONCE_LEN {
        return Err(undecryptable());
    }
    let mut ciphertext = sealed.split_off(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(&sealed).map_err(|_| undecryptable())?;
    let message = message_key(&key)
        .map_err(|_| undecryptable())?
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| undecryptable())?;
    Ok(message.to_vec())
}

/// Builds the AES-256-GCM key for `key` bytes.
fn message_key(key: &[u8]) -> Result<LessSafeKey, SealError> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| SealError::new("invalid message key"))
}

/// HPKE base-mode single-shot seal of `plaintext` to `recipient`, as base64(enc || ciphertext).
fn hpke_seal(
    recipient: &NodePublicKey,
    info: &[u8],
    plaintext: &[u8],
) -> Result<String, SealError> {
    let (encapped, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &recipient.0,
        info,
        plaintext,
        &[],
        &mut OsRng,
    )
    .map_err(|e| SealError::new(format!("HPKE seal failed: {e}")))?;
    let mut sealed = encapped.to_bytes().to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(sealed))
}

/// Opens a value sealed by [`hpke_seal`] with this node's key.
fn hpke_open(node: &NodeSecretKey, info: &[u8], sealed: &str) -> Result<Vec<u8>, SealError> {
    let undecryptable = || SealError::new("sealed value can't be decrypted");
    let sealed = STANDARD
        .decode(sealed.trim())
        .map_err(|_| undecryptable())?;
    if sealed.len() < ENCAPPED_KEY_LEN {
        return Err(undecryptable());
    }
    let (encapped, ciphertext) = sealed.split_at(ENCAPPED_KEY_LEN);
    let encapped =
        <Kem as hpke::Kem>::EncappedKey::from_bytes(encapped).map_err(|_| undecryptable())?;
    hpke::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &node.0,
        &encapped,
        info,
        ciphertext,
        &[],
    )
    .map_err(|_| undecryptable())
}
