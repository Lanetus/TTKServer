//! Sealing of `POST /faf` requests (see [`FafRequest`](crate::faf::FafRequest)) to the RA-TLS keys of the nodes on
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
//!   AES-256-GCM message key, and `body.key` is that key sealed to the last node. The encrypted
//!   plaintext is a [`BODY_HEADER_LEN`]-byte header (send time as big-endian Unix seconds, then a
//!   random [`MESSAGE_ID_LEN`]-byte message id) followed by the message, and the associated data
//!   binds it to `body.key`; the last node rejects stale and repeated bodies (see
//!   [`crate::replay`]), so a hop that saw a request can't have it evaluated again.
//! - **The response** of the last node is encrypted with the same message key (see
//!   [`seal_response`]), so only the client that sealed the body can read it.
//!
//! Every sealed value is base64 (standard alphabet, padded): HPKE values as the encapsulated
//! key (65-byte uncompressed P-256 point) followed by the ciphertext, and `body.message` and
//! responses as a 12-byte nonce followed by the ciphertext.

use crate::faf::FafBody;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use p256::pkcs8::DecodePrivateKey;
use rand_core::OsRng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use x509_parser::prelude::*;
use zeroize::{Zeroize, Zeroizing};

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

/// Prefix of the AES-GCM associated data of a body's message, followed by `body.key`: the
/// message only opens together with the key envelope it was sent with.
const MESSAGE_AAD_PREFIX: &[u8] = b"ttk-faf/v2 message ";

/// Length of the random id of each sealed body.
pub const MESSAGE_ID_LEN: usize = 16;
/// Length of the header in front of a body's message: 8-byte send time, then the message id.
pub const BODY_HEADER_LEN: usize = 8 + MESSAGE_ID_LEN;

/// AES-GCM associated data of a sealed response, separating it from the request message sealed
/// under the same message key.
const RESPONSE_AAD: &[u8] = b"ttk-faf/v1 response";

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
    /// Takes the key from a node's RA-TLS certificate (DER), e.g. the peer certificate of an
    /// RA-TLS connection after attesting the node.
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
        // `SecretKey` zeroizes itself on drop; so does this copy of its scalar.
        let scalar = Zeroizing::new(key.to_bytes());
        <Kem as hpke::Kem>::PrivateKey::from_bytes(&scalar)
            .map(Self)
            .map_err(|_| SealError::new("invalid P-256 private key"))
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> NodePublicKey {
        NodePublicKey(<Kem as hpke::Kem>::sk_to_pk(&self.0))
    }
}

/// The AES-256-GCM message key of a `/faf` body: chosen by the client in [`seal_body_with_key`],
/// recovered by the last node in [`open_body_with_key`], and used by both for the response.
#[derive(Clone)]
pub struct MessageKey([u8; MESSAGE_KEY_LEN]);

/// The key is erased from memory when dropped.
impl Drop for MessageKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MessageKey(..)")
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
    seal_body_with_key(last, message).map(|(body, _)| body)
}

/// Like [`seal_body`], but also returns the message key, to open the last node's response
/// with [`open_response`].
pub fn seal_body_with_key(
    last: &NodePublicKey,
    message: &[u8],
) -> Result<(FafBody, MessageKey), SealError> {
    seal_body_at(last, message, unix_now())
}

/// Like [`seal_body_with_key`], stamping the body as sent at `sent_at` (Unix seconds) instead of
/// now, e.g. to test the last node's freshness check.
pub fn seal_body_at(
    last: &NodePublicKey,
    message: &[u8],
    sent_at: u64,
) -> Result<(FafBody, MessageKey), SealError> {
    let rng = SystemRandom::new();
    let no_randomness = |_| SealError::new("no randomness available");
    let mut key = [0u8; MESSAGE_KEY_LEN];
    rng.fill(&mut key).map_err(no_randomness)?;
    let key = MessageKey(key);
    let mut message_id = [0u8; MESSAGE_ID_LEN];
    rng.fill(&mut message_id).map_err(no_randomness)?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(BODY_HEADER_LEN + message.len()));
    plaintext.extend_from_slice(&sent_at.to_be_bytes());
    plaintext.extend_from_slice(&message_id);
    plaintext.extend_from_slice(message);
    let sealed_key = hpke_seal(last, KEY_INFO, &key.0)?;
    let message = aead_seal(&key, &message_aad(&sealed_key), &plaintext)?;
    Ok((
        FafBody {
            key: sealed_key,
            message,
        },
        key,
    ))
}

/// A body opened by its last node with [`open_body_envelope`].
#[derive(Debug)]
pub struct OpenedBody {
    /// The message key, to answer with [`seal_response`].
    pub key: MessageKey,
    /// The message.
    pub message: Vec<u8>,
    /// The random id the sender gave this body.
    pub message_id: [u8; MESSAGE_ID_LEN],
    /// When the sender sealed it, in Unix seconds (the sender's clock).
    pub sent_at: u64,
}

/// Decrypts a body sealed to this node with [`seal_body`], returning the message.
pub fn open_body(node: &NodeSecretKey, body: &FafBody) -> Result<Vec<u8>, SealError> {
    open_body_envelope(node, body).map(|opened| opened.message)
}

/// Like [`open_body`], but also returns the message key, to answer with [`seal_response`].
pub fn open_body_with_key(
    node: &NodeSecretKey,
    body: &FafBody,
) -> Result<(MessageKey, Vec<u8>), SealError> {
    open_body_envelope(node, body).map(|opened| (opened.key, opened.message))
}

/// Decrypts a body sealed to this node, returning its message key, message, id and send time.
/// Freshness and uniqueness are left to the caller (see [`crate::replay::ReplayGuard`]).
pub fn open_body_envelope(node: &NodeSecretKey, body: &FafBody) -> Result<OpenedBody, SealError> {
    let undecryptable = || SealError::new("body can't be decrypted");
    let key: [u8; MESSAGE_KEY_LEN] = hpke_open(node, KEY_INFO, &body.key)?
        .try_into()
        .map_err(|_| undecryptable())?;
    let key = MessageKey(key);
    let mut plaintext =
        aead_open(&key, &message_aad(&body.key), &body.message).map_err(|_| undecryptable())?;
    if plaintext.len() < BODY_HEADER_LEN {
        return Err(undecryptable());
    }
    let message = plaintext.split_off(BODY_HEADER_LEN);
    let sent_at = u64::from_be_bytes(plaintext[..8].try_into().map_err(|_| undecryptable())?);
    let message_id = plaintext[8..].try_into().map_err(|_| undecryptable())?;
    Ok(OpenedBody {
        key,
        message,
        message_id,
        sent_at,
    })
}

/// The associated data of a body's message: [`MESSAGE_AAD_PREFIX`] followed by `sealed_key`.
fn message_aad(sealed_key: &str) -> Vec<u8> {
    [MESSAGE_AAD_PREFIX, sealed_key.as_bytes()].concat()
}

/// The current time in Unix seconds (0 if the clock is before 1970).
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Encrypts the last node's `response` under the request's message key, as base64(nonce ||
/// ciphertext).
pub fn seal_response(key: &MessageKey, response: &[u8]) -> Result<String, SealError> {
    aead_seal(key, RESPONSE_AAD, response)
}

/// Decrypts a response sealed with [`seal_response`] under the request's message key.
pub fn open_response(key: &MessageKey, sealed: &str) -> Result<Vec<u8>, SealError> {
    aead_open(key, RESPONSE_AAD, sealed)
}

/// AES-256-GCM encryption of `plaintext` under `key` and a fresh random nonce, as
/// base64(nonce || ciphertext).
fn aead_seal(key: &MessageKey, aad: &[u8], plaintext: &[u8]) -> Result<String, SealError> {
    let mut nonce = [0u8; NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| SealError::new("no randomness available"))?;
    let mut ciphertext = plaintext.to_vec();
    message_key(&key.0)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| SealError::new("message encryption failed"))?;
    let mut sealed = nonce.to_vec();
    sealed.extend_from_slice(&ciphertext);
    Ok(STANDARD.encode(sealed))
}

/// Opens a value sealed by [`aead_seal`].
fn aead_open(key: &MessageKey, aad: &[u8], sealed: &str) -> Result<Vec<u8>, SealError> {
    let undecryptable = || SealError::new("message can't be decrypted");
    let mut sealed = STANDARD
        .decode(sealed.trim())
        .map_err(|_| undecryptable())?;
    if sealed.len() < NONCE_LEN {
        return Err(undecryptable());
    }
    let mut ciphertext = sealed.split_off(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(&sealed).map_err(|_| undecryptable())?;
    let plaintext = message_key(&key.0)
        .map_err(|_| undecryptable())?
        .open_in_place(nonce, Aad::from(aad), &mut ciphertext)
        .map_err(|_| undecryptable())?;
    Ok(plaintext.to_vec())
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
