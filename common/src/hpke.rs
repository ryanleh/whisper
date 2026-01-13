//! HPKE (Hybrid Public Key Encryption) module for encrypting client messages.
//!
//! This module provides HPKE-based encryption for client-to-server communication,
//! ensuring confidentiality of VDAF keys in transit.

use hpke::{
    Deserializable, OpModeR, OpModeS, Serializable,
    aead::{AeadCtxR, AeadCtxS},
    rand_core::OsRng,
    setup_receiver, setup_sender,
};
use serde::{Deserialize, Serialize};

/// Algorithm choices - using X25519 for KEM, HKDF-SHA256 for KDF, ChaCha20-Poly1305 for AEAD
pub type Kem = hpke::kem::X25519HkdfSha256;
pub type Kdf = hpke::kdf::HkdfSha256;
pub type Aead = hpke::aead::ChaCha20Poly1305;

/// Size of the encapsulated key for X25519
pub const ENCAPPED_KEY_SIZE: usize = 32;

/// HPKE envelope containing the encapsulated key and ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeEnvelope {
    /// Encapsulated symmetric key (32 bytes for X25519)
    pub enc: Vec<u8>,
    /// Encrypted data (ciphertext + authentication tag)
    pub ct: Vec<u8>,
}

/// A batch of keys that may be plaintext or HPKE-encrypted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyBatch {
    /// Plaintext keys (when HPKE is disabled)
    Plain(Vec<Vec<u8>>),
    /// HPKE-encrypted keys
    Encrypted(Vec<HpkeEnvelope>),
}

impl KeyBatch {
    /// Decrypt the batch if encrypted, or return plaintext keys directly
    pub fn decrypt(&self, server_keys: Option<&ServerKeys>) -> Result<Vec<Vec<u8>>, HpkeError> {
        match self {
            KeyBatch::Plain(keys) => Ok(keys.clone()),
            KeyBatch::Encrypted(envelopes) => {
                let keys = server_keys
                    .ok_or_else(|| HpkeError::SetupError("No HPKE keys provided for decryption".to_string()))?;
                envelopes
                    .iter()
                    .map(|envelope| decrypt_message(keys, envelope))
                    .collect()
            }
        }
    }
    
    /// Returns the number of keys in the batch
    pub fn len(&self) -> usize {
        match self {
            KeyBatch::Plain(keys) => keys.len(),
            KeyBatch::Encrypted(envelopes) => envelopes.len(),
        }
    }
    
    /// Returns true if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    
    /// Returns true if the batch is encrypted
    pub fn is_encrypted(&self) -> bool {
        matches!(self, KeyBatch::Encrypted(_))
    }
}

impl HpkeEnvelope {
    /// Returns the total size of the envelope in bytes
    pub fn size(&self) -> usize {
        self.enc.len() + self.ct.len()
    }

    /// Serialize the envelope to bytes (length-prefixed format)
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("HpkeEnvelope serialization should not fail")
    }

    /// Deserialize the envelope from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        bincode::deserialize(bytes).map_err(|e| HpkeError::DeserializationError(e.to_string()))
    }
}

/// Server key pair for HPKE decryption
#[derive(Clone)]
pub struct ServerKeys {
    pub sk: <Kem as hpke::Kem>::PrivateKey,
    pub pk: <Kem as hpke::Kem>::PublicKey,
}

impl ServerKeys {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let (sk, pk) = <Kem as hpke::Kem>::gen_keypair(&mut OsRng);
        Self { sk, pk }
    }

    /// Get the public key as bytes (for sharing with clients)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes().to_vec()
    }

    /// Get a reference to the public key
    pub fn public_key(&self) -> &<Kem as hpke::Kem>::PublicKey {
        &self.pk
    }

    /// Get a reference to the private key
    pub fn private_key(&self) -> &<Kem as hpke::Kem>::PrivateKey {
        &self.sk
    }

    /// Serialize keys to bytes for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let sk_bytes = self.sk.to_bytes();
        let pk_bytes = self.pk.to_bytes();
        let mut result = Vec::with_capacity(sk_bytes.len() + pk_bytes.len());
        result.extend_from_slice(&sk_bytes);
        result.extend_from_slice(&pk_bytes);
        result
    }

    /// Deserialize keys from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        // X25519 private key is 32 bytes, public key is 32 bytes
        if bytes.len() != 64 {
            return Err(HpkeError::InvalidKeyLength(bytes.len()));
        }
        let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(&bytes[..32])
            .map_err(|e| HpkeError::KeyDeserializationError(format!("{:?}", e)))?;
        let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&bytes[32..])
            .map_err(|e| HpkeError::KeyDeserializationError(format!("{:?}", e)))?;
        Ok(Self { sk, pk })
    }

    /// Write keys to a file
    pub fn write_to_file(&self, path: &str) -> std::io::Result<()> {
        let bytes = self.to_bytes();
        std::fs::write(path, bytes)
    }

    /// Read keys from a file
    pub fn read_from_file(path: &str) -> Result<Self, HpkeError> {
        let bytes = std::fs::read(path).map_err(HpkeError::IoError)?;
        Self::from_bytes(&bytes)
    }
}

/// Public key only (for clients)
#[derive(Clone)]
pub struct PublicKey {
    pub pk: <Kem as hpke::Kem>::PublicKey,
}

impl PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(bytes)
            .map_err(|e| HpkeError::KeyDeserializationError(format!("{:?}", e)))?;
        Ok(Self { pk })
    }

    /// Get as bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.pk.to_bytes().to_vec()
    }

    /// Read from a file (expects just the 32-byte public key)
    pub fn read_from_file(path: &str) -> Result<Self, HpkeError> {
        let bytes = std::fs::read(path).map_err(HpkeError::IoError)?;
        Self::from_bytes(&bytes)
    }

    /// Write to a file
    pub fn write_to_file(&self, path: &str) -> std::io::Result<()> {
        std::fs::write(path, self.to_bytes())
    }
}

/// HPKE-specific errors
#[derive(Debug)]
pub enum HpkeError {
    SetupError(String),
    SealingError(String),
    OpeningError(String),
    DeserializationError(String),
    KeyDeserializationError(String),
    InvalidKeyLength(usize),
    IoError(std::io::Error),
}

impl std::fmt::Display for HpkeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HpkeError::SetupError(e) => write!(f, "HPKE setup error: {}", e),
            HpkeError::SealingError(e) => write!(f, "HPKE sealing error: {}", e),
            HpkeError::OpeningError(e) => write!(f, "HPKE opening error: {}", e),
            HpkeError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            HpkeError::KeyDeserializationError(e) => write!(f, "Key deserialization error: {}", e),
            HpkeError::InvalidKeyLength(len) => write!(f, "Invalid key length: {}", len),
            HpkeError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for HpkeError {}

/// Encrypt plaintext using HPKE
///
/// # Arguments
/// * `public_key` - The recipient's public key
/// * `plaintext` - The data to encrypt
/// * `info` - Context info for key derivation (can be empty)
/// * `aad` - Additional authenticated data (can be empty)
///
/// # Returns
/// The HPKE envelope containing the encapsulated key and ciphertext,
/// along with the sender context for optional follow-up encryptions.
pub fn hpke_encrypt(
    public_key: &<Kem as hpke::Kem>::PublicKey,
    plaintext: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<(HpkeEnvelope, AeadCtxS<Aead, Kdf, Kem>), HpkeError> {
    let (enc, mut sender_ctx) =
        setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, public_key, info, &mut OsRng)
            .map_err(|e| HpkeError::SetupError(format!("{:?}", e)))?;

    let ct = sender_ctx
        .seal(plaintext, aad)
        .map_err(|e| HpkeError::SealingError(format!("{:?}", e)))?;

    Ok((
        HpkeEnvelope {
            enc: enc.to_bytes().to_vec(),
            ct,
        },
        sender_ctx,
    ))
}

/// Decrypt an HPKE envelope
///
/// # Arguments
/// * `server_sk` - The server's private key
/// * `envelope` - The HPKE envelope to decrypt
/// * `info` - Context info (must match what was used during encryption)
/// * `aad` - Additional authenticated data (must match what was used during encryption)
///
/// # Returns
/// The decrypted plaintext and the receiver context for optional follow-up decryptions.
pub fn hpke_decrypt(
    server_sk: &<Kem as hpke::Kem>::PrivateKey,
    envelope: &HpkeEnvelope,
    info: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, AeadCtxR<Aead, Kdf, Kem>), HpkeError> {
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&envelope.enc)
        .map_err(|e| HpkeError::DeserializationError(format!("{:?}", e)))?;

    let mut receiver_ctx = setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, server_sk, &enc, info)
        .map_err(|e| HpkeError::SetupError(format!("{:?}", e)))?;

    let plaintext = receiver_ctx
        .open(&envelope.ct, aad)
        .map_err(|e| HpkeError::OpeningError(format!("{:?}", e)))?;

    Ok((plaintext, receiver_ctx))
}

/// Encrypt using an existing sender context (for session continuity)
pub fn hpke_encrypt_with_context(
    sender_ctx: &mut AeadCtxS<Aead, Kdf, Kem>,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    sender_ctx
        .seal(plaintext, aad)
        .map_err(|e| HpkeError::SealingError(format!("{:?}", e)))
}

/// Decrypt using an existing receiver context (for session continuity)
pub fn hpke_decrypt_with_context(
    receiver_ctx: &mut AeadCtxR<Aead, Kdf, Kem>,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, HpkeError> {
    receiver_ctx
        .open(ciphertext, aad)
        .map_err(|e| HpkeError::OpeningError(format!("{:?}", e)))
}

/// Simple one-shot encryption with a public key (convenience function)
pub fn encrypt_message(public_key: &PublicKey, plaintext: &[u8]) -> Result<HpkeEnvelope, HpkeError> {
    let (envelope, _) = hpke_encrypt(&public_key.pk, plaintext, b"", b"")?;
    Ok(envelope)
}

/// Simple one-shot decryption with server keys (convenience function)
pub fn decrypt_message(server_keys: &ServerKeys, envelope: &HpkeEnvelope) -> Result<Vec<u8>, HpkeError> {
    let (plaintext, _) = hpke_decrypt(&server_keys.sk, envelope, b"", b"")?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encrypt_decrypt() {
        let server_keys = ServerKeys::generate();
        let plaintext = b"Hello, HPKE!";
        let info = b"test-info";
        let aad = b"test-aad";

        // Encrypt
        let (envelope, _sender_ctx) =
            hpke_encrypt(&server_keys.pk, plaintext, info, aad).expect("Encryption should succeed");

        // Decrypt
        let (decrypted, _receiver_ctx) =
            hpke_decrypt(&server_keys.sk, &envelope, info, aad).expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_server_keys_serialization() {
        let server_keys = ServerKeys::generate();
        let bytes = server_keys.to_bytes();
        let restored = ServerKeys::from_bytes(&bytes).expect("Should deserialize");
        
        // Test that the restored keys work
        let plaintext = b"test message";
        let (envelope, _) = hpke_encrypt(&server_keys.pk, plaintext, b"", b"")
            .expect("Encryption should succeed");
        let (decrypted, _) = hpke_decrypt(&restored.sk, &envelope, b"", b"")
            .expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_public_key_only() {
        let server_keys = ServerKeys::generate();
        let pk_bytes = server_keys.public_key_bytes();
        let public_key = PublicKey::from_bytes(&pk_bytes).expect("Should parse public key");
        
        // Encrypt with public key
        let plaintext = b"secret data";
        let envelope = encrypt_message(&public_key, plaintext).expect("Encryption should succeed");
        
        // Decrypt with server keys
        let decrypted = decrypt_message(&server_keys, &envelope).expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_plaintext() {
        let server_keys = ServerKeys::generate();
        let plaintext: Vec<u8> = (0..10000u32).map(|i| (i % 256) as u8).collect();

        let (envelope, _) = hpke_encrypt(&server_keys.pk, &plaintext, b"", b"")
            .expect("Encryption should succeed");
        let (decrypted, _) = hpke_decrypt(&server_keys.sk, &envelope, b"", b"")
            .expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_private_key() {
        let server_keys1 = ServerKeys::generate();
        let server_keys2 = ServerKeys::generate();
        let plaintext = b"secret message";

        let (envelope, _) = hpke_encrypt(&server_keys1.pk, plaintext, b"", b"")
            .expect("Encryption should succeed");

        // Try to decrypt with wrong key
        let result = hpke_decrypt(&server_keys2.sk, &envelope, b"", b"");
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_envelope_serialization() {
        let server_keys = ServerKeys::generate();
        let plaintext = b"test data";
        
        let (envelope, _) = hpke_encrypt(&server_keys.pk, plaintext, b"", b"")
            .expect("Encryption should succeed");
        
        // Serialize and deserialize the envelope
        let bytes = envelope.to_bytes();
        let restored = HpkeEnvelope::from_bytes(&bytes).expect("Should deserialize");
        
        // Decrypt the restored envelope
        let (decrypted, _) = hpke_decrypt(&server_keys.sk, &restored, b"", b"")
            .expect("Decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }
}
