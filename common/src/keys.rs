//! Hardcoded HPKE keys for testing and development.
//!
//! These keys are used when HPKE encryption is enabled but no key files are provided.
//! In production, keys should be loaded from secure storage.

use crate::hpke::ServerKeys;
use hpke::{Deserializable, Kem as HpkeKem};

type HpkeKemType = hpke::kem::X25519HkdfSha256;

/// Aggregator's HPKE secret key (32 bytes)
pub const AGGREGATOR_SK: [u8; 32] = [
    0xd1, 0xf3, 0x99, 0x1e, 0x98, 0xc7, 0xff, 0x7c,
    0x1f, 0x44, 0x3e, 0x1a, 0x20, 0xa0, 0x0d, 0xc5,
    0xf6, 0x33, 0x9d, 0x1e, 0x78, 0xa8, 0xe1, 0xc4,
    0x19, 0xa1, 0x3f, 0xb2, 0x22, 0x91, 0x1f, 0xfe,
];

/// Aggregator's HPKE public key (32 bytes)
pub const AGGREGATOR_PK: [u8; 32] = [
    0xd4, 0xa0, 0x08, 0x7e, 0x4f, 0xee, 0xe2, 0x0c,
    0x5c, 0x06, 0x23, 0xf0, 0xf2, 0x4c, 0x08, 0x7c,
    0x37, 0x04, 0xcb, 0x83, 0xa1, 0x8d, 0xd7, 0xdd,
    0x97, 0xdc, 0x21, 0xce, 0x2c, 0xdf, 0xef, 0x68,
];

/// Decryptor's HPKE secret key (32 bytes)
pub const DECRYPTOR_SK: [u8; 32] = [
    0xf6, 0xc9, 0xe9, 0x24, 0x01, 0xf1, 0xfc, 0x10,
    0x35, 0xf3, 0xcf, 0xc9, 0xa8, 0x6d, 0x07, 0x0f,
    0xfb, 0x57, 0x68, 0x23, 0x1c, 0x8b, 0xec, 0xce,
    0xc0, 0xbd, 0x4d, 0x2d, 0x8b, 0x45, 0x20, 0x16,
];

/// Decryptor's HPKE public key (32 bytes)
pub const DECRYPTOR_PK: [u8; 32] = [
    0xd5, 0xa7, 0x5b, 0x94, 0xb0, 0x90, 0xda, 0x70,
    0x71, 0xc7, 0x1e, 0xd6, 0x38, 0xf3, 0x87, 0x23,
    0xe7, 0x11, 0x7e, 0xdc, 0x64, 0x88, 0x7d, 0xe8,
    0xa5, 0xd1, 0xe7, 0xc4, 0x3a, 0x86, 0x6f, 0x47,
];

/// Load the aggregator's HPKE keys from the embedded constants
pub fn aggregator_keys() -> ServerKeys {
    let sk = <HpkeKemType as HpkeKem>::PrivateKey::from_bytes(&AGGREGATOR_SK)
        .expect("Invalid aggregator secret key");
    let pk = <HpkeKemType as HpkeKem>::PublicKey::from_bytes(&AGGREGATOR_PK)
        .expect("Invalid aggregator public key");
    ServerKeys { sk, pk }
}

/// Load the decryptor's HPKE keys from the embedded constants
pub fn decryptor_keys() -> ServerKeys {
    let sk = <HpkeKemType as HpkeKem>::PrivateKey::from_bytes(&DECRYPTOR_SK)
        .expect("Invalid decryptor secret key");
    let pk = <HpkeKemType as HpkeKem>::PublicKey::from_bytes(&DECRYPTOR_PK)
        .expect("Invalid decryptor public key");
    ServerKeys { sk, pk }
}

/// Get aggregator's public key for clients
pub fn aggregator_public_key() -> crate::hpke::PublicKey {
    crate::hpke::PublicKey::from_bytes(&AGGREGATOR_PK)
        .expect("Invalid aggregator public key")
}

/// Get decryptor's public key for clients
pub fn decryptor_public_key() -> crate::hpke::PublicKey {
    crate::hpke::PublicKey::from_bytes(&DECRYPTOR_PK)
        .expect("Invalid decryptor public key")
}
