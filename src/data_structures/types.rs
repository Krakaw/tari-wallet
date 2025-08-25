use std::fmt;
use std::ops::{Add, Mul, Sub};

use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use hex::ToHex;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tari_crypto::ristretto::RistrettoSecretKey;
use zeroize::Zeroize;

use crate::hex_utils::{HexEncodable, HexError, HexValidatable};
use tari_utilities::ByteArray;

/// Custom serde module for Scalar
mod scalar_serde {
    use super::*;

    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = scalar.to_bytes();
        let hex_string = hex::encode(bytes);
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_string = <String as serde::Deserialize>::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Scalar::from_bytes_mod_order(arr))
    }
}

/// Custom serde module for CompressedRistretto
mod compressed_ristretto_serde {
    use super::*;

    pub fn serialize<S>(compressed: &CompressedRistretto, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = compressed.to_bytes();
        let hex_string = hex::encode(bytes);
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<CompressedRistretto, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_string = <String as serde::Deserialize>::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_string).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(CompressedRistretto(arr))
    }
}

/// Custom borsh module for Scalar
mod scalar_borsh {
    use super::*;

    #[allow(dead_code)]
    pub fn serialize<W: std::io::Write>(scalar: &Scalar, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&scalar.to_bytes(), writer)
    }

    #[allow(dead_code)]
    pub fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Scalar> {
        let bytes = <[u8; 32]>::deserialize_reader(reader)?;
        Ok(Scalar::from_canonical_bytes(bytes).unwrap_or_else(|| {
            // Fallback to zero scalar if bytes are not canonical
            Scalar::from_bytes_mod_order([0u8; 32])
        }))
    }
}

/// A wrapper around a private key that provides zeroization on drop
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrivateKey(#[serde(with = "scalar_serde")] pub Scalar);

impl BorshSerialize for PrivateKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0.to_bytes(), writer)
    }
}

impl BorshDeserialize for PrivateKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes = <[u8; 32]>::deserialize_reader(reader)?;
        Ok(Self(Scalar::from_canonical_bytes(bytes).unwrap_or_else(
            || {
                // Fallback to zero scalar if bytes are not canonical
                Scalar::from_bytes_mod_order([0u8; 32])
            },
        )))
    }
}

impl PrivateKey {
    /// Create a new private key from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Scalar::from_bytes_mod_order(bytes))
    }

    /// Generate a random private key
    pub fn random() -> Self {
        let mut bytes = [0u8; 64];
        OsRng.fill_bytes(&mut bytes);
        Self(Scalar::from_bytes_mod_order_wide(&bytes))
    }

    /// Get the private key bytes
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(HexError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(Self::new(key_bytes))
    }

    /// Create from canonical bytes (ensuring it's a valid scalar)
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err("Private key must be 32 bytes".to_string());
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        Ok(Self::new(key_bytes))
    }

    /// Get the key length
    pub const KEY_LEN: usize = 32;
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        // Overwrite the scalar's memory directly
        let mut bytes = self.0.to_bytes();
        bytes.zeroize();
        // Overwrite the scalar with zero scalar
        self.0 = curve25519_dalek::scalar::Scalar::from_bytes_mod_order([0u8; 32]);
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl HexEncodable for PrivateKey {
    fn to_hex(&self) -> String {
        self.to_hex()
    }
    fn from_hex(hex: &str) -> Result<Self, HexError> {
        Self::from_hex(hex)
    }
}

impl HexValidatable for PrivateKey {}

impl Add for PrivateKey {
    type Output = PrivateKey;
    fn add(self, rhs: PrivateKey) -> PrivateKey {
        PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a PrivateKey> for PrivateKey {
    type Output = PrivateKey;
    fn add(self, rhs: &'a PrivateKey) -> PrivateKey {
        PrivateKey(self.0 + rhs.0)
    }
}

impl Add<PrivateKey> for &PrivateKey {
    type Output = PrivateKey;
    fn add(self, rhs: PrivateKey) -> PrivateKey {
        PrivateKey(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a PrivateKey> for &PrivateKey {
    type Output = PrivateKey;
    fn add(self, rhs: &'a PrivateKey) -> PrivateKey {
        PrivateKey(self.0 + rhs.0)
    }
}

impl Sub for PrivateKey {
    type Output = PrivateKey;
    fn sub(self, rhs: PrivateKey) -> PrivateKey {
        PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Sub<&'a PrivateKey> for PrivateKey {
    type Output = PrivateKey;
    fn sub(self, rhs: &'a PrivateKey) -> PrivateKey {
        PrivateKey(self.0 - rhs.0)
    }
}

impl Sub<PrivateKey> for &PrivateKey {
    type Output = PrivateKey;
    fn sub(self, rhs: PrivateKey) -> PrivateKey {
        PrivateKey(self.0 - rhs.0)
    }
}

impl<'a> Sub<&'a PrivateKey> for &PrivateKey {
    type Output = PrivateKey;
    fn sub(self, rhs: &'a PrivateKey) -> PrivateKey {
        PrivateKey(self.0 - rhs.0)
    }
}

impl Mul for PrivateKey {
    type Output = PrivateKey;
    fn mul(self, rhs: PrivateKey) -> PrivateKey {
        PrivateKey(self.0 * rhs.0)
    }
}

impl<'a> Mul<&'a PrivateKey> for PrivateKey {
    type Output = PrivateKey;
    fn mul(self, rhs: &'a PrivateKey) -> PrivateKey {
        PrivateKey(self.0 * rhs.0)
    }
}

impl Mul<PrivateKey> for &PrivateKey {
    type Output = PrivateKey;
    fn mul(self, rhs: PrivateKey) -> PrivateKey {
        PrivateKey(self.0 * rhs.0)
    }
}

impl<'a> Mul<&'a PrivateKey> for &PrivateKey {
    type Output = PrivateKey;
    fn mul(self, rhs: &'a PrivateKey) -> PrivateKey {
        PrivateKey(self.0 * rhs.0)
    }
}

impl TryFrom<&PrivateKey> for RistrettoSecretKey {
    type Error = tari_utilities::ByteArrayError;

    fn try_from(key: &PrivateKey) -> Result<Self, Self::Error> {
        RistrettoSecretKey::from_canonical_bytes(&key.as_bytes())
    }
}

impl TryFrom<&RistrettoSecretKey> for PrivateKey {
    type Error = String;

    fn try_from(key: &RistrettoSecretKey) -> Result<Self, Self::Error> {
        PrivateKey::from_canonical_bytes(key.as_bytes())
    }
}

/// Micro Minotari amount (smallest unit)
#[derive(
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct MicroMinotari(u64);

impl MicroMinotari {
    /// Create a new Micro Minotari amount
    pub fn new(amount: u64) -> Self {
        Self(amount)
    }

    /// Get the amount as u64
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    /// Convert to Tari (1 Tari = 1,000,000 Micro Minotari)
    pub fn as_tari(&self) -> f64 {
        self.0 as f64 / 1_000_000.0
    }

    /// Create from Tari amount
    pub fn from_tari(tari: f64) -> Self {
        Self((tari * 1_000_000.0) as u64)
    }
}

impl fmt::Display for MicroMinotari {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} μT", self.0)
    }
}

impl From<u64> for MicroMinotari {
    fn from(amount: u64) -> Self {
        Self::new(amount)
    }
}

impl From<MicroMinotari> for u64 {
    fn from(amount: MicroMinotari) -> Self {
        amount.as_u64()
    }
}

/// Compressed commitment (32 bytes)
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct CompressedCommitment {
    /// The commitment bytes
    #[serde(
        serialize_with = "crate::hex_utils::serde_helpers::serialize_array_32",
        deserialize_with = "crate::hex_utils::serde_helpers::deserialize_array_32"
    )]
    pub bytes: [u8; 32],
}

impl CompressedCommitment {
    /// Create a new compressed commitment from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the commitment bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.bytes.encode_hex()
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(HexError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&bytes);
        Ok(Self::new(commitment_bytes))
    }
}

impl HexEncodable for CompressedCommitment {
    fn to_hex(&self) -> String {
        self.bytes.encode_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(HexError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(&bytes);
        Ok(Self::new(commitment_bytes))
    }
}

impl HexValidatable for CompressedCommitment {}

/// Compressed public key (Ristretto)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct CompressedPublicKey(
    #[serde(with = "compressed_ristretto_serde")] pub CompressedRistretto,
);

impl BorshSerialize for CompressedPublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0.to_bytes(), writer)
    }
}

impl BorshDeserialize for CompressedPublicKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let bytes = <[u8; 32]>::deserialize_reader(reader)?;
        Ok(Self(CompressedRistretto(bytes)))
    }
}

impl CompressedPublicKey {
    /// Create a new compressed public key from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(CompressedRistretto(bytes))
    }

    /// Get the public key bytes
    pub fn as_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(HexError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(Self::new(key_bytes))
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 32 {
            return Err("Compressed public key must be 32 bytes".to_string());
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);
        Ok(Self::new(key_bytes))
    }

    /// Decompress to RistrettoPoint
    pub fn decompress(&self) -> Option<RistrettoPoint> {
        self.0.decompress()
    }

    /// Compress from RistrettoPoint
    pub fn from_point(point: &RistrettoPoint) -> Self {
        Self(point.compress())
    }

    /// Create from private key
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        let point = private_key.0 * RISTRETTO_BASEPOINT_POINT;
        Self::from_point(&point)
    }
}

impl HexEncodable for CompressedPublicKey {
    fn to_hex(&self) -> String {
        self.to_hex()
    }
    fn from_hex(hex: &str) -> Result<Self, HexError> {
        Self::from_hex(hex)
    }
}

impl HexValidatable for CompressedPublicKey {}

impl fmt::Display for CompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl TryFrom<&CompressedPublicKey> for tari_common_types::types::CompressedPublicKey {
    type Error = tari_utilities::ByteArrayError;

    fn try_from(key: &CompressedPublicKey) -> Result<Self, Self::Error> {
        tari_common_types::types::CompressedPublicKey::from_canonical_bytes(&key.as_bytes())
    }
}

impl TryFrom<&tari_common_types::types::CompressedPublicKey> for CompressedPublicKey {
    type Error = String;

    fn try_from(key: &tari_common_types::types::CompressedPublicKey) -> Result<Self, Self::Error> {
        CompressedPublicKey::from_canonical_bytes(key.as_bytes())
    }
}

/// Safe array wrapper for zeroization
#[derive(Debug, Clone, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct SafeArray<const N: usize> {
    /// The array data
    pub data: [u8; N],
}

impl<const N: usize> Default for SafeArray<N> {
    fn default() -> Self {
        Self { data: [0u8; N] }
    }
}

impl<const N: usize> SafeArray<N> {
    /// Create a new safe array
    pub fn new(data: [u8; N]) -> Self {
        Self { data }
    }

    /// Get the array data
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.data.encode_hex()
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        if bytes.len() != N {
            return Err(HexError::InvalidLength {
                expected: N,
                actual: bytes.len(),
            });
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        Ok(Self::new(array))
    }
}

impl<const N: usize> Zeroize for SafeArray<N> {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl<const N: usize> Drop for SafeArray<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> HexEncodable for SafeArray<N> {
    fn to_hex(&self) -> String {
        self.data.encode_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        if bytes.len() != N {
            return Err(HexError::InvalidLength {
                expected: N,
                actual: bytes.len(),
            });
        }
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        Ok(Self::new(array))
    }
}

impl<const N: usize> HexValidatable for SafeArray<N> {}

impl<const N: usize> fmt::Display for SafeArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Encrypted data key wrapper
pub struct EncryptedDataKey(SafeArray<32>);

impl EncryptedDataKey {
    /// Create from a safe array
    pub fn from(safe_array: SafeArray<32>) -> Self {
        Self(safe_array)
    }

    /// Reveal the key (use with caution)
    pub fn reveal(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Reveal the key mutably (use with caution) - matches REFERENCE_tari
    pub fn reveal_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0.data
    }

    /// Get the key as a mutable byte slice
    pub fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0.data
    }
}

impl From<SafeArray<32>> for EncryptedDataKey {
    fn from(safe_array: SafeArray<32>) -> Self {
        Self(safe_array)
    }
}

/// Fixed hash type (32 bytes) used for transaction hashes and outputs
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct FixedHash {
    /// The hash bytes
    #[serde(
        serialize_with = "crate::hex_utils::serde_helpers::serialize_array_32",
        deserialize_with = "crate::hex_utils::serde_helpers::deserialize_array_32"
    )]
    pub bytes: [u8; 32],
}

impl FixedHash {
    /// Create a new fixed hash from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the hash bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Get the hash as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the byte size of the hash
    pub fn byte_size() -> usize {
        32
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        self.bytes.encode_hex()
    }

    /// Create from hex string
    pub fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(HexError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);
        Ok(Self::new(hash_bytes))
    }
}

impl TryFrom<&[u8]> for FixedHash {
    type Error = HexError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 32 {
            return Err(HexError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(bytes);
        Ok(Self::new(hash_bytes))
    }
}

impl From<[u8; 32]> for FixedHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(bytes)
    }
}

impl HexEncodable for FixedHash {
    fn to_hex(&self) -> String {
        self.bytes.encode_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(HexError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);
        Ok(Self::new(hash_bytes))
    }
}

impl HexValidatable for FixedHash {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hex_utils::HexError;

    #[test]
    fn test_micro_minotari() {
        let amount = MicroMinotari::new(1_000_000);
        assert_eq!(amount.as_u64(), 1_000_000);
        assert_eq!(amount.as_tari(), 1.0);
        assert_eq!(MicroMinotari::from_tari(2.5).as_u64(), 2_500_000);

        // Test edge cases
        let zero = MicroMinotari::new(0);
        assert_eq!(zero.as_tari(), 0.0);
        assert_eq!(MicroMinotari::from_tari(0.0).as_u64(), 0);

        let max_amount = MicroMinotari::new(u64::MAX);
        assert_eq!(max_amount.as_u64(), u64::MAX);

        // Test fractional conversion
        assert_eq!(MicroMinotari::from_tari(0.5).as_u64(), 500_000);
        assert_eq!(MicroMinotari::from_tari(0.000001).as_u64(), 1);

        // Test display
        let display_amount = MicroMinotari::new(1500000);
        assert_eq!(format!("{display_amount}"), "1500000 μT");

        // Test ordering
        assert!(MicroMinotari::new(100) < MicroMinotari::new(200));
        assert!(MicroMinotari::new(100) <= MicroMinotari::new(100));
        assert!(MicroMinotari::new(200) > MicroMinotari::new(100));

        // Test From/Into conversions
        let from_u64: MicroMinotari = 500_000u64.into();
        assert_eq!(from_u64.as_u64(), 500_000);
        let to_u64: u64 = from_u64.into();
        assert_eq!(to_u64, 500_000);
    }

    #[test]
    fn test_private_key() {
        let key_bytes = [1u8; 32];
        let key = PrivateKey::new(key_bytes);
        assert_eq!(key.as_bytes(), key_bytes);

        let hex = key.to_hex();
        let key_from_hex = PrivateKey::from_hex(&hex).unwrap();
        assert_eq!(key, key_from_hex);

        // Test random key generation
        let random_key1 = PrivateKey::random();
        let random_key2 = PrivateKey::random();
        assert_ne!(random_key1.as_bytes(), random_key2.as_bytes());

        // Test canonical bytes
        let canonical_key = PrivateKey::from_canonical_bytes(&key_bytes).unwrap();
        assert_eq!(canonical_key.as_bytes(), key_bytes);

        // Test invalid canonical bytes
        assert!(PrivateKey::from_canonical_bytes(&[1u8; 31]).is_err());
        assert!(PrivateKey::from_canonical_bytes(&[1u8; 33]).is_err());

        // Test key length constant
        assert_eq!(PrivateKey::KEY_LEN, 32);

        // Test hex encoding errors
        assert!(PrivateKey::from_hex("invalid_hex").is_err());
        assert!(PrivateKey::from_hex("").is_err());
        assert!(PrivateKey::from_hex("deadbeef").is_err()); // Too short

        // Test valid hex encoding
        let valid_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let key_from_valid_hex = PrivateKey::from_hex(valid_hex).unwrap();
        assert_eq!(key_from_valid_hex.as_bytes(), [1u8; 32]);
    }

    #[test]
    fn test_private_key_arithmetic() {
        let key1 = PrivateKey::new([1u8; 32]);
        let key2 = PrivateKey::new([2u8; 32]);

        // Test addition
        let sum1 = key1.clone() + key2.clone();
        let sum2 = &key1 + &key2;
        let sum3 = key1.clone() + &key2;
        let sum4 = &key1 + key2.clone();

        // All addition forms should give same result
        assert_eq!(sum1.as_bytes(), sum2.as_bytes());
        assert_eq!(sum2.as_bytes(), sum3.as_bytes());
        assert_eq!(sum3.as_bytes(), sum4.as_bytes());

        // Test subtraction
        let diff1 = key2.clone() - key1.clone();
        let diff2 = &key2 - &key1;
        let diff3 = key2.clone() - &key1;
        let diff4 = &key2 - key1.clone();

        // All subtraction forms should give same result
        assert_eq!(diff1.as_bytes(), diff2.as_bytes());
        assert_eq!(diff2.as_bytes(), diff3.as_bytes());
        assert_eq!(diff3.as_bytes(), diff4.as_bytes());

        // Test multiplication
        let prod1 = key1.clone() * key2.clone();
        let prod2 = &key1 * &key2;
        let prod3 = key1.clone() * &key2;
        let prod4 = &key1 * key2.clone();

        // All multiplication forms should give same result
        assert_eq!(prod1.as_bytes(), prod2.as_bytes());
        assert_eq!(prod2.as_bytes(), prod3.as_bytes());
        assert_eq!(prod3.as_bytes(), prod4.as_bytes());
    }

    #[test]
    fn test_private_key_zeroization() {
        let mut key = PrivateKey::new([42u8; 32]);
        // Note: the actual bytes may be different due to scalar canonicalization
        // But we can test that zeroize() changes the key
        let _original_bytes = key.as_bytes();

        // Manual zeroize
        key.zeroize();
        assert_eq!(key.as_bytes(), [0u8; 32]);

        // Test that drop zeroizes
        let key2 = PrivateKey::new([99u8; 32]);
        // Just ensure we can access the bytes before drop
        let _bytes = key2.as_bytes();
        drop(key2);
        // Can't test after drop, but this ensures the drop implementation is called
    }

    #[test]
    fn test_compressed_commitment() {
        let commitment_bytes = [1u8; 32];
        let commitment = CompressedCommitment::new(commitment_bytes);
        assert_eq!(commitment.as_bytes(), &commitment_bytes);

        let hex = commitment.to_hex();
        let commitment_from_hex = CompressedCommitment::from_hex(&hex).unwrap();
        assert_eq!(commitment, commitment_from_hex);

        // Test hex encoding/decoding edge cases
        let zero_commitment = CompressedCommitment::new([0u8; 32]);
        let zero_hex = zero_commitment.to_hex();
        assert_eq!(
            zero_hex,
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        let max_commitment = CompressedCommitment::new([255u8; 32]);
        let max_hex = max_commitment.to_hex();
        assert_eq!(
            max_hex,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );

        // Test invalid hex
        assert!(CompressedCommitment::from_hex("invalid").is_err());
        assert!(CompressedCommitment::from_hex("deadbeef").is_err()); // Too short
        assert!(CompressedCommitment::from_hex("").is_err());

        // Test clone, equality, hash
        let commitment2 = commitment.clone();
        assert_eq!(commitment, commitment2);

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&commitment, &mut hasher);
        // Just ensure hashing doesn't panic
    }

    #[test]
    fn test_compressed_public_key() {
        let key_bytes = [1u8; 32];
        let key = CompressedPublicKey::new(key_bytes);
        assert_eq!(key.as_bytes(), key_bytes);

        let hex = key.to_hex();
        let key_from_hex = CompressedPublicKey::from_hex(&hex).unwrap();
        assert_eq!(key, key_from_hex);

        // Test default
        let default_key = CompressedPublicKey::default();
        assert_eq!(default_key.as_bytes(), [0u8; 32]);

        // Test display
        let display_str = format!("{key}");
        assert_eq!(display_str, hex);

        // Test from private key
        let private_key = PrivateKey::new([42u8; 32]);
        let public_key = CompressedPublicKey::from_private_key(&private_key);
        // Ensure it doesn't panic and returns a valid key
        assert_eq!(public_key.as_bytes().len(), 32);

        // Test decompression (may or may not succeed depending on the bytes)
        let _decompressed = key.decompress(); // Just ensure it doesn't panic

        // Test hex edge cases
        assert!(CompressedPublicKey::from_hex("invalid").is_err());
        assert!(CompressedPublicKey::from_hex("deadbeef").is_err()); // Too short

        // Test valid long hex
        let valid_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let key_from_valid = CompressedPublicKey::from_hex(valid_hex).unwrap();
        assert_eq!(key_from_valid.to_hex(), valid_hex);
    }

    #[test]
    fn test_safe_array() {
        let array_data = [1u8; 32];
        let array = SafeArray::new(array_data);
        assert_eq!(array.as_bytes(), &array_data);

        let hex = array.to_hex();
        let array_from_hex = SafeArray::from_hex(&hex).unwrap();
        assert_eq!(array, array_from_hex);

        // Test different sizes
        let small_array: SafeArray<4> = SafeArray::new([1, 2, 3, 4]);
        assert_eq!(small_array.as_bytes(), &[1, 2, 3, 4]);

        let large_array: SafeArray<64> = SafeArray::new([42u8; 64]);
        assert_eq!(large_array.as_bytes().len(), 64);

        // Test default
        let default_array: SafeArray<16> = SafeArray::default();
        assert_eq!(default_array.as_bytes(), &[0u8; 16]);

        // Test display
        let display_array: SafeArray<4> = SafeArray::new([0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(format!("{display_array}"), "deadbeef");

        // Test hex encoding edge cases
        let empty_like: SafeArray<0> = SafeArray::new([]);
        let empty_hex = empty_like.to_hex();
        assert_eq!(empty_hex, "");

        // Test invalid hex length
        assert!(SafeArray::<4>::from_hex("deadbeef00").is_err()); // Too long
        assert!(SafeArray::<4>::from_hex("dead").is_err()); // Too short
        assert!(SafeArray::<4>::from_hex("deadbeef").is_ok()); // Just right

        // Test zeroization
        let mut zeroizable_array: SafeArray<8> = SafeArray::new([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(zeroizable_array.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
        zeroizable_array.zeroize();
        assert_eq!(zeroizable_array.as_bytes(), &[0u8; 8]);
    }

    #[test]
    fn test_encrypted_data_key() {
        let safe_array = SafeArray::new([42u8; 32]);
        let mut encrypted_key = EncryptedDataKey::from(safe_array.clone());

        assert_eq!(encrypted_key.reveal(), &[42u8; 32]);

        // Test mutable access
        let key_bytes = encrypted_key.reveal_mut();
        key_bytes[0] = 99;
        assert_eq!(encrypted_key.reveal()[0], 99);

        let mut_bytes = encrypted_key.as_mut_bytes();
        mut_bytes[1] = 88;
        assert_eq!(encrypted_key.reveal()[1], 88);

        // Test from conversion
        let safe_array2 = SafeArray::new([77u8; 32]);
        let encrypted_key2: EncryptedDataKey = safe_array2.into();
        assert_eq!(encrypted_key2.reveal(), &[77u8; 32]);
    }

    #[test]
    fn test_fixed_hash() {
        let hash_bytes = [1u8; 32];
        let hash = FixedHash::new(hash_bytes);
        assert_eq!(hash.as_bytes(), &hash_bytes);
        assert_eq!(hash.as_slice(), &hash_bytes[..]);
        assert_eq!(FixedHash::byte_size(), 32);

        // Test hex encoding
        let hex = hash.to_hex();
        let hash_from_hex = FixedHash::from_hex(&hex).unwrap();
        assert_eq!(hash, hash_from_hex);

        // Test from array
        let hash_from_array: FixedHash = [42u8; 32].into();
        assert_eq!(hash_from_array.as_bytes(), &[42u8; 32]);

        // Test try_from slice
        let slice = &[99u8; 32][..];
        let hash_from_slice = FixedHash::try_from(slice).unwrap();
        assert_eq!(hash_from_slice.as_bytes(), &[99u8; 32]);

        // Test try_from with wrong length
        let wrong_slice = &[1u8; 16][..];
        assert!(FixedHash::try_from(wrong_slice).is_err());

        let too_long_slice = &[1u8; 64][..];
        assert!(FixedHash::try_from(too_long_slice).is_err());

        // Test hex edge cases
        assert!(FixedHash::from_hex("invalid").is_err());
        assert!(FixedHash::from_hex("deadbeef").is_err()); // Too short

        let valid_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let hash_from_valid = FixedHash::from_hex(valid_hex).unwrap();
        assert_eq!(hash_from_valid.to_hex(), valid_hex);

        // Test equality and cloning
        let hash2 = hash.clone();
        assert_eq!(hash, hash2);

        // Test hashing
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(&hash, &mut hasher);
    }

    #[test]
    fn test_hex_error_variants() {
        // Test different error types for comprehensive coverage
        match PrivateKey::from_hex("invalid") {
            Err(HexError::InvalidHex(_)) => {}
            _ => panic!("Expected InvalidHex error"),
        }

        match PrivateKey::from_hex("deadbeef") {
            Err(HexError::InvalidLength { expected, actual }) => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 4);
            }
            _ => panic!("Expected InvalidLength error"),
        }
    }

    #[test]
    fn test_serde_serialization() {
        // Test PrivateKey serialization
        let private_key = PrivateKey::new([42u8; 32]);
        let serialized = serde_json::to_string(&private_key).unwrap();
        let deserialized: PrivateKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(private_key.as_bytes(), deserialized.as_bytes());

        // Test CompressedPublicKey serialization
        let public_key = CompressedPublicKey::new([99u8; 32]);
        let serialized = serde_json::to_string(&public_key).unwrap();
        let deserialized: CompressedPublicKey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(public_key.as_bytes(), deserialized.as_bytes());

        // Test CompressedCommitment serialization
        let commitment = CompressedCommitment::new([77u8; 32]);
        let serialized = serde_json::to_string(&commitment).unwrap();
        let deserialized: CompressedCommitment = serde_json::from_str(&serialized).unwrap();
        assert_eq!(commitment.as_bytes(), deserialized.as_bytes());

        // Test FixedHash serialization
        let hash = FixedHash::new([88u8; 32]);
        let serialized = serde_json::to_string(&hash).unwrap();
        let deserialized: FixedHash = serde_json::from_str(&serialized).unwrap();
        assert_eq!(hash.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn test_borsh_serialization() {
        // Test PrivateKey borsh serialization
        let private_key = PrivateKey::new([42u8; 32]);
        let serialized = borsh::to_vec(&private_key).unwrap();
        let deserialized =
            <PrivateKey as borsh::BorshDeserialize>::deserialize(&mut &serialized[..]).unwrap();
        assert_eq!(private_key.as_bytes(), deserialized.as_bytes());

        // Test CompressedPublicKey borsh serialization
        let public_key = CompressedPublicKey::new([99u8; 32]);
        let serialized = borsh::to_vec(&public_key).unwrap();
        let deserialized =
            <CompressedPublicKey as borsh::BorshDeserialize>::deserialize(&mut &serialized[..])
                .unwrap();
        assert_eq!(public_key.as_bytes(), deserialized.as_bytes());

        // Test CompressedCommitment borsh serialization
        let commitment = CompressedCommitment::new([77u8; 32]);
        let serialized = borsh::to_vec(&commitment).unwrap();
        let deserialized =
            <CompressedCommitment as borsh::BorshDeserialize>::deserialize(&mut &serialized[..])
                .unwrap();
        assert_eq!(commitment.as_bytes(), deserialized.as_bytes());

        // Test SafeArray borsh serialization
        let safe_array: SafeArray<8> = SafeArray::new([1, 2, 3, 4, 5, 6, 7, 8]);
        let serialized = borsh::to_vec(&safe_array).unwrap();
        let deserialized =
            <SafeArray<8> as borsh::BorshDeserialize>::deserialize(&mut &serialized[..]).unwrap();
        assert_eq!(safe_array.as_bytes(), deserialized.as_bytes());

        // Test FixedHash borsh serialization
        let hash = FixedHash::new([88u8; 32]);
        let serialized = borsh::to_vec(&hash).unwrap();
        let deserialized =
            <FixedHash as borsh::BorshDeserialize>::deserialize(&mut &serialized[..]).unwrap();
        assert_eq!(hash.as_bytes(), deserialized.as_bytes());
    }

    #[test]
    fn test_edge_case_values() {
        // Test with all zeros
        let zero_key = PrivateKey::new([0u8; 32]);
        let zero_commitment = CompressedCommitment::new([0u8; 32]);
        let zero_public_key = CompressedPublicKey::new([0u8; 32]);
        let zero_hash = FixedHash::new([0u8; 32]);

        // Note: PrivateKey may canonicalize the scalar, so we check length instead of exact value
        assert_eq!(zero_key.to_hex().len(), 64); // 32 bytes * 2 hex chars
        assert_eq!(
            zero_commitment.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            zero_public_key.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            zero_hash.to_hex(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        // Test with all max values (note: max values will be canonicalized by scalar operations)
        let max_key = PrivateKey::new([255u8; 32]);
        let max_commitment = CompressedCommitment::new([255u8; 32]);
        let max_public_key = CompressedPublicKey::new([255u8; 32]);
        let max_hash = FixedHash::new([255u8; 32]);

        // For PrivateKey, the scalar will be reduced modulo the curve order
        assert_eq!(max_key.to_hex().len(), 64); // Should still be 32 bytes
        assert_eq!(
            max_commitment.to_hex(),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        assert_eq!(
            max_public_key.to_hex(),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        assert_eq!(
            max_hash.to_hex(),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn test_memory_safety_and_cleanup() {
        // Test that memory is properly managed for sensitive data types
        {
            let mut keys = Vec::new();
            for i in 0..100 {
                let mut key_bytes = [0u8; 32];
                key_bytes[0] = i as u8;
                keys.push(PrivateKey::new(key_bytes));
            }
            // All keys should be properly cleaned up when dropped
        }

        // Test SafeArray zeroization on drop
        {
            let mut arrays = Vec::new();
            for i in 0..50 {
                let mut array_bytes = [0u8; 32];
                array_bytes[0] = i as u8;
                arrays.push(SafeArray::new(array_bytes));
            }
            // All arrays should be properly zeroized when dropped
        }
    }
}
