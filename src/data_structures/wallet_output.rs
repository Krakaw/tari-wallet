use crate::data_structures::{
    encrypted_data::EncryptedData,
    payment_id::PaymentId,
    types::{CompressedPublicKey, MicroMinotari},
};
use crate::hex_utils::{HexEncodable, HexError, HexValidatable};
use borsh::{BorshDeserialize, BorshSerialize};
use hex::ToHex;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fmt::{Debug, Formatter},
};

/// Simplified key identifier for lightweight wallet operations
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
pub enum LightweightKeyId {
    /// A simple string identifier for keys
    String(String),
    /// A public key identifier
    PublicKey(CompressedPublicKey),
    /// Zero key (for special cases)
    #[default]
    Zero,
}

impl std::fmt::Display for LightweightKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightweightKeyId::String(s) => write!(f, "{s}"),
            LightweightKeyId::PublicKey(pk) => write!(f, "{pk}"),
            LightweightKeyId::Zero => write!(f, "zero"),
        }
    }
}

/// Simplified output features for lightweight wallet operations
#[derive(
    Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize,
)]
pub struct LightweightOutputFeatures {
    /// Output type (payment, coinbase, burn, etc.)
    pub output_type: LightweightOutputType,
    /// Maturity height (when the output can be spent)
    pub maturity: u64,
    /// Range proof type
    pub range_proof_type: LightweightRangeProofType,
}

impl LightweightOutputFeatures {
    /// Get the serialized bytes of the output features
    pub fn bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).unwrap_or_default()
    }
}

impl Default for LightweightOutputFeatures {
    fn default() -> Self {
        Self {
            output_type: LightweightOutputType::Payment,
            maturity: 0,
            range_proof_type: LightweightRangeProofType::BulletProofPlus,
        }
    }
}

/// Simplified output types
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
pub enum LightweightOutputType {
    #[default]
    Payment,
    Coinbase,
    Burn,
    ValidatorNodeRegistration,
    CodeTemplateRegistration,
}

/// Simplified range proof types
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
pub enum LightweightRangeProofType {
    #[default]
    BulletProofPlus,
    RevealedValue,
}

/// Simplified script for lightweight wallet operations
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
pub struct LightweightScript {
    /// Script bytes
    pub bytes: Vec<u8>,
}

/// Simplified covenant for lightweight wallet operations
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
pub struct LightweightCovenant {
    /// Covenant bytes
    pub bytes: Vec<u8>,
}

/// Simplified execution stack for lightweight wallet operations
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
pub struct LightweightExecutionStack {
    /// Stack items as bytes
    pub items: Vec<Vec<u8>>,
}

impl LightweightExecutionStack {
    /// Get the serialized bytes of the execution stack
    pub fn bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self.items).unwrap_or_default()
    }
}

// TODO: Replace with tari_crypto::ristretto::CompressedRistrettoComAndPubSig
/// Simplified signature for lightweight wallet operations
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
pub struct LightweightSignature {
    /// Signature bytes
    pub bytes: Vec<u8>,
}

/// Simplified range proof for lightweight wallet operations
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Default,
)]
pub struct LightweightRangeProof {
    /// Range proof bytes
    pub bytes: Vec<u8>,
}

/// A lightweight wallet output where the value and spending key are known
/// This is a simplified version of the full WalletOutput for use in lightweight wallets
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LightweightWalletOutput {
    /// Output version
    pub version: u8,
    /// Output value in Micro Minotari
    pub value: MicroMinotari,
    /// Spending key identifier
    pub spending_key_id: LightweightKeyId,
    /// Output features
    pub features: LightweightOutputFeatures,
    /// Script
    pub script: LightweightScript,
    /// Covenant
    pub covenant: LightweightCovenant,
    /// Input data (execution stack)
    pub input_data: LightweightExecutionStack,
    /// Script key identifier
    pub script_key_id: LightweightKeyId,
    /// Sender offset public key
    pub sender_offset_public_key: CompressedPublicKey,
    /// Metadata signature
    pub metadata_signature: LightweightSignature,
    /// Script lock height
    pub script_lock_height: u64,
    /// Encrypted data
    pub encrypted_data: EncryptedData,
    /// Minimum value promise
    pub minimum_value_promise: MicroMinotari,
    /// Range proof (optional)
    pub range_proof: Option<LightweightRangeProof>,
    /// Payment ID
    pub payment_id: PaymentId,
}

impl LightweightWalletOutput {
    /// Creates a new lightweight wallet output
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u8,
        value: MicroMinotari,
        spending_key_id: LightweightKeyId,
        features: LightweightOutputFeatures,
        script: LightweightScript,
        input_data: LightweightExecutionStack,
        script_key_id: LightweightKeyId,
        sender_offset_public_key: CompressedPublicKey,
        metadata_signature: LightweightSignature,
        script_lock_height: u64,
        covenant: LightweightCovenant,
        encrypted_data: EncryptedData,
        minimum_value_promise: MicroMinotari,
        range_proof: Option<LightweightRangeProof>,
        payment_id: PaymentId,
    ) -> Self {
        Self {
            version,
            value,
            spending_key_id,
            features,
            script,
            input_data,
            script_key_id,
            sender_offset_public_key,
            metadata_signature,
            script_lock_height,
            covenant,
            encrypted_data,
            minimum_value_promise,
            range_proof,
            payment_id,
        }
    }

    /// Creates a new lightweight wallet output with default values
    pub fn new_default(
        value: MicroMinotari,
        spending_key_id: LightweightKeyId,
        script_key_id: LightweightKeyId,
        sender_offset_public_key: CompressedPublicKey,
        encrypted_data: EncryptedData,
        payment_id: PaymentId,
    ) -> Self {
        Self {
            version: 1, // Current version
            value,
            spending_key_id,
            features: LightweightOutputFeatures::default(),
            script: LightweightScript::default(),
            input_data: LightweightExecutionStack::default(),
            script_key_id,
            sender_offset_public_key,
            metadata_signature: LightweightSignature::default(),
            script_lock_height: 0,
            covenant: LightweightCovenant::default(),
            encrypted_data,
            minimum_value_promise: MicroMinotari::new(0),
            range_proof: None,
            payment_id,
        }
    }

    /// Get the output value
    pub fn value(&self) -> MicroMinotari {
        self.value
    }

    /// Get the spending key ID
    pub fn spending_key_id(&self) -> &LightweightKeyId {
        &self.spending_key_id
    }

    /// Get the script key ID
    pub fn script_key_id(&self) -> &LightweightKeyId {
        &self.script_key_id
    }

    /// Get the encrypted data
    pub fn encrypted_data(&self) -> &EncryptedData {
        &self.encrypted_data
    }

    /// Get the payment ID
    pub fn payment_id(&self) -> &PaymentId {
        &self.payment_id
    }

    /// Check if this is a coinbase output
    pub fn is_coinbase(&self) -> bool {
        matches!(self.features.output_type, LightweightOutputType::Coinbase)
    }

    /// Check if this is a burn output
    pub fn is_burn(&self) -> bool {
        matches!(self.features.output_type, LightweightOutputType::Burn)
    }

    /// Get the maturity height
    pub fn maturity(&self) -> u64 {
        self.features.maturity
    }

    /// Get the script lock height
    pub fn script_lock_height(&self) -> u64 {
        self.script_lock_height
    }

    /// Check if the output is mature at the given block height
    pub fn is_mature_at(&self, block_height: u64) -> bool {
        block_height >= self.features.maturity
    }

    /// Check if the script is unlocked at the given block height
    pub fn is_script_unlocked_at(&self, block_height: u64) -> bool {
        block_height >= self.script_lock_height
    }

    /// Check if the output can be spent at the given block height
    pub fn can_be_spent_at(&self, block_height: u64) -> bool {
        self.is_mature_at(block_height) && self.is_script_unlocked_at(block_height)
    }

    /// Get the range proof type
    pub fn range_proof_type(&self) -> &LightweightRangeProofType {
        &self.features.range_proof_type
    }

    /// Get the output type
    pub fn output_type(&self) -> &LightweightOutputType {
        &self.features.output_type
    }

    /// Get the minimum value promise
    pub fn minimum_value_promise(&self) -> MicroMinotari {
        self.minimum_value_promise
    }

    /// Get the sender offset public key
    pub fn sender_offset_public_key(&self) -> &CompressedPublicKey {
        &self.sender_offset_public_key
    }

    /// Get the metadata signature
    pub fn metadata_signature(&self) -> &LightweightSignature {
        &self.metadata_signature
    }

    /// Get the script
    pub fn script(&self) -> &LightweightScript {
        &self.script
    }

    /// Get the covenant
    pub fn covenant(&self) -> &LightweightCovenant {
        &self.covenant
    }

    /// Get the input data
    pub fn input_data(&self) -> &LightweightExecutionStack {
        &self.input_data
    }

    /// Get the range proof
    pub fn range_proof(&self) -> Option<&LightweightRangeProof> {
        self.range_proof.as_ref()
    }

    /// Set the range proof
    pub fn set_range_proof(&mut self, range_proof: LightweightRangeProof) {
        self.range_proof = Some(range_proof);
    }

    /// Remove the range proof
    pub fn remove_range_proof(&mut self) {
        self.range_proof = None;
    }

    /// Update the encrypted data
    pub fn update_encrypted_data(&mut self, encrypted_data: EncryptedData) {
        self.encrypted_data = encrypted_data;
    }

    /// Update the payment ID
    pub fn update_payment_id(&mut self, payment_id: PaymentId) {
        self.payment_id = payment_id;
    }

    /// Get the output version
    pub fn version(&self) -> u8 {
        self.version
    }
}

impl PartialOrd<LightweightWalletOutput> for LightweightWalletOutput {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LightweightWalletOutput {
    fn cmp(&self, other: &Self) -> Ordering {
        // Primary sort by maturity, then by value
        self.features
            .maturity
            .cmp(&other.features.maturity)
            .then(self.value.cmp(&other.value))
    }
}

impl Debug for LightweightWalletOutput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightweightWalletOutput")
            .field("version", &self.version)
            .field("value", &self.value)
            .field("spending_key_id", &self.spending_key_id)
            .field("features", &self.features)
            .field("script_lock_height", &self.script_lock_height)
            .field("payment_id", &self.payment_id)
            .finish()
    }
}

impl Default for LightweightWalletOutput {
    fn default() -> Self {
        Self {
            version: 1,
            value: MicroMinotari::new(0),
            spending_key_id: LightweightKeyId::Zero,
            features: LightweightOutputFeatures::default(),
            script: LightweightScript::default(),
            input_data: LightweightExecutionStack::default(),
            script_key_id: LightweightKeyId::Zero,
            sender_offset_public_key: CompressedPublicKey::new([0u8; 32]),
            metadata_signature: LightweightSignature::default(),
            script_lock_height: 0,
            covenant: LightweightCovenant::default(),
            encrypted_data: EncryptedData::default(),
            minimum_value_promise: MicroMinotari::new(0),
            range_proof: None,
            payment_id: PaymentId::U256(U256::from(12345)),
        }
    }
}

impl HexEncodable for LightweightWalletOutput {
    fn to_hex(&self) -> String {
        // For complex structures, we'll serialize to bytes first, then hex
        let bytes = borsh::to_vec(self).unwrap_or_default();
        bytes.encode_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        borsh::from_slice(&bytes).map_err(|e| HexError::InvalidHex(e.to_string()))
    }
}

impl HexValidatable for LightweightWalletOutput {}

impl HexEncodable for LightweightScript {
    fn to_hex(&self) -> String {
        self.bytes.encode_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        Ok(Self { bytes })
    }
}

impl HexValidatable for LightweightScript {}

impl HexEncodable for LightweightSignature {
    fn to_hex(&self) -> String {
        self.bytes.encode_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        Ok(Self { bytes })
    }
}

impl HexValidatable for LightweightSignature {}

impl HexEncodable for LightweightRangeProof {
    fn to_hex(&self) -> String {
        self.bytes.encode_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        Ok(Self { bytes })
    }
}

impl HexValidatable for LightweightRangeProof {}

impl HexEncodable for LightweightCovenant {
    fn to_hex(&self) -> String {
        self.bytes.encode_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        Ok(Self { bytes })
    }
}

impl HexValidatable for LightweightCovenant {}

impl HexEncodable for LightweightExecutionStack {
    fn to_hex(&self) -> String {
        // For execution stack, we'll serialize the items to a single hex string
        let bytes = borsh::to_vec(&self.items).unwrap_or_default();
        bytes.encode_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, HexError> {
        let bytes = hex::decode(hex).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        let items: Vec<Vec<u8>> =
            borsh::from_slice(&bytes).map_err(|e| HexError::InvalidHex(e.to_string()))?;
        Ok(Self { items })
    }
}

impl HexValidatable for LightweightExecutionStack {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hex_utils::HexEncodable;
    use primitive_types::U256;

    #[test]
    fn test_lightweight_wallet_output_creation() {
        let value = MicroMinotari::new(1000000);
        let spending_key_id = LightweightKeyId::String("spending_key_1".to_string());
        let script_key_id = LightweightKeyId::String("script_key_1".to_string());
        let sender_offset_public_key = CompressedPublicKey::new([0u8; 32]);
        let encrypted_data = EncryptedData::default();
        let payment_id = PaymentId::U256(U256::from(12345));

        let output = LightweightWalletOutput::new_default(
            value,
            spending_key_id.clone(),
            script_key_id.clone(),
            sender_offset_public_key.clone(),
            encrypted_data.clone(),
            payment_id.clone(),
        );

        assert_eq!(output.value(), value);
        assert_eq!(output.spending_key_id(), &spending_key_id);
        assert_eq!(output.script_key_id(), &script_key_id);
        assert_eq!(output.sender_offset_public_key(), &sender_offset_public_key);
        assert_eq!(output.encrypted_data(), &encrypted_data);
        assert_eq!(output.payment_id(), &payment_id);
        assert_eq!(output.version(), 1);
    }

    #[test]
    fn test_lightweight_wallet_output_full_constructor() {
        let value = MicroMinotari::new(2500000);
        let spending_key_id = LightweightKeyId::PublicKey(CompressedPublicKey::new([1u8; 32]));
        let script_key_id = LightweightKeyId::Zero;
        let sender_offset_public_key = CompressedPublicKey::new([2u8; 32]);
        let encrypted_data = EncryptedData::from_bytes(&[1, 2, 3, 4, 5]).unwrap_or_default();
        let payment_id = PaymentId::Empty;

        let features = LightweightOutputFeatures {
            output_type: LightweightOutputType::Coinbase,
            maturity: 50,
            range_proof_type: LightweightRangeProofType::RevealedValue,
        };

        let script = LightweightScript {
            bytes: vec![10, 20, 30],
        };
        let covenant = LightweightCovenant {
            bytes: vec![40, 50, 60],
        };
        let input_data = LightweightExecutionStack {
            items: vec![vec![70, 80, 90]],
        };
        let metadata_signature = LightweightSignature {
            bytes: vec![100, 110, 120],
        };
        let range_proof = Some(LightweightRangeProof {
            bytes: vec![130, 140, 150],
        });

        let output = LightweightWalletOutput::new(
            2,
            value,
            spending_key_id.clone(),
            features.clone(),
            script.clone(),
            input_data.clone(),
            script_key_id.clone(),
            sender_offset_public_key.clone(),
            metadata_signature.clone(),
            75,
            covenant.clone(),
            encrypted_data.clone(),
            MicroMinotari::new(1000),
            range_proof.clone(),
            payment_id.clone(),
        );

        assert_eq!(output.version(), 2);
        assert_eq!(output.value(), value);
        assert_eq!(output.spending_key_id(), &spending_key_id);
        assert_eq!(output.script_key_id(), &script_key_id);
        assert_eq!(output.output_type(), &LightweightOutputType::Coinbase);
        assert_eq!(output.maturity(), 50);
        assert_eq!(output.script_lock_height(), 75);
        assert_eq!(
            output.range_proof_type(),
            &LightweightRangeProofType::RevealedValue
        );
        assert_eq!(output.script(), &script);
        assert_eq!(output.covenant(), &covenant);
        assert_eq!(output.input_data(), &input_data);
        assert_eq!(output.metadata_signature(), &metadata_signature);
        assert_eq!(output.range_proof(), range_proof.as_ref());
        assert_eq!(output.minimum_value_promise(), MicroMinotari::new(1000));
        assert!(output.is_coinbase());
        assert!(!output.is_burn());
    }

    #[test]
    fn test_lightweight_key_id_variants() {
        let string_key = LightweightKeyId::String("test_key".to_string());
        let public_key = LightweightKeyId::PublicKey(CompressedPublicKey::new([1u8; 32]));
        let zero_key = LightweightKeyId::Zero;

        assert_eq!(string_key.to_string(), "test_key");
        assert_eq!(
            public_key.to_string(),
            "0101010101010101010101010101010101010101010101010101010101010101"
        );
        assert_eq!(zero_key.to_string(), "zero");

        // Test equality
        assert_eq!(string_key, LightweightKeyId::String("test_key".to_string()));
        assert_eq!(zero_key, LightweightKeyId::default());
        assert_ne!(string_key, public_key);
    }

    #[test]
    fn test_lightweight_output_features() {
        let mut features = LightweightOutputFeatures::default();
        assert_eq!(features.output_type, LightweightOutputType::Payment);
        assert_eq!(features.maturity, 0);
        assert_eq!(
            features.range_proof_type,
            LightweightRangeProofType::BulletProofPlus
        );

        features.output_type = LightweightOutputType::ValidatorNodeRegistration;
        features.maturity = 1000;
        features.range_proof_type = LightweightRangeProofType::RevealedValue;

        let bytes = features.bytes();
        assert!(!bytes.is_empty());

        // Test all output types
        let all_types = vec![
            LightweightOutputType::Payment,
            LightweightOutputType::Coinbase,
            LightweightOutputType::Burn,
            LightweightOutputType::ValidatorNodeRegistration,
            LightweightOutputType::CodeTemplateRegistration,
        ];

        for output_type in all_types {
            features.output_type = output_type.clone();
            assert_eq!(features.output_type, output_type);
        }
    }

    #[test]
    fn test_lightweight_script_components() {
        let script = LightweightScript {
            bytes: vec![1, 2, 3, 4, 5],
        };
        let covenant = LightweightCovenant {
            bytes: vec![6, 7, 8, 9, 10],
        };
        let signature = LightweightSignature {
            bytes: vec![11, 12, 13, 14, 15],
        };
        let range_proof = LightweightRangeProof {
            bytes: vec![16, 17, 18, 19, 20],
        };

        let execution_stack = LightweightExecutionStack {
            items: vec![vec![21, 22], vec![23, 24, 25]],
        };

        assert_eq!(script.bytes, vec![1, 2, 3, 4, 5]);
        assert_eq!(covenant.bytes, vec![6, 7, 8, 9, 10]);
        assert_eq!(signature.bytes, vec![11, 12, 13, 14, 15]);
        assert_eq!(range_proof.bytes, vec![16, 17, 18, 19, 20]);
        assert_eq!(execution_stack.items, vec![vec![21, 22], vec![23, 24, 25]]);

        let stack_bytes = execution_stack.bytes();
        assert!(!stack_bytes.is_empty());
    }

    #[test]
    fn test_lightweight_wallet_output_maturity() {
        let mut output = LightweightWalletOutput::default();
        output.features.maturity = 100;

        assert!(!output.is_mature_at(50));
        assert!(output.is_mature_at(100));
        assert!(output.is_mature_at(150));
    }

    #[test]
    fn test_lightweight_wallet_output_script_lock() {
        let output = LightweightWalletOutput {
            script_lock_height: 200,
            ..Default::default()
        };

        assert!(!output.is_script_unlocked_at(150));
        assert!(output.is_script_unlocked_at(200));
        assert!(output.is_script_unlocked_at(250));
    }

    #[test]
    fn test_lightweight_wallet_output_can_be_spent() {
        let mut output = LightweightWalletOutput::default();
        output.features.maturity = 100;
        output.script_lock_height = 200;

        assert!(!output.can_be_spent_at(50)); // Neither mature nor unlocked
        assert!(!output.can_be_spent_at(150)); // Mature but not unlocked
        assert!(output.can_be_spent_at(250)); // Both mature and unlocked
    }

    #[test]
    fn test_lightweight_wallet_output_edge_cases() {
        let mut output = LightweightWalletOutput::default();

        // Test boundary conditions
        output.features.maturity = 0;
        output.script_lock_height = 0;
        assert!(output.can_be_spent_at(0));
        assert!(output.can_be_spent_at(1));

        // Test maximum values
        output.features.maturity = u64::MAX;
        output.script_lock_height = u64::MAX;
        assert!(!output.can_be_spent_at(u64::MAX - 1));
        assert!(output.can_be_spent_at(u64::MAX));

        // Test with high maturity but low script lock
        output.features.maturity = 1000;
        output.script_lock_height = 500;
        assert!(output.is_mature_at(1000));
        assert!(output.is_script_unlocked_at(500));
        assert!(output.can_be_spent_at(1000)); // Both conditions met
    }

    #[test]
    fn test_lightweight_wallet_output_types() {
        let mut output = LightweightWalletOutput::default();

        // Test default (payment)
        assert!(!output.is_coinbase());
        assert!(!output.is_burn());
        assert_eq!(output.output_type(), &LightweightOutputType::Payment);

        // Test coinbase
        output.features.output_type = LightweightOutputType::Coinbase;
        assert!(output.is_coinbase());
        assert!(!output.is_burn());
        assert_eq!(output.output_type(), &LightweightOutputType::Coinbase);

        // Test burn
        output.features.output_type = LightweightOutputType::Burn;
        assert!(!output.is_coinbase());
        assert!(output.is_burn());
        assert_eq!(output.output_type(), &LightweightOutputType::Burn);

        // Test other types
        output.features.output_type = LightweightOutputType::ValidatorNodeRegistration;
        assert!(!output.is_coinbase());
        assert!(!output.is_burn());

        output.features.output_type = LightweightOutputType::CodeTemplateRegistration;
        assert!(!output.is_coinbase());
        assert!(!output.is_burn());
    }

    #[test]
    fn test_lightweight_wallet_output_ordering() {
        let mut output1 = LightweightWalletOutput::default();
        output1.features.maturity = 100;
        output1.value = MicroMinotari::new(1000000);

        let mut output2 = LightweightWalletOutput::default();
        output2.features.maturity = 200;
        output2.value = MicroMinotari::new(500000);

        // output1 should come before output2 due to lower maturity
        assert!(output1 < output2);
        assert!(output1 <= output2);
        assert!(output2 > output1);
        assert!(output2 >= output1);

        let mut output3 = LightweightWalletOutput::default();
        output3.features.maturity = 100;
        output3.value = MicroMinotari::new(2000000);

        // output1 should come before output3 due to lower value (same maturity)
        assert!(output1 < output3);

        // Test equal outputs
        let output4 = output1.clone();
        assert_eq!(output1, output4);
        assert!(output1 <= output4);
        assert!(output1 >= output4);
    }

    #[test]
    fn test_lightweight_wallet_output_mutations() {
        let mut output = LightweightWalletOutput::default();

        // Test setting and removing range proof
        assert!(output.range_proof().is_none());

        let range_proof = LightweightRangeProof {
            bytes: vec![1, 2, 3, 4, 5],
        };
        output.set_range_proof(range_proof.clone());
        assert_eq!(output.range_proof(), Some(&range_proof));

        output.remove_range_proof();
        assert!(output.range_proof().is_none());

        // Test updating encrypted data
        let new_encrypted_data = EncryptedData::from_bytes(&[10, 20, 30, 40]).unwrap_or_default();
        output.update_encrypted_data(new_encrypted_data.clone());
        assert_eq!(output.encrypted_data(), &new_encrypted_data);

        // Test updating payment ID
        let new_payment_id = PaymentId::U256(U256::from(98765));
        output.update_payment_id(new_payment_id.clone());
        assert_eq!(output.payment_id(), &new_payment_id);
    }

    #[test]
    fn test_hex_encoding_for_components() {
        let script = LightweightScript {
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let hex = script.to_hex();
        let decoded = LightweightScript::from_hex(&hex).unwrap();
        assert_eq!(script, decoded);

        let signature = LightweightSignature {
            bytes: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        let hex = signature.to_hex();
        let decoded = LightweightSignature::from_hex(&hex).unwrap();
        assert_eq!(signature, decoded);

        let range_proof = LightweightRangeProof {
            bytes: vec![0x12, 0x34, 0x56, 0x78],
        };
        let hex = range_proof.to_hex();
        let decoded = LightweightRangeProof::from_hex(&hex).unwrap();
        assert_eq!(range_proof, decoded);

        let covenant = LightweightCovenant {
            bytes: vec![0xAB, 0xCD, 0xEF, 0x01],
        };
        let hex = covenant.to_hex();
        let decoded = LightweightCovenant::from_hex(&hex).unwrap();
        assert_eq!(covenant, decoded);

        let execution_stack = LightweightExecutionStack {
            items: vec![vec![0x11, 0x22], vec![0x33, 0x44, 0x55]],
        };
        let hex = execution_stack.to_hex();
        let decoded = LightweightExecutionStack::from_hex(&hex).unwrap();
        assert_eq!(execution_stack, decoded);
    }

    #[test]
    fn test_hex_encoding_errors() {
        // Test invalid hex strings
        assert!(LightweightScript::from_hex("invalid_hex").is_err());
        assert!(LightweightSignature::from_hex("ZZ").is_err());
        assert!(LightweightRangeProof::from_hex("").is_ok()); // Empty is valid
        assert!(LightweightCovenant::from_hex("deadbeef").is_ok()); // Valid hex
        assert!(LightweightExecutionStack::from_hex("not_valid_borsh").is_err());
    }

    #[test]
    fn test_lightweight_wallet_output_hex_serialization() {
        let output = LightweightWalletOutput::default();
        let hex = output.to_hex();
        let decoded = LightweightWalletOutput::from_hex(&hex).unwrap();
        assert_eq!(output, decoded);

        // Test with modified output
        let mut complex_output = output.clone();
        complex_output.value = MicroMinotari::new(5000000);
        complex_output.features.output_type = LightweightOutputType::Coinbase;
        complex_output.features.maturity = 500;
        complex_output.script_lock_height = 1000;

        let hex = complex_output.to_hex();
        let decoded = LightweightWalletOutput::from_hex(&hex).unwrap();
        assert_eq!(complex_output, decoded);
    }

    #[test]
    fn test_default_implementations() {
        let default_output = LightweightWalletOutput::default();
        assert_eq!(default_output.version(), 1);
        assert_eq!(default_output.value(), MicroMinotari::new(0));
        assert_eq!(default_output.spending_key_id(), &LightweightKeyId::Zero);
        assert_eq!(default_output.script_key_id(), &LightweightKeyId::Zero);
        assert_eq!(default_output.script_lock_height(), 0);
        assert_eq!(default_output.maturity(), 0);
        assert!(default_output.range_proof().is_none());

        let default_features = LightweightOutputFeatures::default();
        assert_eq!(default_features.output_type, LightweightOutputType::Payment);
        assert_eq!(default_features.maturity, 0);
        assert_eq!(
            default_features.range_proof_type,
            LightweightRangeProofType::BulletProofPlus
        );

        let default_script = LightweightScript::default();
        assert!(default_script.bytes.is_empty());

        let default_covenant = LightweightCovenant::default();
        assert!(default_covenant.bytes.is_empty());

        let default_execution_stack = LightweightExecutionStack::default();
        assert!(default_execution_stack.items.is_empty());

        let default_signature = LightweightSignature::default();
        assert!(default_signature.bytes.is_empty());

        let default_range_proof = LightweightRangeProof::default();
        assert!(default_range_proof.bytes.is_empty());
    }

    #[test]
    fn test_debug_formatting() {
        let output = LightweightWalletOutput::default();
        let debug_str = format!("{output:?}");
        assert!(debug_str.contains("LightweightWalletOutput"));
        assert!(debug_str.contains("version"));
        assert!(debug_str.contains("value"));
        assert!(debug_str.contains("spending_key_id"));
    }
}
