use crate::data_structures::{
    encrypted_data::EncryptedData,
    transaction_input::TransactionInput,
    types::{CompressedCommitment, CompressedPublicKey, MicroMinotari},
    wallet_output::{Covenant, OutputFeatures, OutputType, RangeProof, Script, Signature},
};
use crate::errors::{SerializationError, ValidationError, WalletError};
use crate::hex_utils::{HexEncodable, HexError, HexValidatable};
use blake2::{Blake2b, Digest};
use borsh::{BorshDeserialize, BorshSerialize};
use digest::consts::{U32, U64};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter},
};

/// Output for a transaction, defining the new ownership of coins that are being transferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TransactionOutput {
    /// Output version
    pub version: u8,
    /// Options for an output's structure or use
    pub features: OutputFeatures,
    /// The homomorphic commitment representing the output amount
    pub commitment: CompressedCommitment,
    /// A proof that the commitment is in the right range
    pub proof: Option<RangeProof>,
    /// The script that will be executed when spending this output
    pub script: Script,
    /// Tari script offset pubkey, K_O
    pub sender_offset_public_key: CompressedPublicKey,
    /// UTXO signature with the script offset private key, k_O
    pub metadata_signature: Signature,
    /// The covenant that will be executed when spending this output
    pub covenant: Covenant,
    /// Encrypted value.
    pub encrypted_data: EncryptedData,
    /// The minimum value of the commitment that is proven by the range proof
    pub minimum_value_promise: MicroMinotari,
    /// Core output features
    pub output_features: tari_transaction_components::transaction_components::OutputFeatures,
}

impl TransactionOutput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u8,
        features: OutputFeatures,
        commitment: CompressedCommitment,
        proof: Option<RangeProof>,
        script: Script,
        sender_offset_public_key: CompressedPublicKey,
        metadata_signature: Signature,
        covenant: Covenant,
        encrypted_data: EncryptedData,
        minimum_value_promise: MicroMinotari,
        output_features: tari_transaction_components::transaction_components::OutputFeatures,
    ) -> Self {
        Self {
            version,
            features,
            commitment,
            proof,
            script,
            sender_offset_public_key,
            metadata_signature,
            covenant,
            encrypted_data,
            minimum_value_promise,
            output_features,
        }
    }

    /// Create new Transaction Output with current version (convenience method)
    #[allow(clippy::too_many_arguments)]
    pub fn new_current_version(
        features: OutputFeatures,
        commitment: CompressedCommitment,
        proof: Option<RangeProof>,
        script: Script,
        sender_offset_public_key: CompressedPublicKey,
        metadata_signature: Signature,
        covenant: Covenant,
        encrypted_data: EncryptedData,
        minimum_value_promise: MicroMinotari,
        output_features: tari_transaction_components::transaction_components::OutputFeatures,
    ) -> Self {
        Self::new(
            1, // Current version
            features,
            commitment,
            proof,
            script,
            sender_offset_public_key,
            metadata_signature,
            covenant,
            encrypted_data,
            minimum_value_promise,
            output_features,
        )
    }

    // Accessor methods
    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn features(&self) -> &OutputFeatures {
        &self.features
    }

    pub fn commitment(&self) -> &CompressedCommitment {
        &self.commitment
    }

    pub fn proof(&self) -> Option<&RangeProof> {
        self.proof.as_ref()
    }

    pub fn script(&self) -> &Script {
        &self.script
    }

    pub fn sender_offset_public_key(&self) -> &CompressedPublicKey {
        &self.sender_offset_public_key
    }

    pub fn metadata_signature(&self) -> &Signature {
        &self.metadata_signature
    }

    pub fn covenant(&self) -> &Covenant {
        &self.covenant
    }

    pub fn encrypted_data(&self) -> &EncryptedData {
        &self.encrypted_data
    }

    pub fn minimum_value_promise(&self) -> MicroMinotari {
        self.minimum_value_promise
    }

    /// Calculate the hash of this output
    pub fn hash(&self) -> [u8; 32] {
        // For lightweight implementation, we use a simple hash of the serialized output
        // This matches the structure of the reference implementation
        let mut hasher = Blake2b::<U32>::new();
        hasher.update([self.version]);
        hasher.update(borsh::to_vec(&self.features).unwrap_or_default());
        hasher.update(self.commitment.as_bytes());

        // Hash range proof if present
        if let Some(proof) = &self.proof {
            hasher.update(&proof.bytes);
        } else {
            hasher.update([0u8; 32]); // Zero hash for None
        }

        hasher.update(&self.script.bytes);
        hasher.update(self.sender_offset_public_key.as_bytes());
        hasher.update(&self.metadata_signature.ephemeral_commitment);
        hasher.update(&self.metadata_signature.ephemeral_pubkey);
        hasher.update(&self.metadata_signature.u_a);
        hasher.update(&self.metadata_signature.u_x);
        hasher.update(&self.metadata_signature.u_y);
        hasher.update(&self.covenant.bytes);
        hasher.update(borsh::to_vec(&self.encrypted_data).unwrap_or_default());
        hasher.update(self.minimum_value_promise.as_u64().to_le_bytes());

        let hash = hasher.finalize();
        hash.into()
    }

    /// Calculate the SMT (Sparse Merkle Tree) hash for blockchain integration
    pub fn smt_hash(&self, mined_height: u64) -> [u8; 32] {
        let utxo_hash = self.hash();
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(b"smt_hash"); // Domain separator
        hasher.update(utxo_hash);
        hasher.update(mined_height.to_le_bytes());

        let hash = hasher.finalize();
        hash.into()
    }

    /// Returns true if the output is a coinbase, otherwise false
    pub fn is_coinbase(&self) -> bool {
        matches!(self.features.output_type, OutputType::Coinbase)
    }

    /// Returns true if the output is burned, otherwise false
    pub fn is_burned(&self) -> bool {
        matches!(self.features.output_type, OutputType::Burn)
    }

    /// Check if this output is equal to a transaction input by comparing hashes
    pub fn is_equal_to(&self, input: &TransactionInput) -> bool {
        self.hash() == input.output_hash
    }

    /// Get the hex display of the range proof
    pub fn proof_hex_display(&self, full: bool) -> String {
        if let Some(proof) = &self.proof {
            let proof_hex = hex::encode(&proof.bytes);
            if full {
                format!("Some({proof_hex})")
            } else if proof_hex.len() > 32 {
                let start = &proof_hex[0..16];
                let end = &proof_hex[proof_hex.len() - 16..proof_hex.len()];
                format!("Some({start}..{end})")
            } else {
                format!("Some({proof_hex})")
            }
        } else {
            let promise = self.minimum_value_promise.as_u64();
            format!("None({promise})")
        }
    }

    /// Get the size of features, scripts and covenant in bytes
    pub fn get_features_and_scripts_size(&self) -> Result<usize, WalletError> {
        let features_size = borsh::to_vec(&self.features)
            .map_err(|e| {
                WalletError::SerializationError(SerializationError::BorshSerializationError(
                    e.to_string(),
                ))
            })?
            .len();
        let script_size = self.script.bytes.len();
        let covenant_size = self.covenant.bytes.len();
        let encrypted_data_size = self.encrypted_data.get_payment_id_size();

        Ok(features_size + script_size + covenant_size + encrypted_data_size)
    }

    /// Verify the metadata signature (simplified version for implementation)
    pub fn verify_metadata_signature(&self) -> Result<(), WalletError> {
        // For the implementation, we perform a basic signature validation
        // This is a simplified version compared to the full cryptographic verification
        // in the reference implementation

        if self.metadata_signature.u_a.is_empty() {
            return Err(WalletError::ValidationError(
                ValidationError::MetadataSignatureValidationFailed(
                    "Metadata signature is empty".to_string(),
                ),
            ));
        }

        // Basic length and format validation
        if self.metadata_signature.u_a.len() != 64 {
            return Err(WalletError::ValidationError(
                ValidationError::MetadataSignatureValidationFailed(
                    "Invalid metadata signature length".to_string(),
                ),
            ));
        }

        // For a full implementation, this would perform cryptographic verification
        // using the commitment, sender offset public key, and challenge
        Ok(())
    }

    /// Verify validator node signature (simplified for lightweight implementation)
    pub fn verify_validator_node_signature(&self) -> Result<(), WalletError> {
        // Check if this is a validator node registration output
        if matches!(
            self.features.output_type,
            OutputType::ValidatorNodeRegistration
        ) {
            // For lightweight implementation, perform basic validation
            // The full implementation would verify cryptographic signatures
            if self.metadata_signature.u_a.is_empty() {
                return Err(WalletError::ValidationError(
                    ValidationError::SignatureValidationFailed(
                        "Validator node signature is not valid".to_string(),
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Build metadata signature challenge (simplified for lightweight implementation)
    #[allow(clippy::too_many_arguments)]
    pub fn build_metadata_signature_challenge(
        version: u8,
        script: &Script,
        features: &OutputFeatures,
        sender_offset_public_key: &CompressedPublicKey,
        ephemeral_commitment: &[u8; 32],
        ephemeral_pubkey: &[u8; 32],
        commitment: &CompressedCommitment,
        covenant: &Covenant,
        encrypted_data: &EncryptedData,
        minimum_value_promise: MicroMinotari,
    ) -> [u8; 64] {
        let message = Self::metadata_signature_message_from_parts(
            version,
            script,
            features,
            covenant,
            encrypted_data,
            minimum_value_promise,
        );
        Self::finalize_metadata_signature_challenge(
            version,
            sender_offset_public_key,
            ephemeral_commitment,
            ephemeral_pubkey,
            commitment,
            &message,
        )
    }

    /// Finalize metadata signature challenge
    pub fn finalize_metadata_signature_challenge(
        version: u8,
        sender_offset_public_key: &CompressedPublicKey,
        ephemeral_commitment: &[u8; 32],
        ephemeral_pubkey: &[u8; 32],
        commitment: &CompressedCommitment,
        message: &[u8; 32],
    ) -> [u8; 64] {
        let mut hasher = Blake2b::<U64>::new();
        hasher.update(b"metadata_signature"); // Domain separator
        hasher.update([version]);
        hasher.update(ephemeral_pubkey);
        hasher.update(ephemeral_commitment);
        hasher.update(sender_offset_public_key.as_bytes());
        hasher.update(commitment.as_bytes());
        hasher.update(message);

        let hash = hasher.finalize();
        hash.into()
    }

    /// Create metadata signature message from parts
    pub fn metadata_signature_message_from_parts(
        version: u8,
        script: &Script,
        features: &OutputFeatures,
        covenant: &Covenant,
        encrypted_data: &EncryptedData,
        minimum_value_promise: MicroMinotari,
    ) -> [u8; 32] {
        let common = Self::metadata_signature_message_common_from_parts(
            version,
            features,
            covenant,
            encrypted_data,
            minimum_value_promise,
        );
        Self::metadata_signature_message_from_script_and_common(script, &common)
    }

    /// Create common metadata signature message from parts
    pub fn metadata_signature_message_common_from_parts(
        version: u8,
        features: &OutputFeatures,
        covenant: &Covenant,
        encrypted_data: &EncryptedData,
        minimum_value_promise: MicroMinotari,
    ) -> [u8; 32] {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(b"metadata_message"); // Domain separator
        hasher.update([version]);
        hasher.update(borsh::to_vec(features).unwrap_or_default());
        hasher.update(&covenant.bytes);
        hasher.update(borsh::to_vec(encrypted_data).unwrap_or_default());
        hasher.update(minimum_value_promise.as_u64().to_le_bytes());

        let hash = hasher.finalize();
        hash.into()
    }

    /// Create metadata signature message from script and common parts
    pub fn metadata_signature_message_from_script_and_common(
        script: &Script,
        common: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(b"metadata_message"); // Domain separator
        hasher.update(&script.bytes);
        hasher.update(common);

        let hash = hasher.finalize();
        hash.into()
    }
}

impl Default for TransactionOutput {
    fn default() -> Self {
        Self {
            version: 1,
            features: OutputFeatures::default(),
            commitment: CompressedCommitment::new([0u8; 32]),
            proof: None,
            script: Script::default(),
            sender_offset_public_key: CompressedPublicKey::new([0u8; 32]),
            metadata_signature: Signature::default(),
            covenant: Covenant::default(),
            encrypted_data: EncryptedData::default(),
            minimum_value_promise: MicroMinotari::new(0),
            output_features:
                tari_transaction_components::transaction_components::OutputFeatures::default(),
        }
    }
}

impl Display for TransactionOutput {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            fmt,
            "({}, {:?}) [{:?}], Script: ({}), Offset Pubkey: ({}), Metadata Signature: ({}), Encrypted data ({}), Proof: {}",
            hex::encode(self.commitment.as_bytes()),
            hex::encode(self.hash()),
            self.features,
            hex::encode(&self.script.bytes),
            hex::encode(self.sender_offset_public_key.as_bytes()),
            hex::encode(&self.metadata_signature.u_a),
            hex::encode(borsh::to_vec(&self.encrypted_data).unwrap_or_default()),
            self.proof_hex_display(false),
        )
    }
}

impl PartialOrd for TransactionOutput {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionOutput {
    fn cmp(&self, other: &Self) -> Ordering {
        self.commitment.as_bytes().cmp(other.commitment.as_bytes())
    }
}

impl HexEncodable for TransactionOutput {
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

impl HexValidatable for TransactionOutput {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_transaction_output_creation() {
        let features = OutputFeatures::default();
        let commitment = CompressedCommitment::new([1u8; 32]);
        let proof = Some(RangeProof::default());
        let script = Script::default();
        let sender_offset_public_key = CompressedPublicKey::new([2u8; 32]);
        let metadata_signature = Signature::default();
        let covenant = Covenant::default();
        let encrypted_data = EncryptedData::default();
        let minimum_value_promise = MicroMinotari::new(1000);

        let output = TransactionOutput::new(
            1,
            features.clone(),
            commitment.clone(),
            proof.clone(),
            script.clone(),
            sender_offset_public_key.clone(),
            metadata_signature.clone(),
            covenant.clone(),
            encrypted_data.clone(),
            minimum_value_promise,
            tari_transaction_components::transaction_components::OutputFeatures::default(),
        );

        assert_eq!(output.version(), 1);
        assert_eq!(output.features(), &features);
        assert_eq!(output.commitment(), &commitment);
        assert_eq!(output.proof(), proof.as_ref());
        assert_eq!(output.script(), &script);
        assert_eq!(output.sender_offset_public_key(), &sender_offset_public_key);
        assert_eq!(output.metadata_signature(), &metadata_signature);
        assert_eq!(output.covenant(), &covenant);
        assert_eq!(output.encrypted_data(), &encrypted_data);
        assert_eq!(output.minimum_value_promise(), minimum_value_promise);
    }

    #[test]
    fn test_transaction_output_default() {
        let output = TransactionOutput::default();
        assert_eq!(output.version(), 1);
        assert_eq!(output.minimum_value_promise(), MicroMinotari::new(0));
    }

    #[test]
    fn test_hash_computation() {
        let output = TransactionOutput::default();
        let hash1 = output.hash();
        let hash2 = output.hash();
        assert_eq!(hash1, hash2); // Hash should be deterministic
        assert_eq!(hash1.len(), 32); // Should be 32 bytes
    }

    #[test]
    fn test_smt_hash_computation() {
        let output = TransactionOutput::default();
        let smt_hash1 = output.smt_hash(100);
        let smt_hash2 = output.smt_hash(100);
        let smt_hash3 = output.smt_hash(101);

        assert_eq!(smt_hash1, smt_hash2); // Same height should give same hash
        assert_ne!(smt_hash1, smt_hash3); // Different heights should give different hashes
        assert_eq!(smt_hash1.len(), 32); // Should be 32 bytes
    }

    #[test]
    fn test_is_coinbase() {
        let mut output = TransactionOutput::default();
        assert!(!output.is_coinbase());

        output.features.output_type = OutputType::Coinbase;
        assert!(output.is_coinbase());
    }

    #[test]
    fn test_is_burned() {
        let mut output = TransactionOutput::default();
        assert!(!output.is_burned());

        output.features.output_type = OutputType::Burn;
        assert!(output.is_burned());
    }

    #[test]
    fn test_ordering() {
        let output1 = TransactionOutput {
            commitment: CompressedCommitment::new([1u8; 32]),
            ..Default::default()
        };
        let output2 = TransactionOutput {
            commitment: CompressedCommitment::new([2u8; 32]),
            ..Default::default()
        };

        assert!(output1 < output2);
        assert!(output2 > output1);
    }

    #[test]
    fn test_display() {
        let output = TransactionOutput::default();
        let display_str = format!("{output}");
        assert!(!display_str.is_empty());
        assert!(display_str.contains("Script:"));
        assert!(display_str.contains("Offset Pubkey:"));
    }

    #[test]
    fn test_verify_metadata_signature() {
        let output = TransactionOutput::default();
        // With empty signature, should fail
        assert!(output.verify_metadata_signature().is_err());

        let mut output_with_sig = output;
        output_with_sig.metadata_signature.u_a = [1u8; 64].to_vec();
        // With proper length signature, should pass basic validation
        assert!(output_with_sig.verify_metadata_signature().is_ok());
    }

    #[test]
    fn test_get_features_and_scripts_size() {
        let output = TransactionOutput::default();
        let size = output.get_features_and_scripts_size().unwrap();
        assert!(size > 0);
    }

    #[test]
    fn test_current_version_constructor() {
        let features = OutputFeatures::default();
        let commitment = CompressedCommitment::new([1u8; 32]);
        let proof = Some(RangeProof::default());
        let script = Script::default();
        let sender_offset_public_key = CompressedPublicKey::new([2u8; 32]);
        let metadata_signature = Signature::default();
        let covenant = Covenant::default();
        let encrypted_data = EncryptedData::default();
        let minimum_value_promise = MicroMinotari::new(1000);

        let output = TransactionOutput::new_current_version(
            features,
            commitment,
            proof,
            script,
            sender_offset_public_key,
            metadata_signature,
            covenant,
            encrypted_data,
            minimum_value_promise,
            tari_transaction_components::transaction_components::OutputFeatures::default(),
        );

        assert_eq!(output.version(), 1); // Should use current version
    }

    #[test]
    fn test_proof_hex_display() {
        let mut output = TransactionOutput::default();

        // Test with no proof
        let hex_display = output.proof_hex_display(false);
        assert!(hex_display.starts_with("None("));

        // Test with proof
        output.proof = Some(RangeProof {
            bytes: vec![1, 2, 3, 4],
        });
        let hex_display = output.proof_hex_display(true);
        assert!(hex_display.starts_with("Some("));
        assert!(hex_display.contains("01020304"));
    }
}
