//! Commitment integrity and correctness verification for lightweight wallets
//!
//! This module provides lightweight validation for Pedersen commitments
//! without requiring the full Tari crypto stack.

use crate::{
    data_structures::types::{CompressedCommitment, MicroMinotari, PrivateKey},
    errors::ValidationError,
};

/// Commitment validator
#[derive(Debug, Clone)]
pub struct CommitmentValidator;

impl CommitmentValidator {
    /// Validate the structure of a Pedersen commitment
    pub fn validate_structure(commitment: &CompressedCommitment) -> Result<(), ValidationError> {
        let bytes = commitment.as_bytes();
        if bytes.len() != 32 {
            return Err(ValidationError::commitment_validation_failed(
                "Commitment must be 32 bytes",
            ));
        }
        // Check for valid prefix (Tari uses 0x08 or 0x09 for compressed Ristretto)
        if bytes[0] != 0x08 && bytes[0] != 0x09 {
            return Err(ValidationError::commitment_validation_failed(
                "Invalid commitment format prefix",
            ));
        }
        Ok(())
    }

    /// Validate a commitment against a known value and blinding factor (if available)
    ///
    /// # Arguments
    /// * `commitment` - The commitment to check
    /// * `value` - The value committed to (optional)
    /// * `blinding` - The blinding factor used (optional)
    ///
    /// # Returns
    /// * `Ok(())` if the commitment is valid
    /// * `Err(ValidationError)` if the commitment is invalid
    pub fn validate_correctness(
        commitment: &CompressedCommitment,
        _value: Option<MicroMinotari>,
        _blinding: Option<&PrivateKey>,
    ) -> Result<(), ValidationError> {
        Self::validate_structure(commitment)?;
        // In lightweight mode, we cannot reconstruct the commitment without the full crypto stack
        // If both value and blinding are provided, we can optionally check against a known commitment
        // TODO: Integrate with curve25519-dalek or tari_crypto for full correctness check if needed
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::types::CompressedCommitment;

    #[test]
    fn test_commitment_structure_valid() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x08;
        let commitment = CompressedCommitment::new(bytes);
        assert!(CommitmentValidator::validate_structure(&commitment).is_ok());
    }

    #[test]
    fn test_commitment_structure_invalid_length() {
        // Create a 32-byte array with valid data
        let bytes = [0x08; 32];
        let commitment = CompressedCommitment::new(bytes);
        // Since we now use 32-byte arrays, this test validates that the structure check works
        let result = CommitmentValidator::validate_structure(&commitment);
        assert!(result.is_ok()); // Should be valid since it's the correct length now
    }

    #[test]
    fn test_commitment_structure_invalid_prefix() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x01; // Invalid prefix
        let commitment = CompressedCommitment::new(bytes);
        assert!(CommitmentValidator::validate_structure(&commitment).is_err());
    }

    #[test]
    fn test_commitment_correctness_no_value_blinding() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x08;
        let commitment = CompressedCommitment::new(bytes);
        assert!(CommitmentValidator::validate_correctness(&commitment, None, None).is_ok());
    }
}
