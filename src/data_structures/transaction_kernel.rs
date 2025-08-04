use crate::data_structures::types::{CompressedCommitment, CompressedPublicKey, MicroMinotari};
use crate::errors::DataStructureError;
use borsh::{BorshDeserialize, BorshSerialize};
use zeroize::Zeroize;

/// Transaction kernel structure
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TransactionKernel {
    /// Kernel version
    pub version: u8,
    /// Kernel features
    pub features: u8,
    /// Transaction fee
    pub fee: MicroMinotari,
    /// Lock height
    pub lock_height: u64,
    /// Excess commitment
    pub excess: CompressedPublicKey,
    /// Excess signature
    pub excess_sig: [u8; 64],
    /// Hash type
    pub hash_type: u8,
    /// Optional burn commitment
    pub burn_commitment: Option<CompressedCommitment>,
}

impl Default for TransactionKernel {
    fn default() -> Self {
        Self {
            version: 0,
            features: 0,
            fee: MicroMinotari::new(0),
            lock_height: 0,
            excess: CompressedPublicKey::new([0u8; 32]),
            excess_sig: [0u8; 64],
            hash_type: 0,
            burn_commitment: None,
        }
    }
}

impl TransactionKernel {
    /// Create a new transaction kernel
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u8,
        features: u8,
        fee: MicroMinotari,
        lock_height: u64,
        excess: CompressedPublicKey,
        excess_sig: [u8; 64],
        hash_type: u8,
        burn_commitment: Option<CompressedCommitment>,
    ) -> Self {
        Self {
            version,
            features,
            fee,
            lock_height,
            excess,
            excess_sig,
            hash_type,
            burn_commitment,
        }
    }

    /// Get the excess as a hex string
    pub fn excess_hex(&self) -> String {
        hex::encode(self.excess.as_bytes())
    }

    /// Get the excess signature as a hex string
    pub fn excess_sig_hex(&self) -> String {
        hex::encode(self.excess_sig)
    }

    /// Get the burn commitment as a hex string if present
    pub fn burn_commitment_hex(&self) -> Option<String> {
        self.burn_commitment
            .as_ref()
            .map(|c| hex::encode(c.as_bytes()))
    }

    /// Check if this is a coinbase kernel
    pub fn is_coinbase(&self) -> bool {
        self.features & 0x01 != 0
    }

    /// Check if this is a burn kernel
    pub fn is_burn(&self) -> bool {
        self.features & 0x02 != 0
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, DataStructureError> {
        borsh::to_vec(self).map_err(|e| DataStructureError::InvalidDataFormat(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DataStructureError> {
        borsh::from_slice(bytes).map_err(|e| DataStructureError::InvalidDataFormat(e.to_string()))
    }

    /// Serialize to hex string
    pub fn to_hex(&self) -> Result<String, DataStructureError> {
        let bytes = self.to_bytes()?;
        Ok(hex::encode(bytes))
    }

    /// Deserialize from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, DataStructureError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| DataStructureError::InvalidDataFormat(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

impl Zeroize for TransactionKernel {
    fn zeroize(&mut self) {
        self.excess_sig.zeroize();
        if let Some(_burn_commitment) = &mut self.burn_commitment {
            // Zeroize the burn commitment if present
            // Note: CompressedCommitment would need to implement Zeroize for this to work fully
        }
    }
}

impl Drop for TransactionKernel {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_kernel_creation() {
        let kernel = TransactionKernel::default();
        assert_eq!(kernel.version, 0);
        assert_eq!(kernel.features, 0);
        assert_eq!(kernel.fee.as_u64(), 0);
        assert_eq!(kernel.lock_height, 0);
    }

    #[test]
    fn test_transaction_kernel_serialization() {
        let kernel = TransactionKernel::default();
        let bytes = kernel.to_bytes().unwrap();
        let deserialized = TransactionKernel::from_bytes(&bytes).unwrap();
        assert_eq!(kernel, deserialized);
    }

    #[test]
    fn test_transaction_kernel_hex_serialization() {
        let kernel = TransactionKernel::default();
        let hex = kernel.to_hex().unwrap();
        let deserialized = TransactionKernel::from_hex(&hex).unwrap();
        assert_eq!(kernel, deserialized);
    }

    #[test]
    fn test_kernel_feature_flags() {
        let mut kernel = TransactionKernel::default();

        // Test coinbase flag
        kernel.features = 0x01;
        assert!(kernel.is_coinbase());
        assert!(!kernel.is_burn());

        // Test burn flag
        kernel.features = 0x02;
        assert!(!kernel.is_coinbase());
        assert!(kernel.is_burn());

        // Test both flags
        kernel.features = 0x03;
        assert!(kernel.is_coinbase());
        assert!(kernel.is_burn());
    }
}
