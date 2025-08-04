use crate::data_structures::{
    payment_id::PaymentId,
    types::MicroMinotari,
    wallet_output::{KeyId, WalletOutput},
};
use crate::errors::WalletError;

/// Result of wallet output reconstruction
#[derive(Debug, Clone)]
pub struct WalletOutputReconstructionResult {
    /// The reconstructed wallet output
    pub wallet_output: WalletOutput,
    /// The extracted value
    pub value: MicroMinotari,
    /// The extracted payment ID
    pub payment_id: PaymentId,
    /// The key used for decryption
    pub decryption_key_id: KeyId,
}

/// Options for wallet output reconstruction
#[derive(Debug, Clone)]
pub struct WalletOutputReconstructionOptions {
    /// Whether to attempt decryption with derived keys
    pub try_derived_keys: bool,
    /// Whether to attempt decryption with imported keys
    pub try_imported_keys: bool,
    /// Maximum number of derived keys to try
    pub max_derived_keys: u64,
    /// Whether to extract payment ID
    pub extract_payment_id: bool,
    /// Whether to validate the reconstructed output
    pub validate_output: bool,
}

impl Default for WalletOutputReconstructionOptions {
    fn default() -> Self {
        Self {
            try_derived_keys: true,
            try_imported_keys: true,
            max_derived_keys: 100,
            extract_payment_id: true,
            validate_output: true,
        }
    }
}

/// Wallet output reconstruction error
#[derive(Debug, thiserror::Error)]
pub enum WalletOutputReconstructionError {
    #[error("Failed to decrypt encrypted data: {0}")]
    DecryptionFailed(#[from] WalletError),

    #[error("Failed to extract payment ID: {0}")]
    PaymentIdExtractionFailed(String),

    #[error("No suitable key found for decryption")]
    NoSuitableKey,

    #[error("Invalid output features: {0}")]
    InvalidOutputFeatures(String),

    #[error("Invalid output type: {0}")]
    InvalidOutputType(String),

    #[error("Invalid range proof type: {0}")]
    InvalidRangeProofType(String),

    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}

/// Wallet output reconstructor
///
/// This struct will be implemented once the entropy-based key derivation is complete.
/// For now, individual functions provide the reconstruction functionality.
pub struct WalletOutputReconstructor {
    options: WalletOutputReconstructionOptions,
}

impl WalletOutputReconstructor {
    /// Create a new wallet output reconstructor with default options
    pub fn new() -> Self {
        Self {
            options: WalletOutputReconstructionOptions::default(),
        }
    }
}

impl Default for WalletOutputReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletOutputReconstructor {
    /// Create a new wallet output reconstructor with custom options
    pub fn with_options(options: WalletOutputReconstructionOptions) -> Self {
        Self { options }
    }

    /// Get the current options
    pub fn options(&self) -> &WalletOutputReconstructionOptions {
        &self.options
    }

    /// Set new options
    pub fn set_options(&mut self, options: WalletOutputReconstructionOptions) {
        self.options = options;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_output_reconstruction_options() {
        let options = WalletOutputReconstructionOptions::default();
        assert!(options.try_derived_keys);
        assert!(options.try_imported_keys);
        assert_eq!(options.max_derived_keys, 100);
        assert!(options.extract_payment_id);
        assert!(options.validate_output);
    }

    #[test]
    fn test_wallet_output_reconstructor_creation() {
        let reconstructor = WalletOutputReconstructor::new();
        assert!(reconstructor.options().try_derived_keys);

        let custom_options = WalletOutputReconstructionOptions {
            try_derived_keys: false,
            try_imported_keys: true,
            max_derived_keys: 50,
            extract_payment_id: false,
            validate_output: false,
        };

        let reconstructor = WalletOutputReconstructor::with_options(custom_options.clone());
        assert!(!reconstructor.options().try_derived_keys);
        assert_eq!(reconstructor.options().max_derived_keys, 50);
    }
}
