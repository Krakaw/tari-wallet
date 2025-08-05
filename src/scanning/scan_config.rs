//! Configuration structures for wallet scanning operations.
//!
//! This module defines the configuration options and data structures
//! used to control wallet scanning behavior, including scan ranges,
//! output formats, and wallet context information.
//!
//! This module is part of the scanner.rs binary refactoring effort.

use crate::{
    data_structures::types::PrivateKey,
    errors::{KeyManagementError, WalletResult},
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
    wallet::Wallet,
};
use hex;
use tari_utilities::ByteArray;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Output format options for scanner results
///
/// Controls how scanning results are displayed to the user.
///
/// # Examples
/// ```ignore
/// use lightweight_wallet_libs::scanning::OutputFormat;
/// use std::str::FromStr;
///
/// let format = OutputFormat::from_str("json").unwrap();
/// assert!(matches!(format, OutputFormat::Json));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    /// Detailed output with full transaction information
    Detailed,
    /// Summary output with condensed information
    Summary,
    /// JSON output for programmatic consumption
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "detailed" => Ok(OutputFormat::Detailed),
            "summary" => Ok(OutputFormat::Summary),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!(
                "Invalid output format: {s}. Valid options: detailed, summary, json"
            )),
        }
    }
}

/// Configuration for scanner binary operations
///
/// This structure contains all the configuration options needed by the scanner binary
/// to control scanning behavior, output format, storage, and progress reporting.
///
/// # Examples
/// ```ignore
/// use lightweight_wallet_libs::scanning::{BinaryScanConfig, OutputFormat};
///
/// let config = BinaryScanConfig {
///     from_block: 1000,
///     to_block: 2000,
///     block_heights: None,
///     progress_frequency: 10,
///     quiet: false,
///     output_format: OutputFormat::Detailed,
///     batch_size: 100,
///     database_path: Some("wallet.db".to_string()),
///     wallet_name: Some("main-wallet".to_string()),
///     explicit_from_block: None,
///     use_database: true,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct BinaryScanConfig {
    /// Starting block height for scanning
    pub from_block: u64,
    /// Ending block height for scanning
    pub to_block: u64,
    /// Specific block heights to scan (overrides range when specified)
    pub block_heights: Option<Vec<u64>>,
    /// Frequency of progress updates (every N blocks)
    pub progress_frequency: usize,
    /// Whether to suppress detailed output
    pub quiet: bool,
    /// Output format for scan results
    pub output_format: OutputFormat,
    /// Number of blocks to process in each batch
    pub batch_size: usize,
    /// Path to the database file (None for memory-only)
    pub database_path: Option<String>,
    /// Name of the wallet to use/create
    pub wallet_name: Option<String>,
    /// Explicitly set from_block (for resume functionality)
    pub explicit_from_block: Option<u64>,
    /// Whether to use database storage
    pub use_database: bool,
}

impl BinaryScanConfig {
    /// Create a new binary scan configuration with default values
    ///
    /// # Examples
    /// ```ignore
    /// use lightweight_wallet_libs::scanning::{BinaryScanConfig, OutputFormat};
    ///
    /// let config = BinaryScanConfig::new(1000, 2000);
    /// assert_eq!(config.from_block, 1000);
    /// assert_eq!(config.to_block, 2000);
    /// assert_eq!(config.batch_size, 100);
    /// ```
    pub fn new(from_block: u64, to_block: u64) -> Self {
        Self {
            from_block,
            to_block,
            block_heights: None,
            progress_frequency: 10,
            quiet: false,
            output_format: OutputFormat::Detailed,
            batch_size: 100,
            database_path: None,
            wallet_name: None,
            explicit_from_block: None,
            use_database: false,
        }
    }

    /// Enable database storage with the specified path
    pub fn with_database(mut self, database_path: String) -> Self {
        self.database_path = Some(database_path);
        self.use_database = true;
        self
    }

    /// Set the wallet name to use
    pub fn with_wallet_name(mut self, wallet_name: String) -> Self {
        self.wallet_name = Some(wallet_name);
        self
    }

    /// Set the output format
    pub fn with_output_format(mut self, output_format: OutputFormat) -> Self {
        self.output_format = output_format;
        self
    }

    /// Enable quiet mode (suppress detailed output)
    pub fn with_quiet_mode(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Set specific block heights to scan instead of a range
    pub fn with_specific_blocks(mut self, block_heights: Vec<u64>) -> Self {
        self.block_heights = Some(block_heights);
        self
    }
}

/// Wallet scanning context containing view key and entropy
///
/// This structure holds the cryptographic context needed for wallet scanning,
/// including the private view key and entropy derived from the wallet seed.
/// It provides all the necessary cryptographic material for detecting and
/// decrypting wallet outputs during blockchain scanning.
///
/// # Components
/// - **View Key**: Used for detecting and decrypting wallet outputs
/// - **Entropy**: Wallet-specific entropy for key derivation and scanning
///
/// # Security Considerations
/// - This structure contains sensitive cryptographic material
/// - Implements `Zeroize` and `ZeroizeOnDrop` for automatic memory cleanup
/// - Sensitive data is securely cleared when the struct is dropped
/// - Should not be stored in persistent memory or logged
/// - Use secure memory handling practices when working with this data
///
/// # Creation Methods
/// 1. **From Wallet** (Recommended): Provides full scanning context with entropy
/// 2. **From View Key**: Limited context for view-only scanning operations
/// 3. **From Seed Phrase**: Direct construction from mnemonic phrase
///
/// # Examples
/// ```ignore
/// use lightweight_wallet_libs::scanning::ScanContext;
/// use lightweight_wallet_libs::wallet::Wallet;
///
/// // From a wallet (provides full context)
/// let wallet = Wallet::generate_new_with_seed_phrase(None).unwrap();
/// let context = ScanContext::from_wallet(&wallet).unwrap();
///
/// // From a view key (limited context)
/// let view_key_hex = "9d84cc4795b509dadae90bd68b42f7d630a6a3d56281c0b5dd1c0ed36390e70a";
/// let context = ScanContext::from_view_key(view_key_hex).unwrap();
/// ```
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct ScanContext {
    /// Wallet ID for event tracking
    pub wallet_id: String,
    /// Private view key for wallet scanning
    pub view_key: PrivateKey,
    /// Wallet entropy (16 bytes)
    pub entropy: [u8; 16],
}

impl ScanContext {
    /// Create scan context from a wallet
    ///
    /// Extracts the view key and entropy from the wallet's seed phrase.
    /// This provides full scanning capabilities including entropy-based derivations.
    ///
    /// # Arguments
    /// * `wallet` - The wallet to extract scanning context from
    ///
    /// # Returns
    /// A `ScanContext` with both view key and entropy populated
    ///
    /// # Errors
    /// Returns an error if the wallet seed phrase cannot be exported or processed
    pub fn from_wallet(wallet: &Wallet) -> WalletResult<Self> {
        // Setup wallet keys
        let mut seed_phrase = wallet.export_seed_phrase()?;
        let encrypted_bytes = mnemonic_to_bytes(&seed_phrase)?;
        let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, None)?;
        let entropy = cipher_seed.entropy();

        let entropy_array: [u8; 16] = entropy
            .try_into()
            .map_err(|_| KeyManagementError::key_derivation_failed("Invalid entropy length"))?;

        let mut view_key_raw =
            key_derivation::derive_private_key_from_entropy(&entropy_array, "data encryption", 0)?;
        let view_key_bytes = view_key_raw
            .as_bytes()
            .try_into()
            .expect("Should convert to array");
        let view_key = PrivateKey::new(view_key_bytes);

        // Zeroize intermediate sensitive data
        seed_phrase.zeroize();
        view_key_raw.zeroize();

        // Generate a consistent wallet ID based on the entropy
        let wallet_id = format!("wallet_{}", hex::encode(&entropy_array[..8]));

        Ok(Self {
            wallet_id,
            view_key,
            entropy: entropy_array,
        })
    }

    /// Create scan context from a hex view key
    ///
    /// Creates a view-only scanning context from a 64-character hex view key.
    /// The entropy will be set to zeros since it cannot be derived from just the view key.
    ///
    /// # Arguments
    /// * `view_key_hex` - 64-character hexadecimal string representing the view key
    ///
    /// # Returns
    /// A `ScanContext` with view key populated and entropy set to zeros
    ///
    /// # Errors
    /// Returns an error if the hex string is invalid or not exactly 32 bytes
    pub fn from_view_key(view_key_hex: &str) -> WalletResult<Self> {
        // Parse the hex view key
        let mut view_key_bytes = hex::decode(view_key_hex).map_err(|_| {
            KeyManagementError::key_derivation_failed("Invalid hex format for view key")
        })?;

        if view_key_bytes.len() != 32 {
            view_key_bytes.zeroize(); // Clear the invalid data
            return Err(KeyManagementError::key_derivation_failed(
                "View key must be exactly 32 bytes (64 hex characters)",
            )
            .into());
        }

        let view_key_array: [u8; 32] = view_key_bytes.try_into().map_err(|_| {
            KeyManagementError::key_derivation_failed("Failed to convert view key to array")
        })?;

        let view_key = PrivateKey::new(view_key_array);

        let entropy = [0u8; 16];

        // Generate a wallet ID based on view key since we don't have entropy
        let wallet_id = format!("viewkey_{}", hex::encode(&view_key_array[..8]));

        Ok(Self {
            wallet_id,
            view_key,
            entropy,
        })
    }

    /// Check if this context has entropy (from wallet vs view-key only)
    ///
    /// Returns `true` if the context was created from a wallet (has entropy),
    /// `false` if it was created from just a view key.
    ///
    /// # Returns
    /// `true` if entropy is available, `false` if view-key only
    pub fn has_entropy(&self) -> bool {
        self.entropy != [0u8; 16]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_output_format_from_str_valid() {
        assert_eq!(
            OutputFormat::from_str("detailed").unwrap(),
            OutputFormat::Detailed
        );
        assert_eq!(
            OutputFormat::from_str("summary").unwrap(),
            OutputFormat::Summary
        );
        assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);

        // Case insensitive
        assert_eq!(
            OutputFormat::from_str("DETAILED").unwrap(),
            OutputFormat::Detailed
        );
        assert_eq!(
            OutputFormat::from_str("Summary").unwrap(),
            OutputFormat::Summary
        );
        assert_eq!(OutputFormat::from_str("JSON").unwrap(), OutputFormat::Json);
    }

    #[test]
    fn test_output_format_from_str_invalid() {
        let result = OutputFormat::from_str("invalid");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Invalid output format: invalid"));

        let result = OutputFormat::from_str("");
        assert!(result.is_err());
    }

    #[test]
    fn test_binary_scan_config_new() {
        let config = BinaryScanConfig::new(100, 200);

        assert_eq!(config.from_block, 100);
        assert_eq!(config.to_block, 200);
        assert_eq!(config.block_heights, None);
        assert_eq!(config.progress_frequency, 10);
        assert!(!config.quiet);
        assert_eq!(config.output_format, OutputFormat::Detailed);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.database_path, None);
        assert_eq!(config.wallet_name, None);
        assert_eq!(config.explicit_from_block, None);
        assert!(!config.use_database);
    }

    #[test]
    fn test_binary_scan_config_with_database() {
        let config = BinaryScanConfig::new(100, 200).with_database("test.db".to_string());

        assert_eq!(config.database_path, Some("test.db".to_string()));
        assert!(config.use_database);
    }

    #[test]
    fn test_binary_scan_config_with_wallet_name() {
        let config = BinaryScanConfig::new(100, 200).with_wallet_name("test-wallet".to_string());

        assert_eq!(config.wallet_name, Some("test-wallet".to_string()));
    }

    #[test]
    fn test_binary_scan_config_with_output_format() {
        let config = BinaryScanConfig::new(100, 200).with_output_format(OutputFormat::Json);

        assert_eq!(config.output_format, OutputFormat::Json);
    }

    #[test]
    fn test_binary_scan_config_with_quiet_mode() {
        let config = BinaryScanConfig::new(100, 200).with_quiet_mode(true);

        assert!(config.quiet);
    }

    #[test]
    fn test_binary_scan_config_with_specific_blocks() {
        let blocks = vec![100, 150, 200];
        let config = BinaryScanConfig::new(100, 200).with_specific_blocks(blocks.clone());

        assert_eq!(config.block_heights, Some(blocks));
    }

    #[test]
    fn test_binary_scan_config_builder_chain() {
        let config = BinaryScanConfig::new(100, 200)
            .with_database("test.db".to_string())
            .with_wallet_name("test-wallet".to_string())
            .with_output_format(OutputFormat::Json)
            .with_quiet_mode(true)
            .with_specific_blocks(vec![150]);

        assert_eq!(config.from_block, 100);
        assert_eq!(config.to_block, 200);
        assert_eq!(config.database_path, Some("test.db".to_string()));
        assert!(config.use_database);
        assert_eq!(config.wallet_name, Some("test-wallet".to_string()));
        assert_eq!(config.output_format, OutputFormat::Json);
        assert!(config.quiet);
        assert_eq!(config.block_heights, Some(vec![150]));
    }

    #[test]
    fn test_scan_context_from_view_key_valid() {
        let view_key_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let context = ScanContext::from_view_key(view_key_hex).unwrap();

        assert_eq!(context.view_key.as_bytes().len(), 32);
        assert_eq!(context.entropy, [0u8; 16]);
        assert!(!context.has_entropy());
    }

    #[test]
    fn test_scan_context_from_view_key_invalid_hex() {
        let invalid_hex = "not_hex_string";
        let result = ScanContext::from_view_key(invalid_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_context_from_view_key_wrong_length() {
        let short_hex = "1234567890abcdef";
        let result = ScanContext::from_view_key(short_hex);
        assert!(result.is_err());

        let long_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234";
        let result = ScanContext::from_view_key(long_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_context_has_entropy() {
        // View key only context
        let view_key_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let context = ScanContext::from_view_key(view_key_hex).unwrap();
        assert!(!context.has_entropy());

        // Context with entropy
        let context_with_entropy = ScanContext {
            wallet_id: "test_wallet".to_string(),
            view_key: PrivateKey::new([1u8; 32]),
            entropy: [1u8; 16],
        };
        assert!(context_with_entropy.has_entropy());
    }
}
