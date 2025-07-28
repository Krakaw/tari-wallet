//! Configuration structures for wallet scanning operations.
//!
//! This module defines the configuration options and data structures
//! used to control wallet scanning behavior, including scan ranges,
//! output formats, and wallet context information.
//!
//! This module is part of the scanner.rs binary refactoring effort.

use crate::{
    data_structures::types::PrivateKey,
    errors::{KeyManagementError, LightweightWalletResult},
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
    wallet::Wallet,
};
use hex;
use tari_utilities::ByteArray;

/// Output format options for scanner results
///
/// Controls how scanning results are displayed to the user.
///
/// # Examples
/// ```
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
/// ```
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
    /// ```
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
///
/// # Examples
/// ```no_run
/// use lightweight_wallet_libs::scanning::ScanContext;
/// use lightweight_wallet_libs::wallet::Wallet;
///
/// // From a wallet
/// let wallet = Wallet::generate_new_with_seed_phrase(None)?;
/// let context = ScanContext::from_wallet(&wallet)?;
///
/// // From a view key
/// let view_key_hex = "a1b2c3d4..."; // 64 character hex string
/// let context = ScanContext::from_view_key(view_key_hex)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct ScanContext {
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
    pub fn from_wallet(wallet: &Wallet) -> LightweightWalletResult<Self> {
        // Setup wallet keys
        let seed_phrase = wallet.export_seed_phrase()?;
        let encrypted_bytes = mnemonic_to_bytes(&seed_phrase)?;
        let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, None)?;
        let entropy = cipher_seed.entropy();

        let entropy_array: [u8; 16] = entropy
            .try_into()
            .map_err(|_| KeyManagementError::key_derivation_failed("Invalid entropy length"))?;

        let view_key_raw =
            key_derivation::derive_private_key_from_entropy(&entropy_array, "data encryption", 0)?;
        let view_key = PrivateKey::new(
            view_key_raw
                .as_bytes()
                .try_into()
                .expect("Should convert to array"),
        );

        Ok(Self {
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
    pub fn from_view_key(view_key_hex: &str) -> LightweightWalletResult<Self> {
        // Parse the hex view key
        let view_key_bytes = hex::decode(view_key_hex).map_err(|_| {
            KeyManagementError::key_derivation_failed("Invalid hex format for view key")
        })?;

        if view_key_bytes.len() != 32 {
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

        Ok(Self { view_key, entropy })
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

// OutputFormat and ScanContext moved from scanner.rs
