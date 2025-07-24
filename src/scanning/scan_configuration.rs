//! Scan configuration management for the scanner library

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::errors::{LightweightWalletError, LightweightWalletResult};
use crate::extraction::ExtractionConfig;
use crate::key_management::{KeyManager, KeyStore};
use crate::scanning::wallet_source::{
    WalletContext as LibWalletContext, WalletSource as LibWalletSource,
};

/// Comprehensive configuration structure for all scan parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfiguration {
    /// Starting block height (wallet birthday)
    pub start_height: u64,
    /// Ending block height (optional, if None scans to tip)
    pub end_height: Option<u64>,
    /// Specific block heights to scan (overrides range if provided)
    #[serde(default)]
    pub specific_blocks: Option<Vec<u64>>,
    /// Maximum number of blocks to scan in one request
    pub batch_size: u64,
    /// Timeout for requests
    #[serde(with = "duration_serde")]
    pub request_timeout: Duration,
    /// Progress update frequency (every N blocks)
    pub progress_frequency: u64,
    /// Whether to scan for stealth addresses
    pub scan_stealth_addresses: bool,
    /// Maximum number of addresses to scan per account
    pub max_addresses_per_account: u32,
    /// Whether to scan for imported keys
    pub scan_imported_keys: bool,
    /// Extraction configuration (excluded from serialization for security)
    #[serde(skip)]
    pub extraction_config: ExtractionConfig,
    /// Wallet source for initialization
    #[serde(skip)]
    pub wallet_source: Option<LibWalletSource>,
    /// Output format for progress reporting
    #[serde(default)]
    pub output_format: OutputFormat,
    /// Whether to run in quiet mode (minimal output)
    pub quiet: bool,
}

/// Output format options for scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Detailed progress with full information
    Detailed,
    /// Summary progress with key metrics
    Summary,
    /// JSON structured output
    Json,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Summary
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = LightweightWalletError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "detailed" => Ok(OutputFormat::Detailed),
            "summary" => Ok(OutputFormat::Summary),
            "json" => Ok(OutputFormat::Json),
            _ => Err(LightweightWalletError::InvalidArgument {
                argument: "output_format".to_string(),
                value: s.to_string(),
                message: "Valid options: detailed, summary, json".to_string(),
            }),
        }
    }
}

impl Default for ScanConfiguration {
    fn default() -> Self {
        Self {
            start_height: 0,
            end_height: None,
            specific_blocks: None,
            batch_size: 100,
            request_timeout: Duration::from_secs(30),
            progress_frequency: 10,
            scan_stealth_addresses: true,
            max_addresses_per_account: 1000,
            scan_imported_keys: true,
            extraction_config: ExtractionConfig::default(),
            wallet_source: None,
            output_format: OutputFormat::default(),
            quiet: false,
        }
    }
}

impl ScanConfiguration {
    /// Create a new scan configuration with a starting block height
    pub fn new(start_height: u64) -> Self {
        Self {
            start_height,
            ..Default::default()
        }
    }

    /// Create a scan configuration for a specific block range
    pub fn new_range(start_height: u64, end_height: u64) -> Self {
        Self {
            start_height,
            end_height: Some(end_height),
            ..Default::default()
        }
    }

    /// Create a scan configuration for specific blocks
    pub fn new_specific_blocks(blocks: Vec<u64>) -> Self {
        let start_height = blocks.iter().min().copied().unwrap_or(0);
        Self {
            start_height,
            specific_blocks: Some(blocks),
            ..Default::default()
        }
    }

    /// Set the ending block height
    pub fn with_end_height(mut self, end_height: u64) -> Self {
        self.end_height = Some(end_height);
        self
    }

    /// Set specific blocks to scan
    pub fn with_specific_blocks(mut self, blocks: Vec<u64>) -> Self {
        self.specific_blocks = Some(blocks);
        self
    }

    /// Set the batch size for scanning
    pub fn with_batch_size(mut self, batch_size: u64) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Set the request timeout
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Set the progress frequency
    pub fn with_progress_frequency(mut self, frequency: u64) -> Self {
        self.progress_frequency = frequency;
        self
    }

    /// Set whether to scan for stealth addresses
    pub fn with_stealth_address_scanning(mut self, enabled: bool) -> Self {
        self.scan_stealth_addresses = enabled;
        self
    }

    /// Set maximum addresses per account
    pub fn with_max_addresses_per_account(mut self, max: u32) -> Self {
        self.max_addresses_per_account = max;
        self
    }

    /// Set whether to scan for imported keys
    pub fn with_imported_key_scanning(mut self, enabled: bool) -> Self {
        self.scan_imported_keys = enabled;
        self
    }

    /// Set the extraction configuration
    pub fn with_extraction_config(mut self, config: ExtractionConfig) -> Self {
        self.extraction_config = config;
        self
    }

    /// Set the wallet source
    pub fn with_wallet_source(mut self, wallet_source: LibWalletSource) -> Self {
        self.wallet_source = Some(wallet_source);
        self
    }

    /// Initialize the wallet from the configured source
    pub fn initialize_wallet(&self) -> LightweightWalletResult<Option<LibWalletContext>> {
        match &self.wallet_source {
            Some(source) => {
                let context = source.clone().initialize_wallet()?;
                Ok(Some(context))
            }
            None => Ok(None),
        }
    }

    /// Set the output format
    pub fn with_output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }

    /// Set quiet mode
    pub fn with_quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    /// Validate the configuration and return errors if invalid
    pub fn validate(&self) -> LightweightWalletResult<()> {
        // Validate batch size
        if self.batch_size == 0 {
            return Err(LightweightWalletError::InvalidArgument {
                argument: "batch_size".to_string(),
                value: self.batch_size.to_string(),
                message: "Batch size must be greater than 0".to_string(),
            });
        }

        if self.batch_size > 1000 {
            return Err(LightweightWalletError::InvalidArgument {
                argument: "batch_size".to_string(),
                value: self.batch_size.to_string(),
                message: "Batch size should not exceed 1000 for performance reasons".to_string(),
            });
        }

        // Validate progress frequency
        if self.progress_frequency == 0 {
            return Err(LightweightWalletError::InvalidArgument {
                argument: "progress_frequency".to_string(),
                value: self.progress_frequency.to_string(),
                message: "Progress frequency must be greater than 0".to_string(),
            });
        }

        // Validate timeout
        if self.request_timeout.as_secs() == 0 {
            return Err(LightweightWalletError::InvalidArgument {
                argument: "request_timeout".to_string(),
                value: format!("{:?}", self.request_timeout),
                message: "Request timeout must be greater than 0".to_string(),
            });
        }

        if self.request_timeout.as_secs() > 300 {
            return Err(LightweightWalletError::InvalidArgument {
                argument: "request_timeout".to_string(),
                value: format!("{:?}", self.request_timeout),
                message: "Request timeout should not exceed 5 minutes".to_string(),
            });
        }

        // Validate block range
        if let Some(end_height) = self.end_height {
            if end_height < self.start_height {
                return Err(LightweightWalletError::InvalidArgument {
                    argument: "end_height".to_string(),
                    value: end_height.to_string(),
                    message: format!(
                        "End height ({}) cannot be less than start height ({})",
                        end_height, self.start_height
                    ),
                });
            }
        }

        // Validate specific blocks
        if let Some(ref blocks) = self.specific_blocks {
            if blocks.is_empty() {
                return Err(LightweightWalletError::InvalidArgument {
                    argument: "specific_blocks".to_string(),
                    value: "empty".to_string(),
                    message: "Specific blocks list cannot be empty".to_string(),
                });
            }

            // Check for duplicates
            let mut sorted_blocks = blocks.clone();
            sorted_blocks.sort_unstable();
            sorted_blocks.dedup();
            if sorted_blocks.len() != blocks.len() {
                return Err(LightweightWalletError::InvalidArgument {
                    argument: "specific_blocks".to_string(),
                    value: format!("{:?}", blocks),
                    message: "Specific blocks list contains duplicates".to_string(),
                });
            }
        }

        // Validate max addresses per account
        if self.max_addresses_per_account == 0 {
            return Err(LightweightWalletError::InvalidArgument {
                argument: "max_addresses_per_account".to_string(),
                value: self.max_addresses_per_account.to_string(),
                message: "Max addresses per account must be greater than 0".to_string(),
            });
        }

        if self.max_addresses_per_account > 10000 {
            return Err(LightweightWalletError::InvalidArgument {
                argument: "max_addresses_per_account".to_string(),
                value: self.max_addresses_per_account.to_string(),
                message:
                    "Max addresses per account should not exceed 10000 for performance reasons"
                        .to_string(),
            });
        }

        Ok(())
    }

    /// Get the total number of blocks to scan
    pub fn get_total_blocks(&self) -> Option<u64> {
        if let Some(ref blocks) = self.specific_blocks {
            Some(blocks.len() as u64)
        } else if let Some(end_height) = self.end_height {
            Some(end_height.saturating_sub(self.start_height) + 1)
        } else {
            None // Scanning to tip
        }
    }

    /// Check if scanning specific blocks
    pub fn is_scanning_specific_blocks(&self) -> bool {
        self.specific_blocks.is_some()
    }

    /// Get the blocks to scan (either range or specific)
    pub fn get_blocks_to_scan(&self) -> ScanBlocks {
        if let Some(ref blocks) = self.specific_blocks {
            ScanBlocks::Specific(blocks.clone())
        } else {
            ScanBlocks::Range {
                start: self.start_height,
                end: self.end_height,
            }
        }
    }
}

/// Represents the blocks to scan
#[derive(Debug, Clone)]
pub enum ScanBlocks {
    /// Scan a range of blocks
    Range { start: u64, end: Option<u64> },
    /// Scan specific blocks
    Specific(Vec<u64>),
}

/// Wallet source for initialization options
#[derive(Debug, Clone)]
pub enum WalletSource {
    /// Create from seed phrase
    SeedPhrase(String),
    /// Create from view key (hex format)
    ViewKey(String),
    /// Use existing wallet from database
    Existing(String),
    /// Generate new wallet
    Generated,
}

impl WalletSource {
    /// Validate the wallet source
    pub fn validate(&self) -> LightweightWalletResult<()> {
        match self {
            WalletSource::SeedPhrase(phrase) => {
                if phrase.trim().is_empty() {
                    return Err(LightweightWalletError::InvalidArgument {
                        argument: "seed_phrase".to_string(),
                        value: "empty".to_string(),
                        message: "Seed phrase cannot be empty".to_string(),
                    });
                }
                // Basic word count validation (12 or 24 words typical)
                let word_count = phrase.split_whitespace().count();
                if word_count < 12 || word_count > 24 {
                    return Err(LightweightWalletError::InvalidArgument {
                        argument: "seed_phrase".to_string(),
                        value: format!("{} words", word_count),
                        message: "Seed phrase should contain 12-24 words".to_string(),
                    });
                }
            }
            WalletSource::ViewKey(key) => {
                if key.trim().is_empty() {
                    return Err(LightweightWalletError::InvalidArgument {
                        argument: "view_key".to_string(),
                        value: "empty".to_string(),
                        message: "View key cannot be empty".to_string(),
                    });
                }
                // Validate hex format and length (64 characters for 32 bytes)
                if key.len() != 64 {
                    return Err(LightweightWalletError::InvalidArgument {
                        argument: "view_key".to_string(),
                        value: format!("{} characters", key.len()),
                        message: "View key must be exactly 64 hex characters (32 bytes)"
                            .to_string(),
                    });
                }
                if !key.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(LightweightWalletError::InvalidArgument {
                        argument: "view_key".to_string(),
                        value: "invalid_format".to_string(),
                        message: "View key must contain only hexadecimal characters".to_string(),
                    });
                }
            }
            WalletSource::Existing(name) => {
                if name.trim().is_empty() {
                    return Err(LightweightWalletError::InvalidArgument {
                        argument: "wallet_name".to_string(),
                        value: "empty".to_string(),
                        message: "Wallet name cannot be empty".to_string(),
                    });
                }
            }
            WalletSource::Generated => {
                // Always valid
            }
        }
        Ok(())
    }
}

/// Wallet context for scanner initialization
pub struct WalletContext {
    /// Wallet source
    pub source: WalletSource,
    /// Extraction configuration
    pub extraction_config: ExtractionConfig,
    /// Key manager for wallet key derivation
    pub key_manager: Option<Box<dyn KeyManager + Send + Sync>>,
    /// Key store for imported keys
    pub key_store: Option<KeyStore>,
}

impl std::fmt::Debug for WalletContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletContext")
            .field("source", &self.source)
            .field("extraction_config", &self.extraction_config)
            .field(
                "key_manager",
                &self.key_manager.as_ref().map(|_| "KeyManager"),
            )
            .field("key_store", &self.key_store)
            .finish()
    }
}

impl Clone for WalletContext {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            extraction_config: self.extraction_config.clone(),
            // Note: KeyManager cannot be cloned, so we set it to None
            // The caller should re-set the key manager if needed
            key_manager: None,
            key_store: self.key_store.clone(),
        }
    }
}

impl WalletContext {
    /// Create a new wallet context
    pub fn new(source: WalletSource, extraction_config: ExtractionConfig) -> Self {
        Self {
            source,
            extraction_config,
            key_manager: None,
            key_store: None,
        }
    }

    /// Set the key manager
    pub fn with_key_manager(mut self, key_manager: Box<dyn KeyManager + Send + Sync>) -> Self {
        self.key_manager = Some(key_manager);
        self
    }

    /// Set the key store
    pub fn with_key_store(mut self, key_store: KeyStore) -> Self {
        self.key_store = Some(key_store);
        self
    }

    /// Validate the wallet context
    pub fn validate(&self) -> LightweightWalletResult<()> {
        self.source.validate()?;
        // Could add extraction config validation here if needed
        Ok(())
    }
}

// Helper module for Duration serialization
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_scan_configuration_default() {
        let config = ScanConfiguration::default();
        assert_eq!(config.start_height, 0);
        assert_eq!(config.end_height, None);
        assert_eq!(config.specific_blocks, None);
        assert_eq!(config.batch_size, 100);
        assert_eq!(config.request_timeout, Duration::from_secs(30));
        assert_eq!(config.progress_frequency, 10);
        assert!(config.scan_stealth_addresses);
        assert_eq!(config.max_addresses_per_account, 1000);
        assert!(config.scan_imported_keys);
        assert!(!config.quiet);
        assert!(matches!(config.output_format, OutputFormat::Summary));
    }

    #[test]
    fn test_scan_configuration_new() {
        let config = ScanConfiguration::new(1000);
        assert_eq!(config.start_height, 1000);
        assert_eq!(config.end_height, None);
        // All other fields should be defaults
        assert_eq!(config.batch_size, 100);
    }

    #[test]
    fn test_scan_configuration_new_range() {
        let config = ScanConfiguration::new_range(1000, 2000);
        assert_eq!(config.start_height, 1000);
        assert_eq!(config.end_height, Some(2000));
    }

    #[test]
    fn test_scan_configuration_new_specific_blocks() {
        let blocks = vec![1000, 1500, 2000];
        let config = ScanConfiguration::new_specific_blocks(blocks.clone());
        assert_eq!(config.start_height, 1000); // minimum value
        assert_eq!(config.specific_blocks, Some(blocks));
    }

    #[test]
    fn test_scan_configuration_new_specific_blocks_empty() {
        let blocks = vec![];
        let config = ScanConfiguration::new_specific_blocks(blocks);
        assert_eq!(config.start_height, 0); // default when empty
        assert_eq!(config.specific_blocks, Some(vec![]));
    }

    #[test]
    fn test_scan_configuration_builder_methods() {
        let config = ScanConfiguration::new(0)
            .with_end_height(1000)
            .with_batch_size(50)
            .with_request_timeout(Duration::from_secs(60))
            .with_progress_frequency(5)
            .with_stealth_address_scanning(false)
            .with_max_addresses_per_account(500)
            .with_imported_key_scanning(false)
            .with_output_format(OutputFormat::Json)
            .with_quiet(true);

        assert_eq!(config.end_height, Some(1000));
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.request_timeout, Duration::from_secs(60));
        assert_eq!(config.progress_frequency, 5);
        assert!(!config.scan_stealth_addresses);
        assert_eq!(config.max_addresses_per_account, 500);
        assert!(!config.scan_imported_keys);
        assert!(matches!(config.output_format, OutputFormat::Json));
        assert!(config.quiet);
    }

    #[test]
    fn test_scan_configuration_validate_success() {
        let config = ScanConfiguration::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_scan_configuration_validate_batch_size_zero() {
        let mut config = ScanConfiguration::default();
        config.batch_size = 0;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            LightweightWalletError::InvalidArgument { .. }
        ));
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "batch_size");
            assert!(message.contains("must be greater than 0"));
        }
    }

    #[test]
    fn test_scan_configuration_validate_batch_size_too_large() {
        let mut config = ScanConfiguration::default();
        config.batch_size = 1001;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "batch_size");
            assert!(message.contains("should not exceed 1000"));
        }
    }

    #[test]
    fn test_scan_configuration_validate_progress_frequency_zero() {
        let mut config = ScanConfiguration::default();
        config.progress_frequency = 0;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "progress_frequency");
            assert!(message.contains("must be greater than 0"));
        }
    }

    #[test]
    fn test_scan_configuration_validate_timeout_zero() {
        let mut config = ScanConfiguration::default();
        config.request_timeout = Duration::from_secs(0);

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "request_timeout");
            assert!(message.contains("must be greater than 0"));
        }
    }

    #[test]
    fn test_scan_configuration_validate_timeout_too_large() {
        let mut config = ScanConfiguration::default();
        config.request_timeout = Duration::from_secs(301); // Over 5 minutes

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "request_timeout");
            assert!(message.contains("should not exceed 5 minutes"));
        }
    }

    #[test]
    fn test_scan_configuration_validate_invalid_block_range() {
        let mut config = ScanConfiguration::default();
        config.start_height = 2000;
        config.end_height = Some(1000); // End < start

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "end_height");
            assert!(message.contains("cannot be less than start height"));
        }
    }

    #[test]
    fn test_scan_configuration_validate_empty_specific_blocks() {
        let mut config = ScanConfiguration::default();
        config.specific_blocks = Some(vec![]);

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "specific_blocks");
            assert!(message.contains("cannot be empty"));
        }
    }

    #[test]
    fn test_scan_configuration_validate_duplicate_specific_blocks() {
        let mut config = ScanConfiguration::default();
        config.specific_blocks = Some(vec![1000, 1500, 1000, 2000]); // Contains duplicate

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "specific_blocks");
            assert!(message.contains("contains duplicates"));
        }
    }

    #[test]
    fn test_scan_configuration_validate_max_addresses_zero() {
        let mut config = ScanConfiguration::default();
        config.max_addresses_per_account = 0;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "max_addresses_per_account");
            assert!(message.contains("must be greater than 0"));
        }
    }

    #[test]
    fn test_scan_configuration_validate_max_addresses_too_large() {
        let mut config = ScanConfiguration::default();
        config.max_addresses_per_account = 10001;

        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "max_addresses_per_account");
            assert!(message.contains("should not exceed 10000"));
        }
    }

    #[test]
    fn test_scan_configuration_get_total_blocks_range() {
        let config = ScanConfiguration::new_range(1000, 1010);
        assert_eq!(config.get_total_blocks(), Some(11)); // 1000-1010 inclusive
    }

    #[test]
    fn test_scan_configuration_get_total_blocks_specific() {
        let config = ScanConfiguration::new_specific_blocks(vec![1000, 1500, 2000]);
        assert_eq!(config.get_total_blocks(), Some(3));
    }

    #[test]
    fn test_scan_configuration_get_total_blocks_open_ended() {
        let config = ScanConfiguration::new(1000);
        assert_eq!(config.get_total_blocks(), None); // Scanning to tip
    }

    #[test]
    fn test_scan_configuration_is_scanning_specific_blocks() {
        let mut config = ScanConfiguration::new(0);
        assert!(!config.is_scanning_specific_blocks());

        config.specific_blocks = Some(vec![1000]);
        assert!(config.is_scanning_specific_blocks());
    }

    #[test]
    fn test_scan_configuration_get_blocks_to_scan_range() {
        let config = ScanConfiguration::new_range(1000, 2000);
        match config.get_blocks_to_scan() {
            ScanBlocks::Range { start, end } => {
                assert_eq!(start, 1000);
                assert_eq!(end, Some(2000));
            }
            _ => panic!("Expected Range variant"),
        }
    }

    #[test]
    fn test_scan_configuration_get_blocks_to_scan_specific() {
        let blocks = vec![1000, 1500, 2000];
        let config = ScanConfiguration::new_specific_blocks(blocks.clone());
        match config.get_blocks_to_scan() {
            ScanBlocks::Specific(scan_blocks) => {
                assert_eq!(scan_blocks, blocks);
            }
            _ => panic!("Expected Specific variant"),
        }
    }

    #[test]
    fn test_output_format_from_str_valid() {
        assert!(matches!(
            "detailed".parse::<OutputFormat>().unwrap(),
            OutputFormat::Detailed
        ));
        assert!(matches!(
            "SUMMARY".parse::<OutputFormat>().unwrap(),
            OutputFormat::Summary
        ));
        assert!(matches!(
            "Json".parse::<OutputFormat>().unwrap(),
            OutputFormat::Json
        ));
    }

    #[test]
    fn test_output_format_from_str_invalid() {
        let result = "invalid".parse::<OutputFormat>();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument,
            value,
            message,
        } = err
        {
            assert_eq!(argument, "output_format");
            assert_eq!(value, "invalid");
            assert!(message.contains("Valid options: detailed, summary, json"));
        }
    }

    #[test]
    fn test_wallet_source_validate_seed_phrase_valid() {
        let source = WalletSource::SeedPhrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string());
        assert!(source.validate().is_ok());
    }

    #[test]
    fn test_wallet_source_validate_seed_phrase_empty() {
        let source = WalletSource::SeedPhrase("".to_string());
        let result = source.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "seed_phrase");
            assert!(message.contains("cannot be empty"));
        }
    }

    #[test]
    fn test_wallet_source_validate_seed_phrase_too_few_words() {
        let source = WalletSource::SeedPhrase("abandon abandon abandon".to_string());
        let result = source.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "seed_phrase");
            assert!(message.contains("should contain 12-24 words"));
        }
    }

    #[test]
    fn test_wallet_source_validate_seed_phrase_too_many_words() {
        // 25 words
        let source = WalletSource::SeedPhrase("abandon ".repeat(25).trim().to_string());
        let result = source.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "seed_phrase");
            assert!(message.contains("should contain 12-24 words"));
        }
    }

    #[test]
    fn test_wallet_source_validate_view_key_valid() {
        let source = WalletSource::ViewKey(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
        );
        assert!(source.validate().is_ok());
    }

    #[test]
    fn test_wallet_source_validate_view_key_empty() {
        let source = WalletSource::ViewKey("".to_string());
        let result = source.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "view_key");
            assert!(message.contains("cannot be empty"));
        }
    }

    #[test]
    fn test_wallet_source_validate_view_key_wrong_length() {
        let source = WalletSource::ViewKey("abcdef123".to_string()); // Too short
        let result = source.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "view_key");
            assert!(message.contains("must be exactly 64 hex characters"));
        }
    }

    #[test]
    fn test_wallet_source_validate_view_key_invalid_hex() {
        let source = WalletSource::ViewKey(
            "ghijklmnopqrstuvwxyzghijklmnopqrstuvwxyzghijklmnopqrstuvwxyzghij".to_string(),
        );
        let result = source.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "view_key");
            assert!(message.contains("must contain only hexadecimal characters"));
        }
    }

    #[test]
    fn test_wallet_source_validate_existing_valid() {
        let source = WalletSource::Existing("my_wallet".to_string());
        assert!(source.validate().is_ok());
    }

    #[test]
    fn test_wallet_source_validate_existing_empty() {
        let source = WalletSource::Existing("".to_string());
        let result = source.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let LightweightWalletError::InvalidArgument {
            argument, message, ..
        } = err
        {
            assert_eq!(argument, "wallet_name");
            assert!(message.contains("cannot be empty"));
        }
    }

    #[test]
    fn test_wallet_source_validate_generated() {
        let source = WalletSource::Generated;
        assert!(source.validate().is_ok());
    }

    #[test]
    fn test_wallet_context_new() {
        let source = WalletSource::Generated;
        let extraction_config = ExtractionConfig::default();
        let context = WalletContext::new(source.clone(), extraction_config);

        assert!(matches!(context.source, WalletSource::Generated));
        // Note: ExtractionConfig doesn't implement PartialEq, so we just verify structure
        assert!(context.key_manager.is_none());
        assert!(context.key_store.is_none());
    }

    #[test]
    fn test_wallet_context_validate() {
        let source = WalletSource::Generated;
        let extraction_config = ExtractionConfig::default();
        let context = WalletContext::new(source, extraction_config);

        assert!(context.validate().is_ok());
    }

    #[test]
    fn test_wallet_context_validate_invalid_source() {
        let source = WalletSource::SeedPhrase("".to_string()); // Invalid empty seed phrase
        let extraction_config = ExtractionConfig::default();
        let context = WalletContext::new(source, extraction_config);

        let result = context.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_context_clone() {
        let source = WalletSource::Generated;
        let extraction_config = ExtractionConfig::default();
        let context = WalletContext::new(source.clone(), extraction_config);

        let cloned = context.clone();
        assert!(matches!(cloned.source, WalletSource::Generated));
        // Note: ExtractionConfig doesn't implement PartialEq, so we just verify structure
        assert!(cloned.key_manager.is_none()); // KeyManager cannot be cloned
        assert!(cloned.key_store.is_none());
    }

    #[test]
    fn test_scan_blocks_debug() {
        let range_blocks = ScanBlocks::Range {
            start: 1000,
            end: Some(2000),
        };
        let debug_str = format!("{:?}", range_blocks);
        assert!(debug_str.contains("Range"));
        assert!(debug_str.contains("1000"));
        assert!(debug_str.contains("2000"));

        let specific_blocks = ScanBlocks::Specific(vec![1000, 1500, 2000]);
        let debug_str = format!("{:?}", specific_blocks);
        assert!(debug_str.contains("Specific"));
        assert!(debug_str.contains("1000"));
    }

    #[test]
    fn test_duration_serde() {
        let config = ScanConfiguration::default();

        // Serialize to JSON
        let json = serde_json::to_string(&config).expect("Failed to serialize");
        assert!(json.contains("\"request_timeout\":30"));

        // Deserialize from JSON
        let deserialized: ScanConfiguration =
            serde_json::from_str(&json).expect("Failed to deserialize");
        assert_eq!(deserialized.request_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_edge_case_block_range_equal() {
        let config = ScanConfiguration::new_range(1000, 1000);
        assert!(config.validate().is_ok());
        assert_eq!(config.get_total_blocks(), Some(1)); // Single block
    }

    #[test]
    fn test_edge_case_large_valid_values() {
        let mut config = ScanConfiguration::default();
        config.batch_size = 1000; // Maximum allowed
        config.request_timeout = Duration::from_secs(300); // Maximum allowed (5 minutes)
        config.max_addresses_per_account = 10000; // Maximum allowed

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_edge_case_minimal_valid_values() {
        let mut config = ScanConfiguration::default();
        config.batch_size = 1; // Minimum allowed
        config.progress_frequency = 1; // Minimum allowed
        config.request_timeout = Duration::from_secs(1); // Minimum allowed
        config.max_addresses_per_account = 1; // Minimum allowed

        assert!(config.validate().is_ok());
    }
}
