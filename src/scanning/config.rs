//! Enhanced scanning configuration for lightweight wallet libraries
//!
//! This module provides comprehensive configuration types for wallet scanning operations,
//! abstracted from CLI-specific implementations to work in various environments including
//! WASM, library integrations, and command-line applications.

use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::{
    data_structures::types::PrivateKey,
    errors::{LightweightWalletResult, KeyManagementError},
    key_management::{
        key_derivation,
        seed_phrase::{mnemonic_to_bytes, CipherSeed},
    },
    wallet::Wallet,
};
use tari_utilities::ByteArray;

/// Enhanced configuration for wallet scanning operations
/// 
/// This provides more comprehensive configuration options than the basic `ScanConfig`
/// in the scanning module, including wallet-specific settings, progress reporting,
/// and output formatting preferences.
#[derive(Debug, Clone)]
pub struct EnhancedScanConfig {
    /// Starting block height for scanning
    pub from_block: u64,
    /// Ending block height for scanning
    pub to_block: u64,
    /// Specific block heights to scan (overrides range if provided)
    pub block_heights: Option<Vec<u64>>,
    /// Batch size for scanning operations
    pub batch_size: usize,
    /// Progress update frequency (every N blocks)
    pub progress_frequency: usize,
    /// Output format preference
    pub output_format: OutputFormat,
    /// Request timeout for network operations
    pub request_timeout: Duration,
    /// Whether explicit from_block was provided (for resume logic)
    pub explicit_from_block: Option<u64>,
}

impl EnhancedScanConfig {
    /// Create a new enhanced scan config with defaults
    pub fn new(from_block: u64, to_block: u64) -> Self {
        Self {
            from_block,
            to_block,
            block_heights: None,
            batch_size: 10,
            progress_frequency: 10,
            output_format: OutputFormat::Summary,
            request_timeout: Duration::from_secs(30),
            explicit_from_block: None,
        }
    }

    /// Create config for specific block heights
    pub fn for_specific_blocks(blocks: Vec<u64>) -> Self {
        let from_block = blocks.iter().min().copied().unwrap_or(0);
        let to_block = blocks.iter().max().copied().unwrap_or(0);
        
        Self {
            from_block,
            to_block,
            block_heights: Some(blocks),
            batch_size: 10,
            progress_frequency: 10,
            output_format: OutputFormat::Summary,
            request_timeout: Duration::from_secs(30),
            explicit_from_block: None,
        }
    }

    /// Set batch size for scanning
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Set progress update frequency
    pub fn with_progress_frequency(mut self, frequency: usize) -> Self {
        self.progress_frequency = frequency;
        self
    }

    /// Set output format
    pub fn with_output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }

    /// Set request timeout
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Mark that an explicit from_block was provided
    pub fn with_explicit_from_block(mut self, from_block: u64) -> Self {
        self.explicit_from_block = Some(from_block);
        self.from_block = from_block;
        self
    }

    /// Check if scanning specific blocks (vs range)
    pub fn is_scanning_specific_blocks(&self) -> bool {
        self.block_heights.is_some()
    }

    /// Get the blocks to scan (either range or specific blocks)
    pub fn get_blocks_to_scan(&self) -> Vec<u64> {
        self.block_heights.clone().unwrap_or_else(|| {
            (self.from_block..=self.to_block).collect()
        })
    }

    /// Get total number of blocks to scan
    pub fn total_blocks(&self) -> usize {
        self.get_blocks_to_scan().len()
    }

    /// Convert to basic ScanConfig for compatibility
    pub fn to_basic_scan_config(&self) -> crate::scanning::ScanConfig {
        crate::scanning::ScanConfig {
            start_height: self.from_block,
            end_height: Some(self.to_block),
            specific_heights: self.block_heights.clone(),
            batch_size: self.batch_size as u64,
            request_timeout: self.request_timeout,
            extraction_config: crate::extraction::ExtractionConfig::default(),
        }
    }
}

/// Output format options for scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Detailed output with full transaction history
    Detailed,
    /// Summary output with key statistics
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
                "Invalid output format: {}. Valid options: detailed, summary, json",
                s
            )),
        }
    }
}

/// Wallet scanning context containing cryptographic keys and entropy
/// 
/// This provides the necessary cryptographic material for scanning and
/// decrypting wallet outputs, supporting both full wallet access (with entropy)
/// and view-only access (view key only).
#[derive(Debug, Clone)]
pub struct WalletScanContext {
    /// Private view key for decrypting encrypted data
    pub view_key: PrivateKey,
    /// Wallet entropy for key derivation (empty for view-key-only mode)
    pub entropy: [u8; 16],
}

impl WalletScanContext {
    /// Create scan context from a wallet
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

    /// Create scan context from a view key (view-only mode)
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
        let entropy = [0u8; 16]; // No entropy for view-only mode

        Ok(Self { view_key, entropy })
    }

    /// Create scan context from view key bytes
    pub fn from_view_key_bytes(view_key_bytes: [u8; 32]) -> Self {
        Self {
            view_key: PrivateKey::new(view_key_bytes),
            entropy: [0u8; 16], // No entropy for view-only mode
        }
    }

    /// Create scan context with both view key and entropy
    pub fn with_entropy(view_key: PrivateKey, entropy: [u8; 16]) -> Self {
        Self { view_key, entropy }
    }

    /// Check if this context has full wallet entropy (vs view-key-only)
    pub fn has_entropy(&self) -> bool {
        self.entropy != [0u8; 16]
    }

    /// Check if this is view-key-only mode
    pub fn is_view_only(&self) -> bool {
        !self.has_entropy()
    }

    /// Get the scanning mode as a string
    pub fn scanning_mode(&self) -> &'static str {
        if self.has_entropy() {
            "Full wallet"
        } else {
            "View-only"
        }
    }
}

/// Block height range specification for scanning
#[derive(Debug, Clone)]
pub struct BlockHeightRange {
    /// Starting block height
    pub from_block: u64,
    /// Ending block height
    pub to_block: u64,
    /// Specific block heights (overrides range if provided)
    pub block_heights: Option<Vec<u64>>,
}

impl BlockHeightRange {
    /// Create a new block height range
    pub fn new(from_block: u64, to_block: u64) -> Self {
        Self {
            from_block,
            to_block,
            block_heights: None,
        }
    }

    /// Create range for specific block heights
    pub fn for_specific_blocks(block_heights: Vec<u64>) -> Self {
        let from_block = block_heights.iter().min().copied().unwrap_or(0);
        let to_block = block_heights.iter().max().copied().unwrap_or(0);
        
        Self {
            from_block,
            to_block,
            block_heights: Some(block_heights),
        }
    }

    /// Convert to enhanced scan config
    pub fn into_enhanced_scan_config(self) -> EnhancedScanConfig {
        EnhancedScanConfig {
            from_block: self.from_block,
            to_block: self.to_block,
            block_heights: self.block_heights,
            batch_size: 10,
            progress_frequency: 10,
            output_format: OutputFormat::Summary,
            request_timeout: Duration::from_secs(30),
            explicit_from_block: None,
        }
    }

    /// Get the blocks to scan
    pub fn get_blocks(&self) -> Vec<u64> {
        self.block_heights.clone().unwrap_or_else(|| {
            (self.from_block..=self.to_block).collect()
        })
    }

    /// Check if scanning specific blocks
    pub fn is_specific_blocks(&self) -> bool {
        self.block_heights.is_some()
    }

    /// Get total number of blocks
    pub fn block_count(&self) -> usize {
        self.get_blocks().len()
    }
}

/// Helper function to derive entropy from a seed phrase string
/// Used for creating WalletScanContext from seed phrases
pub fn derive_entropy_from_seed_phrase(seed_phrase: &str) -> LightweightWalletResult<[u8; 16]> {
    let encrypted_bytes = mnemonic_to_bytes(seed_phrase)?;
    let cipher_seed = CipherSeed::from_enciphered_bytes(&encrypted_bytes, None)?;
    let entropy = cipher_seed.entropy();
    
    let entropy_array: [u8; 16] = entropy.try_into()
        .map_err(|_| KeyManagementError::key_derivation_failed("Invalid entropy length"))?;
    
    Ok(entropy_array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enhanced_scan_config_creation() {
        let config = EnhancedScanConfig::new(100, 200);
        assert_eq!(config.from_block, 100);
        assert_eq!(config.to_block, 200);
        assert_eq!(config.total_blocks(), 101);
        assert!(!config.is_scanning_specific_blocks());
    }

    #[test]
    fn test_enhanced_scan_config_specific_blocks() {
        let blocks = vec![100, 150, 200];
        let config = EnhancedScanConfig::for_specific_blocks(blocks.clone());
        assert_eq!(config.from_block, 100);
        assert_eq!(config.to_block, 200);
        assert_eq!(config.get_blocks_to_scan(), blocks);
        assert!(config.is_scanning_specific_blocks());
    }

    #[test]
    fn test_output_format_parsing() {
        assert!(matches!("detailed".parse::<OutputFormat>().unwrap(), OutputFormat::Detailed));
        assert!(matches!("summary".parse::<OutputFormat>().unwrap(), OutputFormat::Summary));
        assert!(matches!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json));
        assert!("invalid".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn test_wallet_scan_context_view_key() {
        let view_key_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let context = WalletScanContext::from_view_key(view_key_hex).unwrap();
        assert!(context.is_view_only());
        assert!(!context.has_entropy());
        assert_eq!(context.scanning_mode(), "View-only");
    }

    #[test]
    fn test_block_height_range() {
        let range = BlockHeightRange::new(100, 200);
        assert_eq!(range.block_count(), 101);
        assert!(!range.is_specific_blocks());

        let specific = BlockHeightRange::for_specific_blocks(vec![100, 150, 200]);
        assert_eq!(specific.block_count(), 3);
        assert!(specific.is_specific_blocks());
    }
} 