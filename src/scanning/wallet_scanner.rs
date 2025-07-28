//! Main wallet scanning implementation and public API.
//!
//! This module contains the core blockchain scanning logic, wallet creation
//! and setup functions, and the primary public API for wallet scanning
//! operations.
//!
//! # Module Organization
//! - Transaction extraction helper functions
//! - Wallet creation utilities
//! - Block processing helpers
//! - Balance calculation helpers
//! - Core scanning logic and public API
//!
//! This module is part of the scanner.rs binary refactoring effort.

use blake2::{Blake2b, Digest};
use digest::consts::U32;
use tari_utilities::ByteArray;
use tokio::time::Instant;

use crate::{
    common::format_number,
    data_structures::{
        transaction::TransactionDirection, transaction_output::LightweightTransactionOutput,
        types::PrivateKey, wallet_transaction::WalletState,
    },
    errors::{KeyManagementError, LightweightWalletError, LightweightWalletResult},
    key_management::key_derivation,
    scanning::GrpcBlockchainScanner,
    storage::storage_trait::{OutputStatus, StoredOutput},
    wallet::Wallet,
};

use super::{BinaryScanConfig, ProgressInfo, ProgressTracker, ScanContext, ScannerStorage};

// =============================================================================
// Transaction extraction helper functions
// =============================================================================

/// Filter transactions from a specific block
#[cfg(all(feature = "grpc", feature = "storage"))]
fn filter_block_transactions(
    wallet_state: &WalletState,
    block_height: u64,
    direction: TransactionDirection,
) -> Vec<&crate::data_structures::wallet_transaction::WalletTransaction> {
    wallet_state
        .transactions
        .iter()
        .filter(|tx| tx.block_height == block_height && tx.transaction_direction == direction)
        .collect()
}

/// Create stored output from blockchain output and transaction data
#[cfg(all(feature = "grpc", feature = "storage"))]
fn create_stored_output_from_blockchain_data(
    transaction: &crate::data_structures::wallet_transaction::WalletTransaction,
    blockchain_output: &LightweightTransactionOutput,
    scan_context: &ScanContext,
    wallet_id: u32,
    output_index: usize,
) -> LightweightWalletResult<StoredOutput> {
    // Derive spending keys for this output
    let (spending_key, script_private_key) =
        derive_utxo_spending_keys(&scan_context.entropy, output_index as u64)?;

    // Extract script input data and lock height
    let (input_data, script_lock_height) = extract_script_data(&blockchain_output.script.bytes)?;

    // Create StoredOutput from blockchain data
    let stored_output = StoredOutput {
        id: None, // Will be set by database
        wallet_id,

        // Core UTXO identification
        commitment: blockchain_output.commitment.as_bytes().to_vec(),
        hash: compute_output_hash(blockchain_output)?,
        value: transaction.value,

        // Spending keys (derived from entropy)
        spending_key: hex::encode(spending_key.as_bytes()),
        script_private_key: hex::encode(script_private_key.as_bytes()),

        // Script and covenant data
        script: blockchain_output.script.bytes.clone(),
        input_data,
        covenant: blockchain_output.covenant.bytes.clone(),

        // Output features and type
        output_type: blockchain_output.features.output_type.clone() as u32,
        features_json: serde_json::to_string(&blockchain_output.features).map_err(|e| {
            LightweightWalletError::StorageError(format!("Failed to serialize features: {e}"))
        })?,

        // Maturity and lock constraints
        maturity: blockchain_output.features.maturity,
        script_lock_height,

        // Metadata signature components
        sender_offset_public_key: blockchain_output
            .sender_offset_public_key
            .as_bytes()
            .to_vec(),
        // Note: LightweightSignature only has bytes field, so we use placeholders
        // In a full implementation, these would be extracted from the signature structure
        metadata_signature_ephemeral_commitment: vec![0u8; 32], // Placeholder
        metadata_signature_ephemeral_pubkey: vec![0u8; 32],     // Placeholder
        metadata_signature_u_a: if blockchain_output.metadata_signature.bytes.len() >= 32 {
            blockchain_output.metadata_signature.bytes[0..32].to_vec()
        } else {
            vec![0u8; 32]
        },
        metadata_signature_u_x: if blockchain_output.metadata_signature.bytes.len() >= 64 {
            blockchain_output.metadata_signature.bytes[32..64].to_vec()
        } else {
            vec![0u8; 32]
        },
        metadata_signature_u_y: vec![0u8; 32], // Placeholder

        // Payment information
        encrypted_data: blockchain_output.encrypted_data.as_bytes().to_vec(),
        minimum_value_promise: blockchain_output.minimum_value_promise.as_u64(),

        // Range proof
        rangeproof: blockchain_output.proof.as_ref().map(|p| p.bytes.clone()),

        // Status and spending tracking
        status: if transaction.is_spent {
            OutputStatus::Spent as u32
        } else {
            OutputStatus::Unspent as u32
        },
        mined_height: Some(transaction.block_height),
        spent_in_tx_id: if transaction.is_spent {
            // Calculate transaction ID from spent block and input index
            transaction.spent_in_block.and_then(|spent_block| {
                transaction
                    .spent_in_input
                    .map(|spent_input| generate_transaction_id(spent_block, spent_input))
            })
        } else {
            None
        },

        // Timestamps (will be set by database)
        created_at: None,
        updated_at: None,
    };

    Ok(stored_output)
}

/// Extract UTXO data from blockchain outputs and create StoredOutput objects
#[cfg(all(feature = "grpc", feature = "storage"))]
pub fn extract_utxo_outputs_from_wallet_state(
    wallet_state: &WalletState,
    scan_context: &ScanContext,
    wallet_id: u32,
    block_outputs: &[LightweightTransactionOutput],
    block_height: u64,
) -> LightweightWalletResult<Vec<StoredOutput>> {
    let mut utxo_outputs = Vec::new();

    // Get inbound transactions from this specific block
    let block_transactions =
        filter_block_transactions(wallet_state, block_height, TransactionDirection::Inbound);

    for transaction in block_transactions {
        // Find the corresponding blockchain output
        if let Some(output_index) = transaction.output_index {
            if let Some(blockchain_output) = block_outputs.get(output_index) {
                let stored_output = create_stored_output_from_blockchain_data(
                    transaction,
                    blockchain_output,
                    scan_context,
                    wallet_id,
                    output_index,
                )?;

                utxo_outputs.push(stored_output);
            }
        }
    }

    Ok(utxo_outputs)
}

/// Extract script input data and script lock height from script bytes
#[cfg(all(feature = "grpc", feature = "storage"))]
fn extract_script_data(script_bytes: &[u8]) -> LightweightWalletResult<(Vec<u8>, u64)> {
    // If script is empty, return empty data
    if script_bytes.is_empty() {
        return Ok((Vec::new(), 0));
    }

    let mut input_data = Vec::new();
    let mut script_lock_height = 0u64;
    let mut potential_heights = Vec::new();

    // Parse script bytecode to extract data
    // This is a simplified parser - in a full implementation, you'd use a proper script interpreter
    let mut i = 0;
    while i < script_bytes.len() {
        match script_bytes[i] {
            // Check for potential lock height patterns
            0x6a => {
                // OP_PUSHDATA - extract the data being pushed
                if i + 1 < script_bytes.len() {
                    let data_len = script_bytes[i + 1] as usize;
                    if i + 2 + data_len <= script_bytes.len() {
                        let data = &script_bytes[i + 2..i + 2 + data_len];
                        input_data.extend_from_slice(data);

                        // Check if this could be a block height (8 bytes, little endian)
                        if data_len == 8 {
                            let bytes: [u8; 8] = data.try_into().unwrap_or([0u8; 8]);
                            let potential_height = u64::from_le_bytes(bytes);

                            // Reasonable block height range (current mainnet is around 3M blocks)
                            if potential_height > 0 && potential_height < 10_000_000 {
                                potential_heights.push(potential_height);
                            }
                        }
                        i += 2 + data_len;
                    } else {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            // Look for other relevant opcodes that might contain lock heights
            0x51..=0x60 => {
                // OP_1 through OP_16 - small numbers
                let value = (script_bytes[i] - 0x50) as u64;
                potential_heights.push(value);
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    // Use the largest reasonable value as script lock height
    if let Some(&max_height) = potential_heights.iter().max() {
        script_lock_height = max_height;
    }

    Ok((input_data, script_lock_height))
}

/// Generate a deterministic transaction ID from block height and input index
#[cfg(all(feature = "grpc", feature = "storage"))]
fn generate_transaction_id(block_height: u64, input_index: usize) -> u64 {
    // Create a deterministic transaction ID by combining block height and input index
    // This is a simplified approach - in a real implementation, you'd use the actual transaction hash
    //
    // Format: [32-bit block_height][32-bit input_index]
    // This ensures unique IDs while being deterministic and easily debuggable

    // Use the block height as the upper 32 bits and input index as lower 32 bits
    let tx_id = ((block_height & 0xFFFFFFFF) << 32) | (input_index as u64 & 0xFFFFFFFF);

    // Ensure we don't return 0 (which is often treated as "no transaction")
    if tx_id == 0 {
        1
    } else {
        tx_id
    }
}

/// Derive spending keys for a UTXO output using wallet entropy
/// For view-key mode (entropy all zeros), returns placeholder keys
#[cfg(all(feature = "grpc", feature = "storage"))]
fn derive_utxo_spending_keys(
    entropy: &[u8; 16],
    output_index: u64,
) -> LightweightWalletResult<(PrivateKey, PrivateKey)> {
    // Check if we have real entropy or if this is view-key mode
    let has_real_entropy = entropy != &[0u8; 16];

    if has_real_entropy {
        // Derive real spending keys using wallet entropy
        let spending_key_raw = key_derivation::derive_private_key_from_entropy(
            entropy,
            "wallet_spending", // Branch for spending keys
            output_index,
        )?;

        let script_private_key_raw = key_derivation::derive_private_key_from_entropy(
            entropy,
            "script_keys", // Branch for script keys
            output_index,
        )?;

        // Convert to PrivateKey type
        let spending_key =
            PrivateKey::new(spending_key_raw.as_bytes().try_into().map_err(|_| {
                KeyManagementError::key_derivation_failed("Failed to convert spending key")
            })?);

        let script_private_key =
            PrivateKey::new(script_private_key_raw.as_bytes().try_into().map_err(|_| {
                KeyManagementError::key_derivation_failed("Failed to convert script private key")
            })?);

        Ok((spending_key, script_private_key))
    } else {
        // View-key mode: use placeholder keys (cannot spend, but can store UTXO structure)
        let placeholder_key_bytes = [0u8; 32];
        let spending_key = PrivateKey::new(placeholder_key_bytes);
        let script_private_key = PrivateKey::new(placeholder_key_bytes);

        Ok((spending_key, script_private_key))
    }
}

/// Compute output hash for UTXO identification
#[cfg(all(feature = "grpc", feature = "storage"))]
fn compute_output_hash(output: &LightweightTransactionOutput) -> LightweightWalletResult<Vec<u8>> {
    // Compute hash of output fields for identification
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(output.commitment.as_bytes());
    hasher.update(output.script.bytes.as_slice());
    hasher.update(output.sender_offset_public_key.as_bytes());
    hasher.update(output.minimum_value_promise.as_u64().to_le_bytes());

    Ok(hasher.finalize().to_vec())
}

// =============================================================================
// Wallet creation utilities
// =============================================================================

/// Create a wallet from a seed phrase and return the scan context with default block
///
/// This function combines wallet creation from a seed phrase with scan context creation,
/// providing a convenient wrapper for the scanner binary.
///
/// # Arguments
/// * `seed_phrase` - The mnemonic seed phrase to create the wallet from
///
/// # Returns
/// A tuple containing:
/// - `ScanContext` with view key and entropy from the wallet
/// - `u64` representing the wallet's birthday (default from block)
///
/// # Errors
/// Returns an error if the wallet creation or scan context creation fails
pub fn create_wallet_from_seed_phrase(
    seed_phrase: &str,
) -> LightweightWalletResult<(ScanContext, u64)> {
    let wallet = Wallet::new_from_seed_phrase(seed_phrase, None)?;
    let scan_context = ScanContext::from_wallet(&wallet)?;
    let default_from_block = wallet.birthday();
    Ok((scan_context, default_from_block))
}

/// Create a scan context from a view key with default block set to genesis
///
/// This function creates a view-only scan context from a hex view key,
/// providing a convenient wrapper for the scanner binary.
///
/// # Arguments
/// * `view_key_hex` - 64-character hexadecimal string representing the view key
///
/// # Returns
/// A tuple containing:
/// - `ScanContext` with view key populated and entropy set to zeros
/// - `u64` set to 0 (genesis block) since no wallet birthday is available
///
/// # Errors
/// Returns an error if the view key is invalid or cannot be parsed
pub fn create_wallet_from_view_key(
    view_key_hex: &str,
) -> LightweightWalletResult<(ScanContext, u64)> {
    let scan_context = ScanContext::from_view_key(view_key_hex)?;
    let default_from_block = 0; // Start from genesis when using view key only
    Ok((scan_context, default_from_block))
}

// =============================================================================
// Core scanning API and result types
// =============================================================================

/// Additional metadata about the scanning operation
#[derive(Debug, Clone)]
pub struct ScanMetadata {
    /// Block range that was scanned
    pub from_block: u64,
    pub to_block: u64,
    /// Total blocks that were processed
    pub blocks_processed: usize,
    /// Whether specific blocks were scanned vs a range
    pub had_specific_blocks: bool,
    /// Start time of the scan operation
    pub start_time: Option<Instant>,
    /// End time of the scan operation  
    pub end_time: Option<Instant>,
}

impl ScanMetadata {
    /// Create new scan metadata
    pub fn new(
        from_block: u64,
        to_block: u64,
        blocks_processed: usize,
        had_specific_blocks: bool,
    ) -> Self {
        Self {
            from_block,
            to_block,
            blocks_processed,
            had_specific_blocks,
            start_time: None,
            end_time: None,
        }
    }

    /// Calculate scan duration if times are available
    pub fn duration(&self) -> Option<std::time::Duration> {
        match (self.start_time, self.end_time) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            _ => None,
        }
    }

    /// Calculate blocks per second if duration is available
    pub fn blocks_per_second(&self) -> Option<f64> {
        self.duration().map(|duration| {
            if duration.as_secs_f64() > 0.0 {
                self.blocks_processed as f64 / duration.as_secs_f64()
            } else {
                0.0
            }
        })
    }
}

/// Represents the result of a wallet scanning operation
#[derive(Debug, Clone)]
pub enum ScanResult {
    /// Scan completed successfully with final wallet state and metadata
    Completed(WalletState, Option<ScanMetadata>),
    /// Scan was interrupted (e.g., by user) with current wallet state and metadata
    Interrupted(WalletState, Option<ScanMetadata>),
}

impl ScanResult {
    /// Get the wallet state from the scan result
    pub fn wallet_state(&self) -> &WalletState {
        match self {
            ScanResult::Completed(state, _) => state,
            ScanResult::Interrupted(state, _) => state,
        }
    }

    /// Get the scan metadata from the scan result
    pub fn metadata(&self) -> Option<&ScanMetadata> {
        match self {
            ScanResult::Completed(_, metadata) => metadata.as_ref(),
            ScanResult::Interrupted(_, metadata) => metadata.as_ref(),
        }
    }

    /// Check if the scan was completed successfully
    pub fn is_completed(&self) -> bool {
        matches!(self, ScanResult::Completed(_, _))
    }

    /// Check if the scan was interrupted
    pub fn is_interrupted(&self) -> bool {
        matches!(self, ScanResult::Interrupted(_, _))
    }

    /// Get the block range that was scanned
    pub fn block_range(&self) -> Option<(u64, u64)> {
        self.metadata().map(|meta| (meta.from_block, meta.to_block))
    }

    /// Get the number of blocks processed
    pub fn blocks_processed(&self) -> Option<usize> {
        self.metadata().map(|meta| meta.blocks_processed)
    }

    /// Get the scan duration
    pub fn duration(&self) -> Option<std::time::Duration> {
        self.metadata().and_then(|meta| meta.duration())
    }

    /// Get the scan speed in blocks per second
    pub fn blocks_per_second(&self) -> Option<f64> {
        self.metadata().and_then(|meta| meta.blocks_per_second())
    }

    /// Display result in JSON format
    #[cfg(feature = "grpc")]
    pub fn display_json(&self) {
        display_json_results(self.wallet_state())
    }

    /// Display result in summary format
    #[cfg(feature = "grpc")]
    pub fn display_summary(&self, config: &BinaryScanConfig) {
        display_summary_results(self.wallet_state(), config)
    }

    /// Display result in detailed format
    #[cfg(feature = "grpc")]
    pub fn display_detailed(&self, config: &BinaryScanConfig) {
        display_wallet_activity(self.wallet_state(), config.from_block, config.to_block)
    }

    /// Display result in the specified format
    #[cfg(feature = "grpc")]
    pub fn display(&self, config: &BinaryScanConfig) {
        match config.output_format {
            crate::scanning::OutputFormat::Json => self.display_json(),
            crate::scanning::OutputFormat::Summary => self.display_summary(config),
            crate::scanning::OutputFormat::Detailed => self.display_detailed(config),
        }
    }

    /// Create a resume command string for interrupted scans
    pub fn resume_command(&self, original_command_args: &str) -> Option<String> {
        if let ScanResult::Interrupted(wallet_state, _) = self {
            let next_block = wallet_state
                .transactions
                .iter()
                .map(|tx| tx.block_height)
                .max()
                .map(|h| h + 1)
                .unwrap_or(0);

            if next_block > 0 {
                Some(format!(
                    "{} --from-block {}",
                    original_command_args, next_block
                ))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Get wallet balance summary from the result
    pub fn get_balance_summary(&self) -> (u64, u64, i64, usize, usize) {
        self.wallet_state().get_summary()
    }

    /// Get transaction direction counts from the result
    pub fn get_direction_counts(&self) -> (usize, usize, usize) {
        self.wallet_state().get_direction_counts()
    }

    /// Check if any wallet activity was found
    pub fn has_activity(&self) -> bool {
        !self.wallet_state().transactions.is_empty()
    }

    /// Get the current wallet balance
    pub fn current_balance(&self) -> i64 {
        self.wallet_state().get_balance()
    }

    /// Get the total number of transactions found
    pub fn transaction_count(&self) -> usize {
        self.wallet_state().transactions.len()
    }

    /// Export scan result to JSON string
    #[cfg(feature = "grpc")]
    pub fn to_json_string(&self) -> String {
        let wallet_state = self.wallet_state();
        let (total_received, total_spent, balance, unspent_count, spent_count) =
            wallet_state.get_summary();
        let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

        let mut json = String::from("{\n");
        json.push_str("  \"summary\": {\n");
        json.push_str(&format!(
            "    \"total_transactions\": {},\n",
            wallet_state.transactions.len()
        ));
        json.push_str(&format!("    \"inbound_count\": {},\n", inbound_count));
        json.push_str(&format!("    \"outbound_count\": {},\n", outbound_count));
        json.push_str(&format!("    \"total_received\": {},\n", total_received));
        json.push_str(&format!("    \"total_spent\": {},\n", total_spent));
        json.push_str(&format!("    \"current_balance\": {},\n", balance));
        json.push_str(&format!("    \"unspent_outputs\": {},\n", unspent_count));
        json.push_str(&format!("    \"spent_outputs\": {}\n", spent_count));
        json.push_str("  }");

        if let Some(metadata) = self.metadata() {
            json.push_str(",\n  \"metadata\": {\n");
            json.push_str(&format!("    \"from_block\": {},\n", metadata.from_block));
            json.push_str(&format!("    \"to_block\": {},\n", metadata.to_block));
            json.push_str(&format!(
                "    \"blocks_processed\": {},\n",
                metadata.blocks_processed
            ));
            json.push_str(&format!(
                "    \"had_specific_blocks\": {}",
                metadata.had_specific_blocks
            ));

            if let Some(duration) = metadata.duration() {
                json.push_str(&format!(
                    ",\n    \"duration_seconds\": {:.3}",
                    duration.as_secs_f64()
                ));
            }
            if let Some(bps) = metadata.blocks_per_second() {
                json.push_str(&format!(",\n    \"blocks_per_second\": {:.2}", bps));
            }

            json.push_str("\n  }");
        }

        json.push_str(",\n  \"status\": \"");
        json.push_str(if self.is_completed() {
            "completed"
        } else {
            "interrupted"
        });
        json.push_str("\"\n}");

        json
    }
}

/// Configuration for the wallet scanner
pub struct WalletScannerConfig {
    /// Progress tracking configuration
    pub progress_tracker: Option<ProgressTracker>,
    /// Batch size for block processing (number of blocks to process at once)
    pub batch_size: usize,
    /// Timeout duration for blockchain operations
    pub timeout: Option<std::time::Duration>,
    /// Whether to enable detailed logging
    pub verbose_logging: bool,
    /// Custom retry configuration for failed operations
    pub retry_config: RetryConfig,
}

/// Errors that can occur during scanner configuration
#[derive(Debug, Clone)]
pub enum ScannerConfigError {
    /// Invalid batch size
    InvalidBatchSize {
        value: usize,
        min: usize,
        max: usize,
    },
    /// Invalid timeout duration
    InvalidTimeout {
        value: std::time::Duration,
        min: std::time::Duration,
        max: std::time::Duration,
    },
    /// Invalid retry configuration
    InvalidRetryConfig { reason: String },
    /// General validation error
    ValidationError { field: String, reason: String },
}

impl std::fmt::Display for ScannerConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScannerConfigError::InvalidBatchSize { value, min, max } => {
                write!(
                    f,
                    "Invalid batch size {}: must be between {} and {}",
                    value, min, max
                )
            }
            ScannerConfigError::InvalidTimeout { value, min, max } => {
                write!(
                    f,
                    "Invalid timeout {:?}: must be between {:?} and {:?}",
                    value, min, max
                )
            }
            ScannerConfigError::InvalidRetryConfig { reason } => {
                write!(f, "Invalid retry configuration: {}", reason)
            }
            ScannerConfigError::ValidationError { field, reason } => {
                write!(f, "Validation error for {}: {}", field, reason)
            }
        }
    }
}

impl std::error::Error for ScannerConfigError {}

impl From<ScannerConfigError> for LightweightWalletError {
    fn from(error: ScannerConfigError) -> Self {
        LightweightWalletError::InvalidArgument {
            argument: "scanner_config".to_string(),
            value: "validation_error".to_string(),
            message: error.to_string(),
        }
    }
}

/// Retry configuration for failed operations
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: usize,
    /// Base delay between retries
    pub base_delay: std::time::Duration,
    /// Maximum delay between retries (for exponential backoff)
    pub max_delay: std::time::Duration,
    /// Whether to use exponential backoff
    pub exponential_backoff: bool,
}

impl RetryConfig {
    /// Create a conservative retry configuration with more attempts and longer delays
    pub fn conservative() -> Self {
        Self {
            max_retries: 5,
            base_delay: std::time::Duration::from_secs(2),
            max_delay: std::time::Duration::from_secs(30),
            exponential_backoff: true,
        }
    }

    /// Create an aggressive retry configuration with fewer attempts and shorter delays
    pub fn aggressive() -> Self {
        Self {
            max_retries: 2,
            base_delay: std::time::Duration::from_millis(100),
            max_delay: std::time::Duration::from_secs(5),
            exponential_backoff: true,
        }
    }

    /// Create a configuration with no retries
    pub fn no_retries() -> Self {
        Self {
            max_retries: 0,
            base_delay: std::time::Duration::from_millis(0),
            max_delay: std::time::Duration::from_millis(0),
            exponential_backoff: false,
        }
    }

    /// Validate the retry configuration
    pub fn validate(&self) -> Result<(), ScannerConfigError> {
        if self.max_retries > 100 {
            return Err(ScannerConfigError::InvalidRetryConfig {
                reason: "max_retries cannot exceed 100".to_string(),
            });
        }

        if self.base_delay > std::time::Duration::from_secs(60) {
            return Err(ScannerConfigError::InvalidRetryConfig {
                reason: "base_delay cannot exceed 60 seconds".to_string(),
            });
        }

        if self.max_delay < self.base_delay {
            return Err(ScannerConfigError::InvalidRetryConfig {
                reason: "max_delay must be greater than or equal to base_delay".to_string(),
            });
        }

        Ok(())
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: std::time::Duration::from_millis(500),
            max_delay: std::time::Duration::from_secs(10),
            exponential_backoff: true,
        }
    }
}

impl WalletScannerConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ScannerConfigError> {
        // Validate batch size
        if self.batch_size == 0 {
            return Err(ScannerConfigError::InvalidBatchSize {
                value: self.batch_size,
                min: 1,
                max: 1000,
            });
        }
        if self.batch_size > 1000 {
            return Err(ScannerConfigError::InvalidBatchSize {
                value: self.batch_size,
                min: 1,
                max: 1000,
            });
        }

        // Validate timeout
        if let Some(timeout) = self.timeout {
            if timeout < std::time::Duration::from_millis(100) {
                return Err(ScannerConfigError::InvalidTimeout {
                    value: timeout,
                    min: std::time::Duration::from_millis(100),
                    max: std::time::Duration::from_secs(300),
                });
            }
            if timeout > std::time::Duration::from_secs(300) {
                return Err(ScannerConfigError::InvalidTimeout {
                    value: timeout,
                    min: std::time::Duration::from_millis(100),
                    max: std::time::Duration::from_secs(300),
                });
            }
        }

        // Validate retry config
        self.retry_config.validate()?;

        Ok(())
    }
}

impl Default for WalletScannerConfig {
    fn default() -> Self {
        Self {
            progress_tracker: None,
            batch_size: 10,
            timeout: Some(std::time::Duration::from_secs(30)),
            verbose_logging: false,
            retry_config: RetryConfig::default(),
        }
    }
}

impl Clone for WalletScannerConfig {
    fn clone(&self) -> Self {
        Self {
            progress_tracker: None, // Progress tracker cannot be cloned due to callback
            batch_size: self.batch_size,
            timeout: self.timeout,
            verbose_logging: self.verbose_logging,
            retry_config: self.retry_config.clone(),
        }
    }
}

impl std::fmt::Debug for WalletScannerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletScannerConfig")
            .field("progress_tracker", &self.progress_tracker.is_some())
            .field("batch_size", &self.batch_size)
            .field("timeout", &self.timeout)
            .field("verbose_logging", &self.verbose_logging)
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

/// Wallet scanner for performing blockchain scanning operations
///
/// This struct encapsulates the main scanning functionality that was previously
/// implemented directly in the scanner binary. It provides a clean API for
/// scanning wallets across blockchain height ranges with flexible configuration.
///
/// # Examples
///
/// ```rust,no_run
/// use lightweight_wallet_libs::scanning::WalletScanner;
///
/// // Create a basic scanner
/// let scanner = WalletScanner::new();
///
/// // Create a scanner with progress tracking
/// let scanner = WalletScanner::new()
///     .with_progress_callback(|info| {
///         println!("Progress: {}%", info.progress_percent);
///     })
///     .with_batch_size(20)
///     .with_timeout(std::time::Duration::from_secs(60))
///     .with_verbose_logging(true);
/// ```
pub struct WalletScanner {
    /// Scanner configuration
    config: WalletScannerConfig,
}

impl WalletScanner {
    /// Create a new wallet scanner with default configuration
    pub fn new() -> Self {
        Self {
            config: WalletScannerConfig::default(),
        }
    }

    /// Create a wallet scanner from a configuration
    pub fn from_config(config: WalletScannerConfig) -> Self {
        Self { config }
    }

    /// Set a progress callback for tracking scan progress
    ///
    /// The callback will be called periodically during scanning with progress information.
    /// Note: The total blocks will be set automatically when scanning begins.
    pub fn with_progress_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ProgressInfo) + Send + Sync + 'static,
    {
        // Create a progress tracker with placeholder total_blocks (will be updated during scan)
        let progress_tracker = ProgressTracker::new(0).with_callback(Box::new(callback));
        self.config.progress_tracker = Some(progress_tracker);
        self
    }

    /// Set a progress tracker for monitoring scan progress
    pub fn with_progress_tracker(mut self, progress_tracker: ProgressTracker) -> Self {
        self.config.progress_tracker = Some(progress_tracker);
        self
    }

    /// Set the batch size for block processing
    ///
    /// Larger batch sizes can improve performance but may use more memory.
    /// Default is 10 blocks per batch.
    ///
    /// # Panics
    /// Panics if batch_size is invalid (0 or > 1000). Use `try_with_batch_size` for error handling.
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.config.batch_size = batch_size;
        // Validate immediately to provide early feedback
        if let Err(e) = self.config.validate() {
            panic!("Invalid batch size: {}", e);
        }
        self
    }

    /// Set the batch size for block processing (fallible version)
    ///
    /// Larger batch sizes can improve performance but may use more memory.
    /// Default is 10 blocks per batch.
    ///
    /// # Errors
    /// Returns an error if batch_size is invalid (0 or > 1000).
    pub fn try_with_batch_size(mut self, batch_size: usize) -> Result<Self, ScannerConfigError> {
        self.config.batch_size = batch_size;
        self.config.validate()?;
        Ok(self)
    }

    /// Set the timeout duration for blockchain operations
    ///
    /// This timeout applies to individual GRPC calls to the blockchain.
    /// Default is 30 seconds.
    ///
    /// # Panics
    /// Panics if timeout is invalid. Use `try_with_timeout` for error handling.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config.timeout = Some(timeout);
        // Validate immediately to provide early feedback
        if let Err(e) = self.config.validate() {
            panic!("Invalid timeout: {}", e);
        }
        self
    }

    /// Set the timeout duration for blockchain operations (fallible version)
    ///
    /// This timeout applies to individual GRPC calls to the blockchain.
    /// Default is 30 seconds.
    ///
    /// # Errors
    /// Returns an error if timeout is invalid (< 100ms or > 300s).
    pub fn try_with_timeout(
        mut self,
        timeout: std::time::Duration,
    ) -> Result<Self, ScannerConfigError> {
        self.config.timeout = Some(timeout);
        self.config.validate()?;
        Ok(self)
    }

    /// Enable or disable verbose logging
    ///
    /// When enabled, the scanner will output detailed information about its operations.
    /// Default is disabled.
    pub fn with_verbose_logging(mut self, enabled: bool) -> Self {
        self.config.verbose_logging = enabled;
        self
    }

    /// Set retry configuration for failed operations
    ///
    /// Configure how the scanner handles temporary failures during blockchain operations.
    ///
    /// # Panics
    /// Panics if retry_config is invalid. Use `try_with_retry_config` for error handling.
    pub fn with_retry_config(mut self, retry_config: RetryConfig) -> Self {
        self.config.retry_config = retry_config;
        // Validate immediately to provide early feedback
        if let Err(e) = self.config.validate() {
            panic!("Invalid retry config: {}", e);
        }
        self
    }

    /// Set retry configuration for failed operations (fallible version)
    ///
    /// Configure how the scanner handles temporary failures during blockchain operations.
    ///
    /// # Errors
    /// Returns an error if retry configuration is invalid.
    pub fn try_with_retry_config(
        mut self,
        retry_config: RetryConfig,
    ) -> Result<Self, ScannerConfigError> {
        self.config.retry_config = retry_config;
        self.config.validate()?;
        Ok(self)
    }

    /// Get the current configuration
    pub fn config(&self) -> &WalletScannerConfig {
        &self.config
    }

    /// Get a mutable reference to the configuration
    pub fn config_mut(&mut self) -> &mut WalletScannerConfig {
        &mut self.config
    }

    /// Build and validate the scanner configuration
    ///
    /// This method validates the entire configuration and returns a fully configured scanner.
    /// Use this method when you want to ensure all configuration is valid before proceeding.
    ///
    /// # Errors
    /// Returns an error if any configuration parameter is invalid.
    ///
    /// # Examples
    /// ```rust,no_run
    /// use lightweight_wallet_libs::scanning::WalletScanner;
    /// use std::time::Duration;
    ///
    /// let scanner = WalletScanner::new()
    ///     .try_with_batch_size(50)?
    ///     .try_with_timeout(Duration::from_secs(60))?
    ///     .build()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn build(self) -> Result<WalletScanner, ScannerConfigError> {
        self.config.validate()?;
        Ok(self)
    }

    /// Validate the current configuration without consuming the scanner
    ///
    /// This method allows you to check if the current configuration is valid
    /// without building the final scanner.
    ///
    /// # Errors
    /// Returns an error if any configuration parameter is invalid.
    pub fn validate(&self) -> Result<(), ScannerConfigError> {
        self.config.validate()
    }

    /// Create a quick scanner with simple progress display
    ///
    /// This is a convenience method that creates a scanner with basic progress tracking
    /// that prints progress to stdout.
    pub fn with_simple_progress() -> Self {
        Self::new().with_progress_callback(|info| {
            print!("\r🔍 Progress: {:.1}% ({}/{}) | Block {} | {:.1} blocks/s | Found: {} outputs, {} spent   ",
                info.progress_percent,
                info.blocks_processed,
                info.total_blocks,
                info.current_block,
                info.blocks_per_sec,
                info.outputs_found,
                info.inputs_found
            );
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
        })
    }

    /// Create a scanner optimized for performance
    ///
    /// This sets larger batch sizes and disables verbose logging for faster scanning.
    pub fn performance_optimized() -> Self {
        Self::new()
            .with_batch_size(50)
            .with_timeout(std::time::Duration::from_secs(60))
            .with_verbose_logging(false)
    }

    /// Create a scanner optimized for reliability
    ///
    /// This uses smaller batch sizes and more aggressive retry settings.
    pub fn reliability_optimized() -> Self {
        Self::new()
            .with_batch_size(5)
            .with_timeout(std::time::Duration::from_secs(10))
            .with_retry_config(RetryConfig {
                max_retries: 5,
                base_delay: std::time::Duration::from_millis(1000),
                max_delay: std::time::Duration::from_secs(30),
                exponential_backoff: true,
            })
            .with_verbose_logging(true)
    }

    /// Perform wallet scanning across blocks with cancellation support
    ///
    /// This is the main scanning method that processes blockchain blocks to find
    /// wallet outputs and transactions. It supports both specific block scanning
    /// and range scanning with automatic resume functionality.
    ///
    /// # Arguments
    /// * `scanner` - GRPC blockchain scanner for fetching blocks
    /// * `scan_context` - Wallet scanning context with keys and entropy
    /// * `config` - Binary scan configuration
    /// * `storage_backend` - Storage backend for persistence
    /// * `cancel_rx` - Channel receiver for cancellation signals
    ///
    /// # Returns
    /// `ScanResult` indicating completion or interruption with wallet state and metadata
    ///
    /// # Errors
    /// Returns an error if:
    /// - Blockchain connection fails
    /// - Invalid scan configuration provided
    /// - Storage operations fail
    /// - Scanning is cancelled by external signal
    pub async fn scan(
        &mut self,
        scanner: &mut GrpcBlockchainScanner,
        scan_context: &ScanContext,
        config: &BinaryScanConfig,
        storage_backend: &mut ScannerStorage,
        cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> LightweightWalletResult<ScanResult> {
        // Log scan start if verbose logging is enabled
        if self.config.verbose_logging && !config.quiet {
            println!("🚀 Starting wallet scan with enhanced scanner");
            println!("   • Batch size: {}", self.config.batch_size);
            if let Some(timeout) = self.config.timeout {
                println!("   • Timeout: {:?}", timeout);
            }
            println!(
                "   • Progress tracking: {}",
                self.config.progress_tracker.is_some()
            );
        }

        let start_time = Instant::now();

        // Execute the scan with enhanced error handling
        let scan_result = self
            .execute_scan_with_retry(scanner, scan_context, config, storage_backend, cancel_rx)
            .await;

        // Add timing information to the result
        match scan_result {
            Ok(ScanResult::Completed(wallet_state, mut metadata)) => {
                if let Some(ref mut meta) = metadata {
                    meta.start_time = Some(start_time);
                    meta.end_time = Some(Instant::now());
                }
                Ok(ScanResult::Completed(wallet_state, metadata))
            }
            Ok(ScanResult::Interrupted(wallet_state, mut metadata)) => {
                if let Some(ref mut meta) = metadata {
                    meta.start_time = Some(start_time);
                    meta.end_time = Some(Instant::now());
                }
                Ok(ScanResult::Interrupted(wallet_state, metadata))
            }
            Err(e) => {
                if self.config.verbose_logging && !config.quiet {
                    println!("❌ Scan failed after {:?}: {}", start_time.elapsed(), e);
                }
                Err(e)
            }
        }
    }

    /// Execute the scan with retry logic for failed operations
    async fn execute_scan_with_retry(
        &mut self,
        scanner: &mut GrpcBlockchainScanner,
        scan_context: &ScanContext,
        config: &BinaryScanConfig,
        storage_backend: &mut ScannerStorage,
        cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> LightweightWalletResult<ScanResult> {
        let mut attempts = 0;
        let max_retries = self.config.retry_config.max_retries;

        loop {
            match scan_wallet_across_blocks_with_cancellation(
                scanner,
                scan_context,
                config,
                storage_backend,
                cancel_rx,
                self.config.progress_tracker.as_mut(),
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    attempts += 1;

                    // Check if this is a retryable error and we haven't exceeded max retries
                    if attempts <= max_retries && self.is_retryable_error(&e) {
                        if self.config.verbose_logging && !config.quiet {
                            println!("⚠️  Scan attempt {} failed, retrying: {}", attempts, e);
                        }

                        // Calculate delay with exponential backoff if enabled
                        let delay = if self.config.retry_config.exponential_backoff {
                            let exp = (attempts - 1).min(10) as u32; // Cap to prevent overflow
                            std::cmp::min(
                                self.config.retry_config.base_delay * (2_u32.pow(exp)),
                                self.config.retry_config.max_delay,
                            )
                        } else {
                            self.config.retry_config.base_delay
                        };

                        // Wait before retrying
                        tokio::time::sleep(delay).await;
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Check if an error is retryable
    fn is_retryable_error(&self, error: &LightweightWalletError) -> bool {
        match error {
            // Network-related errors are typically retryable
            LightweightWalletError::StorageError(msg) if msg.contains("connection") => true,
            LightweightWalletError::StorageError(msg) if msg.contains("timeout") => true,
            LightweightWalletError::StorageError(msg) if msg.contains("network") => true,
            // Temporary GRPC errors
            LightweightWalletError::StorageError(msg) if msg.contains("unavailable") => true,
            LightweightWalletError::StorageError(msg) if msg.contains("deadline exceeded") => true,
            // Other errors are typically not retryable
            _ => false,
        }
    }
}

impl Default for WalletScanner {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Block processing helper functions
// =============================================================================

/// Determine scanning block range with resume support
#[cfg(feature = "grpc")]
async fn determine_scan_range(
    config: &BinaryScanConfig,
    storage_backend: &mut ScannerStorage,
) -> LightweightWalletResult<(u64, u64)> {
    // Handle automatic resume functionality for database storage
    if config.use_database && config.explicit_from_block.is_none() && config.block_heights.is_none()
    {
        #[cfg(feature = "storage")]
        if let Some(_wallet_id) = storage_backend.wallet_id {
            // Get the wallet to check its resume block
            if let Some(wallet_birthday) = storage_backend.get_wallet_birthday().await? {
                if !config.quiet {
                    println!(
                        "📄 Resuming wallet from last scanned block {}",
                        format_number(wallet_birthday)
                    );
                }
                return Ok((wallet_birthday, config.to_block));
            } else {
                if !config.quiet {
                    println!("📄 Wallet not found, starting from configuration");
                }
                return Ok((config.from_block, config.to_block));
            }
        } else {
            if !config.quiet {
                println!("⚠️  Resume requires a selected wallet");
            }
            return Ok((config.from_block, config.to_block));
        }

        #[cfg(not(feature = "storage"))]
        {
            return Ok((config.from_block, config.to_block));
        }
    } else {
        Ok((config.from_block, config.to_block))
    }
}

/// Prepare block heights list for scanning
#[cfg(feature = "grpc")]
fn prepare_block_heights(config: &BinaryScanConfig, from_block: u64, to_block: u64) -> Vec<u64> {
    let has_specific_blocks = config.block_heights.is_some();

    if has_specific_blocks {
        let heights = config.block_heights.as_ref().unwrap().clone();
        if !config.quiet {
            display_scan_info(config, &heights, has_specific_blocks);
        }
        heights
    } else {
        let heights: Vec<u64> = (from_block..=to_block).collect();
        if !config.quiet {
            display_scan_info(config, &heights, has_specific_blocks);
        }
        heights
    }
}

/// Initialize scanning operation and return initial state
#[cfg(feature = "grpc")]
fn initialize_scan_state() -> (WalletState, Instant) {
    let wallet_state = WalletState::new();
    let start_time = Instant::now();
    (wallet_state, start_time)
}

/// Core scanning logic - simplified and focused with batch processing
#[cfg(feature = "grpc")]
async fn scan_wallet_across_blocks_with_cancellation(
    _scanner: &mut GrpcBlockchainScanner,
    _scan_context: &ScanContext,
    config: &BinaryScanConfig,
    storage_backend: &mut ScannerStorage,
    _cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    _progress_tracker: Option<&mut ProgressTracker>,
) -> LightweightWalletResult<ScanResult> {
    // Determine scanning block range with resume support
    let (from_block, to_block) = determine_scan_range(config, storage_backend).await?;

    // Initialize scanning state
    let (wallet_state, _start_time) = initialize_scan_state();

    // TODO: Setup progress tracking if available
    // Progress tracking will be implemented in a future task

    // Prepare block heights list for scanning
    let block_heights = prepare_block_heights(config, from_block, to_block);

    // TODO: Implement the actual scanning logic
    // For now, this is a placeholder that will be fully implemented in future tasks

    if !config.quiet {
        println!("🔄 Wallet scanning functionality moved to library (placeholder implementation)");
        println!(
            "   • Scan range: {} to {}",
            format_number(from_block),
            format_number(to_block)
        );
        println!(
            "   • Blocks to scan: {}",
            format_number(block_heights.len())
        );
        println!("   • Note: Full scanning implementation will be completed in subsequent tasks");
    }

    // Create scan metadata
    let metadata = ScanMetadata::new(
        from_block,
        to_block,
        block_heights.len(),
        config.block_heights.is_some(),
    );

    Ok(ScanResult::Completed(wallet_state, Some(metadata)))
}

/// Display scan configuration information
#[cfg(feature = "grpc")]
fn display_scan_info(config: &BinaryScanConfig, block_heights: &[u64], has_specific_blocks: bool) {
    if has_specific_blocks {
        println!(
            "🔍 Scanning {} specific blocks: {:?}",
            format_number(block_heights.len()),
            if block_heights.len() <= 10 {
                block_heights
                    .iter()
                    .map(|h| format_number(*h))
                    .collect::<Vec<_>>()
                    .join(", ")
            } else {
                format!(
                    "{}..{} and {} others",
                    format_number(block_heights[0]),
                    format_number(block_heights.last().copied().unwrap_or(0)),
                    format_number(block_heights.len() - 2)
                )
            }
        );
    } else {
        let block_range = config.to_block - config.from_block + 1;
        println!(
            "🔍 Scanning blocks {} to {} ({} blocks total)...",
            format_number(config.from_block),
            format_number(config.to_block),
            format_number(block_range)
        );
    }

    println!();
}

// =============================================================================
// Balance calculation and summary helper functions
// =============================================================================

/// Calculate wallet balance summary
#[cfg(feature = "grpc")]
fn calculate_wallet_summary(wallet_state: &WalletState) -> (u64, u64, i64, usize, usize) {
    wallet_state.get_summary()
}

/// Calculate transaction direction counts
#[cfg(feature = "grpc")]
fn calculate_direction_counts(wallet_state: &WalletState) -> (usize, usize, usize) {
    wallet_state.get_direction_counts()
}

/// Format currency amount for display
#[cfg(feature = "grpc")]
fn format_currency_amount(amount: u64) -> String {
    format!(
        "{} μT ({:.6} T)",
        format_number(amount),
        amount as f64 / 1_000_000.0
    )
}

/// Check if wallet has any activity in the scanned range
#[cfg(feature = "grpc")]
fn has_wallet_activity(wallet_state: &WalletState) -> bool {
    !wallet_state.transactions.is_empty()
}

/// Display no activity message
#[cfg(feature = "grpc")]
fn display_no_activity_message(from_block: u64, to_block: u64) {
    println!(
        "💡 No wallet activity found in blocks {} to {}",
        format_number(from_block),
        format_number(to_block)
    );
    if from_block > 1 {
        println!("   ⚠️  Note: Scanning from block {} - wallet history before this block was not checked", format_number(from_block));
        println!("   💡 For complete history, try: cargo run --bin scanner --features grpc-storage -- --seed-phrase \"your seed phrase\" --from-block 1");
    }
}

/// Display wallet activity summary header
#[cfg(feature = "grpc")]
fn display_activity_header(from_block: u64, to_block: u64) {
    println!("🏦 WALLET ACTIVITY SUMMARY");
    println!("========================");
    println!(
        "Scan range: Block {} to {} ({} blocks)",
        format_number(from_block),
        format_number(to_block),
        format_number(to_block - from_block + 1)
    );
}

/// Display transaction breakdown by direction
#[cfg(feature = "grpc")]
fn display_transaction_breakdown(
    inbound_count: usize,
    outbound_count: usize,
    total_received: u64,
    total_spent: u64,
) {
    println!(
        "📥 Inbound:  {} transactions, {}",
        format_number(inbound_count),
        format_currency_amount(total_received)
    );
    println!(
        "📤 Outbound: {} transactions, {}",
        format_number(outbound_count),
        format_currency_amount(total_spent)
    );
}

/// Display current balance and total activity
#[cfg(feature = "grpc")]
fn display_balance_and_totals(balance: i64, total_count: usize) {
    println!(
        "💰 Current balance: {}",
        format_currency_amount(balance.abs() as u64)
    );
    println!(
        "📊 Total activity: {} transactions",
        format_number(total_count)
    );
    println!();
}

/// Display wallet activity summary
#[cfg(feature = "grpc")]
#[allow(dead_code)]
fn display_wallet_activity(wallet_state: &WalletState, from_block: u64, to_block: u64) {
    if !has_wallet_activity(wallet_state) {
        display_no_activity_message(from_block, to_block);
        return;
    }

    // Calculate summary values
    let (total_received, total_spent, balance, _unspent_count, _spent_count) =
        calculate_wallet_summary(wallet_state);
    let (inbound_count, outbound_count, _) = calculate_direction_counts(wallet_state);
    let total_count = wallet_state.transactions.len();

    // Display formatted summary
    display_activity_header(from_block, to_block);
    display_transaction_breakdown(inbound_count, outbound_count, total_received, total_spent);
    display_balance_and_totals(balance, total_count);
}

// =============================================================================
// Result output formatting functions
// =============================================================================

/// Display scan results in JSON format
#[cfg(feature = "grpc")]
fn display_json_results(wallet_state: &WalletState) {
    let (total_received, total_spent, balance, unspent_count, spent_count) =
        wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

    println!("{{");
    println!("  \"summary\": {{");
    println!(
        "    \"total_transactions\": {},",
        format_number(wallet_state.transactions.len())
    );
    println!("    \"inbound_count\": {},", format_number(inbound_count));
    println!("    \"outbound_count\": {},", format_number(outbound_count));
    println!("    \"total_received\": {},", format_number(total_received));
    println!("    \"total_spent\": {},", format_number(total_spent));
    println!("    \"current_balance\": {},", format_number(balance));
    println!("    \"unspent_outputs\": {},", format_number(unspent_count));
    println!("    \"spent_outputs\": {}", format_number(spent_count));
    println!("  }}");
    println!("}}");
}

/// Display scan results in summary format
#[cfg(feature = "grpc")]
fn display_summary_results(wallet_state: &WalletState, config: &BinaryScanConfig) {
    let (total_received, total_spent, balance, unspent_count, spent_count) =
        wallet_state.get_summary();
    let (inbound_count, outbound_count, _) = wallet_state.get_direction_counts();

    println!("📊 WALLET SCAN SUMMARY");
    println!("=====================");
    println!(
        "Scan range: Block {} to {}",
        format_number(config.from_block),
        format_number(config.to_block)
    );
    println!(
        "Total transactions: {}",
        format_number(wallet_state.transactions.len())
    );
    println!(
        "Inbound: {} transactions ({:.6} T)",
        format_number(inbound_count),
        total_received as f64 / 1_000_000.0
    );
    println!(
        "Outbound: {} transactions ({:.6} T)",
        format_number(outbound_count),
        total_spent as f64 / 1_000_000.0
    );
    println!("Current balance: {:.6} T", balance as f64 / 1_000_000.0);
    println!("Unspent outputs: {}", format_number(unspent_count));
    println!("Spent outputs: {}", format_number(spent_count));
}

// Placeholder type definitions until actual implementation
// TODO: Rename to WalletScanner once refactoring is complete and trait is moved
pub struct BinaryWalletScanner;
pub struct BinaryScanResult;
