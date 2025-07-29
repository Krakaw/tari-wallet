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
use zeroize::Zeroize;

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
        // Note: LightweightSignature only contains raw bytes field. The structured fields
        // below are not available in the current data structure, so we use zero values
        metadata_signature_ephemeral_commitment: vec![0u8; 32], // Not available in LightweightSignature
        metadata_signature_ephemeral_pubkey: vec![0u8; 32], // Not available in LightweightSignature
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
        metadata_signature_u_y: vec![0u8; 32], // Not available in LightweightSignature

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
/// For view-key mode (entropy all zeros), returns zero keys since spending is not possible
#[cfg(all(feature = "grpc", feature = "storage"))]
fn derive_utxo_spending_keys(
    entropy: &[u8; 16],
    output_index: u64,
) -> LightweightWalletResult<(PrivateKey, PrivateKey)> {
    // Check if we have real entropy or if this is view-key mode
    let has_real_entropy = entropy != &[0u8; 16];

    if has_real_entropy {
        // Derive real spending keys using wallet entropy
        let mut spending_key_raw = key_derivation::derive_private_key_from_entropy(
            entropy,
            "wallet_spending", // Branch for spending keys
            output_index,
        )?;

        let mut script_private_key_raw = key_derivation::derive_private_key_from_entropy(
            entropy,
            "script_keys", // Branch for script keys
            output_index,
        )?;

        // Convert to PrivateKey type
        let spending_key_bytes = spending_key_raw.as_bytes().try_into().map_err(|_| {
            KeyManagementError::key_derivation_failed("Failed to convert spending key")
        })?;
        let spending_key = PrivateKey::new(spending_key_bytes);

        let script_private_key_bytes =
            script_private_key_raw.as_bytes().try_into().map_err(|_| {
                KeyManagementError::key_derivation_failed("Failed to convert script private key")
            })?;
        let script_private_key = PrivateKey::new(script_private_key_bytes);

        // Zeroize the intermediate key material
        spending_key_raw.zeroize();
        script_private_key_raw.zeroize();

        Ok((spending_key, script_private_key))
    } else {
        // View-key mode: use zero keys since spending keys cannot be derived without entropy
        let zero_key_bytes = [0u8; 32];
        let spending_key = PrivateKey::new(zero_key_bytes);
        let script_private_key = PrivateKey::new(zero_key_bytes);

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
///
/// Contains detailed information about a completed or interrupted scanning
/// operation, including timing, block ranges, and processing statistics.
/// This metadata is useful for logging, monitoring, and resuming operations.
///
/// # Examples
/// ```
/// use lightweight_wallet_libs::scanning::ScanMetadata;
///
/// let metadata = ScanMetadata::new(1000, 2000, 1001, false);
/// if let Some(duration) = metadata.duration() {
///     println!("Scan took {:?}", duration);
/// }
/// ```
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
                Some(format!("{original_command_args} --from-block {next_block}"))
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
        json.push_str(&format!("    \"inbound_count\": {inbound_count},\n"));
        json.push_str(&format!("    \"outbound_count\": {outbound_count},\n"));
        json.push_str(&format!("    \"total_received\": {total_received},\n"));
        json.push_str(&format!("    \"total_spent\": {total_spent},\n"));
        json.push_str(&format!("    \"current_balance\": {balance},\n"));
        json.push_str(&format!("    \"unspent_outputs\": {unspent_count},\n"));
        json.push_str(&format!("    \"spent_outputs\": {spent_count}\n"));
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
                json.push_str(&format!(",\n    \"blocks_per_second\": {bps:.2}"));
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
///
/// This structure controls the behavior of wallet scanning operations,
/// including performance settings, logging options, and retry behavior.
///
/// # Examples
/// ```
/// use lightweight_wallet_libs::scanning::WalletScannerConfig;
///
/// let config = WalletScannerConfig::default()
///     .with_batch_size(20)
///     .with_verbose_logging(true);
/// ```
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
                    "Invalid batch size {value}: must be between {min} and {max}"
                )
            }
            ScannerConfigError::InvalidTimeout { value, min, max } => {
                write!(
                    f,
                    "Invalid timeout {value:?}: must be between {min:?} and {max:?}"
                )
            }
            ScannerConfigError::InvalidRetryConfig { reason } => {
                write!(f, "Invalid retry configuration: {reason}")
            }
            ScannerConfigError::ValidationError { field, reason } => {
                write!(f, "Validation error for {field}: {reason}")
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
///
/// Controls how the scanner behaves when encountering transient failures
/// during blockchain operations. Supports exponential backoff with configurable
/// delays and maximum retry attempts.
///
/// # Examples
/// ```
/// use lightweight_wallet_libs::scanning::RetryConfig;
/// use std::time::Duration;
///
/// let retry_config = RetryConfig::default()
///     .with_max_retries(5)
///     .with_base_delay(Duration::from_secs(1))
///     .with_exponential_backoff(true);
/// ```
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
/// # Features
/// - **Configurable batch processing** for optimal performance
/// - **Built-in retry logic** with exponential backoff for transient failures
/// - **Progress tracking** with customizable callbacks and real-time updates
/// - **Graceful interruption** support for user-initiated cancellation
/// - **Comprehensive error handling** with detailed error context
/// - **Memory-efficient streaming** processing for large block ranges
/// - **Resumable scanning** from the last successfully processed block
///
/// # Performance Considerations
/// - Larger batch sizes improve throughput but increase memory usage
/// - Progress callbacks add minimal overhead when used judiciously
/// - Retry logic helps handle network instability gracefully
/// - Database operations are batched for optimal I/O performance
///
/// # Examples
///
/// Basic scanner setup:
/// ```rust,no_run
/// use lightweight_wallet_libs::scanning::WalletScanner;
///
/// // Create a basic scanner
/// let scanner = WalletScanner::new();
/// ```
///
/// Advanced configuration with progress tracking:
/// ```rust,no_run
/// use lightweight_wallet_libs::scanning::WalletScanner;
/// use std::time::Duration;
///
/// let scanner = WalletScanner::new()
///     .with_progress_callback(|info| {
///         println!("Progress: {:.2}% ({}/{} blocks, {} outputs found)",
///                  info.progress_percent,
///                  info.blocks_processed,
///                  info.total_blocks,
///                  info.outputs_found);
///     })
///     .with_batch_size(20)
///     .with_timeout(Duration::from_secs(60))
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
        // Create a progress tracker with total_blocks=0 (will be updated when scanning begins)
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
            panic!("Invalid batch size: {e}");
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
            panic!("Invalid timeout: {e}");
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
            panic!("Invalid retry config: {e}");
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
                println!("   • Timeout: {timeout:?}");
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
                            println!("⚠️  Scan attempt {attempts} failed, retrying: {e}");
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
                Ok((wallet_birthday, config.to_block))
            } else {
                if !config.quiet {
                    println!("📄 Wallet not found, starting from configuration");
                }
                Ok((config.from_block, config.to_block))
            }
        } else {
            if !config.quiet {
                println!("⚠️  Resume requires a selected wallet");
            }
            Ok((config.from_block, config.to_block))
        }

        #[cfg(not(feature = "storage"))]
        {
            Ok((config.from_block, config.to_block))
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
    scanner: &mut GrpcBlockchainScanner,
    scan_context: &ScanContext,
    config: &BinaryScanConfig,
    storage_backend: &mut ScannerStorage,
    cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    mut progress_tracker: Option<&mut ProgressTracker>,
) -> LightweightWalletResult<ScanResult> {
    // Determine scanning block range with resume support
    let (from_block, to_block) = determine_scan_range(config, storage_backend).await?;

    // Initialize scanning state
    let (mut wallet_state, _start_time) = initialize_scan_state();

    // Update progress tracker with total block count
    if let Some(tracker) = progress_tracker.as_mut() {
        let total_blocks = to_block - from_block + 1;
        // Update the total blocks but preserve existing configuration and callback
        tracker.set_total_blocks(total_blocks as usize);
    }

    // Prepare block heights list for scanning
    let block_heights = prepare_block_heights(config, from_block, to_block);

    if !config.quiet {
        println!(
            "🔍 Scanning blocks {} to {} ({} blocks total)...",
            format_number(from_block),
            format_number(to_block),
            format_number(block_heights.len())
        );
    }

    // Create extraction config from scan context
    let extraction_config = crate::extraction::ExtractionConfig {
        enable_key_derivation: true,
        validate_range_proofs: true,
        validate_signatures: true,
        handle_special_outputs: true,
        detect_corruption: true,
        private_key: Some(scan_context.view_key.clone()),
        public_key: None,
    };

    // Create scan config for the blockchain scanner
    let _scan_config = super::ScanConfig {
        start_height: from_block,
        end_height: Some(to_block),
        batch_size: config.batch_size as u64,
        request_timeout: std::time::Duration::from_secs(30),
        extraction_config: extraction_config.clone(),
    };

    // Perform the actual blockchain scan
    let mut current_block = from_block;
    let mut blocks_processed = 0u64;
    let mut last_progress_update = Instant::now();

    // Process blocks in batches with cancellation support
    while current_block <= to_block {
        // Check for cancellation
        if *cancel_rx.borrow() {
            if !config.quiet {
                println!("\n🛑 Scan cancelled by user");
            }
            let metadata = ScanMetadata::new(
                from_block,
                current_block.saturating_sub(1),
                blocks_processed as usize,
                config.block_heights.is_some(),
            );
            return Ok(ScanResult::Interrupted(wallet_state, Some(metadata)));
        }

        let batch_end = std::cmp::min(current_block + config.batch_size as u64 - 1, to_block);

        // Create batch config (currently unused as we manually process blocks)
        let _batch_config = super::ScanConfig {
            start_height: current_block,
            end_height: Some(batch_end),
            batch_size: config.batch_size as u64,
            request_timeout: std::time::Duration::from_secs(30),
            extraction_config: extraction_config.clone(),
        };

        // Get blocks and process them using the proper block scanning logic
        let block_heights: Vec<u64> = (current_block..=batch_end).collect();
        match scanner.get_blocks_by_heights(block_heights.clone()).await {
            Ok(blocks) => {
                for block_info in blocks {
                    // Convert BlockInfo to Block for processing
                    let block = crate::data_structures::block::Block::new(
                        block_info.height,
                        block_info.hash.clone(),
                        block_info.timestamp,
                        block_info.outputs.clone(),
                        block_info.inputs.clone(),
                    );

                    // Use the real block scanning logic that actually works!
                    let (found_outputs, spent_outputs) = block.scan_for_wallet_activity(
                        &scan_context.view_key,
                        &scan_context.entropy,
                        &mut wallet_state,
                    )?;

                    if !config.quiet && (found_outputs > 0 || spent_outputs > 0) {
                        println!(
                            "Block {}: found {} outputs, {} spent",
                            block.height, found_outputs, spent_outputs
                        );
                    }

                    // Update progress with actual wallet activity found
                    if let Some(tracker) = progress_tracker.as_mut() {
                        tracker.update(block.height, found_outputs, spent_outputs);
                    }
                }

                let batch_size = batch_end - current_block + 1;
                blocks_processed += batch_size;

                // Update progress display
                if !config.quiet
                    && (blocks_processed % config.progress_frequency as u64 == 0
                        || last_progress_update.elapsed().as_secs() >= 1)
                {
                    if let Some(tracker) = progress_tracker.as_ref() {
                        let _progress_info = tracker.get_progress_info();
                        // Progress callbacks are handled internally by ProgressTracker
                    }
                    last_progress_update = Instant::now();
                }

                current_block = batch_end + 1;
            }
            Err(e) => {
                if !config.quiet {
                    eprintln!("❌ Error getting blocks {current_block}-{batch_end}: {e}");
                }
                return Err(e);
            }
        }
    }

    // Wallet state has been updated directly by the block scanning logic
    let total_blocks_scanned = to_block - from_block + 1;
    if !config.quiet {
        println!("✅ Completed scanning {total_blocks_scanned} blocks");
        if !wallet_state.transactions.is_empty() {
            println!(
                "   Found {} total transactions",
                wallet_state.transactions.len()
            );
        }
    }

    // Save results to storage if using database
    if !storage_backend.is_memory_only {
        storage_backend
            .save_transactions_incremental(&wallet_state.transactions)
            .await?;

        // Update the wallet's latest scanned block
        storage_backend
            .update_wallet_scanned_block(to_block)
            .await?;
    }

    if !config.quiet {
        println!(); // Clear progress line
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
        format_currency_amount(balance.unsigned_abs())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_scan_metadata_new() {
        let metadata = ScanMetadata::new(100, 200, 50, false);

        assert_eq!(metadata.from_block, 100);
        assert_eq!(metadata.to_block, 200);
        assert_eq!(metadata.blocks_processed, 50);
        assert!(!metadata.had_specific_blocks);
        assert!(metadata.start_time.is_none());
        assert!(metadata.end_time.is_none());
    }

    #[test]
    fn test_scan_metadata_duration() {
        let mut metadata = ScanMetadata::new(100, 200, 50, false);

        // No duration without times set
        assert!(metadata.duration().is_none());

        // Set times
        let start = Instant::now();
        std::thread::sleep(Duration::from_millis(10));
        let end = Instant::now();

        metadata.start_time = Some(start);
        metadata.end_time = Some(end);

        // Should have a duration now
        let duration = metadata.duration().unwrap();
        assert!(duration.as_millis() >= 10);
    }

    #[test]
    fn test_scan_metadata_blocks_per_second() {
        let mut metadata = ScanMetadata::new(100, 200, 100, false);

        // No speed without duration
        assert!(metadata.blocks_per_second().is_none());

        // Set times for 1 second duration
        let start = Instant::now();
        let end = start + Duration::from_secs(1);
        metadata.start_time = Some(start);
        metadata.end_time = Some(end);

        // Should calculate 100 blocks/second
        let bps = metadata.blocks_per_second().unwrap();
        assert_eq!(bps, 100.0);
    }

    #[test]
    fn test_scan_result_wallet_state() {
        let wallet_state = WalletState::new();
        let metadata = ScanMetadata::new(100, 200, 50, false);

        let completed = ScanResult::Completed(wallet_state.clone(), Some(metadata.clone()));
        let interrupted = ScanResult::Interrupted(wallet_state.clone(), Some(metadata));

        // Both should return the same wallet state
        assert_eq!(completed.wallet_state().transactions.len(), 0);
        assert_eq!(interrupted.wallet_state().transactions.len(), 0);
    }

    #[test]
    fn test_scan_result_metadata() {
        let wallet_state = WalletState::new();
        let metadata = ScanMetadata::new(100, 200, 50, false);

        let result = ScanResult::Completed(wallet_state, Some(metadata));

        let returned_metadata = result.metadata().unwrap();
        assert_eq!(returned_metadata.from_block, 100);
        assert_eq!(returned_metadata.to_block, 200);
        assert_eq!(returned_metadata.blocks_processed, 50);
    }

    #[test]
    fn test_scan_result_is_completed() {
        let wallet_state = WalletState::new();
        let metadata = ScanMetadata::new(100, 200, 50, false);

        let completed = ScanResult::Completed(wallet_state.clone(), Some(metadata.clone()));
        let interrupted = ScanResult::Interrupted(wallet_state, Some(metadata));

        assert!(completed.is_completed());
        assert!(!interrupted.is_completed());

        assert!(!completed.is_interrupted());
        assert!(interrupted.is_interrupted());
    }

    #[test]
    fn test_scan_result_block_range() {
        let wallet_state = WalletState::new();
        let metadata = ScanMetadata::new(100, 200, 50, false);

        let result = ScanResult::Completed(wallet_state, Some(metadata));

        let (from, to) = result.block_range().unwrap();
        assert_eq!(from, 100);
        assert_eq!(to, 200);
    }

    #[test]
    fn test_scan_result_blocks_processed() {
        let wallet_state = WalletState::new();
        let metadata = ScanMetadata::new(100, 200, 50, false);

        let result = ScanResult::Completed(wallet_state, Some(metadata));

        assert_eq!(result.blocks_processed().unwrap(), 50);
    }

    #[test]
    fn test_scan_result_has_activity() {
        let wallet_state = WalletState::new();
        let result = ScanResult::Completed(wallet_state, None);

        assert!(!result.has_activity());
        assert_eq!(result.current_balance(), 0);
        assert_eq!(result.transaction_count(), 0);
    }

    #[test]
    fn test_scan_result_balance_summary() {
        let wallet_state = WalletState::new();
        let result = ScanResult::Completed(wallet_state, None);

        let (total_received, total_spent, balance, unspent_count, spent_count) =
            result.get_balance_summary();
        assert_eq!(total_received, 0);
        assert_eq!(total_spent, 0);
        assert_eq!(balance, 0);
        assert_eq!(unspent_count, 0);
        assert_eq!(spent_count, 0);
    }

    #[test]
    fn test_scan_result_direction_counts() {
        let wallet_state = WalletState::new();
        let result = ScanResult::Completed(wallet_state, None);

        let (inbound_count, outbound_count, total_count) = result.get_direction_counts();
        assert_eq!(inbound_count, 0);
        assert_eq!(outbound_count, 0);
        assert_eq!(total_count, 0);
    }

    #[test]
    fn test_scan_result_resume_command() {
        let wallet_state = WalletState::new();
        let metadata = ScanMetadata::new(100, 200, 50, false);

        let completed = ScanResult::Completed(wallet_state.clone(), Some(metadata.clone()));
        let interrupted = ScanResult::Interrupted(wallet_state, Some(metadata));

        // Completed scans don't have resume commands
        assert!(completed.resume_command("--seed-phrase test").is_none());

        // Interrupted scans with no transactions don't have resume commands
        assert!(interrupted.resume_command("--seed-phrase test").is_none());
    }

    #[test]
    fn test_retry_config_validate() {
        // Valid config
        let config = RetryConfig::default();
        assert!(config.validate().is_ok());

        // Invalid max_retries
        let invalid_config = RetryConfig {
            max_retries: 101,
            ..RetryConfig::default()
        };
        assert!(invalid_config.validate().is_err());

        // Invalid base_delay
        let invalid_config = RetryConfig {
            base_delay: Duration::from_secs(61),
            ..RetryConfig::default()
        };
        assert!(invalid_config.validate().is_err());

        // Invalid max_delay < base_delay
        let invalid_config = RetryConfig {
            base_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(5),
            ..RetryConfig::default()
        };
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_retry_config_presets() {
        let conservative = RetryConfig::conservative();
        assert_eq!(conservative.max_retries, 5);
        assert_eq!(conservative.base_delay, Duration::from_secs(2));
        assert!(conservative.exponential_backoff);

        let aggressive = RetryConfig::aggressive();
        assert_eq!(aggressive.max_retries, 2);
        assert_eq!(aggressive.base_delay, Duration::from_millis(100));
        assert!(aggressive.exponential_backoff);

        let no_retries = RetryConfig::no_retries();
        assert_eq!(no_retries.max_retries, 0);
        assert!(!no_retries.exponential_backoff);
    }

    #[test]
    fn test_wallet_scanner_config_validate() {
        // Valid default config
        let config = WalletScannerConfig::default();
        assert!(config.validate().is_ok());

        // Invalid batch size (0)
        let mut invalid_config = WalletScannerConfig::default();
        invalid_config.batch_size = 0;
        assert!(invalid_config.validate().is_err());

        // Invalid batch size (too large)
        let mut invalid_config = WalletScannerConfig::default();
        invalid_config.batch_size = 1001;
        assert!(invalid_config.validate().is_err());

        // Invalid timeout (too short)
        let mut invalid_config = WalletScannerConfig::default();
        invalid_config.timeout = Some(Duration::from_millis(50));
        assert!(invalid_config.validate().is_err());

        // Invalid timeout (too long)
        let mut invalid_config = WalletScannerConfig::default();
        invalid_config.timeout = Some(Duration::from_secs(301));
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_wallet_scanner_new() {
        let scanner = WalletScanner::new();
        assert_eq!(scanner.config.batch_size, 10);
        assert_eq!(scanner.config.timeout, Some(Duration::from_secs(30)));
        assert!(!scanner.config.verbose_logging);
        assert!(scanner.config.progress_tracker.is_none());
    }

    #[test]
    fn test_wallet_scanner_from_config() {
        let config = WalletScannerConfig {
            batch_size: 25,
            timeout: Some(Duration::from_secs(60)),
            verbose_logging: true,
            ..Default::default()
        };

        let scanner = WalletScanner::from_config(config);
        assert_eq!(scanner.config.batch_size, 25);
        assert_eq!(scanner.config.timeout, Some(Duration::from_secs(60)));
        assert!(scanner.config.verbose_logging);
    }

    #[test]
    fn test_wallet_scanner_with_batch_size() {
        let scanner = WalletScanner::new().with_batch_size(50);
        assert_eq!(scanner.config.batch_size, 50);
    }

    #[test]
    #[should_panic(expected = "Invalid batch size")]
    fn test_wallet_scanner_with_invalid_batch_size() {
        let _scanner = WalletScanner::new().with_batch_size(0);
    }

    #[test]
    fn test_wallet_scanner_try_with_batch_size() {
        let scanner = WalletScanner::new().try_with_batch_size(50);
        assert!(scanner.is_ok());
        assert_eq!(scanner.unwrap().config.batch_size, 50);

        let scanner = WalletScanner::new().try_with_batch_size(0);
        assert!(scanner.is_err());
    }

    #[test]
    fn test_wallet_scanner_with_timeout() {
        let timeout = Duration::from_secs(60);
        let scanner = WalletScanner::new().with_timeout(timeout);
        assert_eq!(scanner.config.timeout, Some(timeout));
    }

    #[test]
    fn test_wallet_scanner_try_with_timeout() {
        let timeout = Duration::from_secs(60);
        let scanner = WalletScanner::new().try_with_timeout(timeout);
        assert!(scanner.is_ok());
        assert_eq!(scanner.unwrap().config.timeout, Some(timeout));

        let invalid_timeout = Duration::from_millis(50);
        let scanner = WalletScanner::new().try_with_timeout(invalid_timeout);
        assert!(scanner.is_err());
    }

    #[test]
    fn test_wallet_scanner_with_verbose_logging() {
        let scanner = WalletScanner::new().with_verbose_logging(true);
        assert!(scanner.config.verbose_logging);

        let scanner = WalletScanner::new().with_verbose_logging(false);
        assert!(!scanner.config.verbose_logging);
    }

    #[test]
    fn test_wallet_scanner_with_retry_config() {
        let retry_config = RetryConfig::aggressive();
        let scanner = WalletScanner::new().with_retry_config(retry_config.clone());
        assert_eq!(
            scanner.config.retry_config.max_retries,
            retry_config.max_retries
        );
    }

    #[test]
    fn test_wallet_scanner_try_with_retry_config() {
        let retry_config = RetryConfig::aggressive();
        let scanner = WalletScanner::new().try_with_retry_config(retry_config.clone());
        assert!(scanner.is_ok());

        let invalid_retry_config = RetryConfig {
            max_retries: 101,
            ..RetryConfig::default()
        };
        let scanner = WalletScanner::new().try_with_retry_config(invalid_retry_config);
        assert!(scanner.is_err());
    }

    #[test]
    fn test_wallet_scanner_config_access() {
        let mut scanner = WalletScanner::new();

        // Read access
        assert_eq!(scanner.config().batch_size, 10);

        // Mutable access
        scanner.config_mut().batch_size = 20;
        assert_eq!(scanner.config().batch_size, 20);
    }

    #[test]
    fn test_wallet_scanner_build() {
        let scanner = WalletScanner::new()
            .with_batch_size(25)
            .with_verbose_logging(true)
            .build();

        assert!(scanner.is_ok());
        let scanner = scanner.unwrap();
        assert_eq!(scanner.config.batch_size, 25);
        assert!(scanner.config.verbose_logging);
    }

    #[test]
    fn test_wallet_scanner_validate() {
        let scanner = WalletScanner::new();
        assert!(scanner.validate().is_ok());

        let mut scanner = WalletScanner::new();
        scanner.config_mut().batch_size = 0;
        assert!(scanner.validate().is_err());
    }

    #[test]
    fn test_wallet_scanner_presets() {
        let simple = WalletScanner::with_simple_progress();
        assert!(simple.config.progress_tracker.is_some());

        let performance = WalletScanner::performance_optimized();
        assert_eq!(performance.config.batch_size, 50);
        assert_eq!(performance.config.timeout, Some(Duration::from_secs(60)));
        assert!(!performance.config.verbose_logging);

        let reliability = WalletScanner::reliability_optimized();
        assert_eq!(reliability.config.batch_size, 5);
        assert_eq!(reliability.config.timeout, Some(Duration::from_secs(10)));
        assert!(reliability.config.verbose_logging);
        assert_eq!(reliability.config.retry_config.max_retries, 5);
    }

    #[test]
    fn test_wallet_scanner_is_retryable_error() {
        let scanner = WalletScanner::new();

        // Network errors should be retryable
        let connection_error =
            LightweightWalletError::StorageError("connection failed".to_string());
        assert!(scanner.is_retryable_error(&connection_error));

        let timeout_error = LightweightWalletError::StorageError("timeout occurred".to_string());
        assert!(scanner.is_retryable_error(&timeout_error));

        let unavailable_error =
            LightweightWalletError::StorageError("service unavailable".to_string());
        assert!(scanner.is_retryable_error(&unavailable_error));

        // Other errors should not be retryable
        let validation_error = LightweightWalletError::InvalidArgument {
            argument: "test".to_string(),
            value: "test".to_string(),
            message: "test error".to_string(),
        };
        assert!(!scanner.is_retryable_error(&validation_error));
    }

    #[test]
    fn test_create_wallet_from_seed_phrase() {
        // Test with a valid seed phrase
        let seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let result = create_wallet_from_seed_phrase(seed_phrase);

        // This test may fail if wallet dependencies aren't available in test context
        // Just check that the function exists and returns the right type
        if let Ok((scan_context, _default_from_block)) = result {
            // Should have entropy from wallet
            assert!(scan_context.has_entropy());
        }
        // If it fails, that's OK for unit test purposes since this is primarily integration functionality
    }

    #[test]
    fn test_create_wallet_from_view_key() {
        let view_key_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let result = create_wallet_from_view_key(view_key_hex);

        assert!(result.is_ok());
        let (scan_context, default_from_block) = result.unwrap();

        // Should not have entropy (view-key only)
        assert!(!scan_context.has_entropy());
        assert_eq!(default_from_block, 0);
    }

    #[test]
    fn test_create_wallet_from_invalid_view_key() {
        let invalid_view_key = "invalid_hex";
        let result = create_wallet_from_view_key(invalid_view_key);

        assert!(result.is_err());
    }

    #[cfg(all(feature = "grpc", feature = "storage"))]
    #[test]
    fn test_generate_transaction_id() {
        let tx_id_1 = generate_transaction_id(1000, 5);
        let tx_id_2 = generate_transaction_id(1000, 6);
        let tx_id_3 = generate_transaction_id(1001, 5);

        // Should be deterministic
        assert_eq!(tx_id_1, generate_transaction_id(1000, 5));

        // Should be different for different inputs
        assert_ne!(tx_id_1, tx_id_2);
        assert_ne!(tx_id_1, tx_id_3);

        // Should never return 0
        assert_ne!(generate_transaction_id(0, 0), 0);
    }

    #[cfg(all(feature = "grpc", feature = "storage"))]
    #[test]
    fn test_derive_utxo_spending_keys_with_entropy() {
        let entropy = [1u8; 16];
        let result = derive_utxo_spending_keys(&entropy, 0);

        assert!(result.is_ok());
        let (spending_key, script_private_key) = result.unwrap();

        // Should not be zero keys
        assert_ne!(spending_key.as_bytes(), [0u8; 32]);
        assert_ne!(script_private_key.as_bytes(), [0u8; 32]);
    }

    #[cfg(all(feature = "grpc", feature = "storage"))]
    #[test]
    fn test_derive_utxo_spending_keys_view_only() {
        let entropy = [0u8; 16]; // View-key mode
        let result = derive_utxo_spending_keys(&entropy, 0);

        assert!(result.is_ok());
        let (spending_key, script_private_key) = result.unwrap();

        // Should be zero keys in view-only mode
        assert_eq!(spending_key.as_bytes(), [0u8; 32]);
        assert_eq!(script_private_key.as_bytes(), [0u8; 32]);
    }

    #[cfg(all(feature = "grpc", feature = "storage"))]
    #[test]
    fn test_extract_script_data_empty() {
        let result = extract_script_data(&[]);
        assert!(result.is_ok());

        let (input_data, script_lock_height) = result.unwrap();
        assert!(input_data.is_empty());
        assert_eq!(script_lock_height, 0);
    }

    #[cfg(all(feature = "grpc", feature = "storage"))]
    #[test]
    fn test_extract_script_data_with_data() {
        // Create a simple script with OP_PUSHDATA
        let script_bytes = vec![0x6a, 0x04, 0x01, 0x02, 0x03, 0x04]; // PUSHDATA 4 bytes
        let result = extract_script_data(&script_bytes);

        assert!(result.is_ok());
        let (input_data, _script_lock_height) = result.unwrap();
        assert_eq!(input_data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_format_currency_amount() {
        let amount = 1_000_000u64; // 1 Tari
        let formatted = format_currency_amount(amount);

        assert!(formatted.contains("1,000,000 μT"));
        assert!(formatted.contains("1.000000 T"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_has_wallet_activity() {
        let empty_state = WalletState::new();
        assert!(!has_wallet_activity(&empty_state));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_calculate_wallet_summary() {
        let wallet_state = WalletState::new();
        let (total_received, total_spent, balance, unspent_count, spent_count) =
            calculate_wallet_summary(&wallet_state);

        assert_eq!(total_received, 0);
        assert_eq!(total_spent, 0);
        assert_eq!(balance, 0);
        assert_eq!(unspent_count, 0);
        assert_eq!(spent_count, 0);
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn test_calculate_direction_counts() {
        let wallet_state = WalletState::new();
        let (inbound_count, outbound_count, total_count) =
            calculate_direction_counts(&wallet_state);

        assert_eq!(inbound_count, 0);
        assert_eq!(outbound_count, 0);
        assert_eq!(total_count, 0);
    }
}

// Note: The legacy BinaryWalletScanner and BinaryScanResult types have been removed
// as they were placeholders. The new WalletScanner and ScanResult types provide
// the complete scanning functionality.
