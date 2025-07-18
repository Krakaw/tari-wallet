//! Enhanced wallet scanning functionality
//!
//! This module contains the advanced wallet scanning logic extracted from the binary
//! scanner implementation. It provides comprehensive scanning capabilities including:
//! - UTXO extraction and storage
//! - Transaction flow tracking
//! - Progress reporting with callbacks
//! - Error handling with recovery strategies
//! - Cancellation support

#[cfg(feature = "storage")]
use tari_utilities::ByteArray;
use crate::{
    data_structures::{
        block::Block,
        wallet_transaction::WalletState,
    },
    errors::{LightweightWalletResult, LightweightWalletError},
    scanning::{
        BlockchainScanner, WalletScanContext, EnhancedScanConfig,
        EnhancedScanProgress, ScanPhase, ErrorResponse, ScanError,
        EnhancedProgressCallback, ErrorCallback, CancellationToken,
    },
};

#[cfg(feature = "storage")]
use crate::{
    data_structures::{
        transaction::TransactionDirection,
        transaction_output::LightweightTransactionOutput,
        transaction_input::TransactionInput,
        types::PrivateKey,
    },
};

#[cfg(feature = "storage")]
use crate::{
    storage::{
        ScannerStorage, ScannerStorageConfig, WalletSelectionStrategy, StoredOutput, OutputStatus,
    },
};

#[cfg(feature = "storage")]
use blake2::{Blake2b, Digest};
#[cfg(feature = "storage")]
use digest::consts::U32;

/// Result of an enhanced scan operation
#[derive(Debug, Clone)]
pub enum EnhancedScanResult {
    /// Scan completed successfully
    Completed(WalletState),
    /// Scan was interrupted but has partial results
    Interrupted(WalletState),
    /// Scan failed with an error
    Failed(String),
}

/// Enhanced wallet scanner with comprehensive functionality
/// 
/// This scanner provides advanced features beyond the basic `BlockchainScanner`,
/// including storage integration, progress reporting, error handling, and
/// comprehensive transaction tracking.
pub struct EnhancedWalletScanner<S: BlockchainScanner> {
    /// Underlying blockchain scanner
    scanner: S,
    /// Storage backend for persisting results
    #[cfg(feature = "storage")]
    storage: ScannerStorage,
    /// Scanner configuration
    config: EnhancedScanConfig,
    /// Wallet scanning context
    scan_context: Option<WalletScanContext>,
}

impl<S: BlockchainScanner> EnhancedWalletScanner<S> {
    /// Create a new enhanced wallet scanner with storage
    #[cfg(feature = "storage")]
    pub fn new_with_storage(
        scanner: S,
        storage: ScannerStorage,
        config: EnhancedScanConfig,
    ) -> Self {
        Self {
            scanner,
            storage,
            config,
            scan_context: None,
        }
    }

    /// Create a new enhanced wallet scanner without storage
    pub fn new(
        scanner: S,
        config: EnhancedScanConfig,
    ) -> Self {
        Self {
            scanner,
            #[cfg(feature = "storage")]
            storage: ScannerStorage::new_memory(),
            config,
            scan_context: None,
        }
    }

    /// Set the wallet scanning context
    pub fn with_scan_context(mut self, scan_context: WalletScanContext) -> Self {
        self.scan_context = Some(scan_context);
        self
    }

    /// Get the current configuration
    pub fn config(&self) -> &EnhancedScanConfig {
        &self.config
    }

    /// Get the storage backend
    #[cfg(feature = "storage")]
    pub fn storage(&self) -> &ScannerStorage {
        &self.storage
    }

    /// Get mutable access to storage
    #[cfg(feature = "storage")]
    pub fn storage_mut(&mut self) -> &mut ScannerStorage {
        &mut self.storage
    }

    /// Initialize the scanner with wallet setup
    #[cfg(feature = "storage")]
    pub async fn initialize_wallet(
        &mut self,
        selection_strategy: WalletSelectionStrategy,
        selection_callback: Option<&crate::storage::WalletSelectionCallback>,
    ) -> LightweightWalletResult<()> {
        // Select or create wallet if using database storage
        if !self.storage.is_memory_only() {
            let selection_result = self.storage.select_wallet(
                selection_strategy,
                selection_callback,
            ).await?;

            // Load scan context from wallet if not already provided
            if self.scan_context.is_none() {
                self.scan_context = self.storage.load_scan_context().await?;
            }
        }

        // Validate that we have a scan context
        if self.scan_context.is_none() {
            return Err(LightweightWalletError::ConfigurationError(
                "No scan context available - provide keys or use existing wallet".to_string()
            ));
        }

        Ok(())
    }

    /// Get wallet birthday (resume block) if available
    #[cfg(feature = "storage")]
    pub async fn get_wallet_birthday(&self) -> LightweightWalletResult<Option<u64>> {
        self.storage.get_wallet_birthday().await
    }

    /// Scan wallet across blocks with comprehensive error handling and progress reporting
    pub async fn scan_wallet(
        &mut self,
        progress_callback: Option<&dyn EnhancedProgressCallback>,
        error_callback: Option<&dyn ErrorCallback>,
        cancellation_token: Option<&dyn CancellationToken>,
    ) -> LightweightWalletResult<EnhancedScanResult> {
        // Ensure we have a scan context and clone it to avoid borrowing issues
        let scan_context = self.scan_context.clone()
            .ok_or_else(|| LightweightWalletError::ConfigurationError(
                "No scan context available".to_string()
            ))?;

        // Get blocks to scan
        let block_heights = self.config.get_blocks_to_scan();
        let total_blocks = block_heights.len();

        // Initialize progress tracking
        let mut progress = EnhancedScanProgress::new(total_blocks);
        progress.set_phase(ScanPhase::Initializing);

        if let Some(callback) = progress_callback {
            callback.on_scan_start(total_blocks);
            callback.on_phase_change(ScanPhase::Initializing, ScanPhase::ScanningBlocks);
        }

        // Initialize wallet state
        let mut wallet_state = WalletState::new();
        progress.set_phase(ScanPhase::ScanningBlocks);

        // Process blocks in batches
        let batch_size = self.config.batch_size;
        for (batch_index, batch_heights) in block_heights.chunks(batch_size).enumerate() {
            // Check for cancellation
            if let Some(token) = cancellation_token {
                if token.is_cancelled() {
                    progress.set_phase(ScanPhase::Interrupted);
                    if let Some(callback) = progress_callback {
                        callback.on_scan_interrupted(&wallet_state, &progress);
                    }
                    return Ok(EnhancedScanResult::Interrupted(wallet_state));
                }
            }

            // Process this batch with error handling
            match self.process_block_batch(
                batch_heights,
                &mut wallet_state,
                &scan_context,
                &mut progress,
                progress_callback,
            ).await {
                Ok(_) => {
                    // Update progress
                    if let Some(callback) = progress_callback {
                        callback.on_progress(&progress);
                    }

                    // Save progress to storage
                    #[cfg(feature = "storage")]
                    if !self.storage.is_memory_only() {
                        if let Some(last_block) = batch_heights.last() {
                            let _ = self.storage.update_wallet_scanned_block(*last_block).await;
                        }
                    }
                },
                Err(e) => {
                    // Handle error through callback
                    let error_info = ScanError {
                        error: e.to_string(),
                        details: Some(format!("Failed to process batch starting at block {}", 
                            batch_heights.first().unwrap_or(&0))),
                        block_height: batch_heights.first().copied(),
                        error_batch: Some(batch_heights.to_vec()),
                        remaining_blocks: block_heights[((batch_index + 1) * batch_size).min(block_heights.len())..].to_vec(),
                        is_recoverable: true,
                        recovery_suggestions: vec![
                            "Try reducing batch size".to_string(),
                            "Check network connection".to_string(),
                            "Skip this batch and continue".to_string(),
                        ],
                    };

                    let response = if let Some(callback) = error_callback {
                        callback.on_error(&error_info)
                    } else {
                        ErrorResponse::Abort
                    };

                    match response {
                        ErrorResponse::Continue => {
                            // Skip this batch and continue
                            continue;
                        },
                        ErrorResponse::Retry => {
                            // Retry with smaller batch size
                            let retry_batch_size = (batch_size / 2).max(1);
                            for retry_chunk in batch_heights.chunks(retry_batch_size) {
                                if let Err(retry_error) = self.process_block_batch(
                                    retry_chunk,
                                    &mut wallet_state,
                                    &scan_context,
                                    &mut progress,
                                    progress_callback,
                                ).await {
                                    // If retry also fails, abort
                                    progress.set_phase(ScanPhase::Failed);
                                    return Ok(EnhancedScanResult::Failed(retry_error.to_string()));
                                }
                            }
                        },
                        ErrorResponse::Abort => {
                            progress.set_phase(ScanPhase::Failed);
                            return Ok(EnhancedScanResult::Failed(e.to_string()));
                        }
                    }
                }
            }
        }

        // Save final results to storage
        progress.set_phase(ScanPhase::SavingResults);
        if let Some(callback) = progress_callback {
            callback.on_phase_change(ScanPhase::ScanningBlocks, ScanPhase::SavingResults);
        }

        #[cfg(feature = "storage")]
        if !self.storage.is_memory_only() {
            // Save all transactions
            let all_transactions: Vec<_> = wallet_state.transactions.iter().cloned().collect();
            if !all_transactions.is_empty() {
                if let Err(e) = self.storage.save_transactions(&all_transactions).await {
                    // Log warning but don't fail the scan
                    eprintln!("Warning: Failed to save transactions to storage: {}", e);
                }
            }
        }

        // Scan completed successfully
        progress.set_phase(ScanPhase::Completed);
        if let Some(callback) = progress_callback {
            callback.on_scan_complete(&wallet_state, &progress);
        }

        Ok(EnhancedScanResult::Completed(wallet_state))
    }

    /// Process a batch of blocks
    async fn process_block_batch(
        &mut self,
        batch_heights: &[u64],
        wallet_state: &mut WalletState,
        scan_context: &WalletScanContext,
        progress: &mut EnhancedScanProgress,
        progress_callback: Option<&dyn EnhancedProgressCallback>,
    ) -> LightweightWalletResult<()> {
        // Fetch blocks via scanner
        let block_infos = self.scanner.get_blocks_by_heights(batch_heights.to_vec()).await?;

        // Process each block
        for (_block_index, block_height) in batch_heights.iter().enumerate() {
            // Find corresponding block info
            let block_info = block_infos.iter()
                .find(|b| b.height == *block_height)
                .ok_or_else(|| LightweightWalletError::ResourceNotFound(
                    format!("Block {} not found in batch response", block_height)
                ))?;

            // Create block for processing
            #[cfg(feature = "grpc")]
            let block = Block::from_block_info(block_info.clone());
            
            #[cfg(not(feature = "grpc"))]
            let block = Block::new(
                block_info.height,
                block_info.hash.clone(),
                block_info.timestamp,
                block_info.outputs.clone(),
                block_info.inputs.clone(),
            );

            // Process outputs and inputs
            let found_outputs = block.process_outputs(
                &scan_context.view_key,
                &scan_context.entropy,
                wallet_state,
            )?;

            let spent_outputs = block.process_inputs(wallet_state)?;

            // Update progress
            progress.update_block_progress(*block_height, found_outputs, spent_outputs);
            progress.update_wallet_state(wallet_state.clone());

            // Extract and save UTXO data if using storage
            #[cfg(feature = "storage")]
            if !self.storage.is_memory_only() {
                if let Some(wallet_id) = self.storage.wallet_id() {
                    match self.extract_utxo_outputs_from_wallet_state(
                        wallet_state,
                        scan_context,
                        wallet_id,
                        &block.outputs,
                        *block_height,
                    ) {
                        Ok(utxo_outputs) => {
                            if !utxo_outputs.is_empty() {
                                let _ = self.storage.save_outputs(&utxo_outputs).await;
                            }
                        },
                        Err(e) => {
                            // Log warning but continue
                            eprintln!("Warning: Failed to extract UTXO data for block {}: {}", 
                                block_height, e);
                        }
                    }
                }
            }

            // Update progress every N blocks
            if progress.blocks_processed % self.config.progress_frequency == 0 {
                if let Some(callback) = progress_callback {
                    callback.on_progress(&progress);
                }
            }
        }

        Ok(())
    }

    /// Extract UTXO outputs from wallet state for storage
    #[cfg(feature = "storage")]
    fn extract_utxo_outputs_from_wallet_state(
        &self,
        wallet_state: &WalletState,
        scan_context: &WalletScanContext,
        wallet_id: u32,
        block_outputs: &[LightweightTransactionOutput],
        block_height: u64,
    ) -> LightweightWalletResult<Vec<StoredOutput>> {
        let mut utxo_outputs = Vec::new();

        // Get inbound transactions from this specific block
        let block_transactions: Vec<_> = wallet_state
            .transactions
            .iter()
            .filter(|tx| {
                tx.block_height == block_height
                    && tx.transaction_direction == TransactionDirection::Inbound
            })
            .collect();

        for transaction in block_transactions {
            // Find the corresponding blockchain output
            if let Some(output_index) = transaction.output_index {
                if let Some(blockchain_output) = block_outputs.get(output_index) {
                    // Derive spending keys for this output
                    let (spending_key, script_private_key) =
                        self.derive_utxo_spending_keys(&scan_context.entropy, output_index as u64)?;

                    // Extract script input data and lock height
                    let (input_data, script_lock_height) = 
                        self.extract_script_data(&blockchain_output.script.bytes)?;

                    // Create StoredOutput from blockchain data
                    let stored_output = StoredOutput {
                        id: None, // Will be set by database
                        wallet_id,

                        // Core UTXO identification
                        commitment: blockchain_output.commitment.as_bytes().to_vec(),
                        hash: self.compute_output_hash(blockchain_output)?,
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
                        features_json: serde_json::to_string(&blockchain_output.features).map_err(
                            |e| {
                                LightweightWalletError::StorageError(format!(
                                    "Failed to serialize features: {}",
                                    e
                                ))
                            },
                        )?,

                        // Maturity and lock constraints
                        maturity: blockchain_output.features.maturity,
                        script_lock_height,

                        // Metadata signature components
                        sender_offset_public_key: blockchain_output
                            .sender_offset_public_key
                            .as_bytes()
                            .to_vec(),
                        // Simplified metadata signature handling
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
                            transaction.spent_in_block.and_then(|spent_block| {
                                transaction.spent_in_input.map(|spent_input| {
                                    self.generate_transaction_id(spent_block, spent_input)
                                })
                            })
                        } else {
                            None
                        },

                        // Timestamps (will be set by database)
                        created_at: None,
                        updated_at: None,
                    };

                    utxo_outputs.push(stored_output);
                }
            }
        }

        Ok(utxo_outputs)
    }

    /// Derive spending keys for a UTXO output using wallet entropy
    #[cfg(feature = "storage")]
    fn derive_utxo_spending_keys(
        &self,
        entropy: &[u8; 16],
        output_index: u64,
    ) -> LightweightWalletResult<(PrivateKey, PrivateKey)> {
        use crate::key_management::key_derivation;

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
            let spending_key = PrivateKey::new(spending_key_raw.as_bytes().try_into().map_err(
                |_| crate::errors::KeyManagementError::key_derivation_failed("Failed to convert spending key")
            )?);

            let script_private_key = PrivateKey::new(script_private_key_raw.as_bytes().try_into().map_err(
                |_| crate::errors::KeyManagementError::key_derivation_failed("Failed to convert script private key")
            )?);

            Ok((spending_key, script_private_key))
        } else {
            // View-key mode: use placeholder keys (cannot spend, but can store UTXO structure)
            let placeholder_key_bytes = [0u8; 32];
            let spending_key = PrivateKey::new(placeholder_key_bytes);
            let script_private_key = PrivateKey::new(placeholder_key_bytes);

            Ok((spending_key, script_private_key))
        }
    }

    /// Extract script input data and script lock height from script bytes
    #[cfg(feature = "storage")]
    fn extract_script_data(&self, script_bytes: &[u8]) -> LightweightWalletResult<(Vec<u8>, u64)> {
        // Simplified script data extraction
        // In a full implementation, this would use proper script parsing
        
        if script_bytes.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let mut input_data = Vec::new();
        let mut script_lock_height = 0u64;

        // Look for data patterns in the script
        let mut i = 0;
        while i < script_bytes.len() {
            match script_bytes[i] {
                // OP_PUSHDATA opcodes - extract the data being pushed
                0x01..=0x4b => {
                    let data_len = script_bytes[i] as usize;
                    i += 1;
                    if i + data_len <= script_bytes.len() {
                        let data = script_bytes[i..i + data_len].to_vec();
                        
                        // Use larger, meaningful data as input data
                        if !data.iter().all(|&b| b == 0) && data.len() >= 1 {
                            if input_data.is_empty() || data.len() > input_data.len() {
                                input_data = data.clone();
                            }
                        }

                        // Check if this could be a height value
                        if data.len() == 4 || data.len() == 8 {
                            let height = if data.len() == 4 {
                                u32::from_le_bytes(data.clone().try_into().unwrap_or([0; 4])) as u64
                            } else {
                                u64::from_le_bytes(data.clone().try_into().unwrap_or([0; 8]))
                            };
                            
                            if height > 0 && height < 10_000_000 && height > 100 {
                                script_lock_height = height;
                            }
                        }
                        
                        i += data_len;
                    } else {
                        break;
                    }
                }
                _ => {
                    i += 1;
                }
            }
        }

        Ok((input_data, script_lock_height))
    }

    /// Compute output hash for UTXO identification
    #[cfg(feature = "storage")]
    fn compute_output_hash(&self, output: &LightweightTransactionOutput) -> LightweightWalletResult<Vec<u8>> {
        // Compute hash of output fields for identification
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(output.commitment.as_bytes());
        hasher.update(output.script.bytes.as_slice());
        hasher.update(output.sender_offset_public_key.as_bytes());
        hasher.update(&output.minimum_value_promise.as_u64().to_le_bytes());

        Ok(hasher.finalize().to_vec())
    }

    /// Generate a deterministic transaction ID from block height and input index
    #[cfg(feature = "storage")]
    fn generate_transaction_id(&self, block_height: u64, input_index: usize) -> u64 {
        // Create a deterministic transaction ID by combining block height and input index
        let tx_id = ((block_height & 0xFFFFFFFF) << 32) | (input_index as u64 & 0xFFFFFFFF);
        
        // Ensure we don't return 0
        if tx_id == 0 { 1 } else { tx_id }
    }
}

/// Builder for creating enhanced wallet scanners
pub struct EnhancedScannerBuilder<S: BlockchainScanner> {
    scanner: Option<S>,
    #[cfg(feature = "storage")]
    storage_config: Option<ScannerStorageConfig>,
    scan_config: Option<EnhancedScanConfig>,
}

impl<S: BlockchainScanner> EnhancedScannerBuilder<S> {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            scanner: None,
            #[cfg(feature = "storage")]
            storage_config: None,
            scan_config: None,
        }
    }

    /// Set the blockchain scanner
    pub fn with_scanner(mut self, scanner: S) -> Self {
        self.scanner = Some(scanner);
        self
    }

    /// Set storage configuration
    #[cfg(feature = "storage")]
    pub fn with_storage_config(mut self, config: ScannerStorageConfig) -> Self {
        self.storage_config = Some(config);
        self
    }

    /// Set scan configuration
    pub fn with_scan_config(mut self, config: EnhancedScanConfig) -> Self {
        self.scan_config = Some(config);
        self
    }

    /// Build the enhanced scanner with storage
    #[cfg(feature = "storage")]
    pub async fn build_with_storage(self) -> LightweightWalletResult<EnhancedWalletScanner<S>> {
        let scanner = self.scanner.ok_or_else(|| {
            LightweightWalletError::ConfigurationError("Scanner not provided".to_string())
        })?;

        let storage_config = self.storage_config.unwrap_or_else(|| {
            ScannerStorageConfig::memory()
        });

        let scan_config = self.scan_config.unwrap_or_else(|| {
            EnhancedScanConfig::new(0, 1000)
        });

        let storage = if storage_config.use_memory_storage {
            ScannerStorage::new_memory()
        } else {
            ScannerStorage::new_with_database(storage_config).await?
        };

        Ok(EnhancedWalletScanner::new_with_storage(scanner, storage, scan_config))
    }

    /// Build the enhanced scanner (memory-only mode)
    pub fn build(self) -> LightweightWalletResult<EnhancedWalletScanner<S>> {
        let scanner = self.scanner.ok_or_else(|| {
            LightweightWalletError::ConfigurationError("Scanner not provided".to_string())
        })?;

        let scan_config = self.scan_config.unwrap_or_else(|| {
            EnhancedScanConfig::new(0, 1000)
        });

        Ok(EnhancedWalletScanner::new(scanner, scan_config))
    }
}

impl<S: BlockchainScanner> Default for EnhancedScannerBuilder<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanning::MockBlockchainScanner;

    #[test]
    fn test_enhanced_scanner_builder() {
        let mock_scanner = MockBlockchainScanner::new();
        let builder = EnhancedScannerBuilder::new()
            .with_scanner(mock_scanner)
            .with_scan_config(EnhancedScanConfig::new(100, 200));

        let scanner = builder.build().unwrap();
        assert_eq!(scanner.config().from_block, 100);
        assert_eq!(scanner.config().to_block, 200);
        
        #[cfg(feature = "storage")]
        assert!(scanner.storage().is_memory_only());
    }

    #[test]
    fn test_enhanced_scan_result() {
        let wallet_state = WalletState::new();
        
        let result = EnhancedScanResult::Completed(wallet_state.clone());
        assert!(matches!(result, EnhancedScanResult::Completed(_)));

        let result = EnhancedScanResult::Interrupted(wallet_state.clone());
        assert!(matches!(result, EnhancedScanResult::Interrupted(_)));

        let result = EnhancedScanResult::Failed("test error".to_string());
        assert!(matches!(result, EnhancedScanResult::Failed(_)));
    }
} 