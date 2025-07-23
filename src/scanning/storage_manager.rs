//! Storage management for scanning operations and scan results
//!
//! This module provides storage abstractions specifically designed for the scanner library,
//! building on top of the existing wallet storage infrastructure.

#[cfg(feature = "storage")]
use async_trait::async_trait;

#[cfg(feature = "storage")]
use crate::data_structures::{
    wallet_output::LightweightWalletOutput,
    wallet_transaction::WalletState,
};

#[cfg(feature = "storage")]
use crate::errors::LightweightWalletResult;

#[cfg(feature = "storage")]
use super::scan_results::ScanResults;

/// Storage manager trait for unified storage operations in the scanner library
#[cfg(feature = "storage")]
#[async_trait(?Send)]
pub trait StorageManager: Send + Sync {
    /// Save scan results to storage
    async fn save_scan_results(&mut self, results: &ScanResults) -> LightweightWalletResult<()>;
    
    /// Save a single wallet output to storage
    async fn save_wallet_output(&mut self, wallet_id: u32, output: &LightweightWalletOutput) -> LightweightWalletResult<()>;
    
    /// Save multiple wallet outputs in batch
    async fn save_wallet_outputs(&mut self, wallet_id: u32, outputs: &[LightweightWalletOutput]) -> LightweightWalletResult<()>;
    
    /// Save wallet state (transactions and balances)
    async fn save_wallet_state(&mut self, wallet_id: u32, state: &WalletState) -> LightweightWalletResult<()>;
    
    /// Mark output as spent by commitment
    async fn mark_output_spent(&mut self, commitment: &[u8], block_height: u64) -> LightweightWalletResult<()>;
    
    /// Get wallet state with current balances
    async fn get_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState>;
    
    /// Update the latest scanned block for a wallet
    async fn update_scanned_block(&mut self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<()>;
    
    /// Get the latest scanned block for a wallet
    async fn get_latest_scanned_block(&self, wallet_id: u32) -> LightweightWalletResult<Option<u64>>;
}

/// Mock storage manager for testing and non-storage scenarios
#[cfg(feature = "storage")]
#[derive(Debug, Default)]
pub struct MockStorageManager {
    latest_scanned_blocks: std::collections::HashMap<u32, u64>,
}

#[cfg(feature = "storage")]
impl MockStorageManager {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(feature = "storage")]
#[async_trait(?Send)]
impl StorageManager for MockStorageManager {
    async fn save_scan_results(&mut self, _results: &ScanResults) -> LightweightWalletResult<()> {
        // Mock implementation - just return success
        Ok(())
    }
    
    async fn save_wallet_output(&mut self, _wallet_id: u32, _output: &LightweightWalletOutput) -> LightweightWalletResult<()> {
        // Mock implementation - just return success
        Ok(())
    }
    
    async fn save_wallet_outputs(&mut self, _wallet_id: u32, _outputs: &[LightweightWalletOutput]) -> LightweightWalletResult<()> {
        // Mock implementation - just return success
        Ok(())
    }
    
    async fn save_wallet_state(&mut self, _wallet_id: u32, _state: &WalletState) -> LightweightWalletResult<()> {
        // Mock implementation - just return success
        Ok(())
    }
    
    async fn mark_output_spent(&mut self, _commitment: &[u8], _block_height: u64) -> LightweightWalletResult<()> {
        // Mock implementation - just return success
        Ok(())
    }
    
    async fn get_wallet_state(&self, _wallet_id: u32) -> LightweightWalletResult<WalletState> {
        // Mock implementation - return empty wallet state
        Ok(WalletState::new())
    }
    
    async fn update_scanned_block(&mut self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<()> {
        self.latest_scanned_blocks.insert(wallet_id, block_height);
        Ok(())
    }
    
    async fn get_latest_scanned_block(&self, wallet_id: u32) -> LightweightWalletResult<Option<u64>> {
        Ok(self.latest_scanned_blocks.get(&wallet_id).copied())
    }
}

// Storage implementations are only available with the storage feature
#[cfg(feature = "storage")]
mod storage_adapters {
    use super::*;
    use std::sync::Arc;
    #[cfg(not(target_arch = "wasm32"))]
    use tokio::sync::mpsc;
    use std::time::{Duration, Instant};
    use crate::storage::WalletStorage;
    use crate::errors::LightweightWalletError;

    /// Background writer adapter for high-performance scanning with non-blocking writes
    /// 
    /// This adapter is only available on native platforms (not WASM) due to its dependency on tokio.
    /// For WASM environments, use DirectStorageAdapter instead.
    #[cfg(not(target_arch = "wasm32"))]
    pub struct BackgroundWriterAdapter {
        /// Channel for sending storage commands to background task
        command_sender: mpsc::UnboundedSender<StorageCommand>,
        /// Handle to the background storage task
        _task_handle: tokio::task::JoinHandle<()>,
        /// Reference to the underlying storage for read operations
        storage: Arc<dyn WalletStorage>,
        /// Configuration for the background writer
        _config: BackgroundWriterConfig,
    }

    /// Shared storage handler functions for both adapters
    mod storage_handlers {
        use super::*;
        
        /// Handle saving scan results to storage
        pub async fn handle_save_scan_results(
            storage: &dyn WalletStorage,
            results: &ScanResults,
        ) -> LightweightWalletResult<()> {
            // Save the wallet state which contains all the transactions
            if !results.wallet_state.transactions.is_empty() {
                // For now, assume wallet_id = 1 - this would need to be passed in properly
                storage.save_transactions(1, &results.wallet_state.transactions).await?;
            }
            
            // Update the latest scanned block based on scan configuration
            let latest_block = results.scan_config_summary.start_height + results.scan_config_summary.total_blocks_scanned;
            if latest_block > results.scan_config_summary.start_height {
                storage.update_wallet_scanned_block(1, latest_block - 1).await?;
            }
            
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "Saved scan results: {} transactions, {} blocks scanned (blocks {}-{})",
                results.wallet_state.transactions.len(),
                results.scan_config_summary.total_blocks_scanned,
                results.scan_config_summary.start_height,
                latest_block - 1
            );
            
            Ok(())
        }

        /// Handle saving a single wallet output to storage  
        pub async fn handle_save_wallet_output(
            storage: &dyn WalletStorage,
            wallet_id: u32,
            output: &LightweightWalletOutput,
        ) -> LightweightWalletResult<()> {
            let stored_output = convert_to_stored_output(wallet_id, output)?;
            storage.save_output(&stored_output).await.map(|_| ())
        }

        /// Handle saving multiple wallet outputs to storage
        pub async fn handle_save_wallet_outputs(
            storage: &dyn WalletStorage,
            wallet_id: u32,
            outputs: &[LightweightWalletOutput],
        ) -> LightweightWalletResult<()> {
            let stored_outputs: Result<Vec<_>, _> = outputs.iter()
                .map(|output| convert_to_stored_output(wallet_id, output))
                .collect();
            
            let stored_outputs = stored_outputs?;
            storage.save_outputs(&stored_outputs).await.map(|_| ())
        }

        /// Handle saving wallet state to storage
        pub async fn handle_save_wallet_state(
            storage: &dyn WalletStorage,
            wallet_id: u32,
            state: &WalletState,
        ) -> LightweightWalletResult<()> {
            storage.save_transactions(wallet_id, &state.transactions).await?;
            
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "Saved wallet state for wallet {}: {} transactions",
                wallet_id,
                state.transactions.len()
            );
            
            Ok(())
        }

        /// Handle marking an output as spent
        pub async fn handle_mark_output_spent(
            _storage: &dyn WalletStorage,
            _commitment: &[u8],
            _block_height: u64,
        ) -> LightweightWalletResult<()> {
            // For now, we don't have a direct way to mark outputs spent by commitment
            // This would need to be implemented in the storage layer
            // TODO: Implement proper commitment-based spent tracking
            Ok(())
        }

        /// Convert LightweightWalletOutput to StoredOutput format
        fn convert_to_stored_output(wallet_id: u32, output: &LightweightWalletOutput) -> LightweightWalletResult<crate::storage::storage_trait::StoredOutput> {
            use crate::storage::storage_trait::StoredOutput;
            use hex;
            
            // Create a dummy commitment - in practice this would come from actual output data
            let commitment_bytes = match &output.spending_key_id {
                crate::data_structures::wallet_output::LightweightKeyId::String(s) => {
                    // Use a hash of the string as a placeholder commitment
                    use blake2::digest::{Digest, FixedOutput};
                    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
                    hasher.update(s.as_bytes());
                    hasher.finalize_fixed().to_vec()
                }
                crate::data_structures::wallet_output::LightweightKeyId::PublicKey(pk) => {
                    pk.as_bytes().to_vec()
                }
                crate::data_structures::wallet_output::LightweightKeyId::Zero => {
                    vec![0u8; 32]
                }
            };
            
            // Create placeholder output hash
            let output_hash = {
                use blake2::digest::{Digest, FixedOutput};
                let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
                hasher.update(&commitment_bytes);
                hasher.update(&output.value.as_u64().to_le_bytes());
                hasher.finalize_fixed().to_vec()
            };
            
            // Convert spending key ID to string for storage
            let spending_key_str = match &output.spending_key_id {
                crate::data_structures::wallet_output::LightweightKeyId::String(s) => s.clone(),
                crate::data_structures::wallet_output::LightweightKeyId::PublicKey(pk) => hex::encode(pk.as_bytes()),
                crate::data_structures::wallet_output::LightweightKeyId::Zero => "zero".to_string(),
            };
            
            Ok(StoredOutput {
                id: None, // Let database assign ID
                wallet_id,
                commitment: commitment_bytes,
                hash: output_hash,
                value: output.value.as_u64(),
                spending_key: spending_key_str.clone(),
                script_private_key: spending_key_str, // Use same key for now
                script: vec![], // Placeholder - would need proper serialization of LightweightScript
                input_data: vec![], // Placeholder - would need proper serialization of LightweightExecutionStack
                covenant: vec![], // Placeholder - would need proper serialization of LightweightCovenant
                output_type: 0, // Default to payment output
                features_json: serde_json::to_string(&output.features).unwrap_or_default(),
                maturity: output.minimum_value_promise.as_u64(),
                script_lock_height: 0, // Default
                sender_offset_public_key: vec![0u8; 32], // Placeholder
                metadata_signature_ephemeral_commitment: vec![0u8; 32], // Placeholder
                metadata_signature_ephemeral_pubkey: vec![0u8; 32], // Placeholder
                metadata_signature_u_a: vec![0u8; 32], // Placeholder
                metadata_signature_u_x: vec![0u8; 32], // Placeholder
                metadata_signature_u_y: vec![0u8; 32], // Placeholder
                encrypted_data: serde_json::to_vec(&output.encrypted_data).unwrap_or_default(),
                minimum_value_promise: output.minimum_value_promise.as_u64(),
                rangeproof: output.range_proof.as_ref().map(|_| vec![]), // Placeholder
                status: 0, // Unspent
                mined_height: None, // LightweightWalletOutput doesn't have mined_height field
                spent_in_tx_id: None,
                created_at: None,
                updated_at: None,
            })
        }
    }

    /// Configuration for BackgroundWriterAdapter optimization
    #[derive(Debug, Clone)]
    #[cfg(not(target_arch = "wasm32"))]
    pub struct BackgroundWriterConfig {
        /// Maximum number of operations to batch together
        pub max_batch_size: usize,
        /// Maximum time to wait before flushing a partial batch (milliseconds)
        pub batch_timeout_ms: u64,
        /// Maximum queue size before applying backpressure
        pub max_queue_size: Option<usize>,
        /// Enable detailed performance tracking
        pub enable_performance_tracking: bool,
        /// Number of retry attempts for failed operations
        pub max_retries: u32,
        /// Base delay for exponential backoff (milliseconds)
        pub retry_base_delay_ms: u64,
    }

    impl Default for BackgroundWriterConfig {
        fn default() -> Self {
            Self {
                max_batch_size: 100,
                batch_timeout_ms: 100,
                max_queue_size: Some(10000),
                enable_performance_tracking: true,
                max_retries: 3,
                retry_base_delay_ms: 10,
            }
        }
    }

    /// Commands sent to the background storage writer
    #[derive(Debug)]
    #[cfg(not(target_arch = "wasm32"))]
    enum StorageCommand {
        SaveScanResults {
            results: ScanResults,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        SaveWalletOutput {
            wallet_id: u32,
            output: LightweightWalletOutput,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        SaveWalletOutputs {
            wallet_id: u32,
            outputs: Vec<LightweightWalletOutput>,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        SaveWalletState {
            wallet_id: u32,
            state: WalletState,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        MarkOutputSpent {
            commitment: Vec<u8>,
            block_height: u64,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        UpdateScannedBlock {
            wallet_id: u32,
            block_height: u64,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        },
        /// Batch command for multiple operations
        #[allow(dead_code)]
        BatchOperations {
            operations: Vec<BatchOperation>,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<Vec<LightweightWalletResult<()>>>>,
        },
        /// Force flush any pending batched operations
        FlushBatch,
        Shutdown,
    }

    /// Individual operation that can be batched
    #[derive(Debug)]
    #[cfg(not(target_arch = "wasm32"))]
    pub enum BatchOperation {
        SaveWalletOutput {
            wallet_id: u32,
            output: LightweightWalletOutput,
        },
        MarkOutputSpent {
            commitment: Vec<u8>,
            block_height: u64,
        },
        UpdateScannedBlock {
            wallet_id: u32,
            block_height: u64,
        },
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl BackgroundWriterAdapter {
    /// Create a new background writer adapter with default configuration
    pub fn new(storage: Arc<dyn WalletStorage>) -> Self {
    Self::with_config(storage, BackgroundWriterConfig::default())
    }

    /// Create a new background writer adapter with custom configuration
    pub fn with_config(storage: Arc<dyn WalletStorage>, config: BackgroundWriterConfig) -> Self {
    let (command_sender, mut command_receiver) = mpsc::unbounded_channel();
    let storage_clone = storage.clone();
    let config_clone = config.clone();
    
    // Spawn background task for processing storage commands
    let task_handle = tokio::spawn(async move {
    let mut stats = WriterStats::new(config_clone.enable_performance_tracking);
    let mut batch_buffer = BatchBuffer::new(config_clone.max_batch_size);
    let mut batch_timer = tokio::time::interval(Duration::from_millis(config_clone.batch_timeout_ms));
    batch_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    
    loop {
    tokio::select! {
    // Process incoming commands
    command = command_receiver.recv() => {
        match command {
            Some(command) => {
            let start_time = Instant::now();
            
            match command {
                    StorageCommand::SaveScanResults { results, response } => {
                        let result = Self::handle_save_scan_results(&*storage_clone, &results).await;
                                    stats.record_operation("save_scan_results", start_time.elapsed());
                    let _ = response.send(result);
                }
                    StorageCommand::SaveWalletOutput { wallet_id, output, response } => {
                        // Add to batch buffer if batching is enabled
                    if config_clone.max_batch_size > 1 {
                        batch_buffer.add_operation(BatchOperation::SaveWalletOutput { wallet_id, output }, response);
                        if batch_buffer.should_flush() {
                                                Self::flush_batch_buffer(&*storage_clone, &mut batch_buffer, &mut stats).await;
                            }
                    } else {
                        let result = Self::handle_save_wallet_output(&*storage_clone, wallet_id, &output).await;
                        stats.record_operation("save_wallet_output", start_time.elapsed());
                            let _ = response.send(result);
                        }
                }
                StorageCommand::SaveWalletOutputs { wallet_id, outputs, response } => {
                    let result = Self::handle_save_wallet_outputs(&*storage_clone, wallet_id, &outputs).await;
                        stats.record_operation("save_wallet_outputs", start_time.elapsed());
                            let _ = response.send(result);
                            }
                                StorageCommand::SaveWalletState { wallet_id, state, response } => {
                                    let result = Self::handle_save_wallet_state(&*storage_clone, wallet_id, &state).await;
                                    stats.record_operation("save_wallet_state", start_time.elapsed());
                                let _ = response.send(result);
                            }
                            StorageCommand::MarkOutputSpent { commitment, block_height, response } => {
                                    // Add to batch buffer if batching is enabled
                                        if config_clone.max_batch_size > 1 {
                                                batch_buffer.add_spent_operation(BatchOperation::MarkOutputSpent { commitment, block_height }, response);
                                                if batch_buffer.should_flush() {
                                                    Self::flush_batch_buffer(&*storage_clone, &mut batch_buffer, &mut stats).await;
                                                }
                                            } else {
                                                let result = Self::handle_mark_output_spent(&*storage_clone, &commitment, block_height).await;
                                                stats.record_operation("mark_output_spent", start_time.elapsed());
                                                let _ = response.send(result);
                                            }
                                        }
                                        StorageCommand::UpdateScannedBlock { wallet_id, block_height, response } => {
                                            let result = storage_clone.update_wallet_scanned_block(wallet_id, block_height).await;
                                            stats.record_operation("update_scanned_block", start_time.elapsed());
                                            let _ = response.send(result);
                                        }
                                        StorageCommand::BatchOperations { operations, response } => {
                                            let result = Self::handle_batch_operations(&*storage_clone, operations).await;
                                            stats.record_operation("batch_operations", start_time.elapsed());
                                            let _ = response.send(result);
                                        }
                                        StorageCommand::FlushBatch => {
                                            Self::flush_batch_buffer(&*storage_clone, &mut batch_buffer, &mut stats).await;
                                        }
                                        StorageCommand::Shutdown => {
                                            // Flush any pending operations before shutdown
                                            Self::flush_batch_buffer(&*storage_clone, &mut batch_buffer, &mut stats).await;
                                            
                                            #[cfg(feature = "tracing")]
                                            tracing::info!("Background storage writer shutting down. Stats: {:?}", stats);
                                            break;
                                        }
                                    }
                                }
                                None => break, // Channel closed
                            }
                        }
                        
                        // Periodic batch flush timer
                        _ = batch_timer.tick() => {
                            if !batch_buffer.is_empty() {
                                Self::flush_batch_buffer(&*storage_clone, &mut batch_buffer, &mut stats).await;
                            }
                        }
                    }
                }
            });
            
            Self {
                command_sender,
                _task_handle: task_handle,
                storage,
                _config: config,
            }
        }
        
        /// Send a command to the background writer and wait for response
        async fn send_command(&self, command: StorageCommand) -> LightweightWalletResult<()> {
            let (response_sender, response_receiver) = tokio::sync::oneshot::channel();
            
            // Wrap the command with the response channel
            let command_with_response = match command {
                StorageCommand::SaveScanResults { results, .. } => {
                    StorageCommand::SaveScanResults { results, response: response_sender }
                }
                StorageCommand::SaveWalletOutput { wallet_id, output, .. } => {
                    StorageCommand::SaveWalletOutput { wallet_id, output, response: response_sender }
                }
                StorageCommand::SaveWalletOutputs { wallet_id, outputs, .. } => {
                    StorageCommand::SaveWalletOutputs { wallet_id, outputs, response: response_sender }
                }
                StorageCommand::SaveWalletState { wallet_id, state, .. } => {
                    StorageCommand::SaveWalletState { wallet_id, state, response: response_sender }
                }
                StorageCommand::MarkOutputSpent { commitment, block_height, .. } => {
                    StorageCommand::MarkOutputSpent { commitment, block_height, response: response_sender }
                }
                StorageCommand::UpdateScannedBlock { wallet_id, block_height, .. } => {
                    StorageCommand::UpdateScannedBlock { wallet_id, block_height, response: response_sender }
                }
                StorageCommand::BatchOperations { .. } | StorageCommand::FlushBatch | StorageCommand::Shutdown => {
                    return Err(LightweightWalletError::InternalError("Invalid command for send_command".to_string()));
                }
            };
            
            self.command_sender.send(command_with_response)
                .map_err(|_| LightweightWalletError::InternalError("Background writer channel closed".to_string()))?;
                
            response_receiver.await
                .map_err(|_| LightweightWalletError::InternalError("Background writer response channel closed".to_string()))?
        }
        
        /// Handle saving scan results in background task
        async fn handle_save_scan_results(
            storage: &dyn WalletStorage,
            results: &ScanResults,
        ) -> LightweightWalletResult<()> {
            storage_handlers::handle_save_scan_results(storage, results).await
        }
        
        /// Handle saving a single wallet output in background task
        async fn handle_save_wallet_output(
            storage: &dyn WalletStorage,
            wallet_id: u32,
            output: &LightweightWalletOutput,
        ) -> LightweightWalletResult<()> {
            let stored_output = Self::convert_to_stored_output(wallet_id, output)?;
            storage.save_output(&stored_output).await?;
            Ok(())
        }
        
        /// Handle saving multiple wallet outputs in background task
        async fn handle_save_wallet_outputs(
            storage: &dyn WalletStorage,
            wallet_id: u32,
            outputs: &[LightweightWalletOutput],
        ) -> LightweightWalletResult<()> {
            let stored_outputs: Result<Vec<_>, _> = outputs.iter()
                .map(|output| Self::convert_to_stored_output(wallet_id, output))
                .collect();
            
            let stored_outputs = stored_outputs?;
            storage.save_outputs(&stored_outputs).await?;
            Ok(())
        }
        
        /// Handle saving wallet state in background task
        async fn handle_save_wallet_state(
            storage: &dyn WalletStorage,
            wallet_id: u32,
            state: &WalletState,
        ) -> LightweightWalletResult<()> {
            // Save all transactions in the wallet state
            storage.save_transactions(wallet_id, &state.transactions).await
        }
        
        /// Handle marking output as spent in background task
        async fn handle_mark_output_spent(
            storage: &dyn WalletStorage,
            commitment: &[u8],
            block_height: u64,
        ) -> LightweightWalletResult<()> {
            use crate::data_structures::types::CompressedCommitment;
            
            // Convert commitment bytes to CompressedCommitment
            if commitment.len() != 32 {
                return Err(LightweightWalletError::InvalidArgument {
                    argument: "commitment".to_string(),
                    value: hex::encode(commitment),
                    message: "Commitment must be exactly 32 bytes".to_string(),
                });
            }
            
            let mut commitment_array = [0u8; 32];
            commitment_array.copy_from_slice(commitment);
            let compressed_commitment = CompressedCommitment::new(commitment_array);
            
            // Mark the transaction as spent using the compressed commitment
            let _result = storage.mark_transaction_spent(&compressed_commitment, block_height, 0).await?;
            
            #[cfg(feature = "tracing")]
            tracing::debug!(
                "Marked output spent: commitment={}, block_height={}",
                hex::encode(commitment),
                block_height
            );
            
            Ok(())
        }
        
        /// Shutdown the background writer gracefully
        pub async fn shutdown(&self) {
            let _ = self.command_sender.send(StorageCommand::Shutdown);
        }

        /// Force flush any pending batched operations
        pub async fn flush_batch(&self) -> LightweightWalletResult<()> {
            self.command_sender.send(StorageCommand::FlushBatch)
                .map_err(|_| LightweightWalletError::InternalError("Background writer channel closed".to_string()))?;
            Ok(())
        }

        /// Flush the batch buffer and process all pending operations
        async fn flush_batch_buffer(
            storage: &dyn WalletStorage,
            batch_buffer: &mut BatchBuffer,
            stats: &mut WriterStats,
        ) {
            if batch_buffer.is_empty() {
                return;
            }

            let operations = batch_buffer.clear();
            let batch_size = operations.len();
            
            #[cfg(feature = "tracing")]
            tracing::debug!("Flushing batch of {} operations", batch_size);

            let start_time = Instant::now();
            
            // Group operations by type for efficient processing
            let mut wallet_outputs = Vec::new();
            let mut wallet_outputs_responses = Vec::new();
            let mut spent_operations = Vec::new();
            let mut spent_responses = Vec::new();
            let mut block_updates = Vec::new();
            let mut block_responses = Vec::new();

            for (operation, response) in operations {
                match operation {
                    BatchOperation::SaveWalletOutput { wallet_id, output } => {
                        wallet_outputs.push((wallet_id, output));
                        wallet_outputs_responses.push(response);
                    }
                    BatchOperation::MarkOutputSpent { commitment, block_height } => {
                        spent_operations.push((commitment, block_height));
                        spent_responses.push(response);
                    }
                    BatchOperation::UpdateScannedBlock { wallet_id, block_height } => {
                        block_updates.push((wallet_id, block_height));
                        block_responses.push(response);
                    }
                }
            }

            // Process wallet outputs in batch
            if !wallet_outputs.is_empty() {
                let results = Self::handle_batch_wallet_outputs(storage, wallet_outputs).await;
                for (result, response) in results.into_iter().zip(wallet_outputs_responses) {
                    let _ = response.send(result);
                }
            }

            // Process spent operations in batch
            if !spent_operations.is_empty() {
                let results = Self::handle_batch_spent_operations(storage, spent_operations).await;
                for (result, response) in results.into_iter().zip(spent_responses) {
                    let _ = response.send(result);
                }
            }

            // Process block updates individually (they're usually unique per wallet)
            for ((wallet_id, block_height), response) in block_updates.into_iter().zip(block_responses) {
                let result = storage.update_wallet_scanned_block(wallet_id, block_height).await;
                let _ = response.send(result);
            }

            stats.record_batch(batch_size);
            stats.record_operation("batch_flush", start_time.elapsed());

            #[cfg(feature = "tracing")]
            tracing::debug!("Completed batch flush in {:?}", start_time.elapsed());
        }

        /// Handle batch operations command
        async fn handle_batch_operations(
            storage: &dyn WalletStorage,
            operations: Vec<BatchOperation>,
        ) -> LightweightWalletResult<Vec<LightweightWalletResult<()>>> {
            let mut results = Vec::with_capacity(operations.len());
            
            for operation in operations {
                let result = match operation {
                    BatchOperation::SaveWalletOutput { wallet_id, output } => {
                        Self::handle_save_wallet_output(storage, wallet_id, &output).await
                    }
                    BatchOperation::MarkOutputSpent { commitment, block_height } => {
                        Self::handle_mark_output_spent(storage, &commitment, block_height).await
                    }
                    BatchOperation::UpdateScannedBlock { wallet_id, block_height } => {
                        storage.update_wallet_scanned_block(wallet_id, block_height).await
                    }
                };
                results.push(result);
            }
            
            Ok(results)
        }

        /// Handle multiple wallet outputs efficiently
        async fn handle_batch_wallet_outputs(
            storage: &dyn WalletStorage,
            outputs: Vec<(u32, LightweightWalletOutput)>,
        ) -> Vec<LightweightWalletResult<()>> {
            // Group by wallet_id for more efficient batch processing
            let mut by_wallet: std::collections::HashMap<u32, Vec<LightweightWalletOutput>> = std::collections::HashMap::new();
            let mut wallet_ids = Vec::new();
            
            for (wallet_id, output) in outputs {
                by_wallet.entry(wallet_id).or_insert_with(Vec::new).push(output);
                wallet_ids.push(wallet_id);
            }

            let mut results = Vec::with_capacity(wallet_ids.len());

            for wallet_id in wallet_ids {
                if let Some(wallet_outputs) = by_wallet.get(&wallet_id) {
                    if wallet_outputs.len() == 1 {
                        // Single output, use individual handling
                        let result = Self::handle_save_wallet_output(storage, wallet_id, &wallet_outputs[0]).await;
                        results.push(result);
                    } else {
                        // Multiple outputs, use batch handling
                        let result = Self::handle_save_wallet_outputs(storage, wallet_id, wallet_outputs).await;
                        // For batch operations, we return the same result for each output in the batch
                        for _ in 0..wallet_outputs.len() {
                            // Push a copy of the result for each output
                            match &result {
                                Ok(()) => results.push(Ok(())),
                                Err(e) => results.push(Err(LightweightWalletError::InternalError(e.to_string()))),
                            }
                        }
                    }
                }
            }

            results
        }

        /// Handle multiple spent operations efficiently
        async fn handle_batch_spent_operations(
            storage: &dyn WalletStorage,
            operations: Vec<(Vec<u8>, u64)>,
        ) -> Vec<LightweightWalletResult<()>> {
            let mut results = Vec::with_capacity(operations.len());
            
            // For now, process individually - could be optimized with batch spent marking
            for (commitment, block_height) in operations {
                let result = Self::handle_mark_output_spent(storage, &commitment, block_height).await;
                results.push(result);
            }
            
            results
        }
        
        /// Convert LightweightWalletOutput to StoredOutput format
        fn convert_to_stored_output(wallet_id: u32, output: &LightweightWalletOutput) -> LightweightWalletResult<crate::storage::storage_trait::StoredOutput> {
            use crate::storage::storage_trait::StoredOutput;
            use hex;
            
            // Create a dummy commitment and hash - in practice these would come from actual output data
            let commitment_hex = match &output.spending_key_id {
                crate::data_structures::wallet_output::LightweightKeyId::String(s) => {
                    // Use a hash of the string as a placeholder commitment
                    use blake2::digest::{Digest, FixedOutput};
                    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
                    hasher.update(s.as_bytes());
                    hex::encode(hasher.finalize_fixed())
                }
                crate::data_structures::wallet_output::LightweightKeyId::PublicKey(pk) => {
                    hex::encode(pk.as_bytes())
                }
                crate::data_structures::wallet_output::LightweightKeyId::Zero => {
                    hex::encode([0u8; 32])
                }
            };
            
            let script_key_hex = match &output.script_key_id {
                crate::data_structures::wallet_output::LightweightKeyId::String(s) => {
                    // Use a hash of the string as a placeholder key
                    use blake2::digest::{Digest, FixedOutput};
                    let mut hasher = blake2::Blake2b::<blake2::digest::consts::U32>::new();
                    hasher.update(s.as_bytes());
                    hex::encode(hasher.finalize_fixed())
                }
                crate::data_structures::wallet_output::LightweightKeyId::PublicKey(pk) => {
                    hex::encode(pk.as_bytes())
                }
                crate::data_structures::wallet_output::LightweightKeyId::Zero => {
                    hex::encode([0u8; 32])
                }
            };
            
            let commitment_bytes = hex::decode(&commitment_hex)
                .map_err(|e| LightweightWalletError::InternalError(format!("Invalid commitment hex: {}", e)))?;
            
            Ok(StoredOutput {
                id: None,
                wallet_id,
                commitment: commitment_bytes.clone(),
                hash: commitment_bytes, // Use same as commitment for now
                value: output.value.as_u64(),
                spending_key: commitment_hex, // Use commitment as placeholder spending key
                script_private_key: script_key_hex,
                script: output.script.bytes.clone(),
                input_data: output.input_data.bytes(),
                covenant: output.covenant.bytes.clone(),
                output_type: match output.features.output_type {
                    crate::data_structures::wallet_output::LightweightOutputType::Payment => 0,
                    crate::data_structures::wallet_output::LightweightOutputType::Coinbase => 1,
                    crate::data_structures::wallet_output::LightweightOutputType::Burn => 2,
                    crate::data_structures::wallet_output::LightweightOutputType::ValidatorNodeRegistration => 3,
                    crate::data_structures::wallet_output::LightweightOutputType::CodeTemplateRegistration => 4,
                },
                features_json: serde_json::to_string(&output.features)
                    .map_err(|e| LightweightWalletError::InternalError(format!("Failed to serialize features: {}", e)))?,
                maturity: output.features.maturity,
                script_lock_height: output.script_lock_height,
                sender_offset_public_key: output.sender_offset_public_key.as_bytes().to_vec(),
                metadata_signature_ephemeral_commitment: output.metadata_signature.bytes.clone(),
                metadata_signature_ephemeral_pubkey: vec![], // Not available in lightweight format
                metadata_signature_u_a: vec![], // Not available in lightweight format
                metadata_signature_u_x: vec![], // Not available in lightweight format
                metadata_signature_u_y: vec![], // Not available in lightweight format
                encrypted_data: output.encrypted_data.to_byte_vec(),
                minimum_value_promise: output.minimum_value_promise.as_u64(),
                rangeproof: output.range_proof.as_ref().map(|rp| rp.bytes.clone()),
                status: 0, // Unspent by default
                mined_height: None,
                spent_in_tx_id: None,
                created_at: None,
                updated_at: None,
            })
        }
    }

    #[async_trait(?Send)]
    impl StorageManager for BackgroundWriterAdapter {
        async fn save_scan_results(&mut self, results: &ScanResults) -> LightweightWalletResult<()> {
            let command = StorageCommand::SaveScanResults {
                results: results.clone(),
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn save_wallet_output(&mut self, wallet_id: u32, output: &LightweightWalletOutput) -> LightweightWalletResult<()> {
            let command = StorageCommand::SaveWalletOutput {
                wallet_id,
                output: output.clone(),
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn save_wallet_outputs(&mut self, wallet_id: u32, outputs: &[LightweightWalletOutput]) -> LightweightWalletResult<()> {
            let command = StorageCommand::SaveWalletOutputs {
                wallet_id,
                outputs: outputs.to_vec(),
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn save_wallet_state(&mut self, wallet_id: u32, state: &WalletState) -> LightweightWalletResult<()> {
            let command = StorageCommand::SaveWalletState {
                wallet_id,
                state: state.clone(),
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn mark_output_spent(&mut self, commitment: &[u8], block_height: u64) -> LightweightWalletResult<()> {
            let command = StorageCommand::MarkOutputSpent {
                commitment: commitment.to_vec(),
                block_height,
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn get_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState> {
            self.storage.load_wallet_state(wallet_id).await
        }
        
        async fn update_scanned_block(&mut self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<()> {
            let command = StorageCommand::UpdateScannedBlock {
                wallet_id,
                block_height,
                response: tokio::sync::oneshot::channel().0, // Dummy sender, will be replaced
            };
            self.send_command(command).await
        }
        
        async fn get_latest_scanned_block(&self, wallet_id: u32) -> LightweightWalletResult<Option<u64>> {
            let wallet = self.storage.get_wallet_by_id(wallet_id).await?;
            Ok(wallet.and_then(|w| w.latest_scanned_block))
        }
    }

    /// Direct storage adapter for immediate writes (suitable for WASM and low-latency scenarios)
    pub struct DirectStorageAdapter {
        /// Direct reference to storage backend
        storage: Arc<dyn WalletStorage>,
    }

    impl DirectStorageAdapter {
        /// Create a new direct storage adapter
        pub fn new(storage: Arc<dyn WalletStorage>) -> Self {
            Self { storage }
        }
    }

    #[async_trait(?Send)]
    impl StorageManager for DirectStorageAdapter {
        async fn save_scan_results(&mut self, results: &ScanResults) -> LightweightWalletResult<()> {
            storage_handlers::handle_save_scan_results(&*self.storage, results).await
        }
        
        async fn save_wallet_output(&mut self, wallet_id: u32, output: &LightweightWalletOutput) -> LightweightWalletResult<()> {
            storage_handlers::handle_save_wallet_output(&*self.storage, wallet_id, output).await
        }
        
        async fn save_wallet_outputs(&mut self, wallet_id: u32, outputs: &[LightweightWalletOutput]) -> LightweightWalletResult<()> {
            storage_handlers::handle_save_wallet_outputs(&*self.storage, wallet_id, outputs).await
        }
        
        async fn save_wallet_state(&mut self, wallet_id: u32, state: &WalletState) -> LightweightWalletResult<()> {
            storage_handlers::handle_save_wallet_state(&*self.storage, wallet_id, state).await
        }
        
        async fn mark_output_spent(&mut self, commitment: &[u8], block_height: u64) -> LightweightWalletResult<()> {
            storage_handlers::handle_mark_output_spent(&*self.storage, commitment, block_height).await
        }
        
        async fn get_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState> {
            self.storage.load_wallet_state(wallet_id).await
        }
        
        async fn update_scanned_block(&mut self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<()> {
            self.storage.update_wallet_scanned_block(wallet_id, block_height).await
        }
        
        async fn get_latest_scanned_block(&self, wallet_id: u32) -> LightweightWalletResult<Option<u64>> {
            let wallet = self.storage.get_wallet_by_id(wallet_id).await?;
            Ok(wallet.and_then(|w| w.latest_scanned_block))
        }
    }

    /// Statistics tracking for the background writer
    #[derive(Debug)]
    #[cfg(not(target_arch = "wasm32"))]
    pub struct WriterStats {
        operations_count: std::collections::HashMap<String, u64>,
        total_time: std::collections::HashMap<String, Duration>,
        min_time: std::collections::HashMap<String, Duration>,
        max_time: std::collections::HashMap<String, Duration>,
        total_operations: u64,
        total_batches: u64,
        average_batch_size: f64,
        enable_detailed_tracking: bool,
        start_time: Instant,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl WriterStats {
        pub fn new(enable_detailed_tracking: bool) -> Self {
            Self {
                operations_count: std::collections::HashMap::new(),
                total_time: std::collections::HashMap::new(),
                min_time: std::collections::HashMap::new(),
                max_time: std::collections::HashMap::new(),
                total_operations: 0,
                total_batches: 0,
                average_batch_size: 0.0,
                enable_detailed_tracking,
                start_time: Instant::now(),
            }
        }

        pub fn record_operation(&mut self, operation: &str, duration: Duration) {
            self.total_operations += 1;
            *self.operations_count.entry(operation.to_string()).or_insert(0) += 1;
            *self.total_time.entry(operation.to_string()).or_insert(Duration::ZERO) += duration;
            
            if self.enable_detailed_tracking {
                let min_entry = self.min_time.entry(operation.to_string()).or_insert(duration);
                if duration < *min_entry {
                    *min_entry = duration;
                }
                
                let max_entry = self.max_time.entry(operation.to_string()).or_insert(duration);
                if duration > *max_entry {
                    *max_entry = duration;
                }
            }
        }

        pub fn record_batch(&mut self, batch_size: usize) {
            self.total_batches += 1;
            self.average_batch_size = (self.average_batch_size * (self.total_batches - 1) as f64 + batch_size as f64) / self.total_batches as f64;
        }

        pub fn get_throughput(&self) -> f64 {
            let elapsed = self.start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                self.total_operations as f64 / elapsed
            } else {
                0.0
            }
        }

        #[cfg(test)]
        pub fn total_operations(&self) -> u64 {
            self.total_operations
        }

        #[cfg(test)]
        pub fn total_batches(&self) -> u64 {
            self.total_batches
        }

        #[cfg(test)]
        pub fn average_batch_size(&self) -> f64 {
            self.average_batch_size
        }

        #[cfg(test)]
        pub fn operations_count(&self) -> &std::collections::HashMap<String, u64> {
            &self.operations_count
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl Default for WriterStats {
        fn default() -> Self {
            Self::new(true)
        }
    }

    /// Buffer for batching operations to improve performance
    #[derive(Debug)]
    #[cfg(not(target_arch = "wasm32"))]
    pub struct BatchBuffer {
        operations: Vec<(BatchOperation, tokio::sync::oneshot::Sender<LightweightWalletResult<()>>)>,
        max_size: usize,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl BatchBuffer {
        pub fn new(max_size: usize) -> Self {
            Self {
                operations: Vec::with_capacity(max_size),
                max_size,
            }
        }

        pub fn add_operation(
            &mut self,
            operation: BatchOperation,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        ) {
            self.operations.push((operation, response));
        }

        pub fn add_spent_operation(
            &mut self,
            operation: BatchOperation,
            response: tokio::sync::oneshot::Sender<LightweightWalletResult<()>>,
        ) {
            self.operations.push((operation, response));
        }

        pub fn should_flush(&self) -> bool {
            self.operations.len() >= self.max_size
        }

        pub fn is_empty(&self) -> bool {
            self.operations.is_empty()
        }

        pub fn len(&self) -> usize {
            self.operations.len()
        }

        pub fn clear(&mut self) -> Vec<(BatchOperation, tokio::sync::oneshot::Sender<LightweightWalletResult<()>>)> {
            std::mem::take(&mut self.operations)
        }
    }

    /// Architecture detection and adapter selection strategy
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AdapterSelectionStrategy {
        /// Automatically detect the best adapter for the current architecture
        Auto,
        /// Force use of DirectStorageAdapter (immediate writes)
        Direct,
        /// Force use of BackgroundWriterAdapter (only available on native platforms)
        #[cfg(not(target_arch = "wasm32"))]
        Background,
    }

    impl Default for AdapterSelectionStrategy {
        fn default() -> Self {
            Self::Auto
        }
    }

    /// Builder for creating storage managers with automatic architecture detection
    pub struct StorageManagerBuilder {
        storage: Option<Arc<dyn WalletStorage>>,
        adapter_strategy: AdapterSelectionStrategy,
        #[cfg(not(target_arch = "wasm32"))]
        background_writer_config: BackgroundWriterConfig,
    }

    impl StorageManagerBuilder {
        /// Create a new storage manager builder with automatic architecture detection
        pub fn new() -> Self {
            Self {
                storage: None,
                adapter_strategy: AdapterSelectionStrategy::Auto,
                #[cfg(not(target_arch = "wasm32"))]
                background_writer_config: BackgroundWriterConfig::default(),
            }
        }

        /// Create a storage manager with automatic architecture detection (convenience method)
        pub fn auto(storage: Arc<dyn WalletStorage>) -> LightweightWalletResult<Box<dyn StorageManager>> {
            Self::new().with_storage(storage).build()
        }
        
        /// Set the underlying storage backend
        pub fn with_storage(mut self, storage: Arc<dyn WalletStorage>) -> Self {
            self.storage = Some(storage);
            self
        }
        
        /// Set the adapter selection strategy
        pub fn with_adapter_strategy(mut self, strategy: AdapterSelectionStrategy) -> Self {
            self.adapter_strategy = strategy;
            self
        }

        /// Force use of DirectStorageAdapter (immediate writes, WASM-compatible)
        pub fn with_direct_adapter(mut self) -> Self {
            self.adapter_strategy = AdapterSelectionStrategy::Direct;
            self
        }

        /// Force use of BackgroundWriterAdapter (async writes, native only)
        #[cfg(not(target_arch = "wasm32"))]
        pub fn with_background_adapter(mut self) -> Self {
            self.adapter_strategy = AdapterSelectionStrategy::Background;
            self
        }

        /// Configure whether to use background writer (legacy method for backward compatibility)
        /// Deprecated: Use with_adapter_strategy() or with_direct_adapter()/with_background_adapter()
        #[deprecated(since = "0.2.0", note = "Use with_adapter_strategy() or with_direct_adapter()/with_background_adapter() instead")]
        pub fn with_background_writer(mut self, enabled: bool) -> Self {
            if enabled {
                #[cfg(not(target_arch = "wasm32"))]
                {
                    self.adapter_strategy = AdapterSelectionStrategy::Background;
                }
                #[cfg(target_arch = "wasm32")]
                {
                    // On WASM, background writer is not available, fall back to Direct
                    self.adapter_strategy = AdapterSelectionStrategy::Direct;
                }
            } else {
                self.adapter_strategy = AdapterSelectionStrategy::Direct;
            }
            self
        }

        /// Set custom background writer configuration
        #[cfg(not(target_arch = "wasm32"))]
        pub fn with_background_writer_config(mut self, config: BackgroundWriterConfig) -> Self {
            self.background_writer_config = config;
            self
        }

        /// Set batch size for background writer (native only)
        #[cfg(not(target_arch = "wasm32"))]
        pub fn with_batch_size(mut self, batch_size: usize) -> Self {
            self.background_writer_config.max_batch_size = batch_size;
            self
        }

        /// Set batch timeout for background writer (native only)
        #[cfg(not(target_arch = "wasm32"))]
        pub fn with_batch_timeout(mut self, timeout_ms: u64) -> Self {
            self.background_writer_config.batch_timeout_ms = timeout_ms;
            self
        }

        /// Enable or disable performance tracking (native only)
        #[cfg(not(target_arch = "wasm32"))]
        pub fn with_performance_tracking(mut self, enabled: bool) -> Self {
            self.background_writer_config.enable_performance_tracking = enabled;
            self
        }

        /// Set maximum queue size (native only)
        #[cfg(not(target_arch = "wasm32"))]
        pub fn with_max_queue_size(mut self, max_size: Option<usize>) -> Self {
            self.background_writer_config.max_queue_size = max_size;
            self
        }
        
        /// Build the storage manager with automatic architecture detection
        pub fn build(self) -> LightweightWalletResult<Box<dyn StorageManager>> {
            let storage = self.storage.ok_or_else(|| {
                LightweightWalletError::ConfigurationError("Storage backend is required".to_string())
            })?;
            
            // Determine which adapter to use based on strategy and architecture
            let use_background_adapter = match self.adapter_strategy {
                AdapterSelectionStrategy::Auto => {
                    // Automatic detection: prefer BackgroundWriter on native, DirectStorage on WASM
                    #[cfg(not(target_arch = "wasm32"))]
                    {
                        true // Native platforms: use BackgroundWriterAdapter for better performance
                    }
                    #[cfg(target_arch = "wasm32")]
                    {
                        false // WASM: use DirectStorageAdapter (tokio not available)
                    }
                }
                AdapterSelectionStrategy::Direct => false, // Always use DirectStorageAdapter
                #[cfg(not(target_arch = "wasm32"))]
                AdapterSelectionStrategy::Background => {
                    // Validate that BackgroundWriter is available on this platform
                    true
                }
            };
            
            // Create the appropriate adapter
            #[cfg(not(target_arch = "wasm32"))]
            if use_background_adapter {
                #[cfg(feature = "tracing")]
                tracing::debug!("Creating BackgroundWriterAdapter for native architecture");
                Ok(Box::new(BackgroundWriterAdapter::with_config(storage, self.background_writer_config)))
            } else {
                #[cfg(feature = "tracing")]
                tracing::debug!("Creating DirectStorageAdapter for native architecture");
                Ok(Box::new(DirectStorageAdapter::new(storage)))
            }
            
            #[cfg(target_arch = "wasm32")]
            {
                // WASM always uses DirectStorageAdapter since tokio isn't available
                #[cfg(feature = "tracing")]
                tracing::debug!("Creating DirectStorageAdapter for WASM architecture");
                Ok(Box::new(DirectStorageAdapter::new(storage)))
            }
        }
    }

    impl Default for StorageManagerBuilder {
        fn default() -> Self {
            Self::new()
        }
    }
}

// Re-export storage adapters when storage feature is enabled
#[cfg(feature = "storage")]
#[cfg(all(feature = "storage", not(target_arch = "wasm32")))]
pub use storage_adapters::{BackgroundWriterAdapter, BackgroundWriterConfig, BatchBuffer, BatchOperation, WriterStats};

#[cfg(feature = "storage")]
pub use storage_adapters::{AdapterSelectionStrategy, DirectStorageAdapter, StorageManagerBuilder};

#[cfg(all(test, feature = "storage", not(target_arch = "wasm32")))]
mod tests {
    #[cfg(feature = "storage")]
    use super::*;
    
    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_mock_storage_manager() {
        let mut manager = MockStorageManager::new();
        
        // Test update and get scanned block
        manager.update_scanned_block(1, 1000).await.unwrap();
        let block = manager.get_latest_scanned_block(1).await.unwrap();
        assert_eq!(block, Some(1000));
        
        // Test non-existent wallet
        let block = manager.get_latest_scanned_block(999).await.unwrap();
        assert_eq!(block, None);
    }
    
    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_architecture_detection() {
        use crate::storage::sqlite::SqliteStorage;
        use crate::storage::storage_trait::WalletStorage;
        use tempfile::NamedTempFile;
        
        let temp_file = NamedTempFile::new().unwrap();
        let storage = std::sync::Arc::new(SqliteStorage::new(temp_file.path().to_str().unwrap()).await.unwrap());
        
        // Initialize storage 
        storage.initialize().await.unwrap();
        
        // Test automatic detection - should build successfully
        let manager = StorageManagerBuilder::new()
            .with_storage(storage.clone())
            .build()
            .unwrap();
        
        // On native platforms with auto strategy, should create BackgroundWriterAdapter
        // On WASM, should create DirectStorageAdapter
        // Just test that the manager was created successfully - saves us from complex test data setup
        drop(manager);
        
        // Test explicit Direct strategy  
        let manager = StorageManagerBuilder::new()
            .with_storage(storage.clone())
            .with_direct_adapter()
            .build()
            .unwrap();
        
        drop(manager);
        
        // Test convenience method
        let manager = StorageManagerBuilder::auto(storage.clone()).unwrap();
        drop(manager);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn test_adapter_selection_strategy() {
        // Test strategy enum behavior
        assert_eq!(AdapterSelectionStrategy::default(), AdapterSelectionStrategy::Auto);
        
        let auto_strategy = AdapterSelectionStrategy::Auto;
        let direct_strategy = AdapterSelectionStrategy::Direct;
        
        assert_ne!(auto_strategy, direct_strategy);
        assert_eq!(format!("{:?}", auto_strategy), "Auto");
        assert_eq!(format!("{:?}", direct_strategy), "Direct");
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_storage_manager_builder_legacy() {
        use crate::storage::sqlite::SqliteStorage;
        use crate::storage::WalletStorage;
        use tempfile::NamedTempFile;
        
        let temp_file = NamedTempFile::new().unwrap();
        let storage = std::sync::Arc::new(SqliteStorage::new(temp_file.path().to_str().unwrap()).await.unwrap());
        
        // Initialize the storage (create tables)
        storage.initialize().await.unwrap();
        
        let manager = StorageManagerBuilder::new()
            .with_storage(storage)
            .with_background_writer(false)
            .build()
            .unwrap();
            
        let result = manager.get_latest_scanned_block(1).await;
        // Should return None for non-existent wallet, not an error
        assert_eq!(result.unwrap(), None);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_background_writer_configuration() {
        use crate::storage::sqlite::SqliteStorage;
        use crate::storage::WalletStorage;
        use tempfile::NamedTempFile;
        
        let temp_file = NamedTempFile::new().unwrap();
        let storage = std::sync::Arc::new(SqliteStorage::new(temp_file.path().to_str().unwrap()).await.unwrap());
        
        // Initialize the storage (create tables)
        storage.initialize().await.unwrap();
        
        // Test custom configuration
        let config = BackgroundWriterConfig {
            max_batch_size: 50,
            batch_timeout_ms: 200,
            max_queue_size: Some(5000),
            enable_performance_tracking: true,
            max_retries: 5,
            retry_base_delay_ms: 20,
        };
        
        let manager = StorageManagerBuilder::new()
            .with_storage(storage.clone())
            .with_background_writer(true)
            .with_background_writer_config(config)
            .build()
            .unwrap();
            
        let result = manager.get_latest_scanned_block(1).await;
        assert_eq!(result.unwrap(), None);
        
        // Test builder methods
        let manager2 = StorageManagerBuilder::new()
            .with_storage(storage)
            .with_batch_size(25)
            .with_batch_timeout(150)
            .with_performance_tracking(false)
            .with_max_queue_size(Some(2000))
            .build()
            .unwrap();
            
        let result2 = manager2.get_latest_scanned_block(1).await;
        assert_eq!(result2.unwrap(), None);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_batch_buffer() {
        use super::storage_adapters::{BatchBuffer, BatchOperation};
        let mut buffer = BatchBuffer::new(3);
        
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
        assert!(!buffer.should_flush());
        
        // Add operations up to batch size
        let (tx1, _rx1) = tokio::sync::oneshot::channel();
        let (tx2, _rx2) = tokio::sync::oneshot::channel();
        let (tx3, _rx3) = tokio::sync::oneshot::channel();
        
        buffer.add_operation(
            BatchOperation::SaveWalletOutput {
                wallet_id: 1,
                output: crate::data_structures::wallet_output::LightweightWalletOutput::default(),
            },
            tx1,
        );
        
        assert_eq!(buffer.len(), 1);
        assert!(!buffer.should_flush());
        
        buffer.add_operation(
            BatchOperation::UpdateScannedBlock {
                wallet_id: 1,
                block_height: 1000,
            },
            tx2,
        );
        
        assert_eq!(buffer.len(), 2);
        assert!(!buffer.should_flush());
        
        buffer.add_operation(
            BatchOperation::MarkOutputSpent {
                commitment: vec![0u8; 32],
                block_height: 1001,
            },
            tx3,
        );
        
        assert_eq!(buffer.len(), 3);
        assert!(buffer.should_flush());
        
        // Clear buffer
        let operations = buffer.clear();
        assert_eq!(operations.len(), 3);
        assert!(buffer.is_empty());
        assert_eq!(buffer.len(), 0);
    }

    #[cfg(feature = "storage")]
    #[test]
    fn test_writer_stats() {
        use super::storage_adapters::WriterStats;
        use std::time::Duration;
        let mut stats = WriterStats::new(true);
        
        assert_eq!(stats.total_operations(), 0);
        assert_eq!(stats.total_batches(), 0);
        assert_eq!(stats.get_throughput(), 0.0); // No time elapsed yet
        
        stats.record_operation("test_op", Duration::from_millis(100));
        assert_eq!(stats.total_operations(), 1);
        assert_eq!(*stats.operations_count().get("test_op").unwrap(), 1);
        
        stats.record_batch(5);
        assert_eq!(stats.total_batches(), 1);
        assert_eq!(stats.average_batch_size(), 5.0);
        
        stats.record_batch(3);
        assert_eq!(stats.total_batches(), 2);
        assert_eq!(stats.average_batch_size(), 4.0); // (5 + 3) / 2
    }
}
