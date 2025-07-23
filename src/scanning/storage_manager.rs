//! Storage management for scanning operations and scan results
//!
//! This module provides storage abstractions specifically designed for the scanner library,
//! building on top of the existing wallet storage infrastructure.

#[cfg(feature = "storage")]
use async_trait::async_trait;

#[cfg(feature = "storage")]
use crate::data_structures::{
    wallet_output::LightweightWalletOutput,
    wallet_transaction::{WalletState, WalletTransaction},
};

#[cfg(feature = "storage")]
use crate::errors::LightweightWalletResult;

#[cfg(feature = "storage")]
use super::scan_results::ScanResults;

/// Public batch operation enum for efficient mixed storage operations
#[derive(Debug, Clone)]
#[cfg(feature = "storage")]
pub enum BatchStorageOperation {
    /// Save a wallet output to storage
    SaveWalletOutput {
        wallet_id: u32,
        output: LightweightWalletOutput,
    },
    /// Mark output as spent by commitment
    MarkOutputSpent {
        commitment: Vec<u8>,
        block_height: u64,
    },
    /// Update scanned block height for a wallet
    UpdateScannedBlock {
        wallet_id: u32,
        block_height: u64,
    },
}

/// Configuration for incremental wallet state saving with memory management
#[derive(Debug, Clone)]
#[cfg(feature = "storage")]
pub struct IncrementalSaveConfig {
    /// Maximum chunk size for transaction batches (number of transactions)
    pub transaction_chunk_size: usize,
    /// Memory pressure threshold in bytes before forcing smaller chunks
    pub memory_pressure_threshold: usize,
    /// Whether to enable adaptive chunk sizing based on memory usage
    pub adaptive_chunk_sizing: bool,
    /// Maximum memory usage in bytes before pausing and flushing
    pub max_memory_usage: usize,
    /// Enable detailed progress reporting
    pub enable_progress_reporting: bool,
}

#[cfg(feature = "storage")]
impl Default for IncrementalSaveConfig {
    fn default() -> Self {
        Self {
            transaction_chunk_size: 1000,
            memory_pressure_threshold: 50 * 1024 * 1024, // 50MB
            adaptive_chunk_sizing: true,
            max_memory_usage: 100 * 1024 * 1024, // 100MB
            enable_progress_reporting: false,
        }
    }
}

/// Progress information for incremental transaction saving
#[derive(Debug, Clone)]
#[cfg(feature = "storage")]
pub struct TransactionSaveProgress {
    /// Total number of transactions to save
    pub total_transactions: usize,
    /// Number of transactions saved so far
    pub transactions_saved: usize,
    /// Number of chunks processed
    pub chunks_processed: usize,
    /// Estimated memory usage in bytes
    pub estimated_memory_usage: usize,
    /// Whether the save operation is complete
    pub is_complete: bool,
    /// Duration of the save operation so far
    pub elapsed_time: std::time::Duration,
    /// Average transactions per second
    pub throughput: f64,
}

/// Progress information for incremental wallet state saving
#[derive(Debug, Clone)]
#[cfg(feature = "storage")]
pub struct WalletStateSaveProgress {
    /// Progress for transaction saving
    pub transaction_progress: TransactionSaveProgress,
    /// Number of outputs saved
    pub outputs_saved: usize,
    /// Total estimated memory usage including outputs
    pub total_memory_usage: usize,
    /// Whether adaptive chunk sizing was triggered
    pub adaptive_sizing_triggered: bool,
}

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
    
    /// Mark multiple outputs as spent in batch for efficient spent output tracking
    async fn mark_outputs_spent_batch(&mut self, spent_outputs: &[(Vec<u8>, u64)]) -> LightweightWalletResult<Vec<LightweightWalletResult<()>>>;
    
    /// Execute a batch of mixed operations (save outputs, mark spent, update blocks) efficiently
    async fn execute_batch_operations(&mut self, operations: Vec<BatchStorageOperation>) -> LightweightWalletResult<Vec<LightweightWalletResult<()>>>;
    
    /// Get wallet state with current balances
    async fn get_wallet_state(&self, wallet_id: u32) -> LightweightWalletResult<WalletState>;
    
    /// Update the latest scanned block for a wallet
    async fn update_scanned_block(&mut self, wallet_id: u32, block_height: u64) -> LightweightWalletResult<()>;
    
    /// Get the latest scanned block for a wallet
    async fn get_latest_scanned_block(&self, wallet_id: u32) -> LightweightWalletResult<Option<u64>>;
    
    /// Flush any pending batched operations (for background writers)
    async fn flush_pending_operations(&mut self) -> LightweightWalletResult<()>;
    
    /// Save transactions incrementally with memory management to handle large transaction sets
    async fn save_transactions_incremental(&mut self, wallet_id: u32, transactions: &[WalletTransaction], chunk_size: Option<usize>) -> LightweightWalletResult<TransactionSaveProgress>;
    
    /// Save wallet state incrementally with automatic memory management
    async fn save_wallet_state_incremental(&mut self, wallet_id: u32, state: &WalletState, save_config: IncrementalSaveConfig) -> LightweightWalletResult<WalletStateSaveProgress>;
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
    
    async fn mark_outputs_spent_batch(&mut self, spent_outputs: &[(Vec<u8>, u64)]) -> LightweightWalletResult<Vec<LightweightWalletResult<()>>> {
        // Mock implementation - return success for all operations
        let results = (0..spent_outputs.len()).map(|_| Ok(())).collect();
        Ok(results)
    }
    
    async fn execute_batch_operations(&mut self, operations: Vec<BatchStorageOperation>) -> LightweightWalletResult<Vec<LightweightWalletResult<()>>> {
        // Mock implementation - return success for all operations
        let mut results = Vec::with_capacity(operations.len());
        for operation in operations {
            match operation {
                BatchStorageOperation::SaveWalletOutput { .. } => {
                    results.push(Ok(()));
                }
                BatchStorageOperation::MarkOutputSpent { .. } => {
                    results.push(Ok(()));
                }
                BatchStorageOperation::UpdateScannedBlock { wallet_id, block_height } => {
                    self.latest_scanned_blocks.insert(wallet_id, block_height);
                    results.push(Ok(()));
                }
            }
        }
        Ok(results)
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
    
    async fn flush_pending_operations(&mut self) -> LightweightWalletResult<()> {
        // Mock implementation - no operations to flush
        Ok(())
    }
    
    async fn save_transactions_incremental(&mut self, _wallet_id: u32, transactions: &[WalletTransaction], chunk_size: Option<usize>) -> LightweightWalletResult<TransactionSaveProgress> {
        // Mock implementation - simulate successful incremental save
        use std::time::{Duration, Instant};
        let start_time = Instant::now();
        
        // Simulate some processing time for larger transaction sets
        if transactions.len() > 100 {
            #[cfg(not(target_arch = "wasm32"))]
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        
        let effective_chunk_size = chunk_size.unwrap_or(1000);
        let chunks_processed = if transactions.is_empty() {
            0
        } else {
            (transactions.len() + effective_chunk_size - 1) / effective_chunk_size // Proper ceiling division
        };
        
        let elapsed = start_time.elapsed();
        let throughput = if elapsed.as_secs_f64() > 0.0 {
            transactions.len() as f64 / elapsed.as_secs_f64()
        } else {
            f64::INFINITY
        };
        
        Ok(TransactionSaveProgress {
            total_transactions: transactions.len(),
            transactions_saved: transactions.len(),
            chunks_processed,
            estimated_memory_usage: transactions.len() * 200, // Estimate ~200 bytes per transaction
            is_complete: true,
            elapsed_time: elapsed,
            throughput,
        })
    }
    
    async fn save_wallet_state_incremental(&mut self, wallet_id: u32, state: &WalletState, _save_config: IncrementalSaveConfig) -> LightweightWalletResult<WalletStateSaveProgress> {
        // Mock implementation - simulate successful incremental wallet state save
        let transaction_progress = self.save_transactions_incremental(wallet_id, &state.transactions, None).await?;
        
        Ok(WalletStateSaveProgress {
            transaction_progress,
            outputs_saved: 0, // WalletState doesn't have separate outputs field
            total_memory_usage: state.transactions.len() * 200,
            adaptive_sizing_triggered: false,
        })
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
        
        async fn mark_outputs_spent_batch(&mut self, spent_outputs: &[(Vec<u8>, u64)]) -> LightweightWalletResult<Vec<LightweightWalletResult<()>>> {
            // Convert to batch operations
            let batch_ops: Vec<BatchOperation> = spent_outputs.iter()
                .map(|(commitment, block_height)| BatchOperation::MarkOutputSpent {
                    commitment: commitment.clone(),
                    block_height: *block_height,
                })
                .collect();
            
            let (response_sender, response_receiver) = tokio::sync::oneshot::channel();
            let command = StorageCommand::BatchOperations {
                operations: batch_ops,
                response: response_sender,
            };
            
            self.command_sender.send(command)
                .map_err(|_| LightweightWalletError::InternalError("Background writer channel closed".to_string()))?;
                
            response_receiver.await
                .map_err(|_| LightweightWalletError::InternalError("Background writer response channel closed".to_string()))?
        }
        
        async fn execute_batch_operations(&mut self, operations: Vec<BatchStorageOperation>) -> LightweightWalletResult<Vec<LightweightWalletResult<()>>> {
            // Convert public BatchStorageOperation to internal BatchOperation
            let batch_ops: Vec<BatchOperation> = operations.into_iter()
                .map(|op| match op {
                    BatchStorageOperation::SaveWalletOutput { wallet_id, output } => {
                        BatchOperation::SaveWalletOutput { wallet_id, output }
                    }
                    BatchStorageOperation::MarkOutputSpent { commitment, block_height } => {
                        BatchOperation::MarkOutputSpent { commitment, block_height }
                    }
                    BatchStorageOperation::UpdateScannedBlock { wallet_id, block_height } => {
                        BatchOperation::UpdateScannedBlock { wallet_id, block_height }
                    }
                })
                .collect();
            
            let (response_sender, response_receiver) = tokio::sync::oneshot::channel();
            let command = StorageCommand::BatchOperations {
                operations: batch_ops,
                response: response_sender,
            };
            
            self.command_sender.send(command)
                .map_err(|_| LightweightWalletError::InternalError("Background writer channel closed".to_string()))?;
                
            response_receiver.await
                .map_err(|_| LightweightWalletError::InternalError("Background writer response channel closed".to_string()))?
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
        
        async fn flush_pending_operations(&mut self) -> LightweightWalletResult<()> {
            self.flush_batch().await
        }
        
        async fn save_transactions_incremental(&mut self, wallet_id: u32, transactions: &[WalletTransaction], chunk_size: Option<usize>) -> LightweightWalletResult<TransactionSaveProgress> {
            use std::time::Instant;
            
            let start_time = Instant::now();
            let total_transactions = transactions.len();
            
            if total_transactions == 0 {
                return Ok(TransactionSaveProgress {
                    total_transactions: 0,
                    transactions_saved: 0,
                    chunks_processed: 0,
                    estimated_memory_usage: 0,
                    is_complete: true,
                    elapsed_time: start_time.elapsed(),
                    throughput: 0.0,
                });
            }
            
            let config = IncrementalSaveConfig::default();
            let actual_chunk_size = chunk_size.unwrap_or_else(|| {
                storage_adapters::memory_management::calculate_optimal_chunk_size(transactions, &config)
            });
            
            let mut transactions_saved = 0;
            let mut chunks_processed = 0;
            let mut estimated_memory_usage = 0;
            
            // Process transactions in chunks
            for chunk in transactions.chunks(actual_chunk_size) {
                // Estimate memory usage for this chunk
                let chunk_memory: usize = chunk.iter()
                    .map(storage_adapters::memory_management::estimate_transaction_memory)
                    .sum();
                estimated_memory_usage += chunk_memory;
                
                // Save the chunk
                let result = self.storage.save_transactions(wallet_id, chunk).await;
                if let Err(e) = result {
                    return Err(e);
                }
                
                transactions_saved += chunk.len();
                chunks_processed += 1;
                
                // Check memory pressure and flush if needed
                if storage_adapters::memory_management::check_memory_pressure(estimated_memory_usage, &config) {
                    self.flush_batch().await?;
                    // Reset memory usage estimate after flush
                    estimated_memory_usage = chunk_memory;
                }
                
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    "Saved transaction chunk {}/{}: {} transactions ({} bytes estimated)",
                    chunks_processed,
                    (total_transactions + actual_chunk_size - 1) / actual_chunk_size,
                    chunk.len(),
                    chunk_memory
                );
            }
            
            let elapsed = start_time.elapsed();
            let throughput = if elapsed.as_secs_f64() > 0.0 {
                total_transactions as f64 / elapsed.as_secs_f64()
            } else {
                f64::INFINITY
            };
            
            Ok(TransactionSaveProgress {
                total_transactions,
                transactions_saved,
                chunks_processed,
                estimated_memory_usage,
                is_complete: true,
                elapsed_time: elapsed,
                throughput,
            })
        }
        
        async fn save_wallet_state_incremental(&mut self, wallet_id: u32, state: &WalletState, save_config: IncrementalSaveConfig) -> LightweightWalletResult<WalletStateSaveProgress> {
            use std::time::Instant;
            
            let start_time = Instant::now();
            
            // Calculate optimal chunk size for transactions
            let transaction_chunk_size = storage_adapters::memory_management::calculate_optimal_chunk_size(
                &state.transactions, 
                &save_config
            );
            
            let adaptive_sizing_triggered = transaction_chunk_size != save_config.transaction_chunk_size;
            
            // Save transactions incrementally
            let transaction_progress = self.save_transactions_incremental(
                wallet_id, 
                &state.transactions, 
                Some(transaction_chunk_size)
            ).await?;
            
            // Save outputs if present (using existing batch mechanism)
            let outputs_saved = 0;
            // WalletState doesn't have separate outputs field - outputs are stored as transactions
            // For now, we'll count the outputs as zero since they're handled as transactions
                
            #[cfg(feature = "tracing")]
            tracing::debug!("Skipped saving {} outputs (conversion not implemented)", outputs_saved);
            
            let total_memory_usage = transaction_progress.estimated_memory_usage + (outputs_saved * 100);
            
            #[cfg(feature = "tracing")]
            tracing::info!(
                "Completed incremental wallet state save: {} transactions, {} outputs, {} MB estimated, took {:?}",
                transaction_progress.transactions_saved,
                outputs_saved,
                total_memory_usage / (1024 * 1024),
                start_time.elapsed()
            );
            
            Ok(WalletStateSaveProgress {
                transaction_progress,
                outputs_saved,
                total_memory_usage,
                adaptive_sizing_triggered,
            })
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
        
        async fn mark_outputs_spent_batch(&mut self, spent_outputs: &[(Vec<u8>, u64)]) -> LightweightWalletResult<Vec<LightweightWalletResult<()>>> {
            let mut results = Vec::with_capacity(spent_outputs.len());
            
            // Process each spent output individually for the direct adapter
            for (commitment, block_height) in spent_outputs {
                let result = storage_handlers::handle_mark_output_spent(&*self.storage, commitment, *block_height).await;
                results.push(result);
            }
            
            Ok(results)
        }
        
        async fn execute_batch_operations(&mut self, operations: Vec<BatchStorageOperation>) -> LightweightWalletResult<Vec<LightweightWalletResult<()>>> {
            let mut results = Vec::with_capacity(operations.len());
            
            // Process each operation individually for the direct adapter
            for operation in operations {
                let result = match operation {
                    BatchStorageOperation::SaveWalletOutput { wallet_id, output } => {
                        storage_handlers::handle_save_wallet_output(&*self.storage, wallet_id, &output).await
                    }
                    BatchStorageOperation::MarkOutputSpent { commitment, block_height } => {
                        storage_handlers::handle_mark_output_spent(&*self.storage, &commitment, block_height).await
                    }
                    BatchStorageOperation::UpdateScannedBlock { wallet_id, block_height } => {
                        self.storage.update_wallet_scanned_block(wallet_id, block_height).await
                    }
                };
                results.push(result);
            }
            
            Ok(results)
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
        
        async fn flush_pending_operations(&mut self) -> LightweightWalletResult<()> {
            // Direct adapter has no pending operations to flush
            Ok(())
        }
        
        async fn save_transactions_incremental(&mut self, wallet_id: u32, transactions: &[WalletTransaction], chunk_size: Option<usize>) -> LightweightWalletResult<TransactionSaveProgress> {
            use std::time::Instant;
            
            let start_time = Instant::now();
            let total_transactions = transactions.len();
            
            if total_transactions == 0 {
                return Ok(TransactionSaveProgress {
                    total_transactions: 0,
                    transactions_saved: 0,
                    chunks_processed: 0,
                    estimated_memory_usage: 0,
                    is_complete: true,
                    elapsed_time: start_time.elapsed(),
                    throughput: 0.0,
                });
            }
            
            let config = IncrementalSaveConfig::default();
            let actual_chunk_size = chunk_size.unwrap_or_else(|| {
                storage_adapters::memory_management::calculate_optimal_chunk_size(transactions, &config)
            });
            
            let mut transactions_saved = 0;
            let mut chunks_processed = 0;
            let mut estimated_memory_usage = 0;
            
            // Process transactions in chunks
            for chunk in transactions.chunks(actual_chunk_size) {
                // Estimate memory usage for this chunk
                let chunk_memory: usize = chunk.iter()
                    .map(storage_adapters::memory_management::estimate_transaction_memory)
                    .sum();
                estimated_memory_usage += chunk_memory;
                
                // Save the chunk directly
                let result = self.storage.save_transactions(wallet_id, chunk).await;
                if let Err(e) = result {
                    return Err(e);
                }
                
                transactions_saved += chunk.len();
                chunks_processed += 1;
                
                #[cfg(feature = "tracing")]
                tracing::debug!(
                    "Saved transaction chunk {}/{}: {} transactions ({} bytes estimated)",
                    chunks_processed,
                    (total_transactions + actual_chunk_size - 1) / actual_chunk_size,
                    chunk.len(),
                    chunk_memory
                );
            }
            
            let elapsed = start_time.elapsed();
            let throughput = if elapsed.as_secs_f64() > 0.0 {
                total_transactions as f64 / elapsed.as_secs_f64()
            } else {
                f64::INFINITY
            };
            
            Ok(TransactionSaveProgress {
                total_transactions,
                transactions_saved,
                chunks_processed,
                estimated_memory_usage,
                is_complete: true,
                elapsed_time: elapsed,
                throughput,
            })
        }
        
        async fn save_wallet_state_incremental(&mut self, wallet_id: u32, state: &WalletState, save_config: IncrementalSaveConfig) -> LightweightWalletResult<WalletStateSaveProgress> {
            use std::time::Instant;
            
            let start_time = Instant::now();
            
            // Calculate optimal chunk size for transactions
            let transaction_chunk_size = storage_adapters::memory_management::calculate_optimal_chunk_size(
                &state.transactions, 
                &save_config
            );
            
            let adaptive_sizing_triggered = transaction_chunk_size != save_config.transaction_chunk_size;
            
            // Save transactions incrementally
            let transaction_progress = self.save_transactions_incremental(
                wallet_id, 
                &state.transactions, 
                Some(transaction_chunk_size)
            ).await?;
            
            // Save outputs if present
            let outputs_saved = 0;
            // WalletState doesn't have separate outputs field - outputs are stored as transactions
            // For now, we'll count the outputs as zero since they're handled as transactions
                
            #[cfg(feature = "tracing")]
            tracing::debug!("Skipped saving {} outputs (conversion not implemented)", outputs_saved);
            
            let total_memory_usage = transaction_progress.estimated_memory_usage + (outputs_saved * 100);
            
            #[cfg(feature = "tracing")]
            tracing::info!(
                "Completed incremental wallet state save: {} transactions, {} outputs, {} MB estimated, took {:?}",
                transaction_progress.transactions_saved,
                outputs_saved,
                total_memory_usage / (1024 * 1024),
                start_time.elapsed()
            );
            
            Ok(WalletStateSaveProgress {
                transaction_progress,
                outputs_saved,
                total_memory_usage,
                adaptive_sizing_triggered,
            })
        }
    }

    /// Create a storage manager optimized for the current architecture
    /// 
    /// On native platforms, returns a BackgroundWriterAdapter for high-performance scanning.
    /// On WASM platforms, returns a DirectStorageAdapter for immediate writes.
    #[allow(dead_code)]
    pub fn create_optimized_storage_manager(storage: Arc<dyn WalletStorage>) -> Box<dyn StorageManager> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            Box::new(BackgroundWriterAdapter::new(storage))
        }
        
        #[cfg(target_arch = "wasm32")]
        {
            Box::new(DirectStorageAdapter::new(storage))
        }
    }
    
    /// Create a storage manager with custom background writer configuration
    /// 
    /// Only available on native platforms. For WASM, this falls back to DirectStorageAdapter.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(dead_code)]
    pub fn create_background_storage_manager(
        storage: Arc<dyn WalletStorage>,
        config: BackgroundWriterConfig,
    ) -> Box<dyn StorageManager> {
        Box::new(BackgroundWriterAdapter::with_config(storage, config))
    }
    
    /// Create a direct storage manager for immediate writes
    /// 
    /// Suitable for WASM environments or when you need immediate consistency.
    #[allow(dead_code)]
    pub fn create_direct_storage_manager(storage: Arc<dyn WalletStorage>) -> Box<dyn StorageManager> {
        Box::new(DirectStorageAdapter::new(storage))
    }

    /// Memory management utilities for incremental saving
    pub mod memory_management {
        use super::*;
        
        /// Estimate memory usage of a transaction
        pub fn estimate_transaction_memory(transaction: &WalletTransaction) -> usize {
            // Base size of the struct
            let mut size = std::mem::size_of::<WalletTransaction>();
            
            // Add variable size fields
            if let Some(ref output_hash) = transaction.output_hash {
                size += output_hash.len();
            }
            
            // PaymentId can vary significantly in size
            size += estimate_payment_id_size(&transaction.payment_id);
            
            size
        }
        
        /// Estimate memory usage of a PaymentId
        pub fn estimate_payment_id_size(payment_id: &crate::data_structures::payment_id::PaymentId) -> usize {
            use crate::data_structures::payment_id::PaymentId;
            
            match payment_id {
                PaymentId::Empty => 0,
                PaymentId::U256(_) => 32, // U256 is 32 bytes
                PaymentId::Open { user_data, .. } => {
                    user_data.len() + 8 // User data plus some overhead
                }
                PaymentId::AddressAndData { user_data, .. } => {
                    64 + user_data.len() // TariAddress is approximately 64 bytes + user data
                }
                PaymentId::TransactionInfo { user_data, sent_output_hashes, .. } => {
                    // TransactionInfo includes vectors and can be quite large
                    64 + user_data.len() + (sent_output_hashes.len() * 32) // Conservative estimate
                }
                PaymentId::Raw(data) => data.len(),
            }
        }
        
        /// Calculate optimal chunk size based on memory constraints
        pub fn calculate_optimal_chunk_size(
            transactions: &[WalletTransaction],
            config: &IncrementalSaveConfig,
        ) -> usize {
            if !config.adaptive_chunk_sizing {
                return config.transaction_chunk_size;
            }
            
            if transactions.is_empty() {
                return config.transaction_chunk_size;
            }
            
            // Sample first few transactions to estimate average size
            let sample_size = std::cmp::min(10, transactions.len());
            let total_sample_memory: usize = transactions[..sample_size]
                .iter()
                .map(estimate_transaction_memory)
                .sum();
            
            let avg_transaction_size = total_sample_memory / sample_size;
            
            // Calculate how many transactions fit within memory threshold
            let optimal_chunk_size = config.memory_pressure_threshold / avg_transaction_size;
            
            // Clamp between 1 and configured maximum
            std::cmp::max(1, std::cmp::min(optimal_chunk_size, config.transaction_chunk_size))
        }
        
        /// Check if current memory usage exceeds threshold
        pub fn check_memory_pressure(current_usage: usize, config: &IncrementalSaveConfig) -> bool {
            current_usage >= config.memory_pressure_threshold
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

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_batch_spent_outputs_mock() {
        let mut storage_manager = MockStorageManager::new();
        
        // Create some test spent output data
        let spent_outputs = vec![
            (vec![1u8; 32], 100u64),
            (vec![2u8; 32], 101u64),
            (vec![3u8; 32], 102u64),
        ];
        
        // Test batch marking outputs as spent
        let results = storage_manager.mark_outputs_spent_batch(&spent_outputs).await;
        assert!(results.is_ok());
        
        let results = results.unwrap();
        assert_eq!(results.len(), 3);
        
        // All operations should succeed
        for result in results {
            assert!(result.is_ok());
        }
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_batch_mixed_operations_mock() {
        use crate::data_structures::{
            wallet_output::{LightweightWalletOutput, LightweightKeyId, LightweightOutputFeatures},
            types::MicroMinotari,
        };
        
        let mut storage_manager = MockStorageManager::new();
        
        // Create test output
        let test_output = LightweightWalletOutput {
            spending_key_id: LightweightKeyId::String("test_key_1".to_string()),
            script_key_id: LightweightKeyId::String("script_key_1".to_string()),
            value: MicroMinotari::from(1000u64),
            features: LightweightOutputFeatures::default(),
            ..Default::default()
        };
        
        // Create mixed batch operations
        let batch_operations = vec![
            BatchStorageOperation::SaveWalletOutput {
                wallet_id: 1,
                output: test_output.clone(),
            },
            BatchStorageOperation::MarkOutputSpent {
                commitment: vec![4u8; 32],
                block_height: 200,
            },
            BatchStorageOperation::UpdateScannedBlock {
                wallet_id: 1,
                block_height: 200,
            },
            BatchStorageOperation::SaveWalletOutput {
                wallet_id: 2,
                output: test_output,
            },
        ];
        
        // Execute batch operations
        let results = storage_manager.execute_batch_operations(batch_operations).await;
        assert!(results.is_ok());
        
        let results = results.unwrap();
        assert_eq!(results.len(), 4);
        
        // All operations should succeed
        for result in results {
            assert!(result.is_ok());
        }
        
        // Verify that the block update was applied
        let latest_block = storage_manager.get_latest_scanned_block(1).await.unwrap();
        assert_eq!(latest_block, Some(200));
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_flush_pending_operations_mock() {
        let mut storage_manager = MockStorageManager::new();
        
        // Mock storage manager has no pending operations, so this should just succeed
        let result = storage_manager.flush_pending_operations().await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_incremental_transaction_saving_mock() {
        use crate::data_structures::{
            wallet_transaction::WalletTransaction,
            payment_id::PaymentId,
            transaction::{TransactionDirection, TransactionStatus},
            types::CompressedCommitment,
        };
        
        let mut storage_manager = MockStorageManager::new();
        
        // Create some test transactions
        let transactions = vec![
            WalletTransaction {
                block_height: 100,
                output_index: Some(0),
                input_index: None,
                commitment: CompressedCommitment::new([1u8; 32]),
                output_hash: Some(vec![1u8; 32]),
                value: 1000,
                payment_id: PaymentId::Empty,
                is_spent: false,
                spent_in_block: None,
                spent_in_input: None,
                transaction_status: TransactionStatus::Coinbase,
                transaction_direction: TransactionDirection::Inbound,
                is_mature: true,
            },
            WalletTransaction {
                block_height: 101,
                output_index: Some(1),
                input_index: None,
                commitment: CompressedCommitment::new([2u8; 32]),
                output_hash: Some(vec![2u8; 32]),
                value: 2000,
                payment_id: PaymentId::Empty,
                is_spent: false,
                spent_in_block: None,
                spent_in_input: None,
                transaction_status: TransactionStatus::Coinbase,
                transaction_direction: TransactionDirection::Inbound,
                is_mature: true,
            },
        ];
        
        // Test incremental save with default chunk size
        let progress = storage_manager.save_transactions_incremental(1, &transactions, None).await;
        assert!(progress.is_ok());
        
        let progress = progress.unwrap();
        assert_eq!(progress.total_transactions, 2);
        assert_eq!(progress.transactions_saved, 2);
        assert_eq!(progress.chunks_processed, 1);
        assert!(progress.is_complete);
        assert!(progress.throughput > 0.0 || progress.throughput.is_infinite());
        
        // Test incremental save with custom chunk size (should use ceiling division for chunks)
        let progress = storage_manager.save_transactions_incremental(1, &transactions, Some(1)).await;
        assert!(progress.is_ok());
        
        let progress = progress.unwrap();
        assert_eq!(progress.total_transactions, 2);
        assert_eq!(progress.transactions_saved, 2);
        assert_eq!(progress.chunks_processed, 2); // With chunk_size=1, 2 transactions = 2 chunks
        assert!(progress.is_complete);
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_incremental_wallet_state_saving_mock() {
        use crate::data_structures::{
            wallet_transaction::{WalletTransaction, WalletState},
            payment_id::PaymentId,
            transaction::{TransactionDirection, TransactionStatus},
            types::CompressedCommitment,
        };
        
        let mut storage_manager = MockStorageManager::new();
        
        // Create a wallet state with some transactions
        let transaction = WalletTransaction {
            block_height: 100,
            output_index: Some(0),
            input_index: None,
            commitment: CompressedCommitment::new([1u8; 32]),
            output_hash: Some(vec![1u8; 32]),
            value: 1000,
            payment_id: PaymentId::Empty,
            is_spent: false,
            spent_in_block: None,
            spent_in_input: None,
            transaction_status: TransactionStatus::Coinbase,
            transaction_direction: TransactionDirection::Inbound,
            is_mature: true,
        };
        
        let mut wallet_state = WalletState::new();
        wallet_state.transactions.push(transaction);
        wallet_state.rebuild_commitment_index();
        
        // Test incremental wallet state save
        let save_config = IncrementalSaveConfig::default();
        let progress = storage_manager.save_wallet_state_incremental(1, &wallet_state, save_config).await;
        assert!(progress.is_ok());
        
        let progress = progress.unwrap();
        assert_eq!(progress.transaction_progress.total_transactions, 1);
        assert_eq!(progress.transaction_progress.transactions_saved, 1);
        assert!(progress.transaction_progress.is_complete);
        assert_eq!(progress.outputs_saved, 0); // No separate outputs in WalletState
        assert!(!progress.adaptive_sizing_triggered); // Should not trigger for small dataset
    }

    #[cfg(feature = "storage")]
    #[tokio::test]
    async fn test_memory_estimation() {
        use crate::data_structures::{
            wallet_transaction::WalletTransaction,
            payment_id::PaymentId,
            transaction::{TransactionDirection, TransactionStatus},
            types::CompressedCommitment,
        };
        
        // Test basic transaction memory estimation
        let transaction = WalletTransaction {
            block_height: 100,
            output_index: Some(0),
            input_index: None,
            commitment: CompressedCommitment::new([1u8; 32]),
            output_hash: Some(vec![1u8; 32]),
            value: 1000,
            payment_id: PaymentId::Empty,
            is_spent: false,
            spent_in_block: None,
            spent_in_input: None,
            transaction_status: TransactionStatus::Coinbase,
            transaction_direction: TransactionDirection::Inbound,
            is_mature: true,
        };
        
        let memory_usage = storage_adapters::memory_management::estimate_transaction_memory(&transaction);
        
        // Should be at least the size of the struct
        assert!(memory_usage >= std::mem::size_of::<WalletTransaction>());
        
        // Should account for the output hash
        assert!(memory_usage >= std::mem::size_of::<WalletTransaction>() + 32);
    }

    #[cfg(feature = "storage")]
    #[tokio::test] 
    async fn test_adaptive_chunk_sizing() {
        use crate::data_structures::{
            wallet_transaction::WalletTransaction,
            payment_id::PaymentId,
            transaction::{TransactionDirection, TransactionStatus},
            types::CompressedCommitment,
        };
        
        // Create transactions with different memory footprints
        let transactions: Vec<WalletTransaction> = (0..100).map(|i| {
            WalletTransaction {
                block_height: 100 + i,
                output_index: Some(i as usize),
                input_index: None,
                commitment: CompressedCommitment::new([i as u8; 32]),
                output_hash: Some(vec![i as u8; 32]),
                value: 1000 + i,
                payment_id: PaymentId::Empty,
                is_spent: false,
                spent_in_block: None,
                spent_in_input: None,
                transaction_status: TransactionStatus::Coinbase,
                transaction_direction: TransactionDirection::Inbound,
                is_mature: true,
            }
        }).collect();
        
        // Test with adaptive sizing enabled
        let config_adaptive = IncrementalSaveConfig {
            transaction_chunk_size: 50,
            adaptive_chunk_sizing: true,
            ..Default::default()
        };
        
        let adaptive_chunk_size = storage_adapters::memory_management::calculate_optimal_chunk_size(
            &transactions, 
            &config_adaptive
        );
        
        // Test with adaptive sizing disabled
        let config_fixed = IncrementalSaveConfig {
            transaction_chunk_size: 50,
            adaptive_chunk_sizing: false,
            ..Default::default()
        };
        
        let fixed_chunk_size = storage_adapters::memory_management::calculate_optimal_chunk_size(
            &transactions, 
            &config_fixed
        );
        
        // Fixed should always return the configured size
        assert_eq!(fixed_chunk_size, 50);
        
        // Adaptive should be reasonable (between 1 and configured max)
        assert!(adaptive_chunk_size >= 1);
        assert!(adaptive_chunk_size <= config_adaptive.transaction_chunk_size);
    }
}
